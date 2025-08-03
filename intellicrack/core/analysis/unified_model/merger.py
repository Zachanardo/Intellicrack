"""
Result Merger for Unified Binary Model

This module provides the ResultMerger class responsible for intelligently
merging overlapping analysis results from different tools and sources.
"""

import logging
from typing import Dict, Any, List, Optional, Union, Set
from collections import defaultdict

from .model import (
    FunctionInfo, SymbolDatabase, SectionInfo, ProtectionAnalysis,
    VulnerabilityAnalysis, AnalysisSource, ConfidenceLevel
)


class ResultMerger:
    """
    Handles intelligent merging of overlapping analysis results.
    
    This class implements strategies for consolidating data when multiple
    analysis tools provide information about the same entities (functions,
    symbols, sections, etc.).
    """
    
    def __init__(self, logger: Optional[logging.Logger] = None):
        """
        Initialize the result merger.
        
        Args:
            logger: Optional logger instance
        """
        self.logger = logger or logging.getLogger(__name__)
        
        # Source priority mapping (higher values = higher priority)
        self.source_priority = {
            AnalysisSource.GHIDRA: 90,
            AnalysisSource.RADARE2: 85,
            AnalysisSource.BINARY_ANALYZER: 70,
            AnalysisSource.VULNERABILITY_ENGINE: 80,
            AnalysisSource.ENTROPY_ANALYZER: 60,
            AnalysisSource.YARA_ENGINE: 75,
            AnalysisSource.DYNAMIC_ANALYZER: 95,  # Runtime data is often most accurate
            AnalysisSource.SANDBOX: 85,
            AnalysisSource.BUILDER: 50
        }
        
    def merge_functions(self, existing_functions: Dict[int, FunctionInfo],
                       new_functions: Dict[int, FunctionInfo]) -> Dict[int, FunctionInfo]:
        """
        Merge function information from multiple sources.
        
        Args:
            existing_functions: Currently stored function data
            new_functions: New function data to merge
            
        Returns:
            Merged function dictionary
        """
        self.logger.debug(f"Merging {len(new_functions)} new functions with {len(existing_functions)} existing")
        
        merged = existing_functions.copy()
        
        for address, new_func in new_functions.items():
            if address in merged:
                # Merge with existing function
                merged[address] = self._merge_single_function(merged[address], new_func)
            else:
                # Add new function
                merged[address] = new_func
                
        self.logger.debug(f"Function merge complete: {len(merged)} total functions")
        return merged
        
    def merge_symbols(self, existing_symbols: SymbolDatabase,
                     new_symbols: SymbolDatabase) -> SymbolDatabase:
        """
        Merge symbol information from multiple sources.
        
        Args:
            existing_symbols: Currently stored symbol data
            new_symbols: New symbol data to merge
            
        Returns:
            Merged SymbolDatabase
        """
        self.logger.debug("Merging symbol databases")
        
        # Merge imports
        merged_imports = self._merge_symbol_dicts(existing_symbols.imports, new_symbols.imports)
        
        # Merge exports
        merged_exports = self._merge_symbol_dicts(existing_symbols.exports, new_symbols.exports)
        
        # Merge strings
        merged_strings = self._merge_symbol_dicts(existing_symbols.strings, new_symbols.strings)
        
        # Merge symbols by address
        merged_by_address = self._merge_symbol_dicts(
            existing_symbols.symbols_by_address, 
            new_symbols.symbols_by_address
        )
        
        return SymbolDatabase(
            imports=merged_imports,
            exports=merged_exports,
            strings=merged_strings,
            symbols_by_address=merged_by_address
        )
        
    def merge_sections(self, existing_sections: Dict[str, SectionInfo],
                      new_sections: Dict[str, SectionInfo]) -> Dict[str, SectionInfo]:
        """
        Merge section information from multiple sources.
        
        Args:
            existing_sections: Currently stored section data
            new_sections: New section data to merge
            
        Returns:
            Merged section dictionary
        """
        self.logger.debug(f"Merging {len(new_sections)} new sections with {len(existing_sections)} existing")
        
        merged = existing_sections.copy()
        
        for name, new_section in new_sections.items():
            if name in merged:
                # Merge with existing section
                merged[name] = self._merge_single_section(merged[name], new_section)
            else:
                # Add new section
                merged[name] = new_section
                
        return merged
        
    def merge_protections(self, existing_protections: ProtectionAnalysis,
                         new_protections: ProtectionAnalysis) -> ProtectionAnalysis:
        """
        Merge protection analysis from multiple sources.
        
        Args:
            existing_protections: Currently stored protection data
            new_protections: New protection data to merge
            
        Returns:
            Merged ProtectionAnalysis
        """
        self.logger.debug("Merging protection analysis")
        
        return ProtectionAnalysis(
            packers=self._merge_protection_lists(existing_protections.packers, new_protections.packers),
            obfuscation_techniques=self._merge_protection_lists(
                existing_protections.obfuscation_techniques,
                new_protections.obfuscation_techniques
            ),
            anti_debug_methods=self._merge_protection_lists(
                existing_protections.anti_debug_methods,
                new_protections.anti_debug_methods
            ),
            anti_vm_methods=self._merge_protection_lists(
                existing_protections.anti_vm_methods,
                new_protections.anti_vm_methods
            ),
            code_integrity_checks=self._merge_protection_lists(
                existing_protections.code_integrity_checks,
                new_protections.code_integrity_checks
            ),
            licensing_mechanisms=self._merge_protection_lists(
                existing_protections.licensing_mechanisms,
                new_protections.licensing_mechanisms
            ),
            protection_confidence=self._merge_confidence_dicts(
                existing_protections.protection_confidence,
                new_protections.protection_confidence
            )
        )
        
    def merge_vulnerabilities(self, existing_vulns: VulnerabilityAnalysis,
                            new_vulns: VulnerabilityAnalysis) -> VulnerabilityAnalysis:
        """
        Merge vulnerability analysis from multiple sources.
        
        Args:
            existing_vulns: Currently stored vulnerability data
            new_vulns: New vulnerability data to merge
            
        Returns:
            Merged VulnerabilityAnalysis
        """
        self.logger.debug("Merging vulnerability analysis")
        
        return VulnerabilityAnalysis(
            buffer_overflows=self._merge_vulnerability_lists(
                existing_vulns.buffer_overflows,
                new_vulns.buffer_overflows
            ),
            format_string_bugs=self._merge_vulnerability_lists(
                existing_vulns.format_string_bugs,
                new_vulns.format_string_bugs
            ),
            integer_overflows=self._merge_vulnerability_lists(
                existing_vulns.integer_overflows,
                new_vulns.integer_overflows
            ),
            use_after_free=self._merge_vulnerability_lists(
                existing_vulns.use_after_free,
                new_vulns.use_after_free
            ),
            code_injection_points=self._merge_vulnerability_lists(
                existing_vulns.code_injection_points,
                new_vulns.code_injection_points
            ),
            licensing_bypasses=self._merge_vulnerability_lists(
                existing_vulns.licensing_bypasses,
                new_vulns.licensing_bypasses
            ),
            vulnerability_scores=self._merge_confidence_dicts(
                existing_vulns.vulnerability_scores,
                new_vulns.vulnerability_scores
            )
        )
        
    def _merge_single_function(self, existing: FunctionInfo, new: FunctionInfo) -> FunctionInfo:
        """
        Merge two FunctionInfo objects intelligently.
        
        Args:
            existing: Existing function information
            new: New function information to merge
            
        Returns:
            Merged FunctionInfo
        """
        # Determine which source has higher priority
        existing_priority = self.source_priority.get(existing.source, 0)
        new_priority = self.source_priority.get(new.source, 0)
        
        # Use higher priority source for conflicting data
        if new_priority > existing_priority:
            primary, secondary = new, existing
        else:
            primary, secondary = existing, new
            
        # Merge specific fields intelligently
        name = primary.name if primary.name and primary.name != f'sub_{primary.address:x}' else secondary.name
        
        # Use more detailed signature
        signature = primary.signature if len(primary.signature) > len(secondary.signature) else secondary.signature
        
        # Use more detailed decompiled code
        decompiled_code = (primary.decompiled_code if len(primary.decompiled_code) > len(secondary.decompiled_code) 
                          else secondary.decompiled_code)
        
        # Merge call lists
        calls_to = list(set(primary.calls_to + secondary.calls_to))
        calls_from = list(set(primary.calls_from + secondary.calls_from))
        
        # Merge local variables and parameters
        local_variables = self._merge_unique_dicts(primary.local_variables, secondary.local_variables)
        parameters = self._merge_unique_dicts(primary.parameters, secondary.parameters)
        
        # Use higher confidence
        confidence = primary.confidence if primary.confidence.value > secondary.confidence.value else secondary.confidence
        
        # Combine analysis notes
        notes = []
        if primary.analysis_notes:
            notes.append(f"[{primary.source.value}] {primary.analysis_notes}")
        if secondary.analysis_notes and secondary.analysis_notes != primary.analysis_notes:
            notes.append(f"[{secondary.source.value}] {secondary.analysis_notes}")
        analysis_notes = "; ".join(notes)
        
        return FunctionInfo(
            address=primary.address,
            name=name,
            size=max(primary.size, secondary.size),
            signature=signature,
            calls_to=calls_to,
            calls_from=calls_from,
            local_variables=local_variables,
            parameters=parameters,
            return_type=primary.return_type if primary.return_type != 'unknown' else secondary.return_type,
            complexity_score=max(primary.complexity_score, secondary.complexity_score),
            is_library_function=primary.is_library_function or secondary.is_library_function,
            decompiled_code=decompiled_code,
            analysis_notes=analysis_notes,
            confidence=confidence,
            source=primary.source
        )
        
    def _merge_single_section(self, existing: SectionInfo, new: SectionInfo) -> SectionInfo:
        """
        Merge two SectionInfo objects intelligently.
        
        Args:
            existing: Existing section information
            new: New section information to merge
            
        Returns:
            Merged SectionInfo
        """
        # Use higher priority source
        existing_priority = self.source_priority.get(existing.source, 0)
        new_priority = self.source_priority.get(new.source, 0)
        
        if new_priority > existing_priority:
            primary, secondary = new, existing
        else:
            primary, secondary = existing, new
            
        # Combine analysis notes
        notes = []
        if primary.analysis_notes:
            notes.append(f"[{primary.source.value}] {primary.analysis_notes}")
        if secondary.analysis_notes and secondary.analysis_notes != primary.analysis_notes:
            notes.append(f"[{secondary.source.value}] {secondary.analysis_notes}")
        analysis_notes = "; ".join(notes)
        
        return SectionInfo(
            name=primary.name,
            virtual_address=primary.virtual_address or secondary.virtual_address,
            virtual_size=max(primary.virtual_size, secondary.virtual_size),
            raw_address=primary.raw_address or secondary.raw_address,
            raw_size=max(primary.raw_size, secondary.raw_size),
            permissions=primary.permissions if primary.permissions else secondary.permissions,
            entropy=max(primary.entropy, secondary.entropy),
            contains_code=primary.contains_code or secondary.contains_code,
            contains_data=primary.contains_data or secondary.contains_data,
            analysis_notes=analysis_notes,
            source=primary.source
        )
        
    def _merge_symbol_dicts(self, existing: Dict, new: Dict) -> Dict:
        """
        Merge two symbol dictionaries with conflict resolution.
        
        Args:
            existing: Existing symbol dictionary
            new: New symbol dictionary to merge
            
        Returns:
            Merged symbol dictionary
        """
        merged = existing.copy()
        
        for key, new_value in new.items():
            if key in merged:
                existing_value = merged[key]
                
                # If both are dictionaries with source information, merge intelligently
                if (isinstance(existing_value, dict) and isinstance(new_value, dict) and
                    'source' in existing_value and 'source' in new_value):
                    
                    existing_priority = self.source_priority.get(existing_value['source'], 0)
                    new_priority = self.source_priority.get(new_value['source'], 0)
                    
                    if new_priority > existing_priority:
                        merged[key] = new_value
                    # If same priority, merge fields
                    elif new_priority == existing_priority:
                        merged_entry = existing_value.copy()
                        for field, value in new_value.items():
                            if field not in merged_entry or not merged_entry[field]:
                                merged_entry[field] = value
                        merged[key] = merged_entry
                else:
                    # Simple replacement for non-dict values
                    merged[key] = new_value
            else:
                merged[key] = new_value
                
        return merged
        
    def _merge_protection_lists(self, existing: List[Dict], new: List[Dict]) -> List[Dict]:
        """
        Merge protection mechanism lists, removing duplicates.
        
        Args:
            existing: Existing protection list
            new: New protection list to merge
            
        Returns:
            Merged protection list
        """
        merged = existing.copy()
        
        for new_item in new:
            # Check for duplicates based on type and key identifying fields
            is_duplicate = False
            for existing_item in merged:
                if self._are_protections_duplicate(existing_item, new_item):
                    is_duplicate = True
                    break
                    
            if not is_duplicate:
                merged.append(new_item)
                
        return merged
        
    def _merge_vulnerability_lists(self, existing: List[Dict], new: List[Dict]) -> List[Dict]:
        """
        Merge vulnerability lists, removing duplicates.
        
        Args:
            existing: Existing vulnerability list
            new: New vulnerability list to merge
            
        Returns:
            Merged vulnerability list
        """
        merged = existing.copy()
        
        for new_item in new:
            # Check for duplicates based on address or key identifying fields
            is_duplicate = False
            for existing_item in merged:
                if self._are_vulnerabilities_duplicate(existing_item, new_item):
                    is_duplicate = True
                    break
                    
            if not is_duplicate:
                merged.append(new_item)
                
        return merged
        
    def _merge_confidence_dicts(self, existing: Dict[str, float], new: Dict[str, float]) -> Dict[str, float]:
        """
        Merge confidence score dictionaries, taking maximum confidence.
        
        Args:
            existing: Existing confidence scores
            new: New confidence scores to merge
            
        Returns:
            Merged confidence scores
        """
        merged = existing.copy()
        
        for key, new_confidence in new.items():
            if key in merged:
                merged[key] = max(merged[key], new_confidence)
            else:
                merged[key] = new_confidence
                
        return merged
        
    def _merge_unique_dicts(self, list1: List[Dict], list2: List[Dict]) -> List[Dict]:
        """
        Merge two lists of dictionaries, removing duplicates based on name/key.
        
        Args:
            list1: First list of dictionaries
            list2: Second list of dictionaries
            
        Returns:
            Merged list with unique entries
        """
        merged = list1.copy()
        existing_names = {item.get('name', item.get('key', '')) for item in merged}
        
        for item in list2:
            name = item.get('name', item.get('key', ''))
            if name not in existing_names:
                merged.append(item)
                existing_names.add(name)
                
        return merged
        
    def _are_protections_duplicate(self, item1: Dict, item2: Dict) -> bool:
        """
        Check if two protection items are duplicates.
        
        Args:
            item1: First protection item
            item2: Second protection item
            
        Returns:
            True if items are duplicates
        """
        # Compare by type and address/name
        if item1.get('type') != item2.get('type'):
            return False
            
        # Check address if available
        if 'address' in item1 and 'address' in item2:
            return item1['address'] == item2['address']
            
        # Check name if available
        if 'name' in item1 and 'name' in item2:
            return item1['name'] == item2['name']
            
        # If no clear identifying fields, not duplicate
        return False
        
    def _are_vulnerabilities_duplicate(self, item1: Dict, item2: Dict) -> bool:
        """
        Check if two vulnerability items are duplicates.
        
        Args:
            item1: First vulnerability item
            item2: Second vulnerability item
            
        Returns:
            True if items are duplicates
        """
        # Compare by address if available
        if 'address' in item1 and 'address' in item2:
            return item1['address'] == item2['address']
            
        # Compare by function name if available
        if 'function' in item1 and 'function' in item2:
            return item1['function'] == item2['function']
            
        # Compare by description/type for similar vulnerabilities
        if 'description' in item1 and 'description' in item2:
            return item1['description'] == item2['description']
            
        return False
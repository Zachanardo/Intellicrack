"""
Model Validator for Unified Binary Model

This module provides the ModelValidator class responsible for validating
the consistency and completeness of unified binary models.
"""

import logging
import re
from typing import List, Dict, Any, Optional, Set, Tuple
from pathlib import Path

from .model import (
    UnifiedBinaryModel, BinaryMetadata, FunctionInfo, SymbolDatabase,
    SectionInfo, ProtectionAnalysis, VulnerabilityAnalysis, RuntimeBehavior,
    ValidationResult, AnalysisSource, ConfidenceLevel
)


class ValidationError:
    """Represents a validation error with severity and context."""
    
    def __init__(self, severity: str, category: str, message: str, 
                 context: Optional[Dict[str, Any]] = None):
        self.severity = severity  # 'error', 'warning', 'info'
        self.category = category  # 'metadata', 'functions', 'symbols', etc.
        self.message = message
        self.context = context or {}
        
    def __str__(self) -> str:
        return f"[{self.severity.upper()}] {self.category}: {self.message}"


class ModelValidator:
    """
    Validates unified binary models for consistency and completeness.
    
    This class performs comprehensive validation of the unified model to ensure
    data integrity, consistency across different analysis results, and completeness
    of the analysis.
    """
    
    def __init__(self, logger: Optional[logging.Logger] = None):
        """
        Initialize the model validator.
        
        Args:
            logger: Optional logger instance
        """
        self.logger = logger or logging.getLogger(__name__)
        self.errors: List[ValidationError] = []
        self.warnings: List[ValidationError] = []
        self.info: List[ValidationError] = []
        
    def validate_model(self, model: UnifiedBinaryModel) -> ValidationResult:
        """
        Perform comprehensive validation of the unified model.
        
        Args:
            model: UnifiedBinaryModel to validate
            
        Returns:
            ValidationResult containing validation status and issues
        """
        self.logger.info(f"Starting validation of unified model for {model.binary_path}")
        
        # Clear previous validation results
        self.errors.clear()
        self.warnings.clear()
        self.info.clear()
        
        # Perform validation checks
        self._validate_basic_structure(model)
        self._validate_metadata(model.metadata)
        self._validate_functions(model.functions)
        self._validate_symbols(model.symbols)
        self._validate_sections(model.sections)
        self._validate_protections(model.protections)
        self._validate_vulnerabilities(model.vulnerabilities)
        self._validate_runtime_behavior(model.runtime_behavior)
        self._validate_consistency(model)
        self._validate_completeness(model)
        
        # Create validation result
        result = ValidationResult(
            is_valid=len(self.errors) == 0,
            errors=[str(error) for error in self.errors],
            warnings=[str(warning) for warning in self.warnings],
            validation_time=None  # Will be set by caller
        )
        
        self.logger.info(f"Validation complete: {len(self.errors)} errors, "
                        f"{len(self.warnings)} warnings, {len(self.info)} info")
        
        return result
        
    def _validate_basic_structure(self, model: UnifiedBinaryModel) -> None:
        """Validate basic model structure and required fields."""
        if not model.binary_path:
            self._add_error("metadata", "Binary path is empty or None")
            
        if not model.file_hash:
            self._add_error("metadata", "File hash is empty or None")
        elif len(model.file_hash) != 64:
            self._add_error("metadata", f"Invalid file hash length: {len(model.file_hash)} (expected 64)")
            
        # Validate file exists
        if model.binary_path and not Path(model.binary_path).exists():
            self._add_warning("metadata", f"Binary file not found: {model.binary_path}")
            
        # Check if model has any analysis data
        has_data = (
            len(model.functions) > 0 or
            len(model.symbols.imports) > 0 or
            len(model.symbols.exports) > 0 or
            len(model.sections) > 0 or
            len(model.protections.packers) > 0 or
            len(model.vulnerabilities.buffer_overflows) > 0
        )
        
        if not has_data:
            self._add_warning("completeness", "Model appears to contain no analysis data")
            
    def _validate_metadata(self, metadata: BinaryMetadata) -> None:
        """Validate binary metadata for consistency."""
        # Validate file format
        valid_formats = {
            'PE', 'ELF', 'Mach-O', 'PE32', 'PE64', 'ELF32', 'ELF64',
            'unknown', 'DOS', 'NE', 'LE', 'LX'
        }
        if metadata.file_format not in valid_formats:
            self._add_warning("metadata", f"Unusual file format: {metadata.file_format}")
            
        # Validate architecture
        valid_architectures = {
            'x86', 'x64', 'x86_64', 'arm', 'arm64', 'aarch64', 'mips',
            'mips64', 'ppc', 'ppc64', 'sparc', 'unknown'
        }
        if metadata.architecture not in valid_architectures:
            self._add_warning("metadata", f"Unusual architecture: {metadata.architecture}")
            
        # Validate endianness
        if metadata.endianness not in ['little', 'big', 'unknown']:
            self._add_warning("metadata", f"Invalid endianness: {metadata.endianness}")
            
        # Validate addresses
        if metadata.entry_point < 0:
            self._add_error("metadata", f"Invalid entry point: {metadata.entry_point}")
            
        if metadata.base_address < 0:
            self._add_error("metadata", f"Invalid base address: {metadata.base_address}")
            
        # Validate file size
        if metadata.file_size <= 0:
            self._add_error("metadata", f"Invalid file size: {metadata.file_size}")
            
        # Check for reasonable file size (warn if > 1GB)
        if metadata.file_size > 1024 * 1024 * 1024:
            self._add_warning("metadata", f"Large file size: {metadata.file_size} bytes")
            
    def _validate_functions(self, functions: Dict[int, FunctionInfo]) -> None:
        """Validate function analysis data."""
        if not functions:
            self._add_info("functions", "No functions found in analysis")
            return
            
        self._add_info("functions", f"Analyzing {len(functions)} functions")
        
        # Track addresses for overlap detection
        address_ranges = []
        
        for address, func in functions.items():
            # Validate address consistency
            if func.address != address:
                self._add_error("functions", 
                               f"Function address mismatch: key={address}, func.address={func.address}")
                               
            # Validate address is reasonable
            if func.address < 0:
                self._add_error("functions", f"Invalid function address: {func.address}")
                
            # Validate size
            if func.size < 0:
                self._add_error("functions", f"Invalid function size: {func.size} at {func.address:x}")
            elif func.size == 0:
                self._add_warning("functions", f"Function with zero size at {func.address:x}")
            elif func.size > 1024 * 1024:  # 1MB
                self._add_warning("functions", f"Unusually large function: {func.size} bytes at {func.address:x}")
                
            # Validate name
            if not func.name:
                self._add_warning("functions", f"Function has no name at {func.address:x}")
            elif not re.match(r'^[a-zA-Z_][a-zA-Z0-9_]*$', func.name.replace('@', '_')):
                # Allow some special characters common in mangled names
                if not any(char in func.name for char in ['@', ':', '.', '?', '$']):
                    self._add_warning("functions", f"Unusual function name: {func.name}")
                    
            # Track address ranges for overlap detection
            if func.size > 0:
                address_ranges.append((func.address, func.address + func.size, func.name))
                
            # Validate confidence level
            if not isinstance(func.confidence, ConfidenceLevel):
                self._add_error("functions", f"Invalid confidence type for function {func.name}")
                
            # Validate source
            if not isinstance(func.source, AnalysisSource):
                self._add_error("functions", f"Invalid source type for function {func.name}")
                
        # Check for overlapping functions
        self._check_function_overlaps(address_ranges)
        
    def _validate_symbols(self, symbols: SymbolDatabase) -> None:
        """Validate symbol database for consistency."""
        # Validate imports
        for address, import_data in symbols.imports.items():
            if not isinstance(address, int) or address < 0:
                self._add_error("symbols", f"Invalid import address: {address}")
                
            if isinstance(import_data, dict):
                if 'name' not in import_data or not import_data['name']:
                    self._add_warning("symbols", f"Import at {address:x} has no name")
                    
        # Validate exports
        for address, export_data in symbols.exports.items():
            if not isinstance(address, int) or address < 0:
                self._add_error("symbols", f"Invalid export address: {address}")
                
            if isinstance(export_data, dict):
                if 'name' not in export_data or not export_data['name']:
                    self._add_warning("symbols", f"Export at {address:x} has no name")
                    
        # Validate strings
        for address, string_data in symbols.strings.items():
            if not isinstance(address, int) or address < 0:
                self._add_error("symbols", f"Invalid string address: {address}")
                
        # Check for overlapping symbol addresses
        all_addresses = set(symbols.imports.keys()) | set(symbols.exports.keys()) | set(symbols.strings.keys())
        if len(all_addresses) != (len(symbols.imports) + len(symbols.exports) + len(symbols.strings)):
            overlaps = self._find_symbol_overlaps(symbols)
            for addr in overlaps:
                self._add_warning("symbols", f"Address {addr:x} used by multiple symbol types")
                
    def _validate_sections(self, sections: Dict[str, SectionInfo]) -> None:
        """Validate section information."""
        if not sections:
            self._add_warning("sections", "No sections found in analysis")
            return
            
        self._add_info("sections", f"Analyzing {len(sections)} sections")
        
        # Track address ranges for overlap detection
        address_ranges = []
        
        for name, section in sections.items():
            # Validate name consistency
            if section.name != name:
                self._add_error("sections", f"Section name mismatch: key={name}, section.name={section.name}")
                
            # Validate addresses and sizes
            if section.virtual_address < 0:
                self._add_error("sections", f"Invalid virtual address in section {name}: {section.virtual_address}")
                
            if section.virtual_size < 0:
                self._add_error("sections", f"Invalid virtual size in section {name}: {section.virtual_size}")
                
            if section.raw_address < 0:
                self._add_error("sections", f"Invalid raw address in section {name}: {section.raw_address}")
                
            if section.raw_size < 0:
                self._add_error("sections", f"Invalid raw size in section {name}: {section.raw_size}")
                
            # Validate entropy
            if section.entropy < 0 or section.entropy > 8:
                self._add_warning("sections", f"Unusual entropy in section {name}: {section.entropy}")
                
            # Check for high entropy (possible packing/encryption)
            if section.entropy > 7.5:
                self._add_info("sections", f"High entropy section {name}: {section.entropy} (possible packing)")
                
            # Validate permissions
            if section.permissions and not re.match(r'^[rwx-]+$', section.permissions.lower()):
                self._add_warning("sections", f"Unusual permissions format in section {name}: {section.permissions}")
                
            # Track address ranges
            if section.virtual_size > 0:
                address_ranges.append((
                    section.virtual_address,
                    section.virtual_address + section.virtual_size,
                    name
                ))
                
        # Check for overlapping sections
        self._check_section_overlaps(address_ranges)
        
    def _validate_protections(self, protections: ProtectionAnalysis) -> None:
        """Validate protection analysis data."""
        # Validate each protection list
        protection_lists = [
            ('packers', protections.packers),
            ('obfuscation', protections.obfuscation_techniques),
            ('anti_debug', protections.anti_debug_methods),
            ('anti_vm', protections.anti_vm_methods),
            ('code_integrity', protections.code_integrity_checks),
            ('licensing', protections.licensing_mechanisms)
        ]
        
        for category, protection_list in protection_lists:
            for i, protection in enumerate(protection_list):
                if not isinstance(protection, dict):
                    self._add_error("protections", f"Invalid protection format in {category}[{i}]")
                    continue
                    
                # Validate required fields
                if 'type' not in protection:
                    self._add_warning("protections", f"Protection in {category}[{i}] missing type field")
                    
                # Validate confidence if present
                if 'confidence' in protection:
                    confidence = protection['confidence']
                    if isinstance(confidence, ConfidenceLevel):
                        continue
                    elif isinstance(confidence, (int, float)):
                        if not 0 <= confidence <= 100:
                            self._add_warning("protections", 
                                            f"Invalid confidence value in {category}[{i}]: {confidence}")
                    else:
                        self._add_warning("protections", 
                                        f"Invalid confidence type in {category}[{i}]: {type(confidence)}")
                        
    def _validate_vulnerabilities(self, vulnerabilities: VulnerabilityAnalysis) -> None:
        """Validate vulnerability analysis data."""
        vuln_lists = [
            ('buffer_overflows', vulnerabilities.buffer_overflows),
            ('format_string_bugs', vulnerabilities.format_string_bugs),
            ('integer_overflows', vulnerabilities.integer_overflows),
            ('use_after_free', vulnerabilities.use_after_free),
            ('code_injection_points', vulnerabilities.code_injection_points),
            ('licensing_bypasses', vulnerabilities.licensing_bypasses)
        ]
        
        for category, vuln_list in vuln_lists:
            for i, vuln in enumerate(vuln_list):
                if not isinstance(vuln, dict):
                    self._add_error("vulnerabilities", f"Invalid vulnerability format in {category}[{i}]")
                    continue
                    
                # Validate address if present
                if 'address' in vuln:
                    address = vuln['address']
                    if not isinstance(address, int) or address < 0:
                        self._add_warning("vulnerabilities", 
                                        f"Invalid address in {category}[{i}]: {address}")
                        
                # Validate severity if present
                if 'severity' in vuln:
                    severity = vuln['severity']
                    valid_severities = {'low', 'medium', 'high', 'critical'}
                    if severity not in valid_severities:
                        self._add_warning("vulnerabilities", 
                                        f"Invalid severity in {category}[{i}]: {severity}")
                        
    def _validate_runtime_behavior(self, runtime_behavior: Optional[RuntimeBehavior]) -> None:
        """Validate runtime behavior data if present."""
        if not runtime_behavior:
            return
            
        # Validate execution time
        if runtime_behavior.execution_time < 0:
            self._add_error("runtime", f"Invalid execution time: {runtime_behavior.execution_time}")
            
        # Validate memory usage
        if runtime_behavior.memory_usage:
            for key, value in runtime_behavior.memory_usage.items():
                if not isinstance(value, (int, float)) or value < 0:
                    self._add_warning("runtime", f"Invalid memory usage value for {key}: {value}")
                    
        # Validate system calls
        for i, syscall in enumerate(runtime_behavior.system_calls):
            if not isinstance(syscall, dict):
                self._add_warning("runtime", f"Invalid system call format at index {i}")
            elif 'name' not in syscall:
                self._add_warning("runtime", f"System call at index {i} missing name")
                
    def _validate_consistency(self, model: UnifiedBinaryModel) -> None:
        """Validate consistency across different analysis components."""
        # Check if entry point function exists
        if model.metadata.entry_point > 0:
            entry_point_found = any(
                func.address <= model.metadata.entry_point < func.address + func.size
                for func in model.functions.values()
                if func.size > 0
            )
            if not entry_point_found:
                self._add_warning("consistency", 
                                f"Entry point {model.metadata.entry_point:x} not found in function list")
                
        # Check if imported functions have corresponding symbols
        import_addresses = set(model.symbols.imports.keys())
        function_addresses = set(model.functions.keys())
        
        missing_import_functions = import_addresses - function_addresses
        if missing_import_functions:
            self._add_info("consistency", 
                          f"{len(missing_import_functions)} imported functions not in function list")
            
    def _validate_completeness(self, model: UnifiedBinaryModel) -> None:
        """Validate completeness of analysis."""
        # Check for minimum expected data
        if not model.functions and not model.symbols.imports:
            self._add_warning("completeness", "No functions or imports found - analysis may be incomplete")
            
        # Check for section data
        if not model.sections:
            self._add_warning("completeness", "No sections found - static analysis may be incomplete")
            
        # Check analysis timeline
        if not model.analysis_timeline:
            self._add_warning("completeness", "No analysis timeline - tracking may be incomplete")
            
        # Check for tool results
        if not model.tool_results:
            self._add_warning("completeness", "No tool results stored - original data not preserved")
            
    def _check_function_overlaps(self, address_ranges: List[Tuple[int, int, str]]) -> None:
        """Check for overlapping function address ranges."""
        sorted_ranges = sorted(address_ranges)
        
        for i in range(len(sorted_ranges) - 1):
            current = sorted_ranges[i]
            next_range = sorted_ranges[i + 1]
            
            if current[1] > next_range[0]:  # Overlap detected
                self._add_warning("functions", 
                                f"Function overlap: {current[2]} ({current[0]:x}-{current[1]:x}) "
                                f"overlaps with {next_range[2]} ({next_range[0]:x}-{next_range[1]:x})")
                                
    def _check_section_overlaps(self, address_ranges: List[Tuple[int, int, str]]) -> None:
        """Check for overlapping section address ranges."""
        sorted_ranges = sorted(address_ranges)
        
        for i in range(len(sorted_ranges) - 1):
            current = sorted_ranges[i]
            next_range = sorted_ranges[i + 1]
            
            if current[1] > next_range[0]:  # Overlap detected
                self._add_warning("sections", 
                                f"Section overlap: {current[2]} ({current[0]:x}-{current[1]:x}) "
                                f"overlaps with {next_range[2]} ({next_range[0]:x}-{next_range[1]:x})")
                                
    def _find_symbol_overlaps(self, symbols: SymbolDatabase) -> Set[int]:
        """Find addresses used by multiple symbol types."""
        all_addresses = []
        all_addresses.extend(symbols.imports.keys())
        all_addresses.extend(symbols.exports.keys())
        all_addresses.extend(symbols.strings.keys())
        
        seen = set()
        overlaps = set()
        
        for addr in all_addresses:
            if addr in seen:
                overlaps.add(addr)
            else:
                seen.add(addr)
                
        return overlaps
        
    def _add_error(self, category: str, message: str, context: Optional[Dict[str, Any]] = None) -> None:
        """Add a validation error."""
        self.errors.append(ValidationError('error', category, message, context))
        
    def _add_warning(self, category: str, message: str, context: Optional[Dict[str, Any]] = None) -> None:
        """Add a validation warning."""
        self.warnings.append(ValidationError('warning', category, message, context))
        
    def _add_info(self, category: str, message: str, context: Optional[Dict[str, Any]] = None) -> None:
        """Add a validation info message."""
        self.info.append(ValidationError('info', category, message, context))
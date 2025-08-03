"""
Unified Binary Model Builder

This module provides the UnifiedModelBuilder class responsible for constructing
UnifiedBinaryModel instances from various analysis tool outputs. It handles
the integration of results from different analysis phases and tools.
"""

import hashlib
import logging
import time
from pathlib import Path
from typing import Dict, Any, Optional, List, Set

from .model import (
    UnifiedBinaryModel, BinaryMetadata, FunctionInfo, SymbolDatabase,
    SectionInfo, ProtectionAnalysis, VulnerabilityAnalysis, RuntimeBehavior,
    AnalysisEvent, ValidationResult, AnalysisPhase, AnalysisSource,
    ConfidenceLevel, ProtectionType, VulnerabilityType
)


class UnifiedModelBuilder:
    """
    Builds unified binary models from various analysis tool outputs.
    
    This class orchestrates the integration of results from multiple analysis
    tools into a coherent, validated unified model.
    """
    
    def __init__(self, binary_path: str, logger: Optional[logging.Logger] = None):
        """
        Initialize the model builder.
        
        Args:
            binary_path: Path to the binary being analyzed
            logger: Optional logger instance
        """
        self.binary_path = Path(binary_path)
        self.logger = logger or logging.getLogger(__name__)
        self.model: Optional[UnifiedBinaryModel] = None
        
    def create_initial_model(self) -> UnifiedBinaryModel:
        """
        Create the initial unified model with basic metadata.
        
        Returns:
            Initial UnifiedBinaryModel instance
        """
        # Calculate file hash
        file_hash = self._calculate_file_hash()
        
        # Get basic file metadata
        stat = self.binary_path.stat()
        
        # Create initial metadata
        metadata = BinaryMetadata(
            filename=self.binary_path.name,
            file_size=stat.st_size,
            creation_time=stat.st_ctime,
            modification_time=stat.st_mtime,
            file_format="unknown",
            architecture="unknown",
            endianness="unknown",
            entry_point=0,
            base_address=0,
            compiler_info={},
            debug_info_present=False,
            stripped=False,
            digital_signature=None
        )
        
        # Create initial model
        self.model = UnifiedBinaryModel(
            binary_path=str(self.binary_path),
            file_hash=file_hash,
            metadata=metadata,
            functions={},
            symbols=SymbolDatabase(
                imports={},
                exports={},
                strings={},
                symbols_by_address={}
            ),
            sections={},
            protections=ProtectionAnalysis(
                packers=[],
                obfuscation_techniques=[],
                anti_debug_methods=[],
                anti_vm_methods=[],
                code_integrity_checks=[],
                licensing_mechanisms=[],
                protection_confidence={}
            ),
            vulnerabilities=VulnerabilityAnalysis(
                buffer_overflows=[],
                format_string_bugs=[],
                integer_overflows=[],
                use_after_free=[],
                code_injection_points=[],
                licensing_bypasses=[],
                vulnerability_scores={}
            ),
            runtime_behavior=None,
            tool_results={},
            analysis_timeline=[],
            data_confidence={},
            validation_status=None
        )
        
        # Log initial model creation
        self._add_event(AnalysisPhase.INITIALIZATION, AnalysisSource.BUILDER,
                       "Created initial unified model", {"file_hash": file_hash})
        
        self.logger.info(f"Created initial unified model for {self.binary_path}")
        return self.model
        
    def integrate_basic_analysis(self, result: Dict[str, Any]) -> None:
        """
        Integrate basic binary analysis results.
        
        Args:
            result: Dictionary containing basic analysis results
        """
        if not self.model:
            raise ValueError("Model not initialized. Call create_initial_model() first.")
            
        self.logger.debug("Integrating basic analysis results")
        
        # Update metadata from basic analysis
        if 'format' in result:
            self.model.metadata.file_format = result['format']
            
        if 'file_info' in result:
            file_info = result['file_info']
            if 'architecture' in file_info:
                self.model.metadata.architecture = file_info['architecture']
            if 'endianness' in file_info:
                self.model.metadata.endianness = file_info['endianness']
            if 'entry_point' in file_info:
                self.model.metadata.entry_point = file_info['entry_point']
                
        # Store raw tool results
        self.model.tool_results['basic_analysis'] = result
        
        # Add to timeline
        self._add_event(AnalysisPhase.STATIC_ANALYSIS, AnalysisSource.BINARY_ANALYZER,
                       "Integrated basic analysis", {"format": result.get('format', 'unknown')})
        
    def integrate_radare2_analysis(self, result: Dict[str, Any]) -> None:
        """
        Integrate Radare2 analysis results.
        
        Args:
            result: Dictionary containing Radare2 analysis results
        """
        if not self.model:
            raise ValueError("Model not initialized")
            
        self.logger.debug("Integrating Radare2 analysis results")
        
        # Process imports
        if 'imports' in result:
            for imp in result['imports']:
                address = imp.get('plt', 0)
                self.model.symbols.imports[address] = {
                    'name': imp.get('name', ''),
                    'library': imp.get('libname', ''),
                    'type': imp.get('type', ''),
                    'source': AnalysisSource.RADARE2,
                    'confidence': ConfidenceLevel.HIGH
                }
                
        # Process exports
        if 'exports' in result:
            for exp in result['exports']:
                address = exp.get('vaddr', 0)
                self.model.symbols.exports[address] = {
                    'name': exp.get('name', ''),
                    'type': exp.get('type', ''),
                    'size': exp.get('size', 0),
                    'source': AnalysisSource.RADARE2,
                    'confidence': ConfidenceLevel.HIGH
                }
                
        # Process functions
        if 'functions' in result:
            for func in result['functions']:
                address = func.get('offset', 0)
                self.model.functions[address] = FunctionInfo(
                    address=address,
                    name=func.get('name', f'sub_{address:x}'),
                    size=func.get('size', 0),
                    signature='',
                    calls_to=[],
                    calls_from=[],
                    local_variables=[],
                    parameters=[],
                    return_type='unknown',
                    complexity_score=0,
                    is_library_function=False,
                    decompiled_code='',
                    analysis_notes='',
                    confidence=ConfidenceLevel.HIGH,
                    source=AnalysisSource.RADARE2
                )
                
        # Process sections
        if 'sections' in result:
            for section in result['sections']:
                name = section.get('name', '')
                self.model.sections[name] = SectionInfo(
                    name=name,
                    virtual_address=section.get('vaddr', 0),
                    virtual_size=section.get('vsize', 0),
                    raw_address=section.get('paddr', 0),
                    raw_size=section.get('size', 0),
                    permissions=section.get('perm', ''),
                    entropy=section.get('entropy', 0.0),
                    contains_code=bool(section.get('perm', '').find('x') != -1),
                    contains_data=True,
                    analysis_notes='',
                    source=AnalysisSource.RADARE2
                )
                
        # Store raw results
        self.model.tool_results['radare2'] = result
        
        # Add to timeline
        self._add_event(AnalysisPhase.STATIC_ANALYSIS, AnalysisSource.RADARE2,
                       "Integrated Radare2 analysis", {
                           "functions_count": len(result.get('functions', [])),
                           "imports_count": len(result.get('imports', [])),
                           "exports_count": len(result.get('exports', []))
                       })
        
    def integrate_ghidra_analysis(self, result: Dict[str, Any]) -> None:
        """
        Integrate Ghidra decompilation results.
        
        Args:
            result: Dictionary containing Ghidra analysis results
        """
        if not self.model:
            raise ValueError("Model not initialized")
            
        self.logger.debug("Integrating Ghidra analysis results")
        
        # Process license functions
        if 'license_functions' in result:
            for func_data in result['license_functions']:
                address = func_data.get('address', 0)
                
                # Update existing function or create new one
                if address in self.model.functions:
                    func = self.model.functions[address]
                    func.decompiled_code = func_data.get('decompiled_code', '')
                    func.analysis_notes = func_data.get('analysis', '')
                    func.signature = func_data.get('signature', '')
                else:
                    self.model.functions[address] = FunctionInfo(
                        address=address,
                        name=func_data.get('name', f'license_func_{address:x}'),
                        size=func_data.get('size', 0),
                        signature=func_data.get('signature', ''),
                        calls_to=[],
                        calls_from=[],
                        local_variables=[],
                        parameters=[],
                        return_type='unknown',
                        complexity_score=0,
                        is_library_function=False,
                        decompiled_code=func_data.get('decompiled_code', ''),
                        analysis_notes=func_data.get('analysis', ''),
                        confidence=ConfidenceLevel.HIGH,
                        source=AnalysisSource.GHIDRA
                    )
                    
                # Add licensing protection information
                self.model.protections.licensing_mechanisms.append({
                    'type': 'license_function',
                    'address': address,
                    'name': func_data.get('name', ''),
                    'confidence': ConfidenceLevel.HIGH,
                    'details': func_data.get('analysis', '')
                })
                
        # Store raw results
        self.model.tool_results['ghidra'] = result
        
        # Add to timeline
        self._add_event(AnalysisPhase.DECOMPILATION, AnalysisSource.GHIDRA,
                       "Integrated Ghidra analysis", {
                           "license_functions": len(result.get('license_functions', []))
                       })
        
    def integrate_vulnerability_analysis(self, result: Dict[str, Any]) -> None:
        """
        Integrate vulnerability analysis results.
        
        Args:
            result: Dictionary containing vulnerability analysis results
        """
        if not self.model:
            raise ValueError("Model not initialized")
            
        self.logger.debug("Integrating vulnerability analysis results")
        
        # Process different vulnerability types
        if 'buffer_overflows' in result:
            self.model.vulnerabilities.buffer_overflows.extend(result['buffer_overflows'])
            
        if 'format_string_bugs' in result:
            self.model.vulnerabilities.format_string_bugs.extend(result['format_string_bugs'])
            
        if 'licensing_bypasses' in result:
            self.model.vulnerabilities.licensing_bypasses.extend(result['licensing_bypasses'])
            
        # Store raw results
        self.model.tool_results['vulnerability_analysis'] = result
        
        # Add to timeline
        self._add_event(AnalysisPhase.VULNERABILITY_ANALYSIS, AnalysisSource.VULNERABILITY_ENGINE,
                       "Integrated vulnerability analysis", {
                           "vulnerabilities_found": sum(len(v) for v in [
                               result.get('buffer_overflows', []),
                               result.get('format_string_bugs', []),
                               result.get('licensing_bypasses', [])
                           ])
                       })
        
    def integrate_protection_analysis(self, result: Dict[str, Any]) -> None:
        """
        Integrate protection mechanism analysis results.
        
        Args:
            result: Dictionary containing protection analysis results
        """
        if not self.model:
            raise ValueError("Model not initialized")
            
        self.logger.debug("Integrating protection analysis results")
        
        # Process different protection types
        if 'packers' in result:
            self.model.protections.packers.extend(result['packers'])
            
        if 'obfuscation' in result:
            self.model.protections.obfuscation_techniques.extend(result['obfuscation'])
            
        if 'anti_debug' in result:
            self.model.protections.anti_debug_methods.extend(result['anti_debug'])
            
        if 'anti_vm' in result:
            self.model.protections.anti_vm_methods.extend(result['anti_vm'])
            
        # Store raw results
        self.model.tool_results['protection_analysis'] = result
        
        # Add to timeline
        self._add_event(AnalysisPhase.PROTECTION_ANALYSIS, AnalysisSource.YARA_ENGINE,
                       "Integrated protection analysis", {
                           "protections_found": sum(len(p) for p in [
                               result.get('packers', []),
                               result.get('obfuscation', []),
                               result.get('anti_debug', []),
                               result.get('anti_vm', [])
                           ])
                       })
        
    def integrate_dynamic_analysis(self, result: Dict[str, Any]) -> None:
        """
        Integrate dynamic analysis results.
        
        Args:
            result: Dictionary containing dynamic analysis results
        """
        if not self.model:
            raise ValueError("Model not initialized")
            
        self.logger.debug("Integrating dynamic analysis results")
        
        # Create runtime behavior model
        self.model.runtime_behavior = RuntimeBehavior(
            execution_time=result.get('execution_time', 0.0),
            memory_usage=result.get('memory_usage', {}),
            system_calls=result.get('system_calls', []),
            network_activity=result.get('network_activity', []),
            file_operations=result.get('file_operations', []),
            registry_operations=result.get('registry_operations', []),
            process_creation=result.get('process_creation', []),
            code_injection_attempts=result.get('code_injection', []),
            debugger_detection_attempts=result.get('debugger_detection', []),
            vm_detection_attempts=result.get('vm_detection', []),
            licensing_checks=result.get('licensing_checks', []),
            crash_locations=result.get('crashes', []),
            analysis_notes=result.get('notes', '')
        )
        
        # Store raw results
        self.model.tool_results['dynamic_analysis'] = result
        
        # Add to timeline
        self._add_event(AnalysisPhase.DYNAMIC_ANALYSIS, AnalysisSource.DYNAMIC_ANALYZER,
                       "Integrated dynamic analysis", {
                           "execution_time": result.get('execution_time', 0.0),
                           "system_calls": len(result.get('system_calls', []))
                       })
        
    def finalize_model(self) -> UnifiedBinaryModel:
        """
        Finalize the unified model by performing validation and cleanup.
        
        Returns:
            Completed and validated UnifiedBinaryModel
        """
        if not self.model:
            raise ValueError("Model not initialized")
            
        self.logger.info("Finalizing unified model")
        
        # Calculate overall confidence scores
        self._calculate_confidence_scores()
        
        # Perform model validation
        self._validate_model()
        
        # Add finalization event
        self._add_event(AnalysisPhase.FINALIZATION, AnalysisSource.BUILDER,
                       "Model finalized", {
                           "total_functions": len(self.model.functions),
                           "total_sections": len(self.model.sections),
                           "total_events": len(self.model.analysis_timeline)
                       })
        
        self.logger.info(f"Unified model finalized with {len(self.model.functions)} functions "
                        f"and {len(self.model.sections)} sections")
        
        return self.model
        
    def _calculate_file_hash(self) -> str:
        """Calculate SHA256 hash of the binary file."""
        hasher = hashlib.sha256()
        with open(self.binary_path, 'rb') as f:
            for chunk in iter(lambda: f.read(4096), b""):
                hasher.update(chunk)
        return hasher.hexdigest()
        
    def _add_event(self, phase: AnalysisPhase, source: AnalysisSource, 
                   description: str, metadata: Dict[str, Any]) -> None:
        """Add an event to the analysis timeline."""
        if self.model:
            event = AnalysisEvent(
                timestamp=time.time(),
                phase=phase,
                source=source,
                description=description,
                metadata=metadata
            )
            self.model.analysis_timeline.append(event)
            
    def _calculate_confidence_scores(self) -> None:
        """Calculate confidence scores for different data categories."""
        if not self.model:
            return
            
        # Calculate function analysis confidence
        if self.model.functions:
            total_confidence = sum(
                func.confidence.value for func in self.model.functions.values()
                if hasattr(func.confidence, 'value')
            )
            avg_confidence = total_confidence / len(self.model.functions)
            self.model.data_confidence['functions'] = avg_confidence / 100.0
            
        # Calculate symbol confidence
        symbol_sources = set()
        for imports in [self.model.symbols.imports, self.model.symbols.exports]:
            for symbol_data in imports.values():
                if isinstance(symbol_data, dict) and 'source' in symbol_data:
                    symbol_sources.add(symbol_data['source'])
        self.model.data_confidence['symbols'] = len(symbol_sources) / 3.0  # Normalize by max sources
        
        # Calculate overall confidence
        if self.model.data_confidence:
            overall = sum(self.model.data_confidence.values()) / len(self.model.data_confidence)
            self.model.data_confidence['overall'] = overall
            
    def _validate_model(self) -> None:
        """Validate the completed model for consistency."""
        if not self.model:
            return
            
        errors = []
        warnings = []
        
        # Validate basic metadata
        if not self.model.metadata.file_format or self.model.metadata.file_format == "unknown":
            warnings.append("File format not determined")
            
        if not self.model.metadata.architecture or self.model.metadata.architecture == "unknown":
            warnings.append("Architecture not determined")
            
        # Validate functions
        for addr, func in self.model.functions.items():
            if func.address != addr:
                errors.append(f"Function address mismatch: {addr} != {func.address}")
                
        # Validate sections
        for name, section in self.model.sections.items():
            if section.name != name:
                errors.append(f"Section name mismatch: {name} != {section.name}")
                
        # Create validation result
        self.model.validation_status = ValidationResult(
            is_valid=len(errors) == 0,
            errors=errors,
            warnings=warnings,
            validation_time=time.time()
        )
        
        if errors:
            self.logger.error(f"Model validation failed with {len(errors)} errors: {errors}")
        elif warnings:
            self.logger.warning(f"Model validation completed with {len(warnings)} warnings: {warnings}")
        else:
            self.logger.info("Model validation passed successfully")
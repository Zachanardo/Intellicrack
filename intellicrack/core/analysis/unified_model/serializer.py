"""
Model Serializer for Unified Binary Model

This module provides the ModelSerializer class responsible for saving
and loading unified binary models to/from persistent storage.
"""

import json
import pickle
import gzip
import logging
import time
from pathlib import Path
from typing import Dict, Any, Optional, Union
from dataclasses import asdict, is_dataclass
from enum import Enum

from .model import (
    UnifiedBinaryModel, BinaryMetadata, FunctionInfo, SymbolDatabase,
    SectionInfo, ProtectionAnalysis, VulnerabilityAnalysis, RuntimeBehavior,
    AnalysisEvent, ValidationResult, AnalysisPhase, AnalysisSource,
    ConfidenceLevel, ProtectionType, VulnerabilityType
)


class SerializationFormat(Enum):
    """Supported serialization formats."""
    JSON = "json"
    JSON_COMPRESSED = "json.gz"
    PICKLE = "pickle"
    PICKLE_COMPRESSED = "pickle.gz"


class ModelSerializer:
    """
    Handles serialization and deserialization of unified binary models.
    
    This class provides methods to save unified models to disk and load them back,
    supporting multiple formats including JSON and binary pickle formats with
    optional compression.
    """
    
    def __init__(self, logger: Optional[logging.Logger] = None):
        """
        Initialize the model serializer.
        
        Args:
            logger: Optional logger instance
        """
        self.logger = logger or logging.getLogger(__name__)
        
    def save_model(self, model: UnifiedBinaryModel, output_path: Union[str, Path],
                   format_type: SerializationFormat = SerializationFormat.JSON_COMPRESSED) -> bool:
        """
        Save a unified model to disk.
        
        Args:
            model: UnifiedBinaryModel to save
            output_path: Path to save the model
            format_type: Serialization format to use
            
        Returns:
            True if successful, False otherwise
        """
        output_path = Path(output_path)
        
        try:
            self.logger.info(f"Saving unified model to {output_path} in {format_type.value} format")
            
            # Ensure output directory exists
            output_path.parent.mkdir(parents=True, exist_ok=True)
            
            # Convert model to serializable format
            model_data = self._model_to_dict(model)
            
            # Add metadata
            model_data['_serialization_metadata'] = {
                'format': format_type.value,
                'version': '1.0',
                'timestamp': time.time(),
                'serializer': 'ModelSerializer'
            }
            
            # Save based on format
            if format_type == SerializationFormat.JSON:
                self._save_json(model_data, output_path)
            elif format_type == SerializationFormat.JSON_COMPRESSED:
                self._save_json_compressed(model_data, output_path)
            elif format_type == SerializationFormat.PICKLE:
                self._save_pickle(model_data, output_path)
            elif format_type == SerializationFormat.PICKLE_COMPRESSED:
                self._save_pickle_compressed(model_data, output_path)
            else:
                raise ValueError(f"Unsupported serialization format: {format_type}")
                
            self.logger.info(f"Successfully saved unified model to {output_path}")
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to save unified model: {e}")
            return False
            
    def load_model(self, input_path: Union[str, Path]) -> Optional[UnifiedBinaryModel]:
        """
        Load a unified model from disk.
        
        Args:
            input_path: Path to load the model from
            
        Returns:
            UnifiedBinaryModel if successful, None otherwise
        """
        input_path = Path(input_path)
        
        if not input_path.exists():
            self.logger.error(f"Model file not found: {input_path}")
            return None
            
        try:
            self.logger.info(f"Loading unified model from {input_path}")
            
            # Determine format from file extension
            format_type = self._detect_format(input_path)
            
            # Load based on format
            if format_type == SerializationFormat.JSON:
                model_data = self._load_json(input_path)
            elif format_type == SerializationFormat.JSON_COMPRESSED:
                model_data = self._load_json_compressed(input_path)
            elif format_type == SerializationFormat.PICKLE:
                model_data = self._load_pickle(input_path)
            elif format_type == SerializationFormat.PICKLE_COMPRESSED:
                model_data = self._load_pickle_compressed(input_path)
            else:
                raise ValueError(f"Unsupported file format: {input_path.suffix}")
                
            # Convert back to model
            model = self._dict_to_model(model_data)
            
            self.logger.info(f"Successfully loaded unified model from {input_path}")
            return model
            
        except Exception as e:
            self.logger.error(f"Failed to load unified model: {e}")
            return None
            
    def export_summary(self, model: UnifiedBinaryModel, output_path: Union[str, Path]) -> bool:
        """
        Export a human-readable summary of the model.
        
        Args:
            model: UnifiedBinaryModel to summarize
            output_path: Path to save the summary
            
        Returns:
            True if successful, False otherwise
        """
        output_path = Path(output_path)
        
        try:
            self.logger.info(f"Exporting model summary to {output_path}")
            
            # Generate summary
            summary = self._generate_summary(model)
            
            # Write summary to file
            with open(output_path, 'w', encoding='utf-8') as f:
                f.write(summary)
                
            self.logger.info(f"Successfully exported model summary to {output_path}")
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to export model summary: {e}")
            return False
            
    def _model_to_dict(self, model: UnifiedBinaryModel) -> Dict[str, Any]:
        """Convert UnifiedBinaryModel to dictionary for serialization."""
        # Convert dataclass to dict
        model_dict = asdict(model)
        
        # Convert enums to their values
        model_dict = self._convert_enums_to_values(model_dict)
        
        return model_dict
        
    def _dict_to_model(self, data: Dict[str, Any]) -> UnifiedBinaryModel:
        """Convert dictionary back to UnifiedBinaryModel."""
        # Remove serialization metadata if present
        data.pop('_serialization_metadata', None)
        
        # Convert enum values back to enums
        data = self._convert_values_to_enums(data)
        
        # Reconstruct nested dataclasses
        metadata = BinaryMetadata(**data['metadata'])
        
        # Reconstruct functions
        functions = {}
        for addr_str, func_data in data['functions'].items():
            functions[int(addr_str)] = FunctionInfo(**func_data)
            
        # Reconstruct symbols
        symbols = SymbolDatabase(**data['symbols'])
        
        # Reconstruct sections
        sections = {}
        for name, section_data in data['sections'].items():
            sections[name] = SectionInfo(**section_data)
            
        # Reconstruct protections
        protections = ProtectionAnalysis(**data['protections'])
        
        # Reconstruct vulnerabilities
        vulnerabilities = VulnerabilityAnalysis(**data['vulnerabilities'])
        
        # Reconstruct runtime behavior
        runtime_behavior = None
        if data['runtime_behavior']:
            runtime_behavior = RuntimeBehavior(**data['runtime_behavior'])
            
        # Reconstruct analysis timeline
        timeline = []
        for event_data in data['analysis_timeline']:
            timeline.append(AnalysisEvent(**event_data))
            
        # Reconstruct validation status
        validation_status = None
        if data['validation_status']:
            validation_status = ValidationResult(**data['validation_status'])
            
        return UnifiedBinaryModel(
            binary_path=data['binary_path'],
            file_hash=data['file_hash'],
            metadata=metadata,
            functions=functions,
            symbols=symbols,
            sections=sections,
            protections=protections,
            vulnerabilities=vulnerabilities,
            runtime_behavior=runtime_behavior,
            tool_results=data['tool_results'],
            analysis_timeline=timeline,
            data_confidence=data['data_confidence'],
            validation_status=validation_status
        )
        
    def _convert_enums_to_values(self, data: Any) -> Any:
        """Recursively convert enum instances to their values."""
        if isinstance(data, Enum):
            return data.value
        elif isinstance(data, dict):
            return {key: self._convert_enums_to_values(value) for key, value in data.items()}
        elif isinstance(data, list):
            return [self._convert_enums_to_values(item) for item in data]
        else:
            return data
            
    def _convert_values_to_enums(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Convert enum values back to enum instances."""
        # This is a simplified version - in practice, you'd need to track
        # which fields should be converted to which enum types
        
        def convert_field(field_name: str, value: Any) -> Any:
            if field_name == 'source' and isinstance(value, str):
                try:
                    return AnalysisSource(value)
                except ValueError:
                    return value
            elif field_name == 'confidence' and isinstance(value, str):
                try:
                    return ConfidenceLevel(value)
                except ValueError:
                    return value
            elif field_name == 'phase' and isinstance(value, str):
                try:
                    return AnalysisPhase(value)
                except ValueError:
                    return value
            return value
            
        def process_dict(d: Dict[str, Any]) -> Dict[str, Any]:
            result = {}
            for key, value in d.items():
                if isinstance(value, dict):
                    result[key] = process_dict(value)
                elif isinstance(value, list):
                    result[key] = [process_dict(item) if isinstance(item, dict) else convert_field(key, item) 
                                  for item in value]
                else:
                    result[key] = convert_field(key, value)
            return result
            
        return process_dict(data)
        
    def _detect_format(self, path: Path) -> SerializationFormat:
        """Detect serialization format from file extension."""
        suffix = path.suffix.lower()
        
        if suffix == '.json':
            return SerializationFormat.JSON
        elif suffix == '.gz' and path.stem.endswith('.json'):
            return SerializationFormat.JSON_COMPRESSED
        elif suffix == '.pickle':
            return SerializationFormat.PICKLE
        elif suffix == '.gz' and path.stem.endswith('.pickle'):
            return SerializationFormat.PICKLE_COMPRESSED
        else:
            # Default to JSON for unknown extensions
            return SerializationFormat.JSON
            
    def _save_json(self, data: Dict[str, Any], path: Path) -> None:
        """Save data as JSON."""
        with open(path, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=2, default=str)
            
    def _save_json_compressed(self, data: Dict[str, Any], path: Path) -> None:
        """Save data as compressed JSON."""
        json_str = json.dumps(data, default=str)
        with gzip.open(path, 'wt', encoding='utf-8') as f:
            f.write(json_str)
            
    def _save_pickle(self, data: Dict[str, Any], path: Path) -> None:
        """Save data as pickle."""
        with open(path, 'wb') as f:
            pickle.dump(data, f, protocol=pickle.HIGHEST_PROTOCOL)
            
    def _save_pickle_compressed(self, data: Dict[str, Any], path: Path) -> None:
        """Save data as compressed pickle."""
        with gzip.open(path, 'wb') as f:
            pickle.dump(data, f, protocol=pickle.HIGHEST_PROTOCOL)
            
    def _load_json(self, path: Path) -> Dict[str, Any]:
        """Load data from JSON."""
        with open(path, 'r', encoding='utf-8') as f:
            return json.load(f)
            
    def _load_json_compressed(self, path: Path) -> Dict[str, Any]:
        """Load data from compressed JSON."""
        with gzip.open(path, 'rt', encoding='utf-8') as f:
            return json.load(f)
            
    def _load_pickle(self, path: Path) -> Dict[str, Any]:
        """Load data from pickle."""
        with open(path, 'rb') as f:
            return pickle.load(f)
            
    def _load_pickle_compressed(self, path: Path) -> Dict[str, Any]:
        """Load data from compressed pickle."""
        with gzip.open(path, 'rb') as f:
            return pickle.load(f)
            
    def _generate_summary(self, model: UnifiedBinaryModel) -> str:
        """Generate a human-readable summary of the model."""
        lines = []
        lines.append("=" * 80)
        lines.append("UNIFIED BINARY MODEL SUMMARY")
        lines.append("=" * 80)
        lines.append("")
        
        # Basic information
        lines.append(f"Binary Path: {model.binary_path}")
        lines.append(f"File Hash: {model.file_hash}")
        lines.append("")
        
        # Metadata
        lines.append("METADATA:")
        lines.append(f"  Format: {model.metadata.file_format}")
        lines.append(f"  Architecture: {model.metadata.architecture}")
        lines.append(f"  Endianness: {model.metadata.endianness}")
        lines.append(f"  Entry Point: 0x{model.metadata.entry_point:x}")
        lines.append(f"  Base Address: 0x{model.metadata.base_address:x}")
        lines.append(f"  File Size: {model.metadata.file_size:,} bytes")
        lines.append("")
        
        # Functions
        lines.append(f"FUNCTIONS: {len(model.functions)} total")
        if model.functions:
            # Group functions by source
            by_source = {}
            for func in model.functions.values():
                source = func.source.value if hasattr(func.source, 'value') else str(func.source)
                by_source.setdefault(source, []).append(func)
                
            for source, funcs in by_source.items():
                lines.append(f"  {source}: {len(funcs)} functions")
                
        lines.append("")
        
        # Symbols
        lines.append("SYMBOLS:")
        lines.append(f"  Imports: {len(model.symbols.imports)}")
        lines.append(f"  Exports: {len(model.symbols.exports)}")
        lines.append(f"  Strings: {len(model.symbols.strings)}")
        lines.append("")
        
        # Sections
        lines.append(f"SECTIONS: {len(model.sections)} total")
        if model.sections:
            for name, section in model.sections.items():
                lines.append(f"  {name}: VA=0x{section.virtual_address:x}, "
                           f"Size={section.virtual_size}, Entropy={section.entropy:.2f}")
        lines.append("")
        
        # Protections
        lines.append("PROTECTIONS:")
        lines.append(f"  Packers: {len(model.protections.packers)}")
        lines.append(f"  Obfuscation: {len(model.protections.obfuscation_techniques)}")
        lines.append(f"  Anti-Debug: {len(model.protections.anti_debug_methods)}")
        lines.append(f"  Anti-VM: {len(model.protections.anti_vm_methods)}")
        lines.append(f"  Licensing: {len(model.protections.licensing_mechanisms)}")
        lines.append("")
        
        # Vulnerabilities
        lines.append("VULNERABILITIES:")
        lines.append(f"  Buffer Overflows: {len(model.vulnerabilities.buffer_overflows)}")
        lines.append(f"  Format String: {len(model.vulnerabilities.format_string_bugs)}")
        lines.append(f"  Integer Overflows: {len(model.vulnerabilities.integer_overflows)}")
        lines.append(f"  Use After Free: {len(model.vulnerabilities.use_after_free)}")
        lines.append(f"  Code Injection: {len(model.vulnerabilities.code_injection_points)}")
        lines.append(f"  Licensing Bypasses: {len(model.vulnerabilities.licensing_bypasses)}")
        lines.append("")
        
        # Runtime behavior
        if model.runtime_behavior:
            lines.append("RUNTIME BEHAVIOR:")
            lines.append(f"  Execution Time: {model.runtime_behavior.execution_time:.2f}s")
            lines.append(f"  System Calls: {len(model.runtime_behavior.system_calls)}")
            lines.append(f"  Network Activity: {len(model.runtime_behavior.network_activity)}")
            lines.append(f"  File Operations: {len(model.runtime_behavior.file_operations)}")
            lines.append("")
        
        # Analysis timeline
        lines.append(f"ANALYSIS TIMELINE: {len(model.analysis_timeline)} events")
        if model.analysis_timeline:
            for event in model.analysis_timeline[-5:]:  # Show last 5 events
                timestamp = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(event.timestamp))
                source = event.source.value if hasattr(event.source, 'value') else str(event.source)
                lines.append(f"  [{timestamp}] {source}: {event.description}")
        lines.append("")
        
        # Validation status
        if model.validation_status:
            lines.append("VALIDATION STATUS:")
            lines.append(f"  Valid: {model.validation_status.is_valid}")
            lines.append(f"  Errors: {len(model.validation_status.errors)}")
            lines.append(f"  Warnings: {len(model.validation_status.warnings)}")
            lines.append("")
        
        # Tool results
        lines.append(f"TOOL RESULTS: {len(model.tool_results)} tools")
        for tool_name in model.tool_results.keys():
            lines.append(f"  {tool_name}")
        lines.append("")
        
        lines.append("=" * 80)
        
        return "\n".join(lines)
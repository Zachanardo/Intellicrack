"""Protection pattern engine with advanced detection capabilities.

This module provides the main pattern engine that integrates with existing
analysis components and provides comprehensive protection detection.

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

import logging
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

from .database_manager import ProtectionDatabaseManager
from .pattern_matcher import AdvancedPatternMatcher, ScanResult
from .signature_database import ArchitectureType, ProtectionType
from ..analysis.yara_pattern_engine import YaraPatternEngine, YaraScanResult
import logging

logger = logging.getLogger(__name__)


class ProtectionDetectionResult:
    """Comprehensive protection detection result."""
    
    def __init__(self, file_path: str):
        """Initialize detection result.
        
        Args:
            file_path: Path to analyzed file
        """
        self.file_path = file_path
        self.database_result: Optional[ScanResult] = None
        self.yara_result: Optional[YaraScanResult] = None
        self.combined_detections: Set[str] = set()
        self.confidence_scores: Dict[str, float] = {}
        self.protection_types: Set[ProtectionType] = set()
        self.analysis_metadata: Dict[str, Any] = {}
        self.error: Optional[str] = None
    
    @property
    def has_protections(self) -> bool:
        """Check if any protections were detected."""
        return len(self.combined_detections) > 0
    
    @property
    def high_confidence_detections(self) -> Set[str]:
        """Get protections detected with high confidence (>0.8)."""
        return {name for name, confidence in self.confidence_scores.items() if confidence > 0.8}
    
    @property
    def protection_summary(self) -> Dict[str, Any]:
        """Get summary of detected protections."""
        return {
            'total_detections': len(self.combined_detections),
            'high_confidence_count': len(self.high_confidence_detections),
            'protection_types': [pt.value for pt in self.protection_types],
            'detections': list(self.combined_detections),
            'confidence_scores': self.confidence_scores
        }


class ProtectionPatternEngine:
    """Main protection pattern engine integrating multiple detection methods."""
    
    def __init__(self, database_path: Optional[Path] = None):
        """Initialize the protection pattern engine.
        
        Args:
            database_path: Optional path to protection database
        """
        self.logger = logging.getLogger(__name__)
        
        # Initialize database manager
        self.database_manager = ProtectionDatabaseManager(database_path)
        
        # Initialize YARA engine if available
        try:
            self.yara_engine = YaraPatternEngine()
            self.yara_available = True
            self.logger.info("YARA pattern engine initialized")
        except Exception as e:
            self.yara_engine = None
            self.yara_available = False
            self.logger.warning(f"YARA pattern engine not available: {e}")
        
        # Configuration
        self.config = {
            'use_database': True,
            'use_yara': True,
            'combine_results': True,
            'min_confidence': 0.3,
            'weight_database': 0.7,
            'weight_yara': 0.3,
            'enable_heuristics': True,
            'enable_behavioral_analysis': False
        }
        
        # Load built-in detection rules
        self._load_detection_rules()
    
    def _load_detection_rules(self):
        """Load built-in detection rules and heuristics."""
        # Heuristic detection rules
        self.heuristic_rules = {
            'high_entropy_sections': {
                'description': 'Sections with unusually high entropy (possible packing/encryption)',
                'min_entropy': 7.5,
                'confidence': 0.6
            },
            'suspicious_imports': {
                'description': 'Suspicious API imports often used by protections',
                'api_functions': [
                    'VirtualAlloc', 'VirtualProtect', 'CreateRemoteThread',
                    'WriteProcessMemory', 'ReadProcessMemory', 'NtQueryInformationProcess'
                ],
                'min_count': 3,
                'confidence': 0.5
            },
            'packed_characteristics': {
                'description': 'Characteristics typical of packed executables',
                'indicators': [
                    'small_code_section', 'large_data_section', 'few_imports',
                    'high_entropy', 'unusual_entry_point'
                ],
                'min_indicators': 2,
                'confidence': 0.7
            }
        }
    
    def analyze_file(self, file_path: str, architecture: Optional[ArchitectureType] = None,
                    enable_deep_analysis: bool = False) -> ProtectionDetectionResult:
        """Perform comprehensive protection analysis on a file.
        
        Args:
            file_path: Path to file to analyze
            architecture: Optional architecture hint
            enable_deep_analysis: Enable deep behavioral analysis
            
        Returns:
            Comprehensive detection results
        """
        result = ProtectionDetectionResult(file_path)
        
        try:
            # Database-based detection
            if self.config['use_database']:
                result.database_result = self.database_manager.scan_file(file_path, architecture=architecture)
                if result.database_result.error:
                    result.error = result.database_result.error
                    return result
                
                # Extract detections from database result
                for match in result.database_result.matches:
                    if match.adjusted_confidence >= self.config['min_confidence']:
                        result.combined_detections.add(match.signature_name)
                        result.confidence_scores[match.signature_name] = match.adjusted_confidence
                        result.protection_types.add(match.protection_type)
            
            # YARA-based detection
            if self.config['use_yara'] and self.yara_available:
                try:
                    result.yara_result = self.yara_engine.scan_file(file_path)
                    
                    # Extract detections from YARA result
                    for match in result.yara_result.matches:
                        if match.confidence >= self.config['min_confidence']:
                            result.combined_detections.add(match.rule_name)
                            
                            # Combine confidence scores if detection exists in both
                            existing_confidence = result.confidence_scores.get(match.rule_name, 0.0)
                            if existing_confidence > 0:
                                # Weighted average
                                combined_confidence = (
                                    existing_confidence * self.config['weight_database'] +
                                    match.confidence * self.config['weight_yara']
                                )
                            else:
                                combined_confidence = match.confidence
                            
                            result.confidence_scores[match.rule_name] = combined_confidence
                            
                            # Map YARA categories to protection types
                            if hasattr(match, 'category'):
                                result.protection_types.add(self._map_yara_category(match.category))
                
                except Exception as e:
                    self.logger.warning(f"YARA scanning failed: {e}")
            
            # Heuristic analysis
            if self.config['enable_heuristics']:
                heuristic_detections = self._perform_heuristic_analysis(file_path)
                for detection, confidence in heuristic_detections.items():
                    if confidence >= self.config['min_confidence']:
                        result.combined_detections.add(detection)
                        result.confidence_scores[detection] = confidence
                        result.protection_types.add(ProtectionType.CUSTOM)
            
            # Behavioral analysis (if enabled)
            if self.config['enable_behavioral_analysis'] and enable_deep_analysis:
                behavioral_detections = self._perform_behavioral_analysis(file_path)
                result.analysis_metadata['behavioral'] = behavioral_detections
            
            # Additional metadata
            result.analysis_metadata.update({
                'database_matches': len(result.database_result.matches) if result.database_result else 0,
                'yara_matches': len(result.yara_result.matches) if result.yara_result else 0,
                'scan_time': result.database_result.scan_time if result.database_result else 0.0,
                'file_size': result.database_result.file_size if result.database_result else 0,
                'architecture': architecture.value if architecture else 'unknown'
            })
            
        except Exception as e:
            self.logger.error(f"Error analyzing file {file_path}: {e}")
            result.error = str(e)
        
        return result
    
    def _map_yara_category(self, category) -> ProtectionType:
        """Map YARA pattern category to protection type."""
        # Import here to avoid circular imports
        from ..analysis.yara_pattern_engine import PatternCategory
        
        mapping = {
            PatternCategory.PROTECTION: ProtectionType.CODE_PROTECTION,
            PatternCategory.PACKER: ProtectionType.PACKER,
            PatternCategory.LICENSING: ProtectionType.LICENSING,
            PatternCategory.ANTI_DEBUG: ProtectionType.ANTI_DEBUG,
            PatternCategory.ANTI_VM: ProtectionType.ANTI_VM,
            PatternCategory.OBFUSCATION: ProtectionType.OBFUSCATION,
        }
        
        return mapping.get(category, ProtectionType.CUSTOM)
    
    def _perform_heuristic_analysis(self, file_path: str) -> Dict[str, float]:
        """Perform heuristic-based protection detection.
        
        Args:
            file_path: Path to file to analyze
            
        Returns:
            Dictionary of detection names and confidence scores
        """
        detections = {}
        
        try:
            with open(file_path, 'rb') as f:
                data = f.read()
            
            # Check for high entropy sections (simplified)
            if self._check_high_entropy(data):
                detections['High Entropy Content'] = self.heuristic_rules['high_entropy_sections']['confidence']
            
            # Check for suspicious imports
            if self._check_suspicious_imports(data):
                detections['Suspicious API Imports'] = self.heuristic_rules['suspicious_imports']['confidence']
            
            # Check for packed characteristics
            if self._check_packed_characteristics(data):
                detections['Packed Executable Characteristics'] = self.heuristic_rules['packed_characteristics']['confidence']
            
        except Exception as e:
            self.logger.error(f"Error in heuristic analysis: {e}")
        
        return detections
    
    def _check_high_entropy(self, data: bytes) -> bool:
        """Check if data has high entropy indicating encryption/packing."""
        if len(data) < 1024:
            return False
        
        # Calculate entropy for chunks of data
        import math
        chunk_size = 1024
        high_entropy_chunks = 0
        
        for i in range(0, len(data) - chunk_size, chunk_size):
            chunk = data[i:i + chunk_size]
            
            # Calculate entropy
            byte_counts = {}
            for byte in chunk:
                byte_counts[byte] = byte_counts.get(byte, 0) + 1
            
            entropy = 0.0
            for count in byte_counts.values():
                probability = count / len(chunk)
                if probability > 0:
                    entropy -= probability * math.log2(probability)
            
            if entropy > self.heuristic_rules['high_entropy_sections']['min_entropy']:
                high_entropy_chunks += 1
        
        # Consider high entropy if more than 30% of chunks have high entropy
        total_chunks = (len(data) - chunk_size) // chunk_size
        return high_entropy_chunks / max(1, total_chunks) > 0.3
    
    def _check_suspicious_imports(self, data: bytes) -> bool:
        """Check for suspicious API imports."""
        try:
            # Convert to string for simple string searching
            data_str = data.decode('utf-8', errors='ignore').lower()
            
            suspicious_apis = self.heuristic_rules['suspicious_imports']['api_functions']
            found_apis = 0
            
            for api in suspicious_apis:
                if api.lower() in data_str:
                    found_apis += 1
            
            return found_apis >= self.heuristic_rules['suspicious_imports']['min_count']
            
        except Exception:
            return False
    
    def _check_packed_characteristics(self, data: bytes) -> bool:
        """Check for characteristics typical of packed executables."""
        indicators = 0
        
        # Check for PE structure
        if len(data) > 64 and data[:2] == b'MZ':
            try:
                import struct
                pe_offset = struct.unpack('<L', data[60:64])[0]
                if pe_offset + 24 < len(data) and data[pe_offset:pe_offset+4] == b'PE\x00\x00':
                    # Basic PE analysis for packing indicators
                    
                    # Check for small number of sections
                    num_sections = struct.unpack('<H', data[pe_offset+6:pe_offset+8])[0]
                    if num_sections <= 3:
                        indicators += 1
                    
                    # Check for unusual section names or characteristics
                    # This is a simplified check
                    if b'UPX' in data[:1024] or b'.packed' in data[:1024]:
                        indicators += 2
                    
            except (struct.error, IndexError):
                pass
        
        return indicators >= self.heuristic_rules['packed_characteristics']['min_indicators']
    
    def _perform_behavioral_analysis(self, file_path: str) -> Dict[str, Any]:
        """Perform behavioral analysis (placeholder for future implementation).
        
        Args:
            file_path: Path to file to analyze
            
        Returns:
            Behavioral analysis results
        """
        # This would integrate with dynamic analysis components
        # For now, return placeholder data
        return {
            'dynamic_analysis_performed': False,
            'emulation_results': None,
            'api_call_patterns': [],
            'runtime_behaviors': []
        }
    
    def analyze_multiple_files(self, file_paths: List[str], 
                             architecture: Optional[ArchitectureType] = None) -> List[ProtectionDetectionResult]:
        """Analyze multiple files for protection patterns.
        
        Args:
            file_paths: List of file paths to analyze
            architecture: Optional architecture hint
            
        Returns:
            List of detection results
        """
        results = []
        
        # Use database manager's parallel scanning for efficiency
        scan_results = self.database_manager.scan_multiple_files(file_paths, architecture)
        
        for i, scan_result in enumerate(scan_results):
            result = ProtectionDetectionResult(file_paths[i])
            result.database_result = scan_result
            
            if not scan_result.error:
                # Extract detections
                for match in scan_result.matches:
                    if match.adjusted_confidence >= self.config['min_confidence']:
                        result.combined_detections.add(match.signature_name)
                        result.confidence_scores[match.signature_name] = match.adjusted_confidence
                        result.protection_types.add(match.protection_type)
            else:
                result.error = scan_result.error
            
            results.append(result)
        
        return results
    
    def get_protection_database_info(self) -> Dict[str, Any]:
        """Get information about the protection database.
        
        Returns:
            Database information and statistics
        """
        return self.database_manager.get_database_statistics()
    
    def search_protections(self, query: str, protection_type: Optional[ProtectionType] = None) -> List[Dict[str, Any]]:
        """Search for protection information.
        
        Args:
            query: Search query
            protection_type: Optional filter by protection type
            
        Returns:
            List of matching protection information
        """
        signatures = self.database_manager.search_protections(query, protection_type)
        
        results = []
        for signature in signatures:
            info = self.database_manager.get_protection_info(signature.id)
            if info:
                results.append(info)
        
        return results
    
    def get_supported_protections(self) -> Dict[str, List[str]]:
        """Get list of supported protection schemes by type.
        
        Returns:
            Dictionary mapping protection types to lists of supported schemes
        """
        supported = {}
        
        for prot_type in ProtectionType:
            signatures = self.database_manager.get_protection_signatures(prot_type)
            supported[prot_type.value] = [sig.name for sig in signatures]
        
        return supported
    
    def update_configuration(self, config: Dict[str, Any]) -> bool:
        """Update engine configuration.
        
        Args:
            config: Configuration updates
            
        Returns:
            True if configuration updated successfully
        """
        try:
            self.config.update(config)
            
            # Update database manager configuration if needed
            if any(key.startswith('cache') or key in ['max_file_size', 'scan_timeout'] 
                   for key in config.keys()):
                db_config = {k: v for k, v in config.items() 
                           if k in ['enable_caching', 'max_file_size', 'scan_timeout']}
                self.database_manager.update_configuration(db_config)
            
            self.logger.info("Protection pattern engine configuration updated")
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to update configuration: {e}")
            return False
    
    def export_detection_results(self, results: List[ProtectionDetectionResult], 
                               output_path: str, format: str = 'json') -> bool:
        """Export detection results to file.
        
        Args:
            results: List of detection results to export
            output_path: Output file path
            format: Export format ('json', 'csv', 'xml')
            
        Returns:
            True if export successful
        """
        try:
            # Convert to scan results for database manager export
            scan_results = []
            for result in results:
                if result.database_result:
                    scan_results.append(result.database_result)
                else:
                    # Create minimal scan result for YARA-only detections
                    from .pattern_matcher import ScanResult
                    scan_result = ScanResult(
                        file_path=result.file_path,
                        file_size=0,
                        file_hash="",
                        architecture=None,
                        error=result.error
                    )
                    scan_results.append(scan_result)
            
            return self.database_manager.export_results(scan_results, output_path, format)
            
        except Exception as e:
            self.logger.error(f"Failed to export detection results: {e}")
            return False
    
    def shutdown(self):
        """Shutdown the pattern engine."""
        try:
            self.database_manager.shutdown()
            self.logger.info("Protection pattern engine shut down successfully")
            
        except Exception as e:
            self.logger.error(f"Error during shutdown: {e}")
    
    def __enter__(self):
        """Context manager entry."""
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit."""
        self.shutdown()
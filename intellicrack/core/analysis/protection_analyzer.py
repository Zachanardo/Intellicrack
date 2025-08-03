"""Protection-aware binary analyzer integrating the protection database system.

This module extends the core binary analysis capabilities with advanced protection
detection using the comprehensive protection database system.

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
from typing import Any, Dict, List, Optional, Union

from .binary_analyzer import BinaryAnalyzer
from ..protection_database import (
    ProtectionPatternEngine, ProtectionType, ArchitectureType
)


class ProtectionAwareBinaryAnalyzer:
    """Enhanced binary analyzer with integrated protection detection."""
    
    def __init__(self, database_path: Optional[Path] = None):
        """Initialize the protection-aware binary analyzer.
        
        Args:
            database_path: Optional path to protection database
        """
        self.logger = logging.getLogger(__name__)
        
        # Initialize core binary analyzer
        self.binary_analyzer = BinaryAnalyzer()
        
        # Initialize protection pattern engine
        try:
            self.protection_engine = ProtectionPatternEngine(database_path)
            self.protection_available = True
            self.logger.info("Protection pattern engine initialized")
        except Exception as e:
            self.protection_engine = None
            self.protection_available = False
            self.logger.warning(f"Protection pattern engine not available: {e}")
        
        # Analysis configuration
        self.config = {
            'enable_protection_detection': True,
            'enable_deep_analysis': False,
            'enable_heuristics': True,
            'min_confidence': 0.5,
            'include_low_confidence': False
        }
    
    def analyze(self, binary_path: Union[str, Path], 
                architecture: Optional[ArchitectureType] = None,
                enable_deep_scan: bool = False) -> Dict[str, Any]:
        """Perform comprehensive binary analysis with protection detection.
        
        Args:
            binary_path: Path to binary file
            architecture: Optional architecture hint
            enable_deep_scan: Enable deep protection analysis
            
        Returns:
            Complete analysis results
        """
        try:
            binary_path = Path(binary_path)
            
            # Start with core binary analysis
            self.logger.info(f"Analyzing binary: {binary_path}")
            results = self.binary_analyzer.analyze(binary_path)
            
            if 'error' in results:
                return results
            
            # Add protection analysis if available
            if self.protection_available and self.config['enable_protection_detection']:
                protection_results = self._analyze_protections(
                    binary_path, architecture, enable_deep_scan
                )
                results['protection_analysis'] = protection_results
                
                # Enhance core results with protection insights
                self._enhance_results_with_protection_data(results, protection_results)
            else:
                results['protection_analysis'] = {
                    'available': False,
                    'reason': 'Protection analysis engine not available'
                }
            
            return results
            
        except Exception as e:
            self.logger.error(f"Analysis failed for {binary_path}: {e}")
            return {
                'error': str(e),
                'file_path': str(binary_path)
            }
    
    def _analyze_protections(self, binary_path: Path, 
                           architecture: Optional[ArchitectureType] = None,
                           enable_deep_scan: bool = False) -> Dict[str, Any]:
        """Analyze file for protection schemes.
        
        Args:
            binary_path: Path to binary file
            architecture: Optional architecture hint
            enable_deep_scan: Enable deep analysis
            
        Returns:
            Protection analysis results
        """
        try:
            # Perform protection detection
            detection_result = self.protection_engine.analyze_file(
                str(binary_path), 
                architecture=architecture,
                enable_deep_analysis=enable_deep_scan
            )
            
            if detection_result.error:
                return {
                    'available': True,
                    'success': False,
                    'error': detection_result.error
                }
            
            # Filter results by confidence
            filtered_detections = {}
            for name, confidence in detection_result.confidence_scores.items():
                if confidence >= self.config['min_confidence']:
                    filtered_detections[name] = confidence
                elif self.config['include_low_confidence']:
                    filtered_detections[name] = confidence
            
            # Build protection analysis results
            analysis_results = {
                'available': True,
                'success': True,
                'scan_metadata': {
                    'file_size': detection_result.database_result.file_size if detection_result.database_result else 0,
                    'scan_time': detection_result.database_result.scan_time if detection_result.database_result else 0.0,
                    'architecture': architecture.value if architecture else 'auto-detected'
                },
                'detections': {
                    'total_found': len(filtered_detections),
                    'high_confidence': len(detection_result.high_confidence_detections),
                    'protection_schemes': list(filtered_detections.keys()),
                    'confidence_scores': filtered_detections
                },
                'protection_types': {
                    'detected_types': [pt.value for pt in detection_result.protection_types],
                    'has_packer': ProtectionType.PACKER in detection_result.protection_types,
                    'has_drm': ProtectionType.DRM in detection_result.protection_types,
                    'has_code_protection': ProtectionType.CODE_PROTECTION in detection_result.protection_types,
                    'has_anti_debug': ProtectionType.ANTI_DEBUG in detection_result.protection_types,
                    'has_anti_vm': ProtectionType.ANTI_VM in detection_result.protection_types
                },
                'analysis_details': {
                    'database_matches': len(detection_result.database_result.matches) if detection_result.database_result else 0,
                    'yara_matches': len(detection_result.yara_result.matches) if detection_result.yara_result else 0,
                    'heuristic_detections': len([d for d in filtered_detections.keys() if 'heuristic' in d.lower() or 'generic' in d.lower()])
                },
                'recommendations': self._generate_protection_recommendations(detection_result)
            }
            
            # Add detailed match information if requested
            if enable_deep_scan and detection_result.database_result:
                analysis_results['detailed_matches'] = []
                for match in detection_result.database_result.matches:
                    if match.adjusted_confidence >= self.config['min_confidence']:
                        match_info = {
                            'signature_name': match.signature_name,
                            'protection_type': match.protection_type.value,
                            'confidence': match.confidence,
                            'adjusted_confidence': match.adjusted_confidence,
                            'match_count': match.match_count,
                            'false_positive_score': match.false_positive_score,
                            'matches': match.matches[:10]  # Limit to first 10 matches
                        }
                        analysis_results['detailed_matches'].append(match_info)
            
            return analysis_results
            
        except Exception as e:
            self.logger.error(f"Protection analysis failed: {e}")
            return {
                'available': True,
                'success': False,
                'error': str(e)
            }
    
    def _generate_protection_recommendations(self, detection_result) -> List[Dict[str, str]]:
        """Generate recommendations based on detected protections.
        
        Args:
            detection_result: Protection detection results
            
        Returns:
            List of recommendation dictionaries
        """
        recommendations = []
        
        # Check for packers
        if ProtectionType.PACKER in detection_result.protection_types:
            packer_names = [name for name, _ in detection_result.confidence_scores.items() 
                          if any(packer in name.lower() for packer in ['upx', 'packer', 'pack'])]
            
            if packer_names:
                recommendations.append({
                    'type': 'unpacking',
                    'priority': 'high',
                    'description': f'File appears to be packed with {", ".join(packer_names)}. Consider unpacking before analysis.',
                    'actions': ['Use specialized unpacker', 'Dynamic analysis', 'Memory dumping']
                })
        
        # Check for code protection
        if ProtectionType.CODE_PROTECTION in detection_result.protection_types:
            protection_names = [name for name, _ in detection_result.confidence_scores.items() 
                              if any(prot in name.lower() for prot in ['themida', 'vmprotect', 'enigma'])]
            
            if protection_names:
                recommendations.append({
                    'type': 'code_protection',
                    'priority': 'high',
                    'description': f'Advanced code protection detected: {", ".join(protection_names)}',
                    'actions': ['Specialized tools required', 'Dynamic analysis recommended', 'Manual reverse engineering']
                })
        
        # Check for anti-debugging
        if ProtectionType.ANTI_DEBUG in detection_result.protection_types:
            recommendations.append({
                'type': 'anti_debug',
                'priority': 'medium',
                'description': 'Anti-debugging techniques detected. Debugger evasion required.',
                'actions': ['Use stealth debugging', 'Patch anti-debug checks', 'Use specialized debuggers']
            })
        
        # Check for DRM
        if ProtectionType.DRM in detection_result.protection_types:
            recommendations.append({
                'type': 'drm',
                'priority': 'high',
                'description': 'DRM system detected. License verification analysis recommended.',
                'actions': ['Analyze licensing mechanism', 'Network traffic analysis', 'Activation bypass research']
            })
        
        # General recommendations
        if not detection_result.combined_detections:
            recommendations.append({
                'type': 'general',
                'priority': 'low',
                'description': 'No obvious protection schemes detected. Standard analysis can proceed.',
                'actions': ['Static analysis', 'Dynamic analysis', 'Reverse engineering']
            })
        elif len(detection_result.high_confidence_detections) > 3:
            recommendations.append({
                'type': 'multiple_protections',
                'priority': 'very_high',
                'description': 'Multiple protection schemes detected. Complex analysis required.',
                'actions': ['Layered approach', 'Specialized tools', 'Expert consultation']
            })
        
        return recommendations
    
    def _enhance_results_with_protection_data(self, results: Dict[str, Any], 
                                            protection_results: Dict[str, Any]):
        """Enhance core analysis results with protection information.
        
        Args:
            results: Core analysis results to enhance
            protection_results: Protection analysis results
        """
        if not protection_results.get('success'):
            return
        
        # Add protection summary to file info
        if 'file_info' not in results:
            results['file_info'] = {}
        
        detections = protection_results.get('detections', {})
        results['file_info']['protection_summary'] = {
            'protected': detections.get('total_found', 0) > 0,
            'protection_count': detections.get('total_found', 0),
            'high_confidence_count': detections.get('high_confidence', 0),
            'schemes': detections.get('protection_schemes', [])
        }
        
        # Add to analysis metadata
        if 'analysis_metadata' not in results:
            results['analysis_metadata'] = {}
        
        results['analysis_metadata']['protection_analysis'] = {
            'engine_available': True,
            'scan_time': protection_results.get('scan_metadata', {}).get('scan_time', 0.0),
            'database_matches': protection_results.get('analysis_details', {}).get('database_matches', 0)
        }
        
        # Add security assessment
        protection_types = protection_results.get('protection_types', {})
        security_level = 'low'
        
        if protection_types.get('has_code_protection') or protection_types.get('has_drm'):
            security_level = 'high'
        elif protection_types.get('has_packer') or protection_types.get('has_anti_debug'):
            security_level = 'medium'
        
        results['security_assessment'] = {
            'protection_level': security_level,
            'analysis_complexity': 'high' if detections.get('total_found', 0) > 2 else 'medium' if detections.get('total_found', 0) > 0 else 'low',
            'recommended_tools': self._get_recommended_tools(protection_types)
        }
    
    def _get_recommended_tools(self, protection_types: Dict[str, Any]) -> List[str]:
        """Get recommended analysis tools based on detected protections.
        
        Args:
            protection_types: Detected protection types
            
        Returns:
            List of recommended tool names
        """
        tools = ['Static Analysis', 'Hex Editor']
        
        if protection_types.get('has_packer'):
            tools.extend(['UPX', 'Generic Unpackers', 'PE Explorer'])
        
        if protection_types.get('has_code_protection'):
            tools.extend(['x64dbg', 'IDA Pro', 'Ghidra', 'Dynamic Analysis'])
        
        if protection_types.get('has_anti_debug'):
            tools.extend(['ScyllaHide', 'Stealth Debuggers'])
        
        if protection_types.get('has_drm'):
            tools.extend(['Wireshark', 'API Monitor', 'Process Monitor'])
        
        if protection_types.get('has_anti_vm'):
            tools.extend(['Physical Machine Analysis', 'VM Detection Bypass'])
        
        return list(set(tools))  # Remove duplicates
    
    def get_protection_info(self, protection_name: str) -> Optional[Dict[str, Any]]:
        """Get detailed information about a specific protection scheme.
        
        Args:
            protection_name: Name of protection scheme
            
        Returns:
            Protection information dictionary
        """
        if not self.protection_available:
            return None
        
        return self.protection_engine.get_protection_info(protection_name)
    
    def search_protections(self, query: str) -> List[Dict[str, Any]]:
        """Search for protection schemes matching a query.
        
        Args:
            query: Search query
            
        Returns:
            List of matching protection information
        """
        if not self.protection_available:
            return []
        
        return self.protection_engine.search_protections(query)
    
    def update_configuration(self, config: Dict[str, Any]) -> bool:
        """Update analyzer configuration.
        
        Args:
            config: Configuration updates
            
        Returns:
            True if configuration updated successfully
        """
        try:
            self.config.update(config)
            
            # Update protection engine configuration if available
            if self.protection_available and any(
                key in config for key in ['min_confidence', 'enable_heuristics', 'cache_size']
            ):
                engine_config = {
                    k: v for k, v in config.items() 
                    if k in ['min_confidence', 'enable_heuristics', 'cache_size']
                }
                self.protection_engine.update_configuration(engine_config)
            
            self.logger.info("Protection-aware analyzer configuration updated")
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to update configuration: {e}")
            return False
    
    def get_analysis_statistics(self) -> Dict[str, Any]:
        """Get analyzer and protection engine statistics.
        
        Returns:
            Statistics dictionary
        """
        stats = {
            'protection_engine_available': self.protection_available,
            'configuration': self.config.copy()
        }
        
        if self.protection_available:
            db_stats = self.protection_engine.get_protection_database_info()
            stats['protection_database'] = db_stats
        
        return stats
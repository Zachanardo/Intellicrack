"""
Radare2 JSON Output Standardization for AI/ML Integration

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
import json
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple, Union

from ...utils.logger import get_logger

logger = get_logger(__name__)


class R2JSONStandardizer:
    """
    Standardizes all radare2 analysis output into consistent JSON format for AI/ML integration.
    
    This class provides a unified interface for converting various radare2 analysis results
    into a standardized JSON schema that can be easily consumed by AI/ML pipelines,
    databases, and external analysis tools.
    """

    # Standard schema version for compatibility tracking
    SCHEMA_VERSION = "2.0.0"

    # Standard analysis types
    ANALYSIS_TYPES = {
        'decompilation': 'Decompilation Analysis',
        'vulnerability': 'Vulnerability Detection',
        'strings': 'String Analysis',
        'imports': 'Import/Export Analysis',
        'cfg': 'Control Flow Graph',
        'ai': 'AI Pattern Recognition',
        'signatures': 'FLIRT Signature Analysis',
        'esil': 'ESIL Emulation',
        'bypass': 'Bypass Generation',
        'binary_diff': 'Binary Comparison',
        'scripting': 'Custom Scripting',
        'comprehensive': 'Comprehensive Analysis'
    }

    def __init__(self):
        self.logger = logger
        self.analysis_id = str(uuid.uuid4())
        self.timestamp = datetime.now(timezone.utc).isoformat()

    def standardize_analysis_result(self,
                                   analysis_type: str,
                                   raw_result: Dict[str, Any],
                                   binary_path: str,
                                   metadata: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """
        Standardize any radare2 analysis result into the unified format.
        
        Args:
            analysis_type: Type of analysis performed
            raw_result: Raw result from radare2 analysis
            binary_path: Path to analyzed binary
            metadata: Optional additional metadata
            
        Returns:
            Dict containing standardized analysis result
        """
        try:
            # Create base standardized structure
            standardized = self._create_base_structure(analysis_type, binary_path, metadata)

            # Process specific analysis type
            if analysis_type == 'decompilation':
                standardized.update(self._standardize_decompilation(raw_result))
            elif analysis_type == 'vulnerability':
                standardized.update(self._standardize_vulnerability(raw_result))
            elif analysis_type == 'strings':
                standardized.update(self._standardize_strings(raw_result))
            elif analysis_type == 'imports':
                standardized.update(self._standardize_imports(raw_result))
            elif analysis_type == 'cfg':
                standardized.update(self._standardize_cfg(raw_result))
            elif analysis_type == 'ai':
                standardized.update(self._standardize_ai(raw_result))
            elif analysis_type == 'signatures':
                standardized.update(self._standardize_signatures(raw_result))
            elif analysis_type == 'esil':
                standardized.update(self._standardize_esil(raw_result))
            elif analysis_type == 'bypass':
                standardized.update(self._standardize_bypass(raw_result))
            elif analysis_type == 'binary_diff':
                standardized.update(self._standardize_binary_diff(raw_result))
            elif analysis_type == 'scripting':
                standardized.update(self._standardize_scripting(raw_result))
            elif analysis_type == 'comprehensive':
                standardized.update(self._standardize_comprehensive(raw_result))
            else:
                standardized.update(self._standardize_generic(raw_result))

            # Add validation and checksums
            standardized = self._add_validation_data(standardized)

            # Validate schema compliance
            self._validate_schema(standardized)

            return standardized

        except Exception as e:
            self.logger.error(f"Failed to standardize {analysis_type} result: {e}")
            return self._create_error_result(analysis_type, binary_path, str(e))

    def _create_base_structure(self,
                              analysis_type: str,
                              binary_path: str,
                              metadata: Optional[Dict[str, Any]]) -> Dict[str, Any]:
        """Create base standardized structure"""
        return {
            # Schema and version information
            "schema_version": self.SCHEMA_VERSION,
            "format_version": "radare2_analysis_v2",

            # Analysis metadata
            "analysis_metadata": {
                "analysis_id": self.analysis_id,
                "analysis_type": analysis_type,
                "analysis_description": self.ANALYSIS_TYPES.get(analysis_type, "Unknown Analysis"),
                "timestamp": self.timestamp,
                "engine": "radare2",
                "engine_version": self._get_radare2_version(),
                "intellicrack_version": "2.0.0"
            },

            # Binary metadata
            "binary_metadata": {
                "file_path": binary_path,
                "file_name": binary_path.split('/')[-1] if binary_path else "unknown",
                "file_hash": self._calculate_file_hash(binary_path),
                "file_size": self._get_file_size(binary_path),
                "analysis_time": self.timestamp
            },

            # Additional metadata
            "additional_metadata": metadata or {},

            # Results structure (to be filled by specific methods)
            "analysis_results": {},

            # Summary statistics (to be calculated)
            "summary_statistics": {},

            # Quality metrics
            "quality_metrics": {},

            # AI/ML ready features
            "ml_features": {},

            # Status and errors
            "status": {
                "success": True,
                "errors": [],
                "warnings": []
            }
        }

    def _standardize_decompilation(self, raw_result: Dict[str, Any]) -> Dict[str, Any]:
        """Standardize decompilation analysis results"""
        return {
            "analysis_results": {
                "license_functions": self._normalize_function_list(
                    raw_result.get('license_functions', [])
                ),
                "decompiled_code": self._normalize_decompiled_code(
                    raw_result.get('decompiled_functions', {})
                ),
                "license_patterns": self._normalize_patterns(
                    raw_result.get('license_patterns', [])
                ),
                "validation_routines": self._normalize_validation_routines(
                    raw_result.get('validation_routines', [])
                )
            },
            "summary_statistics": {
                "total_functions_analyzed": len(raw_result.get('license_functions', [])),
                "license_functions_found": len([f for f in raw_result.get('license_functions', [])
                                              if f.get('confidence', 0) > 0.5]),
                "decompilation_success_rate": self._calculate_decompilation_success_rate(raw_result),
                "average_function_complexity": self._calculate_average_complexity(raw_result)
            },
            "ml_features": {
                "function_features": self._extract_function_features(raw_result),
                "pattern_features": self._extract_pattern_features(raw_result),
                "complexity_features": self._extract_complexity_features(raw_result)
            }
        }

    def _standardize_vulnerability(self, raw_result: Dict[str, Any]) -> Dict[str, Any]:
        """Standardize vulnerability analysis results"""
        vulnerabilities = []

        # Collect vulnerabilities from all categories
        vuln_categories = [
            'buffer_overflows', 'format_string_bugs', 'integer_overflows',
            'use_after_free', 'double_free', 'null_pointer_dereferences',
            'race_conditions', 'privilege_escalation', 'code_injection',
            'path_traversal', 'information_disclosure', 'cryptographic_weaknesses'
        ]

        for category in vuln_categories:
            if category in raw_result:
                for vuln in raw_result[category]:
                    vulnerabilities.append(self._normalize_vulnerability(vuln, category))

        return {
            "analysis_results": {
                "vulnerabilities": vulnerabilities,
                "vulnerability_categories": self._categorize_vulnerabilities(vulnerabilities),
                "cve_matches": self._normalize_cve_matches(raw_result.get('cve_matches', [])),
                "exploit_generation": self._normalize_exploit_data(raw_result.get('exploit_generation', {})),
                "severity_assessment": self._normalize_severity_assessment(raw_result.get('severity_assessment', {}))
            },
            "summary_statistics": {
                "total_vulnerabilities": len(vulnerabilities),
                "critical_vulnerabilities": len([v for v in vulnerabilities if v.get('severity') == 'critical']),
                "high_vulnerabilities": len([v for v in vulnerabilities if v.get('severity') == 'high']),
                "medium_vulnerabilities": len([v for v in vulnerabilities if v.get('severity') == 'medium']),
                "low_vulnerabilities": len([v for v in vulnerabilities if v.get('severity') == 'low']),
                "exploitable_vulnerabilities": len([v for v in vulnerabilities if v.get('exploitable', False)]),
                "overall_risk_score": self._calculate_risk_score(vulnerabilities)
            },
            "ml_features": {
                "vulnerability_vectors": self._extract_vulnerability_vectors(vulnerabilities),
                "exploitability_features": self._extract_exploitability_features(vulnerabilities),
                "risk_features": self._extract_risk_features(raw_result)
            }
        }

    def _standardize_strings(self, raw_result: Dict[str, Any]) -> Dict[str, Any]:
        """Standardize string analysis results"""
        return {
            "analysis_results": {
                "license_strings": self._normalize_string_list(raw_result.get('license_strings', [])),
                "crypto_strings": self._normalize_string_list(raw_result.get('crypto_strings', [])),
                "error_strings": self._normalize_string_list(raw_result.get('error_message_strings', [])),
                "debug_strings": self._normalize_string_list(raw_result.get('debug_strings', [])),
                "suspicious_patterns": self._normalize_pattern_list(raw_result.get('suspicious_patterns', [])),
                "entropy_analysis": self._normalize_entropy_analysis(raw_result.get('string_entropy_analysis', {})),
                "cross_references": self._normalize_cross_references(raw_result.get('cross_references', {}))
            },
            "summary_statistics": {
                "total_strings": raw_result.get('total_strings', 0),
                "license_string_count": len(raw_result.get('license_strings', [])),
                "crypto_string_count": len(raw_result.get('crypto_strings', [])),
                "high_entropy_strings": len(raw_result.get('string_entropy_analysis', {}).get('high_entropy_strings', [])),
                "suspicious_pattern_count": len(raw_result.get('suspicious_patterns', [])),
                "average_string_entropy": raw_result.get('string_entropy_analysis', {}).get('average_entropy', 0)
            },
            "ml_features": {
                "string_distribution": self._extract_string_distribution_features(raw_result),
                "entropy_features": self._extract_string_entropy_features(raw_result),
                "pattern_features": self._extract_string_pattern_features(raw_result)
            }
        }

    def _standardize_imports(self, raw_result: Dict[str, Any]) -> Dict[str, Any]:
        """Standardize import/export analysis results"""
        return {
            "analysis_results": {
                "imports": self._normalize_import_list(raw_result.get('imports', [])),
                "exports": self._normalize_export_list(raw_result.get('exports', [])),
                "api_categories": self._normalize_api_categories(raw_result.get('api_categories', {})),
                "suspicious_apis": self._normalize_suspicious_apis(raw_result.get('suspicious_apis', [])),
                "anti_analysis_apis": self._normalize_anti_analysis_apis(raw_result.get('anti_analysis_apis', [])),
                "library_dependencies": self._normalize_library_dependencies(raw_result.get('library_dependencies', []))
            },
            "summary_statistics": {
                "total_imports": len(raw_result.get('imports', [])),
                "total_exports": len(raw_result.get('exports', [])),
                "unique_libraries": len(set(imp.get('library', '') for imp in raw_result.get('imports', []))),
                "suspicious_api_count": len(raw_result.get('suspicious_apis', [])),
                "anti_analysis_count": len(raw_result.get('anti_analysis_apis', [])),
                "api_diversity_score": self._calculate_api_diversity(raw_result)
            },
            "ml_features": {
                "api_usage_vectors": self._extract_api_usage_vectors(raw_result),
                "library_features": self._extract_library_features(raw_result),
                "suspicious_behavior_features": self._extract_suspicious_behavior_features(raw_result)
            }
        }

    def _standardize_cfg(self, raw_result: Dict[str, Any]) -> Dict[str, Any]:
        """Standardize CFG analysis results"""
        return {
            "analysis_results": {
                "functions_analyzed": raw_result.get('functions_analyzed', 0),
                "complexity_metrics": self._normalize_complexity_metrics(raw_result.get('complexity_metrics', {})),
                "license_patterns": self._normalize_cfg_patterns(raw_result.get('license_patterns', [])),
                "graph_data": self._normalize_graph_data(raw_result.get('graph_data', {})),
                "call_graph_analysis": self._normalize_call_graph(raw_result.get('call_graph_analysis', {})),
                "vulnerability_patterns": self._normalize_vuln_patterns(raw_result.get('vulnerability_analysis', {})),
                "similarity_analysis": self._normalize_similarity_analysis(raw_result.get('similarity_analysis', {}))
            },
            "summary_statistics": {
                "total_functions": raw_result.get('functions_analyzed', 0),
                "average_complexity": self._get_average_complexity(raw_result),
                "max_complexity": self._get_max_complexity(raw_result),
                "license_pattern_count": len(raw_result.get('license_patterns', [])),
                "vulnerability_pattern_count": self._count_vulnerability_patterns(raw_result),
                "graph_density": self._calculate_graph_density(raw_result)
            },
            "ml_features": {
                "graph_structural_features": self._extract_graph_structural_features(raw_result),
                "complexity_distribution": self._extract_complexity_distribution(raw_result),
                "pattern_features": self._extract_cfg_pattern_features(raw_result)
            }
        }

    def _standardize_ai(self, raw_result: Dict[str, Any]) -> Dict[str, Any]:
        """Standardize AI analysis results"""
        return {
            "analysis_results": {
                "license_detection": self._normalize_ai_license_detection(raw_result.get('ai_license_detection', {})),
                "vulnerability_prediction": self._normalize_ai_vuln_prediction(raw_result.get('ai_vulnerability_prediction', {})),
                "function_clustering": self._normalize_function_clustering(raw_result.get('function_clustering', {})),
                "anomaly_detection": self._normalize_anomaly_detection(raw_result.get('anomaly_detection', {})),
                "code_similarity": self._normalize_code_similarity(raw_result.get('code_similarity', {})),
                "bypass_suggestions": self._normalize_bypass_suggestions(raw_result.get('automated_bypass_suggestions', {}))
            },
            "summary_statistics": {
                "license_confidence": raw_result.get('ai_license_detection', {}).get('confidence', 0),
                "vulnerability_risk_score": raw_result.get('ai_vulnerability_prediction', {}).get('overall_risk_score', 0),
                "anomaly_score": raw_result.get('anomaly_detection', {}).get('anomaly_score', 0),
                "clustering_quality": raw_result.get('function_clustering', {}).get('clustering_quality', 0),
                "similarity_score": raw_result.get('code_similarity', {}).get('average_internal_similarity', 0),
                "bypass_success_probability": self._calculate_bypass_success_probability(raw_result)
            },
            "ml_features": {
                "prediction_features": self._extract_ai_prediction_features(raw_result),
                "clustering_features": self._extract_clustering_features(raw_result),
                "anomaly_features": self._extract_anomaly_features(raw_result)
            }
        }

    def _standardize_comprehensive(self, raw_result: Dict[str, Any]) -> Dict[str, Any]:
        """Standardize comprehensive analysis results"""
        components = raw_result.get('components', {})

        # Standardize each component
        standardized_components = {}
        for component_name, component_data in components.items():
            if component_data and not component_data.get('error'):
                standardized_components[component_name] = self.standardize_analysis_result(
                    component_name, component_data, raw_result.get('binary_path', ''), {}
                )

        return {
            "analysis_results": {
                "components": standardized_components,
                "cross_component_analysis": self._perform_cross_component_analysis(standardized_components),
                "unified_findings": self._create_unified_findings(standardized_components),
                "correlation_analysis": self._perform_correlation_analysis(standardized_components)
            },
            "summary_statistics": {
                "components_analyzed": len(standardized_components),
                "successful_components": len([c for c in standardized_components.values()
                                            if c.get('status', {}).get('success', False)]),
                "total_vulnerabilities": self._count_total_vulnerabilities(standardized_components),
                "total_license_functions": self._count_total_license_functions(standardized_components),
                "overall_risk_score": self._calculate_overall_risk_score(standardized_components),
                "analysis_completeness": self._calculate_analysis_completeness(standardized_components)
            },
            "ml_features": {
                "unified_feature_vector": self._create_unified_feature_vector(standardized_components),
                "component_correlations": self._extract_component_correlations(standardized_components),
                "meta_features": self._extract_meta_features(standardized_components)
            }
        }

    def _standardize_generic(self, raw_result: Dict[str, Any]) -> Dict[str, Any]:
        """Standardize generic/unknown analysis results"""
        return {
            "analysis_results": {
                "raw_data": raw_result,
                "normalized_data": self._normalize_generic_data(raw_result)
            },
            "summary_statistics": {
                "data_size": len(str(raw_result)),
                "field_count": len(raw_result) if isinstance(raw_result, dict) else 0,
                "has_errors": 'error' in raw_result if isinstance(raw_result, dict) else False
            },
            "ml_features": {
                "generic_features": self._extract_generic_features(raw_result)
            }
        }

    def _add_validation_data(self, standardized: Dict[str, Any]) -> Dict[str, Any]:
        """Add validation data and checksums"""
        # Calculate data checksum
        data_str = json.dumps(standardized.get('analysis_results', {}), sort_keys=True)
        data_checksum = hashlib.sha256(data_str.encode()).hexdigest()

        # Add validation metadata
        standardized['validation'] = {
            "data_checksum": data_checksum,
            "schema_validation": True,
            "completeness_score": self._calculate_completeness_score(standardized),
            "quality_score": self._calculate_quality_score(standardized)
        }

        return standardized

    def _validate_schema(self, standardized: Dict[str, Any]) -> bool:
        """Validate standardized result against schema"""
        required_fields = [
            'schema_version', 'analysis_metadata', 'binary_metadata',
            'analysis_results', 'summary_statistics', 'ml_features', 'status'
        ]

        for field in required_fields:
            if field not in standardized:
                raise ValueError(f"Missing required field: {field}")

        return True

    def _create_error_result(self, analysis_type: str, binary_path: str, error: str) -> Dict[str, Any]:
        """Create standardized error result"""
        return {
            "schema_version": self.SCHEMA_VERSION,
            "analysis_metadata": {
                "analysis_id": self.analysis_id,
                "analysis_type": analysis_type,
                "timestamp": self.timestamp,
                "engine": "radare2"
            },
            "binary_metadata": {
                "file_path": binary_path,
                "file_name": binary_path.split('/')[-1] if binary_path else "unknown"
            },
            "analysis_results": {},
            "summary_statistics": {},
            "ml_features": {},
            "status": {
                "success": False,
                "errors": [error],
                "warnings": []
            },
            "validation": {
                "schema_validation": False,
                "completeness_score": 0.0,
                "quality_score": 0.0
            }
        }

    # Helper methods for normalization (implementing key ones, others would follow similar patterns)

    def _normalize_function_list(self, functions: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Normalize function list to standard format"""
        normalized = []
        for func in functions:
            normalized.append({
                "name": func.get('name', 'unknown'),
                "address": self._normalize_address(func.get('address', 0)),
                "size": func.get('size', 0),
                "complexity": func.get('complexity', 1),
                "confidence": func.get('confidence', 0.0),
                "type": func.get('type', 'unknown'),
                "attributes": func.get('attributes', {}),
                "cross_references": func.get('cross_references', [])
            })
        return normalized

    def _normalize_vulnerability(self, vuln: Dict[str, Any], category: str) -> Dict[str, Any]:
        """Normalize vulnerability to standard format"""
        return {
            "id": str(uuid.uuid4()),
            "category": category,
            "type": vuln.get('type', category),
            "severity": vuln.get('severity', 'medium'),
            "function": vuln.get('function', 'unknown'),
            "address": self._normalize_address(vuln.get('address', 0)),
            "description": vuln.get('description', ''),
            "exploitable": vuln.get('exploitable', False),
            "cve_references": vuln.get('cve_references', []),
            "mitigation": vuln.get('mitigation', ''),
            "confidence": vuln.get('confidence', 0.5)
        }

    def _normalize_address(self, address: Union[str, int]) -> str:
        """Normalize address to standard hex string format"""
        if isinstance(address, str):
            if address.startswith('0x'):
                return address
            else:
                try:
                    return f"0x{int(address):x}"
                except ValueError:
                    return "0x0"
        elif isinstance(address, int):
            return f"0x{address:x}"
        else:
            return "0x0"

    def _get_radare2_version(self) -> str:
        """Get radare2 version"""
        try:
            import subprocess
            result = subprocess.run(['radare2', '-v'], capture_output=True, text=True, timeout=5)
            if result.returncode == 0:
                return result.stdout.split('\n')[0].strip()
        except:
            pass
        return "unknown"

    def _calculate_file_hash(self, file_path: str) -> str:
        """Calculate file hash"""
        try:
            if file_path and os.path.exists(file_path):
                with open(file_path, 'rb') as f:
                    return hashlib.sha256(f.read()).hexdigest()
        except:
            pass
        return "unknown"

    def _get_file_size(self, file_path: str) -> int:
        """Get file size"""
        try:
            if file_path and os.path.exists(file_path):
                return os.path.getsize(file_path)
        except:
            pass
        return 0

    def _calculate_completeness_score(self, standardized: Dict[str, Any]) -> float:
        """Calculate completeness score for validation"""
        total_fields = 0
        filled_fields = 0

        def count_fields(obj, path=""):
            nonlocal total_fields, filled_fields
            if isinstance(obj, dict):
                for key, value in obj.items():
                    total_fields += 1
                    if value is not None and value != "" and value != [] and value != {}:
                        filled_fields += 1
                    if isinstance(value, (dict, list)):
                        count_fields(value, f"{path}.{key}")
            elif isinstance(obj, list):
                for i, item in enumerate(obj):
                    if isinstance(item, (dict, list)):
                        count_fields(item, f"{path}[{i}]")

        count_fields(standardized.get('analysis_results', {}))

        return filled_fields / max(1, total_fields)

    def _calculate_quality_score(self, standardized: Dict[str, Any]) -> float:
        """Calculate quality score for validation"""
        # Simple quality scoring based on data presence and consistency
        score = 0.0
        max_score = 100.0

        # Check required sections
        if standardized.get('analysis_results'):
            score += 20
        if standardized.get('summary_statistics'):
            score += 20
        if standardized.get('ml_features'):
            score += 20

        # Check status
        if standardized.get('status', {}).get('success', False):
            score += 20

        # Check metadata completeness
        metadata = standardized.get('analysis_metadata', {})
        if all(key in metadata for key in ['analysis_id', 'analysis_type', 'timestamp']):
            score += 20

        return score / max_score

    # Placeholder implementations for complex helper methods
    # (In a full implementation, these would contain detailed logic)

    def _extract_function_features(self, raw_result: Dict[str, Any]) -> Dict[str, Any]:
        """Extract ML features from function data"""
        return {"feature_count": len(raw_result.get('license_functions', []))}

    def _extract_pattern_features(self, raw_result: Dict[str, Any]) -> Dict[str, Any]:
        """Extract ML features from pattern data"""
        return {"pattern_count": len(raw_result.get('license_patterns', []))}

    def _calculate_risk_score(self, vulnerabilities: List[Dict[str, Any]]) -> float:
        """Calculate overall risk score"""
        if not vulnerabilities:
            return 0.0

        severity_weights = {'critical': 4, 'high': 3, 'medium': 2, 'low': 1}
        total_weight = sum(severity_weights.get(v.get('severity', 'low'), 1) for v in vulnerabilities)
        max_possible = len(vulnerabilities) * 4

        return min(1.0, total_weight / max_possible) if max_possible > 0 else 0.0


def standardize_r2_result(analysis_type: str,
                         raw_result: Dict[str, Any],
                         binary_path: str,
                         metadata: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """
    Convenience function to standardize any radare2 analysis result.
    
    Args:
        analysis_type: Type of analysis
        raw_result: Raw analysis result
        binary_path: Path to analyzed binary
        metadata: Optional metadata
        
    Returns:
        Standardized analysis result
    """
    standardizer = R2JSONStandardizer()
    return standardizer.standardize_analysis_result(analysis_type, raw_result, binary_path, metadata)


def batch_standardize_results(results: List[Tuple[str, Dict[str, Any], str]]) -> List[Dict[str, Any]]:
    """
    Batch standardize multiple analysis results.
    
    Args:
        results: List of (analysis_type, raw_result, binary_path) tuples
        
    Returns:
        List of standardized results
    """
    standardizer = R2JSONStandardizer()
    standardized_results = []

    for analysis_type, raw_result, binary_path in results:
        try:
            standardized = standardizer.standardize_analysis_result(analysis_type, raw_result, binary_path)
            standardized_results.append(standardized)
        except Exception as e:
            logger.error(f"Failed to standardize {analysis_type} result: {e}")
            error_result = standardizer._create_error_result(analysis_type, binary_path, str(e))
            standardized_results.append(error_result)

    return standardized_results


__all__ = [
    'R2JSONStandardizer',
    'standardize_r2_result',
    'batch_standardize_results'
]

"""Radare2 JSON Output Standardization for AI/ML Integration.

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
along with Intellicrack.  If not, see https://www.gnu.org/licenses/.
"""

import hashlib
import json
import os
import shutil
import uuid
from datetime import UTC, datetime, timezone
from typing import Any

from ...utils.logger import get_logger


logger = get_logger(__name__)


class R2JSONStandardizer:
    """Standardizes all radare2 analysis output into consistent JSON format for AI/ML integration.

    This class provides a unified interface for converting various radare2 analysis results
    into a standardized JSON schema that can be easily consumed by AI/ML pipelines,
    databases, and external analysis tools.
    """

    # Standard schema version for compatibility tracking
    SCHEMA_VERSION = "2.0.0"

    # Standard analysis types
    ANALYSIS_TYPES = {
        "decompilation": "Decompilation Analysis",
        "vulnerability": "Vulnerability Detection",
        "strings": "String Analysis",
        "imports": "Import/Export Analysis",
        "cfg": "Control Flow Graph",
        "ai": "AI Pattern Recognition",
        "signatures": "FLIRT Signature Analysis",
        "esil": "ESIL Emulation",
        "bypass": "Bypass Generation",
        "binary_diff": "Binary Comparison",
        "scripting": "Custom Scripting",
        "comprehensive": "Comprehensive Analysis",
    }

    def __init__(self) -> None:
        """Initialize the Radare2 JSON standardizer.

        Sets up a unique analysis ID and timestamp for result tracking.
        """
        self.logger = logger
        self.analysis_id = str(uuid.uuid4())
        self.timestamp = datetime.now(UTC).isoformat()

    def standardize_analysis_result(
        self,
        analysis_type: str,
        raw_result: dict[str, Any],
        binary_path: str,
        metadata: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Standardize any radare2 analysis result into the unified format.

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
            if analysis_type == "decompilation":
                standardized.update(self._standardize_decompilation(raw_result))
            elif analysis_type == "vulnerability":
                standardized.update(self._standardize_vulnerability(raw_result))
            elif analysis_type == "strings":
                standardized.update(self._standardize_strings(raw_result))
            elif analysis_type == "imports":
                standardized.update(self._standardize_imports(raw_result))
            elif analysis_type == "cfg":
                standardized.update(self._standardize_cfg(raw_result))
            elif analysis_type == "ai":
                standardized.update(self._standardize_ai(raw_result))
            elif analysis_type == "signatures":
                standardized.update(self._standardize_signatures(raw_result))
            elif analysis_type == "esil":
                standardized.update(self._standardize_esil(raw_result))
            elif analysis_type == "bypass":
                standardized.update(self._standardize_bypass(raw_result))
            elif analysis_type == "binary_diff":
                standardized.update(self._standardize_binary_diff(raw_result))
            elif analysis_type == "scripting":
                standardized.update(self._standardize_scripting(raw_result))
            elif analysis_type == "comprehensive":
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

    def _create_base_structure(self, analysis_type: str, binary_path: str, metadata: dict[str, Any] | None) -> dict[str, Any]:
        """Create base standardized structure."""
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
                "intellicrack_version": "2.0.0",
            },
            # Binary metadata
            "binary_metadata": {
                "file_path": binary_path,
                "file_name": binary_path.rsplit("/", maxsplit=1)[-1] if binary_path else "unknown",
                "file_hash": self._calculate_file_hash(binary_path),
                "file_size": self._get_file_size(binary_path),
                "analysis_time": self.timestamp,
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
                "warnings": [],
            },
        }

    def _standardize_decompilation(self, raw_result: dict[str, Any]) -> dict[str, Any]:
        """Standardize decompilation analysis results."""
        return {
            "analysis_results": {
                "license_functions": self._normalize_function_list(
                    raw_result.get("license_functions", []),
                ),
                "decompiled_code": self._normalize_decompiled_code(
                    raw_result.get("decompiled_functions", {}),
                ),
                "license_patterns": self._normalize_patterns(
                    raw_result.get("license_patterns", []),
                ),
                "validation_routines": self._normalize_validation_routines(
                    raw_result.get("validation_routines", []),
                ),
            },
            "summary_statistics": {
                "total_functions_analyzed": len(raw_result.get("license_functions", [])),
                "license_functions_found": len([f for f in raw_result.get("license_functions", []) if f.get("confidence", 0) > 0.5]),
                "decompilation_success_rate": self._calculate_decompilation_success_rate(raw_result),
                "average_function_complexity": self._calculate_average_complexity(raw_result),
            },
            "ml_features": {
                "function_features": self._extract_function_features(raw_result),
                "pattern_features": self._extract_pattern_features(raw_result),
                "complexity_features": self._extract_complexity_features(raw_result),
            },
        }

    def _standardize_vulnerability(self, raw_result: dict[str, Any]) -> dict[str, Any]:
        """Standardize vulnerability analysis results."""
        vulnerabilities = []

        # Collect vulnerabilities from all categories
        vuln_categories = [
            "buffer_overflows",
            "format_string_bugs",
            "integer_overflows",
            "use_after_free",
            "double_free",
            "null_pointer_dereferences",
            "race_conditions",
            "privilege_escalation",
            "code_injection",
            "path_traversal",
            "information_disclosure",
            "cryptographic_weaknesses",
        ]

        for category in vuln_categories:
            if category in raw_result:
                vulnerabilities.extend(self._normalize_vulnerability(vuln, category) for vuln in raw_result[category])
        return {
            "analysis_results": {
                "vulnerabilities": vulnerabilities,
                "vulnerability_categories": self._categorize_vulnerabilities(vulnerabilities),
                "cve_matches": self._normalize_cve_matches(raw_result.get("cve_matches", [])),
                "exploit_generation": self._normalize_exploit_data(raw_result.get("exploit_generation", {})),
                "severity_assessment": self._normalize_severity_assessment(raw_result.get("severity_assessment", {})),
            },
            "summary_statistics": {
                "total_vulnerabilities": len(vulnerabilities),
                "critical_vulnerabilities": len([v for v in vulnerabilities if v.get("severity") == "critical"]),
                "high_vulnerabilities": len([v for v in vulnerabilities if v.get("severity") == "high"]),
                "medium_vulnerabilities": len([v for v in vulnerabilities if v.get("severity") == "medium"]),
                "low_vulnerabilities": len([v for v in vulnerabilities if v.get("severity") == "low"]),
                "exploitable_vulnerabilities": len([v for v in vulnerabilities if v.get("exploitable", False)]),
                "overall_risk_score": self._calculate_risk_score(vulnerabilities),
            },
            "ml_features": {
                "vulnerability_vectors": self._extract_vulnerability_vectors(vulnerabilities),
                "exploitability_features": self._extract_exploitability_features(vulnerabilities),
                "risk_features": self._extract_risk_features(raw_result),
            },
        }

    def _standardize_strings(self, raw_result: dict[str, Any]) -> dict[str, Any]:
        """Standardize string analysis results."""
        return {
            "analysis_results": {
                "license_strings": self._normalize_string_list(raw_result.get("license_strings", [])),
                "crypto_strings": self._normalize_string_list(raw_result.get("crypto_strings", [])),
                "error_strings": self._normalize_string_list(raw_result.get("error_message_strings", [])),
                "debug_strings": self._normalize_string_list(raw_result.get("debug_strings", [])),
                "suspicious_patterns": self._normalize_pattern_list(raw_result.get("suspicious_patterns", [])),
                "entropy_analysis": self._normalize_entropy_analysis(raw_result.get("string_entropy_analysis", {})),
                "cross_references": self._normalize_cross_references(raw_result.get("cross_references", {})),
            },
            "summary_statistics": {
                "total_strings": raw_result.get("total_strings", 0),
                "license_string_count": len(raw_result.get("license_strings", [])),
                "crypto_string_count": len(raw_result.get("crypto_strings", [])),
                "high_entropy_strings": len(raw_result.get("string_entropy_analysis", {}).get("high_entropy_strings", [])),
                "suspicious_pattern_count": len(raw_result.get("suspicious_patterns", [])),
                "average_string_entropy": raw_result.get("string_entropy_analysis", {}).get("average_entropy", 0),
            },
            "ml_features": {
                "string_distribution": self._extract_string_distribution_features(raw_result),
                "entropy_features": self._extract_string_entropy_features(raw_result),
                "pattern_features": self._extract_string_pattern_features(raw_result),
            },
        }

    def _standardize_imports(self, raw_result: dict[str, Any]) -> dict[str, Any]:
        """Standardize import/export analysis results."""
        return {
            "analysis_results": {
                "imports": self._normalize_import_list(raw_result.get("imports", [])),
                "exports": self._normalize_export_list(raw_result.get("exports", [])),
                "api_categories": self._normalize_api_categories(raw_result.get("api_categories", {})),
                "suspicious_apis": self._normalize_suspicious_apis(raw_result.get("suspicious_apis", [])),
                "anti_analysis_apis": self._normalize_anti_analysis_apis(raw_result.get("anti_analysis_apis", [])),
                "library_dependencies": self._normalize_library_dependencies(raw_result.get("library_dependencies", [])),
            },
            "summary_statistics": {
                "total_imports": len(raw_result.get("imports", [])),
                "total_exports": len(raw_result.get("exports", [])),
                "unique_libraries": len({imp.get("library", "") for imp in raw_result.get("imports", [])}),
                "suspicious_api_count": len(raw_result.get("suspicious_apis", [])),
                "anti_analysis_count": len(raw_result.get("anti_analysis_apis", [])),
                "api_diversity_score": self._calculate_api_diversity(raw_result),
            },
            "ml_features": {
                "api_usage_vectors": self._extract_api_usage_vectors(raw_result),
                "library_features": self._extract_library_features(raw_result),
                "suspicious_behavior_features": self._extract_suspicious_behavior_features(raw_result),
            },
        }

    def _standardize_cfg(self, raw_result: dict[str, Any]) -> dict[str, Any]:
        """Standardize CFG analysis results."""
        return {
            "analysis_results": {
                "functions_analyzed": raw_result.get("functions_analyzed", 0),
                "complexity_metrics": self._normalize_complexity_metrics(raw_result.get("complexity_metrics", {})),
                "license_patterns": self._normalize_cfg_patterns(raw_result.get("license_patterns", [])),
                "graph_data": self._normalize_graph_data(raw_result.get("graph_data", {})),
                "call_graph_analysis": self._normalize_call_graph(raw_result.get("call_graph_analysis", {})),
                "vulnerability_patterns": self._normalize_vuln_patterns(raw_result.get("vulnerability_analysis", {})),
                "similarity_analysis": self._normalize_similarity_analysis(raw_result.get("similarity_analysis", {})),
            },
            "summary_statistics": {
                "total_functions": raw_result.get("functions_analyzed", 0),
                "average_complexity": self._get_average_complexity(raw_result),
                "max_complexity": self._get_max_complexity(raw_result),
                "license_pattern_count": len(raw_result.get("license_patterns", [])),
                "vulnerability_pattern_count": self._count_vulnerability_patterns(raw_result),
                "graph_density": self._calculate_graph_density(raw_result),
            },
            "ml_features": {
                "graph_structural_features": self._extract_graph_structural_features(raw_result),
                "complexity_distribution": self._extract_complexity_distribution(raw_result),
                "pattern_features": self._extract_cfg_pattern_features(raw_result),
            },
        }

    def _standardize_ai(self, raw_result: dict[str, Any]) -> dict[str, Any]:
        """Standardize AI analysis results."""
        return {
            "analysis_results": {
                "license_detection": self._normalize_ai_license_detection(raw_result.get("ai_license_detection", {})),
                "vulnerability_prediction": self._normalize_ai_vuln_prediction(raw_result.get("ai_vulnerability_prediction", {})),
                "function_clustering": self._normalize_function_clustering(raw_result.get("function_clustering", {})),
                "anomaly_detection": self._normalize_anomaly_detection(raw_result.get("anomaly_detection", {})),
                "code_similarity": self._normalize_code_similarity(raw_result.get("code_similarity", {})),
                "bypass_suggestions": self._normalize_bypass_suggestions(raw_result.get("automated_bypass_suggestions", {})),
            },
            "summary_statistics": {
                "license_confidence": raw_result.get("ai_license_detection", {}).get("confidence", 0),
                "vulnerability_risk_score": raw_result.get("ai_vulnerability_prediction", {}).get("overall_risk_score", 0),
                "anomaly_score": raw_result.get("anomaly_detection", {}).get("anomaly_score", 0),
                "clustering_quality": raw_result.get("function_clustering", {}).get("clustering_quality", 0),
                "similarity_score": raw_result.get("code_similarity", {}).get("average_internal_similarity", 0),
                "bypass_success_probability": self._calculate_bypass_success_probability(raw_result),
            },
            "ml_features": {
                "prediction_features": self._extract_ai_prediction_features(raw_result),
                "clustering_features": self._extract_clustering_features(raw_result),
                "anomaly_features": self._extract_anomaly_features(raw_result),
            },
        }

    def _standardize_signatures(self, raw_result: dict[str, Any]) -> dict[str, Any]:
        """Standardize signature analysis results."""
        return {
            "analysis_results": {
                "signatures_found": raw_result.get("signatures_found", []),
                "signature_matches": raw_result.get("signature_matches", {}),
                "pattern_analysis": raw_result.get("pattern_analysis", {}),
                "license_bypass_signatures": raw_result.get("license_bypass_signatures", []),
                "library_signatures": raw_result.get("library_signatures", []),
            },
            "summary_statistics": {
                "total_signatures": len(raw_result.get("signatures_found", [])),
                "license_bypass_signature_count": len(raw_result.get("license_bypass_signatures", [])),
                "library_signature_count": len(raw_result.get("library_signatures", [])),
                "confidence_score": raw_result.get("confidence_score", 0),
            },
            "ml_features": {
                "signature_patterns": raw_result.get("signature_patterns", []),
                "signature_entropy": raw_result.get("signature_entropy", 0),
            },
        }

    def _standardize_esil(self, raw_result: dict[str, Any]) -> dict[str, Any]:
        """Standardize ESIL analysis results."""
        return {
            "analysis_results": {
                "esil_expressions": raw_result.get("esil_expressions", []),
                "emulation_results": raw_result.get("emulation_results", {}),
                "register_states": raw_result.get("register_states", {}),
                "memory_accesses": raw_result.get("memory_accesses", []),
                "taint_analysis": raw_result.get("taint_analysis", {}),
            },
            "summary_statistics": {
                "total_expressions": len(raw_result.get("esil_expressions", [])),
                "unique_operations": len(set(raw_result.get("unique_operations", []))),
                "memory_access_count": len(raw_result.get("memory_accesses", [])),
                "tainted_registers": len(raw_result.get("taint_analysis", {}).get("tainted_registers", [])),
            },
            "ml_features": {
                "esil_patterns": raw_result.get("esil_patterns", []),
                "operation_distribution": raw_result.get("operation_distribution", {}),
            },
        }

    def _standardize_bypass(self, raw_result: dict[str, Any]) -> dict[str, Any]:
        """Standardize bypass analysis results."""
        return {
            "analysis_results": {
                "bypass_techniques": raw_result.get("bypass_techniques", []),
                "protection_mechanisms": raw_result.get("protection_mechanisms", []),
                "patch_points": raw_result.get("patch_points", []),
                "bypass_scripts": raw_result.get("bypass_scripts", {}),
                "success_probability": raw_result.get("success_probability", {}),
            },
            "summary_statistics": {
                "total_techniques": len(raw_result.get("bypass_techniques", [])),
                "protection_count": len(raw_result.get("protection_mechanisms", [])),
                "patch_point_count": len(raw_result.get("patch_points", [])),
                "average_success_rate": raw_result.get("average_success_rate", 0),
            },
            "ml_features": {
                "bypass_patterns": raw_result.get("bypass_patterns", []),
                "protection_complexity": raw_result.get("protection_complexity", 0),
            },
        }

    def _standardize_binary_diff(self, raw_result: dict[str, Any]) -> dict[str, Any]:
        """Standardize binary diff results."""
        return {
            "analysis_results": {
                "diff_summary": raw_result.get("diff_summary", {}),
                "function_diffs": raw_result.get("function_diffs", []),
                "added_functions": raw_result.get("added_functions", []),
                "removed_functions": raw_result.get("removed_functions", []),
                "modified_functions": raw_result.get("modified_functions", []),
                "similarity_metrics": raw_result.get("similarity_metrics", {}),
            },
            "summary_statistics": {
                "total_functions_diff": len(raw_result.get("function_diffs", [])),
                "added_count": len(raw_result.get("added_functions", [])),
                "removed_count": len(raw_result.get("removed_functions", [])),
                "modified_count": len(raw_result.get("modified_functions", [])),
                "overall_similarity": raw_result.get("overall_similarity", 0),
            },
            "ml_features": {
                "diff_patterns": raw_result.get("diff_patterns", []),
                "change_distribution": raw_result.get("change_distribution", {}),
            },
        }

    def _standardize_scripting(self, raw_result: dict[str, Any]) -> dict[str, Any]:
        """Standardize scripting analysis results."""
        return {
            "analysis_results": {
                "script_outputs": raw_result.get("script_outputs", {}),
                "custom_analysis": raw_result.get("custom_analysis", {}),
                "script_metadata": raw_result.get("script_metadata", {}),
                "execution_logs": raw_result.get("execution_logs", []),
                "script_results": raw_result.get("script_results", {}),
            },
            "summary_statistics": {
                "scripts_executed": len(raw_result.get("script_outputs", {})),
                "execution_time": raw_result.get("total_execution_time", 0),
                "errors_count": len(raw_result.get("errors", [])),
                "warnings_count": len(raw_result.get("warnings", [])),
            },
            "ml_features": {
                "script_patterns": raw_result.get("script_patterns", []),
                "result_features": raw_result.get("result_features", {}),
            },
        }

    def _standardize_comprehensive(self, raw_result: dict[str, Any]) -> dict[str, Any]:
        """Standardize comprehensive analysis results."""
        components = raw_result.get("components", {})

        standardized_components = {
            component_name: self.standardize_analysis_result(
                component_name,
                component_data,
                raw_result.get("binary_path", ""),
                {},
            )
            for component_name, component_data in components.items()
            if component_data and not component_data.get("error")
        }
        return {
            "analysis_results": {
                "components": standardized_components,
                "cross_component_analysis": self._perform_cross_component_analysis(standardized_components),
                "unified_findings": self._create_unified_findings(standardized_components),
                "correlation_analysis": self._perform_correlation_analysis(standardized_components),
            },
            "summary_statistics": {
                "components_analyzed": len(standardized_components),
                "successful_components": len([c for c in standardized_components.values() if c.get("status", {}).get("success", False)]),
                "total_vulnerabilities": self._count_total_vulnerabilities(standardized_components),
                "total_license_functions": self._count_total_license_functions(standardized_components),
                "overall_risk_score": self._calculate_overall_risk_score(standardized_components),
                "analysis_completeness": self._calculate_analysis_completeness(standardized_components),
            },
            "ml_features": {
                "unified_feature_vector": self._create_unified_feature_vector(standardized_components),
                "component_correlations": self._extract_component_correlations(standardized_components),
                "meta_features": self._extract_meta_features(standardized_components),
            },
        }

    def _standardize_generic(self, raw_result: dict[str, Any]) -> dict[str, Any]:
        """Standardize generic/unknown analysis results."""
        return {
            "analysis_results": {
                "raw_data": raw_result,
                "normalized_data": self._normalize_generic_data(raw_result),
            },
            "summary_statistics": {
                "data_size": len(str(raw_result)),
                "field_count": len(raw_result) if isinstance(raw_result, dict) else 0,
                "has_errors": "error" in raw_result if isinstance(raw_result, dict) else False,
            },
            "ml_features": {
                "generic_features": self._extract_generic_features(raw_result),
            },
        }

    def _add_validation_data(self, standardized: dict[str, Any]) -> dict[str, Any]:
        """Add validation data and checksums."""
        # Calculate data checksum
        data_str = json.dumps(standardized.get("analysis_results", {}), sort_keys=True)
        data_checksum = hashlib.sha256(data_str.encode()).hexdigest()

        # Add validation metadata
        standardized["validation"] = {
            "data_checksum": data_checksum,
            "schema_validation": True,
            "completeness_score": self._calculate_completeness_score(standardized),
            "quality_score": self._calculate_quality_score(standardized),
        }

        return standardized

    def _validate_schema(self, standardized: dict[str, Any]) -> bool:
        """Validate standardized result against schema."""
        required_fields = [
            "schema_version",
            "analysis_metadata",
            "binary_metadata",
            "analysis_results",
            "summary_statistics",
            "ml_features",
            "status",
        ]

        for field in required_fields:
            if field not in standardized:
                raise ValueError(f"Missing required field: {field}")

        return True

    def _create_error_result(self, analysis_type: str, binary_path: str, error: str) -> dict[str, Any]:
        """Create standardized error result."""
        return {
            "schema_version": self.SCHEMA_VERSION,
            "analysis_metadata": {
                "analysis_id": self.analysis_id,
                "analysis_type": analysis_type,
                "timestamp": self.timestamp,
                "engine": "radare2",
            },
            "binary_metadata": {
                "file_path": binary_path,
                "file_name": binary_path.rsplit("/", maxsplit=1)[-1] if binary_path else "unknown",
            },
            "analysis_results": {},
            "summary_statistics": {},
            "ml_features": {},
            "status": {
                "success": False,
                "errors": [error],
                "warnings": [],
            },
            "validation": {
                "schema_validation": False,
                "completeness_score": 0.0,
                "quality_score": 0.0,
            },
        }

    # Helper methods for normalization (implementing key ones, others would follow similar patterns)

    def _normalize_function_list(self, functions: list[dict[str, Any]]) -> list[dict[str, Any]]:
        """Normalize function list to standard format."""
        return [
            {
                "name": func.get("name", "unknown"),
                "address": self._normalize_address(func.get("address", 0)),
                "size": func.get("size", 0),
                "complexity": func.get("complexity", 1),
                "confidence": func.get("confidence", 0.0),
                "type": func.get("type", "unknown"),
                "attributes": func.get("attributes", {}),
                "cross_references": func.get("cross_references", []),
            }
            for func in functions
        ]

    def _normalize_vulnerability(self, vuln: dict[str, Any], category: str) -> dict[str, Any]:
        """Normalize vulnerability to standard format."""
        return {
            "id": str(uuid.uuid4()),
            "category": category,
            "type": vuln.get("type", category),
            "severity": vuln.get("severity", "medium"),
            "function": vuln.get("function", "unknown"),
            "address": self._normalize_address(vuln.get("address", 0)),
            "description": vuln.get("description", ""),
            "exploitable": vuln.get("exploitable", False),
            "cve_references": vuln.get("cve_references", []),
            "mitigation": vuln.get("mitigation", ""),
            "confidence": vuln.get("confidence", 0.5),
        }

    def _normalize_address(self, address: str | int) -> str:
        """Normalize address to standard hex string format."""
        if isinstance(address, str):
            if address.startswith("0x"):
                return address
            try:
                return f"0x{int(address):x}"
            except ValueError as e:
                self.logger.error("Value error in radare2_json_standardizer: %s", e)
                return "0x0"
        elif isinstance(address, int):
            return f"0x{address:x}"
        else:
            return "0x0"

    def _get_radare2_version(self) -> str:
        """Get radare2 version."""
        try:
            import subprocess

            if radare2_path := shutil.which("radare2"):
                result = subprocess.run(  # nosec S603 - Legitimate subprocess usage for security research and binary analysis
                    [radare2_path, "-v"],
                    check=False,
                    capture_output=True,
                    text=True,
                    timeout=5,
                    shell=False,  # Explicitly secure - using list format prevents shell injection
                )
                if result.returncode == 0:
                    return result.stdout.split("\n")[0].strip()
            else:
                logger.warning("radare2 command not found in PATH")
        except Exception as e:
            self.logger.debug(f"Failed to get radare2 version: {e}")
        return "unknown"

    def _calculate_file_hash(self, file_path: str) -> str:
        """Calculate file hash."""
        try:
            if file_path and os.path.exists(file_path):
                with open(file_path, "rb") as f:
                    return hashlib.sha256(f.read()).hexdigest()
        except Exception as e:
            self.logger.debug(f"Failed to calculate file hash for {file_path}: {e}")
        return "unknown"

    def _get_file_size(self, file_path: str) -> int:
        """Get file size."""
        try:
            if file_path and os.path.exists(file_path):
                return os.path.getsize(file_path)
        except Exception as e:
            self.logger.debug(f"Failed to get file size for {file_path}: {e}")
        return 0

    def _calculate_completeness_score(self, standardized: dict[str, Any]) -> float:
        """Calculate completeness score for validation."""
        total_fields = 0
        filled_fields = 0

        def count_fields(obj: dict[str, Any] | list[Any], path: str = "") -> None:
            nonlocal total_fields, filled_fields
            if isinstance(obj, dict):
                for key, value in obj.items():
                    total_fields += 1
                    if value is not None and value not in ("", [], {}):
                        filled_fields += 1
                    if isinstance(value, (dict, list)):
                        count_fields(value, f"{path}.{key}")
            elif isinstance(obj, list):
                for i, item in enumerate(obj):
                    if isinstance(item, (dict, list)):
                        count_fields(item, f"{path}[{i}]")

        count_fields(standardized.get("analysis_results", {}))

        return filled_fields / max(1, total_fields)

    def _calculate_quality_score(self, standardized: dict[str, Any]) -> float:
        """Calculate quality score for validation."""
        # Simple quality scoring based on data presence and consistency
        score = 0.0
        max_score = 100.0

        # Check required sections
        if standardized.get("analysis_results"):
            score += 20
        if standardized.get("summary_statistics"):
            score += 20
        if standardized.get("ml_features"):
            score += 20

        # Check status
        if standardized.get("status", {}).get("success", False):
            score += 20

        # Check metadata completeness
        metadata = standardized.get("analysis_metadata", {})
        if all(key in metadata for key in ["analysis_id", "analysis_type", "timestamp"]):
            score += 20

        return score / max_score

    def _normalize_decompiled_code(self, decompiled_functions: dict[str, Any]) -> dict[str, Any]:
        """Normalize decompiled code structures."""
        return {
            func_name: {
                "code": code_data.get("code", ""),
                "language": code_data.get("language", "c"),
                "quality_score": code_data.get("quality_score", 0.5),
                "variables": code_data.get("variables", []),
                "calls": code_data.get("calls", []),
            }
            for func_name, code_data in decompiled_functions.items()
        }

    def _normalize_patterns(self, patterns: list[dict[str, Any]]) -> list[dict[str, Any]]:
        """Normalize pattern data."""
        return [
            {
                "id": pattern.get("id", str(uuid.uuid4())),
                "type": pattern.get("type", "unknown"),
                "pattern": pattern.get("pattern", ""),
                "confidence": pattern.get("confidence", 0.5),
                "matches": pattern.get("matches", []),
            }
            for pattern in patterns
        ]

    def _normalize_validation_routines(self, routines: list[dict[str, Any]]) -> list[dict[str, Any]]:
        """Normalize validation routine data."""
        return [
            {
                "name": routine.get("name", "unknown"),
                "type": routine.get("type", "license_check"),
                "address": self._normalize_address(routine.get("address", 0)),
                "complexity": routine.get("complexity", "medium"),
                "bypassed": routine.get("bypassed", False),
            }
            for routine in routines
        ]

    def _calculate_decompilation_success_rate(self, raw_result: dict[str, Any]) -> float:
        """Calculate decompilation success rate."""
        total_functions = len(raw_result.get("license_functions", []))
        if total_functions == 0:
            return 0.0
        successful = sum(bool(f.get("decompiled", False)) for f in raw_result.get("license_functions", []))
        return successful / total_functions

    def _calculate_average_complexity(self, raw_result: dict[str, Any]) -> float:
        """Calculate average function complexity."""
        functions = raw_result.get("license_functions", [])
        if not functions:
            return 0.0
        complexities = [f.get("complexity", 1) for f in functions if f.get("complexity")]
        return sum(complexities) / len(complexities) if complexities else 0.0

    def _extract_function_features(self, raw_result: dict[str, Any]) -> dict[str, Any]:
        """Extract function-based features for ML."""
        functions = raw_result.get("license_functions", [])
        return {
            "total_functions": len(functions),
            "avg_function_size": sum(f.get("size", 0) for f in functions) / max(1, len(functions)),
            "max_function_size": max((f.get("size", 0) for f in functions), default=0),
            "function_types": list({f.get("type", "unknown") for f in functions}),
            "call_depth_avg": sum(f.get("call_depth", 0) for f in functions) / max(1, len(functions)),
        }

    def _extract_pattern_features(self, raw_result: dict[str, Any]) -> dict[str, Any]:
        """Extract pattern-based features for ML."""
        patterns = raw_result.get("license_patterns", [])
        return {
            "pattern_count": len(patterns),
            "pattern_types": list({p.get("type", "unknown") for p in patterns}),
            "avg_confidence": sum(p.get("confidence", 0) for p in patterns) / max(1, len(patterns)),
            "high_confidence_patterns": len([p for p in patterns if p.get("confidence", 0) > 0.8]),
        }

    def _extract_complexity_features(self, raw_result: dict[str, Any]) -> dict[str, Any]:
        """Extract complexity-based features for ML."""
        functions = raw_result.get("license_functions", [])
        return {
            "complexity_distribution": self._get_complexity_distribution(functions),
            "cyclomatic_complexity_avg": self._calculate_avg_cyclomatic_complexity(functions),
            "nesting_level_avg": self._calculate_avg_nesting_level(functions),
        }

    def _extract_vulnerability_vectors(self, vulnerabilities: list[dict[str, Any]]) -> dict[str, Any]:
        """Extract vulnerability vectors for ML."""
        return {
            "vuln_count_by_severity": self._count_vulns_by_severity(vulnerabilities),
            "vuln_count_by_type": self._count_vulns_by_type(vulnerabilities),
            "exploitable_count": len([v for v in vulnerabilities if v.get("exploitable", False)]),
            "avg_confidence": sum(v.get("confidence", 0) for v in vulnerabilities) / max(1, len(vulnerabilities)),
        }

    def _extract_exploitability_features(self, vulnerabilities: list[dict[str, Any]]) -> dict[str, Any]:
        """Extract exploitability features for ML."""
        return {
            "total_exploitable": len([v for v in vulnerabilities if v.get("exploitable", False)]),
            "high_severity_exploitable": len([v for v in vulnerabilities if v.get("exploitable", False) and v.get("severity") == "high"]),
            "remote_exploitable": len([v for v in vulnerabilities if v.get("exploitable", False) and "remote" in v.get("type", "")]),
            "privilege_escalation_vulns": len([v for v in vulnerabilities if "privilege" in v.get("category", "").lower()]),
        }

    def _extract_risk_features(self, raw_result: dict[str, Any]) -> dict[str, Any]:
        """Extract risk assessment features for ML."""
        return {
            "overall_risk_score": raw_result.get("risk_score", 0.5),
            "attack_surface_score": raw_result.get("attack_surface", 0.5),
            "mitigation_coverage": raw_result.get("mitigation_coverage", 0.0),
            "false_positive_rate": raw_result.get("false_positive_rate", 0.1),
        }

    def _extract_string_distribution_features(self, raw_result: dict[str, Any]) -> dict[str, Any]:
        """Extract string distribution features for ML."""
        strings = raw_result.get("strings", [])
        return {
            "total_strings": len(strings),
            "avg_string_length": sum(len(s.get("value", "")) for s in strings) / max(1, len(strings)),
            "string_types": self._categorize_strings(strings),
            "unicode_ratio": len([s for s in strings if s.get("encoding") == "unicode"]) / max(1, len(strings)),
        }

    def _extract_string_entropy_features(self, raw_result: dict[str, Any]) -> dict[str, Any]:
        """Extract string entropy features for ML."""
        strings = raw_result.get("strings", [])
        entropies = [s.get("entropy", 0) for s in strings if s.get("entropy") is not None]
        return {
            "avg_entropy": sum(entropies) / max(1, len(entropies)),
            "max_entropy": max(entropies, default=0),
            "high_entropy_count": len([e for e in entropies if e > 6.0]),
            "entropy_variance": self._calculate_variance(entropies),
        }

    def _extract_string_pattern_features(self, raw_result: dict[str, Any]) -> dict[str, Any]:
        """Extract string pattern features for ML."""
        strings = raw_result.get("strings", [])
        return {
            "url_patterns": len([s for s in strings if "http" in s.get("value", "").lower()]),
            "file_path_patterns": len([s for s in strings if "\\" in s.get("value", "") or "/" in s.get("value", "")]),
            "registry_patterns": len([s for s in strings if "HKEY_" in s.get("value", "")]),
            "crypto_patterns": len(
                [s for s in strings if any(crypto in s.get("value", "").lower() for crypto in ["aes", "rsa", "md5", "sha"])],
            ),
        }

    def _extract_api_usage_vectors(self, raw_result: dict[str, Any]) -> dict[str, Any]:
        """Extract API usage vectors for ML."""
        imports = raw_result.get("imports", [])
        return {
            "total_imports": len(imports),
            "api_categories": self._categorize_apis(imports),
            "suspicious_apis": self._count_suspicious_apis(imports),
            "crypto_apis": len([i for i in imports if "crypt" in i.get("name", "").lower()]),
        }

    def _extract_library_features(self, raw_result: dict[str, Any]) -> dict[str, Any]:
        """Extract library features for ML."""
        imports = raw_result.get("imports", [])
        exports = raw_result.get("exports", [])
        return {
            "library_count": len({i.get("library", "") for i in imports}),
            "export_count": len(exports),
            "import_export_ratio": len(imports) / max(1, len(exports)),
            "common_libraries": self._get_common_libraries(imports),
        }

    def _extract_suspicious_behavior_features(self, raw_result: dict[str, Any]) -> dict[str, Any]:
        """Extract suspicious behavior features for ML."""
        imports = raw_result.get("imports", [])
        return {
            "process_manipulation": self._count_process_apis(imports),
            "file_operations": self._count_file_apis(imports),
            "network_operations": self._count_network_apis(imports),
            "registry_operations": self._count_registry_apis(imports),
            "memory_operations": self._count_memory_apis(imports),
        }

    def _extract_graph_structural_features(self, raw_result: dict[str, Any]) -> dict[str, Any]:
        """Extract graph structural features for ML."""
        cfg_data = raw_result.get("cfg", {})
        return {
            "node_count": cfg_data.get("node_count", 0),
            "edge_count": cfg_data.get("edge_count", 0),
            "connectivity": cfg_data.get("edge_count", 0) / max(1, cfg_data.get("node_count", 1)),
            "max_depth": cfg_data.get("max_depth", 0),
            "branch_factor": cfg_data.get("avg_branches", 0),
        }

    def _extract_complexity_distribution(self, raw_result: dict[str, Any]) -> dict[str, Any]:
        """Extract complexity distribution features for ML."""
        cfg_data = raw_result.get("cfg", {})
        functions = cfg_data.get("functions", [])
        complexities = [f.get("complexity", 0) for f in functions]
        return {
            "complexity_histogram": self._create_histogram(complexities, bins=10),
            "complexity_percentiles": self._calculate_percentiles(complexities),
            "high_complexity_functions": len([c for c in complexities if c > 20]),
        }

    def _extract_cfg_pattern_features(self, raw_result: dict[str, Any]) -> dict[str, Any]:
        """Extract CFG pattern features for ML."""
        cfg_data = raw_result.get("cfg", {})
        return {
            "loop_patterns": cfg_data.get("loop_count", 0),
            "conditional_patterns": cfg_data.get("conditional_count", 0),
            "call_patterns": cfg_data.get("call_count", 0),
            "recursion_patterns": cfg_data.get("recursion_count", 0),
        }

    def _extract_ai_prediction_features(self, raw_result: dict[str, Any]) -> dict[str, Any]:
        """Extract AI prediction features for ML."""
        predictions = raw_result.get("predictions", [])
        return {
            "prediction_count": len(predictions),
            "avg_confidence": sum(p.get("confidence", 0) for p in predictions) / max(1, len(predictions)),
            "prediction_types": list({p.get("type", "unknown") for p in predictions}),
            "high_confidence_predictions": len([p for p in predictions if p.get("confidence", 0) > 0.8]),
        }

    def _extract_clustering_features(self, raw_result: dict[str, Any]) -> dict[str, Any]:
        """Extract clustering features for ML."""
        clusters = raw_result.get("clusters", [])
        return {
            "cluster_count": len(clusters),
            "avg_cluster_size": sum(c.get("size", 0) for c in clusters) / max(1, len(clusters)),
            "cluster_cohesion": sum(c.get("cohesion", 0) for c in clusters) / max(1, len(clusters)),
            "outlier_count": raw_result.get("outliers", 0),
        }

    def _extract_anomaly_features(self, raw_result: dict[str, Any]) -> dict[str, Any]:
        """Extract anomaly features for ML."""
        anomalies = raw_result.get("anomalies", [])
        return {
            "anomaly_count": len(anomalies),
            "anomaly_types": list({a.get("type", "unknown") for a in anomalies}),
            "avg_anomaly_score": sum(a.get("score", 0) for a in anomalies) / max(1, len(anomalies)),
            "critical_anomalies": len([a for a in anomalies if a.get("severity") == "critical"]),
        }

    def _extract_component_correlations(self, components: dict[str, Any]) -> dict[str, Any]:
        """Extract component correlation features for ML."""
        return {
            "decompilation_vuln_correlation": self._calculate_correlation(
                components.get("decompilation", {}),
                components.get("vulnerability", {}),
            ),
            "string_import_correlation": self._calculate_correlation(
                components.get("strings", {}),
                components.get("imports", {}),
            ),
            "cfg_complexity_correlation": self._calculate_correlation(
                components.get("cfg", {}),
                components.get("decompilation", {}),
            ),
        }

    def _extract_meta_features(self, components: dict[str, Any]) -> dict[str, Any]:
        """Extract meta features for ML."""
        return {
            "analysis_completeness": len([c for c in components.values() if c.get("success", False)]) / max(1, len(components)),
            "data_quality_score": sum(c.get("quality_score", 0.5) for c in components.values()) / max(1, len(components)),
            "analysis_time_total": sum(c.get("duration", 0) for c in components.values()),
            "component_consistency": self._calculate_component_consistency(components),
        }

    def _extract_generic_features(self, raw_result: dict[str, Any]) -> dict[str, Any]:
        """Extract generic features for ML."""
        return {
            "data_size": len(str(raw_result)),
            "key_count": len(raw_result.keys()),
            "nested_levels": self._calculate_nesting_depth(raw_result),
            "data_types": self._analyze_data_types(raw_result),
        }

    def _calculate_risk_score(self, vulnerabilities: list[dict[str, Any]]) -> float:
        """Calculate overall risk score."""
        if not vulnerabilities:
            return 0.0

        severity_weights = {"critical": 4, "high": 3, "medium": 2, "low": 1}
        total_weight = sum(severity_weights.get(v.get("severity", "low"), 1) for v in vulnerabilities)
        max_possible = len(vulnerabilities) * 4

        return min(1.0, total_weight / max_possible) if max_possible > 0 else 0.0

    # Helper methods for feature extraction
    def _get_complexity_distribution(self, functions: list[dict[str, Any]]) -> dict[str, int]:
        """Get complexity distribution."""
        distribution = {"low": 0, "medium": 0, "high": 0}
        for func in functions:
            complexity = func.get("complexity", 1)
            if complexity < 5:
                distribution["low"] += 1
            elif complexity < 15:
                distribution["medium"] += 1
            else:
                distribution["high"] += 1
        return distribution

    def _calculate_avg_cyclomatic_complexity(self, functions: list[dict[str, Any]]) -> float:
        """Calculate average cyclomatic complexity."""
        complexities = [f.get("cyclomatic_complexity", 1) for f in functions]
        return sum(complexities) / max(1, len(complexities))

    def _calculate_avg_nesting_level(self, functions: list[dict[str, Any]]) -> float:
        """Calculate average nesting level."""
        nesting_levels = [f.get("nesting_level", 1) for f in functions]
        return sum(nesting_levels) / max(1, len(nesting_levels))

    def _count_vulns_by_severity(self, vulnerabilities: list[dict[str, Any]]) -> dict[str, int]:
        """Count vulnerabilities by severity."""
        counts = {"low": 0, "medium": 0, "high": 0, "critical": 0}
        for vuln in vulnerabilities:
            severity = vuln.get("severity", "medium")
            counts[severity] = counts.get(severity, 0) + 1
        return counts

    def _count_vulns_by_type(self, vulnerabilities: list[dict[str, Any]]) -> dict[str, int]:
        """Count vulnerabilities by type."""
        counts = {}
        for vuln in vulnerabilities:
            vuln_type = vuln.get("type", "unknown")
            counts[vuln_type] = counts.get(vuln_type, 0) + 1
        return counts

    def _categorize_strings(self, strings: list[dict[str, Any]]) -> dict[str, int]:
        """Categorize strings by type."""
        categories = {"ascii": 0, "unicode": 0, "base64": 0, "hex": 0, "other": 0}
        for string in strings:
            encoding = string.get("encoding", "ascii")
            if encoding in categories:
                categories[encoding] += 1
            else:
                categories["other"] += 1
        return categories

    def _calculate_variance(self, values: list[float]) -> float:
        """Calculate variance of values."""
        if not values:
            return 0.0
        mean = sum(values) / len(values)
        return sum((x - mean) ** 2 for x in values) / len(values)

    def _categorize_apis(self, imports: list[dict[str, Any]]) -> dict[str, int]:
        """Categorize APIs by function type."""
        categories = {
            "file": 0,
            "network": 0,
            "process": 0,
            "registry": 0,
            "crypto": 0,
            "memory": 0,
            "other": 0,
        }

        api_keywords = {
            "file": ["file", "read", "write", "create", "delete"],
            "network": ["socket", "connect", "send", "recv", "http"],
            "process": ["process", "thread", "exec", "spawn"],
            "registry": ["reg", "key", "hkey"],
            "crypto": ["crypt", "hash", "encrypt", "decrypt"],
            "memory": ["malloc", "alloc", "heap", "virtual"],
        }

        for imp in imports:
            name = imp.get("name", "").lower()
            categorized = False
            for category, keywords in api_keywords.items():
                if any(keyword in name for keyword in keywords):
                    categories[category] += 1
                    categorized = True
                    break
            if not categorized:
                categories["other"] += 1

        return categories

    def _count_suspicious_apis(self, imports: list[dict[str, Any]]) -> int:
        """Count suspicious API calls."""
        suspicious_keywords = [
            "createprocess",
            "shellexecute",
            "writeprocessmemory",
            "virtualalloc",
            "loadlibrary",
            "getprocaddress",
            "regsetvalue",
            "createfile",
            "internetopen",
        ]
        count = 0
        for imp in imports:
            name = imp.get("name", "").lower()
            if any(keyword in name for keyword in suspicious_keywords):
                count += 1
        return count

    def _get_common_libraries(self, imports: list[dict[str, Any]]) -> list[str]:
        """Get list of common libraries."""
        libraries = {}
        for imp in imports:
            lib = imp.get("library", "unknown")
            libraries[lib] = libraries.get(lib, 0) + 1

        # Return top 5 most common libraries
        return sorted(libraries.keys(), key=lambda x: libraries[x], reverse=True)[:5]

    def _count_process_apis(self, imports: list[dict[str, Any]]) -> int:
        """Count process manipulation APIs."""
        process_keywords = ["createprocess", "terminateprocess", "openprocess", "thread"]
        return sum(bool(any(keyword in imp.get("name", "").lower() for keyword in process_keywords)) for imp in imports)

    def _count_file_apis(self, imports: list[dict[str, Any]]) -> int:
        """Count file operation APIs."""
        file_keywords = ["createfile", "readfile", "writefile", "deletefile", "copyfile"]
        return sum(bool(any(keyword in imp.get("name", "").lower() for keyword in file_keywords)) for imp in imports)

    def _count_network_apis(self, imports: list[dict[str, Any]]) -> int:
        """Count network operation APIs."""
        network_keywords = ["socket", "connect", "send", "recv", "internetopen", "urldownload"]
        return sum(bool(any(keyword in imp.get("name", "").lower() for keyword in network_keywords)) for imp in imports)

    def _count_registry_apis(self, imports: list[dict[str, Any]]) -> int:
        """Count registry operation APIs."""
        registry_keywords = ["regopen", "regclose", "regset", "regquery", "regdelete"]
        return sum(bool(any(keyword in imp.get("name", "").lower() for keyword in registry_keywords)) for imp in imports)

    def _count_memory_apis(self, imports: list[dict[str, Any]]) -> int:
        """Count memory operation APIs."""
        memory_keywords = [
            "virtualalloc",
            "writeprocessmemory",
            "readprocessmemory",
            "malloc",
            "heap",
        ]
        return sum(bool(any(keyword in imp.get("name", "").lower() for keyword in memory_keywords)) for imp in imports)

    def _create_histogram(self, values: list[float], bins: int = 10) -> list[int]:
        """Create histogram from values."""
        if not values:
            return [0] * bins

        min_val, max_val = min(values), max(values)
        if min_val == max_val:
            histogram = [0] * bins
            histogram[0] = len(values)
            return histogram

        bin_width = (max_val - min_val) / bins
        histogram = [0] * bins

        for value in values:
            bin_index = min(int((value - min_val) / bin_width), bins - 1)
            histogram[bin_index] += 1

        return histogram

    def _calculate_percentiles(self, values: list[float]) -> dict[str, float]:
        """Calculate percentiles."""
        if not values:
            return {"p25": 0, "p50": 0, "p75": 0, "p90": 0, "p95": 0}

        sorted_values = sorted(values)
        n = len(sorted_values)

        return {
            "p25": sorted_values[int(0.25 * n)],
            "p50": sorted_values[int(0.50 * n)],
            "p75": sorted_values[int(0.75 * n)],
            "p90": sorted_values[int(0.90 * n)],
            "p95": sorted_values[int(0.95 * n)],
        }

    def _calculate_correlation(self, data1: dict[str, Any], data2: dict[str, Any]) -> float:
        """Calculate correlation between two datasets."""
        # Simplified correlation calculation
        if not data1 or not data2:
            return 0.0

        # Extract numeric values from both datasets
        values1 = self._extract_numeric_values(data1)
        values2 = self._extract_numeric_values(data2)

        if len(values1) != len(values2) or len(values1) == 0:
            return 0.0

        # Calculate Pearson correlation coefficient
        n = len(values1)
        sum1 = sum(values1)
        sum2 = sum(values2)
        sum1_sq = sum(x * x for x in values1)
        sum2_sq = sum(x * x for x in values2)
        sum_products = sum(x * y for x, y in zip(values1, values2, strict=False))

        numerator = n * sum_products - sum1 * sum2
        denominator = ((n * sum1_sq - sum1 * sum1) * (n * sum2_sq - sum2 * sum2)) ** 0.5

        return 0.0 if denominator == 0 else numerator / denominator

    def _calculate_component_consistency(self, components: dict[str, Any]) -> float:
        """Calculate consistency between components."""
        success_rates = [
            1.0 if component["success"] else 0.0
            for component in components.values()
            if isinstance(component, dict) and "success" in component
        ]
        if not success_rates:
            return 0.0

        # Calculate variance in success rates (lower variance = higher consistency)
        mean_success = sum(success_rates) / len(success_rates)
        variance = sum((x - mean_success) ** 2 for x in success_rates) / len(success_rates)

        # Convert variance to consistency score (inverse relationship)
        return max(0.0, 1.0 - variance)

    def _calculate_nesting_depth(self, data: dict[str, Any] | list[Any] | object, current_depth: int = 0) -> int:
        """Calculate maximum nesting depth of data structure."""
        if isinstance(data, dict):
            if not data:
                return current_depth
            return max(self._calculate_nesting_depth(value, current_depth + 1) for value in data.values())
        if isinstance(data, list):
            if not data:
                return current_depth
            return max(self._calculate_nesting_depth(item, current_depth + 1) for item in data)
        return current_depth

    def _analyze_data_types(self, data: dict[str, Any]) -> dict[str, int]:
        """Analyze data types in the structure."""
        type_counts = {}

        def count_types(obj: object) -> None:
            if isinstance(obj, dict):
                type_counts["dict"] = type_counts.get("dict", 0) + 1
                for value in obj.values():
                    count_types(value)
            elif isinstance(obj, list):
                type_counts["list"] = type_counts.get("list", 0) + 1
                for item in obj:
                    count_types(item)
            elif isinstance(obj, str):
                type_counts["str"] = type_counts.get("str", 0) + 1
            elif isinstance(obj, int):
                type_counts["int"] = type_counts.get("int", 0) + 1
            elif isinstance(obj, float):
                type_counts["float"] = type_counts.get("float", 0) + 1
            elif isinstance(obj, bool):
                type_counts["bool"] = type_counts.get("bool", 0) + 1
            else:
                type_counts["other"] = type_counts.get("other", 0) + 1

        count_types(data)
        return type_counts

    def _extract_numeric_values(self, data: dict[str, Any]) -> list[float]:
        """Extract numeric values from nested data structure."""
        values = []

        def extract_values(obj: object) -> None:
            if isinstance(obj, dict):
                for value in obj.values():
                    extract_values(value)
            elif isinstance(obj, list):
                for item in obj:
                    extract_values(item)
            elif isinstance(obj, (int, float)):
                values.append(float(obj))

        extract_values(data)
        return values

    def _categorize_vulnerabilities(self, vulnerabilities: list[dict[str, Any]]) -> dict[str, list[dict[str, Any]]]:
        """Categorize vulnerabilities by type and severity."""
        categories = {
            "memory_corruption": [],
            "injection": [],
            "privilege_escalation": [],
            "information_disclosure": [],
            "denial_of_service": [],
            "cryptographic": [],
            "authentication": [],
            "authorization": [],
            "other": [],
        }

        for vuln in vulnerabilities:
            vuln_type = vuln.get("type", "").lower()
            if any(keyword in vuln_type for keyword in ["buffer", "overflow", "corruption", "heap", "stack"]):
                categories["memory_corruption"].append(vuln)
            elif any(keyword in vuln_type for keyword in ["injection", "xss", "sql", "command"]):
                categories["injection"].append(vuln)
            elif any(keyword in vuln_type for keyword in ["privilege", "escalation", "elevation"]):
                categories["privilege_escalation"].append(vuln)
            elif any(keyword in vuln_type for keyword in ["disclosure", "leak", "exposure"]):
                categories["information_disclosure"].append(vuln)
            elif any(keyword in vuln_type for keyword in ["dos", "denial", "crash"]):
                categories["denial_of_service"].append(vuln)
            elif any(keyword in vuln_type for keyword in ["crypto", "encryption", "hash", "cipher"]):
                categories["cryptographic"].append(vuln)
            elif any(keyword in vuln_type for keyword in ["auth", "login", "password"]):
                categories["authentication"].append(vuln)
            elif any(keyword in vuln_type for keyword in ["authorization", "permission", "access"]):
                categories["authorization"].append(vuln)
            else:
                categories["other"].append(vuln)

        return categories

    def _normalize_cve_matches(self, cve_matches: list[dict[str, Any]]) -> list[dict[str, Any]]:
        """Normalize CVE match data."""
        normalized_matches = []
        for match in cve_matches:
            normalized_match = {
                "cve_id": match.get("cve_id", match.get("id", "unknown")),
                "score": float(match.get("score", match.get("cvss_score", 0.0))),
                "severity": match.get("severity", "unknown"),
                "description": match.get("description", ""),
                "affected_components": match.get("affected_components", []),
                "references": match.get("references", []),
                "published_date": match.get("published_date", ""),
                "last_modified": match.get("last_modified", ""),
                "vector": match.get("vector", ""),
                "exploitability": match.get("exploitability", "unknown"),
                "impact": match.get("impact", "unknown"),
            }
            normalized_matches.append(normalized_match)
        return normalized_matches

    def _normalize_exploit_data(self, exploit_data: dict[str, Any]) -> dict[str, Any]:
        """Normalize exploit generation data."""
        return {
            "exploit_available": exploit_data.get("exploit_available", False),
            "exploit_types": exploit_data.get("exploit_types", []),
            "exploit_complexity": exploit_data.get("complexity", "unknown"),
            "exploit_reliability": exploit_data.get("reliability", "unknown"),
            "required_conditions": exploit_data.get("required_conditions", []),
            "mitigation_bypasses": exploit_data.get("mitigation_bypasses", []),
            "payload_types": exploit_data.get("payload_types", []),
            "delivery_methods": exploit_data.get("delivery_methods", []),
            "success_probability": float(exploit_data.get("success_probability", 0.0)),
            "exploit_code": exploit_data.get("exploit_code", ""),
            "references": exploit_data.get("references", []),
        }

    def _normalize_severity_assessment(self, severity_data: dict[str, Any]) -> dict[str, Any]:
        """Normalize severity assessment data."""
        return {
            "overall_severity": severity_data.get("overall_severity", "unknown"),
            "risk_score": float(severity_data.get("risk_score", 0.0)),
            "exploitability_score": float(severity_data.get("exploitability_score", 0.0)),
            "impact_score": float(severity_data.get("impact_score", 0.0)),
            "environmental_score": float(severity_data.get("environmental_score", 0.0)),
            "temporal_score": float(severity_data.get("temporal_score", 0.0)),
            "confidence_level": severity_data.get("confidence_level", "unknown"),
            "assessment_method": severity_data.get("assessment_method", "automated"),
            "contributing_factors": severity_data.get("contributing_factors", []),
            "severity_breakdown": severity_data.get("severity_breakdown", {}),
            "recommendations": severity_data.get("recommendations", []),
        }

    def _normalize_string_list(self, string_list: list[dict[str, Any]]) -> list[dict[str, Any]]:
        """Normalize string analysis data."""
        normalized_strings = []
        for string_data in string_list:
            if isinstance(string_data, str):
                string_data = {"string": string_data}

            normalized_string = {
                "string": string_data.get("string", string_data.get("value", "")),
                "address": string_data.get("address", string_data.get("addr", 0)),
                "length": string_data.get("length", string_data.get("len", len(string_data.get("string", "")))),
                "encoding": string_data.get("encoding", "ascii"),
                "type": string_data.get("type", "string"),
                "section": string_data.get("section", ""),
                "references": string_data.get("references", []),
                "confidence": float(string_data.get("confidence", 1.0)),
                "entropy": float(string_data.get("entropy", 0.0)),
                "classification": string_data.get("classification", "unknown"),
            }
            normalized_strings.append(normalized_string)
        return normalized_strings

    def _normalize_pattern_list(self, pattern_list: list[dict[str, Any]]) -> list[dict[str, Any]]:
        """Normalize pattern analysis data."""
        normalized_patterns = []
        for pattern_data in pattern_list:
            if isinstance(pattern_data, str):
                pattern_data = {"pattern": pattern_data}

            normalized_pattern = {
                "pattern": pattern_data.get("pattern", pattern_data.get("value", "")),
                "pattern_type": pattern_data.get("pattern_type", pattern_data.get("type", "unknown")),
                "matches": pattern_data.get("matches", []),
                "confidence": float(pattern_data.get("confidence", 1.0)),
                "severity": pattern_data.get("severity", "low"),
                "description": pattern_data.get("description", ""),
                "references": pattern_data.get("references", []),
                "locations": pattern_data.get("locations", []),
            }
            normalized_patterns.append(normalized_pattern)
        return normalized_patterns

    def _normalize_entropy_analysis(self, entropy_data: dict[str, Any]) -> dict[str, Any]:
        """Normalize entropy analysis data."""
        return {
            "overall_entropy": float(entropy_data.get("overall_entropy", 0.0)),
            "section_entropy": entropy_data.get("section_entropy", {}),
            "high_entropy_sections": entropy_data.get("high_entropy_sections", []),
            "entropy_threshold": float(entropy_data.get("entropy_threshold", 7.0)),
            "suspicious_entropy_regions": entropy_data.get("suspicious_entropy_regions", []),
            "entropy_statistics": {
                "mean": float(entropy_data.get("mean_entropy", 0.0)),
                "median": float(entropy_data.get("median_entropy", 0.0)),
                "std_dev": float(entropy_data.get("std_dev_entropy", 0.0)),
                "min": float(entropy_data.get("min_entropy", 0.0)),
                "max": float(entropy_data.get("max_entropy", 0.0)),
            },
            "packed_indicators": entropy_data.get("packed_indicators", []),
            "encryption_indicators": entropy_data.get("encryption_indicators", []),
        }

    def _normalize_cross_references(self, xref_data: dict[str, Any]) -> dict[str, Any]:
        """Normalize cross-reference data."""
        return {
            "function_calls": xref_data.get("function_calls", []),
            "data_references": xref_data.get("data_references", []),
            "string_references": xref_data.get("string_references", []),
            "import_references": xref_data.get("import_references", []),
            "export_references": xref_data.get("export_references", []),
            "call_graph": xref_data.get("call_graph", {}),
            "reference_statistics": {
                "total_references": len(xref_data.get("all_references", [])),
                "internal_references": len(xref_data.get("internal_references", [])),
                "external_references": len(xref_data.get("external_references", [])),
                "unresolved_references": len(xref_data.get("unresolved_references", [])),
            },
        }

    def _normalize_import_list(self, import_list: list[dict[str, Any]]) -> list[dict[str, Any]]:
        """Normalize import data."""
        normalized_imports = []
        for import_data in import_list:
            if isinstance(import_data, str):
                import_data = {"name": import_data}

            normalized_import = {
                "name": import_data.get("name", import_data.get("function", "")),
                "library": import_data.get("library", import_data.get("dll", import_data.get("module", ""))),
                "address": import_data.get("address", import_data.get("addr", 0)),
                "ordinal": import_data.get("ordinal", 0),
                "type": import_data.get("type", "function"),
                "binding": import_data.get("binding", "unknown"),
                "plt_address": import_data.get("plt_address", import_data.get("plt", 0)),
                "got_address": import_data.get("got_address", import_data.get("got", 0)),
                "is_suspicious": bool(import_data.get("is_suspicious", False)),
                "risk_level": import_data.get("risk_level", "low"),
                "description": import_data.get("description", ""),
                "references": import_data.get("references", []),
            }
            normalized_imports.append(normalized_import)
        return normalized_imports

    def _normalize_export_list(self, export_list: list[dict[str, Any]]) -> list[dict[str, Any]]:
        """Normalize export data."""
        normalized_exports = []
        for export_data in export_list:
            if isinstance(export_data, str):
                export_data = {"name": export_data}

            normalized_export = {
                "name": export_data.get("name", export_data.get("function", "")),
                "address": export_data.get("address", export_data.get("addr", 0)),
                "ordinal": export_data.get("ordinal", 0),
                "type": export_data.get("type", "function"),
                "visibility": export_data.get("visibility", "public"),
                "size": export_data.get("size", 0),
                "section": export_data.get("section", ""),
                "is_forwarded": bool(export_data.get("is_forwarded", False)),
                "forward_target": export_data.get("forward_target", ""),
                "is_suspicious": bool(export_data.get("is_suspicious", False)),
                "description": export_data.get("description", ""),
                "references": export_data.get("references", []),
            }
            normalized_exports.append(normalized_export)
        return normalized_exports

    def _normalize_api_categories(self, api_categories: dict[str, Any]) -> dict[str, list[dict[str, Any]]]:
        """Normalize API category data."""
        normalized_categories = {}
        for category, apis in api_categories.items():
            if not isinstance(apis, list):
                apis = []

            normalized_apis = []
            for api in apis:
                if isinstance(api, str):
                    api = {"name": api}

                normalized_api = {
                    "name": api.get("name", ""),
                    "category": category,
                    "risk_level": api.get("risk_level", "low"),
                    "description": api.get("description", ""),
                    "usage_count": api.get("usage_count", 0),
                    "first_seen": api.get("first_seen", ""),
                    "last_seen": api.get("last_seen", ""),
                }
                normalized_apis.append(normalized_api)

            normalized_categories[category] = normalized_apis
        return normalized_categories

    def _normalize_suspicious_apis(self, suspicious_apis: list[dict[str, Any]]) -> list[dict[str, Any]]:
        """Normalize suspicious API data."""
        normalized_apis = []
        for api_data in suspicious_apis:
            if isinstance(api_data, str):
                api_data = {"name": api_data}

            normalized_api = {
                "name": api_data.get("name", ""),
                "reason": api_data.get("reason", api_data.get("suspicion_reason", "")),
                "risk_score": float(api_data.get("risk_score", 0.0)),
                "category": api_data.get("category", "unknown"),
                "indicators": api_data.get("indicators", []),
                "usage_patterns": api_data.get("usage_patterns", []),
                "context": api_data.get("context", ""),
                "mitigation": api_data.get("mitigation", ""),
                "references": api_data.get("references", []),
            }
            normalized_apis.append(normalized_api)
        return normalized_apis

    def _normalize_anti_analysis_apis(self, anti_analysis_apis: list[dict[str, Any]]) -> list[dict[str, Any]]:
        """Normalize anti-analysis API data."""
        normalized_apis = []
        for api_data in anti_analysis_apis:
            if isinstance(api_data, str):
                api_data = {"name": api_data}

            normalized_api = {
                "name": api_data.get("name", ""),
                "technique": api_data.get("technique", api_data.get("anti_analysis_technique", "")),
                "severity": api_data.get("severity", "medium"),
                "evasion_type": api_data.get("evasion_type", "unknown"),
                "detection_difficulty": api_data.get("detection_difficulty", "medium"),
                "bypass_methods": api_data.get("bypass_methods", []),
                "indicators": api_data.get("indicators", []),
                "description": api_data.get("description", ""),
                "countermeasures": api_data.get("countermeasures", []),
            }
            normalized_apis.append(normalized_api)
        return normalized_apis

    def _normalize_library_dependencies(self, dependencies: list[dict[str, Any]]) -> list[dict[str, Any]]:
        """Normalize library dependency data."""
        normalized_deps = []
        for dep_data in dependencies:
            if isinstance(dep_data, str):
                dep_data = {"name": dep_data}

            normalized_dep = {
                "name": dep_data.get("name", dep_data.get("library", "")),
                "version": dep_data.get("version", ""),
                "path": dep_data.get("path", ""),
                "architecture": dep_data.get("architecture", dep_data.get("arch", "")),
                "is_system_library": bool(dep_data.get("is_system_library", False)),
                "is_third_party": bool(dep_data.get("is_third_party", False)),
                "functions_used": dep_data.get("functions_used", []),
                "load_time": dep_data.get("load_time", "static"),
                "security_rating": dep_data.get("security_rating", "unknown"),
                "known_vulnerabilities": dep_data.get("known_vulnerabilities", []),
                "reputation": dep_data.get("reputation", "unknown"),
            }
            normalized_deps.append(normalized_dep)
        return normalized_deps

    def _calculate_api_diversity(self, raw_result: dict[str, Any]) -> float:
        """Calculate API diversity score."""
        imports = raw_result.get("imports", [])
        if not imports:
            return 0.0

        # Calculate diversity based on unique libraries and API categories
        unique_libraries = set()
        api_categories = set()

        for imp in imports:
            if isinstance(imp, dict):
                if library := imp.get("library", imp.get("dll", "")):
                    unique_libraries.add(library)

                # Basic API categorization
                name = imp.get("name", "").lower()
                if any(keyword in name for keyword in ["create", "open", "read", "write"]):
                    api_categories.add("file_io")
                elif any(keyword in name for keyword in ["connect", "send", "recv", "socket"]):
                    api_categories.add("network")
                elif any(keyword in name for keyword in ["alloc", "free", "heap", "virtual"]):
                    api_categories.add("memory")
                elif any(keyword in name for keyword in ["process", "thread", "createprocess"]):
                    api_categories.add("process")
                elif any(keyword in name for keyword in ["reg", "registry", "key"]):
                    api_categories.add("registry")
                else:
                    api_categories.add("other")

        # Diversity score based on number of unique libraries and categories
        library_diversity = len(unique_libraries) / max(len(imports), 1)
        category_diversity = len(api_categories) / 6.0  # 6 total categories

        return min((library_diversity + category_diversity) / 2.0, 1.0)

    def _normalize_complexity_metrics(self, complexity_data: dict[str, Any]) -> dict[str, Any]:
        """Normalize complexity metrics data."""
        return {
            "cyclomatic_complexity": {
                "average": float(complexity_data.get("avg_cyclomatic", 0.0)),
                "maximum": float(complexity_data.get("max_cyclomatic", 0.0)),
                "minimum": float(complexity_data.get("min_cyclomatic", 0.0)),
                "total": float(complexity_data.get("total_cyclomatic", 0.0)),
            },
            "cognitive_complexity": {
                "average": float(complexity_data.get("avg_cognitive", 0.0)),
                "maximum": float(complexity_data.get("max_cognitive", 0.0)),
                "total": float(complexity_data.get("total_cognitive", 0.0)),
            },
            "nesting_depth": {
                "average": float(complexity_data.get("avg_nesting", 0.0)),
                "maximum": float(complexity_data.get("max_nesting", 0.0)),
            },
            "instruction_count": {
                "total": complexity_data.get("total_instructions", 0),
                "average_per_function": float(complexity_data.get("avg_instructions", 0.0)),
            },
            "basic_block_count": {
                "total": complexity_data.get("total_blocks", 0),
                "average_per_function": float(complexity_data.get("avg_blocks", 0.0)),
            },
        }

    def _normalize_cfg_patterns(self, pattern_list: list[dict[str, Any]]) -> list[dict[str, Any]]:
        """Normalize control flow graph patterns."""
        normalized_patterns = []
        for pattern in pattern_list:
            if isinstance(pattern, str):
                pattern = {"pattern": pattern}

            normalized_pattern = {
                "pattern": pattern.get("pattern", ""),
                "pattern_type": pattern.get("pattern_type", pattern.get("type", "unknown")),
                "confidence": float(pattern.get("confidence", 0.0)),
                "locations": pattern.get("locations", []),
                "frequency": pattern.get("frequency", 1),
                "characteristics": pattern.get("characteristics", []),
                "related_functions": pattern.get("related_functions", []),
                "risk_score": float(pattern.get("risk_score", 0.0)),
            }
            normalized_patterns.append(normalized_pattern)
        return normalized_patterns

    def _normalize_graph_data(self, graph_data: dict[str, Any]) -> dict[str, Any]:
        """Normalize graph analysis data."""
        return {
            "nodes": graph_data.get("nodes", []),
            "edges": graph_data.get("edges", []),
            "node_count": len(graph_data.get("nodes", [])),
            "edge_count": len(graph_data.get("edges", [])),
            "density": float(graph_data.get("density", 0.0)),
            "clustering_coefficient": float(graph_data.get("clustering_coefficient", 0.0)),
            "connected_components": graph_data.get("connected_components", 0),
            "diameter": graph_data.get("diameter", 0),
            "average_path_length": float(graph_data.get("average_path_length", 0.0)),
            "centrality_measures": graph_data.get("centrality_measures", {}),
            "strongly_connected_components": graph_data.get("strongly_connected_components", []),
        }

    def _normalize_call_graph(self, call_graph_data: dict[str, Any]) -> dict[str, Any]:
        """Normalize call graph analysis data."""
        return {
            "function_calls": call_graph_data.get("function_calls", []),
            "call_hierarchy": call_graph_data.get("call_hierarchy", {}),
            "entry_points": call_graph_data.get("entry_points", []),
            "leaf_functions": call_graph_data.get("leaf_functions", []),
            "recursive_calls": call_graph_data.get("recursive_calls", []),
            "indirect_calls": call_graph_data.get("indirect_calls", []),
            "call_depth": {
                "maximum": call_graph_data.get("max_call_depth", 0),
                "average": float(call_graph_data.get("avg_call_depth", 0.0)),
            },
            "fan_in_out": {
                "max_fan_in": call_graph_data.get("max_fan_in", 0),
                "max_fan_out": call_graph_data.get("max_fan_out", 0),
                "avg_fan_in": float(call_graph_data.get("avg_fan_in", 0.0)),
                "avg_fan_out": float(call_graph_data.get("avg_fan_out", 0.0)),
            },
        }

    def _normalize_vuln_patterns(self, vuln_data: dict[str, Any]) -> dict[str, Any]:
        """Normalize vulnerability pattern data."""
        return {
            "detected_patterns": vuln_data.get("detected_patterns", []),
            "pattern_categories": vuln_data.get("pattern_categories", {}),
            "confidence_scores": vuln_data.get("confidence_scores", {}),
            "exploit_potential": vuln_data.get("exploit_potential", {}),
            "mitigation_suggestions": vuln_data.get("mitigation_suggestions", []),
            "cwe_mappings": vuln_data.get("cwe_mappings", []),
            "severity_distribution": vuln_data.get("severity_distribution", {}),
            "pattern_locations": vuln_data.get("pattern_locations", []),
        }

    def _normalize_similarity_analysis(self, similarity_data: dict[str, Any]) -> dict[str, Any]:
        """Normalize similarity analysis data."""
        return {
            "function_similarities": similarity_data.get("function_similarities", []),
            "code_clone_detection": similarity_data.get("code_clone_detection", {}),
            "structural_similarities": similarity_data.get("structural_similarities", []),
            "semantic_similarities": similarity_data.get("semantic_similarities", []),
            "similarity_threshold": float(similarity_data.get("similarity_threshold", 0.8)),
            "matching_algorithms": similarity_data.get("matching_algorithms", []),
            "similarity_scores": {
                "average": float(similarity_data.get("avg_similarity", 0.0)),
                "maximum": float(similarity_data.get("max_similarity", 0.0)),
                "minimum": float(similarity_data.get("min_similarity", 0.0)),
            },
        }

    def _get_average_complexity(self, raw_result: dict[str, Any]) -> float:
        """Get average complexity from analysis results."""
        complexity_data = raw_result.get("complexity_metrics", {})
        return float(complexity_data.get("avg_cyclomatic", 0.0))

    def _get_max_complexity(self, raw_result: dict[str, Any]) -> float:
        """Get maximum complexity from analysis results."""
        complexity_data = raw_result.get("complexity_metrics", {})
        return float(complexity_data.get("max_cyclomatic", 0.0))

    def _count_vulnerability_patterns(self, raw_result: dict[str, Any]) -> int:
        """Count vulnerability patterns in analysis results."""
        vuln_data = raw_result.get("vulnerability_analysis", {})
        patterns = vuln_data.get("detected_patterns", [])
        return len(patterns) if isinstance(patterns, list) else 0

    def _calculate_graph_density(self, raw_result: dict[str, Any]) -> float:
        """Calculate graph density from analysis results."""
        graph_data = raw_result.get("graph_data", {})
        nodes = len(graph_data.get("nodes", []))
        edges = len(graph_data.get("edges", []))

        if nodes <= 1:
            return 0.0

        max_edges = nodes * (nodes - 1)
        return (2.0 * edges) / max_edges if max_edges > 0 else 0.0

    def _normalize_ai_license_detection(self, ai_license_data: dict[str, Any]) -> dict[str, Any]:
        """Normalize AI license detection data."""
        return {
            "detected_license_type": ai_license_data.get("detected_license_type", "unknown"),
            "confidence": float(ai_license_data.get("confidence", 0.0)),
            "protection_mechanisms": ai_license_data.get("protection_mechanisms", []),
            "bypass_difficulty": ai_license_data.get("bypass_difficulty", "unknown"),
            "license_patterns": ai_license_data.get("license_patterns", []),
            "key_validation_methods": ai_license_data.get("key_validation_methods", []),
            "anti_tampering_features": ai_license_data.get("anti_tampering_features", []),
            "recommended_approach": ai_license_data.get("recommended_approach", ""),
            "success_probability": float(ai_license_data.get("success_probability", 0.0)),
            "alternative_strategies": ai_license_data.get("alternative_strategies", []),
        }

    def _normalize_ai_vuln_prediction(self, ai_vuln_data: dict[str, Any]) -> dict[str, Any]:
        """Normalize AI vulnerability prediction data."""
        return {
            "predicted_vulnerabilities": ai_vuln_data.get("predicted_vulnerabilities", []),
            "overall_risk_score": float(ai_vuln_data.get("overall_risk_score", 0.0)),
            "confidence_scores": ai_vuln_data.get("confidence_scores", {}),
            "vulnerability_categories": ai_vuln_data.get("vulnerability_categories", {}),
            "exploitability_assessment": ai_vuln_data.get("exploitability_assessment", {}),
            "recommended_mitigations": ai_vuln_data.get("recommended_mitigations", []),
            "false_positive_probability": float(ai_vuln_data.get("false_positive_probability", 0.0)),
            "model_accuracy": float(ai_vuln_data.get("model_accuracy", 0.0)),
            "feature_importance": ai_vuln_data.get("feature_importance", {}),
            "prediction_rationale": ai_vuln_data.get("prediction_rationale", ""),
        }

    def _normalize_function_clustering(self, clustering_data: dict[str, Any]) -> dict[str, Any]:
        """Normalize function clustering data."""
        return {
            "clusters": clustering_data.get("clusters", []),
            "cluster_count": len(clustering_data.get("clusters", [])),
            "clustering_algorithm": clustering_data.get("clustering_algorithm", "unknown"),
            "clustering_quality": float(clustering_data.get("clustering_quality", 0.0)),
            "silhouette_score": float(clustering_data.get("silhouette_score", 0.0)),
            "outliers": clustering_data.get("outliers", []),
            "cluster_characteristics": clustering_data.get("cluster_characteristics", {}),
            "feature_weights": clustering_data.get("feature_weights", {}),
            "similarity_matrix": clustering_data.get("similarity_matrix", []),
            "optimization_metrics": clustering_data.get("optimization_metrics", {}),
        }

    def _normalize_anomaly_detection(self, anomaly_data: dict[str, Any]) -> dict[str, Any]:
        """Normalize anomaly detection data."""
        return {
            "detected_anomalies": anomaly_data.get("detected_anomalies", []),
            "anomaly_score": float(anomaly_data.get("anomaly_score", 0.0)),
            "detection_threshold": float(anomaly_data.get("detection_threshold", 0.5)),
            "anomaly_types": anomaly_data.get("anomaly_types", []),
            "statistical_outliers": anomaly_data.get("statistical_outliers", []),
            "behavioral_anomalies": anomaly_data.get("behavioral_anomalies", []),
            "structural_anomalies": anomaly_data.get("structural_anomalies", []),
            "confidence_intervals": anomaly_data.get("confidence_intervals", {}),
            "baseline_model": anomaly_data.get("baseline_model", "unknown"),
            "anomaly_explanations": anomaly_data.get("anomaly_explanations", []),
        }

    def _normalize_code_similarity(self, similarity_data: dict[str, Any]) -> dict[str, Any]:
        """Normalize code similarity data."""
        return {
            "internal_similarities": similarity_data.get("internal_similarities", []),
            "external_similarities": similarity_data.get("external_similarities", []),
            "average_internal_similarity": float(similarity_data.get("average_internal_similarity", 0.0)),
            "similarity_distribution": similarity_data.get("similarity_distribution", {}),
            "similar_function_pairs": similarity_data.get("similar_function_pairs", []),
            "duplicate_code_blocks": similarity_data.get("duplicate_code_blocks", []),
            "similarity_algorithms": similarity_data.get("similarity_algorithms", []),
            "threshold_settings": similarity_data.get("threshold_settings", {}),
            "code_reuse_patterns": similarity_data.get("code_reuse_patterns", []),
            "semantic_similarities": similarity_data.get("semantic_similarities", []),
        }

    def _normalize_bypass_suggestions(self, bypass_data: dict[str, Any]) -> dict[str, Any]:
        """Normalize automated bypass suggestions data."""
        return {
            "suggested_bypasses": bypass_data.get("suggested_bypasses", []),
            "bypass_categories": bypass_data.get("bypass_categories", {}),
            "success_probabilities": bypass_data.get("success_probabilities", {}),
            "required_tools": bypass_data.get("required_tools", []),
            "complexity_ratings": bypass_data.get("complexity_ratings", {}),
            "prerequisite_conditions": bypass_data.get("prerequisite_conditions", []),
            "alternative_approaches": bypass_data.get("alternative_approaches", []),
            "risk_assessments": bypass_data.get("risk_assessments", {}),
            "automation_scripts": bypass_data.get("automation_scripts", []),
            "manual_steps": bypass_data.get("manual_steps", []),
        }

    def _calculate_bypass_success_probability(self, raw_result: dict[str, Any]) -> float:
        """Calculate overall bypass success probability."""
        bypass_data = raw_result.get("automated_bypass_suggestions", {})
        success_probs = bypass_data.get("success_probabilities", {})

        if not success_probs:
            return 0.0

        # Calculate weighted average of success probabilities
        total_weight = 0
        weighted_sum = 0

        for bypass_type, prob in success_probs.items():
            weight = 1.0  # Default weight
            if "easy" in bypass_type.lower():
                weight = 1.5
            elif "hard" in bypass_type.lower():
                weight = 0.5

            weighted_sum += float(prob) * weight
            total_weight += weight

        return weighted_sum / total_weight if total_weight > 0 else 0.0

    def _perform_cross_component_analysis(self, components: dict[str, dict[str, Any]]) -> dict[str, Any]:
        """Perform cross-component analysis."""
        return {
            "component_interactions": self._analyze_component_interactions(components),
            "shared_indicators": self._find_shared_indicators(components),
            "consistency_checks": self._perform_consistency_checks(components),
            "complementary_findings": self._find_complementary_findings(components),
            "conflicting_results": self._identify_conflicts(components),
            "confidence_aggregation": self._aggregate_confidence_scores(components),
            "recommendation_synthesis": self._synthesize_recommendations(components),
        }

    def _create_unified_findings(self, components: dict[str, dict[str, Any]]) -> dict[str, Any]:
        """Create unified findings from multiple components."""
        unified_findings = {
            "vulnerabilities": [],
            "license_indicators": [],
            "anomalies": [],
            "patterns": [],
            "recommendations": [],
        }

        for component_name, component_data in components.items():
            analysis_results = component_data.get("analysis_results", {})

            # Aggregate vulnerabilities
            if "vulnerabilities" in analysis_results:
                for vuln in analysis_results["vulnerabilities"]:
                    if isinstance(vuln, dict):
                        vuln["source_component"] = component_name
                        unified_findings["vulnerabilities"].append(vuln)

            # Aggregate license indicators
            if "license_strings" in analysis_results:
                for indicator in analysis_results["license_strings"]:
                    if isinstance(indicator, dict):
                        indicator["source_component"] = component_name
                        unified_findings["license_indicators"].append(indicator)

            # Aggregate anomalies
            if "detected_anomalies" in analysis_results:
                for anomaly in analysis_results["detected_anomalies"]:
                    if isinstance(anomaly, dict):
                        anomaly["source_component"] = component_name
                        unified_findings["anomalies"].append(anomaly)

        return unified_findings

    def _perform_correlation_analysis(self, components: dict[str, dict[str, Any]]) -> dict[str, Any]:
        """Perform correlation analysis between components."""
        return {
            "correlation_matrix": self._calculate_correlation_matrix(components),
            "significant_correlations": self._find_significant_correlations(components),
            "causal_relationships": self._identify_causal_relationships(components),
            "dependency_graph": self._build_dependency_graph(components),
            "temporal_correlations": self._analyze_temporal_correlations(components),
            "statistical_measures": self._calculate_statistical_measures(components),
        }

    def _count_total_vulnerabilities(self, components: dict[str, dict[str, Any]]) -> int:
        """Count total vulnerabilities across all components."""
        total_count = 0
        for component_data in components.values():
            analysis_results = component_data.get("analysis_results", {})
            if "vulnerabilities" in analysis_results:
                vulns = analysis_results["vulnerabilities"]
                if isinstance(vulns, list):
                    total_count += len(vulns)
        return total_count

    def _count_total_license_functions(self, components: dict[str, dict[str, Any]]) -> int:
        """Count total license-related functions across all components."""
        total_count = 0
        for component_data in components.values():
            analysis_results = component_data.get("analysis_results", {})
            if "license_strings" in analysis_results:
                license_items = analysis_results["license_strings"]
                if isinstance(license_items, list):
                    total_count += len(license_items)
        return total_count

    def _calculate_overall_risk_score(self, components: dict[str, dict[str, Any]]) -> float:
        """Calculate overall risk score across all components."""
        risk_scores = []
        for component_data in components.values():
            summary_stats = component_data.get("summary_statistics", {})
            if "vulnerability_risk_score" in summary_stats:
                risk_scores.append(float(summary_stats["vulnerability_risk_score"]))
            elif "risk_score" in summary_stats:
                risk_scores.append(float(summary_stats["risk_score"]))

        if not risk_scores:
            return 0.0

        # Calculate weighted average (higher scores get more weight)
        weights = [score + 1 for score in risk_scores]  # Add 1 to avoid zero weights
        weighted_sum = sum(score * weight for score, weight in zip(risk_scores, weights, strict=False))
        total_weight = sum(weights)

        return weighted_sum / total_weight if total_weight > 0 else 0.0

    def _calculate_analysis_completeness(self, components: dict[str, dict[str, Any]]) -> float:
        """Calculate analysis completeness across all components."""
        if not components:
            return 0.0

        successful_components = 0
        total_components = len(components)

        for component_data in components.values():
            status = component_data.get("status", {})
            if status.get("success", False):
                successful_components += 1

        return successful_components / total_components if total_components > 0 else 0.0

    def _create_unified_feature_vector(self, components: dict[str, dict[str, Any]]) -> list[float]:
        """Create unified feature vector from all components."""
        unified_features = []

        for component_data in components.values():
            ml_features = component_data.get("ml_features", {})

            # Extract numerical features
            for feature_group in ml_features.values():
                if isinstance(feature_group, dict):
                    for value in feature_group.values():
                        if isinstance(value, (int, float)):
                            unified_features.append(float(value))
                        elif isinstance(value, list) and all(isinstance(x, (int, float)) for x in value):
                            unified_features.extend([float(x) for x in value])
                elif isinstance(feature_group, list):
                    unified_features.extend(float(item) for item in feature_group if isinstance(item, (int, float)))
        return unified_features

    def _normalize_generic_data(self, raw_data: dict[str, Any]) -> dict[str, Any]:
        """Normalize generic data into standard format."""
        normalized = {}

        for key, value in raw_data.items():
            if isinstance(value, dict):
                normalized[key] = self._normalize_generic_data(value)
            elif isinstance(value, list):
                normalized[key] = [self._normalize_generic_data(item) if isinstance(item, dict) else item for item in value]
            elif isinstance(value, (int, float)):
                normalized[key] = float(value)
            elif isinstance(value, str):
                normalized[key] = value.strip()
            elif isinstance(value, bool):
                normalized[key] = value
            else:
                normalized[key] = str(value)

        return normalized

    # Helper methods for cross-component analysis
    def _analyze_component_interactions(self, components: dict[str, dict[str, Any]]) -> list[dict[str, Any]]:
        """Analyze interactions between components."""
        interactions = []

        # Analyze function-import interactions
        if "functions" in components and "imports" in components:
            functions = components["functions"].get("functions", [])
            imports = components["imports"].get("imports", [])
            import_names = {imp.get("name", "").lower() for imp in imports}

            for func in functions:
                func_name = func.get("name", "").lower()
                # Check if function names suggest interaction with imports
                interactions.extend(
                    {
                        "type": "function_import_interaction",
                        "function": func.get("name"),
                        "import": imp_name,
                        "confidence": 0.8,
                    }
                    for imp_name in import_names
                    if imp_name and len(imp_name) > 3 and imp_name in func_name
                )
        return interactions

    def _find_shared_indicators(self, components: dict[str, dict[str, Any]]) -> list[dict[str, Any]]:
        """Find shared indicators across components."""
        shared_indicators = []

        # Find common strings across different components
        all_strings = set()
        component_strings = {}

        for comp_name, comp_data in components.items():
            comp_strings = set()

            # Extract strings from various data structures
            if isinstance(comp_data, dict):
                strings_data = comp_data.get("strings", [])
                if isinstance(strings_data, list):
                    for string_item in strings_data:
                        if isinstance(string_item, dict):
                            string_val = string_item.get("string", "")
                        else:
                            string_val = str(string_item)
                        if len(string_val) > 4:  # Only meaningful strings
                            comp_strings.add(string_val.lower())
                            all_strings.add(string_val.lower())

            component_strings[comp_name] = comp_strings

        # Find strings that appear in multiple components
        for string_val in all_strings:
            appearing_in = [comp for comp, strings in component_strings.items() if string_val in strings]
            if len(appearing_in) > 1:
                shared_indicators.append(
                    {
                        "type": "shared_string",
                        "value": string_val,
                        "components": appearing_in,
                        "significance": len(appearing_in) / len(components),
                    },
                )

        return shared_indicators

    def _perform_consistency_checks(self, components: dict[str, dict[str, Any]]) -> dict[str, Any]:
        """Perform consistency checks across components."""
        consistency_report = {
            "consistent": True,
            "issues": [],
            "warnings": [],
        }

        binary_info = {
            comp_name: comp_data["binary_info"]
            for comp_name, comp_data in components.items()
            if isinstance(comp_data, dict) and "binary_info" in comp_data
        }
        # Verify architectural consistency
        if len(binary_info) > 1:
            architectures = set()
            for info in binary_info.values():
                if isinstance(info, dict):
                    if arch := info.get("architecture", info.get("arch")):
                        architectures.add(arch)

            if len(architectures) > 1:
                consistency_report["consistent"] = False
                consistency_report["issues"].append(
                    {
                        "type": "architecture_mismatch",
                        "description": f"Multiple architectures detected: {list(architectures)}",
                        "components": list(binary_info.keys()),
                    },
                )

        return consistency_report

    def _find_complementary_findings(self, components: dict[str, dict[str, Any]]) -> list[dict[str, Any]]:
        """Find complementary findings across components."""
        complementary = []

        # Find functions that reference suspicious imports
        if "functions" in components and "imports" in components:
            functions = components["functions"].get("functions", [])
            imports = components["imports"].get("imports", [])

            suspicious_imports = [
                imp
                for imp in imports
                if any(keyword in imp.get("name", "").lower() for keyword in ["crypt", "license", "trial", "activation"])
            ]

            for func in functions:
                func_name = func.get("name", "").lower()
                for sus_imp in suspicious_imports:
                    imp_name = sus_imp.get("name", "").lower()
                    if imp_name and any(part in func_name for part in imp_name.split("_")):
                        complementary.append(
                            {
                                "type": "function_suspicious_import_link",
                                "function": func.get("name"),
                                "import": sus_imp.get("name"),
                                "risk_level": "high",
                            },
                        )

        return complementary

    def _identify_conflicts(self, components: dict[str, dict[str, Any]]) -> list[dict[str, Any]]:
        """Identify conflicting results across components."""
        conflicts = []

        # Check for conflicting protection assessments
        protection_assessments = {}
        for comp_name, comp_data in components.items():
            if isinstance(comp_data, dict):
                # Look for protection or security assessments
                assessment = comp_data.get("protection_assessment", comp_data.get("security_assessment"))
                if assessment and isinstance(assessment, dict):
                    if risk_level := assessment.get("risk_level"):
                        protection_assessments[comp_name] = risk_level

        # Identify conflicting risk levels
        if len(protection_assessments) > 1:
            risk_levels = set(protection_assessments.values())
            if len(risk_levels) > 1:
                conflicts.append(
                    {
                        "type": "risk_level_conflict",
                        "description": "Components disagree on risk assessment",
                        "assessments": protection_assessments,
                        "severity": "medium",
                    },
                )

        return conflicts

    def _aggregate_confidence_scores(self, components: dict[str, dict[str, Any]]) -> dict[str, float]:
        """Aggregate confidence scores across components."""
        aggregated_scores = {}

        # Collect all confidence scores from components
        all_scores = []
        component_scores = {}

        for comp_name, comp_data in components.items():
            scores = []
            if isinstance(comp_data, dict):
                # Extract confidence scores from various analyses
                for value in comp_data.values():
                    if isinstance(value, list):
                        for item in value:
                            if isinstance(item, dict) and "confidence" in item:
                                score = item["confidence"]
                                if isinstance(score, (int, float)) and 0 <= score <= 1:
                                    scores.append(score)

            if scores:
                component_scores[comp_name] = sum(scores) / len(scores)
                all_scores.extend(scores)

        # Calculate overall aggregated confidence
        if all_scores:
            aggregated_scores["overall"] = sum(all_scores) / len(all_scores)
            aggregated_scores["max"] = max(all_scores)
            aggregated_scores["min"] = min(all_scores)

        aggregated_scores |= component_scores
        return aggregated_scores

    def _synthesize_recommendations(self, components: dict[str, dict[str, Any]]) -> list[str]:
        """Synthesize recommendations from all components."""
        recommendations = []

        # Collect all recommendations from components
        all_recommendations = set()

        for comp_data in components.values():
            if isinstance(comp_data, dict):
                # Look for recommendations in various forms
                recs = comp_data.get("recommendations", [])
                suggestions = comp_data.get("suggestions", [])

                # Add recommendations with source attribution
                for rec_list in [recs, suggestions]:
                    if isinstance(rec_list, list):
                        for rec in rec_list:
                            if isinstance(rec, str):
                                all_recommendations.add(rec)
                            elif isinstance(rec, dict):
                                if rec_text := rec.get(
                                    "recommendation",
                                    rec.get("suggestion", rec.get("text")),
                                ):
                                    all_recommendations.add(str(rec_text))

        # Prioritize unique recommendations
        recommendations = list(all_recommendations)

        # Add synthesized recommendations based on cross-component analysis
        if len(components) > 1:
            recommendations.append("Consider cross-component analysis for comprehensive protection bypass")

        return recommendations

    def _calculate_correlation_matrix(self, components: dict[str, dict[str, Any]]) -> list[list[float]]:
        """Calculate correlation matrix between components."""
        component_names = list(components.keys())
        n = len(component_names)

        if n < 2:
            return []

        # Initialize correlation matrix
        correlation_matrix = [[0.0 for _ in range(n)] for _ in range(n)]

        # Calculate pairwise correlations based on shared elements
        for i in range(n):
            for j in range(n):
                if i == j:
                    correlation_matrix[i][j] = 1.0
                else:
                    comp1_data = components[component_names[i]]
                    comp2_data = components[component_names[j]]

                    # Calculate correlation based on shared findings
                    shared_count = 0
                    total_count = 0

                    if isinstance(comp1_data, dict) and isinstance(comp2_data, dict):
                        # Compare similar data types
                        for data_type in ["strings", "functions", "imports"]:
                            data1 = comp1_data.get(data_type, [])
                            data2 = comp2_data.get(data_type, [])

                            if isinstance(data1, list) and isinstance(data2, list):
                                names1 = {item.get("name", str(item)) for item in data1 if isinstance(item, dict)}
                                names2 = {item.get("name", str(item)) for item in data2 if isinstance(item, dict)}

                                if names1 or names2:
                                    shared = len(names1.intersection(names2))
                                    total = len(names1.union(names2))
                                    if total > 0:
                                        shared_count += shared
                                        total_count += total

                    # Calculate normalized correlation
                    if total_count > 0:
                        correlation_matrix[i][j] = shared_count / total_count
                    else:
                        correlation_matrix[i][j] = 0.0

        return correlation_matrix

    def _find_significant_correlations(self, components: dict[str, dict[str, Any]]) -> list[dict[str, Any]]:
        """Find significant correlations between components."""
        significant_correlations = []

        # Use correlation matrix to find significant relationships
        correlation_matrix = self._calculate_correlation_matrix(components)
        component_names = list(components.keys())

        if correlation_matrix and len(component_names) > 1:
            for i in range(len(component_names)):
                for j in range(i + 1, len(component_names)):
                    correlation = correlation_matrix[i][j]
                    if correlation > 0.5:  # Significant correlation threshold
                        significant_correlations.append(
                            {
                                "component1": component_names[i],
                                "component2": component_names[j],
                                "correlation": correlation,
                                "significance": "high" if correlation > 0.8 else "medium",
                            },
                        )

        return significant_correlations

    def _identify_causal_relationships(self, components: dict[str, dict[str, Any]]) -> list[dict[str, Any]]:
        """Identify causal relationships between components."""
        causal_relationships = []

        # Identify function->import causality (functions call imports)
        if "functions" in components and "imports" in components:
            causal_relationships.append(
                {
                    "cause": "functions",
                    "effect": "imports",
                    "relationship_type": "dependency",
                    "description": "Functions depend on imported APIs",
                    "strength": 0.9,
                },
            )

        # Identify strings->protections causality (strings indicate protection mechanisms)
        if "strings" in components and "protections" in components:
            causal_relationships.append(
                {
                    "cause": "strings",
                    "effect": "protections",
                    "relationship_type": "indication",
                    "description": "String content indicates protection mechanisms",
                    "strength": 0.7,
                },
            )

        return causal_relationships

    def _build_dependency_graph(self, components: dict[str, dict[str, Any]]) -> dict[str, Any]:
        """Build dependency graph between components."""
        dependency_graph = {
            "nodes": [],
            "edges": [],
            "metadata": {},
        }

        # Add nodes for each component
        for comp_name, comp_data in components.items():
            node_info = {
                "id": comp_name,
                "type": "component",
                "size": len(comp_data) if isinstance(comp_data, dict) else 1,
            }
            dependency_graph["nodes"].append(node_info)

        # Add edges based on identified relationships
        causal_relationships = self._identify_causal_relationships(components)
        for relationship in causal_relationships:
            edge = {
                "from": relationship["cause"],
                "to": relationship["effect"],
                "type": relationship["relationship_type"],
                "weight": relationship["strength"],
            }
            dependency_graph["edges"].append(edge)

        dependency_graph["metadata"]["total_nodes"] = len(dependency_graph["nodes"])
        dependency_graph["metadata"]["total_edges"] = len(dependency_graph["edges"])

        return dependency_graph

    def _analyze_temporal_correlations(self, components: dict[str, dict[str, Any]]) -> dict[str, Any]:
        """Analyze temporal correlations between components."""
        # Functions typically execute first, followed by imports, then strings are analyzed
        component_priority = {
            "binary_info": 1,
            "imports": 2,
            "functions": 3,
            "strings": 4,
            "protections": 5,
            "vulnerabilities": 6,
        }

        ordered_components = [
            {
                "component": comp_name,
                "priority": component_priority.get(comp_name, 999),
                "dependencies": [],
            }
            for comp_name in sorted(components, key=lambda x: component_priority.get(x, 999))
            if comp_name in components
        ]
        temporal_analysis = {
            "time_dependencies": [],
            "critical_path": [],
            "execution_order": ordered_components,
        }
        # Identify critical path (components that must execute in sequence)
        if len(ordered_components) > 1:
            temporal_analysis["critical_path"] = [comp["component"] for comp in ordered_components[:3]]

        return temporal_analysis

    def _calculate_statistical_measures(self, components: dict[str, dict[str, Any]]) -> dict[str, float]:
        """Calculate statistical measures for correlations."""
        # Initialize measures based on component analysis
        logger.debug(f"Calculating statistical measures for {len(components)} components")

        measures = {
            "component_count": len(components),
            "avg_confidence": 0.0,
            "data_density": 0.0,
        }

        # Calculate averages from components
        confidences = []
        total_entries = 0
        component_types = set()

        for comp_name, comp_data in components.items():
            if isinstance(comp_data, dict):
                total_entries += len(comp_data)
                component_types.add(comp_name)

                if "confidence" in comp_data:
                    confidences.append(comp_data["confidence"])

                # Log component details for debugging
                logger.debug(f"Component {comp_name}: {len(comp_data)} entries")

        if confidences:
            measures["avg_confidence"] = sum(confidences) / len(confidences)

        # Calculate component diversity and density metrics
        measures["component_diversity"] = len(component_types)
        measures["data_density"] = total_entries / max(1, len(components))

        logger.debug(f"Statistical measures: diversity={measures['component_diversity']}, density={measures['data_density']:.2f}")

        if components:
            measures["data_density"] = total_entries / len(components)

        return measures


def standardize_r2_result(
    analysis_type: str,
    raw_result: dict[str, Any],
    binary_path: str,
    metadata: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Standardize any radare2 analysis result.

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


def batch_standardize_results(
    results: list[tuple[str, dict[str, Any], str]],
) -> list[dict[str, Any]]:
    """Batch standardize multiple analysis results.

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
    "R2JSONStandardizer",
    "batch_standardize_results",
    "standardize_r2_result",
]

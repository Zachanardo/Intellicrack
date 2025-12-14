"""Intelligent Correlation Engine for Multi-Tool Analysis Results.

This module provides advanced correlation and pattern recognition capabilities
to identify relationships between findings from different analysis tools,
increasing confidence in discoveries and revealing hidden connections.

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

import hashlib
import json
import logging
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

import networkx as nx
import numpy as np
from sklearn.cluster import DBSCAN
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.metrics.pairwise import cosine_similarity

from intellicrack.core.orchestration.result_serialization_protocol import (
    BaseResult,
    CryptoResult,
    FunctionResult,
    LicenseCheckResult,
    ProtectionResult,
    StringResult,
)


logger = logging.getLogger(__name__)


class CorrelationType(Enum):
    """Types of correlations between analysis results."""

    ADDRESS_MATCH = "address_match"
    XREF_RELATED = "xref_related"
    STRING_REFERENCE = "string_reference"
    CONTROL_FLOW = "control_flow"
    DATA_FLOW = "data_flow"
    TEMPORAL = "temporal"
    SEMANTIC = "semantic"
    PATTERN = "pattern"
    CLUSTER = "cluster"
    PROTECTION = "protection"
    LICENSE = "license"
    CRYPTO = "crypto"


@dataclass
class Correlation:
    """Represents a correlation between analysis results."""

    id: str
    type: CorrelationType
    source_results: list[str]  # Result IDs
    confidence: float
    evidence: dict[str, Any] = field(default_factory=dict)
    timestamp: float = field(default_factory=time.time)
    description: str = ""


@dataclass
class CorrelationCluster:
    """Group of highly correlated results."""

    id: str
    results: list[BaseResult]
    correlations: list[Correlation]
    cluster_type: str
    confidence: float
    summary: dict[str, Any] = field(default_factory=dict)


class IntelligentCorrelationEngine:
    """Advanced correlation engine for multi-tool analysis results."""

    def __init__(self) -> None:
        """Initialize the correlation engine."""
        self.results: dict[str, BaseResult] = {}
        self.correlations: list[Correlation] = []
        self.clusters: list[CorrelationCluster] = []
        self.correlation_graph = nx.Graph()

        # Correlation thresholds
        self.address_proximity_threshold = 0x100  # 256 bytes
        self.semantic_similarity_threshold = 0.7
        self.temporal_window = 5.0  # seconds
        self.min_cluster_size = 3

        # Pattern databases
        self.license_patterns = self._load_license_patterns()
        self.crypto_patterns = self._load_crypto_patterns()
        self.protection_patterns = self._load_protection_patterns()

        # ML models for semantic analysis
        self.tfidf_vectorizer = TfidfVectorizer(max_features=1000)
        self.function_embeddings = {}

    def _load_license_patterns(self) -> dict[str, Any]:
        """Load known license check patterns."""
        return {
            "serial_validation": {
                "functions": ["validate_serial", "check_license", "verify_key"],
                "strings": ["invalid license", "trial expired", "activation required"],
                "api_calls": ["GetVolumeInformation", "GetComputerName", "RegQueryValueEx"],
                "constants": [0x19990318, 0x12345678, 0xDEADBEEF],
            },
            "hwid_check": {
                "functions": ["get_hwid", "machine_id", "hardware_fingerprint"],
                "strings": ["hardware id", "machine code", "device fingerprint"],
                "api_calls": ["GetVolumeSerialNumber", "GetAdaptersInfo", "DeviceIoControl"],
                "wmi_queries": ["Win32_Processor", "Win32_BaseBoard", "Win32_DiskDrive"],
            },
            "time_bomb": {
                "functions": ["check_expiry", "validate_date", "time_limit"],
                "strings": ["trial period", "days remaining", "expired"],
                "api_calls": ["GetSystemTime", "GetLocalTime", "NtQuerySystemTime"],
                "network_checks": ["time.windows.com", "pool.ntp.org"],
            },
            "online_activation": {
                "functions": ["activate_online", "server_validate", "cloud_check"],
                "strings": ["activation server", "license server", "validation endpoint"],
                "api_calls": ["InternetOpen", "HttpSendRequest", "WinHttpOpen"],
                "domains": ["license.company.com", "activate.vendor.net"],
            },
        }

    def _load_crypto_patterns(self) -> dict[str, Any]:
        """Load cryptographic algorithm patterns."""
        return {
            "aes": {
                "constants": [
                    0x63,
                    0x7C,
                    0x77,
                    0x7B,  # AES S-box start
                    0xC66363A5,
                    0xF87C7C84,  # AES round constants
                ],
                "functions": ["aes_encrypt", "aes_decrypt", "rijndael"],
                "key_sizes": [128, 192, 256],
            },
            "rsa": {
                "constants": [0x10001],  # Common public exponent
                "functions": ["rsa_public", "rsa_private", "modexp"],
                "operations": ["modular_exponentiation", "prime_generation"],
            },
            "sha256": {
                "constants": [
                    0x428A2F98,
                    0x71374491,
                    0xB5C0FBCF,
                    0xE9B5DBA5,  # SHA256 K constants
                ],
                "functions": ["sha256_transform", "sha256_update"],
            },
            "custom_crypto": {
                "indicators": ["xor_encrypt", "custom_hash", "proprietary_cipher"],
                "suspicious": ["weak_prng", "hardcoded_key", "simple_xor"],
            },
        }

    def _load_protection_patterns(self) -> dict[str, Any]:
        """Load protection scheme patterns."""
        return {
            "vmprotect": {
                "markers": [".vmp0", ".vmp1", ".vmp2"],
                "imports": ["VMProtectSDK32.dll", "VMProtectSDK64.dll"],
                "mutations": ["virtualized_functions", "mutated_code"],
            },
            "themida": {
                "markers": [".themida", ".WinLicense"],
                "techniques": ["code_virtualization", "api_wrapping"],
                "anti_debug": ["IsDebuggerPresent", "CheckRemoteDebuggerPresent"],
            },
            "denuvo": {
                "markers": ["denuvo64.dll", "denuvo32.dll"],
                "checks": ["integrity_check", "anti_tamper"],
                "triggers": ["steam_api", "origin_api"],
            },
        }

    def add_result(self, result: BaseResult) -> None:
        """Add analysis result to correlation engine."""
        self.results[result.id] = result
        self.correlation_graph.add_node(result.id, result=result)

        # Trigger incremental correlation
        self._correlate_with_existing(result)

    def add_results_batch(self, results: list[BaseResult]) -> None:
        """Add multiple results and perform batch correlation."""
        for result in results:
            self.results[result.id] = result
            self.correlation_graph.add_node(result.id, result=result)

        # Perform comprehensive correlation
        self._perform_comprehensive_correlation()

    def _correlate_with_existing(self, new_result: BaseResult) -> None:
        """Correlate new result with existing results."""
        for result_id, existing_result in self.results.items():
            if result_id == new_result.id:
                continue

            # Check various correlation types
            correlations = []

            # Address-based correlation
            if (
                hasattr(new_result, "address")
                and hasattr(existing_result, "address")
                and self._check_address_correlation(new_result, existing_result)
            ):
                correlations.append(self._create_address_correlation(new_result, existing_result))

            # Cross-reference correlation
            if (
                isinstance(new_result, FunctionResult)
                and isinstance(existing_result, FunctionResult)
                and self._check_xref_correlation(new_result, existing_result)
            ):
                correlations.append(self._create_xref_correlation(new_result, existing_result))

            # String reference correlation
            if isinstance(new_result, StringResult) and self._check_string_reference(new_result, existing_result):
                correlations.append(self._create_string_correlation(new_result, existing_result))

            # Semantic correlation
            if self._check_semantic_correlation(new_result, existing_result):
                correlations.append(self._create_semantic_correlation(new_result, existing_result))

            # Add correlations to graph
            for correlation in correlations:
                self.correlations.append(correlation)
                self.correlation_graph.add_edge(
                    new_result.id,
                    existing_result.id,
                    weight=correlation.confidence,
                    correlation=correlation,
                )

    def _check_address_correlation(self, result1: BaseResult, result2: BaseResult) -> bool:
        """Check if two results are correlated by address proximity."""
        addr1 = getattr(result1, "address", None)
        addr2 = getattr(result2, "address", None)

        if addr1 is None or addr2 is None:
            return False

        return abs(addr1 - addr2) <= self.address_proximity_threshold

    def _check_xref_correlation(self, func1: FunctionResult, func2: FunctionResult) -> bool:
        """Check if functions are related through cross-references."""
        # Check if func1 calls func2
        if func2.address in func1.xrefs_from:
            return True

        # Check if func2 calls func1
        if func1.address in func2.xrefs_from:
            return True

        # Check if they share common callees
        common_calls = set(func1.xrefs_from) & set(func2.xrefs_from)
        return len(common_calls) > 2

    def _check_string_reference(self, string: StringResult, result: BaseResult) -> bool:
        """Check if string is referenced by result."""
        if isinstance(result, FunctionResult):
            # Check if function references this string
            return string.address in result.xrefs_from

        return False

    def _check_semantic_correlation(self, result1: BaseResult, result2: BaseResult) -> bool:
        """Check semantic similarity between results."""
        # Extract text features
        text1 = self._extract_text_features(result1)
        text2 = self._extract_text_features(result2)

        if not text1 or not text2:
            return False

        # Calculate similarity
        try:
            vec1 = self.tfidf_vectorizer.fit_transform([text1])
            vec2 = self.tfidf_vectorizer.transform([text2])
            similarity = cosine_similarity(vec1, vec2)[0][0]
            return similarity >= self.semantic_similarity_threshold
        except (ValueError, IndexError):
            return False

    def _extract_text_features(self, result: BaseResult) -> str:
        """Extract text features from result for semantic analysis."""
        features = []

        if isinstance(result, FunctionResult):
            features.append(result.name)
            if result.decompiled_code:
                features.append(result.decompiled_code[:500])

        elif isinstance(result, StringResult):
            features.append(result.value)

        elif isinstance(result, LicenseCheckResult):
            features.append(result.check_type)
            features.extend(result.extracted_keys)

        # Add metadata
        features.extend(str(v) for v in result.metadata.values() if isinstance(v, str))

        return " ".join(features)

    def _create_address_correlation(self, result1: BaseResult, result2: BaseResult) -> Correlation:
        """Create address-based correlation."""
        distance = abs(getattr(result1, "address", 0) - getattr(result2, "address", 0))
        confidence = 1.0 - (distance / self.address_proximity_threshold)

        return Correlation(
            id=hashlib.sha256(f"{result1.id}_{result2.id}_addr".encode()).hexdigest(),
            type=CorrelationType.ADDRESS_MATCH,
            source_results=[result1.id, result2.id],
            confidence=confidence,
            evidence={"distance": distance},
            description=f"Address proximity: {distance} bytes apart",
        )

    def _create_xref_correlation(self, func1: FunctionResult, func2: FunctionResult) -> Correlation:
        """Create cross-reference correlation."""
        evidence = {}
        confidence = 0.8

        if func2.address in func1.xrefs_from:
            evidence["relationship"] = "func1_calls_func2"
            confidence = 0.9
        elif func1.address in func2.xrefs_from:
            evidence["relationship"] = "func2_calls_func1"
            confidence = 0.9
        else:
            common_calls = set(func1.xrefs_from) & set(func2.xrefs_from)
            evidence["common_calls"] = list(common_calls)
            evidence["relationship"] = "shared_dependencies"
            confidence = 0.7

        return Correlation(
            id=hashlib.sha256(f"{func1.id}_{func2.id}_xref".encode()).hexdigest(),
            type=CorrelationType.XREF_RELATED,
            source_results=[func1.id, func2.id],
            confidence=confidence,
            evidence=evidence,
            description=f"Cross-reference: {evidence.get('relationship', 'related')}",
        )

    def _create_string_correlation(self, string: StringResult, result: BaseResult) -> Correlation:
        """Create string reference correlation."""
        return Correlation(
            id=hashlib.sha256(f"{string.id}_{result.id}_str".encode()).hexdigest(),
            type=CorrelationType.STRING_REFERENCE,
            source_results=[string.id, result.id],
            confidence=0.85,
            evidence={"string_value": string.value[:50]},
            description=f"String '{string.value[:30]}...' referenced",
        )

    def _create_semantic_correlation(self, result1: BaseResult, result2: BaseResult) -> Correlation:
        """Create semantic similarity correlation."""
        text1 = self._extract_text_features(result1)[:100]
        text2 = self._extract_text_features(result2)[:100]

        # Calculate Jaccard similarity between text features
        set1 = set(text1.split()) if text1 else set()
        set2 = set(text2.split()) if text2 else set()
        intersection = set1 & set2
        union = set1 | set2
        similarity = len(intersection) / len(union) if union else 0.0

        return Correlation(
            id=hashlib.sha256(f"{result1.id}_{result2.id}_sem".encode()).hexdigest(),
            type=CorrelationType.SEMANTIC,
            source_results=[result1.id, result2.id],
            confidence=min(0.95, 0.5 + similarity),
            evidence={
                "similarity_type": "semantic",
                "jaccard_similarity": similarity,
                "text1_preview": text1[:30],
                "text2_preview": text2[:30],
            },
            description=f"Semantic similarity detected (Jaccard: {similarity:.2f})",
        )

    def _perform_comprehensive_correlation(self) -> None:
        """Perform comprehensive correlation analysis on all results."""
        # Pattern-based correlation
        self._correlate_license_patterns()
        self._correlate_crypto_patterns()
        self._correlate_protection_patterns()

        # Clustering analysis
        self._perform_clustering()

        # Graph analysis
        self._analyze_correlation_graph()

    def _correlate_license_patterns(self) -> None:
        """Identify license check patterns across results."""
        for pattern_name, pattern in self.license_patterns.items():
            matching_results = []

            # Find functions matching pattern
            for result_id, result in self.results.items():
                if isinstance(result, FunctionResult):
                    if any(pat in result.name.lower() for pat in pattern["functions"]):
                        matching_results.append(result_id)

                elif isinstance(result, StringResult):
                    if any(pat in result.value.lower() for pat in pattern["strings"]):
                        matching_results.append(result_id)

            # Create correlation if multiple matches
            if len(matching_results) >= 2:
                correlation = Correlation(
                    id=hashlib.sha256(f"license_{pattern_name}_{time.time()}".encode()).hexdigest(),
                    type=CorrelationType.LICENSE,
                    source_results=matching_results,
                    confidence=0.85,
                    evidence={"pattern": pattern_name},
                    description=f"License pattern: {pattern_name}",
                )
                self.correlations.append(correlation)

                # Add edges to graph
                for i in range(len(matching_results)):
                    for j in range(i + 1, len(matching_results)):
                        self.correlation_graph.add_edge(
                            matching_results[i],
                            matching_results[j],
                            weight=0.85,
                            correlation=correlation,
                        )

    def _correlate_crypto_patterns(self) -> None:
        """Identify cryptographic patterns across results."""
        for algo_name, pattern in self.crypto_patterns.items():
            matching_results = []

            for result_id, result in self.results.items():
                if isinstance(result, CryptoResult):
                    if result.algorithm.lower() == algo_name:
                        matching_results.append(result_id)

                elif isinstance(result, FunctionResult):
                    # Check for crypto function names
                    if any(pat in result.name.lower() for pat in pattern.get("functions", [])):
                        matching_results.append(result_id)

            if len(matching_results) >= 2:
                correlation = Correlation(
                    id=hashlib.sha256(f"crypto_{algo_name}_{time.time()}".encode()).hexdigest(),
                    type=CorrelationType.CRYPTO,
                    source_results=matching_results,
                    confidence=0.9,
                    evidence={"algorithm": algo_name},
                    description=f"Cryptographic pattern: {algo_name}",
                )
                self.correlations.append(correlation)

    def _correlate_protection_patterns(self) -> None:
        """Identify protection scheme patterns."""
        for protection_name, pattern in self.protection_patterns.items():
            matching_results = []

            for result_id, result in self.results.items():
                if isinstance(result, ProtectionResult):
                    if protection_name in result.name.lower():
                        matching_results.append(result_id)

                elif isinstance(result, StringResult):
                    # Check for protection markers
                    if any(marker in result.value for marker in pattern.get("markers", [])):
                        matching_results.append(result_id)

            if len(matching_results) >= 2:
                correlation = Correlation(
                    id=hashlib.sha256(f"protection_{protection_name}_{time.time()}".encode()).hexdigest(),
                    type=CorrelationType.PROTECTION,
                    source_results=matching_results,
                    confidence=0.88,
                    evidence={"protection": protection_name},
                    description=f"Protection scheme: {protection_name}",
                )
                self.correlations.append(correlation)

    def _perform_clustering(self) -> None:
        """Perform clustering analysis on correlated results."""
        if len(self.results) < self.min_cluster_size:
            return

        # Extract feature vectors
        features = []
        result_ids = []

        for result_id, result in self.results.items():
            feature_vec = self._extract_feature_vector(result)
            if feature_vec is not None:
                features.append(feature_vec)
                result_ids.append(result_id)

        if len(features) < self.min_cluster_size:
            return

        # Perform DBSCAN clustering
        features_array = np.array(features)
        clustering = DBSCAN(eps=0.3, min_samples=self.min_cluster_size).fit(features_array)

        # Create clusters
        cluster_labels = clustering.labels_
        unique_labels = set(cluster_labels)

        for label in unique_labels:
            if label == -1:  # Noise points
                continue

            cluster_indices = np.where(cluster_labels == label)[0]
            cluster_results = [self.results[result_ids[i]] for i in cluster_indices]

            cluster = CorrelationCluster(
                id=hashlib.sha256(f"cluster_{label}_{time.time()}".encode()).hexdigest(),
                results=cluster_results,
                correlations=[],
                cluster_type="density_based",
                confidence=0.8,
                summary={"size": len(cluster_results)},
            )

            self.clusters.append(cluster)

    def _extract_feature_vector(self, result: BaseResult) -> np.ndarray | None:
        """Extract numerical feature vector from result."""
        features = [result.confidence, result.timestamp]

        # Type-specific features
        if hasattr(result, "address"):
            features.append(float(getattr(result, "address", 0)))

        if isinstance(result, FunctionResult):
            features.extend((
                float(result.size),
                float(result.cyclomatic_complexity),
                float(len(result.xrefs_to)),
                float(len(result.xrefs_from)),
            ))
        elif isinstance(result, StringResult):
            features.append(float(result.length))
            features.append(float(result.entropy))
            features.append(float(len(result.references)))

        # Pad or truncate to fixed size
        target_size = 10
        if len(features) < target_size:
            features.extend([0.0] * (target_size - len(features)))
        else:
            features = features[:target_size]

        return np.array(features)

    def _analyze_correlation_graph(self) -> None:
        """Analyze the correlation graph for patterns."""
        # Find strongly connected components
        if self.correlation_graph.number_of_nodes() <= 0:
            return
        components = list(nx.connected_components(self.correlation_graph))

        for component in components:
            if len(component) >= self.min_cluster_size:
                # Create cluster from component
                cluster_results = [self.results[node] for node in component]
                cluster_correlations = []

                # Get correlations within component
                for node1 in component:
                    for node2 in component:
                        if self.correlation_graph.has_edge(node1, node2):
                            edge_data = self.correlation_graph[node1][node2]
                            if "correlation" in edge_data:
                                cluster_correlations.append(edge_data["correlation"])

                cluster = CorrelationCluster(
                    id=hashlib.sha256(f"graph_cluster_{time.time()}".encode()).hexdigest(),
                    results=cluster_results,
                    correlations=cluster_correlations,
                    cluster_type="graph_component",
                    confidence=0.85,
                    summary={
                        "size": len(component),
                        "density": nx.density(self.correlation_graph.subgraph(component)),
                    },
                )

                self.clusters.append(cluster)

    def get_high_confidence_findings(self, min_confidence: float = 0.85) -> list[dict[str, Any]]:
        """Get findings with high correlation confidence."""
        findings = []

        # Check individual correlations
        for correlation in self.correlations:
            if correlation.confidence >= min_confidence:
                finding = {
                    "type": "correlation",
                    "correlation_type": correlation.type.value,
                    "confidence": correlation.confidence,
                    "description": correlation.description,
                    "results": [self.results[rid] for rid in correlation.source_results],
                    "evidence": correlation.evidence,
                }
                findings.append(finding)

        # Check clusters
        for cluster in self.clusters:
            if cluster.confidence >= min_confidence:
                finding = {
                    "type": "cluster",
                    "cluster_type": cluster.cluster_type,
                    "confidence": cluster.confidence,
                    "size": len(cluster.results),
                    "results": cluster.results,
                    "summary": cluster.summary,
                }
                findings.append(finding)

        return findings

    def generate_correlation_report(self) -> dict[str, Any]:
        """Generate comprehensive correlation report."""
        report = {
            "timestamp": time.time(),
            "total_results": len(self.results),
            "total_correlations": len(self.correlations),
            "total_clusters": len(self.clusters),
            "correlation_types": {},
            "high_confidence_findings": self.get_high_confidence_findings(),
            "graph_metrics": {},
            "patterns_detected": {},
        }

        # Count correlation types
        for correlation in self.correlations:
            cor_type = correlation.type.value
            report["correlation_types"][cor_type] = report["correlation_types"].get(cor_type, 0) + 1

        # Graph metrics
        if self.correlation_graph.number_of_nodes() > 0:
            report["graph_metrics"] = {
                "nodes": self.correlation_graph.number_of_nodes(),
                "edges": self.correlation_graph.number_of_edges(),
                "density": nx.density(self.correlation_graph),
                "components": nx.number_connected_components(self.correlation_graph),
            }

        # Pattern detection summary
        for pattern_type in ["license", "crypto", "protection"]:
            if pattern_correlations := [c for c in self.correlations if pattern_type in c.type.value.lower()]:
                report["patterns_detected"][pattern_type] = len(pattern_correlations)

        return report

    def export_to_json(self, output_path: str) -> None:
        """Export correlation analysis to JSON."""
        export_data = {
            "report": self.generate_correlation_report(),
            "correlations": [
                {
                    "id": c.id,
                    "type": c.type.value,
                    "confidence": c.confidence,
                    "description": c.description,
                    "evidence": c.evidence,
                }
                for c in self.correlations
            ],
            "clusters": [
                {
                    "id": cluster.id,
                    "type": cluster.cluster_type,
                    "size": len(cluster.results),
                    "confidence": cluster.confidence,
                    "summary": cluster.summary,
                }
                for cluster in self.clusters
            ],
        }

        with open(output_path, "w") as f:
            json.dump(export_data, f, indent=2)

        logger.info(f"Exported correlation analysis to {output_path}")

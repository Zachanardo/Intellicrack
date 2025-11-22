#!/usr/bin/env python3
"""Intelligent Correlation System.

Production-ready implementation for cross-tool data correlation:
- Fuzzy matching for function names
- Address space translation
- Confidence scoring algorithms
- Anomaly detection system
- Pattern clustering
- Machine learning correlation
"""

import difflib
import json
import logging
import os
import re
import sys
import time
from collections import defaultdict
from dataclasses import dataclass
from enum import Enum
from pathlib import Path

import joblib
import Levenshtein
import numpy as np
from sklearn.cluster import DBSCAN, KMeans
from sklearn.ensemble import IsolationForest, RandomForestClassifier
from sklearn.metrics.pairwise import cosine_similarity
from sklearn.preprocessing import StandardScaler


logger = logging.getLogger(__name__)


class DataType(Enum):
    """Types of data for correlation."""

    FUNCTION = "function"
    VARIABLE = "variable"
    STRING = "string"
    ADDRESS = "address"
    IMPORT = "import"
    EXPORT = "export"
    STRUCTURE = "structure"
    CONSTANT = "constant"
    PATTERN = "pattern"


@dataclass
class CorrelationItem:
    """Item for correlation."""

    tool: str
    data_type: DataType
    name: str
    address: int
    size: int
    attributes: dict[str, Any]
    confidence: float
    timestamp: float


@dataclass
class CorrelationResult:
    """Result of correlation."""

    items: list[CorrelationItem]
    correlation_score: float
    confidence: float
    method: str
    metadata: dict[str, Any]


@dataclass
class AddressMapping:
    """Address space mapping between tools."""

    tool1: str
    tool2: str
    offset: int
    base1: int
    base2: int
    confidence: float


class FuzzyMatcher:
    """Fuzzy matching for names and patterns."""

    def __init__(self) -> None:
        """Initialize the FuzzyMatcher with similarity thresholds."""
        self.similarity_threshold = 0.7
        self.exact_match_boost = 0.2
        self.prefix_suffix_weight = 0.1

    def match_function_names(self, name1: str, name2: str) -> float:
        """Match function names with fuzzy logic."""
        # Clean names
        clean_name1 = self._clean_function_name(name1)
        clean_name2 = self._clean_function_name(name2)

        # Exact match
        if clean_name1 == clean_name2:
            return 1.0

        # Levenshtein distance
        lev_similarity = 1 - (
            Levenshtein.distance(clean_name1, clean_name2) / max(len(clean_name1), len(clean_name2))
        )
        scores = [lev_similarity]
        # Jaro-Winkler similarity
        jw_similarity = Levenshtein.jaro_winkler(clean_name1, clean_name2)
        scores.append(jw_similarity)

        # Token-based similarity
        tokens1 = self._tokenize(clean_name1)
        tokens2 = self._tokenize(clean_name2)
        token_similarity = self._calculate_token_similarity(tokens1, tokens2)
        scores.append(token_similarity)

        # Substring matching
        substring_score = self._substring_similarity(clean_name1, clean_name2)
        scores.append(substring_score)

        # Mangled name detection
        if self._is_mangled(name1) and self._is_mangled(name2):
            mangled_score = self._match_mangled_names(name1, name2)
            scores.append(mangled_score)

        # Weighted average
        return np.mean(scores)

    def _clean_function_name(self, name: str) -> str:
        """Clean function name for comparison."""
        # Remove common prefixes
        prefixes = ["sub_", "loc_", "func_", "FUN_", "j_"]
        for prefix in prefixes:
            name = name.removeprefix(prefix)

        # Remove address suffixes
        name = re.sub(r"_[0-9a-fA-F]{6,}$", "", name)

        # Convert to lowercase
        return name.lower()

    def _tokenize(self, name: str) -> list[str]:
        """Tokenize name into components."""
        # Split by common separators
        tokens = re.split(r"[_\-\s]+", name)

        # Split camelCase
        camel_tokens = []
        for token in tokens:
            camel_tokens.extend(re.findall(r"[A-Z]?[a-z]+|[A-Z]+(?=[A-Z][a-z]|\b)", token))

        return [t.lower() for t in camel_tokens if t]

    def _calculate_token_similarity(self, tokens1: list[str], tokens2: list[str]) -> float:
        """Calculate similarity between token lists."""
        if not tokens1 or not tokens2:
            return 0.0

        # Find common tokens
        common = set(tokens1) & set(tokens2)
        if not common:
            return 0.0

        # Calculate Jaccard similarity
        union = set(tokens1) | set(tokens2)
        jaccard = len(common) / len(union)

        order_score = sum(bool(t1 == t2)
                      for t1, t2 in zip(tokens1, tokens2, strict=False))
        order_bonus = order_score / max(len(tokens1), len(tokens2))

        return jaccard * 0.7 + order_bonus * 0.3

    def _substring_similarity(self, str1: str, str2: str) -> float:
        """Calculate substring similarity."""
        if not str1 or not str2:
            return 0.0

        # Check if one is substring of another
        if str1 in str2 or str2 in str1:
            return 0.8

        # Find longest common substring
        matcher = difflib.SequenceMatcher(None, str1, str2)
        match = matcher.find_longest_match(0, len(str1), 0, len(str2))

        return 0.0 if match.size == 0 else match.size / max(len(str1), len(str2))

    def _is_mangled(self, name: str) -> bool:
        """Check if name is mangled."""
        # C++ mangling patterns
        if name.startswith("_Z") or name.startswith("?"):
            return True

        # MSVC mangling
        return bool("@@" in name or name.startswith("?"))

    def _match_mangled_names(self, name1: str, name2: str) -> float:
        """Match mangled names."""
        # Extract components from mangled names
        components1 = self._extract_mangled_components(name1)
        components2 = self._extract_mangled_components(name2)

        if not components1 or not components2:
            return 0.0

        # Compare class names
        class_score = 0
        if components1.get("class") and components2.get("class"):
            class_score = self._calculate_token_similarity(
                [components1["class"]], [components2["class"]]
            )

        # Compare method names
        method_score = 0
        if components1.get("method") and components2.get("method"):
            method_score = self._calculate_token_similarity(
                [components1["method"]], [components2["method"]]
            )

        # Compare parameters
        param_score = 0
        if components1.get("params") and components2.get("params"):
            param_score = self._compare_parameter_lists(
                components1["params"], components2["params"]
            )

        return class_score * 0.4 + method_score * 0.4 + param_score * 0.2

    def _extract_mangled_components(self, name: str) -> dict[str, Any]:
        """Extract components from mangled name."""
        components = {}

        # C++ Itanium ABI mangling
        if name.startswith("_Z"):
            if match := re.match(r"_Z(\d+)(\w+)", name):
                components["method"] = match[2]

        elif "@@" in name or name.startswith("?"):
            parts = re.split(r"[@?]+", name)
            if len(parts) >= 2:
                components["method"] = parts[1]
            if len(parts) >= 3:
                components["class"] = parts[2]

        return components

    def _compare_parameter_lists(self, params1: list[str], params2: list[str]) -> float:
        """Compare parameter lists."""
        if not params1 and not params2:
            return 1.0
        if not params1 or not params2:
            return 0.0

        matches = sum(bool(self._compare_types(p1, p2) > 0.5)
                  for p1, p2 in zip(params1, params2, strict=False))
        return matches / max(len(params1), len(params2))

    def _compare_types(self, type1: str, type2: str) -> float:
        """Compare type strings."""
        # Normalize types
        type1 = re.sub(r"\s+", "", type1.lower())
        type2 = re.sub(r"\s+", "", type2.lower())

        if type1 == type2:
            return 1.0

        # Check for equivalent types
        equivalents = {
            "int": ["integer", "int32", "dword"],
            "long": ["int64", "qword", "longlong"],
            "char": ["byte", "int8"],
            "void*": ["ptr", "pointer", "lpvoid"],
            "bool": ["boolean", "byte"],
        }

        for base_type, equiv_list in equivalents.items():
            if type1 in [base_type, *equiv_list] and type2 in [base_type, *equiv_list]:
                return 0.9

        return Levenshtein.jaro_winkler(type1, type2)


class AddressTranslator:
    """Translates addresses between different tools' address spaces."""

    def __init__(self) -> None:
        """Initialize the AddressTranslator with empty mappings and base addresses."""
        self.mappings: list[AddressMapping] = []
        self.base_addresses: dict[str, int] = {}
        self.relocations: dict[str, list[tuple[int, int]]] = {}

    def add_mapping(self, mapping: AddressMapping) -> None:
        """Add address space mapping."""
        self.mappings.append(mapping)

    def set_base_address(self, tool: str, base: int) -> None:
        """Set base address for a tool."""
        self.base_addresses[tool] = base

    def add_relocation(self, tool: str, old_addr: int, new_addr: int) -> None:
        """Add relocation entry."""
        if tool not in self.relocations:
            self.relocations[tool] = []
        self.relocations[tool].append((old_addr, new_addr))

    def translate(self, address: int, from_tool: str, to_tool: str) -> int | None:
        """Translate address between tools."""
        # Direct mapping exists
        for mapping in self.mappings:
            if mapping.tool1 == from_tool and mapping.tool2 == to_tool:
                return self._apply_mapping(address, mapping)
            if mapping.tool2 == from_tool and mapping.tool1 == to_tool:
                # Reverse mapping
                reverse_mapping = AddressMapping(
                    tool1=mapping.tool2,
                    tool2=mapping.tool1,
                    offset=-mapping.offset,
                    base1=mapping.base2,
                    base2=mapping.base1,
                    confidence=mapping.confidence,
                )
                return self._apply_mapping(address, reverse_mapping)

        # Try via base addresses
        if from_tool in self.base_addresses and to_tool in self.base_addresses:
            from_base = self.base_addresses[from_tool]
            to_base = self.base_addresses[to_tool]

            # Calculate relative address
            relative = address - from_base

            # Apply to target
            return to_base + relative

        return None

    def _apply_mapping(self, address: int, mapping: AddressMapping) -> int:
        """Apply address mapping."""
        # Check if address is in range
        if mapping.base1 <= address < mapping.base1 + 0x10000000:  # Assume max 256MB
            relative = address - mapping.base1
            return mapping.base2 + relative + mapping.offset

        # Fallback to offset only
        return address + mapping.offset

    def correlate_by_pattern(self, addresses1: list[int], addresses2: list[int]) -> AddressMapping:
        """Correlate address spaces by pattern matching."""
        if not addresses1 or not addresses2:
            return None

        # Calculate deltas within each set
        deltas1 = [addresses1[i + 1] - addresses1[i] for i in range(len(addresses1) - 1)]
        deltas2 = [addresses2[i + 1] - addresses2[i] for i in range(len(addresses2) - 1)]

        common_deltas = [d1 for d1 in deltas1[:10] if d1 in deltas2]
        if not common_deltas:
            return None

        # Calculate offset
        # Find addresses with same delta pattern
        for i, d1 in enumerate(deltas1):
            if d1 in common_deltas:
                for j, d2 in enumerate(deltas2):
                    if d2 == d1:
                        # Potential match
                        offset = addresses2[j] - addresses1[i]

                        matches = sum(bool((addr1 + offset) in addresses2)
                                  for addr1 in addresses1[:20])
                        confidence = matches / min(20, len(addresses1))

                        if confidence > 0.5:
                            return AddressMapping(
                                tool1="tool1",
                                tool2="tool2",
                                offset=offset,
                                base1=min(addresses1),
                                base2=min(addresses2),
                                confidence=confidence,
                            )

        return None


class ConfidenceScorer:
    """Calculates confidence scores for correlations."""

    def __init__(self) -> None:
        """Initialize the ConfidenceScorer with weighting factors for correlation scoring."""
        self.weights = {
            "name_similarity": 0.3,
            "address_proximity": 0.2,
            "size_match": 0.1,
            "attribute_match": 0.2,
            "pattern_match": 0.2,
        }

    def calculate_score(self, item1: CorrelationItem, item2: CorrelationItem) -> float:
        """Calculate confidence score for correlation."""
        # Name similarity
        fuzzy = FuzzyMatcher()
        scores = {
            "name_similarity": fuzzy.match_function_names(item1.name, item2.name)
        }
        # Address proximity (if from same tool or mapped)
        if item1.tool == item2.tool:
            distance = abs(item1.address - item2.address)
            # Normalize distance (assume max meaningful distance is 1MB)
            scores["address_proximity"] = max(0, 1 - (distance / 0x100000))
        else:
            scores["address_proximity"] = 0.5  # Neutral score for different tools

        # Size match
        if item1.size > 0 and item2.size > 0:
            size_ratio = min(item1.size, item2.size) / max(item1.size, item2.size)
            scores["size_match"] = size_ratio
        else:
            scores["size_match"] = 0.5

        # Attribute matching
        scores["attribute_match"] = self._compare_attributes(item1.attributes, item2.attributes)

        # Pattern matching
        scores["pattern_match"] = self._compare_patterns(item1, item2)

        # Calculate weighted score
        total_score = 0
        total_weight = 0

        for key, weight in self.weights.items():
            if key in scores:
                total_score += scores[key] * weight
                total_weight += weight

        return total_score / total_weight if total_weight > 0 else 0

    def _compare_attributes(self, attrs1: dict, attrs2: dict) -> float:
        """Compare attribute dictionaries."""
        if not attrs1 and not attrs2:
            return 1.0
        if not attrs1 or not attrs2:
            return 0.0

        # Find common keys
        common_keys = set(attrs1.keys()) & set(attrs2.keys())
        if not common_keys:
            return 0.0

        matches = sum(bool(self._values_match(attrs1[key], attrs2[key]))
                  for key in common_keys)
        return matches / len(common_keys)

    def _values_match(self, val1: object, val2: object) -> bool:
        """Check if values match.

        Compare two values for equality, with type-specific logic for numeric
        and string types.

        Args:
            val1: First value to compare. Can be any type.
            val2: Second value to compare. Can be any type.

        Returns:
            True if values match according to type-specific rules, False otherwise.

        """
        if type(val1) is not type(val2):
            return False

        if isinstance(val1, (int, float)):
            # Numeric comparison with tolerance
            return abs(val1 - val2) / max(abs(val1), abs(val2), 1) < 0.1

        if isinstance(val1, str):
            # String comparison
            return Levenshtein.jaro_winkler(val1, val2) > 0.8

        # Default comparison
        return val1 == val2

    def _compare_patterns(self, item1: CorrelationItem, item2: CorrelationItem) -> float:
        """Compare patterns between items."""
        # Extract patterns from attributes
        pattern1 = item1.attributes.get("pattern", "")
        pattern2 = item2.attributes.get("pattern", "")

        if not pattern1 or not pattern2:
            # Try to generate pattern from other attributes
            pattern1 = self._generate_pattern(item1)
            pattern2 = self._generate_pattern(item2)

        if not pattern1 or not pattern2:
            return 0.5

        # Compare patterns
        return self._pattern_similarity(pattern1, pattern2)

    def _generate_pattern(self, item: CorrelationItem) -> str:
        """Generate pattern from item attributes."""
        pattern_parts = [item.data_type.value]

        # Add size category
        if item.size < 100:
            pattern_parts.append("small")
        elif item.size < 1000:
            pattern_parts.append("medium")
        else:
            pattern_parts.append("large")

        # Add attribute signatures
        pattern_parts.extend(
            f"{key}:{value}"
            for key, value in sorted(item.attributes.items())
            if isinstance(value, (int, str))
        )
        return "_".join(pattern_parts)

    def _pattern_similarity(self, pattern1: str, pattern2: str) -> float:
        """Calculate pattern similarity."""
        # Tokenize patterns
        tokens1 = set(pattern1.split("_"))
        tokens2 = set(pattern2.split("_"))

        # Jaccard similarity
        intersection = tokens1 & tokens2
        union = tokens1 | tokens2

        return len(intersection) / len(union) if union else 0.0


class AnomalyDetector:
    """Detect anomalies in correlation data."""

    def __init__(self) -> None:
        """Initialize the AnomalyDetector with isolation forest and threshold settings."""
        self.isolation_forest = IsolationForest(contamination=0.1, random_state=42)
        self.threshold_multiplier = 2.0
        self.min_samples = 10

    def detect_anomalies(self, correlations: list[CorrelationResult]) -> list[CorrelationResult]:
        """Detect anomalous correlations."""
        if len(correlations) < self.min_samples:
            return []

        # Extract features
        features = []
        for corr in correlations:
            feature_vector = self._extract_features(corr)
            features.append(feature_vector)

        features = np.array(features)

        # Fit isolation forest
        predictions = self.isolation_forest.fit_predict(features)

        return [correlations[i] for i, pred in enumerate(predictions) if pred == -1]

    def _extract_features(self, correlation: CorrelationResult) -> np.array:
        """Extract numerical features from correlation."""
        features = [
            correlation.correlation_score,
            correlation.confidence,
            len(correlation.items),
        ]

        # Address spread
        if correlation.items:
            addresses = [item.address for item in correlation.items]
            features.append(np.std(addresses) if len(addresses) > 1 else 0)
            features.append(max(addresses) - min(addresses) if addresses else 0)

        if sizes := [item.size for item in correlation.items if item.size > 0]:
            features.append(np.mean(sizes))
            features.append(np.std(sizes))
        else:
            features.extend((0, 0))
        # Tool diversity
        tools = {item.tool for item in correlation.items}
        features.append(len(tools))

        return np.array(features)

    def detect_outliers_statistical(self, values: list[float]) -> list[int]:
        """Detect statistical outliers using IQR method."""
        if len(values) < 4:
            return []

        q1 = np.percentile(values, 25)
        q3 = np.percentile(values, 75)
        iqr = q3 - q1

        lower_bound = q1 - (self.threshold_multiplier * iqr)
        upper_bound = q3 + (self.threshold_multiplier * iqr)

        return [
            i
            for i, value in enumerate(values)
            if value < lower_bound or value > upper_bound
        ]


class PatternClusterer:
    """Clusters patterns in correlation data."""

    def __init__(self) -> None:
        """Initialize the PatternClusterer with clustering algorithms and scaler."""
        self.dbscan = DBSCAN(eps=0.3, min_samples=5)
        self.kmeans = None
        self.scaler = StandardScaler()

    def cluster_patterns(
        self, items: list[CorrelationItem], method: str = "dbscan"
    ) -> dict[int, list[CorrelationItem]]:
        """Cluster correlation items by patterns."""
        if len(items) < 2:
            return {0: items}

        # Extract features
        features = []
        for item in items:
            feature_vector = self._extract_pattern_features(item)
            features.append(feature_vector)

        features = np.array(features)

        # Scale features
        features_scaled = self.scaler.fit_transform(features)

        # Cluster
        if method == "dbscan":
            labels = self.dbscan.fit_predict(features_scaled)
        elif method == "kmeans":
            # Determine optimal k
            k = min(int(np.sqrt(len(items) / 2)), 10)
            self.kmeans = KMeans(n_clusters=k, random_state=42)
            labels = self.kmeans.fit_predict(features_scaled)
        else:
            raise ValueError(f"Unknown clustering method: {method}")

        # Group items by cluster
        clusters = defaultdict(list)
        for i, label in enumerate(labels):
            clusters[label].append(items[i])

        return dict(clusters)

    def _extract_pattern_features(self, item: CorrelationItem) -> np.array:
        """Extract pattern features from item."""
        features = []

        # Data type encoding
        type_encoding = {
            DataType.FUNCTION: 0,
            DataType.VARIABLE: 1,
            DataType.STRING: 2,
            DataType.ADDRESS: 3,
            DataType.IMPORT: 4,
            DataType.EXPORT: 5,
            DataType.STRUCTURE: 6,
            DataType.CONSTANT: 7,
            DataType.PATTERN: 8,
        }
        features.extend((type_encoding.get(item.data_type, -1), item.address))
        features.extend((item.address % 0x1000, item.size))
        features.append(np.log(item.size + 1))

        # Name features
        name_len = len(item.name)
        features.extend((name_len, 1 if item.name.startswith("sub_") else 0))
        features.extend(
            (
                1 if "_" in item.name else 0,
                1 if any(c.isupper() for c in item.name) else 0,
            )
        )
        features.extend((item.confidence, len(item.attributes)))
        return np.array(features)

    def find_similar_patterns(
        self,
        query: CorrelationItem,
        items: list[CorrelationItem],
        top_k: int = 5,
    ) -> list[tuple[CorrelationItem, float]]:
        """Find items with similar patterns."""
        if not items:
            return []

        # Extract features
        query_features = self._extract_pattern_features(query).reshape(1, -1)
        item_features = [self._extract_pattern_features(item) for item in items]
        item_features = np.array(item_features)

        # Scale features
        all_features = np.vstack([query_features, item_features])
        all_features_scaled = self.scaler.fit_transform(all_features)

        query_scaled = all_features_scaled[0].reshape(1, -1)
        items_scaled = all_features_scaled[1:]

        # Calculate similarities
        similarities = cosine_similarity(query_scaled, items_scaled)[0]

        # Get top k
        top_indices = np.argsort(similarities)[-top_k:][::-1]

        return [(items[idx], similarities[idx]) for idx in top_indices]


class MachineLearningCorrelator:
    """Machine learning-based correlation."""

    def __init__(self, model_path: str | None = None) -> None:
        """Initialize the MachineLearningCorrelator with optional model path.

        Args:
            model_path: Path to pre-trained model file. Defaults to None.

        """
        self.model_path = model_path
        self.classifier: RandomForestClassifier | None = None
        self.scaler = StandardScaler()
        self.feature_names = []
        self.training_data = []

        if model_path and Path(model_path).exists():
            self.load_model(model_path)
        else:
            self._initialize_model()

    def _initialize_model(self) -> None:
        """Initialize ML model."""
        self.classifier = RandomForestClassifier(n_estimators=100, max_depth=10, random_state=42)

    def train(
        self,
        positive_pairs: list[tuple[CorrelationItem, CorrelationItem]],
        negative_pairs: list[tuple[CorrelationItem, CorrelationItem]],
    ) -> None:
        """Train the correlation model."""
        X = []
        y = []

        # Process positive pairs
        for item1, item2 in positive_pairs:
            features = self._extract_pair_features(item1, item2)
            X.append(features)
            y.append(1)

        # Process negative pairs
        for item1, item2 in negative_pairs:
            features = self._extract_pair_features(item1, item2)
            X.append(features)
            y.append(0)

        if not X:
            logger.warning("No training data provided")
            return

        # Scale features
        X = np.array(X)
        X_scaled = self.scaler.fit_transform(X)

        # Train classifier
        self.classifier.fit(X_scaled, y)

        # Store training data
        self.training_data = list(zip(X, y, strict=False))

        logger.info(
            f"Trained model with {len(positive_pairs)} positive and {len(negative_pairs)} negative pairs"
        )

    def predict(self, item1: CorrelationItem, item2: CorrelationItem) -> tuple[bool, float]:
        """Predict if items are correlated."""
        if not self.classifier:
            logger.warning("Model not trained")
            return False, 0.0

        # Extract features
        features = self._extract_pair_features(item1, item2).reshape(1, -1)

        # Scale features
        features_scaled = self.scaler.transform(features)

        # Predict
        prediction = self.classifier.predict(features_scaled)[0]
        probability = self.classifier.predict_proba(features_scaled)[0][1]

        return bool(prediction), float(probability)

    def _extract_pair_features(self, item1: CorrelationItem, item2: CorrelationItem) -> np.array:
        """Extract features from item pair."""
        features = []

        # Name similarity
        fuzzy = FuzzyMatcher()
        name_sim = fuzzy.match_function_names(item1.name, item2.name)
        features.extend((name_sim, 1 if item1.data_type == item2.data_type else 0))
        # Size similarity
        if item1.size > 0 and item2.size > 0:
            size_ratio = min(item1.size, item2.size) / max(item1.size, item2.size)
        else:
            size_ratio = 0
        features.append(size_ratio)

        # Address distance (normalized)
        addr_dist = abs(item1.address - item2.address) / 0x100000  # Normalize by 1MB
        features.append(min(addr_dist, 1.0))

        # Confidence product
        features.append(item1.confidence * item2.confidence)

        # Tool match
        features.append(1 if item1.tool == item2.tool else 0)

        # Attribute overlap
        common_attrs = set(item1.attributes.keys()) & set(item2.attributes.keys())
        attr_overlap = len(common_attrs) / max(len(item1.attributes), len(item2.attributes), 1)
        features.append(attr_overlap)

        # Timestamp difference (normalized to hours)
        time_diff = abs(item1.timestamp - item2.timestamp) / 3600
        features.append(min(time_diff, 24))  # Cap at 24 hours

        # String length similarity
        len_ratio = min(len(item1.name), len(item2.name)) / max(len(item1.name), len(item2.name), 1)
        features.append(len_ratio)

        # Common prefix length
        common_prefix = len(os.path.commonprefix([item1.name, item2.name]))
        features.append(common_prefix / max(len(item1.name), len(item2.name), 1))

        return np.array(features)

    def save_model(self, path: str) -> None:
        """Save trained model."""
        model_data = {
            "classifier": self.classifier,
            "scaler": self.scaler,
            "feature_names": self.feature_names,
            "training_data": self.training_data,
        }
        joblib.dump(model_data, path)
        logger.info(f"Model saved to {path}")

    def load_model(self, path: str) -> None:
        """Load trained model."""
        try:
            model_data = joblib.load(path)
            self.classifier = model_data["classifier"]
            self.scaler = model_data["scaler"]
            self.feature_names = model_data.get("feature_names", [])
            self.training_data = model_data.get("training_data", [])
            logger.info(f"Model loaded from {path}")
        except Exception as e:
            logger.error(f"Failed to load model: {e}")
            self._initialize_model()


class IntelligentCorrelator:
    """Run intelligent correlation system."""

    def __init__(self) -> None:
        """Initialize the IntelligentCorrelator with all required components."""
        self.fuzzy_matcher = FuzzyMatcher()
        self.address_translator = AddressTranslator()
        self.confidence_scorer = ConfidenceScorer()
        self.anomaly_detector = AnomalyDetector()
        self.pattern_clusterer = PatternClusterer()
        self.ml_correlator = MachineLearningCorrelator()
        self.correlation_cache: dict[str, CorrelationResult] = {}

    def correlate(
        self, items: list[CorrelationItem], method: str = "hybrid"
    ) -> list[CorrelationResult]:
        """Correlate items using specified method."""
        if method == "fuzzy":
            return self._correlate_fuzzy(items)
        if method == "ml":
            return self._correlate_ml(items)
        if method == "pattern":
            return self._correlate_pattern(items)
        if method == "hybrid":
            return self._correlate_hybrid(items)
        raise ValueError(f"Unknown correlation method: {method}")

    def _correlate_fuzzy(self, items: list[CorrelationItem]) -> list[CorrelationResult]:
        """Correlate using fuzzy matching."""
        results = []

        # Group items by type
        by_type = defaultdict(list)
        for item in items:
            by_type[item.data_type].append(item)

        # Correlate within each type
        for type_items in by_type.values():
            for i in range(len(type_items)):
                for j in range(i + 1, len(type_items)):
                    item1, item2 = type_items[i], type_items[j]

                    # Calculate similarity
                    name_sim = self.fuzzy_matcher.match_function_names(item1.name, item2.name)

                    if name_sim > self.fuzzy_matcher.similarity_threshold:
                        # Calculate confidence
                        confidence = self.confidence_scorer.calculate_score(item1, item2)

                        result = CorrelationResult(
                            items=[item1, item2],
                            correlation_score=name_sim,
                            confidence=confidence,
                            method="fuzzy",
                            metadata={"name_similarity": name_sim},
                        )
                        results.append(result)

        return results

    def _correlate_ml(self, items: list[CorrelationItem]) -> list[CorrelationResult]:
        """Correlate using machine learning."""
        results = []

        # Check all pairs
        for i in range(len(items)):
            for j in range(i + 1, len(items)):
                item1, item2 = items[i], items[j]

                # Predict correlation
                is_correlated, probability = self.ml_correlator.predict(item1, item2)

                if is_correlated:
                    result = CorrelationResult(
                        items=[item1, item2],
                        correlation_score=probability,
                        confidence=probability,
                        method="ml",
                        metadata={"ml_probability": probability},
                    )
                    results.append(result)

        return results

    def _correlate_pattern(self, items: list[CorrelationItem]) -> list[CorrelationResult]:
        """Correlate using pattern clustering."""
        results = []

        # Cluster items
        clusters = self.pattern_clusterer.cluster_patterns(items)

        # Create correlations from clusters
        for cluster_id, cluster_items in clusters.items():
            if len(cluster_items) > 1:
                # Calculate cluster confidence
                confidence = self._calculate_cluster_confidence(cluster_items)

                result = CorrelationResult(
                    items=cluster_items,
                    correlation_score=confidence,
                    confidence=confidence,
                    method="pattern",
                    metadata={"cluster_id": cluster_id, "cluster_size": len(cluster_items)},
                )
                results.append(result)

        return results

    def _correlate_hybrid(self, items: list[CorrelationItem]) -> list[CorrelationResult]:
        """Hybrid correlation using multiple methods."""
        all_results = []

        # Apply all methods
        fuzzy_results = self._correlate_fuzzy(items)
        ml_results = self._correlate_ml(items) if self.ml_correlator.classifier else []
        pattern_results = self._correlate_pattern(items)

        # Merge results
        result_map = {}

        for results in [fuzzy_results, ml_results, pattern_results]:
            for result in results:
                # Create key from items
                key = self._create_result_key(result.items)

                if key not in result_map:
                    result_map[key] = []
                result_map[key].append(result)

        # Combine scores
        for results in result_map.values():
            combined = self._combine_results(results)
            all_results.append(combined)

        return all_results

    def _calculate_cluster_confidence(self, items: list[CorrelationItem]) -> float:
        """Calculate confidence for a cluster of items."""
        if len(items) < 2:
            return 0.0

        # Calculate pairwise similarities
        similarities = []
        for i in range(len(items)):
            for j in range(i + 1, len(items)):
                score = self.confidence_scorer.calculate_score(items[i], items[j])
                similarities.append(score)

        return np.mean(similarities) if similarities else 0.0

    def _create_result_key(self, items: list[CorrelationItem]) -> str:
        """Create unique key for result items."""
        sorted_items = sorted(items, key=lambda x: (x.tool, x.name, x.address))
        key_parts = [f"{item.tool}:{item.name}:{item.address}" for item in sorted_items]
        return "|".join(key_parts)

    def _combine_results(self, results: list[CorrelationResult]) -> CorrelationResult:
        """Combine multiple correlation results."""
        if len(results) == 1:
            return results[0]

        # Combine scores with weights
        method_weights = {"fuzzy": 0.3, "ml": 0.4, "pattern": 0.3}

        total_score = 0
        total_weight = 0
        metadata = {}

        for result in results:
            weight = method_weights.get(result.method, 0.2)
            total_score += result.correlation_score * weight
            total_weight += weight
            metadata[f"{result.method}_score"] = result.correlation_score

        combined_score = total_score / total_weight if total_weight > 0 else 0

        return CorrelationResult(
            items=results[0].items,
            correlation_score=combined_score,
            confidence=np.mean([r.confidence for r in results]),
            method="hybrid",
            metadata=metadata,
        )

    def detect_anomalies(self, correlations: list[CorrelationResult]) -> list[CorrelationResult]:
        """Detect anomalous correlations."""
        return self.anomaly_detector.detect_anomalies(correlations)

    def translate_addresses(
        self, items: list[CorrelationItem], target_tool: str
    ) -> list[CorrelationItem]:
        """Translate addresses to target tool's address space."""
        translated = []

        for item in items:
            if item.tool == target_tool:
                translated.append(item)
            elif new_addr := self.address_translator.translate(
                item.address, item.tool, target_tool
            ):
                translated_item = CorrelationItem(
                    tool=target_tool,
                    data_type=item.data_type,
                    name=item.name,
                    address=new_addr,
                    size=item.size,
                    attributes=item.attributes.copy(),
                    confidence=item.confidence * 0.9,  # Reduce confidence for translation
                    timestamp=item.timestamp,
                )
                translated.append(translated_item)

        return translated


def main() -> None:
    """Demonstrate example usage of intelligent correlation."""
    import argparse

    parser = argparse.ArgumentParser(description="Intelligent Correlation System")
    parser.add_argument("--test", action="store_true", help="Run test correlation")
    parser.add_argument("--train", help="Train ML model with data file")
    parser.add_argument("--model", help="Model file path")

    args = parser.parse_args()

    # Configure logging
    logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")

    correlator = IntelligentCorrelator()

    if args.test:
        # Create test items
        items = [
            CorrelationItem(
                tool="ghidra",
                data_type=DataType.FUNCTION,
                name="check_license_key",
                address=0x401000,
                size=256,
                attributes={"returns": "bool", "params": 1},
                confidence=0.9,
                timestamp=time.time(),
            ),
            CorrelationItem(
                tool="ida",
                data_type=DataType.FUNCTION,
                name="CheckLicenseKey",
                address=0x401100,
                size=250,
                attributes={"returns": "boolean", "params": 1},
                confidence=0.85,
                timestamp=time.time(),
            ),
            CorrelationItem(
                tool="radare2",
                data_type=DataType.FUNCTION,
                name="sub_401000",
                address=0x401000,
                size=260,
                attributes={"type": "function"},
                confidence=0.7,
                timestamp=time.time(),
            ),
        ]

        # Correlate
        results = correlator.correlate(items, method="hybrid")

        print(f"Found {len(results)} correlations:")
        for result in results:
            print(f"  Score: {result.correlation_score:.2f}, Confidence: {result.confidence:.2f}")
            print(f"  Items: {[item.name for item in result.items]}")
            print(f"  Method: {result.method}")
            print()

    elif args.train:
        # Load training data and train model
        print(f"Loading training data from {args.train}...")

        try:
            with open(args.train) as f:
                training_data = json.load(f)

            # Parse positive pairs
            positive_pairs = []
            for pair_data in training_data.get("positive_pairs", []):
                item1 = CorrelationItem(
                    tool=pair_data["item1"]["tool"],
                    data_type=DataType(pair_data["item1"]["data_type"]),
                    name=pair_data["item1"]["name"],
                    address=pair_data["item1"]["address"],
                    size=pair_data["item1"]["size"],
                    attributes=pair_data["item1"].get("attributes", {}),
                    confidence=pair_data["item1"].get("confidence", 1.0),
                    timestamp=pair_data["item1"].get("timestamp", time.time()),
                )
                item2 = CorrelationItem(
                    tool=pair_data["item2"]["tool"],
                    data_type=DataType(pair_data["item2"]["data_type"]),
                    name=pair_data["item2"]["name"],
                    address=pair_data["item2"]["address"],
                    size=pair_data["item2"]["size"],
                    attributes=pair_data["item2"].get("attributes", {}),
                    confidence=pair_data["item2"].get("confidence", 1.0),
                    timestamp=pair_data["item2"].get("timestamp", time.time()),
                )
                positive_pairs.append((item1, item2))

            # Parse negative pairs
            negative_pairs = []
            for pair_data in training_data.get("negative_pairs", []):
                item1 = CorrelationItem(
                    tool=pair_data["item1"]["tool"],
                    data_type=DataType(pair_data["item1"]["data_type"]),
                    name=pair_data["item1"]["name"],
                    address=pair_data["item1"]["address"],
                    size=pair_data["item1"]["size"],
                    attributes=pair_data["item1"].get("attributes", {}),
                    confidence=pair_data["item1"].get("confidence", 1.0),
                    timestamp=pair_data["item1"].get("timestamp", time.time()),
                )
                item2 = CorrelationItem(
                    tool=pair_data["item2"]["tool"],
                    data_type=DataType(pair_data["item2"]["data_type"]),
                    name=pair_data["item2"]["name"],
                    address=pair_data["item2"]["address"],
                    size=pair_data["item2"]["size"],
                    attributes=pair_data["item2"].get("attributes", {}),
                    confidence=pair_data["item2"].get("confidence", 1.0),
                    timestamp=pair_data["item2"].get("timestamp", time.time()),
                )
                negative_pairs.append((item1, item2))

            print(f"Loaded {len(positive_pairs)} positive and {len(negative_pairs)} negative pairs")

            # Train the model
            correlator.ml_correlator.train(positive_pairs, negative_pairs)

            # Save model if path specified
            if args.model:
                correlator.ml_correlator.save_model(args.model)
                print(f"Model saved to {args.model}")
            else:
                default_path = "correlation_model.pkl"
                correlator.ml_correlator.save_model(default_path)
                print(f"Model saved to {default_path}")

        except FileNotFoundError:
            print(f"Error: Training file {args.train} not found")
            sys.exit(1)
        except json.JSONDecodeError as e:
            print(f"Error: Invalid JSON in training file: {e}")
            sys.exit(1)
        except Exception as e:
            print(f"Error loading training data: {e}")
            sys.exit(1)

    else:
        print("Use --test for testing or --train for training")


if __name__ == "__main__":
    main()

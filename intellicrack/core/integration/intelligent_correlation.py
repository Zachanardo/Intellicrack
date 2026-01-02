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
from typing import Any

import joblib
import Levenshtein
import numpy as np
import numpy.typing as npt
from sklearn.cluster import DBSCAN, KMeans
from sklearn.ensemble import IsolationForest, RandomForestClassifier
from sklearn.metrics.pairwise import cosine_similarity
from sklearn.preprocessing import StandardScaler


logger = logging.getLogger(__name__)


class DataType(Enum):
    """Types of data for correlation.

    Enumeration of different data types that can be extracted from binaries
    and correlated across analysis tools.

    Attributes:
        FUNCTION: Function symbol or code region.
        VARIABLE: Variable or data symbol.
        STRING: String constant found in binary.
        ADDRESS: Raw memory address or location.
        IMPORT: Imported function or library reference.
        EXPORT: Exported function or symbol.
        STRUCTURE: Structure or composite type definition.
        CONSTANT: Numeric or constant value.
        PATTERN: Binary pattern or signature match.

    """

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
    """Item for correlation.

    Represents a single data item that can be correlated across different
    binary analysis tools with confidence scoring and metadata.

    Attributes:
        tool: Tool name identifier where item was discovered (e.g., 'ghidra').
        data_type: Type of data item as DataType enum (function, variable, etc).
        name: Identifier or name of the item.
        address: Memory address of the item as integer value.
        size: Size of the item in bytes as integer value.
        attributes: Additional metadata as dictionary with string keys.
        confidence: Confidence score between 0.0 and 1.0.
        timestamp: Unix timestamp when item was created as float.

    """

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
    """Result of correlation.

    Contains the items that are correlated together with scoring information
    and method metadata.

    Attributes:
        items: List of correlation items that matched together.
        correlation_score: Overall correlation score between 0.0 and 1.0.
        confidence: Confidence in the correlation between 0.0 and 1.0.
        method: Name of the correlation method used as string.
        metadata: Additional metadata from correlation process as dictionary.

    """

    items: list[CorrelationItem]
    correlation_score: float
    confidence: float
    method: str
    metadata: dict[str, Any]


@dataclass
class AddressMapping:
    """Address space mapping between tools.

    Represents the translation relationship between address spaces of two
    different binary analysis tools.

    Attributes:
        tool1: First tool name identifier as string.
        tool2: Second tool name identifier as string.
        offset: Address offset to apply during translation as integer.
        base1: Base address of first tool address space as integer.
        base2: Base address of second tool address space as integer.
        confidence: Confidence in the mapping between 0.0 and 1.0.

    """

    tool1: str
    tool2: str
    offset: int
    base1: int
    base2: int
    confidence: float


class FuzzyMatcher:
    """Fuzzy matching for names and patterns."""

    def __init__(self) -> None:
        """Initialize the FuzzyMatcher with similarity thresholds.

        Sets up default thresholds and weights for name similarity calculations
        including Levenshtein distance, Jaro-Winkler, token-based, and substring
        matching algorithms.

        Returns:
            None

        """
        self.similarity_threshold = 0.7
        self.exact_match_boost = 0.2
        self.prefix_suffix_weight = 0.1

    def match_function_names(self, name1: str, name2: str) -> float:
        """Match function names with fuzzy logic.

        Uses multiple similarity metrics including Levenshtein distance,
        Jaro-Winkler similarity, token-based comparison, and substring
        matching to calculate overall name similarity.

        Args:
            name1: First function name to compare.
            name2: Second function name to compare.

        Returns:
            Similarity score between 0.0 and 1.0.

        """
        # Clean names
        clean_name1 = self._clean_function_name(name1)
        clean_name2 = self._clean_function_name(name2)

        # Exact match
        if clean_name1 == clean_name2:
            return 1.0

        # Levenshtein distance
        lev_similarity = 1 - (Levenshtein.distance(clean_name1, clean_name2) / max(len(clean_name1), len(clean_name2)))
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
        return float(np.mean(scores))

    def _clean_function_name(self, name: str) -> str:
        """Clean function name for comparison.

        Removes common prefixes and address suffixes, then converts to lowercase
        for consistent comparison across different tools' naming conventions.

        Args:
            name: Function name to clean.

        Returns:
            Cleaned function name in lowercase without prefixes or suffixes.

        """
        # Remove common prefixes
        prefixes = ["sub_", "loc_", "func_", "FUN_", "j_"]
        for prefix in prefixes:
            name = name.removeprefix(prefix)

        # Remove address suffixes
        name = re.sub(r"_[0-9a-fA-F]{6,}$", "", name)

        # Convert to lowercase
        return name.lower()

    def _tokenize(self, name: str) -> list[str]:
        """Tokenize name into components.

        Splits name by common separators and camelCase boundaries to extract
        individual tokens for comparison.

        Args:
            name: Name string to tokenize.

        Returns:
            List of lowercase tokens extracted from the name by splitting on
            separators and camelCase boundaries.

        """
        # Split by common separators
        tokens = re.split(r"[_\-\s]+", name)

        # Split camelCase
        camel_tokens = []
        for token in tokens:
            camel_tokens.extend(re.findall(r"[A-Z]?[a-z]+|[A-Z]+(?=[A-Z][a-z]|\b)", token))

        return [t.lower() for t in camel_tokens if t]

    def _calculate_token_similarity(self, tokens1: list[str], tokens2: list[str]) -> float:
        """Calculate similarity between token lists.

        Combines Jaccard similarity with token ordering bonus to assess
        how well two tokenized sequences match.

        Args:
            tokens1: First list of tokens to compare.
            tokens2: Second list of tokens to compare.

        Returns:
            Similarity score between 0.0 and 1.0 combining Jaccard and ordering metrics.

        """
        if not tokens1 or not tokens2:
            return 0.0

        # Find common tokens
        common = set(tokens1) & set(tokens2)
        if not common:
            return 0.0

        # Calculate Jaccard similarity
        union = set(tokens1) | set(tokens2)
        jaccard = len(common) / len(union)

        order_score = sum(t1 == t2 for t1, t2 in zip(tokens1, tokens2, strict=False))
        order_bonus = order_score / max(len(tokens1), len(tokens2))

        return jaccard * 0.7 + order_bonus * 0.3

    def _substring_similarity(self, str1: str, str2: str) -> float:
        """Calculate substring similarity.

        Computes similarity based on substring containment and longest common
        substring matching.

        Args:
            str1: First string to compare.
            str2: Second string to compare.

        Returns:
            Similarity score between 0.0 and 1.0 based on substring metrics.

        """
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
        """Check if name is mangled.

        Detects C++ Itanium ABI and MSVC mangled name patterns.

        Args:
            name: Name string to check for mangling patterns.

        Returns:
            True if name appears to be mangled according to C++ ABI standards,
            False otherwise.

        """
        # C++ mangling patterns
        if name.startswith("_Z") or name.startswith("?"):
            return True

        # MSVC mangling
        return bool("@@" in name or name.startswith("?"))

    def _match_mangled_names(self, name1: str, name2: str) -> float:
        """Match mangled names.

        Compares mangled names by extracting and matching class names, method
        names, and parameter signatures.

        Args:
            name1: First mangled name to compare.
            name2: Second mangled name to compare.

        Returns:
            Similarity score between 0.0 and 1.0 based on component matching.

        """
        # Extract components from mangled names
        components1 = self._extract_mangled_components(name1)
        components2 = self._extract_mangled_components(name2)

        if not components1 or not components2:
            return 0.0

        # Compare class names
        class_score = 0.0
        if components1.get("class") and components2.get("class"):
            class_score = self._calculate_token_similarity([components1["class"]], [components2["class"]])

        # Compare method names
        method_score = 0.0
        if components1.get("method") and components2.get("method"):
            method_score = self._calculate_token_similarity([components1["method"]], [components2["method"]])

        # Compare parameters
        param_score = 0.0
        if components1.get("params") and components2.get("params"):
            param_score = self._compare_parameter_lists(components1["params"], components2["params"])

        return class_score * 0.4 + method_score * 0.4 + param_score * 0.2

    def _extract_mangled_components(self, name: str) -> dict[str, Any]:
        """Extract components from mangled name.

        Parses C++ Itanium ABI and MSVC mangled names to extract method
        and class components.

        Args:
            name: Mangled name to parse.

        Returns:
            Dictionary with extracted components including 'method', 'class',
            and 'params' keys where applicable.

        """
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
        """Compare parameter lists.

        Compares two parameter lists by matching individual parameter types.

        Args:
            params1: First parameter list to compare.
            params2: Second parameter list to compare.

        Returns:
            Ratio of matching parameters to total parameters, between 0.0 and 1.0.

        """
        if not params1 and not params2:
            return 1.0
        if not params1 or not params2:
            return 0.0

        matches = sum(self._compare_types(p1, p2) > 0.5 for p1, p2 in zip(params1, params2, strict=False))
        return matches / max(len(params1), len(params2))

    def _compare_types(self, type1: str, type2: str) -> float:
        """Compare type strings.

        Compares C/C++ type strings with normalization and equivalence checking
        for common type aliases.

        Args:
            type1: First type string to compare.
            type2: Second type string to compare.

        Returns:
            Similarity score between 0.0 and 1.0 based on type equivalence.

        """
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
        """Initialize the AddressTranslator with empty mappings and base addresses.

        Creates empty containers for address mappings, base addresses, and
        relocation records for multiple tools.

        Returns:
            None

        """
        self.mappings: list[AddressMapping] = []
        self.base_addresses: dict[str, int] = {}
        self.relocations: dict[str, list[tuple[int, int]]] = {}

    def add_mapping(self, mapping: AddressMapping) -> None:
        """Add address space mapping.

        Appends the provided address mapping to the internal list of mappings
        for later use in address translation operations.

        Args:
            mapping: Address mapping configuration between two tools with offset,
                base addresses, and confidence score.

        Returns:
            None

        """
        self.mappings.append(mapping)

    def set_base_address(self, tool: str, base: int) -> None:
        """Set base address for a tool.

        Stores the base address for a specific tool in the internal mapping dictionary
        for use in address translation between different tool address spaces.

        Args:
            tool: Tool name identifier string (e.g., 'ghidra', 'ida', 'radare2').
            base: Base address for the tool as hexadecimal integer value.

        Returns:
            None

        """
        self.base_addresses[tool] = base

    def add_relocation(self, tool: str, old_addr: int, new_addr: int) -> None:
        """Add relocation entry.

        Records address relocation information for a tool, tracking how addresses
        were moved during binary loading or processing.

        Args:
            tool: Tool name identifier string for the tool performing relocation.
            old_addr: Original address before relocation as integer value.
            new_addr: Address after relocation as integer value.

        Returns:
            None

        """
        if tool not in self.relocations:
            self.relocations[tool] = []
        self.relocations[tool].append((old_addr, new_addr))

    def translate(self, address: int, from_tool: str, to_tool: str) -> int | None:
        """Translate address between tools.

        Attempts translation using direct mappings, reverse mappings, or base
        address calculations. Returns None if no translation path is found.

        Args:
            address: Address to translate as integer value.
            from_tool: Source tool name identifier string (e.g., 'ghidra').
            to_tool: Target tool name identifier string (e.g., 'ida').

        Returns:
            Translated address as integer, or None if translation is not possible.

        """
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
        """Apply address mapping.

        Translates address using mapping configuration with bounds checking.
        Checks if address falls within expected range and applies offset accordingly.

        Args:
            address: Address to translate as integer value.
            mapping: Address mapping configuration with base addresses and offset.

        Returns:
            Translated address as integer value.

        """
        # Check if address is in range
        if mapping.base1 <= address < mapping.base1 + 0x10000000:  # Assume max 256MB
            relative = address - mapping.base1
            return mapping.base2 + relative + mapping.offset

        # Fallback to offset only
        return address + mapping.offset

    def correlate_by_pattern(self, addresses1: list[int], addresses2: list[int]) -> AddressMapping | None:
        """Correlate address spaces by pattern matching.

        Analyzes address delta patterns to identify corresponding regions between
        two address spaces by comparing distance patterns between consecutive addresses.

        Args:
            addresses1: First list of addresses as integer values.
            addresses2: Second list of addresses as integer values.

        Returns:
            Address mapping object if correlation is found with offset and confidence,
            None if correlation is not found or inputs are empty.

        """
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

                        matches = sum(addr1 + offset in addresses2 for addr1 in addresses1[:20])
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
        """Initialize the ConfidenceScorer with weighting factors for correlation scoring.

        Sets up weighted factors for combining multiple similarity metrics into
        a single confidence score.

        Returns:
            None

        """
        self.weights = {
            "name_similarity": 0.3,
            "address_proximity": 0.2,
            "size_match": 0.1,
            "attribute_match": 0.2,
            "pattern_match": 0.2,
        }

    def calculate_score(self, item1: CorrelationItem, item2: CorrelationItem) -> float:
        """Calculate confidence score for correlation.

        Combines name similarity, address proximity, size matching, attribute
        matching, and pattern matching with weighted scoring to produce overall
        confidence value.

        Args:
            item1: First correlation item to score.
            item2: Second correlation item to score.

        Returns:
            Weighted confidence score between 0.0 and 1.0.

        """
        # Name similarity
        fuzzy = FuzzyMatcher()
        scores = {"name_similarity": fuzzy.match_function_names(item1.name, item2.name)}
        # Address proximity (if from same tool or mapped)
        if item1.tool == item2.tool:
            distance = abs(item1.address - item2.address)
            # Normalize distance (assume max meaningful distance is 1MB)
            scores["address_proximity"] = max(0.0, 1.0 - (distance / 0x100000))
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
        total_score = 0.0
        total_weight = 0.0

        for key, weight in self.weights.items():
            if key in scores:
                total_score += scores[key] * weight
                total_weight += weight

        return total_score / total_weight if total_weight > 0 else 0.0

    def _compare_attributes(self, attrs1: dict[str, Any], attrs2: dict[str, Any]) -> float:
        """Compare attribute dictionaries.

        Compares common attributes between two dictionaries using type-specific
        matching logic for each value type.

        Args:
            attrs1: First attributes dictionary to compare with string keys.
            attrs2: Second attributes dictionary to compare with string keys.

        Returns:
            Ratio of matching attributes to common attributes, between 0.0 and 1.0.

        """
        if not attrs1 and not attrs2:
            return 1.0
        if not attrs1 or not attrs2:
            return 0.0

        # Find common keys
        common_keys = set(attrs1.keys()) & set(attrs2.keys())
        if not common_keys:
            return 0.0

        matches = sum(bool(self._values_match(attrs1[key], attrs2[key])) for key in common_keys)
        return matches / len(common_keys)

    def _values_match(self, val1: object, val2: object) -> bool:
        """Check if values match.

        Compare two values for equality, with type-specific logic for numeric
        and string types. Applies tolerance-based comparison for numeric values
        and similarity-based comparison for strings.

        Args:
            val1: First value to compare. Can be any type.
            val2: Second value to compare. Can be any type.

        Returns:
            True if values match according to type-specific rules, False otherwise.

        """
        if type(val1) is not type(val2):
            return False

        if isinstance(val1, (int, float)) and isinstance(val2, (int, float)):
            # Numeric comparison with tolerance
            return abs(val1 - val2) / max(abs(val1), abs(val2), 1) < 0.1

        if isinstance(val1, str) and isinstance(val2, str):
            # String comparison
            return Levenshtein.jaro_winkler(val1, val2) > 0.8

        # Default comparison
        return val1 == val2

    def _compare_patterns(self, item1: CorrelationItem, item2: CorrelationItem) -> float:
        """Compare patterns between items.

        Extracts or generates patterns from items and compares them using
        token-based similarity metrics. Falls back to generation if patterns
        not available in attributes.

        Args:
            item1: First correlation item to compare patterns from.
            item2: Second correlation item to compare patterns from.

        Returns:
            Pattern similarity score between 0.0 and 1.0.

        """
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
        """Generate pattern from item attributes.

        Creates a string pattern encoding the data type, size category, and
        relevant attributes joined with underscores.

        Args:
            item: Correlation item to generate pattern from.

        Returns:
            Pattern string encoding item characteristics including data type,
            size category, and attribute signatures.

        """
        pattern_parts = [item.data_type.value]

        # Add size category
        if item.size < 100:
            pattern_parts.append("small")
        elif item.size < 1000:
            pattern_parts.append("medium")
        else:
            pattern_parts.append("large")

        # Add attribute signatures
        pattern_parts.extend(f"{key}:{value}" for key, value in sorted(item.attributes.items()) if isinstance(value, (int, str)))
        return "_".join(pattern_parts)

    def _pattern_similarity(self, pattern1: str, pattern2: str) -> float:
        """Calculate pattern similarity.

        Computes Jaccard similarity between tokenized patterns by comparing
        unique tokens separated by underscores.

        Args:
            pattern1: First pattern string to compare.
            pattern2: Second pattern string to compare.

        Returns:
            Similarity score between 0.0 and 1.0 using Jaccard metric.

        """
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
        """Initialize the AnomalyDetector with isolation forest and threshold settings.

        Creates isolation forest model and configures IQR outlier detection thresholds.

        Returns:
            None

        """
        self.isolation_forest = IsolationForest(contamination=0.1, random_state=42)
        self.threshold_multiplier = 2.0
        self.min_samples = 10

    def detect_anomalies(self, correlations: list[CorrelationResult]) -> list[CorrelationResult]:
        """Detect anomalous correlations.

        Uses isolation forest algorithm to identify statistically anomalous
        correlation results based on extracted feature vectors. Returns empty
        list if insufficient samples provided.

        Args:
            correlations: List of correlation results to analyze for anomalies.

        Returns:
            List of detected anomalous correlation results identified as outliers
            by the isolation forest algorithm, empty list if insufficient data.

        """
        if len(correlations) < self.min_samples:
            return []

        # Extract features
        features_list: list[npt.NDArray[np.floating[Any]]] = []
        for corr in correlations:
            feature_vector = self._extract_features(corr)
            features_list.append(feature_vector)

        features: npt.NDArray[np.floating[Any]] = np.array(features_list)

        # Fit isolation forest
        predictions = self.isolation_forest.fit_predict(features)

        return [correlations[i] for i, pred in enumerate(predictions) if pred == -1]

    def _extract_features(self, correlation: CorrelationResult) -> npt.NDArray[np.floating[Any]]:
        """Extract numerical features from correlation.

        Extracts score, confidence, item count, address spread, size statistics,
        and tool diversity metrics for anomaly detection using isolation forest.

        Args:
            correlation: Correlation result to extract features from.

        Returns:
            Numpy array of numerical features for isolation forest classification
            containing score, confidence, item count, address statistics, and
            size metrics.

        """
        features: list[float] = [
            correlation.correlation_score,
            correlation.confidence,
            float(len(correlation.items)),
        ]

        # Address spread
        if correlation.items:
            addresses = [item.address for item in correlation.items]
            features.append(float(np.std(addresses)) if len(addresses) > 1 else 0.0)
            features.append(float(max(addresses) - min(addresses)) if addresses else 0.0)

        if sizes := [item.size for item in correlation.items if item.size > 0]:
            features.append(float(np.mean(sizes)))
            features.append(float(np.std(sizes)))
        else:
            features.extend((0.0, 0.0))
        # Tool diversity
        tools = {item.tool for item in correlation.items}
        features.append(float(len(tools)))

        return np.array(features)

    def detect_outliers_statistical(self, values: list[float]) -> list[int]:
        """Detect statistical outliers using IQR method.

        Uses interquartile range method with configurable threshold multiplier
        to identify values outside expected statistical bounds. Returns empty
        list if insufficient values provided.

        Args:
            values: List of numeric values to analyze as floats.

        Returns:
            List of indices of outlier values that fall outside IQR bounds,
            empty list if fewer than 4 values provided.

        """
        if len(values) < 4:
            return []

        q1 = np.percentile(values, 25)
        q3 = np.percentile(values, 75)
        iqr = q3 - q1

        lower_bound = q1 - (self.threshold_multiplier * iqr)
        upper_bound = q3 + (self.threshold_multiplier * iqr)

        return [i for i, value in enumerate(values) if value < lower_bound or value > upper_bound]


class PatternClusterer:
    """Clusters patterns in correlation data."""

    def __init__(self) -> None:
        """Initialize the PatternClusterer with clustering algorithms and scaler.

        Creates DBSCAN clustering model and standard scaler for feature normalization.

        Returns:
            None

        """
        self.dbscan = DBSCAN(eps=0.3, min_samples=5)
        self.kmeans: KMeans | None = None
        self.scaler = StandardScaler()

    def cluster_patterns(self, items: list[CorrelationItem], method: str = "dbscan") -> dict[int, list[CorrelationItem]]:
        """Cluster correlation items by patterns.

        Groups items into clusters based on extracted pattern features using
        either DBSCAN or K-means clustering after feature scaling. Returns
        single cluster for items with fewer than 2 elements.

        Args:
            items: List of correlation items to cluster.
            method: Clustering method name as string, either 'dbscan' or 'kmeans'.
                Defaults to 'dbscan'.

        Returns:
            Dictionary mapping integer cluster labels to lists of correlation
            items in each cluster. Empty items list returns single cluster.

        Raises:
            ValueError: If method is not 'dbscan' or 'kmeans'.

        """
        if len(items) < 2:
            return {0: items}

        # Extract features
        features_list: list[npt.NDArray[np.floating[Any]]] = []
        for item in items:
            feature_vector = self._extract_pattern_features(item)
            features_list.append(feature_vector)

        features: npt.NDArray[np.floating[Any]] = np.array(features_list)

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

    def _extract_pattern_features(self, item: CorrelationItem) -> npt.NDArray[np.floating[Any]]:
        """Extract pattern features from item.

        Extracts numerical features from item including data type encoding, address,
        size, logarithmic size, name characteristics, and confidence score for
        clustering operations.

        Args:
            item: Correlation item to extract features from.

        Returns:
            Numpy array of pattern features for clustering operations including
            type encoding, addresses, size metrics, and name characteristics.

        """
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
        features = [
            type_encoding.get(item.data_type, -1),
            item.address,
            item.address % 0x1000,
            item.size,
            np.log(item.size + 1),
        ]
        # Name features
        name_len = len(item.name)
        features.extend((
            name_len,
            1 if item.name.startswith("sub_") else 0,
            1 if "_" in item.name else 0,
            1 if any(c.isupper() for c in item.name) else 0,
            item.confidence,
            len(item.attributes),
        ))
        return np.array(features)

    def find_similar_patterns(
        self,
        query: CorrelationItem,
        items: list[CorrelationItem],
        top_k: int = 5,
    ) -> list[tuple[CorrelationItem, float]]:
        """Find items with similar patterns.

        Searches for items with patterns most similar to query using cosine
        similarity on extracted pattern features after standardization. Returns
        empty list if items list is empty.

        Args:
            query: Query correlation item to find matches for.
            items: List of items to search within.
            top_k: Number of top matches to return as integer. Defaults to 5.

        Returns:
            List of tuples containing similar items and their cosine similarity
            scores, empty list if items list is empty.

        """
        if not items:
            return []

        # Extract features
        query_features = self._extract_pattern_features(query).reshape(1, -1)
        item_features_list: list[npt.NDArray[np.floating[Any]]] = [self._extract_pattern_features(item) for item in items]
        item_features: npt.NDArray[np.floating[Any]] = np.array(item_features_list)

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

        Creates a new correlator with scikit-learn classifiers. If model_path
        exists, loads pre-trained model; otherwise initializes new classifier.

        Args:
            model_path: Path to pre-trained model file as string. Defaults to None,
                which initializes a new classifier instead.

        Returns:
            None

        """
        self.model_path = model_path
        self.classifier: RandomForestClassifier | None = None
        self.scaler = StandardScaler()
        self.feature_names: list[str] = []
        self.training_data: list[tuple[npt.NDArray[np.floating[Any]], int]] = []

        if model_path and Path(model_path).exists():
            self.load_model(model_path)
        else:
            self._initialize_model()

    def _initialize_model(self) -> None:
        """Initialize ML model.

        Creates a new Random Forest classifier for correlation prediction with
        100 estimators and maximum depth of 10.

        Returns:
            None

        """
        self.classifier = RandomForestClassifier(n_estimators=100, max_depth=10, random_state=42)

    def train(
        self,
        positive_pairs: list[tuple[CorrelationItem, CorrelationItem]],
        negative_pairs: list[tuple[CorrelationItem, CorrelationItem]],
    ) -> None:
        """Train the correlation model.

        Trains Random Forest classifier using positive and negative example pairs
        with feature scaling and logs training summary. Logs warning if no training
        data provided.

        Args:
            positive_pairs: List of item pairs that should correlate as tuples.
            negative_pairs: List of item pairs that should not correlate as tuples.

        Returns:
            None

        """
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
        X_array: npt.NDArray[np.floating[Any]] = np.array(X)
        X_scaled = self.scaler.fit_transform(X_array)

        # Train classifier
        if self.classifier is not None:
            self.classifier.fit(X_scaled, y)

        # Store training data
        self.training_data = list(zip(X, y, strict=False))

        logger.info("Trained model with %s positive and %s negative pairs", len(positive_pairs), len(negative_pairs))

    def predict(self, item1: CorrelationItem, item2: CorrelationItem) -> tuple[bool, float]:
        """Predict if items are correlated.

        Uses trained Random Forest classifier to predict whether two correlation
        items represent the same underlying entity across different tools. Returns
        (False, 0.0) if model not trained.

        Args:
            item1: First correlation item to compare.
            item2: Second correlation item to compare.

        Returns:
            Tuple of (is_correlated, probability) where is_correlated is bool for
            correlation prediction and probability is confidence score between 0-1.

        """
        if not self.classifier or not hasattr(self.classifier, "estimators_"):
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

    def _extract_pair_features(self, item1: CorrelationItem, item2: CorrelationItem) -> npt.NDArray[np.floating[Any]]:
        """Extract features from item pair.

        Extracts 10 numerical features from a pair of items for ML classification:
        name similarity, type match, size ratio, address distance, confidence
        product, tool match, attribute overlap, timestamp difference, name length
        ratio, and common prefix length for correlation prediction.

        Args:
            item1: First correlation item to extract features from.
            item2: Second correlation item to extract features from.

        Returns:
            Numpy array of 10 numerical features for ML classification as floats.

        """
        features: list[float] = []

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
        features.extend((
            min(addr_dist, 1.0),
            item1.confidence * item2.confidence,
            1 if item1.tool == item2.tool else 0,
        ))
        # Attribute overlap
        common_attrs = set(item1.attributes.keys()) & set(item2.attributes.keys())
        attr_overlap = len(common_attrs) / max(len(item1.attributes), len(item2.attributes), 1)
        features.extend((attr_overlap, min(abs(item1.timestamp - item2.timestamp) / 3600, 24)))
        # String length similarity
        len_ratio = min(len(item1.name), len(item2.name)) / max(len(item1.name), len(item2.name), 1)
        features.append(len_ratio)

        # Common prefix length
        common_prefix = len(os.path.commonprefix([item1.name, item2.name]))
        features.append(common_prefix / max(len(item1.name), len(item2.name), 1))

        return np.array(features)

    def save_model(self, path: str) -> None:
        """Save trained model.

        Serializes classifier, scaler, and training metadata to disk using joblib
        and logs the save operation. Overwrites existing file if present.

        Args:
            path: File path where model should be saved as string.

        Returns:
            None

        """
        model_data = {
            "classifier": self.classifier,
            "scaler": self.scaler,
            "feature_names": self.feature_names,
            "training_data": self.training_data,
        }
        joblib.dump(model_data, path)
        logger.info("Model saved to %s", path)

    def load_model(self, path: str) -> None:
        """Load trained model.

        Deserializes classifier, scaler, and training metadata from disk using joblib.
        Initializes default model if loading fails with exception logging.

        Args:
            path: File path to load model from as string.

        Returns:
            None

        Raises:
            Exception: Exceptions during model loading are caught and logged,
                with default model initialized as fallback.

        """
        try:
            model_data = joblib.load(path)
            self.classifier = model_data["classifier"]
            self.scaler = model_data["scaler"]
            self.feature_names = model_data.get("feature_names", [])
            self.training_data = model_data.get("training_data", [])
            logger.info("Model loaded from %s", path)
        except Exception:
            logger.exception("Failed to load model from %s", path)
            self._initialize_model()


class IntelligentCorrelator:
    """Run intelligent correlation system."""

    def __init__(self) -> None:
        """Initialize the IntelligentCorrelator with all required components.

        Creates instances of all correlation subsystems and empty correlation cache.

        Returns:
            None

        """
        self.fuzzy_matcher = FuzzyMatcher()
        self.address_translator = AddressTranslator()
        self.confidence_scorer = ConfidenceScorer()
        self.anomaly_detector = AnomalyDetector()
        self.pattern_clusterer = PatternClusterer()
        self.ml_correlator = MachineLearningCorrelator()
        self.correlation_cache: dict[str, CorrelationResult] = {}

    def correlate(self, items: list[CorrelationItem], method: str = "hybrid") -> list[CorrelationResult]:
        """Correlate items using specified method.

        Routes correlation request to appropriate backend (fuzzy, ML, pattern clustering,
        or hybrid combination) based on method parameter. Hybrid mode combines all
        methods with weighted aggregation and deduplication.

        Args:
            items: List of correlation items to correlate.
            method: Correlation method name as string: 'fuzzy', 'ml', 'pattern',
                or 'hybrid'. Defaults to 'hybrid'.

        Returns:
            List of correlation results combining correlated items with confidence
            scores from selected method.

        Raises:
            ValueError: If method is not one of 'fuzzy', 'ml', 'pattern', or 'hybrid'.

        """
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
        """Correlate using fuzzy matching.

        Groups items by data type and performs pairwise fuzzy name matching
        to find correlations exceeding similarity threshold with confidence scoring.

        Args:
            items: List of correlation items to correlate.

        Returns:
            List of correlation results from fuzzy matching above threshold,
            empty list if no correlations found above threshold.

        """
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
        """Correlate using machine learning.

        Uses trained Random Forest classifier to predict correlations between
        all item pairs and returns predictions above confidence threshold.

        Args:
            items: List of correlation items to correlate.

        Returns:
            List of correlation results from ML prediction for correlated pairs,
            empty list if no correlations predicted.

        """
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
        """Correlate using pattern clustering.

        Groups items into clusters based on extracted features and converts
        multi-item clusters into correlation results with confidence scoring.

        Args:
            items: List of correlation items to correlate.

        Returns:
            List of correlation results from pattern clustering for multi-item
            clusters, empty list if no multi-item clusters found.

        """
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
        """Hybrid correlation using multiple methods.

        Combines fuzzy matching, machine learning, and pattern clustering results
        using weighted aggregation and deduplication for final correlations.

        Args:
            items: List of correlation items to correlate.

        Returns:
            List of hybrid correlation results with weighted combined scores from
            all correlation methods.

        """
        all_results = []

        # Apply all methods
        fuzzy_results = self._correlate_fuzzy(items)
        ml_results = (
            self._correlate_ml(items)
            if self.ml_correlator.classifier is not None
            and hasattr(self.ml_correlator.classifier, "estimators_")
            else []
        )
        pattern_results = self._correlate_pattern(items)

        # Merge results
        result_map: dict[str, list[CorrelationResult]] = {}

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
        """Calculate confidence for a cluster of items.

        Computes mean pairwise confidence scores for all items in cluster
        using the confidence scorer. Returns 0.0 for clusters with fewer than 2 items.

        Args:
            items: List of correlation items in cluster.

        Returns:
            Mean confidence score for cluster between 0.0 and 1.0, 0.0 if fewer
            than 2 items provided.

        """
        if len(items) < 2:
            return 0.0

        # Calculate pairwise similarities
        similarities = []
        for i in range(len(items)):
            for j in range(i + 1, len(items)):
                score = self.confidence_scorer.calculate_score(items[i], items[j])
                similarities.append(score)

        return float(np.mean(similarities)) if similarities else 0.0

    def _create_result_key(self, items: list[CorrelationItem]) -> str:
        """Create unique key for result items.

        Generates deterministic string key from items sorted by tool, name, and address
        for result deduplication and merging across methods.

        Args:
            items: List of correlation items to create key from.

        Returns:
            Unique string key representing the item set with pipe-separated
            components in format 'tool:name:address|...'.

        """
        sorted_items = sorted(items, key=lambda x: (x.tool, x.name, x.address))
        key_parts = [f"{item.tool}:{item.name}:{item.address}" for item in sorted_items]
        return "|".join(key_parts)

    def _combine_results(self, results: list[CorrelationResult]) -> CorrelationResult:
        """Combine multiple correlation results.

        Merges multiple correlation results for same item set using weighted
        averaging based on method weights (fuzzy 0.3, ML 0.4, pattern 0.3) and
        metadata aggregation. Returns first result unchanged if only one provided.

        Args:
            results: List of correlation results to combine.

        Returns:
            Single combined correlation result with weighted aggregated scores and
            combined metadata from all input results.

        """
        if len(results) == 1:
            return results[0]

        # Combine scores with weights
        method_weights = {"fuzzy": 0.3, "ml": 0.4, "pattern": 0.3}

        total_score = 0.0
        total_weight = 0.0
        metadata: dict[str, Any] = {}

        for result in results:
            weight = method_weights.get(result.method, 0.2)
            total_score += result.correlation_score * weight
            total_weight += weight
            metadata[f"{result.method}_score"] = result.correlation_score

        combined_score = total_score / total_weight if total_weight > 0 else 0.0

        return CorrelationResult(
            items=results[0].items,
            correlation_score=combined_score,
            confidence=float(np.mean([r.confidence for r in results])),
            method="hybrid",
            metadata=metadata,
        )

    def detect_anomalies(self, correlations: list[CorrelationResult]) -> list[CorrelationResult]:
        """Detect anomalous correlations.

        Uses isolation forest algorithm to identify statistically anomalous
        correlation results from the provided list using feature extraction.

        Args:
            correlations: List of correlation results to analyze.

        Returns:
            List of detected anomalous correlation results identified as statistical
            outliers by isolation forest, empty list if insufficient data.

        """
        return self.anomaly_detector.detect_anomalies(correlations)

    def translate_addresses(self, items: list[CorrelationItem], target_tool: str) -> list[CorrelationItem]:
        """Translate addresses to target tool's address space.

        Translates correlation items from their native address spaces to target
        tool's address space using address translator. Confidence reduced to 0.9x
        for translated items to account for translation uncertainty. Items already
        in target space are returned unchanged.

        Args:
            items: List of correlation items to translate.
            target_tool: Target tool name identifier string to translate addresses to.

        Returns:
            List of correlation items with translated addresses in target tool space.
            Items not translatable are excluded from results.

        """
        translated = []

        for item in items:
            if item.tool == target_tool:
                translated.append(item)
            elif new_addr := self.address_translator.translate(item.address, item.tool, target_tool):
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
    """Demonstrate example usage of intelligent correlation.

    Runs test correlations or trains ML model with command-line arguments.
    Test mode creates sample correlation items and demonstrates all correlation
    methods. Training mode loads JSON data with positive/negative pairs and
    trains the ML correlator. Supports optional model path argument.

    Returns:
        None

    """
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

        logger.info("Found %s correlations:", len(results))
        for result in results:
            logger.info("  Score: %.2f, Confidence: %.2f", result.correlation_score, result.confidence)
            logger.info("  Items: %s", [item.name for item in result.items])
            logger.info("  Method: %s", result.method)
            logger.info("")

    elif args.train:
        # Load training data and train model
        logger.info("Loading training data from %s...", args.train)

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

            logger.info("Loaded %s positive and %s negative pairs", len(positive_pairs), len(negative_pairs))

            # Train the model
            correlator.ml_correlator.train(positive_pairs, negative_pairs)

            # Save model if path specified
            if args.model:
                correlator.ml_correlator.save_model(args.model)
                logger.info("Model saved to %s", args.model)
            else:
                default_path = "correlation_model.pkl"
                correlator.ml_correlator.save_model(default_path)
                logger.info("Model saved to %s", default_path)

        except FileNotFoundError:
            logger.exception("Training file %s not found", args.train)
            sys.exit(1)
        except json.JSONDecodeError:
            logger.exception("Invalid JSON in training file %s", args.train)
            sys.exit(1)
        except Exception:
            logger.exception("Error loading training data from %s", args.train)
            sys.exit(1)

    else:
        logger.info("Use --test for testing or --train for training")


if __name__ == "__main__":
    main()

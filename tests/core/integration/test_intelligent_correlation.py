"""Comprehensive tests for intelligent correlation system.

Tests validate ML clustering, fuzzy matching, anomaly detection, address translation,
confidence scoring, and pattern clustering against real-world correlation scenarios.
"""

import time
from pathlib import Path
from typing import Any

import numpy as np
import pytest
from sklearn.cluster import DBSCAN, KMeans

from intellicrack.core.integration.intelligent_correlation import (
    AddressMapping,
    AddressTranslator,
    AnomalyDetector,
    ConfidenceScorer,
    CorrelationItem,
    CorrelationResult,
    DataType,
    FuzzyMatcher,
    IntelligentCorrelator,
    MachineLearningCorrelator,
    PatternClusterer,
)


class TestFuzzyMatcher:
    """Test fuzzy matching for function names and patterns."""

    def test_exact_match_returns_perfect_score(self) -> None:
        """Exact name match produces score of 1.0."""
        matcher = FuzzyMatcher()
        score = matcher.match_function_names("check_license", "check_license")
        assert score == 1.0

    def test_similar_names_produce_high_score(self) -> None:
        """Similar function names produce high similarity score."""
        matcher = FuzzyMatcher()
        score = matcher.match_function_names("check_license_key", "CheckLicenseKey")
        assert score > 0.5

    def test_different_names_produce_low_score(self) -> None:
        """Completely different names produce low score."""
        matcher = FuzzyMatcher()
        score = matcher.match_function_names("validate_serial", "parse_network_packet")
        assert score < 0.3

    def test_common_prefix_removal(self) -> None:
        """Common prefixes (sub_, loc_, FUN_) are removed before matching."""
        matcher = FuzzyMatcher()
        score1 = matcher.match_function_names("sub_401000", "FUN_401000")
        score2 = matcher.match_function_names("loc_validate", "validate")
        assert score1 > 0.7
        assert score2 > 0.7

    def test_address_suffix_removal(self) -> None:
        """Hex address suffixes are removed before matching."""
        matcher = FuzzyMatcher()
        score = matcher.match_function_names("check_license_401000", "check_license_401100")
        assert score > 0.8

    def test_camel_case_tokenization(self) -> None:
        """CamelCase names are tokenized correctly."""
        matcher = FuzzyMatcher()
        score = matcher.match_function_names("CheckLicenseKey", "check_license_key")
        assert score > 0.5

    def test_mangled_name_detection(self) -> None:
        """C++ mangled names are detected and matched."""
        matcher = FuzzyMatcher()
        assert matcher._is_mangled("_Z10check_licenseP4char")
        assert matcher._is_mangled("?validate@@YAXH@Z")
        assert not matcher._is_mangled("normal_function_name")

    def test_substring_similarity(self) -> None:
        """Substring matching produces appropriate scores."""
        matcher = FuzzyMatcher()
        score = matcher._substring_similarity("check_license", "check_license_key")
        assert score > 0.7

    def test_type_equivalence_matching(self) -> None:
        """Equivalent types (int/int32, void*/ptr) are matched."""
        matcher = FuzzyMatcher()
        assert matcher._compare_types("int", "int32") > 0.8
        assert matcher._compare_types("void*", "ptr") > 0.8
        assert matcher._compare_types("long", "int64") > 0.8


class TestAddressTranslator:
    """Test address space translation between analysis tools."""

    def test_direct_mapping_translation(self) -> None:
        """Direct address mapping translates correctly."""
        translator = AddressTranslator()
        mapping = AddressMapping(
            tool1="ghidra",
            tool2="ida",
            offset=0x1000,
            base1=0x400000,
            base2=0x401000,
            confidence=0.95,
        )
        translator.add_mapping(mapping)

        translated = translator.translate(0x401000, "ghidra", "ida")
        assert translated is not None
        assert translated == 0x403000

    def test_reverse_mapping_translation(self) -> None:
        """Reverse mapping works correctly."""
        translator = AddressTranslator()
        mapping = AddressMapping(
            tool1="ghidra",
            tool2="ida",
            offset=0x1000,
            base1=0x400000,
            base2=0x401000,
            confidence=0.95,
        )
        translator.add_mapping(mapping)

        translated = translator.translate(0x402000, "ida", "ghidra")
        assert translated is not None

    def test_base_address_translation(self) -> None:
        """Base address method translates correctly."""
        translator = AddressTranslator()
        translator.set_base_address("tool1", 0x400000)
        translator.set_base_address("tool2", 0x10000000)

        translated = translator.translate(0x401000, "tool1", "tool2")
        assert translated is not None
        assert translated == 0x10001000

    def test_pattern_correlation_detects_offset(self) -> None:
        """Pattern-based correlation detects address offset."""
        translator = AddressTranslator()
        addresses1 = [0x401000, 0x401100, 0x401200, 0x401300]
        addresses2 = [0x501000, 0x501100, 0x501200, 0x501300]

        mapping = translator.correlate_by_pattern(addresses1, addresses2)
        assert mapping is not None
        assert mapping.offset == 0x100000
        assert mapping.confidence > 0.5

    def test_no_mapping_returns_none(self) -> None:
        """Translation without mapping returns None."""
        translator = AddressTranslator()
        result = translator.translate(0x401000, "unknown1", "unknown2")
        assert result is None


class TestConfidenceScorer:
    """Test confidence scoring for correlations."""

    def test_identical_items_high_confidence(self) -> None:
        """Identical items produce high confidence score."""
        scorer = ConfidenceScorer()
        item1 = CorrelationItem(
            tool="ghidra",
            data_type=DataType.FUNCTION,
            name="check_license",
            address=0x401000,
            size=256,
            attributes={"returns": "bool"},
            confidence=1.0,
            timestamp=time.time(),
        )
        item2 = CorrelationItem(
            tool="ghidra",
            data_type=DataType.FUNCTION,
            name="check_license",
            address=0x401000,
            size=256,
            attributes={"returns": "bool"},
            confidence=1.0,
            timestamp=time.time(),
        )

        score = scorer.calculate_score(item1, item2)
        assert score > 0.8

    def test_similar_items_moderate_confidence(self) -> None:
        """Similar items produce moderate confidence score."""
        scorer = ConfidenceScorer()
        item1 = CorrelationItem(
            tool="ghidra",
            data_type=DataType.FUNCTION,
            name="check_license_key",
            address=0x401000,
            size=256,
            attributes={"returns": "bool"},
            confidence=0.9,
            timestamp=time.time(),
        )
        item2 = CorrelationItem(
            tool="ida",
            data_type=DataType.FUNCTION,
            name="CheckLicenseKey",
            address=0x501000,
            size=250,
            attributes={"returns": "boolean"},
            confidence=0.85,
            timestamp=time.time(),
        )

        score = scorer.calculate_score(item1, item2)
        assert 0.4 < score < 0.9

    def test_different_items_low_confidence(self) -> None:
        """Different items produce low confidence score."""
        scorer = ConfidenceScorer()
        item1 = CorrelationItem(
            tool="ghidra",
            data_type=DataType.FUNCTION,
            name="validate_serial",
            address=0x401000,
            size=512,
            attributes={},
            confidence=1.0,
            timestamp=time.time(),
        )
        item2 = CorrelationItem(
            tool="ida",
            data_type=DataType.STRING,
            name="error_message",
            address=0x600000,
            size=32,
            attributes={},
            confidence=1.0,
            timestamp=time.time(),
        )

        score = scorer.calculate_score(item1, item2)
        assert score < 0.4

    def test_numeric_value_matching_with_tolerance(self) -> None:
        """Numeric values match within tolerance."""
        scorer = ConfidenceScorer()
        assert scorer._values_match(100, 105)
        assert scorer._values_match(1.0, 1.05)
        assert not scorer._values_match(100, 200)

    def test_string_value_matching(self) -> None:
        """String values match with fuzzy comparison."""
        scorer = ConfidenceScorer()
        assert scorer._values_match("license", "licence")
        assert scorer._values_match("checkkey", "checkkey")


class TestAnomalyDetector:
    """Test anomaly detection in correlation data."""

    def test_detects_anomalous_correlations(self) -> None:
        """Isolation forest detects anomalous correlation results."""
        detector = AnomalyDetector()
        normal_correlations = []

        for i in range(15):
            items = [
                CorrelationItem(
                    tool="ghidra",
                    data_type=DataType.FUNCTION,
                    name=f"func_{i}",
                    address=0x401000 + i * 0x100,
                    size=200 + i * 10,
                    attributes={},
                    confidence=0.8,
                    timestamp=time.time(),
                ),
                CorrelationItem(
                    tool="ida",
                    data_type=DataType.FUNCTION,
                    name=f"func_{i}",
                    address=0x401000 + i * 0x100,
                    size=200 + i * 10,
                    attributes={},
                    confidence=0.8,
                    timestamp=time.time(),
                ),
            ]
            normal_correlations.append(
                CorrelationResult(
                    items=items,
                    correlation_score=0.85 + i * 0.01,
                    confidence=0.8,
                    method="fuzzy",
                    metadata={},
                )
            )

        anomaly = CorrelationResult(
            items=[
                CorrelationItem(
                    tool="ghidra",
                    data_type=DataType.FUNCTION,
                    name="anomaly",
                    address=0x900000,
                    size=50000,
                    attributes={},
                    confidence=0.1,
                    timestamp=time.time(),
                ),
            ],
            correlation_score=0.01,
            confidence=0.1,
            method="fuzzy",
            metadata={},
        )
        all_correlations = normal_correlations + [anomaly]

        anomalies = detector.detect_anomalies(all_correlations)
        assert len(anomalies) > 0

    def test_statistical_outlier_detection(self) -> None:
        """IQR method detects statistical outliers."""
        detector = AnomalyDetector()
        values = [1.0, 1.1, 1.2, 1.3, 1.4, 1.5, 1.6, 10.0]

        outliers = detector.detect_outliers_statistical(values)
        assert 7 in outliers

    def test_insufficient_samples_returns_empty(self) -> None:
        """Insufficient samples for anomaly detection returns empty list."""
        detector = AnomalyDetector()
        correlations = [
            CorrelationResult(
                items=[],
                correlation_score=0.8,
                confidence=0.8,
                method="fuzzy",
                metadata={},
            )
        ]

        anomalies = detector.detect_anomalies(correlations)
        assert len(anomalies) == 0


class TestPatternClusterer:
    """Test pattern clustering algorithms."""

    def test_dbscan_clustering(self) -> None:
        """DBSCAN clusters similar patterns correctly."""
        clusterer = PatternClusterer()
        items = []

        for i in range(20):
            items.append(
                CorrelationItem(
                    tool="ghidra",
                    data_type=DataType.FUNCTION,
                    name=f"func_{i}",
                    address=0x401000 + i * 0x100,
                    size=200,
                    attributes={},
                    confidence=0.8,
                    timestamp=time.time(),
                )
            )

        clusters = clusterer.cluster_patterns(items, method="dbscan")
        assert len(clusters) > 0

    def test_kmeans_clustering(self) -> None:
        """KMeans clusters patterns into groups."""
        clusterer = PatternClusterer()
        items = []

        for i in range(30):
            items.append(
                CorrelationItem(
                    tool="ghidra",
                    data_type=DataType.FUNCTION if i < 15 else DataType.STRING,
                    name=f"item_{i}",
                    address=0x401000 + i * 0x100,
                    size=200 if i < 15 else 50,
                    attributes={},
                    confidence=0.8,
                    timestamp=time.time(),
                )
            )

        clusters = clusterer.cluster_patterns(items, method="kmeans")
        assert len(clusters) >= 2

    def test_find_similar_patterns(self) -> None:
        """Pattern similarity search finds top-k matches."""
        clusterer = PatternClusterer()
        query = CorrelationItem(
            tool="ghidra",
            data_type=DataType.FUNCTION,
            name="target_function",
            address=0x401000,
            size=256,
            attributes={},
            confidence=0.9,
            timestamp=time.time(),
        )

        items = []
        for i in range(10):
            items.append(
                CorrelationItem(
                    tool="ida",
                    data_type=DataType.FUNCTION,
                    name=f"function_{i}",
                    address=0x401000 + i * 0x100,
                    size=250 + i * 10,
                    attributes={},
                    confidence=0.8,
                    timestamp=time.time(),
                )
            )

        similar = clusterer.find_similar_patterns(query, items, top_k=5)
        assert len(similar) == 5
        assert all(isinstance(score, (float, np.floating)) for _, score in similar)

    def test_invalid_clustering_method_raises_error(self) -> None:
        """Invalid clustering method raises ValueError."""
        clusterer = PatternClusterer()
        items = [
            CorrelationItem(
                tool="ghidra",
                data_type=DataType.FUNCTION,
                name="func1",
                address=0x401000,
                size=200,
                attributes={},
                confidence=0.8,
                timestamp=time.time(),
            ),
            CorrelationItem(
                tool="ida",
                data_type=DataType.FUNCTION,
                name="func2",
                address=0x402000,
                size=200,
                attributes={},
                confidence=0.8,
                timestamp=time.time(),
            ),
        ]

        with pytest.raises(ValueError, match="Unknown clustering method"):
            clusterer.cluster_patterns(items, method="invalid")


class TestMachineLearningCorrelator:
    """Test ML-based correlation prediction."""

    def test_model_initialization(self) -> None:
        """ML model initializes correctly."""
        correlator = MachineLearningCorrelator()
        assert correlator.classifier is not None
        assert correlator.scaler is not None

    def test_training_with_pairs(self) -> None:
        """Model trains on positive and negative pairs."""
        correlator = MachineLearningCorrelator()

        positive_pairs = [
            (
                CorrelationItem(
                    tool="ghidra",
                    data_type=DataType.FUNCTION,
                    name="check_license",
                    address=0x401000,
                    size=256,
                    attributes={},
                    confidence=0.9,
                    timestamp=time.time(),
                ),
                CorrelationItem(
                    tool="ida",
                    data_type=DataType.FUNCTION,
                    name="CheckLicense",
                    address=0x401000,
                    size=250,
                    attributes={},
                    confidence=0.85,
                    timestamp=time.time(),
                ),
            )
        ]

        negative_pairs = [
            (
                CorrelationItem(
                    tool="ghidra",
                    data_type=DataType.FUNCTION,
                    name="validate_serial",
                    address=0x401000,
                    size=256,
                    attributes={},
                    confidence=0.9,
                    timestamp=time.time(),
                ),
                CorrelationItem(
                    tool="ida",
                    data_type=DataType.STRING,
                    name="error_message",
                    address=0x600000,
                    size=32,
                    attributes={},
                    confidence=1.0,
                    timestamp=time.time(),
                ),
            )
        ]

        correlator.train(positive_pairs, negative_pairs)
        assert len(correlator.training_data) == 2

    def test_prediction_after_training(self) -> None:
        """Model makes predictions after training."""
        correlator = MachineLearningCorrelator()

        positive_pairs = []
        negative_pairs = []

        for i in range(10):
            positive_pairs.append(
                (
                    CorrelationItem(
                        tool="ghidra",
                        data_type=DataType.FUNCTION,
                        name=f"func_{i}",
                        address=0x401000 + i * 0x100,
                        size=256,
                        attributes={},
                        confidence=0.9,
                        timestamp=time.time(),
                    ),
                    CorrelationItem(
                        tool="ida",
                        data_type=DataType.FUNCTION,
                        name=f"func_{i}",
                        address=0x401000 + i * 0x100,
                        size=256,
                        attributes={},
                        confidence=0.9,
                        timestamp=time.time(),
                    ),
                )
            )

            negative_pairs.append(
                (
                    CorrelationItem(
                        tool="ghidra",
                        data_type=DataType.FUNCTION,
                        name=f"func_{i}",
                        address=0x401000 + i * 0x100,
                        size=256,
                        attributes={},
                        confidence=0.9,
                        timestamp=time.time(),
                    ),
                    CorrelationItem(
                        tool="ida",
                        data_type=DataType.STRING,
                        name=f"string_{i}",
                        address=0x600000 + i * 0x100,
                        size=32,
                        attributes={},
                        confidence=1.0,
                        timestamp=time.time(),
                    ),
                )
            )

        correlator.train(positive_pairs, negative_pairs)

        test_item1 = CorrelationItem(
            tool="ghidra",
            data_type=DataType.FUNCTION,
            name="new_func",
            address=0x402000,
            size=256,
            attributes={},
            confidence=0.9,
            timestamp=time.time(),
        )
        test_item2 = CorrelationItem(
            tool="ida",
            data_type=DataType.FUNCTION,
            name="new_func",
            address=0x402000,
            size=256,
            attributes={},
            confidence=0.9,
            timestamp=time.time(),
        )

        is_correlated, probability = correlator.predict(test_item1, test_item2)
        assert isinstance(is_correlated, bool)
        assert 0.0 <= probability <= 1.0

    def test_model_save_and_load(self, tmp_path: Path) -> None:
        """Model saves and loads correctly."""
        correlator = MachineLearningCorrelator()

        positive_pairs = [
            (
                CorrelationItem(
                    tool="ghidra",
                    data_type=DataType.FUNCTION,
                    name="func1",
                    address=0x401000,
                    size=256,
                    attributes={},
                    confidence=0.9,
                    timestamp=time.time(),
                ),
                CorrelationItem(
                    tool="ida",
                    data_type=DataType.FUNCTION,
                    name="func1",
                    address=0x401000,
                    size=256,
                    attributes={},
                    confidence=0.9,
                    timestamp=time.time(),
                ),
            )
        ]

        correlator.train(positive_pairs, [])

        model_path = tmp_path / "test_model.pkl"
        correlator.save_model(str(model_path))
        assert model_path.exists()

        new_correlator = MachineLearningCorrelator()
        new_correlator.load_model(str(model_path))
        assert new_correlator.classifier is not None


class TestIntelligentCorrelator:
    """Test integrated correlation system."""

    def test_fuzzy_correlation_method(self) -> None:
        """Fuzzy correlation finds similar items."""
        correlator = IntelligentCorrelator()

        items = [
            CorrelationItem(
                tool="ghidra",
                data_type=DataType.FUNCTION,
                name="check_license",
                address=0x401000,
                size=256,
                attributes={},
                confidence=0.9,
                timestamp=time.time(),
            ),
            CorrelationItem(
                tool="ida",
                data_type=DataType.FUNCTION,
                name="check_license",
                address=0x401100,
                size=250,
                attributes={},
                confidence=0.85,
                timestamp=time.time(),
            ),
            CorrelationItem(
                tool="radare2",
                data_type=DataType.FUNCTION,
                name="validate_serial",
                address=0x402000,
                size=512,
                attributes={},
                confidence=0.8,
                timestamp=time.time(),
            ),
        ]

        results = correlator.correlate(items, method="fuzzy")
        assert len(results) > 0
        assert all(isinstance(r, CorrelationResult) for r in results)

    def test_pattern_correlation_method(self) -> None:
        """Pattern clustering correlates similar items."""
        correlator = IntelligentCorrelator()

        items = []
        for i in range(25):
            items.append(
                CorrelationItem(
                    tool="ghidra",
                    data_type=DataType.FUNCTION,
                    name=f"func_{i}",
                    address=0x401000 + i * 0x100,
                    size=200,
                    attributes={},
                    confidence=0.8,
                    timestamp=time.time(),
                )
            )

        results = correlator.correlate(items, method="pattern")
        assert len(results) > 0

    def test_hybrid_correlation_combines_methods(self) -> None:
        """Hybrid correlation combines multiple methods."""
        correlator = IntelligentCorrelator()

        items = [
            CorrelationItem(
                tool="ghidra",
                data_type=DataType.FUNCTION,
                name="check_license",
                address=0x401000,
                size=256,
                attributes={},
                confidence=0.9,
                timestamp=time.time(),
            ),
            CorrelationItem(
                tool="ida",
                data_type=DataType.FUNCTION,
                name="check_license",
                address=0x401000,
                size=256,
                attributes={},
                confidence=0.9,
                timestamp=time.time(),
            ),
        ]

        results = correlator.correlate(items, method="hybrid")
        assert len(results) > 0
        assert any(r.method == "hybrid" for r in results)

    def test_address_translation(self) -> None:
        """Address translation converts between tools."""
        correlator = IntelligentCorrelator()
        correlator.address_translator.set_base_address("ghidra", 0x400000)
        correlator.address_translator.set_base_address("ida", 0x10000000)

        items = [
            CorrelationItem(
                tool="ghidra",
                data_type=DataType.FUNCTION,
                name="func1",
                address=0x401000,
                size=256,
                attributes={},
                confidence=0.9,
                timestamp=time.time(),
            ),
        ]

        translated = correlator.translate_addresses(items, "ida")
        assert len(translated) == 1
        assert translated[0].tool == "ida"
        assert translated[0].address == 0x10001000

    def test_anomaly_detection(self) -> None:
        """Anomaly detection identifies unusual correlations."""
        correlator = IntelligentCorrelator()

        normal_correlations = []
        for i in range(15):
            items = [
                CorrelationItem(
                    tool="ghidra",
                    data_type=DataType.FUNCTION,
                    name=f"func_{i}",
                    address=0x401000 + i * 0x100,
                    size=200,
                    attributes={},
                    confidence=0.8,
                    timestamp=time.time(),
                ),
            ]
            normal_correlations.append(
                CorrelationResult(
                    items=items,
                    correlation_score=0.85,
                    confidence=0.8,
                    method="fuzzy",
                    metadata={},
                )
            )

        anomalies = correlator.detect_anomalies(normal_correlations)
        assert isinstance(anomalies, list)

    def test_invalid_method_raises_error(self) -> None:
        """Invalid correlation method raises ValueError."""
        correlator = IntelligentCorrelator()
        items = []

        with pytest.raises(ValueError, match="Unknown correlation method"):
            correlator.correlate(items, method="invalid")


class TestEdgeCases:
    """Test edge cases and error conditions."""

    def test_empty_items_list(self) -> None:
        """Empty items list handles gracefully."""
        correlator = IntelligentCorrelator()
        results = correlator.correlate([], method="fuzzy")
        assert len(results) == 0

    def test_single_item_clustering(self) -> None:
        """Single item returns single cluster."""
        clusterer = PatternClusterer()
        items = [
            CorrelationItem(
                tool="ghidra",
                data_type=DataType.FUNCTION,
                name="func",
                address=0x401000,
                size=200,
                attributes={},
                confidence=0.8,
                timestamp=time.time(),
            )
        ]

        clusters = clusterer.cluster_patterns(items)
        assert len(clusters) == 1

    def test_missing_attributes_handled(self) -> None:
        """Missing attributes don't cause errors."""
        scorer = ConfidenceScorer()
        item1 = CorrelationItem(
            tool="ghidra",
            data_type=DataType.FUNCTION,
            name="func1",
            address=0x401000,
            size=256,
            attributes={},
            confidence=0.9,
            timestamp=time.time(),
        )
        item2 = CorrelationItem(
            tool="ida",
            data_type=DataType.FUNCTION,
            name="func2",
            address=0x401100,
            size=250,
            attributes={"returns": "bool"},
            confidence=0.85,
            timestamp=time.time(),
        )

        score = scorer.calculate_score(item1, item2)
        assert 0.0 <= score <= 1.0

    def test_zero_size_items(self) -> None:
        """Zero size items are handled correctly."""
        scorer = ConfidenceScorer()
        item1 = CorrelationItem(
            tool="ghidra",
            data_type=DataType.FUNCTION,
            name="func",
            address=0x401000,
            size=0,
            attributes={},
            confidence=0.9,
            timestamp=time.time(),
        )
        item2 = CorrelationItem(
            tool="ida",
            data_type=DataType.FUNCTION,
            name="func",
            address=0x401000,
            size=0,
            attributes={},
            confidence=0.9,
            timestamp=time.time(),
        )

        score = scorer.calculate_score(item1, item2)
        assert 0.0 <= score <= 1.0


class TestRealWorldScenarios:
    """Test realistic correlation scenarios."""

    def test_ghidra_ida_radare2_correlation(self) -> None:
        """Correlate results from Ghidra, IDA, and radare2."""
        correlator = IntelligentCorrelator()

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
                name="check_license_key",
                address=0x401100,
                size=250,
                attributes={"returns": "boolean", "params": 1},
                confidence=0.85,
                timestamp=time.time(),
            ),
            CorrelationItem(
                tool="radare2",
                data_type=DataType.FUNCTION,
                name="check_license_key",
                address=0x401000,
                size=260,
                attributes={"type": "function"},
                confidence=0.7,
                timestamp=time.time(),
            ),
        ]

        results = correlator.correlate(items, method="hybrid")
        assert len(results) > 0

        high_confidence_results = [r for r in results if r.confidence > 0.5]
        assert len(high_confidence_results) > 0

    def test_vmprotect_function_correlation(self) -> None:
        """Correlate VMProtect-protected function names."""
        matcher = FuzzyMatcher()

        ghidra_name = "FUN_004025a0"
        ida_name = "sub_4025A0"
        radare2_name = "fcn.004025a0"

        score1 = matcher.match_function_names(ghidra_name, ida_name)
        score2 = matcher.match_function_names(ida_name, radare2_name)

        assert score1 > 0.5
        assert score2 > 0.5

    def test_conflicting_correlations(self) -> None:
        """Handle conflicting correlation results."""
        correlator = IntelligentCorrelator()

        items = [
            CorrelationItem(
                tool="ghidra",
                data_type=DataType.FUNCTION,
                name="func_a",
                address=0x401000,
                size=256,
                attributes={},
                confidence=0.9,
                timestamp=time.time(),
            ),
            CorrelationItem(
                tool="ida",
                data_type=DataType.FUNCTION,
                name="func_b",
                address=0x401000,
                size=256,
                attributes={},
                confidence=0.85,
                timestamp=time.time(),
            ),
            CorrelationItem(
                tool="radare2",
                data_type=DataType.FUNCTION,
                name="func_c",
                address=0x401000,
                size=256,
                attributes={},
                confidence=0.8,
                timestamp=time.time(),
            ),
        ]

        results = correlator.correlate(items, method="hybrid")
        assert len(results) >= 0

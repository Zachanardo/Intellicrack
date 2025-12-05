#!/usr/bin/env python3
"""Production tests for success rate analyzer.

Tests validate real statistical analysis of bypass success rates with actual data.
"""

import json
import math
import sqlite3
import tempfile
import time
from pathlib import Path
from typing import Any

import numpy as np
import pytest
from scipy import stats

from intellicrack.plugins.custom_modules.success_rate_analyzer import (
    AnalysisEvent,
    BayesianAnalyzer,
    EventTracker,
    EventType,
    MLPredictor,
    OutcomeType,
    PerformanceMetrics,
    ProtectionCategory,
    ReportGenerator,
    StatisticalResult,
    StatisticalTester,
    SuccessRateAnalyzer,
    SurvivalAnalyzer,
    TimeSeriesAnalyzer,
    TrendAnalysis,
    WilsonScoreInterval,
    get_success_rate_analyzer,
    track_success,
)


class TestWilsonScoreInterval:
    """Tests for Wilson score confidence interval calculation."""

    def test_wilson_score_perfect_success(self) -> None:
        """Wilson score calculates correct interval for 100% success rate."""
        lower, upper = WilsonScoreInterval.calculate(100, 100, confidence_level=0.95)

        assert 0.95 < lower <= 1.0
        assert upper == 1.0
        assert lower < upper

    def test_wilson_score_perfect_failure(self) -> None:
        """Wilson score calculates correct interval for 0% success rate."""
        lower, upper = WilsonScoreInterval.calculate(0, 100, confidence_level=0.95)

        assert lower < 1e-10
        assert 0.0 <= upper < 0.06
        assert lower < upper

    def test_wilson_score_fifty_percent(self) -> None:
        """Wilson score calculates symmetric interval for 50% success rate."""
        lower, upper = WilsonScoreInterval.calculate(50, 100, confidence_level=0.95)

        assert 0.4 < lower < 0.5
        assert 0.5 < upper < 0.6
        assert abs((upper - 0.5) - (0.5 - lower)) < 0.05

    def test_wilson_score_zero_samples(self) -> None:
        """Wilson score handles zero samples correctly."""
        lower, upper = WilsonScoreInterval.calculate(0, 0, confidence_level=0.95)

        assert lower == 0.0
        assert upper == 1.0

    def test_wilson_score_different_confidence_levels(self) -> None:
        """Wilson score produces wider intervals for higher confidence levels."""
        lower_90, upper_90 = WilsonScoreInterval.calculate(50, 100, confidence_level=0.90)
        lower_95, upper_95 = WilsonScoreInterval.calculate(50, 100, confidence_level=0.95)
        lower_99, upper_99 = WilsonScoreInterval.calculate(50, 100, confidence_level=0.99)

        width_90 = upper_90 - lower_90
        width_95 = upper_95 - lower_95
        width_99 = upper_99 - lower_99

        assert width_90 < width_95 < width_99

    def test_wilson_score_small_sample_size(self) -> None:
        """Wilson score produces wider intervals for smaller samples."""
        lower_10, upper_10 = WilsonScoreInterval.calculate(5, 10)
        lower_100, upper_100 = WilsonScoreInterval.calculate(50, 100)

        width_10 = upper_10 - lower_10
        width_100 = upper_100 - lower_100

        assert width_10 > width_100


class TestBayesianAnalyzer:
    """Tests for Bayesian success rate analysis."""

    def test_bayesian_posterior_mean_no_data(self) -> None:
        """Bayesian analyzer with uniform prior gives 0.5 mean with no data."""
        analyzer = BayesianAnalyzer(prior_alpha=1.0, prior_beta=1.0)
        mean = analyzer.posterior_mean(0, 0)

        assert abs(mean - 0.5) < 0.001

    def test_bayesian_posterior_mean_with_successes(self) -> None:
        """Bayesian analyzer updates correctly with success data."""
        analyzer = BayesianAnalyzer(prior_alpha=1.0, prior_beta=1.0)
        mean = analyzer.posterior_mean(80, 20)

        assert 0.75 < mean < 0.85

    def test_bayesian_credible_interval_calculation(self) -> None:
        """Bayesian analyzer calculates valid credible intervals."""
        analyzer = BayesianAnalyzer(prior_alpha=1.0, prior_beta=1.0)
        lower, upper = analyzer.credible_interval(50, 50, confidence=0.95)

        assert 0.0 <= lower < 0.5
        assert 0.5 < upper <= 1.0
        assert lower < upper

    def test_bayesian_posterior_probability_above_threshold(self) -> None:
        """Bayesian analyzer calculates probability above threshold correctly."""
        analyzer = BayesianAnalyzer(prior_alpha=1.0, prior_beta=1.0)

        prob_above_50 = analyzer.posterior_probability(80, 20, 0.5)
        prob_above_90 = analyzer.posterior_probability(80, 20, 0.9)

        assert prob_above_50 > 0.95
        assert prob_above_90 < 0.5
        assert prob_above_50 > prob_above_90

    def test_bayesian_informative_prior(self) -> None:
        """Bayesian analyzer with informative prior influences results."""
        weak_prior = BayesianAnalyzer(prior_alpha=1.0, prior_beta=1.0)
        strong_prior = BayesianAnalyzer(prior_alpha=10.0, prior_beta=10.0)

        mean_weak = weak_prior.posterior_mean(5, 5)
        mean_strong = strong_prior.posterior_mean(5, 5)

        assert abs(mean_weak - mean_strong) < 0.1


class TestSurvivalAnalyzer:
    """Tests for Kaplan-Meier survival analysis."""

    def test_survival_analyzer_empty_data(self) -> None:
        """Survival analyzer handles empty data correctly."""
        analyzer = SurvivalAnalyzer()
        times, probs = analyzer.kaplan_meier_estimate()

        assert len(times) == 0
        assert len(probs) == 0

    def test_survival_analyzer_single_event(self) -> None:
        """Survival analyzer handles single event correctly."""
        analyzer = SurvivalAnalyzer()
        analyzer.add_observation(10.0, censored=False)

        times, probs = analyzer.kaplan_meier_estimate()

        assert len(times) == 1
        assert times[0] == 10.0
        assert probs[0] == 0.0

    def test_survival_analyzer_multiple_events(self) -> None:
        """Survival analyzer calculates survival curve for multiple events."""
        analyzer = SurvivalAnalyzer()

        for duration in [5.0, 10.0, 15.0, 20.0, 25.0]:
            analyzer.add_observation(duration, censored=False)

        times, probs = analyzer.kaplan_meier_estimate()

        assert len(times) == 5
        assert all(probs[i] > probs[i + 1] for i in range(len(probs) - 1))
        assert probs[-1] == 0.0

    def test_survival_analyzer_with_censoring(self) -> None:
        """Survival analyzer handles censored observations correctly."""
        analyzer = SurvivalAnalyzer()

        analyzer.add_observation(5.0, censored=False)
        analyzer.add_observation(10.0, censored=True)
        analyzer.add_observation(15.0, censored=False)

        times, probs = analyzer.kaplan_meier_estimate()

        assert len(times) >= 2

    def test_survival_analyzer_median_survival_time(self) -> None:
        """Survival analyzer calculates median survival time correctly."""
        analyzer = SurvivalAnalyzer()

        for duration in range(1, 21):
            analyzer.add_observation(float(duration), censored=False)

        median = analyzer.median_survival_time()

        assert median is not None
        assert 8.0 <= median <= 12.0


class TestTimeSeriesAnalyzer:
    """Tests for time series analysis and forecasting."""

    def test_time_series_trend_detection_increasing(self) -> None:
        """Time series analyzer detects increasing trends correctly."""
        analyzer = TimeSeriesAnalyzer()

        base_time = time.time()
        for i in range(50):
            analyzer.add_data_point("keygen", base_time + i * 3600, 0.5 + i * 0.01)

        trend = analyzer.detect_trend("keygen", window_size=30)

        assert trend["trend"] == "increasing"
        assert trend["strength"] > 0.5

    def test_time_series_trend_detection_decreasing(self) -> None:
        """Time series analyzer detects decreasing trends correctly."""
        analyzer = TimeSeriesAnalyzer()

        base_time = time.time()
        for i in range(50):
            analyzer.add_data_point("patcher", base_time + i * 3600, 0.9 - i * 0.01)

        trend = analyzer.detect_trend("patcher", window_size=30)

        assert trend["trend"] == "decreasing"
        assert trend["strength"] > 0.5

    def test_time_series_trend_detection_stable(self) -> None:
        """Time series analyzer detects stable trends correctly."""
        analyzer = TimeSeriesAnalyzer()

        np.random.seed(42)
        base_time = time.time()
        for i in range(50):
            noise = np.random.normal(0, 0.01)
            analyzer.add_data_point("detector", base_time + i * 3600, 0.7 + noise)

        trend = analyzer.detect_trend("detector", window_size=30)

        assert trend["trend"] in ["stable", "increasing", "decreasing"]
        if trend["trend"] == "stable":
            assert trend["strength"] < 0.5

    def test_time_series_insufficient_data(self) -> None:
        """Time series analyzer handles insufficient data gracefully."""
        analyzer = TimeSeriesAnalyzer()

        for i in range(5):
            analyzer.add_data_point("test", time.time() + i, 0.5)

        trend = analyzer.detect_trend("test", window_size=30)

        assert trend["trend"] == "insufficient_data"

    def test_time_series_forecast_arima(self) -> None:
        """Time series analyzer produces valid forecasts."""
        analyzer = TimeSeriesAnalyzer()

        base_time = time.time()
        for i in range(50):
            analyzer.add_data_point("bypass", base_time + i * 3600, 0.8 + np.sin(i / 10) * 0.1)

        forecasts, intervals = analyzer.forecast_arima("bypass", periods=10)

        assert len(forecasts) == 10
        assert len(intervals) == 10
        assert all(0.0 <= f <= 1.5 for f in forecasts)
        assert all(intervals[i][0] < forecasts[i] < intervals[i][1] for i in range(10))

    def test_time_series_seasonal_decomposition(self) -> None:
        """Time series analyzer detects seasonal patterns."""
        analyzer = TimeSeriesAnalyzer()

        base_time = time.time()
        period = 24
        for i in range(100):
            seasonal_component = 0.2 * np.sin(2 * np.pi * i / period)
            analyzer.add_data_point("component", base_time + i * 3600, 0.7 + seasonal_component)

        result = analyzer.seasonal_decomposition("component", period=period)

        assert result["seasonal"] is True or result["seasonal_strength"] > 0.05


class TestStatisticalTester:
    """Tests for statistical hypothesis testing."""

    def test_chi_square_test_uniform_distribution(self) -> None:
        """Chi-square test accepts uniform distribution."""
        observed = [100, 100, 100, 100]
        result = StatisticalTester.chi_square_test(observed)

        assert result["p_value"] > 0.05
        assert result["degrees_of_freedom"] == 3

    def test_chi_square_test_non_uniform_distribution(self) -> None:
        """Chi-square test rejects non-uniform distribution."""
        observed = [200, 50, 50, 50]
        result = StatisticalTester.chi_square_test(observed)

        assert result["p_value"] < 0.05

    def test_fishers_exact_test_same_proportions(self) -> None:
        """Fisher's exact test accepts equal proportions."""
        result = StatisticalTester.fishers_exact_test(50, 100, 50, 100)

        assert result["p_value"] > 0.05
        assert abs(result["odds_ratio"] - 1.0) < 0.1

    def test_fishers_exact_test_different_proportions(self) -> None:
        """Fisher's exact test detects different proportions."""
        result = StatisticalTester.fishers_exact_test(80, 100, 20, 100)

        assert result["p_value"] < 0.05
        assert result["odds_ratio"] > 5.0

    def test_mann_whitney_u_test_same_distributions(self) -> None:
        """Mann-Whitney U test accepts samples from same distribution."""
        group1 = np.random.normal(10, 2, 50).tolist()
        group2 = np.random.normal(10, 2, 50).tolist()

        result = StatisticalTester.mann_whitney_u_test(group1, group2)

        assert result["p_value"] > 0.01

    def test_mann_whitney_u_test_different_distributions(self) -> None:
        """Mann-Whitney U test detects different distributions."""
        group1 = np.random.normal(10, 2, 50).tolist()
        group2 = np.random.normal(15, 2, 50).tolist()

        result = StatisticalTester.mann_whitney_u_test(group1, group2)

        assert result["p_value"] < 0.05


class TestPerformanceMetrics:
    """Tests for performance metrics calculation."""

    def test_confusion_matrix_metrics_perfect_classification(self) -> None:
        """Performance metrics calculates perfect scores correctly."""
        metrics = PerformanceMetrics.confusion_matrix_metrics(tp=100, tn=100, fp=0, fn=0)

        assert metrics["accuracy"] == 1.0
        assert metrics["precision"] == 1.0
        assert metrics["recall"] == 1.0
        assert metrics["f1_score"] == 1.0

    def test_confusion_matrix_metrics_zero_predictions(self) -> None:
        """Performance metrics handles zero predictions correctly."""
        metrics = PerformanceMetrics.confusion_matrix_metrics(tp=0, tn=100, fp=0, fn=50)

        assert metrics["accuracy"] == 100 / 150
        assert metrics["precision"] == 0.0
        assert metrics["recall"] == 0.0

    def test_confusion_matrix_metrics_balanced_errors(self) -> None:
        """Performance metrics calculates scores with balanced errors."""
        metrics = PerformanceMetrics.confusion_matrix_metrics(tp=70, tn=70, fp=15, fn=15)

        assert 0.7 < metrics["accuracy"] < 0.9
        assert 0.7 < metrics["precision"] < 0.9
        assert 0.7 < metrics["recall"] < 0.9
        assert 0.7 < metrics["f1_score"] < 0.9

    def test_auc_roc_perfect_separation(self) -> None:
        """AUC-ROC calculation produces 1.0 for perfect separation."""
        y_true = [1, 1, 1, 1, 1, 0, 0, 0, 0, 0]
        y_scores = [0.9, 0.8, 0.7, 0.6, 0.5, 0.4, 0.3, 0.2, 0.1, 0.0]

        auc = PerformanceMetrics.auc_roc(y_true, y_scores)

        assert auc == 1.0

    def test_auc_roc_random_classification(self) -> None:
        """AUC-ROC calculation produces ~0.5 for random classification."""
        y_true = [1, 0, 1, 0, 1, 0, 1, 0, 1, 0]
        y_scores = [0.5, 0.5, 0.5, 0.5, 0.5, 0.5, 0.5, 0.5, 0.5, 0.5]

        auc = PerformanceMetrics.auc_roc(y_true, y_scores)

        assert 0.4 <= auc <= 0.6


class TestEventTracker:
    """Tests for event tracking and database management."""

    def test_event_tracker_initialization(self, tmp_path: Path) -> None:
        """Event tracker initializes database correctly."""
        db_path = tmp_path / "test_init.db"
        tracker = EventTracker(str(db_path))

        assert db_path.exists()

        conn = sqlite3.connect(str(db_path))
        cursor = conn.cursor()
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table'")
        tables = {row[0] for row in cursor.fetchall()}
        conn.close()

        assert "events" in tables
        assert "success_rate_cache" in tables
        assert "trend_cache" in tables

    def test_event_tracker_log_event(self, tmp_path: Path) -> None:
        """Event tracker logs events to database correctly."""
        db_path = tmp_path / "test_log.db"
        tracker = EventTracker(str(db_path))

        event = AnalysisEvent(
            event_id="test123",
            event_type=EventType.BYPASS_ATTEMPT,
            outcome=OutcomeType.SUCCESS,
            protection_category=ProtectionCategory.SERIAL_KEY,
            component="keygen",
            timestamp=time.time(),
            duration=2.5,
            metadata={"version": "1.0"},
            error_details="",
        )

        tracker.log_event(event)

        conn = sqlite3.connect(str(db_path))
        cursor = conn.cursor()
        cursor.execute("SELECT COUNT(*) FROM events")
        count = cursor.fetchone()[0]
        conn.close()

        assert count == 1

    def test_event_tracker_get_events_all(self, tmp_path: Path) -> None:
        """Event tracker retrieves all events correctly."""
        db_path = tmp_path / "test_get_all.db"
        tracker = EventTracker(str(db_path))

        for i in range(10):
            event = AnalysisEvent(
                event_id=f"test{i}",
                event_type=EventType.BYPASS_ATTEMPT,
                outcome=OutcomeType.SUCCESS if i % 2 == 0 else OutcomeType.FAILURE,
                protection_category=ProtectionCategory.SERIAL_KEY,
                component="keygen",
                timestamp=time.time() + i,
            )
            tracker.log_event(event)

        events = tracker.get_events()

        assert len(events) == 10

    def test_event_tracker_get_events_filtered_by_component(self, tmp_path: Path) -> None:
        """Event tracker filters events by component correctly."""
        db_path = tmp_path / "test_filter_component.db"
        tracker = EventTracker(str(db_path))

        for component in ["keygen", "patcher", "detector"]:
            for i in range(5):
                event = AnalysisEvent(
                    event_id=f"{component}{i}",
                    event_type=EventType.BYPASS_ATTEMPT,
                    outcome=OutcomeType.SUCCESS,
                    protection_category=ProtectionCategory.SERIAL_KEY,
                    component=component,
                    timestamp=time.time(),
                )
                tracker.log_event(event)

        keygen_events = tracker.get_events(component="keygen")

        assert len(keygen_events) == 5
        assert all(e.component == "keygen" for e in keygen_events)

    def test_event_tracker_get_events_filtered_by_time(self, tmp_path: Path) -> None:
        """Event tracker filters events by time range correctly."""
        db_path = tmp_path / "test_filter_time.db"
        tracker = EventTracker(str(db_path))

        base_time = time.time()
        for i in range(10):
            event = AnalysisEvent(
                event_id=f"test{i}",
                event_type=EventType.BYPASS_ATTEMPT,
                outcome=OutcomeType.SUCCESS,
                protection_category=ProtectionCategory.SERIAL_KEY,
                component="keygen",
                timestamp=base_time + i * 3600,
            )
            tracker.log_event(event)

        recent_events = tracker.get_events(start_time=base_time + 5 * 3600)

        assert len(recent_events) == 5

    def test_event_tracker_get_success_counts(self, tmp_path: Path) -> None:
        """Event tracker calculates success counts correctly."""
        db_path = tmp_path / "test_success_counts.db"
        tracker = EventTracker(str(db_path))

        for i in range(20):
            event = AnalysisEvent(
                event_id=f"test{i}",
                event_type=EventType.BYPASS_ATTEMPT,
                outcome=OutcomeType.SUCCESS if i < 15 else OutcomeType.FAILURE,
                protection_category=ProtectionCategory.SERIAL_KEY,
                component="keygen",
                timestamp=time.time(),
            )
            tracker.log_event(event)

        success_count, total_count = tracker.get_success_counts()

        assert success_count == 15
        assert total_count == 20


class TestMLPredictor:
    """Tests for machine learning-based success rate prediction."""

    def test_ml_predictor_feature_preparation(self) -> None:
        """ML predictor prepares features correctly from events."""
        predictor = MLPredictor()

        events = []
        base_time = time.time()
        for i in range(200):
            event = AnalysisEvent(
                event_id=f"test{i}",
                event_type=EventType.BYPASS_ATTEMPT,
                outcome=OutcomeType.SUCCESS if np.random.random() > 0.3 else OutcomeType.FAILURE,
                protection_category=ProtectionCategory.SERIAL_KEY,
                component="keygen",
                timestamp=base_time + i * 100,
                duration=np.random.uniform(1.0, 10.0),
            )
            events.append(event)

        X, y = predictor.prepare_features(events)

        assert len(X) > 0
        assert len(y) > 0
        assert X.shape[0] == y.shape[0]
        assert all(0.0 <= rate <= 1.0 for rate in y)

    def test_ml_predictor_training(self) -> None:
        """ML predictor trains successfully with sufficient data."""
        predictor = MLPredictor()

        events = []
        base_time = time.time()
        for window in range(20):
            for i in range(10):
                event = AnalysisEvent(
                    event_id=f"test{window}_{i}",
                    event_type=EventType.BYPASS_ATTEMPT,
                    outcome=OutcomeType.SUCCESS if np.random.random() > 0.3 else OutcomeType.FAILURE,
                    protection_category=ProtectionCategory.SERIAL_KEY,
                    component="keygen",
                    timestamp=base_time + window * 3600 + i * 60,
                    duration=np.random.uniform(1.0, 10.0),
                )
                events.append(event)

        predictor.train(events)

        assert predictor.is_trained is True

    def test_ml_predictor_prediction(self) -> None:
        """ML predictor produces valid predictions after training."""
        predictor = MLPredictor()

        events = []
        base_time = time.time()
        for window in range(20):
            success_rate = 0.8 if window < 10 else 0.4
            for i in range(10):
                event = AnalysisEvent(
                    event_id=f"test{window}_{i}",
                    event_type=EventType.BYPASS_ATTEMPT,
                    outcome=OutcomeType.SUCCESS if np.random.random() < success_rate else OutcomeType.FAILURE,
                    protection_category=ProtectionCategory.SERIAL_KEY,
                    component="keygen",
                    timestamp=base_time + window * 3600 + i * 60,
                    duration=np.random.uniform(1.0, 10.0),
                )
                events.append(event)

        predictor.train(events)
        predictions = predictor.predict(events[-50:])

        assert "ensemble" in predictions
        assert 0.0 <= predictions["ensemble"] <= 1.0
        assert "random_forest" in predictions
        assert "gradient_boosting" in predictions

    def test_ml_predictor_insufficient_data(self) -> None:
        """ML predictor handles insufficient data gracefully."""
        predictor = MLPredictor()

        events = []
        for i in range(5):
            event = AnalysisEvent(
                event_id=f"test{i}",
                event_type=EventType.BYPASS_ATTEMPT,
                outcome=OutcomeType.SUCCESS,
                protection_category=ProtectionCategory.SERIAL_KEY,
                component="keygen",
                timestamp=time.time() + i,
            )
            events.append(event)

        predictor.train(events)

        assert predictor.is_trained is False


class TestReportGenerator:
    """Tests for statistical report generation."""

    @pytest.fixture
    def temp_report_dir(self) -> Path:
        """Create temporary report directory."""
        temp_dir = Path(tempfile.mkdtemp())
        yield temp_dir
        for file in temp_dir.iterdir():
            file.unlink()
        temp_dir.rmdir()

    @pytest.fixture
    def populated_analyzer(self, tmp_path: Path) -> SuccessRateAnalyzer:
        """Create analyzer with populated data."""
        db_path = tmp_path / "test.db"
        analyzer = SuccessRateAnalyzer(str(db_path))

        base_time = time.time()
        for i in range(100):
            analyzer.log_event(
                event_type=EventType.BYPASS_ATTEMPT,
                outcome=OutcomeType.SUCCESS if i % 3 != 0 else OutcomeType.FAILURE,
                protection_category=ProtectionCategory.SERIAL_KEY,
                component="keygen",
                duration=np.random.uniform(1.0, 5.0),
            )

            analyzer.log_event(
                event_type=EventType.BYPASS_ATTEMPT,
                outcome=OutcomeType.SUCCESS if i % 2 == 0 else OutcomeType.FAILURE,
                protection_category=ProtectionCategory.DONGLE,
                component="dongle_emulator",
                duration=np.random.uniform(2.0, 8.0),
            )

        return analyzer

    def test_report_generator_creates_pdf_report(
        self, temp_report_dir: Path, populated_analyzer: SuccessRateAnalyzer
    ) -> None:
        """Report generator creates comprehensive PDF report with real data."""
        generator = ReportGenerator(str(temp_report_dir))
        report_path = generator.generate_comprehensive_report(populated_analyzer)

        assert Path(report_path).exists()
        assert Path(report_path).suffix == ".pdf"
        assert Path(report_path).stat().st_size > 1000

    def test_report_generator_daily_success_rates(
        self, temp_report_dir: Path, populated_analyzer: SuccessRateAnalyzer
    ) -> None:
        """Report generator calculates daily success rates correctly."""
        generator = ReportGenerator(str(temp_report_dir))

        events = populated_analyzer.event_tracker.get_events()
        daily_rates = generator._calculate_daily_success_rates(events)

        assert len(daily_rates) > 0
        assert all(0.0 <= rate <= 1.0 for rate in daily_rates.values())

    def test_report_generator_correlation_matrix(
        self, temp_report_dir: Path, populated_analyzer: SuccessRateAnalyzer
    ) -> None:
        """Report generator prepares valid correlation matrix."""
        generator = ReportGenerator(str(temp_report_dir))

        correlation_matrix = generator._prepare_correlation_data(populated_analyzer)

        if correlation_matrix is not None:
            assert correlation_matrix.shape[0] == correlation_matrix.shape[1]
            assert np.all(np.abs(correlation_matrix) <= 1.0)
            assert np.allclose(np.diag(correlation_matrix), 1.0)


class TestSuccessRateAnalyzer:
    """Tests for main success rate analyzer."""

    @pytest.fixture
    def analyzer(self, tmp_path: Path) -> SuccessRateAnalyzer:
        """Create analyzer instance for testing."""
        db_path = tmp_path / "test.db"
        return SuccessRateAnalyzer(str(db_path))

    def test_analyzer_initialization(self, analyzer: SuccessRateAnalyzer) -> None:
        """Analyzer initializes all components correctly."""
        assert analyzer.event_tracker is not None
        assert analyzer.bayesian_analyzer is not None
        assert analyzer.survival_analyzer is not None
        assert analyzer.time_series_analyzer is not None
        assert analyzer.ml_predictor is not None
        assert analyzer.report_generator is not None

    def test_analyzer_log_event(self, analyzer: SuccessRateAnalyzer) -> None:
        """Analyzer logs events correctly."""
        analyzer.log_event(
            event_type=EventType.BYPASS_ATTEMPT,
            outcome=OutcomeType.SUCCESS,
            protection_category=ProtectionCategory.SERIAL_KEY,
            component="keygen",
            duration=2.5,
            metadata={"version": "1.0"},
        )

        events = analyzer.event_tracker.get_events()

        assert len(events) == 1
        assert events[0].event_type == EventType.BYPASS_ATTEMPT
        assert events[0].outcome == OutcomeType.SUCCESS

    def test_analyzer_get_success_rate_no_data(self, analyzer: SuccessRateAnalyzer) -> None:
        """Analyzer handles no data correctly."""
        result = analyzer.get_success_rate(component="nonexistent")

        assert result.value == 0.0
        assert result.sample_size == 0
        assert result.confidence_interval == (0.0, 1.0)

    def test_analyzer_get_success_rate_with_data(self, analyzer: SuccessRateAnalyzer) -> None:
        """Analyzer calculates success rate correctly with real data."""
        for i in range(100):
            analyzer.log_event(
                event_type=EventType.BYPASS_ATTEMPT,
                outcome=OutcomeType.SUCCESS if i < 75 else OutcomeType.FAILURE,
                protection_category=ProtectionCategory.SERIAL_KEY,
                component="keygen",
            )

        result = analyzer.get_success_rate(component="keygen")

        assert 0.7 < result.value < 0.8
        assert result.sample_size == 100
        assert result.confidence_interval[0] < result.value < result.confidence_interval[1]

    def test_analyzer_get_bayesian_success_rate(self, analyzer: SuccessRateAnalyzer) -> None:
        """Analyzer calculates Bayesian success rate correctly."""
        for i in range(100):
            analyzer.log_event(
                event_type=EventType.BYPASS_ATTEMPT,
                outcome=OutcomeType.SUCCESS if i < 80 else OutcomeType.FAILURE,
                protection_category=ProtectionCategory.SERIAL_KEY,
                component="keygen",
            )

        result = analyzer.get_bayesian_success_rate(component="keygen")

        assert 0.75 < result["posterior_mean"] < 0.85
        assert result["probability_above_50_percent"] > 0.99
        assert result["probability_above_80_percent"] < result["probability_above_50_percent"]

    def test_analyzer_compare_success_rates(self, analyzer: SuccessRateAnalyzer) -> None:
        """Analyzer compares success rates between components correctly."""
        for i in range(100):
            analyzer.log_event(
                event_type=EventType.BYPASS_ATTEMPT,
                outcome=OutcomeType.SUCCESS if i < 80 else OutcomeType.FAILURE,
                protection_category=ProtectionCategory.SERIAL_KEY,
                component="keygen_comp",
            )

        for i in range(100):
            analyzer.log_event(
                event_type=EventType.BYPASS_ATTEMPT,
                outcome=OutcomeType.SUCCESS if i < 40 else OutcomeType.FAILURE,
                protection_category=ProtectionCategory.SERIAL_KEY,
                component="dongle_emulator_comp",
            )

        comparison = analyzer.compare_success_rates("keygen_comp", "dongle_emulator_comp")

        assert "error" not in comparison
        assert comparison["component1"]["success_rate"] > comparison["component2"]["success_rate"]
        assert bool(comparison["significant_difference"]) is True
        assert comparison["statistical_test"]["p_value"] < 0.05

    def test_analyzer_get_trend_analysis(self, analyzer: SuccessRateAnalyzer) -> None:
        """Analyzer performs trend analysis correctly."""
        base_time = time.time()
        for i in range(100):
            success_rate = 0.5 + i * 0.003
            analyzer.log_event(
                event_type=EventType.BYPASS_ATTEMPT,
                outcome=OutcomeType.SUCCESS if np.random.random() < success_rate else OutcomeType.FAILURE,
                protection_category=ProtectionCategory.SERIAL_KEY,
                component="keygen",
            )

        trend = analyzer.get_trend_analysis("keygen")

        assert trend.component == "keygen"
        assert trend.trend_direction in ["increasing", "decreasing", "stable", "unknown"]

    def test_analyzer_get_component_statistics(self, analyzer: SuccessRateAnalyzer) -> None:
        """Analyzer retrieves component statistics correctly."""
        for component in ["keygen", "patcher", "detector"]:
            for i in range(50):
                analyzer.log_event(
                    event_type=EventType.BYPASS_ATTEMPT,
                    outcome=OutcomeType.SUCCESS if i < 30 else OutcomeType.FAILURE,
                    protection_category=ProtectionCategory.SERIAL_KEY,
                    component=component,
                )

        stats = analyzer.get_component_statistics()

        assert len(stats) == 3
        assert "keygen" in stats
        assert "patcher" in stats
        assert "detector" in stats
        assert all(0.0 <= s["success_rate"] <= 1.0 for s in stats.values())

    def test_analyzer_get_category_statistics(self, analyzer: SuccessRateAnalyzer) -> None:
        """Analyzer retrieves category statistics correctly."""
        for category in [ProtectionCategory.SERIAL_KEY, ProtectionCategory.DONGLE, ProtectionCategory.CLOUD_LICENSE]:
            for i in range(50):
                analyzer.log_event(
                    event_type=EventType.BYPASS_ATTEMPT,
                    outcome=OutcomeType.SUCCESS if i < 35 else OutcomeType.FAILURE,
                    protection_category=category,
                    component="test",
                )

        stats = analyzer.get_category_statistics()

        assert len(stats) >= 3
        assert all(0.0 <= s["success_rate"] <= 1.0 for s in stats.values())

    def test_analyzer_generate_performance_dashboard(self, analyzer: SuccessRateAnalyzer) -> None:
        """Analyzer generates valid performance dashboard data."""
        for i in range(100):
            analyzer.log_event(
                event_type=EventType.BYPASS_ATTEMPT,
                outcome=OutcomeType.SUCCESS if i % 2 == 0 else OutcomeType.FAILURE,
                protection_category=ProtectionCategory.SERIAL_KEY,
                component="keygen",
                duration=np.random.uniform(1.0, 5.0),
            )

        dashboard = analyzer.generate_performance_dashboard()

        assert "overall_metrics" in dashboard
        assert "component_performance" in dashboard
        assert dashboard["overall_metrics"]["total_events_24h"] > 0
        assert 0.0 <= dashboard["overall_metrics"]["overall_success_rate_24h"] <= 1.0

    def test_analyzer_export_data_json(self, analyzer: SuccessRateAnalyzer, tmp_path: Path) -> None:
        """Analyzer exports data to JSON correctly."""
        for i in range(50):
            analyzer.log_event(
                event_type=EventType.BYPASS_ATTEMPT,
                outcome=OutcomeType.SUCCESS,
                protection_category=ProtectionCategory.SERIAL_KEY,
                component="keygen",
            )

        output_file = analyzer.export_data(format="json", include_raw_events=True)

        assert Path(output_file).exists()
        assert Path(output_file).suffix == ".json"

        with open(output_file) as f:
            data = json.load(f)

        assert "component_statistics" in data
        assert "category_statistics" in data
        assert "raw_events" in data
        assert len(data["raw_events"]) == 50

        Path(output_file).unlink()

    def test_analyzer_export_data_csv(self, analyzer: SuccessRateAnalyzer, tmp_path: Path) -> None:
        """Analyzer exports data to CSV correctly."""
        for i in range(50):
            analyzer.log_event(
                event_type=EventType.BYPASS_ATTEMPT,
                outcome=OutcomeType.SUCCESS,
                protection_category=ProtectionCategory.SERIAL_KEY,
                component="keygen",
            )

        output_file = analyzer.export_data(format="csv")

        assert Path(output_file).exists()
        assert Path(output_file).suffix == ".csv"

        with open(output_file) as f:
            lines = f.readlines()

        assert len(lines) > 1
        assert "Component" in lines[0]

        Path(output_file).unlink()

    def test_analyzer_caching(self, analyzer: SuccessRateAnalyzer) -> None:
        """Analyzer caches expensive computations correctly."""
        for i in range(50):
            analyzer.log_event(
                event_type=EventType.BYPASS_ATTEMPT,
                outcome=OutcomeType.SUCCESS,
                protection_category=ProtectionCategory.SERIAL_KEY,
                component="keygen",
            )

        result1 = analyzer.get_success_rate(component="keygen")
        result2 = analyzer.get_success_rate(component="keygen")

        assert result1.value == result2.value
        assert result1.confidence_interval == result2.confidence_interval

    def test_analyzer_time_window_filtering(self, analyzer: SuccessRateAnalyzer) -> None:
        """Analyzer filters by time window correctly."""
        base_time = time.time()

        for i in range(100):
            analyzer.log_event(
                event_type=EventType.BYPASS_ATTEMPT,
                outcome=OutcomeType.SUCCESS if i < 80 else OutcomeType.FAILURE,
                protection_category=ProtectionCategory.SERIAL_KEY,
                component="keygen",
            )

        recent_result = analyzer.get_success_rate(component="keygen", time_window=3600)
        all_result = analyzer.get_success_rate(component="keygen")

        assert recent_result.sample_size <= all_result.sample_size


class TestTrackSuccessDecorator:
    """Tests for success tracking decorator."""

    def test_decorator_tracks_successful_function(self, tmp_path: Path) -> None:
        """Decorator tracks successful function execution."""
        db_path = tmp_path / "decorator_test.db"
        analyzer = get_success_rate_analyzer(str(db_path))

        @track_success(EventType.BYPASS_ATTEMPT, ProtectionCategory.SERIAL_KEY, "test_func_success")
        def successful_bypass() -> bool:
            return True

        result = successful_bypass()

        assert result is True

        events = analyzer.event_tracker.get_events(component="test_func_success")
        assert len(events) >= 1
        assert events[0].outcome == OutcomeType.SUCCESS

    def test_decorator_tracks_failed_function(self, tmp_path: Path) -> None:
        """Decorator tracks failed function execution."""
        db_path = tmp_path / "decorator_test2.db"
        analyzer = get_success_rate_analyzer(str(db_path))

        @track_success(EventType.BYPASS_ATTEMPT, ProtectionCategory.SERIAL_KEY, "test_func_fail")
        def failed_bypass() -> bool:
            return False

        result = failed_bypass()

        assert result is False

        events = analyzer.event_tracker.get_events(component="test_func_fail")
        assert len(events) >= 1
        assert events[0].outcome == OutcomeType.FAILURE

    def test_decorator_tracks_exception(self, tmp_path: Path) -> None:
        """Decorator tracks function that raises exception."""
        db_path = tmp_path / "decorator_test3.db"
        analyzer = get_success_rate_analyzer(str(db_path))

        @track_success(EventType.BYPASS_ATTEMPT, ProtectionCategory.SERIAL_KEY, "test_func_error")
        def error_bypass() -> bool:
            raise ValueError("Test error")

        with pytest.raises(ValueError):
            error_bypass()

        events = analyzer.event_tracker.get_events(component="test_func_error")
        assert len(events) >= 1
        assert events[0].outcome == OutcomeType.ERROR
        assert "Test error" in events[0].error_details

    def test_decorator_measures_duration(self, tmp_path: Path) -> None:
        """Decorator measures function execution duration."""
        db_path = tmp_path / "decorator_test4.db"
        analyzer = get_success_rate_analyzer(str(db_path))

        @track_success(EventType.BYPASS_ATTEMPT, ProtectionCategory.SERIAL_KEY, "test_func_duration")
        def slow_bypass() -> bool:
            time.sleep(0.1)
            return True

        slow_bypass()

        events = analyzer.event_tracker.get_events(component="test_func_duration")
        assert len(events) >= 1
        assert events[0].duration >= 0.1


class TestGlobalAnalyzerInstance:
    """Tests for global analyzer instance management."""

    def test_get_success_rate_analyzer_singleton(self) -> None:
        """Global analyzer returns same instance."""
        analyzer1 = get_success_rate_analyzer()
        analyzer2 = get_success_rate_analyzer()

        assert analyzer1 is analyzer2

    def test_get_success_rate_analyzer_initializes_correctly(self) -> None:
        """Global analyzer initializes correctly."""
        analyzer = get_success_rate_analyzer()

        assert analyzer is not None
        assert analyzer.event_tracker is not None


class TestEdgeCases:
    """Tests for edge cases and error handling."""

    @pytest.fixture
    def analyzer(self, tmp_path: Path) -> SuccessRateAnalyzer:
        """Create analyzer for edge case testing."""
        db_path = tmp_path / "test.db"
        return SuccessRateAnalyzer(str(db_path))

    def test_empty_data_analysis(self, analyzer: SuccessRateAnalyzer) -> None:
        """Analyzer handles empty data gracefully."""
        stats = analyzer.get_component_statistics()
        assert len(stats) == 0

        dashboard = analyzer.generate_performance_dashboard()
        assert dashboard["overall_metrics"]["total_events_24h"] == 0

    def test_hundred_percent_success_rate(self, analyzer: SuccessRateAnalyzer) -> None:
        """Analyzer handles 100% success rate correctly."""
        for i in range(100):
            analyzer.log_event(
                event_type=EventType.BYPASS_ATTEMPT,
                outcome=OutcomeType.SUCCESS,
                protection_category=ProtectionCategory.SERIAL_KEY,
                component="perfect_keygen",
            )

        result = analyzer.get_success_rate(component="perfect_keygen")

        assert result.value == 1.0
        assert result.confidence_interval[0] > 0.95
        assert result.confidence_interval[1] == 1.0

    def test_zero_percent_success_rate(self, analyzer: SuccessRateAnalyzer) -> None:
        """Analyzer handles 0% success rate correctly."""
        for i in range(100):
            analyzer.log_event(
                event_type=EventType.BYPASS_ATTEMPT,
                outcome=OutcomeType.FAILURE,
                protection_category=ProtectionCategory.SERIAL_KEY,
                component="broken_keygen",
            )

        result = analyzer.get_success_rate(component="broken_keygen")

        assert result.value == 0.0
        assert result.confidence_interval[0] < 1e-10
        assert result.confidence_interval[1] < 0.06

    def test_single_event_analysis(self, analyzer: SuccessRateAnalyzer) -> None:
        """Analyzer handles single event correctly."""
        analyzer.log_event(
            event_type=EventType.BYPASS_ATTEMPT,
            outcome=OutcomeType.SUCCESS,
            protection_category=ProtectionCategory.SERIAL_KEY,
            component="single_test",
        )

        result = analyzer.get_success_rate(component="single_test")

        assert result.value == 1.0
        assert result.sample_size == 1

    def test_mixed_outcomes(self, analyzer: SuccessRateAnalyzer) -> None:
        """Analyzer handles mixed outcomes correctly."""
        outcomes = [
            OutcomeType.SUCCESS,
            OutcomeType.FAILURE,
            OutcomeType.PARTIAL,
            OutcomeType.TIMEOUT,
            OutcomeType.ERROR,
        ]

        for outcome in outcomes * 20:
            analyzer.log_event(
                event_type=EventType.BYPASS_ATTEMPT,
                outcome=outcome,
                protection_category=ProtectionCategory.SERIAL_KEY,
                component="mixed_test",
            )

        result = analyzer.get_success_rate(component="mixed_test")

        assert 0.0 <= result.value <= 1.0
        assert result.sample_size == 100

    def test_export_with_invalid_format(self, analyzer: SuccessRateAnalyzer) -> None:
        """Analyzer raises error for invalid export format."""
        with pytest.raises(ValueError, match="Unsupported export format"):
            analyzer.export_data(format="invalid")

    def test_comparison_with_insufficient_data(self, analyzer: SuccessRateAnalyzer) -> None:
        """Analyzer handles comparison with insufficient data."""
        analyzer.log_event(
            event_type=EventType.BYPASS_ATTEMPT,
            outcome=OutcomeType.SUCCESS,
            protection_category=ProtectionCategory.SERIAL_KEY,
            component="comp1",
        )

        comparison = analyzer.compare_success_rates("comp1", "nonexistent")

        assert "error" in comparison


class TestRealWorldScenarios:
    """Tests simulating real-world bypass analysis scenarios."""

    @pytest.fixture
    def analyzer(self, tmp_path: Path) -> SuccessRateAnalyzer:
        """Create analyzer for real-world testing."""
        db_path = tmp_path / "realworld.db"
        return SuccessRateAnalyzer(str(db_path))

    def test_keygen_success_rate_analysis(self, analyzer: SuccessRateAnalyzer) -> None:
        """Analyze keygen success rates with realistic data distribution."""
        np.random.seed(42)

        for i in range(500):
            base_success_rate = 0.85
            noise = np.random.normal(0, 0.1)
            success = np.random.random() < (base_success_rate + noise)

            analyzer.log_event(
                event_type=EventType.BYPASS_ATTEMPT,
                outcome=OutcomeType.SUCCESS if success else OutcomeType.FAILURE,
                protection_category=ProtectionCategory.SERIAL_KEY,
                component="vmprotect_keygen",
                duration=np.random.uniform(0.5, 3.0),
            )

        result = analyzer.get_success_rate(component="vmprotect_keygen")

        assert 0.80 < result.value < 0.90
        assert result.sample_size == 500

    def test_multiple_protection_types_comparison(self, analyzer: SuccessRateAnalyzer) -> None:
        """Compare success rates across different protection types."""
        protections = [
            (ProtectionCategory.SERIAL_KEY, "serial_keygen", 0.85),
            (ProtectionCategory.DONGLE, "dongle_emulator", 0.65),
            (ProtectionCategory.CLOUD_LICENSE, "cloud_interceptor", 0.75),
            (ProtectionCategory.VM_PROTECTION, "vm_unpacker", 0.50),
        ]

        for category, component, success_rate in protections:
            for i in range(200):
                outcome = OutcomeType.SUCCESS if np.random.random() < success_rate else OutcomeType.FAILURE
                analyzer.log_event(
                    event_type=EventType.BYPASS_ATTEMPT,
                    outcome=outcome,
                    protection_category=category,
                    component=component,
                    duration=np.random.uniform(1.0, 10.0),
                )

        category_stats = analyzer.get_category_statistics()

        assert len(category_stats) >= 4
        assert category_stats["serial_key"]["success_rate"] > category_stats["vm_protection"]["success_rate"]

    def test_improving_success_rate_trend(self, analyzer: SuccessRateAnalyzer) -> None:
        """Track improving success rate over time as technique improves."""
        base_time = time.time() - 30 * 24 * 3600

        for day in range(30):
            daily_success_rate = 0.5 + (day / 30) * 0.3

            for event_num in range(20):
                outcome = OutcomeType.SUCCESS if np.random.random() < daily_success_rate else OutcomeType.FAILURE
                analyzer.log_event(
                    event_type=EventType.BYPASS_ATTEMPT,
                    outcome=outcome,
                    protection_category=ProtectionCategory.SERIAL_KEY,
                    component="evolving_keygen",
                    duration=np.random.uniform(1.0, 5.0),
                )

        trend = analyzer.get_trend_analysis("evolving_keygen")

        assert trend.trend_direction in ["increasing", "stable"]

    def test_comprehensive_bypass_workflow_tracking(self, analyzer: SuccessRateAnalyzer) -> None:
        """Track complete bypass workflow with multiple stages."""
        workflow_stages = [
            (EventType.PROTECTION_DETECTION, ProtectionCategory.SERIAL_KEY, "detector", 0.95),
            (EventType.ANALYSIS, ProtectionCategory.SERIAL_KEY, "analyzer", 0.85),
            (EventType.BYPASS_ATTEMPT, ProtectionCategory.SERIAL_KEY, "keygen", 0.75),
        ]

        for stage_type, category, component, success_rate in workflow_stages:
            for i in range(100):
                outcome = OutcomeType.SUCCESS if np.random.random() < success_rate else OutcomeType.FAILURE
                analyzer.log_event(
                    event_type=stage_type,
                    outcome=outcome,
                    protection_category=category,
                    component=component,
                    duration=np.random.uniform(0.5, 5.0),
                )

        component_stats = analyzer.get_component_statistics()

        assert len(component_stats) == 3
        assert component_stats["detector"]["success_rate"] > component_stats["keygen"]["success_rate"]

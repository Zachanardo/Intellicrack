#!/usr/bin/env python3
"""Success rate analyzer plugin for Intellicrack.

This file is part of Intellicrack.
Copyright (C) 2025 Zachary Flint.

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see https://www.gnu.org/licenses/.
"""

import hashlib
import json
import logging
import math
import threading
import time
import warnings
from collections import defaultdict
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Any, ParamSpec, TypeVar

from scipy import stats
from sklearn.ensemble import GradientBoostingRegressor, RandomForestRegressor
from sklearn.linear_model import BayesianRidge
from sklearn.preprocessing import StandardScaler

from intellicrack.data import SUCCESS_RATES_DB
from intellicrack.handlers.matplotlib_handler import PdfPages, plt
from intellicrack.handlers.numpy_handler import numpy as np
from intellicrack.handlers.sqlite3_handler import sqlite3
from intellicrack.utils.logger import logger


warnings.filterwarnings("ignore")

"""
Success Rate Analyzer for Intellicrack Framework

Comprehensive statistical analysis system for tracking, analyzing, and predicting
success rates of all protection bypass techniques and detection methods in the
Intellicrack framework using advanced statistical and machine learning methods.

Author: Intellicrack Framework
Version: 2.0.0
License: GPL v3
"""


class EventType(Enum):
    """Types of events to track."""

    PROTECTION_DETECTION = "protection_detection"
    BYPASS_ATTEMPT = "bypass_attempt"
    CLASSIFICATION = "classification"
    EMULATION = "emulation"
    UNWRAPPING = "unwrapping"
    INTERCEPTION = "interception"
    ANALYSIS = "analysis"


class OutcomeType(Enum):
    """Event outcome types."""

    SUCCESS = "success"
    FAILURE = "failure"
    PARTIAL = "partial"
    TIMEOUT = "timeout"
    ERROR = "error"


class ProtectionCategory(Enum):
    """Protection categories for analysis."""

    SERIAL_KEY = "serial_key"
    DONGLE = "dongle"
    ONLINE_VALIDATION = "online_validation"
    TIME_TRIAL = "time_trial"
    VM_PROTECTION = "vm_protection"
    PACKER = "packer"
    ANTI_DEBUG = "anti_debug"
    CERTIFICATE_PINNING = "certificate_pinning"
    CLOUD_LICENSE = "cloud_license"
    CUSTOM = "custom"


@dataclass
class AnalysisEvent:
    """Individual analysis event for tracking."""

    event_id: str
    event_type: EventType
    outcome: OutcomeType
    protection_category: ProtectionCategory
    component: str
    timestamp: float
    duration: float = 0.0
    metadata: dict[str, Any] = field(default_factory=dict)
    error_details: str = ""

    def __post_init__(self) -> None:
        """Initialize analysis event with generated ID if not provided."""
        if not self.event_id:
            self.event_id = self.generate_event_id()

    def generate_event_id(self) -> str:
        """Generate unique event ID.

        Returns:
            str: The unique event ID.
        """
        data = f"{self.event_type.value}_{self.component}_{self.timestamp}"
        return hashlib.sha256(data.encode()).hexdigest()[:16]


@dataclass
class StatisticalResult:
    """Statistical analysis result."""

    metric_name: str
    value: float
    confidence_interval: tuple[float, float]
    p_value: float | None = None
    significance_level: float = 0.05
    sample_size: int = 0
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass
class TrendAnalysis:
    """Trend analysis result."""

    component: str
    protection_category: ProtectionCategory
    trend_direction: str  # "increasing", "decreasing", "stable"
    trend_strength: float  # 0-1 scale
    forecast_values: list[float]
    forecast_intervals: list[tuple[float, float]]
    seasonal_pattern: bool = False
    change_points: list[float] = field(default_factory=list)


class WilsonScoreInterval:
    """Wilson score interval for binomial confidence intervals."""

    @staticmethod
    def calculate(successes: int, total: int, confidence_level: float = 0.95) -> tuple[float, float]:
        """Calculate Wilson score confidence interval.

        Args:
            successes: Number of successful outcomes.
            total: Total number of outcomes.
            confidence_level: Desired confidence level (default 0.95 for 95%).

        Returns:
            tuple[float, float]: Lower and upper bounds of the confidence interval.
        """
        if total == 0:
            return (0.0, 1.0)

        p = successes / total
        z = stats.norm.ppf(1 - (1 - confidence_level) / 2)

        denominator = 1 + z**2 / total
        center = (p + z**2 / (2 * total)) / denominator
        margin = z * math.sqrt((p * (1 - p) + z**2 / (4 * total)) / total) / denominator

        lower = max(0.0, center - margin)
        upper = min(1.0, center + margin)

        return (lower, upper)


class BayesianAnalyzer:
    """Bayesian analysis for success rates."""

    def __init__(self, prior_alpha: float = 1.0, prior_beta: float = 1.0) -> None:
        """Initialize Bayesian analyzer with Beta distribution prior parameters."""
        self.prior_alpha = prior_alpha
        self.prior_beta = prior_beta

    def update_posterior(self, successes: int, failures: int) -> tuple[float, float]:
        """Update Beta posterior parameters.

        Args:
            successes: Number of successful outcomes.
            failures: Number of failed outcomes.

        Returns:
            tuple[float, float]: Updated posterior alpha and beta parameters.
        """
        posterior_alpha = self.prior_alpha + successes
        posterior_beta = self.prior_beta + failures
        return (posterior_alpha, posterior_beta)

    def posterior_mean(self, successes: int, failures: int) -> float:
        """Calculate posterior mean.

        Args:
            successes: Number of successful outcomes.
            failures: Number of failed outcomes.

        Returns:
            float: Posterior mean of the success rate.
        """
        alpha, beta = self.update_posterior(successes, failures)
        return alpha / (alpha + beta)

    def credible_interval(self, successes: int, failures: int, confidence: float = 0.95) -> tuple[float, float]:
        """Calculate Bayesian credible interval.

        Args:
            successes: Number of successful outcomes.
            failures: Number of failed outcomes.
            confidence: Desired confidence level (default 0.95 for 95%).

        Returns:
            tuple[float, float]: Lower and upper bounds of the credible interval.
        """
        alpha, beta = self.update_posterior(successes, failures)
        lower_percentile = (1 - confidence) / 2
        upper_percentile = 1 - lower_percentile

        lower = stats.beta.ppf(lower_percentile, alpha, beta)
        upper = stats.beta.ppf(upper_percentile, alpha, beta)

        return (lower, upper)

    def posterior_probability(self, successes: int, failures: int, threshold: float) -> float:
        """Calculate P(success_rate > threshold | data).

        Args:
            successes: Number of successful outcomes.
            failures: Number of failed outcomes.
            threshold: Success rate threshold value.

        Returns:
            float: Probability that success rate exceeds the threshold.
        """
        alpha, beta = self.update_posterior(successes, failures)
        cdf_result = stats.beta.cdf(threshold, alpha, beta)
        return float(1 - cdf_result)


class SurvivalAnalyzer:
    """Kaplan-Meier survival analysis for bypass longevity."""

    def __init__(self) -> None:
        """Initialize survival analyzer for Kaplan-Meier analysis."""
        self.survival_data: list[tuple[float, bool]] = []

    def add_observation(self, duration: float, censored: bool = False) -> None:
        """Add survival observation.

        Args:
            duration: Duration until event or censoring.
            censored: Whether the observation is censored (default False).
        """
        self.survival_data.append((duration, not censored))  # True = event occurred

    def kaplan_meier_estimate(self) -> tuple[list[float], list[float]]:
        """Calculate Kaplan-Meier survival function.

        Returns:
            tuple[list[float], list[float]]: Times and corresponding survival probabilities.
        """
        if not self.survival_data:
            return ([], [])

        # Sort by duration
        sorted_data = sorted(self.survival_data)

        times = []
        survival_probs = []
        current_survival = 1.0

        i = 0
        while i < len(sorted_data):
            current_time = sorted_data[i][0]
            at_risk = len(sorted_data) - i

            # Count events at this time
            events = 0
            j = i
            while j < len(sorted_data) and sorted_data[j][0] == current_time:
                if sorted_data[j][1]:  # Event occurred (not censored)
                    events += 1
                j += 1

            if events > 0:
                survival_factor = (at_risk - events) / at_risk
                current_survival *= survival_factor

                times.append(current_time)
                survival_probs.append(current_survival)

            i = j

        return (times, survival_probs)

    def median_survival_time(self) -> float | None:
        """Calculate median survival time.

        Returns:
            float | None: Median survival time or None if not calculable.
        """
        times, survival_probs = self.kaplan_meier_estimate()

        if not times:
            return None

        return next(
            (times[i] for i, prob in enumerate(survival_probs) if prob <= 0.5),
            None,
        )


class TimeSeriesAnalyzer:
    """Time series analysis and forecasting."""

    def __init__(self) -> None:
        """Initialize time series analyzer with component history tracking."""
        self.history: defaultdict[str, list[tuple[float, float]]] = defaultdict(list)

    def add_data_point(self, component: str, timestamp: float, value: float) -> None:
        """Add time series data point.

        Args:
            component: Component identifier.
            timestamp: Data point timestamp.
            value: Data point value.
        """
        self.history[component].append((timestamp, value))

    def detect_trend(self, component: str, window_size: int = 30) -> dict[str, Any]:
        """Detect trend using linear regression.

        Args:
            component: Component identifier.
            window_size: Size of the sliding window for trend detection (default 30).

        Returns:
            dict[str, Any]: Trend analysis results including direction, strength, slope, R-squared, and p-value.
        """
        if component not in self.history or len(self.history[component]) < window_size:
            return {"trend": "insufficient_data", "strength": 0.0}

        recent_data = self.history[component][-window_size:]
        times = np.array([point[0] for point in recent_data])
        values = np.array([point[1] for point in recent_data])

        # Normalize times
        times -= times[0]

        # Linear regression
        slope, _intercept, r_value, p_value, _std_err = stats.linregress(times, values)

        # Determine trend direction and strength
        if abs(r_value) < 0.1:
            trend = "stable"
        elif slope > 0:
            trend = "increasing"
        else:
            trend = "decreasing"

        return {
            "trend": trend,
            "strength": abs(r_value),
            "slope": slope,
            "r_squared": r_value**2,
            "p_value": p_value,
        }

    def seasonal_decomposition(self, component: str, period: int = 24) -> dict[str, Any]:
        """Perform seasonal decomposition.

        Args:
            component: Component identifier.
            period: Period for seasonal decomposition (default 24 hours).

        Returns:
            dict[str, Any]: Seasonal decomposition results including seasonal flag, strength, and components.
        """
        if component not in self.history or len(self.history[component]) < period * 2:
            return {"seasonal": False, "components": {}}

        data = self.history[component]
        values = np.array([point[1] for point in data])

        if len(values) < period * 2:
            return {"seasonal": False, "components": {}}

        # Simple seasonal decomposition
        n = len(values)
        seasonal = np.zeros(n)
        trend = np.zeros(n)

        # Calculate trend using moving average
        half_period = period // 2
        for i in range(half_period, n - half_period):
            trend[i] = np.mean(values[i - half_period : i + half_period + 1])

        # Calculate seasonal component
        detrended = values - trend
        for i in range(period):
            seasonal_values = detrended[i::period]
            if len(seasonal_values) > 0:
                seasonal[i::period] = np.mean(seasonal_values[seasonal_values != 0])

        # Calculate residual
        residual = values - trend - seasonal

        # Detect seasonality strength
        total_var = np.var(values)
        seasonal_var = np.var(seasonal)
        seasonal_strength = seasonal_var / total_var if total_var > 0 else 0

        return {
            "seasonal": seasonal_strength > 0.1,
            "seasonal_strength": seasonal_strength,
            "components": {
                "trend": trend.tolist(),
                "seasonal": seasonal.tolist(),
                "residual": residual.tolist(),
            },
        }

    def forecast_arima(self, component: str, periods: int = 10) -> tuple[list[float], list[tuple[float, float]]]:
        """Perform ARIMA-like forecasting.

        Args:
            component: Component identifier.
            periods: Number of periods to forecast (default 10).

        Returns:
            tuple[list[float], list[tuple[float, float]]]: Forecasted values and prediction intervals.
        """
        if component not in self.history or len(self.history[component]) < 10:
            return ([], [])

        data = self.history[component]
        values = np.array([point[1] for point in data])

        # Use last values for simple forecasting
        recent_mean = np.mean(values[-min(20, len(values)) :])
        recent_std = np.std(values[-min(20, len(values)) :])

        # Simple random walk with drift
        last_value = values[-1]
        drift = np.mean(np.diff(values[-min(10, len(values) - 1) :]))

        forecasts = []
        intervals = []

        for i in range(periods):
            # Use combination of trend and mean reversion for better forecasting
            trend_component = last_value + drift * (i + 1)
            mean_reversion_weight = min(0.3, (i + 1) * 0.05)  # Increase mean reversion over time
            forecast = trend_component * (1 - mean_reversion_weight) + recent_mean * mean_reversion_weight

            # Increasing uncertainty over time
            uncertainty = recent_std * np.sqrt(i + 1)

            lower = forecast - 1.96 * uncertainty
            upper = forecast + 1.96 * uncertainty

            forecasts.append(forecast)
            intervals.append((lower, upper))

        return (forecasts, intervals)


class StatisticalTester:
    """Statistical hypothesis testing."""

    @staticmethod
    def chi_square_test(observed: list[int], expected: list[int] | None = None) -> dict[str, float]:
        """Chi-square goodness of fit test.

        Args:
            observed: Observed frequencies.
            expected: Expected frequencies (default uniform distribution).

        Returns:
            dict[str, float]: Chi-square statistic, p-value, and degrees of freedom.
        """
        expected_values: list[float]
        if expected is None:
            expected_values = [float(sum(observed)) / len(observed)] * len(observed)
        else:
            expected_values = [float(x) for x in expected]

        chi2_stat, p_value = stats.chisquare(observed, expected_values)

        return {
            "chi2_statistic": chi2_stat,
            "p_value": p_value,
            "degrees_of_freedom": len(observed) - 1,
        }

    @staticmethod
    def fishers_exact_test(success1: int, total1: int, success2: int, total2: int) -> dict[str, float]:
        """Fisher's exact test for comparing two proportions.

        Args:
            success1: Successes in group 1.
            total1: Total count in group 1.
            success2: Successes in group 2.
            total2: Total count in group 2.

        Returns:
            dict[str, float]: Odds ratio and p-value.
        """
        # Create contingency table
        table = [[success1, total1 - success1], [success2, total2 - success2]]

        odds_ratio, p_value = stats.fisher_exact(table)

        return {
            "odds_ratio": odds_ratio,
            "p_value": p_value,
        }

    @staticmethod
    def mann_whitney_u_test(group1: list[float], group2: list[float]) -> dict[str, float]:
        """Mann-Whitney U test for comparing two independent groups.

        Args:
            group1: First group of observations.
            group2: Second group of observations.

        Returns:
            dict[str, float]: U statistic and p-value.
        """
        statistic, p_value = stats.mannwhitneyu(group1, group2, alternative="two-sided")

        return {
            "u_statistic": statistic,
            "p_value": p_value,
        }


class PerformanceMetrics:
    """Performance metrics calculator."""

    @staticmethod
    def confusion_matrix_metrics(tp: int, tn: int, fp: int, fn: int) -> dict[str, float]:
        """Calculate metrics from confusion matrix.

        Args:
            tp: True positives.
            tn: True negatives.
            fp: False positives.
            fn: False negatives.

        Returns:
            dict[str, float]: Calculated performance metrics.
        """
        total = tp + tn + fp + fn
        if total == 0:
            return {}

        accuracy = (tp + tn) / total
        precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
        recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0
        specificity = tn / (tn + fp) if (tn + fp) > 0 else 0.0
        f1_score = 2 * (precision * recall) / (precision + recall) if (precision + recall) > 0 else 0.0

        return {
            "accuracy": accuracy,
            "precision": precision,
            "recall": recall,
            "specificity": specificity,
            "f1_score": f1_score,
            "sensitivity": recall,
            "true_positive_rate": recall,
            "false_positive_rate": fp / (fp + tn) if (fp + tn) > 0 else 0.0,
        }

    @staticmethod
    def auc_roc(y_true: list[int], y_scores: list[float]) -> float:
        """Calculate AUC-ROC using trapezoidal rule.

        Args:
            y_true: True binary labels.
            y_scores: Predicted scores.

        Returns:
            float: Area Under the ROC Curve.
        """
        if len(set(y_true)) != 2:
            return 0.5  # Cannot calculate ROC for non-binary classification

        # Sort by scores
        sorted_indices = np.argsort(y_scores)[::-1]
        y_true_sorted = np.array(y_true)[sorted_indices]

        # Calculate TPR and FPR at different thresholds
        tpr_values = []
        fpr_values = []

        n_pos = sum(y_true)
        n_neg = len(y_true) - n_pos

        if n_pos == 0 or n_neg == 0:
            return 0.5

        tp = 0
        fp = 0

        for i in range(len(y_true_sorted)):
            if y_true_sorted[i] == 1:
                tp += 1
            else:
                fp += 1

            tpr = tp / n_pos
            fpr = fp / n_neg

            tpr_values.append(tpr)
            fpr_values.append(fpr)

        # Calculate AUC using trapezoidal rule
        auc = 0.0
        for i in range(1, len(fpr_values)):
            auc += (fpr_values[i] - fpr_values[i - 1]) * (tpr_values[i] + tpr_values[i - 1]) / 2

        return auc


class EventTracker:
    """Event tracking and database management."""

    def __init__(self, db_path: str = "") -> None:
        """Initialize event tracker with SQLite database and threading support."""
        self.db_path = db_path or str(SUCCESS_RATES_DB)
        self.lock = threading.Lock()
        self.initialize_database()

    def initialize_database(self) -> None:
        """Initialize SQLite database schema."""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()

            # Events table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS events (
                    event_id TEXT PRIMARY KEY,
                    event_type TEXT NOT NULL,
                    outcome TEXT NOT NULL,
                    protection_category TEXT NOT NULL,
                    component TEXT NOT NULL,
                    timestamp REAL NOT NULL,
                    duration REAL DEFAULT 0.0,
                    metadata TEXT DEFAULT '{}',
                    error_details TEXT DEFAULT ''
                )
            """)

            # Success rate cache table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS success_rate_cache (
                    component TEXT,
                    protection_category TEXT,
                    period_start REAL,
                    period_end REAL,
                    success_count INTEGER,
                    total_count INTEGER,
                    success_rate REAL,
                    confidence_lower REAL,
                    confidence_upper REAL,
                    last_updated REAL,
                    PRIMARY KEY (component, protection_category, period_start, period_end)
                )
            """)

            # Trend analysis cache
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS trend_cache (
                    component TEXT,
                    protection_category TEXT,
                    analysis_type TEXT,
                    result_data TEXT,
                    last_updated REAL,
                    PRIMARY KEY (component, protection_category, analysis_type)
                )
            """)

            # Create indices for performance
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_events_timestamp ON events(timestamp)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_events_component ON events(component)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_events_category ON events(protection_category)")

            conn.commit()

    def log_event(self, event: AnalysisEvent) -> None:
        """Log analysis event to database.

        Args:
            event: The analysis event to log.
        """
        with self.lock, sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()

            cursor.execute(
                """
                    INSERT OR REPLACE INTO events
                    (event_id, event_type, outcome, protection_category, component,
                     timestamp, duration, metadata, error_details)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    event.event_id,
                    event.event_type.value,
                    event.outcome.value,
                    event.protection_category.value,
                    event.component,
                    event.timestamp,
                    event.duration,
                    json.dumps(event.metadata),
                    event.error_details,
                ),
            )

            conn.commit()

    def get_events(
        self,
        component: str | None = None,
        protection_category: ProtectionCategory | None = None,
        start_time: float | None = None,
        end_time: float | None = None,
    ) -> list[AnalysisEvent]:
        """Retrieve events from database with filtering.

        Args:
            component: Filter by component name (optional).
            protection_category: Filter by protection category (optional).
            start_time: Filter events after this timestamp (optional).
            end_time: Filter events before this timestamp (optional).

        Returns:
            list[AnalysisEvent]: List of matching events.
        """
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()

            query = "SELECT * FROM events WHERE 1=1"
            params: list[str | float] = []

            if component:
                query += " AND component = ?"
                params.append(component)

            if protection_category:
                query += " AND protection_category = ?"
                params.append(protection_category.value)

            if start_time:
                query += " AND timestamp >= ?"
                params.append(start_time)

            if end_time:
                query += " AND timestamp <= ?"
                params.append(end_time)

            query += " ORDER BY timestamp DESC"

            cursor.execute(query, params)
            rows = cursor.fetchall()

            events = []
            for row in rows:
                event = AnalysisEvent(
                    event_id=row[0],
                    event_type=EventType(row[1]),
                    outcome=OutcomeType(row[2]),
                    protection_category=ProtectionCategory(row[3]),
                    component=row[4],
                    timestamp=row[5],
                    duration=row[6],
                    metadata=json.loads(row[7]) if row[7] else {},
                    error_details=row[8] or "",
                )
                events.append(event)

            return events

    def get_success_counts(
        self,
        component: str | None = None,
        protection_category: ProtectionCategory | None = None,
        start_time: float | None = None,
        end_time: float | None = None,
    ) -> tuple[int, int]:
        """Get success and total counts.

        Args:
            component: Filter by component name (optional).
            protection_category: Filter by protection category (optional).
            start_time: Filter events after this timestamp (optional).
            end_time: Filter events before this timestamp (optional).

        Returns:
            tuple[int, int]: Counts of successful and total events.
        """
        events = self.get_events(component, protection_category, start_time, end_time)

        success_count = sum(event.outcome == OutcomeType.SUCCESS for event in events)
        total_count = len(events)

        return (success_count, total_count)


class MLPredictor:
    """Machine learning-based success rate predictor."""

    def __init__(self) -> None:
        """Initialize machine learning predictor with ensemble models and feature scaling."""
        self.models = {
            "random_forest": RandomForestRegressor(n_estimators=100, random_state=42),
            "gradient_boosting": GradientBoostingRegressor(n_estimators=100, random_state=42),
            "bayesian_ridge": BayesianRidge(),
        }
        self.scaler = StandardScaler()
        self.is_trained = False
        self.feature_names: list[str] = []

    def prepare_features(self, events: list[AnalysisEvent]) -> tuple[np.ndarray, np.ndarray]:
        """Prepare features for machine learning.

        Args:
            events: List of analysis events to convert to features.

        Returns:
            tuple[np.ndarray, np.ndarray]: Feature matrix and target values.
        """
        if not events:
            return np.array([]), np.array([])

        features = []
        targets = []

        # Group events by time windows
        window_size = 3600  # 1 hour windows
        event_groups = defaultdict(list)

        for event in events:
            window = int(event.timestamp // window_size)
            event_groups[window].append(event)

        for window, window_events in event_groups.items():
            if len(window_events) < 5:  # Skip windows with too few events
                continue

            # Calculate features for this window
            success_count = sum(e.outcome == OutcomeType.SUCCESS for e in window_events)
            total_count = len(window_events)
            success_rate = success_count / total_count if total_count > 0 else 0

            avg_duration = np.mean([e.duration for e in window_events if e.duration > 0])
            if np.isnan(avg_duration):
                avg_duration = 0

            # Protection category distribution
            category_counts: defaultdict[str, int] = defaultdict(int)
            for event in window_events:
                category_counts[event.protection_category.value] += 1

            # Component distribution
            component_counts: defaultdict[str, int] = defaultdict(int)
            for event in window_events:
                component_counts[event.component] += 1

            # Time features
            hour_of_day = (window * window_size) % 86400 // 3600
            day_of_week = ((window * window_size) // 86400) % 7

            feature_vector = [
                total_count,
                avg_duration,
                hour_of_day,
                day_of_week,
                len(category_counts),  # Number of different protection types
                len(component_counts),  # Number of different components
                max(category_counts.values()) / total_count,  # Dominant category ratio
                max(component_counts.values()) / total_count,  # Dominant component ratio
            ]

            features.append(feature_vector)
            targets.append(success_rate)

        self.feature_names = [
            "total_count",
            "avg_duration",
            "hour_of_day",
            "day_of_week",
            "num_categories",
            "num_components",
            "dominant_category_ratio",
            "dominant_component_ratio",
        ]

        return np.array(features), np.array(targets)

    def train(self, events: list[AnalysisEvent]) -> None:
        """Train prediction models.

        Args:
            events: Historical events for training.
        """
        X, y = self.prepare_features(events)

        if len(X) < 10:  # Need minimum samples for training
            return

        # Scale features
        X_scaled = self.scaler.fit_transform(X)

        # Train all models
        for name, model in self.models.items():
            try:
                model.fit(X_scaled, y)
            except Exception as e:
                logger.exception("Error training %s model: %s", name, e)

        self.is_trained = True

    def predict(self, recent_events: list[AnalysisEvent], horizon: int = 24) -> dict[str, Any]:
        """Predict future success rates.

        Args:
            recent_events: Recent events for prediction context.
            horizon: Prediction horizon in hours (default 24).

        Returns:
            dict[str, Any]: Predictions from each model and ensemble.
        """
        if not self.is_trained or not recent_events:
            return {}

        # Use last window as baseline for prediction
        X, _ = self.prepare_features(recent_events[-100:])  # Use last 100 events

        if len(X) == 0:
            return {}

        X_scaled = self.scaler.transform(X[-1:])  # Use most recent feature vector

        predictions = {}

        for name, model in self.models.items():
            try:
                pred = model.predict(X_scaled)[0]
                predictions[name] = max(0.0, min(1.0, pred))  # Clamp to [0, 1]
            except Exception as e:
                logger.exception("Error predicting with %s: %s", name, e)

        # Ensemble prediction (average)
        if predictions:
            ensemble_pred = np.mean(list(predictions.values()))
            predictions["ensemble"] = ensemble_pred

        return predictions


class ReportGenerator:
    """Statistical report generation."""

    def __init__(self, output_dir: str = "reports") -> None:
        """Initialize report generator with configurable output directory."""
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(exist_ok=True)

    def generate_comprehensive_report(self, analyzer: "SuccessRateAnalyzer") -> str:
        """Generate comprehensive PDF report.

        Args:
            analyzer: The SuccessRateAnalyzer instance to report on.

        Returns:
            str: Path to the generated PDF report.
        """
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        report_path = self.output_dir / f"intellicrack_success_analysis_{timestamp}.pdf"

        with PdfPages(str(report_path)) as pdf:
            # Page 1: Executive Summary
            fig, ((ax1, ax2), (ax3, ax4)) = plt.subplots(2, 2, figsize=(11, 8.5))

            # Overall success rates by component
            component_stats = analyzer.get_component_statistics()
            if component_stats:
                components = list(component_stats.keys())
                success_rates = [stats["success_rate"] for stats in component_stats.values()]

                ax1.bar(range(len(components)), success_rates)
                ax1.set_title("Success Rates by Component")
                ax1.set_xlabel("Component")
                ax1.set_ylabel("Success Rate")
                ax1.set_xticks(range(len(components)))
                ax1.set_xticklabels(components, rotation=45, ha="right")
                ax1.set_ylim(0, 1)

            if category_stats := analyzer.get_category_statistics():
                categories = list(category_stats.keys())
                cat_success_rates = [stats["success_rate"] for stats in category_stats.values()]

                ax2.bar(range(len(categories)), cat_success_rates)
                ax2.set_title("Success Rates by Protection Category")
                ax2.set_xlabel("Protection Category")
                ax2.set_ylabel("Success Rate")
                ax2.set_xticks(range(len(categories)))
                ax2.set_xticklabels(categories, rotation=45, ha="right")
                ax2.set_ylim(0, 1)

            # Trend over time
            recent_events = analyzer.event_tracker.get_events(
                start_time=time.time() - 30 * 24 * 3600,  # Last 30 days
            )
            if recent_events:
                daily_success = self._calculate_daily_success_rates(recent_events)
                days = list(daily_success.keys())
                rates = list(daily_success.values())

                ax3.plot(days, rates, marker="o")
                ax3.set_title("Success Rate Trend (30 Days)")
                ax3.set_xlabel("Days Ago")
                ax3.set_ylabel("Success Rate")
                ax3.set_ylim(0, 1)
                ax3.grid(True, alpha=0.3)

            if durations := [event.duration for event in recent_events if event.duration > 0]:
                ax4.hist(durations, bins=20, alpha=0.7, edgecolor="black")
                ax4.set_title("Distribution of Analysis Durations")
                ax4.set_xlabel("Duration (seconds)")
                ax4.set_ylabel("Frequency")

            plt.tight_layout()
            pdf.savefig(fig, bbox_inches="tight")
            plt.close()

            # Page 2: Statistical Analysis
            fig, ((ax1, ax2), (ax3, ax4)) = plt.subplots(2, 2, figsize=(11, 8.5))

            # Confidence intervals
            if component_stats:
                components = list(component_stats.keys())
                means = [stats["success_rate"] for stats in component_stats.values()]
                ci_lower = [stats["confidence_interval"][0] for stats in component_stats.values()]
                ci_upper = [stats["confidence_interval"][1] for stats in component_stats.values()]

                x_pos = range(len(components))
                ax1.errorbar(
                    x_pos,
                    means,
                    yerr=[np.array(means) - ci_lower, ci_upper - np.array(means)],
                    fmt="o",
                    capsize=5,
                    capthick=2,
                )
                ax1.set_title("Success Rates with 95% Confidence Intervals")
                ax1.set_xlabel("Component")
                ax1.set_ylabel("Success Rate")
                ax1.set_xticks(x_pos)
                ax1.set_xticklabels(components, rotation=45, ha="right")
                ax1.set_ylim(0, 1)
                ax1.grid(True, alpha=0.3)

            # Survival analysis if available
            if hasattr(analyzer, "survival_analyzer") and analyzer.survival_analyzer.survival_data:
                times, survival_probs = analyzer.survival_analyzer.kaplan_meier_estimate()
                if times:
                    ax2.step(times, survival_probs, where="post")
                    ax2.set_title("Kaplan-Meier Survival Curve")
                    ax2.set_xlabel("Time (hours)")
                    ax2.set_ylabel("Survival Probability")
                    ax2.set_ylim(0, 1)
                    ax2.grid(True, alpha=0.3)

            # Correlation matrix if enough data
            if len(component_stats) > 2:
                correlation_data = self._prepare_correlation_data(analyzer)
                if correlation_data is not None:
                    im = ax3.imshow(correlation_data, cmap="coolwarm", vmin=-1, vmax=1)
                    ax3.set_title("Component Success Rate Correlations")
                    plt.colorbar(im, ax=ax3)

            # Prediction accuracy if ML models available
            if hasattr(analyzer, "ml_predictor") and analyzer.ml_predictor.is_trained:
                if predictions := analyzer.ml_predictor.predict(recent_events):
                    pred_names = list(predictions.keys())
                    pred_values = list(predictions.values())

                    ax4.bar(range(len(pred_names)), pred_values)
                    ax4.set_title("ML Model Predictions")
                    ax4.set_xlabel("Model")
                    ax4.set_ylabel("Predicted Success Rate")
                    ax4.set_xticks(range(len(pred_names)))
                    ax4.set_xticklabels(pred_names, rotation=45, ha="right")
                    ax4.set_ylim(0, 1)

            plt.tight_layout()
            pdf.savefig(fig, bbox_inches="tight")
            plt.close()

        return str(report_path)

    def _calculate_daily_success_rates(self, events: list[AnalysisEvent]) -> dict[int, float]:
        """Calculate daily success rates.

        Args:
            events: Events to calculate daily success rates for.

        Returns:
            dict[int, float]: Daily success rates mapped by days ago.
        """
        daily_events = defaultdict(list)
        current_time = time.time()

        for event in events:
            days_ago = int((current_time - event.timestamp) / (24 * 3600))
            daily_events[days_ago].append(event)

        daily_success = {}
        for day, day_events in daily_events.items():
            if day_events:
                success_count = sum(e.outcome == OutcomeType.SUCCESS for e in day_events)
                daily_success[day] = success_count / len(day_events)

        return daily_success

    def _prepare_correlation_data(self, analyzer: "SuccessRateAnalyzer") -> np.ndarray | None:
        """Prepare correlation matrix data from actual time series.

        Args:
            analyzer: The SuccessRateAnalyzer instance.

        Returns:
            np.ndarray | None: Correlation matrix or None if unable to calculate.
        """
        try:
            component_stats = analyzer.get_component_statistics()
            if len(component_stats) < 2:
                return None

            # Get time series data for each component
            components = list(component_stats.keys())
            n = len(components)

            # Retrieve events for correlation analysis
            all_events = analyzer.event_tracker.get_events()

            # Create time-aligned success rate vectors for each component
            time_window = 3600  # 1 hour windows
            time_buckets: dict[int, dict[str, list[float]]] = {}

            for event in all_events:
                bucket = int(event.timestamp // time_window)
                if bucket not in time_buckets:
                    time_buckets[bucket] = {comp: [] for comp in components}

                if event.component in components:
                    success_value = 1.0 if event.outcome == OutcomeType.SUCCESS else 0.0
                    time_buckets[bucket][event.component].append(success_value)

            # Calculate average success rates per bucket
            aligned_data: dict[str, list[float]] = {comp: [] for comp in components}

            for bucket in sorted(time_buckets):
                for comp in components:
                    if time_buckets[bucket][comp]:
                        avg_rate = np.mean(time_buckets[bucket][comp])
                        aligned_data[comp].append(avg_rate)
                    # Use previous value or component average if no data
                    elif aligned_data[comp]:
                        aligned_data[comp].append(aligned_data[comp][-1])
                    else:
                        aligned_data[comp].append(component_stats[comp]["success_rate"])

            # Calculate correlation matrix
            if aligned_data[components[0]]:  # Ensure we have data
                data_matrix = np.array([aligned_data[comp] for comp in components])

                # Calculate Pearson correlation coefficients
                correlation_matrix = np.corrcoef(data_matrix)

                # Handle NaN values (in case of constant values)
                correlation_matrix = np.nan_to_num(correlation_matrix, nan=0.0)

                # Ensure diagonal is 1.0
                np.fill_diagonal(correlation_matrix, 1.0)

                return correlation_matrix
            # No time series data available, return identity matrix
            return np.eye(n)

        except Exception as e:
            logger.warning("Failed to calculate correlations: %s", e, exc_info=True)
            return None


class SuccessRateAnalyzer:
    """Run success rate analysis engine."""

    def __init__(self, db_path: str = "") -> None:
        """Initialize comprehensive success rate analyzer with all statistical components."""
        self.event_tracker = EventTracker(db_path or str(SUCCESS_RATES_DB))
        self.bayesian_analyzer = BayesianAnalyzer()
        self.survival_analyzer = SurvivalAnalyzer()
        self.time_series_analyzer = TimeSeriesAnalyzer()
        self.ml_predictor = MLPredictor()
        self.report_generator = ReportGenerator()

        # Cache for expensive computations
        self.cache: dict[str, StatisticalResult] = {}
        self.cache_expiry: dict[str, float] = {}
        self.cache_duration = 3600  # 1 hour cache

        # Start background tasks
        self.is_running = True
        self._start_background_tasks()

    def _start_background_tasks(self) -> None:
        """Start background analysis tasks."""
        def background_worker() -> None:
            while self.is_running:
                try:
                    # Update ML models every hour
                    recent_events = self.event_tracker.get_events(
                        start_time=time.time() - 7 * 24 * 3600,  # Last 7 days
                    )

                    if len(recent_events) > 100:
                        self.ml_predictor.train(recent_events)

                    # Clear expired cache
                    current_time = time.time()
                    expired_keys = [key for key, expiry in self.cache_expiry.items() if expiry < current_time]
                    for key in expired_keys:
                        self.cache.pop(key, None)
                        self.cache_expiry.pop(key, None)

                    time.sleep(3600)  # Run every hour

                except Exception as e:
                    logger.exception("Error in background analysis: %s", e)
                    time.sleep(600)  # Wait 10 minutes on error

        threading.Thread(target=background_worker, daemon=True).start()

    def log_event(
        self,
        event_type: EventType,
        outcome: OutcomeType,
        protection_category: ProtectionCategory,
        component: str,
        duration: float = 0.0,
        metadata: dict[str, Any] | None = None,
        error_details: str = "",
    ) -> None:
        """Log analysis event.

        Args:
            event_type: Type of event to log.
            outcome: Outcome of the event.
            protection_category: Protection category being analyzed.
            component: Component name.
            duration: Duration of the event in seconds (default 0.0).
            metadata: Additional metadata as dictionary (optional).
            error_details: Error details if applicable (default empty string).
        """
        event = AnalysisEvent(
            event_id="",  # Will be auto-generated
            event_type=event_type,
            outcome=outcome,
            protection_category=protection_category,
            component=component,
            timestamp=time.time(),
            duration=duration,
            metadata=metadata or {},
            error_details=error_details,
        )

        self.event_tracker.log_event(event)

        # Update time series
        success_rate = 1.0 if outcome == OutcomeType.SUCCESS else 0.0
        self.time_series_analyzer.add_data_point(component, event.timestamp, success_rate)

        # Update survival analysis for bypasses
        if event_type == EventType.BYPASS_ATTEMPT and duration > 0:
            censored = outcome == OutcomeType.SUCCESS  # Success means bypass is still working
            self.survival_analyzer.add_observation(duration, censored)

    def get_success_rate(
        self,
        component: str | None = None,
        protection_category: ProtectionCategory | None = None,
        time_window: int | None = None,
    ) -> StatisticalResult:
        """Get success rate with confidence interval."""
        cache_key = f"success_rate_{component}_{protection_category}_{time_window}"

        if cache_key in self.cache and self.cache_expiry.get(cache_key, 0) > time.time():
            return self.cache[cache_key]

        start_time: float | None = time.time() - time_window if time_window else None
        success_count, total_count = self.event_tracker.get_success_counts(
            component,
            protection_category,
            start_time,
        )

        if total_count == 0:
            result = StatisticalResult(
                metric_name="success_rate",
                value=0.0,
                confidence_interval=(0.0, 1.0),
                sample_size=0,
            )
        else:
            success_rate = success_count / total_count
            ci_lower, ci_upper = WilsonScoreInterval.calculate(success_count, total_count)

            result = StatisticalResult(
                metric_name="success_rate",
                value=success_rate,
                confidence_interval=(ci_lower, ci_upper),
                sample_size=total_count,
            )

        # Cache result
        self.cache[cache_key] = result
        self.cache_expiry[cache_key] = time.time() + self.cache_duration

        return result

    def get_bayesian_success_rate(
        self, component: str | None = None, protection_category: ProtectionCategory | None = None
    ) -> dict[str, Any]:
        """Get Bayesian success rate analysis."""
        success_count, total_count = self.event_tracker.get_success_counts(component, protection_category)
        failure_count = total_count - success_count

        posterior_mean = self.bayesian_analyzer.posterior_mean(success_count, failure_count)
        credible_interval = self.bayesian_analyzer.credible_interval(success_count, failure_count)

        # Calculate probability of success rate being above various thresholds
        prob_above_50 = self.bayesian_analyzer.posterior_probability(success_count, failure_count, 0.5)
        prob_above_80 = self.bayesian_analyzer.posterior_probability(success_count, failure_count, 0.8)
        prob_above_90 = self.bayesian_analyzer.posterior_probability(success_count, failure_count, 0.9)

        return {
            "posterior_mean": posterior_mean,
            "credible_interval": credible_interval,
            "probability_above_50_percent": prob_above_50,
            "probability_above_80_percent": prob_above_80,
            "probability_above_90_percent": prob_above_90,
            "sample_size": total_count,
        }

    def compare_success_rates(
        self, component1: str, component2: str, protection_category: ProtectionCategory | None = None
    ) -> dict[str, Any]:
        """Compare success rates between components."""
        success1, total1 = self.event_tracker.get_success_counts(component1, protection_category)
        success2, total2 = self.event_tracker.get_success_counts(component2, protection_category)

        if total1 == 0 or total2 == 0:
            return {"error": "Insufficient data for comparison"}

        # Fisher's exact test
        fisher_result = StatisticalTester.fishers_exact_test(success1, total1, success2, total2)

        # Effect size (Cohen's h for proportions)
        p1 = success1 / total1
        p2 = success2 / total2
        cohens_h = 2 * (np.arcsin(np.sqrt(p1)) - np.arcsin(np.sqrt(p2)))

        return {
            "component1": {
                "name": component1,
                "success_rate": p1,
                "sample_size": total1,
            },
            "component2": {
                "name": component2,
                "success_rate": p2,
                "sample_size": total2,
            },
            "statistical_test": fisher_result,
            "effect_size_cohens_h": cohens_h,
            "significant_difference": fisher_result["p_value"] < 0.05,
        }

    def get_trend_analysis(self, component: str, protection_category: ProtectionCategory | None = None) -> TrendAnalysis:
        """Get trend analysis for component."""
        trend_data = self.time_series_analyzer.detect_trend(component)
        forecasts, intervals = self.time_series_analyzer.forecast_arima(component)
        seasonal_data = self.time_series_analyzer.seasonal_decomposition(component)

        return TrendAnalysis(
            component=component,
            protection_category=protection_category or ProtectionCategory.CUSTOM,
            trend_direction=trend_data.get("trend", "unknown"),
            trend_strength=trend_data.get("strength", 0.0),
            forecast_values=forecasts,
            forecast_intervals=intervals,
            seasonal_pattern=seasonal_data.get("seasonal", False),
        )

    def get_component_statistics(self) -> dict[str, dict[str, Any]]:
        """Get statistics for all components."""
        # Get all unique components
        all_events = self.event_tracker.get_events()
        components = {event.component for event in all_events}

        stats = {}
        for component in components:
            success_rate_result = self.get_success_rate(component)
            bayesian_result = self.get_bayesian_success_rate(component)

            stats[component] = {
                "success_rate": success_rate_result.value,
                "confidence_interval": success_rate_result.confidence_interval,
                "sample_size": success_rate_result.sample_size,
                "bayesian_mean": bayesian_result["posterior_mean"],
                "credible_interval": bayesian_result["credible_interval"],
            }

        return stats

    def get_category_statistics(self) -> dict[str, dict[str, Any]]:
        """Get statistics for all protection categories."""
        stats = {}
        for category in ProtectionCategory:
            success_rate_result = self.get_success_rate(protection_category=category)

            if success_rate_result.sample_size > 0:
                stats[category.value] = {
                    "success_rate": success_rate_result.value,
                    "confidence_interval": success_rate_result.confidence_interval,
                    "sample_size": success_rate_result.sample_size,
                }

        return stats

    def generate_performance_dashboard(self) -> dict[str, Any]:
        """Generate real-time performance dashboard data."""
        current_time = time.time()

        # Recent performance (last 24 hours)
        recent_events = self.event_tracker.get_events(start_time=current_time - 24 * 3600)

        # Overall metrics
        total_events = len(recent_events)
        successful_events = sum(e.outcome == OutcomeType.SUCCESS for e in recent_events)
        overall_success_rate = successful_events / total_events if total_events > 0 else 0

        # Component breakdown
        component_performance = {}
        components = {event.component for event in recent_events}

        for component in components:
            component_events = [e for e in recent_events if e.component == component]
            component_successes = sum(e.outcome == OutcomeType.SUCCESS for e in component_events)

            component_performance[component] = {
                "events": len(component_events),
                "successes": component_successes,
                "success_rate": component_successes / len(component_events) if component_events else 0,
                "avg_duration": np.mean([e.duration for e in component_events if e.duration > 0]) if component_events else 0,
            }

        # Recent trends
        trend_analysis = {}
        for component in components:
            trend_data = self.time_series_analyzer.detect_trend(component)
            trend_analysis[component] = trend_data

        # ML predictions
        predictions = {}
        if self.ml_predictor.is_trained:
            predictions = self.ml_predictor.predict(recent_events)

        return {
            "timestamp": current_time,
            "overall_metrics": {
                "total_events_24h": total_events,
                "successful_events_24h": successful_events,
                "overall_success_rate_24h": overall_success_rate,
            },
            "component_performance": component_performance,
            "trend_analysis": trend_analysis,
            "ml_predictions": predictions,
            "survival_analysis": {
                "median_survival_time": self.survival_analyzer.median_survival_time(),
            },
        }

    def generate_comprehensive_report(self) -> str:
        """Generate comprehensive analysis report."""
        return self.report_generator.generate_comprehensive_report(self)

    def export_data(self, format: str = "json", include_raw_events: bool = False) -> str:
        """Export analysis data."""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

        if format == "json":
            output_file = f"intellicrack_analysis_{timestamp}.json"

            data: dict[str, Any] = {
                "export_timestamp": timestamp,
                "component_statistics": self.get_component_statistics(),
                "category_statistics": self.get_category_statistics(),
                "dashboard_data": self.generate_performance_dashboard(),
            }

            if include_raw_events:
                events = self.event_tracker.get_events()
                raw_events: list[dict[str, Any]] = [
                    {
                        "event_id": e.event_id,
                        "event_type": e.event_type.value,
                        "outcome": e.outcome.value,
                        "protection_category": e.protection_category.value,
                        "component": e.component,
                        "timestamp": e.timestamp,
                        "duration": e.duration,
                        "metadata": e.metadata,
                        "error_details": e.error_details,
                    }
                    for e in events
                ]
                data["raw_events"] = raw_events

            with open(output_file, "w") as f:
                json.dump(data, f, indent=2)

            return output_file

        if format == "csv":
            output_file = f"intellicrack_analysis_{timestamp}.csv"

            # Export component statistics as CSV
            component_stats = self.get_component_statistics()

            import csv

            with open(output_file, "w", newline="") as f:
                writer = csv.writer(f)
                writer.writerow(
                    [
                        "Component",
                        "Success Rate",
                        "Confidence Lower",
                        "Confidence Upper",
                        "Sample Size",
                    ],
                )

                for component, stats in component_stats.items():
                    writer.writerow(
                        [
                            component,
                            stats["success_rate"],
                            stats["confidence_interval"][0],
                            stats["confidence_interval"][1],
                            stats["sample_size"],
                        ],
                    )

            return output_file

        raise ValueError(f"Unsupported export format: {format}")

    def shutdown(self) -> None:
        """Shutdown analyzer."""
        self.is_running = False


# Global analyzer instance
_global_analyzer = None

P = ParamSpec("P")
R = TypeVar("R")


def get_success_rate_analyzer(db_path: str | None = None) -> SuccessRateAnalyzer:
    """Get global success rate analyzer instance."""
    global _global_analyzer

    if _global_analyzer is None:
        _global_analyzer = SuccessRateAnalyzer(db_path or str(SUCCESS_RATES_DB))

    return _global_analyzer


# Decorator for automatic success tracking
def track_success(
    event_type: EventType, protection_category: ProtectionCategory, component: str | None = None
) -> Callable[[Callable[P, R]], Callable[P, R]]:
    """Create decorator for automatic success/failure tracking."""

    def decorator(func: Callable[P, R]) -> Callable[P, R]:
        def wrapper(*args: P.args, **kwargs: P.kwargs) -> R:
            analyzer = get_success_rate_analyzer()
            start_time = time.time()
            func_component = component or func.__name__

            try:
                result = func(*args, **kwargs)
                duration = time.time() - start_time

                # Determine outcome based on result
                if isinstance(result, bool):
                    outcome = OutcomeType.SUCCESS if result else OutcomeType.FAILURE
                elif isinstance(result, dict) and "success" in result:
                    outcome = OutcomeType.SUCCESS if result["success"] else OutcomeType.FAILURE
                else:
                    outcome = OutcomeType.SUCCESS  # Assume success if no exception

                analyzer.log_event(
                    event_type=event_type,
                    outcome=outcome,
                    protection_category=protection_category,
                    component=func_component,
                    duration=duration,
                )

                return result

            except Exception as e:
                duration = time.time() - start_time
                analyzer.log_event(
                    event_type=event_type,
                    outcome=OutcomeType.ERROR,
                    protection_category=protection_category,
                    component=func_component,
                    duration=duration,
                    error_details=str(e),
                )
                raise

        return wrapper

    return decorator


if __name__ == "__main__":
    # Production usage - analyze real Intellicrack events
    logging.basicConfig(level=logging.INFO)

    analyzer = SuccessRateAnalyzer()

    # Connect to existing Intellicrack database or create new one
    logger.info("Initializing Success Rate Analysis System...")

    # Import actual Intellicrack components for real-time tracking
    from intellicrack.core.analysis.protection_detector import ProtectionDetector
    from intellicrack.core.exploitation.bypass_manager import BypassManager
    from intellicrack.plugins.custom_modules.hardware_dongle_emulator import HardwareDongleEmulator

    # Hook into real component events for live tracking
    def register_component_hooks() -> dict[str, Callable[..., bool]]:
        """Register success tracking hooks with Intellicrack components."""

        # Track protection detection events
        @track_success(EventType.PROTECTION_DETECTION, ProtectionCategory.SERIAL_KEY, "protection_detector")
        def detect_serial_protection(binary_path: str) -> bool:
            try:
                detector = ProtectionDetector()
                result = detector.analyze_binary(binary_path)
                serial_found = result.get("serial_protection_found", False)
                return bool(serial_found)
            except Exception:
                return False

        # Track bypass attempts
        @track_success(EventType.BYPASS_ATTEMPT, ProtectionCategory.VM_PROTECTION, "bypass_manager")
        def bypass_vm_protection(target_process: str) -> bool:
            try:
                manager = BypassManager()
                result = manager.bypass_protection(target_process, "vm_protection")
                bypass_successful = result.get("bypass_successful", False)
                return bool(bypass_successful)
            except Exception:
                return False

        # Track hardware emulation
        @track_success(EventType.EMULATION, ProtectionCategory.DONGLE, "dongle_emulator")
        def emulate_hardware_dongle(dongle_type: str) -> bool:
            try:
                emulator = HardwareDongleEmulator()
                result = emulator.emulate_dongle(dongle_type)
                emulation_active = result.get("emulation_active", False)
                return bool(emulation_active)
            except Exception:
                return False

        return {
            "detect_serial_protection": detect_serial_protection,
            "bypass_vm_protection": bypass_vm_protection,
            "emulate_hardware_dongle": emulate_hardware_dongle,
        }

    # Load historical events from existing database if available
    logger.info("Loading historical analysis data...")
    historical_events = analyzer.event_tracker.get_events()

    if historical_events:
        logger.info("Found %s historical events in database", len(historical_events))

        # Train ML models on historical data
        if len(historical_events) > 100:
            logger.info("Training machine learning models on historical data...")
            analyzer.ml_predictor.train(historical_events)
            logger.info("ML models trained successfully")
    else:
        logger.info("No historical data found. Starting fresh tracking...")

    # Perform real analysis on actual data
    logger.info("Performing real-time analysis...")

    # Overall success rates
    overall_stats = analyzer.get_component_statistics()
    components = list(overall_stats.keys())
    logger.info("Component Statistics:")
    for component, stats in overall_stats.items():
        logger.info(
            "  %s: %.3f (%.3f-%.3f) n=%s",
            component,
            stats["success_rate"],
            stats["confidence_interval"][0],
            stats["confidence_interval"][1],
            stats["sample_size"],
        )

    # Bayesian analysis
    logger.info("Bayesian Analysis:")
    for component in components:
        bayesian_result = analyzer.get_bayesian_success_rate(component)
        logger.info(
            "  %s: posterior=%.3f, P(>50%%)=%.3f",
            component,
            bayesian_result["posterior_mean"],
            bayesian_result["probability_above_50_percent"],
        )

    # Component comparison
    logger.info("Component Comparison:")
    comparison = analyzer.compare_success_rates(components[0], components[1])
    if "error" not in comparison:
        logger.info("  %s vs %s", comparison["component1"]["name"], comparison["component2"]["name"])
        logger.info("  Success rates: %.3f vs %.3f", comparison["component1"]["success_rate"], comparison["component2"]["success_rate"])
        logger.info("  Significant difference: %s", comparison["significant_difference"])
        logger.info("  p-value: %.4f", comparison["statistical_test"]["p_value"])

    # Trend analysis
    logger.info("Trend Analysis:")
    for component in components:
        trend = analyzer.get_trend_analysis(component)
        logger.info("  %s: %s (strength: %.3f)", component, trend.trend_direction, trend.trend_strength)

    # Dashboard data
    logger.info("Dashboard Summary:")
    dashboard = analyzer.generate_performance_dashboard()
    logger.info("  Total events (24h): %s", dashboard["overall_metrics"]["total_events_24h"])
    logger.info("  Overall success rate (24h): %.3f", dashboard["overall_metrics"]["overall_success_rate_24h"])

    # Generate report
    logg
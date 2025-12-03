"""Comprehensive tests for BypassStrategySelector.

Tests REAL strategy selection logic for certificate bypass operations.
All tests validate intelligent decision-making for real protection scenarios.
"""

import logging
from unittest.mock import Mock

import pytest

from intellicrack.core.certificate.bypass_strategy import BypassStrategySelector
from intellicrack.core.certificate.detection_report import (
    BypassMethod,
    DetectionReport,
    ValidationFunction,
)


logger = logging.getLogger(__name__)


@pytest.fixture
def simple_detection_report() -> DetectionReport:
    """Create detection report with simple validation."""
    return DetectionReport(
        binary_path="simple.exe",
        detected_libraries=["openssl"],
        validation_functions=[
            ValidationFunction(
                api_name="SSL_CTX_set_verify",
                library="libssl.dll",
                address=0x140001000,
                confidence=0.95,
                references=[0x140002000],
                context="certificate validation",
            ),
        ],
        recommended_method=BypassMethod.BINARY_PATCH,
        risk_level="low",
    )


@pytest.fixture
def complex_detection_report() -> DetectionReport:
    """Create detection report with complex multi-library validation."""
    return DetectionReport(
        binary_path="complex.exe",
        detected_libraries=["openssl", "cryptoapi", "boringssl"],
        validation_functions=[
            ValidationFunction(
                api_name="SSL_CTX_set_verify",
                library="libssl.dll",
                address=0x140001000,
                confidence=0.92,
                references=[0x140002000, 0x140003000, 0x140004000],
                context="certificate validation",
            ),
            ValidationFunction(
                api_name="SSL_CTX_set_cert_verify_callback",
                library="libssl.dll",
                address=0x140005000,
                confidence=0.88,
                references=[0x140006000, 0x140007000],
                context="callback registration",
            ),
            ValidationFunction(
                api_name="CertVerifyCertificateChainPolicy",
                library="crypt32.dll",
                address=0x140008000,
                confidence=0.85,
                references=[0x140009000, 0x14000A000, 0x14000B000, 0x14000C000],
                context="chain validation",
            ),
            ValidationFunction(
                api_name="BR_ssl_client_init_full",
                library="boringssl.dll",
                address=0x14000D000,
                confidence=0.80,
                references=[0x14000E000],
                context="ssl initialization",
            ),
        ],
        recommended_method=BypassMethod.HYBRID,
        risk_level="high",
    )


@pytest.fixture
def packed_binary_report() -> DetectionReport:
    """Create detection report for packed binary."""
    report = DetectionReport(
        binary_path="packed.exe",
        detected_libraries=["openssl"],
        validation_functions=[
            ValidationFunction(
                api_name="SSL_CTX_set_verify",
                library="libssl.dll",
                address=0x140001000,
                confidence=0.45,
                references=[],
                context="",
            ),
        ],
        recommended_method=BypassMethod.FRIDA_HOOK,
        risk_level="medium",
    )
    report.is_packed = True
    return report


@pytest.fixture
def network_licensing_report() -> DetectionReport:
    """Create detection report for network-based licensing."""
    return DetectionReport(
        binary_path="network.exe",
        detected_libraries=["winhttp", "openssl"],
        validation_functions=[
            ValidationFunction(
                api_name="WinHttpSendRequest",
                library="winhttp.dll",
                address=0x140001000,
                confidence=0.88,
                references=[0x140002000],
                context="https://licensing.example.com/validate",
            ),
            ValidationFunction(
                api_name="SSL_CTX_set_verify",
                library="libssl.dll",
                address=0x140003000,
                confidence=0.85,
                references=[0x140004000],
                context="server validation callback",
            ),
        ],
        recommended_method=BypassMethod.MITM_PROXY,
        risk_level="medium",
    )


class TestStrategySelectorInitialization:
    """Test strategy selector initialization."""

    def test_selector_initializes(self) -> None:
        """Selector must initialize without dependencies."""
        selector = BypassStrategySelector()

        assert selector is not None


class TestStaticTargetStrategySelection:
    """Test strategy selection for static (non-running) targets."""

    def test_select_binary_patch_for_simple_static_target(
        self,
        simple_detection_report: DetectionReport,
    ) -> None:
        """Simple static target must use binary patch."""
        selector = BypassStrategySelector()

        method = selector.select_optimal_strategy(
            simple_detection_report,
            target_state="static",
        )

        assert method == BypassMethod.BINARY_PATCH

    def test_select_hybrid_for_complex_static_target(
        self,
        complex_detection_report: DetectionReport,
    ) -> None:
        """Complex static target with multiple libraries must use hybrid."""
        selector = BypassStrategySelector()

        method = selector.select_optimal_strategy(
            complex_detection_report,
            target_state="static",
        )

        assert method == BypassMethod.HYBRID

    def test_select_frida_for_packed_binary(
        self,
        packed_binary_report: DetectionReport,
    ) -> None:
        """Packed binary must prefer Frida hook to avoid unpacking."""
        selector = BypassStrategySelector()

        method = selector.select_optimal_strategy(
            packed_binary_report,
            target_state="static",
        )

        assert method == BypassMethod.FRIDA_HOOK

    def test_select_hybrid_for_high_risk_static(self) -> None:
        """High-risk static target must use hybrid approach."""
        report = DetectionReport(
            binary_path="highrisk.exe",
            detected_libraries=["openssl"],
            validation_functions=[
                ValidationFunction(
                    api_name="SSL_CTX_set_verify",
                    library="libssl.dll",
                    address=0x140001000,
                    confidence=0.92,
                    references=[0x140002000] * 20,
                    context="critical system validation",
                ),
            ],
            recommended_method=BypassMethod.HYBRID,
            risk_level="high",
        )

        selector = BypassStrategySelector()

        method = selector.select_optimal_strategy(report, target_state="static")

        assert method == BypassMethod.HYBRID


class TestRunningTargetStrategySelection:
    """Test strategy selection for running targets."""

    def test_select_frida_for_running_target(
        self,
        simple_detection_report: DetectionReport,
    ) -> None:
        """Running target must prefer Frida hook for runtime patching."""
        selector = BypassStrategySelector()

        method = selector.select_optimal_strategy(
            simple_detection_report,
            target_state="running",
        )

        assert method == BypassMethod.FRIDA_HOOK

    def test_select_hybrid_for_complex_running_target(
        self,
        complex_detection_report: DetectionReport,
    ) -> None:
        """Complex running target with multiple libraries must use hybrid."""
        selector = BypassStrategySelector()

        method = selector.select_optimal_strategy(
            complex_detection_report,
            target_state="running",
        )

        assert method == BypassMethod.HYBRID

    def test_select_mitm_for_network_licensing(
        self,
        network_licensing_report: DetectionReport,
    ) -> None:
        """Network-based licensing must use MITM proxy."""
        selector = BypassStrategySelector()

        method = selector.select_optimal_strategy(
            network_licensing_report,
            target_state="running",
        )

        assert method == BypassMethod.MITM_PROXY


class TestPackedBinaryDetection:
    """Test packed binary detection logic."""

    def test_detect_packed_from_low_confidence(self) -> None:
        """Low confidence functions indicate packed binary."""
        report = DetectionReport(
            binary_path="packed.exe",
            detected_libraries=["openssl"],
            validation_functions=[
                ValidationFunction(
                    api_name="SSL_CTX_set_verify",
                    library="libssl.dll",
                    address=0x140001000,
                    confidence=0.35,
                    references=[],
                    context="",
                ),
                ValidationFunction(
                    api_name="SSL_CTX_new",
                    library="libssl.dll",
                    address=0x140002000,
                    confidence=0.40,
                    references=[],
                    context="",
                ),
            ],
            recommended_method=BypassMethod.FRIDA_HOOK,
            risk_level="medium",
        )

        selector = BypassStrategySelector()

        is_packed = selector._is_packed_binary(report)

        assert is_packed

    def test_detect_packed_from_attribute(self) -> None:
        """Must detect packed binary from is_packed attribute."""
        report = DetectionReport(
            binary_path="packed.exe",
            detected_libraries=["openssl"],
            validation_functions=[],
            recommended_method=BypassMethod.FRIDA_HOOK,
            risk_level="medium",
        )
        report.is_packed = True

        selector = BypassStrategySelector()

        is_packed = selector._is_packed_binary(report)

        assert is_packed


class TestNetworkLicensingDetection:
    """Test network-based licensing detection."""

    def test_detect_network_licensing_from_winhttp(self) -> None:
        """Must detect network licensing from WinHTTP functions."""
        report = DetectionReport(
            binary_path="network.exe",
            detected_libraries=["winhttp"],
            validation_functions=[
                ValidationFunction(
                    api_name="WinHttpOpenRequest",
                    library="winhttp.dll",
                    address=0x140001000,
                    confidence=0.85,
                    references=[0x140002000],
                    context="https://activation.server.com",
                ),
            ],
            recommended_method=BypassMethod.MITM_PROXY,
            risk_level="medium",
        )

        selector = BypassStrategySelector()

        is_network = selector._is_network_based_licensing(report)

        assert is_network

    def test_detect_network_licensing_from_context(self) -> None:
        """Must detect network licensing from context keywords."""
        report = DetectionReport(
            binary_path="network.exe",
            detected_libraries=["openssl"],
            validation_functions=[
                ValidationFunction(
                    api_name="SSL_CTX_set_verify",
                    library="libssl.dll",
                    address=0x140001000,
                    confidence=0.88,
                    references=[0x140002000],
                    context="online activation server validation",
                ),
            ],
            recommended_method=BypassMethod.MITM_PROXY,
            risk_level="medium",
        )

        selector = BypassStrategySelector()

        is_network = selector._is_network_based_licensing(report)

        assert is_network


class TestRiskAssessment:
    """Test risk assessment logic."""

    def test_assess_low_risk_for_simple_validation(
        self,
        simple_detection_report: DetectionReport,
    ) -> None:
        """Simple validation with few references is low risk."""
        selector = BypassStrategySelector()

        risk = selector.assess_patch_risk(simple_detection_report)

        assert risk == "low"

    def test_assess_high_risk_for_many_references(self) -> None:
        """Many cross-references indicate high risk."""
        report = DetectionReport(
            binary_path="highrisk.exe",
            detected_libraries=["openssl"],
            validation_functions=[
                ValidationFunction(
                    api_name="SSL_CTX_set_verify",
                    library="libssl.dll",
                    address=0x140001000,
                    confidence=0.92,
                    references=[0x140002000 + i for i in range(20)],
                    context="certificate validation",
                ),
            ],
            recommended_method=BypassMethod.HYBRID,
            risk_level="high",
        )

        selector = BypassStrategySelector()

        risk = selector.assess_patch_risk(report)

        assert risk == "high"

    def test_assess_high_risk_for_critical_context(self) -> None:
        """Critical context keywords indicate high risk."""
        report = DetectionReport(
            binary_path="critical.exe",
            detected_libraries=["openssl"],
            validation_functions=[
                ValidationFunction(
                    api_name="SSL_CTX_set_verify",
                    library="libssl.dll",
                    address=0x140001000,
                    confidence=0.92,
                    references=[0x140002000],
                    context="critical security validation in exception handler",
                ),
            ],
            recommended_method=BypassMethod.FRIDA_HOOK,
            risk_level="high",
        )

        selector = BypassStrategySelector()

        risk = selector.assess_patch_risk(report)

        assert risk == "high"

    def test_assess_medium_risk_for_moderate_complexity(self) -> None:
        """Moderate complexity indicates medium risk."""
        report = DetectionReport(
            binary_path="medium.exe",
            detected_libraries=["openssl"],
            validation_functions=[
                ValidationFunction(
                    api_name="SSL_CTX_set_verify",
                    library="libssl.dll",
                    address=0x140001000,
                    confidence=0.88,
                    references=[0x140002000 + i for i in range(10)],
                    context="certificate validation",
                ),
            ],
            recommended_method=BypassMethod.BINARY_PATCH,
            risk_level="medium",
        )

        selector = BypassStrategySelector()

        risk = selector.assess_patch_risk(report)

        assert risk == "medium"

    def test_assess_high_risk_for_many_functions(self) -> None:
        """Many validation functions indicate high risk."""
        functions = [
            ValidationFunction(
                api_name=f"function_{i}",
                library="libssl.dll",
                address=0x140001000 + i * 0x1000,
                confidence=0.85,
                references=[],
                context="",
            )
            for i in range(12)
        ]

        report = DetectionReport(
            binary_path="many.exe",
            detected_libraries=["openssl"],
            validation_functions=functions,
            recommended_method=BypassMethod.HYBRID,
            risk_level="high",
        )

        selector = BypassStrategySelector()

        risk = selector.assess_patch_risk(report)

        assert risk == "high"


class TestFallbackStrategy:
    """Test fallback strategy selection."""

    def test_fallback_from_binary_patch_to_frida(self) -> None:
        """Binary patch failure must fallback to Frida hook."""
        selector = BypassStrategySelector()

        fallback = selector.get_fallback_strategy(BypassMethod.BINARY_PATCH)

        assert fallback == BypassMethod.FRIDA_HOOK

    def test_fallback_from_frida_to_mitm(self) -> None:
        """Frida hook failure must fallback to MITM proxy."""
        selector = BypassStrategySelector()

        fallback = selector.get_fallback_strategy(BypassMethod.FRIDA_HOOK)

        assert fallback == BypassMethod.MITM_PROXY

    def test_fallback_from_mitm_is_none(self) -> None:
        """MITM proxy has no fallback option."""
        selector = BypassStrategySelector()

        fallback = selector.get_fallback_strategy(BypassMethod.MITM_PROXY)

        assert fallback is None

    def test_fallback_from_hybrid_to_frida(self) -> None:
        """Hybrid failure must fallback to Frida hook."""
        selector = BypassStrategySelector()

        fallback = selector.get_fallback_strategy(BypassMethod.HYBRID)

        assert fallback == BypassMethod.FRIDA_HOOK


class TestEdgeCases:
    """Test edge cases and boundary conditions."""

    def test_strategy_for_no_validation_functions(self) -> None:
        """No validation functions must return NONE method."""
        report = DetectionReport(
            binary_path="empty.exe",
            detected_libraries=[],
            validation_functions=[],
            recommended_method=BypassMethod.NONE,
            risk_level="low",
        )

        selector = BypassStrategySelector()

        method = selector.select_optimal_strategy(report, target_state="static")

        assert method == BypassMethod.NONE

    def test_risk_assessment_for_no_validation_functions(self) -> None:
        """No validation functions must be low risk."""
        report = DetectionReport(
            binary_path="empty.exe",
            detected_libraries=[],
            validation_functions=[],
            recommended_method=BypassMethod.NONE,
            risk_level="low",
        )

        selector = BypassStrategySelector()

        risk = selector.assess_patch_risk(report)

        assert risk == "low"

    def test_strategy_selection_with_exact_threshold_values(self) -> None:
        """Strategy selection must handle exact threshold values correctly."""
        report = DetectionReport(
            binary_path="threshold.exe",
            detected_libraries=["openssl"],
            validation_functions=[
                ValidationFunction(
                    api_name="SSL_CTX_set_verify",
                    library="libssl.dll",
                    address=0x140001000,
                    confidence=0.80,
                    references=[],
                    context="",
                ),
                ValidationFunction(
                    api_name="SSL_CTX_new",
                    library="libssl.dll",
                    address=0x140002000,
                    confidence=0.80,
                    references=[],
                    context="",
                ),
                ValidationFunction(
                    api_name="SSL_connect",
                    library="libssl.dll",
                    address=0x140003000,
                    confidence=0.80,
                    references=[],
                    context="",
                ),
            ],
            recommended_method=BypassMethod.BINARY_PATCH,
            risk_level="low",
        )

        selector = BypassStrategySelector()

        method = selector.select_optimal_strategy(report, target_state="static")

        assert method in [BypassMethod.BINARY_PATCH, BypassMethod.HYBRID]


class TestStrategySelectionConsistency:
    """Test strategy selection consistency and predictability."""

    def test_same_input_produces_same_output(
        self,
        simple_detection_report: DetectionReport,
    ) -> None:
        """Same detection report must produce same strategy."""
        selector = BypassStrategySelector()

        method1 = selector.select_optimal_strategy(simple_detection_report, "static")
        method2 = selector.select_optimal_strategy(simple_detection_report, "static")

        assert method1 == method2

    def test_different_states_produce_different_strategies(
        self,
        simple_detection_report: DetectionReport,
    ) -> None:
        """Static vs running target should potentially use different strategies."""
        selector = BypassStrategySelector()

        static_method = selector.select_optimal_strategy(
            simple_detection_report,
            "static",
        )
        running_method = selector.select_optimal_strategy(
            simple_detection_report,
            "running",
        )

        assert static_method == BypassMethod.BINARY_PATCH
        assert running_method == BypassMethod.FRIDA_HOOK

"""Production tests for bypass strategy selection validating real decision logic.

Tests verify that BypassStrategySelector makes correct strategic decisions based on
real detection data and properly handles fallback chains, risk assessment, and
target state awareness.
"""

import pytest

from intellicrack.core.certificate.bypass_strategy import BypassStrategySelector
from intellicrack.core.certificate.detection_report import (
    BypassMethod,
    DetectionReport,
    ValidationFunction,
)


class TestBypassStrategyProductionDecisions:
    """Tests that validate real strategy selection logic against actual scenarios."""

    def test_static_simple_validation_selects_binary_patch(self) -> None:
        """Simple validation on static binary selects BINARY_PATCH method."""
        funcs = [
            ValidationFunction(
                address=0x401000,
                api_name="CertVerifyCertificateChainPolicy",
                library="crypt32.dll",
                confidence=0.95,
                context="Simple validation in licensing check",
                references=[0x402000],
            ),
        ]

        report = DetectionReport(
            binary_path="simple_app.exe",
            detected_libraries=["crypt32.dll"],
            validation_functions=funcs,
            recommended_method=BypassMethod.NONE,
            risk_level="low",
        )

        selector = BypassStrategySelector()
        method = selector.select_optimal_strategy(report, target_state="static")

        assert method == BypassMethod.BINARY_PATCH
        assert selector.assess_patch_risk(report) == "low"

    def test_running_process_prefers_frida_hook(self) -> None:
        """Running process targets prefer FRIDA_HOOK over binary patching."""
        funcs = [
            ValidationFunction(
                address=0x401000,
                api_name="SSL_CTX_set_verify",
                library="libssl.so.1.1",
                confidence=0.85,
                context="OpenSSL verification callback",
                references=[0x402000, 0x403000],
            ),
        ]

        report = DetectionReport(
            binary_path="/usr/bin/protected_app",
            detected_libraries=["libssl.so.1.1"],
            validation_functions=funcs,
            recommended_method=BypassMethod.NONE,
            risk_level="medium",
        )

        selector = BypassStrategySelector()
        method = selector.select_optimal_strategy(report, target_state="running")

        assert method == BypassMethod.FRIDA_HOOK

    def test_complex_multilayer_validation_selects_hybrid(self) -> None:
        """Complex validation with multiple TLS libraries selects HYBRID approach."""
        funcs = [
            ValidationFunction(
                address=0x401000,
                api_name="CertVerifyCertificateChainPolicy",
                library="crypt32.dll",
                confidence=0.88,
                context="Windows CryptoAPI validation",
                references=[0x402000],
            ),
            ValidationFunction(
                address=0x405000,
                api_name="SSL_CTX_set_verify",
                library="libssl-1_1.dll",
                confidence=0.92,
                context="OpenSSL verification",
                references=[0x406000, 0x407000],
            ),
            ValidationFunction(
                address=0x410000,
                api_name="NSS_Init",
                library="nss3.dll",
                confidence=0.79,
                context="NSS library initialization",
                references=[0x411000],
            ),
            ValidationFunction(
                address=0x415000,
                api_name="CERT_VerifyCertName",
                library="nss3.dll",
                confidence=0.81,
                context="NSS certificate name validation",
                references=[0x416000, 0x417000, 0x418000],
            ),
        ]

        report = DetectionReport(
            binary_path="complex_app.exe",
            detected_libraries=["crypt32.dll", "libssl-1_1.dll", "nss3.dll"],
            validation_functions=funcs,
            recommended_method=BypassMethod.NONE,
            risk_level="medium",
        )

        selector = BypassStrategySelector()
        method = selector.select_optimal_strategy(report, target_state="static")

        assert method == BypassMethod.HYBRID

    def test_packed_binary_detection_forces_frida_hook(self) -> None:
        """Packed binaries with low confidence detections force FRIDA_HOOK."""
        funcs = [
            ValidationFunction(
                address=0x401000,
                api_name="unknown_func_1",
                library="unknown.dll",
                confidence=0.35,
                context="Obfuscated code section",
                references=[],
            ),
            ValidationFunction(
                address=0x402000,
                api_name="unknown_func_2",
                library="unknown.dll",
                confidence=0.42,
                context="Packed section",
                references=[],
            ),
            ValidationFunction(
                address=0x403000,
                api_name="unknown_func_3",
                library="unknown.dll",
                confidence=0.28,
                context="Encrypted code",
                references=[],
            ),
        ]

        report = DetectionReport(
            binary_path="packed_app.exe",
            detected_libraries=["unknown.dll"],
            validation_functions=funcs,
            recommended_method=BypassMethod.NONE,
            risk_level="high",
        )

        selector = BypassStrategySelector()
        method = selector.select_optimal_strategy(report, target_state="static")

        assert method == BypassMethod.FRIDA_HOOK

    def test_network_licensing_selects_mitm_proxy(self) -> None:
        """Network-based licensing detection triggers MITM_PROXY strategy."""
        funcs = [
            ValidationFunction(
                address=0x401000,
                api_name="WinHttpSetOption",
                library="winhttp.dll",
                confidence=0.91,
                context="HTTPS activation server connection",
                references=[0x402000, 0x403000],
            ),
            ValidationFunction(
                address=0x405000,
                api_name="WinHttpSendRequest",
                library="winhttp.dll",
                confidence=0.94,
                context="Online license validation request",
                references=[0x406000],
            ),
        ]

        report = DetectionReport(
            binary_path="online_app.exe",
            detected_libraries=["winhttp.dll"],
            validation_functions=funcs,
            recommended_method=BypassMethod.NONE,
            risk_level="medium",
        )

        selector = BypassStrategySelector()
        method = selector.select_optimal_strategy(report, target_state="running")

        assert method == BypassMethod.MITM_PROXY

    def test_high_risk_validation_avoids_binary_patch(self) -> None:
        """High-risk validation functions avoid destructive binary patching."""
        funcs = [
            ValidationFunction(
                address=0x401000,
                api_name="CertVerifyCertificateChainPolicy",
                library="crypt32.dll",
                confidence=0.89,
                context="Critical security validation in exception handler",
                references=[0x402000 + i for i in range(20)],
            ),
        ]

        report = DetectionReport(
            binary_path="critical_app.exe",
            detected_libraries=["crypt32.dll"],
            validation_functions=funcs,
            recommended_method=BypassMethod.NONE,
            risk_level="high",
        )

        selector = BypassStrategySelector()
        method = selector.select_optimal_strategy(report, target_state="static")
        risk = selector.assess_patch_risk(report)

        assert method != BypassMethod.BINARY_PATCH
        assert risk == "high"

    def test_no_validation_detected_returns_none(self) -> None:
        """No detected validation functions returns NONE method."""
        report = DetectionReport(
            binary_path="no_validation.exe",
            detected_libraries=[],
            validation_functions=[],
            recommended_method=BypassMethod.NONE,
            risk_level="low",
        )

        selector = BypassStrategySelector()
        method = selector.select_optimal_strategy(report, target_state="static")

        assert method == BypassMethod.NONE


class TestFallbackStrategyChain:
    """Tests validating fallback strategy chain logic."""

    def test_fallback_chain_binary_to_frida(self) -> None:
        """BINARY_PATCH failure falls back to FRIDA_HOOK."""
        selector = BypassStrategySelector()
        fallback = selector.get_fallback_strategy(BypassMethod.BINARY_PATCH)

        assert fallback == BypassMethod.FRIDA_HOOK

    def test_fallback_chain_frida_to_mitm(self) -> None:
        """FRIDA_HOOK failure falls back to MITM_PROXY."""
        selector = BypassStrategySelector()
        fallback = selector.get_fallback_strategy(BypassMethod.FRIDA_HOOK)

        assert fallback == BypassMethod.MITM_PROXY

    def test_fallback_chain_hybrid_to_frida(self) -> None:
        """HYBRID failure falls back to FRIDA_HOOK."""
        selector = BypassStrategySelector()
        fallback = selector.get_fallback_strategy(BypassMethod.HYBRID)

        assert fallback == BypassMethod.FRIDA_HOOK

    def test_fallback_chain_mitm_exhausted(self) -> None:
        """MITM_PROXY failure has no fallback (returns None)."""
        selector = BypassStrategySelector()
        fallback = selector.get_fallback_strategy(BypassMethod.MITM_PROXY)

        assert fallback is None

    def test_fallback_chain_none_exhausted(self) -> None:
        """NONE method has no fallback."""
        selector = BypassStrategySelector()
        fallback = selector.get_fallback_strategy(BypassMethod.NONE)

        assert fallback is None

    def test_complete_fallback_chain_validation(self) -> None:
        """Validates complete fallback chain: BINARY -> FRIDA -> MITM -> None."""
        selector = BypassStrategySelector()

        current_method: BypassMethod | None = BypassMethod.BINARY_PATCH
        fallback_chain: list[BypassMethod | None] = [current_method]

        while current_method is not None:
            current_method = selector.get_fallback_strategy(current_method)
            fallback_chain.append(current_method)

        expected_chain: list[BypassMethod | None] = [
            BypassMethod.BINARY_PATCH,
            BypassMethod.FRIDA_HOOK,
            BypassMethod.MITM_PROXY,
            None,
        ]

        assert fallback_chain == expected_chain


class TestRiskAssessmentLogic:
    """Tests validating risk assessment calculations."""

    def test_low_risk_single_function_few_references(self) -> None:
        """Single function with few cross-references assessed as low risk."""
        funcs = [
            ValidationFunction(
                address=0x401000,
                api_name="CertVerifyCertificateChainPolicy",
                library="crypt32.dll",
                confidence=0.92,
                context="Standalone validation function",
                references=[0x402000, 0x403000],
            ),
        ]

        report = DetectionReport(
            binary_path="app.exe",
            detected_libraries=["crypt32.dll"],
            validation_functions=funcs,
            recommended_method=BypassMethod.NONE,
            risk_level="low",
        )

        selector = BypassStrategySelector()
        risk = selector.assess_patch_risk(report)

        assert risk == "low"

    def test_medium_risk_moderate_references(self) -> None:
        """Functions with moderate cross-references assessed as medium risk."""
        funcs = [
            ValidationFunction(
                address=0x401000,
                api_name="SSL_CTX_set_verify",
                library="libssl.so",
                confidence=0.88,
                context="SSL context verification",
                references=[0x402000 + i * 0x100 for i in range(10)],
            ),
        ]

        report = DetectionReport(
            binary_path="app",
            detected_libraries=["libssl.so"],
            validation_functions=funcs,
            recommended_method=BypassMethod.NONE,
            risk_level="medium",
        )

        selector = BypassStrategySelector()
        risk = selector.assess_patch_risk(report)

        assert risk == "medium"

    def test_high_risk_many_references(self) -> None:
        """Functions with many cross-references assessed as high risk."""
        funcs = [
            ValidationFunction(
                address=0x401000,
                api_name="ValidateLicenseCertificate",
                library="app.exe",
                confidence=0.76,
                context="Core licensing function",
                references=[0x500000 + i * 0x50 for i in range(20)],
            ),
        ]

        report = DetectionReport(
            binary_path="app.exe",
            detected_libraries=["app.exe"],
            validation_functions=funcs,
            recommended_method=BypassMethod.NONE,
            risk_level="high",
        )

        selector = BypassStrategySelector()
        risk = selector.assess_patch_risk(report)

        assert risk == "high"

    def test_high_risk_critical_context_keywords(self) -> None:
        """Functions in critical contexts assessed as high risk."""
        critical_contexts = [
            "kernel mode validation",
            "system security check",
            "critical initialization",
            "exception handler validation",
        ]

        for context in critical_contexts:
            funcs = [
                ValidationFunction(
                    address=0x401000,
                    api_name="ValidateSecurityPolicy",
                    library="kernel32.dll",
                    confidence=0.85,
                    context=context,
                    references=[0x402000],
                ),
            ]

            report = DetectionReport(
                binary_path="driver.sys",
                detected_libraries=["kernel32.dll"],
                validation_functions=funcs,
                recommended_method=BypassMethod.NONE,
                risk_level="high",
            )

            selector = BypassStrategySelector()
            risk = selector.assess_patch_risk(report)

            assert risk == "high", f"Context '{context}' should be high risk"

    def test_high_risk_many_validation_functions(self) -> None:
        """Many validation functions (>10) assessed as high risk."""
        funcs = [
            ValidationFunction(
                address=0x401000 + i * 0x1000,
                api_name=f"ValidateFunc_{i}",
                library="app.dll",
                confidence=0.75,
                context=f"Validation point {i}",
                references=[0x500000 + i],
            )
            for i in range(12)
        ]

        report = DetectionReport(
            binary_path="complex_app.exe",
            detected_libraries=["app.dll"],
            validation_functions=funcs,
            recommended_method=BypassMethod.NONE,
            risk_level="high",
        )

        selector = BypassStrategySelector()
        risk = selector.assess_patch_risk(report)

        assert risk == "high"

    def test_medium_risk_several_validation_functions(self) -> None:
        """Several validation functions (6-10) assessed as medium risk."""
        funcs = [
            ValidationFunction(
                address=0x401000 + i * 0x1000,
                api_name=f"ValidateFunc_{i}",
                library="app.dll",
                confidence=0.80,
                context=f"Validation point {i}",
                references=[0x500000 + i],
            )
            for i in range(7)
        ]

        report = DetectionReport(
            binary_path="app.exe",
            detected_libraries=["app.dll"],
            validation_functions=funcs,
            recommended_method=BypassMethod.NONE,
            risk_level="medium",
        )

        selector = BypassStrategySelector()
        risk = selector.assess_patch_risk(report)

        assert risk == "medium"


class TestNetworkLicensingDetection:
    """Tests validating network-based licensing detection."""

    def test_winhttp_functions_detected_as_network(self) -> None:
        """WinHTTP functions indicate network-based licensing."""
        funcs = [
            ValidationFunction(
                address=0x401000,
                api_name="WinHttpSetOption",
                library="winhttp.dll",
                confidence=0.93,
                context="HTTP client configuration",
                references=[0x402000],
            ),
        ]

        report = DetectionReport(
            binary_path="app.exe",
            detected_libraries=["winhttp.dll"],
            validation_functions=funcs,
            recommended_method=BypassMethod.NONE,
            risk_level="medium",
        )

        selector = BypassStrategySelector()
        is_network = selector._is_network_based_licensing(report)

        assert is_network is True

    def test_activation_context_detected_as_network(self) -> None:
        """Activation/online/server keywords indicate network licensing."""
        network_keywords = ["activation", "online", "server", "https", "http"]

        for keyword in network_keywords:
            funcs = [
                ValidationFunction(
                    address=0x401000,
                    api_name="ValidateLicense",
                    library="licensing.dll",
                    confidence=0.88,
                    context=f"License {keyword} validation routine",
                    references=[0x402000],
                ),
            ]

            report = DetectionReport(
                binary_path="app.exe",
                detected_libraries=["licensing.dll"],
                validation_functions=funcs,
                recommended_method=BypassMethod.NONE,
                risk_level="medium",
            )

            selector = BypassStrategySelector()
            is_network = selector._is_network_based_licensing(report)

            assert is_network is True, f"Keyword '{keyword}' should trigger network detection"

    def test_offline_validation_not_detected_as_network(self) -> None:
        """Pure offline validation not detected as network-based."""
        funcs = [
            ValidationFunction(
                address=0x401000,
                api_name="CertVerifyCertificateChainPolicy",
                library="crypt32.dll",
                confidence=0.91,
                context="Local certificate validation",
                references=[0x402000],
            ),
        ]

        report = DetectionReport(
            binary_path="app.exe",
            detected_libraries=["crypt32.dll"],
            validation_functions=funcs,
            recommended_method=BypassMethod.NONE,
            risk_level="low",
        )

        selector = BypassStrategySelector()
        is_network = selector._is_network_based_licensing(report)

        assert is_network is False


class TestEdgeCaseStrategySelection:
    """Tests for edge cases in strategy selection."""

    def test_empty_report_handling(self) -> None:
        """Empty detection report handled gracefully."""
        report = DetectionReport(
            binary_path="empty.exe",
            detected_libraries=[],
            validation_functions=[],
            recommended_method=BypassMethod.NONE,
            risk_level="low",
        )

        selector = BypassStrategySelector()
        method = selector.select_optimal_strategy(report, target_state="static")
        risk = selector.assess_patch_risk(report)

        assert method == BypassMethod.NONE
        assert risk == "low"

    def test_mixed_confidence_packed_detection(self) -> None:
        """Mixed confidence levels correctly identify packed binaries."""
        funcs = [
            ValidationFunction(
                address=0x401000,
                api_name="func1",
                library="unknown",
                confidence=0.95,
                context="Clear function",
                references=[0x402000],
            ),
            ValidationFunction(
                address=0x403000,
                api_name="func2",
                library="unknown",
                confidence=0.35,
                context="Obfuscated",
                references=[],
            ),
            ValidationFunction(
                address=0x405000,
                api_name="func3",
                library="unknown",
                confidence=0.28,
                context="Packed",
                references=[],
            ),
        ]

        report = DetectionReport(
            binary_path="mixed.exe",
            detected_libraries=["unknown"],
            validation_functions=funcs,
            recommended_method=BypassMethod.NONE,
            risk_level="medium",
        )

        selector = BypassStrategySelector()
        is_packed = selector._is_packed_binary(report)

        assert is_packed is True

    def test_explicit_packed_flag_respected(self) -> None:
        """Explicit is_packed flag on report is respected."""

        class PackedDetectionReport(DetectionReport):
            is_packed: bool = True

        funcs = [
            ValidationFunction(
                address=0x401000,
                api_name="SSL_CTX_set_verify",
                library="libssl.so",
                confidence=0.95,
                context="Clear function",
                references=[0x402000],
            ),
        ]

        report = PackedDetectionReport(
            binary_path="packed.exe",
            detected_libraries=["libssl.so"],
            validation_functions=funcs,
            recommended_method=BypassMethod.NONE,
            risk_level="low",
        )

        selector = BypassStrategySelector()
        is_packed = selector._is_packed_binary(report)

        assert is_packed is True

#!/usr/bin/env python3
"""Integration tests for licensing protocol parsers.

Tests the FlexLM, CodeMeter, HASP, and Autodesk protocol parsers
to ensure they work correctly for license emulation.
"""
from __future__ import annotations

import concurrent.futures
import time
from typing import Any

import pytest

from intellicrack.core.network.protocols.autodesk_parser import (
    AutodeskLicensingParser,
    AutodeskRequest,
    AutodeskResponse,
)
from intellicrack.core.network.protocols.codemeter_parser import (
    CodeMeterProtocolParser,
    CodeMeterRequest,
    CodeMeterResponse,
)
from intellicrack.core.network.protocols.flexlm_parser import (
    FlexLMProtocolParser,
    FlexLMRequest,
    FlexLMResponse,
)
from intellicrack.core.network.protocols.hasp_parser import (
    HASPPacketAnalyzer,
    HASPRequest,
    HASPResponse,
    HASPSentinelParser,
    HASPServerEmulator,
)


def create_flexlm_request(
    command: int = 1,
    feature: str = "TEST",
    version_requested: str = "1.0",
    client_id: str = "test@host",
    pid: int = 12345,
) -> FlexLMRequest:
    """Create a FlexLMRequest with defaults for all required fields."""
    return FlexLMRequest(
        command=command,
        version=1,
        sequence=1,
        client_id=client_id,
        feature=feature,
        version_requested=version_requested,
        platform="Windows",
        hostname="testhost",
        username="testuser",
        pid=pid,
        checkout_time=int(time.time()),
        additional_data={},
    )


def create_codemeter_request(
    command: int = 1,
    firm_code: int = 12345,
    product_code: int = 67890,
    challenge_data: bytes = b"",
) -> CodeMeterRequest:
    """Create a CodeMeterRequest with defaults for all required fields."""
    return CodeMeterRequest(
        command=command,
        request_id=1,
        firm_code=firm_code,
        product_code=product_code,
        feature_map=0,
        version="1.0",
        client_id="test_client",
        session_context={},
        challenge_data=challenge_data,
        additional_data={},
    )


def create_autodesk_request(
    request_type: str = "activation",
    product_key: str = "TEST-KEY-123",
) -> AutodeskRequest:
    """Create an AutodeskRequest with defaults for all required fields."""
    return AutodeskRequest(
        request_type=request_type,
        product_key=product_key,
        installation_id="install-001",
        machine_id="machine-001",
        user_id="user-001",
        activation_id="",
        license_method="perpetual",
        request_data={},
        headers={},
        auth_token="",
        platform_info={"os": "Windows", "version": "10"},
    )


class TestFlexLMProtocolIntegration:
    """Tests for FlexLM protocol integration."""

    def test_flexlm_parser_initialization(self) -> None:
        """Test FlexLM parser initializes correctly."""
        parser = FlexLMProtocolParser()

        assert parser is not None
        assert hasattr(parser, 'server_features')
        assert hasattr(parser, 'active_checkouts')

    def test_flexlm_add_feature_and_checkout(self) -> None:
        """Test adding feature and performing checkout."""
        parser = FlexLMProtocolParser()

        parser.add_custom_feature("MATLAB", "R2024a", "MathWorks", count=10)

        assert "MATLAB" in parser.server_features

        request = create_flexlm_request(
            command=1,
            feature="MATLAB",
            version_requested="R2024a",
            client_id="testuser@testhost",
            pid=12345,
        )

        response = parser.generate_response(request)

        assert response is not None
        assert isinstance(response, FlexLMResponse)
        assert response.status == 0

    def test_flexlm_license_limit_enforcement(self) -> None:
        """Test that license limits are enforced."""
        parser = FlexLMProtocolParser()

        parser.add_custom_feature("LIMITED", "1.0", "Test", count=2)

        successful = 0
        failed = 0

        for i in range(5):
            req = create_flexlm_request(
                command=1,
                feature="LIMITED",
                version_requested="1.0",
                client_id=f"user{i}@host",
                pid=10000 + i,
            )
            resp = parser.generate_response(req)

            if resp.status == 0:
                successful += 1
            else:
                failed += 1

        assert successful == 2
        assert failed == 3

    def test_flexlm_statistics_tracking(self) -> None:
        """Test server statistics tracking."""
        parser = FlexLMProtocolParser()

        parser.add_custom_feature("TRACKED", "1.0", "Vendor", count=100)

        for i in range(10):
            req = create_flexlm_request(
                command=1,
                feature="TRACKED",
                version_requested="1.0",
                client_id=f"user{i}@host",
                pid=20000 + i,
            )
            parser.generate_response(req)

        stats = parser.get_server_statistics()

        assert stats is not None
        assert "total_requests" in stats or "request_count" in stats


class TestCodeMeterProtocolIntegration:
    """Tests for CodeMeter protocol integration."""

    def test_codemeter_parser_initialization(self) -> None:
        """Test CodeMeter parser initializes correctly."""
        parser = CodeMeterProtocolParser()

        assert parser is not None
        assert hasattr(parser, 'generate_response')

    def test_codemeter_response_generation(self) -> None:
        """Test CodeMeter response generation."""
        parser = CodeMeterProtocolParser()

        request = create_codemeter_request(
            command=1,
            firm_code=12345,
            product_code=67890,
        )

        response = parser.generate_response(request)

        assert response is not None
        assert isinstance(response, CodeMeterResponse)
        assert hasattr(response, 'status')

    def test_codemeter_encryption_handling(self) -> None:
        """Test CodeMeter encryption challenge handling."""
        parser = CodeMeterProtocolParser()

        challenge = b"TEST_CHALLENGE_DATA"

        request = create_codemeter_request(
            command=3,
            firm_code=11111,
            product_code=22222,
            challenge_data=challenge,
        )

        response = parser.generate_response(request)

        assert response is not None
        assert response.response_data != challenge


class TestHASPProtocolIntegration:
    """Tests for HASP protocol integration."""

    def test_hasp_emulator_initialization(self) -> None:
        """Test HASP emulator initializes correctly."""
        emulator = HASPServerEmulator()

        assert emulator is not None
        assert hasattr(emulator, 'parser')
        assert hasattr(emulator, 'start_server')

    def test_hasp_parser_initialization(self) -> None:
        """Test HASP parser initializes correctly."""
        parser = HASPSentinelParser()

        assert parser is not None
        assert hasattr(parser, 'parse_packet')

    def test_hasp_packet_analyzer_initialization(self) -> None:
        """Test HASP packet analyzer initializes correctly."""
        analyzer = HASPPacketAnalyzer()

        assert analyzer is not None
        assert hasattr(analyzer, 'analyze_packet')


class TestAutodeskProtocolIntegration:
    """Tests for Autodesk protocol integration."""

    def test_autodesk_parser_initialization(self) -> None:
        """Test Autodesk parser initializes correctly."""
        parser = AutodeskLicensingParser()

        assert parser is not None
        assert hasattr(parser, 'active_activations')
        assert hasattr(parser, 'subscription_data')

    def test_autodesk_activation_handling(self) -> None:
        """Test Autodesk activation request handling."""
        parser = AutodeskLicensingParser()

        request = create_autodesk_request(
            request_type="activation",
            product_key="TEST-KEY-123",
        )

        response = parser.generate_response(request)

        assert response is not None
        assert isinstance(response, AutodeskResponse)
        assert hasattr(response, 'status')


class TestConcurrentProtocolProcessing:
    """Tests for concurrent protocol processing."""

    def test_multiple_protocol_parsers_simultaneously(self) -> None:
        """Test multiple parsers running concurrently."""
        flexlm = FlexLMProtocolParser()
        codemeter = CodeMeterProtocolParser()
        hasp_parser = HASPSentinelParser()
        autodesk = AutodeskLicensingParser()

        flexlm.add_custom_feature("CONCURRENT_TEST", "1.0", "Vendor", count=100)

        results: list[dict[str, Any]] = []

        def test_flexlm() -> dict[str, Any]:
            req = create_flexlm_request(
                command=1,
                feature="CONCURRENT_TEST",
                version_requested="1.0",
                client_id="concurrent@test",
                pid=30000,
            )
            resp = flexlm.generate_response(req)
            return {"parser": "FlexLM", "success": resp.status == 0}

        def test_codemeter() -> dict[str, Any]:
            req = create_codemeter_request(
                command=1,
                firm_code=99999,
                product_code=88888,
            )
            resp = codemeter.generate_response(req)
            return {"parser": "CodeMeter", "success": resp is not None}

        def test_hasp() -> dict[str, Any]:
            return {"parser": "HASP", "success": hasp_parser is not None}

        def test_autodesk() -> dict[str, Any]:
            req = create_autodesk_request(
                request_type="activation",
                product_key="CONCURRENT",
            )
            resp = autodesk.generate_response(req)
            return {"parser": "Autodesk", "success": resp is not None}

        with concurrent.futures.ThreadPoolExecutor(max_workers=4) as executor:
            futures = [
                executor.submit(test_flexlm),
                executor.submit(test_codemeter),
                executor.submit(test_hasp),
                executor.submit(test_autodesk),
            ]

            for future in concurrent.futures.as_completed(futures):
                results.append(future.result())

        assert len(results) == 4
        assert all(r["success"] for r in results)

    def test_batch_processing_performance(self) -> None:
        """Test batch processing performance."""
        parser = FlexLMProtocolParser()

        parser.add_custom_feature("PERFORMANCE", "1.0", "Test", count=1000)

        start = time.time()

        for i in range(100):
            req = create_flexlm_request(
                command=1,
                feature="PERFORMANCE",
                version_requested="1.0",
                client_id=f"perf{i}@test",
                pid=40000 + i,
            )
            parser.generate_response(req)

        elapsed = time.time() - start

        assert elapsed < 5.0

        throughput = 100 / elapsed
        assert throughput > 20


class TestProtocolErrorHandling:
    """Tests for protocol error handling."""

    def test_flexlm_invalid_feature_rejection(self) -> None:
        """Test that invalid features are rejected."""
        parser = FlexLMProtocolParser()

        request = create_flexlm_request(
            command=1,
            feature="NONEXISTENT_FEATURE",
            version_requested="1.0",
            client_id="test@test",
            pid=50000,
        )

        response = parser.generate_response(request)

        assert response is not None
        assert response.status != 0

    def test_hasp_emulator_initialization_check(self) -> None:
        """Test HASP emulator initialization check."""
        emulator = HASPServerEmulator()

        assert emulator is not None
        assert hasattr(emulator, 'parser')


class TestProtocolSecurityFeatures:
    """Tests for protocol security features."""

    def test_flexlm_unique_license_keys(self) -> None:
        """Test that unique license keys are generated."""
        parser = FlexLMProtocolParser()

        parser.add_custom_feature("SECURITY", "1.0", "Test", count=100)

        keys: set[str] = set()

        for i in range(50):
            req = create_flexlm_request(
                command=1,
                feature="SECURITY",
                version_requested="1.0",
                client_id=f"sec{i}@test",
                pid=60000 + i,
            )
            resp = parser.generate_response(req)

            if resp.status == 0 and resp.license_key:
                keys.add(resp.license_key)

        assert len(keys) >= 45

    def test_codemeter_varied_encryption_responses(self) -> None:
        """Test that encryption responses vary with challenge data."""
        parser = CodeMeterProtocolParser()

        challenge1 = b"CHALLENGE_A"
        challenge2 = b"CHALLENGE_B"

        req1 = create_codemeter_request(
            command=3,
            firm_code=11111,
            product_code=22222,
            challenge_data=challenge1,
        )

        req2 = create_codemeter_request(
            command=3,
            firm_code=11111,
            product_code=22222,
            challenge_data=challenge2,
        )

        resp1 = parser.generate_response(req1)
        resp2 = parser.generate_response(req2)

        assert resp1.response_data != resp2.response_data

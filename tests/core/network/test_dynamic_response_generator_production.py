"""Production tests for dynamic response generation with real protocol responses.

These tests validate that dynamic_response_generator creates valid, protocol-compliant
responses that actual license servers would accept. Tests MUST FAIL if generated
responses don't match expected protocol formats.

Copyright (C) 2025 Zachary Flint
"""

import json
import re
import struct
import time
import uuid
from typing import Any

import pytest

from intellicrack.core.network.dynamic_response_generator import (
    AdobeProtocolHandler,
    AutodeskProtocolHandler,
    DynamicResponseGenerator,
    FlexLMProtocolHandler,
    GeneratedResponse,
    HASPProtocolHandler,
    MicrosoftKMSHandler,
    ResponseContext,
)


class TestDynamicResponseGeneratorProduction:
    """Production tests for dynamic protocol response generation."""

    @pytest.fixture
    def response_generator(self) -> DynamicResponseGenerator:
        """Create response generator instance."""
        return DynamicResponseGenerator()

    @pytest.fixture
    def flexlm_request_context(self) -> ResponseContext:
        """Create context for FlexLM license request."""
        request_data = b"FEATURE AutoCAD adskflex 2024.0 permanent 1\nSERVER license_server ANY 27000\nVENDOR adskflex\n"
        return ResponseContext(
            source_ip="192.168.1.100",
            source_port=54321,
            target_host="192.168.1.200",
            target_port=27000,
            protocol_type="flexlm",
            request_data=request_data,
            parsed_request=None,
            client_fingerprint="client123",
            timestamp=time.time(),
        )

    @pytest.fixture
    def hasp_request_context(self) -> ResponseContext:
        """Create context for HASP/Sentinel license request."""
        request_data = json.dumps({
            "command": "query",
            "product": "SentinelLicense",
            "version": "1.0",
        }).encode()
        return ResponseContext(
            source_ip="10.0.0.50",
            source_port=48200,
            target_host="10.0.0.10",
            target_port=1947,
            protocol_type="hasp",
            request_data=request_data,
            parsed_request=None,
            client_fingerprint="hasp_client_001",
            timestamp=time.time(),
        )

    def test_flexlm_handler_parses_feature_lines(self) -> None:
        """FlexLM handler correctly parses FEATURE lines from request."""
        handler = FlexLMProtocolHandler()
        request = b"FEATURE AutoCAD adskflex 2024.0 permanent 1\nFEATURE 3dsMax adskflex 2024.0 permanent 1\n"

        parsed = handler.parse_request(request)

        assert parsed is not None, "FlexLM request parsing must succeed"
        assert len(parsed["features"]) == 2, "Must parse both FEATURE lines"
        assert parsed["features"][0]["name"] == "AutoCAD", "First feature must be AutoCAD"
        assert parsed["features"][1]["name"] == "3dsMax", "Second feature must be 3dsMax"
        assert parsed["features"][0]["vendor"] == "adskflex", "Vendor must be extracted"

    def test_flexlm_handler_generates_valid_response(
        self,
        flexlm_request_context: ResponseContext,
    ) -> None:
        """FlexLM handler generates valid license response with correct format."""
        handler = FlexLMProtocolHandler()

        response = handler.generate_response(flexlm_request_context)

        assert response is not None, "Response must be generated"
        assert b"SERVER" in response, "Response must contain SERVER line"
        assert b"VENDOR" in response, "Response must contain VENDOR line"
        assert b"FEATURE" in response, "Response must contain FEATURE line"
        assert b"permanent" in response or b"-" in response, "License must have expiry date or permanent"
        assert b"uncounted" in response, "License must be uncounted"
        assert b"HOSTID=ANY" in response, "Must accept any host ID"

        # Validate computed signature instead of hardcoded SIGN=VALID
        response_text = response.decode("utf-8")
        sign_match = re.search(r'SIGN=([A-F0-9]+)', response_text)
        assert sign_match is not None, "Signature field must be present"
        assert len(sign_match.group(1)) >= 16, "Signature must be at least 16 hex characters"
        assert "SIGN=VALID" not in response_text, "Must not use hardcoded SIGN=VALID"

    def test_hasp_handler_parses_json_request(self) -> None:
        """HASP handler correctly parses JSON-formatted requests."""
        handler = HASPProtocolHandler()
        request = json.dumps({
            "command": "query",
            "product": "SentinelLicense",
        }).encode()

        parsed = handler.parse_request(request)

        assert parsed is not None, "JSON parsing must succeed"
        assert parsed["format"] == "json", "Must identify JSON format"
        assert "data" in parsed, "Must extract JSON data"
        assert parsed["data"]["command"] == "query", "Command must be parsed"

    def test_hasp_handler_parses_binary_request(self) -> None:
        """HASP handler correctly parses binary-formatted requests."""
        handler = HASPProtocolHandler()
        request = struct.pack("<I", 0x12345678) + b"binary_data_here"

        parsed = handler.parse_request(request)

        assert parsed is not None, "Binary parsing must succeed"
        assert parsed["format"] == "binary", "Must identify binary format"
        assert parsed["header"] == 0x12345678, "Header must be extracted"

    def test_hasp_handler_generates_json_response(
        self,
        hasp_request_context: ResponseContext,
    ) -> None:
        """HASP handler generates valid JSON response for JSON requests."""
        handler = HASPProtocolHandler()

        response = handler.generate_response(hasp_request_context)

        assert response is not None, "Response must be generated"

        response_data = json.loads(response.decode())
        assert response_data["status"] == "OK", "Status must be OK"
        assert response_data["key"] == "VALID", "Key must be VALID"
        assert response_data["expiration"] == "permanent", "License must be permanent"
        assert "timestamp" in response_data, "Must include timestamp"
        assert "session_id" in response_data, "Must include session ID"

    def test_adobe_handler_parses_activation_request(self) -> None:
        """Adobe handler identifies activation request type."""
        handler = AdobeProtocolHandler()
        request = json.dumps({
            "type": "activate",
            "product": "Photoshop",
            "serial": "1234-5678-9012-3456",
        }).encode()

        parsed = handler.parse_request(request)

        assert parsed is not None, "Adobe request parsing must succeed"
        assert parsed["type"] == "json", "Must identify JSON format"
        assert parsed["serial"] == "1234-5678-9012-3456", "Serial must be extracted"
        assert parsed["product"] == "Photoshop", "Product must be extracted"

    def test_adobe_handler_generates_success_response(self) -> None:
        """Adobe handler generates successful activation response."""
        handler = AdobeProtocolHandler()
        context = ResponseContext(
            source_ip="10.0.0.1",
            source_port=1234,
            target_host="adobe.com",
            target_port=443,
            protocol_type="adobe",
            request_data=b'{"type": "activate", "serial": "1234-5678-9012-3456"}',
            parsed_request=None,
            client_fingerprint="adobe_client",
            timestamp=time.time(),
        )

        response = handler.generate_response(context)

        assert response is not None, "Response must be generated"
        response_data = json.loads(response.decode())
        assert response_data["status"] == "SUCCESS", "Activation must succeed"
        assert response_data["expiry"] == "never", "License must never expire"
        assert "activation_id" in response_data, "Must include activation ID"

    def test_kms_handler_parses_rpc_request(self) -> None:
        """Microsoft KMS handler parses RPC protocol requests."""
        handler = MicrosoftKMSHandler()
        request = struct.pack("<IIII", 5, 0, 3, 32) + b"\x00" * 32

        parsed = handler.parse_request(request)

        assert parsed is not None, "RPC parsing must succeed"
        assert parsed["format"] == "rpc", "Must identify RPC format"
        assert parsed["version"] == 5, "Version must be extracted"
        assert parsed["data_length"] == 32, "Data length must be extracted"

    def test_kms_handler_generates_rpc_response(self) -> None:
        """Microsoft KMS handler generates valid RPC response."""
        handler = MicrosoftKMSHandler()
        context = ResponseContext(
            source_ip="10.0.0.1",
            source_port=1234,
            target_host="kms.server",
            target_port=1688,
            protocol_type="microsoft",
            request_data=struct.pack("<IIII", 5, 0, 3, 32) + b"\x00" * 32,
            parsed_request=None,
            client_fingerprint="kms_client",
            timestamp=time.time(),
        )

        response = handler.generate_response(context)

        assert response is not None, "Response must be generated"
        assert len(response) >= 16, "Response must include header"
        header = struct.unpack("<IIII", response[:16])
        assert header[1] == 2, "Response type must be 2"

    def test_autodesk_handler_generates_license_response(self) -> None:
        """Autodesk handler generates license response with correct structure."""
        handler = AutodeskProtocolHandler()
        context = ResponseContext(
            source_ip="10.0.0.1",
            source_port=1234,
            target_host="autodesk.com",
            target_port=2080,
            protocol_type="autodesk",
            request_data=b'{"product": "AutoCAD", "version": "2024"}',
            parsed_request=None,
            client_fingerprint="autodesk_client_123",
            timestamp=time.time(),
        )

        response = handler.generate_response(context)

        assert response is not None, "Response must be generated"
        response_data = json.loads(response.decode())
        assert response_data["status"] == "success", "Status must be success"
        assert response_data["license"]["status"] == "ACTIVATED", "License must be activated"
        assert response_data["license"]["type"] == "PERMANENT", "License must be permanent"
        assert "client_id" in response_data, "Must include client ID"

    def test_response_generator_routes_to_flexlm_handler(
        self,
        response_generator: DynamicResponseGenerator,
        flexlm_request_context: ResponseContext,
    ) -> None:
        """Response generator routes FlexLM requests to correct handler."""
        response = response_generator.generate_response(flexlm_request_context)

        assert response.response_type == "protocol_specific", "Must use protocol handler"
        assert response.generation_method == "flexlm_handler", "Must use FlexLM handler"
        assert response.confidence >= 0.9, "Protocol-specific responses have high confidence"
        assert len(response.response_data) > 0, "Response must not be empty"

    def test_response_generator_routes_to_hasp_handler(
        self,
        response_generator: DynamicResponseGenerator,
        hasp_request_context: ResponseContext,
    ) -> None:
        """Response generator routes HASP requests to correct handler."""
        response = response_generator.generate_response(hasp_request_context)

        assert response.response_type == "protocol_specific", "Must use protocol handler"
        assert response.generation_method == "hasp_handler", "Must use HASP handler"
        assert response.confidence >= 0.9, "Protocol-specific responses have high confidence"

    def test_response_caching_functionality(
        self,
        response_generator: DynamicResponseGenerator,
        flexlm_request_context: ResponseContext,
    ) -> None:
        """Response generator caches responses for identical requests."""
        response1 = response_generator.generate_response(flexlm_request_context)
        response2 = response_generator.generate_response(flexlm_request_context)

        assert response2.response_type == "cached", "Second request must be cached"
        assert response2.generation_method == "cache_lookup", "Must use cache"
        assert response2.metadata["cache_hit"] is True, "Cache hit must be flagged"
        assert response1.response_data == response2.response_data, "Cached data must match"

    def test_learning_from_successful_requests(
        self,
        response_generator: DynamicResponseGenerator,
        flexlm_request_context: ResponseContext,
    ) -> None:
        """Response generator learns patterns from successful requests."""
        initial_patterns = len(response_generator.learned_patterns.get("flexlm", []))

        response_generator.generate_response(flexlm_request_context)

        assert "flexlm" in response_generator.learned_patterns, "Must store FlexLM patterns"
        assert len(response_generator.learned_patterns["flexlm"]) > initial_patterns, (
            "Must learn from request"
        )

    def test_pattern_extraction_from_data(
        self,
        response_generator: DynamicResponseGenerator,
    ) -> None:
        """Pattern extraction identifies key structures in data."""
        data = b'{"license": "valid", "expiry": "never"}'

        patterns = response_generator._extract_patterns(data)

        assert len(patterns) > 0, "Must extract patterns"
        assert any("license" in p for p in patterns), "Must extract 'license' pattern"

    def test_adaptive_response_generation(
        self,
        response_generator: DynamicResponseGenerator,
    ) -> None:
        """Adaptive response generates responses from learned patterns."""
        response_generator.learned_patterns["custom"] = [
            {
                "timestamp": time.time(),
                "request_patterns": ["product:AutoCAD", "version:2024"],
                "response_patterns": ['{"status":"success"}', "status:success"],
                "request_size": 100,
                "response_size": 50,
                "source_port": 1234,
                "target_port": 2080,
            },
        ]

        context = ResponseContext(
            source_ip="10.0.0.1",
            source_port=1234,
            target_host="server",
            target_port=2080,
            protocol_type="custom",
            request_data=b'{"product": "AutoCAD", "version": "2024"}',
            parsed_request=None,
            client_fingerprint="client",
            timestamp=time.time(),
        )

        response = response_generator.generate_response(context)

        assert response.response_type in ["adaptive", "generic"], (
            "Must use adaptive or generic response"
        )

    def test_generic_response_for_json_request(
        self,
        response_generator: DynamicResponseGenerator,
    ) -> None:
        """Generic response generator creates JSON response for JSON requests."""
        context = ResponseContext(
            source_ip="10.0.0.1",
            source_port=1234,
            target_host="server",
            target_port=8080,
            protocol_type="unknown",
            request_data=b'{"request": "test"}',
            parsed_request=None,
            client_fingerprint="client",
            timestamp=time.time(),
        )

        response = response_generator.generate_response(context)

        assert response.response_type == "generic", "Must use generic response"
        response_data = json.loads(response.response_data.decode())
        assert response_data["status"] == "OK", "Generic JSON must have OK status"
        assert "response_id" in response_data, "Must include response ID"

    def test_generic_response_for_xml_request(
        self,
        response_generator: DynamicResponseGenerator,
    ) -> None:
        """Generic response generator creates XML response for XML requests."""
        context = ResponseContext(
            source_ip="10.0.0.1",
            source_port=1234,
            target_host="server",
            target_port=8080,
            protocol_type="unknown",
            request_data=b'<?xml version="1.0"?><request><action>test</action></request>',
            parsed_request=None,
            client_fingerprint="client",
            timestamp=time.time(),
        )

        response = response_generator.generate_response(context)

        assert b"<?xml" in response.response_data, "Response must be XML"
        assert b"<status>OK</status>" in response.response_data, "Must include OK status"

    def test_statistics_tracking(
        self,
        response_generator: DynamicResponseGenerator,
        flexlm_request_context: ResponseContext,
    ) -> None:
        """Response generator tracks comprehensive statistics."""
        initial_requests = response_generator.stats["total_requests"]

        response_generator.generate_response(flexlm_request_context)

        stats = response_generator.get_statistics()
        assert stats["total_requests"] > initial_requests, "Request count must increase"
        assert stats["successful_responses"] > 0, "Successful responses must be tracked"
        assert "flexlm" in stats["protocols_handled"], "Protocol must be tracked"
        assert stats["average_response_time"] >= 0, "Average time must be non-negative"

    def test_cache_expiration(
        self,
        response_generator: DynamicResponseGenerator,
        flexlm_request_context: ResponseContext,
    ) -> None:
        """Response cache expires entries after TTL."""
        response_generator.cache_ttl = 0.1  # type: ignore[assignment]

        response_generator.generate_response(flexlm_request_context)

        time.sleep(0.2)

        response2 = response_generator.generate_response(flexlm_request_context)

        assert response2.response_type != "cached", "Expired cache must not be used"

    def test_cache_size_limit(
        self,
        response_generator: DynamicResponseGenerator,
    ) -> None:
        """Response cache enforces size limit."""
        for i in range(1100):
            context = ResponseContext(
                source_ip=f"10.0.0.{i % 255}",
                source_port=1000 + i,
                target_host="server",
                target_port=27000,
                protocol_type="flexlm",
                request_data=f"REQUEST_{i}".encode(),
                parsed_request=None,
                client_fingerprint=f"client_{i}",
                timestamp=time.time(),
            )
            response_generator.generate_response(context)

        assert len(response_generator.response_cache) <= 1000, (
            "Cache must not exceed size limit"
        )

    def test_learning_data_export(
        self,
        response_generator: DynamicResponseGenerator,
        flexlm_request_context: ResponseContext,
    ) -> None:
        """Learning data can be exported for persistence."""
        response_generator.generate_response(flexlm_request_context)

        exported = response_generator.export_learning_data()

        assert "learned_patterns" in exported, "Must export learned patterns"
        assert "statistics" in exported, "Must export statistics"
        assert "cache_size" in exported, "Must export cache size"
        assert "flexlm" in exported["learned_patterns"], "FlexLM patterns must be exported"

    def test_learning_data_import(
        self,
        response_generator: DynamicResponseGenerator,
    ) -> None:
        """Learning data can be imported from previous sessions."""
        learning_data = {
            "learned_patterns": {
                "custom_protocol": [
                    {
                        "timestamp": time.time(),
                        "request_patterns": ["test"],
                        "response_patterns": ["response"],
                        "request_size": 10,
                        "response_size": 20,
                        "source_port": 1234,
                        "target_port": 5678,
                    },
                ],
            },
        }

        response_generator.import_learning_data(learning_data)

        assert "custom_protocol" in response_generator.learned_patterns, (
            "Must import custom protocol patterns"
        )

    def test_similarity_calculation(
        self,
        response_generator: DynamicResponseGenerator,
    ) -> None:
        """Similarity calculation identifies matching patterns."""
        patterns1 = ["license", "status:ok", "product:AutoCAD"]
        patterns2 = ["license", "status:ok", "product:3dsMax"]
        patterns3 = ["completely", "different", "patterns"]

        similarity_12 = response_generator._calculate_similarity(patterns1, patterns2)
        similarity_13 = response_generator._calculate_similarity(patterns1, patterns3)

        assert similarity_12 > similarity_13, "Similar patterns must have higher score"
        assert 0.0 <= similarity_12 <= 1.0, "Similarity must be in valid range"

    def test_error_handling_in_generation(
        self,
        response_generator: DynamicResponseGenerator,
    ) -> None:
        """Response generator handles errors gracefully."""
        context = ResponseContext(
            source_ip="10.0.0.1",
            source_port=1234,
            target_host="server",
            target_port=27000,
            protocol_type="invalid_protocol_that_doesnt_exist",
            request_data=b"\x00\x01\x02\x03",
            parsed_request=None,
            client_fingerprint="client",
            timestamp=time.time(),
        )

        response = response_generator.generate_response(context)

        assert response is not None, "Must return response even on error"
        assert response.response_data is not None, "Must include response data"

    def test_protocol_aware_fallback_http(
        self,
        response_generator: DynamicResponseGenerator,
    ) -> None:
        """Protocol-aware fallback generates HTTP error response."""
        context = ResponseContext(
            source_ip="10.0.0.1",
            source_port=1234,
            target_host="server",
            target_port=80,
            protocol_type="HTTP",
            request_data=b"GET /test HTTP/1.1\r\n\r\n",
            parsed_request=None,
            client_fingerprint="client",
            timestamp=time.time(),
            headers={"accept": "application/json"},
        )

        fallback = response_generator._create_protocol_aware_fallback(context)

        assert b"HTTP/1.1" in fallback, "Must be HTTP response"
        assert b"500" in fallback, "Must be HTTP 500 error"
        assert b"application/json" in fallback or b"json" in fallback, (
            "Must respect accept header"
        )

    def test_intelligent_fallback_license_patterns(
        self,
        response_generator: DynamicResponseGenerator,
    ) -> None:
        """Intelligent fallback detects license-related keywords."""
        context = ResponseContext(
            source_ip="10.0.0.1",
            source_port=1234,
            target_host="server",
            target_port=8080,
            protocol_type="unknown",
            request_data=b"license validation request for adobe photoshop",
            parsed_request=None,
            client_fingerprint="client",
            timestamp=time.time(),
        )

        fallback = response_generator._create_intelligent_fallback(context)

        assert b"ADOBE" in fallback or b"LICENSE_VALID" in fallback, (
            "Must generate license-aware response"
        )

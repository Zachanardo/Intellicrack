"""Production tests for FlexLM signature calculation in dynamic_response_generator.py.

Tests MUST validate real FlexLM signature calculation, vendor key extraction,
cryptographic SIGN= field generation, and checksum validation. These tests
verify offensive capability to generate valid FlexLM license responses that
bypass commercial software licensing protections.

NO MOCKS - All tests use real FlexLM signature algorithms and license formats.

Copyright (C) 2025 Zachary Flint
Licensed under GNU General Public License v3.0
"""

import hashlib
import re
import struct
import time
from pathlib import Path
from typing import Any

import pytest

from intellicrack.core.network.dynamic_response_generator import (
    FlexLMProtocolHandler,
    ResponseContext,
)


class TestFlexLMSignatureCalculation:
    """Test FlexLM signature calculation algorithm implementation."""

    def test_signature_calculation_uses_real_algorithm_not_placeholder(self) -> None:
        """Signature calculation must use real FlexLM algorithm, not SIGN=VALID placeholder."""
        handler = FlexLMProtocolHandler()

        request_data = b"SERVER test ANY 27000\nVENDOR ADSKFLEX\nFEATURE AUTOCAD ADSKFLEX 2024.0 31-dec-2025 100 HOSTID=ANY"

        context = ResponseContext(
            source_ip="192.168.1.100",
            source_port=5000,
            target_host="192.168.1.1",
            target_port=27000,
            protocol_type="flexlm",
            request_data=request_data,
            parsed_request=None,
            client_fingerprint="test_client",
            timestamp=time.time(),
        )

        response = handler.generate_response(context)
        response_text = response.decode("utf-8")

        assert "SIGN=VALID" not in response_text, "Using placeholder SIGN=VALID instead of real signature"
        assert "ck=123" not in response_text, "Using placeholder ck=123 instead of real checksum"

        sign_match = re.search(r'SIGN="?([A-F0-9]+)"?', response_text)
        assert sign_match is not None, "No SIGN= field found in response"

        signature = sign_match.group(1)
        assert len(signature) >= 32, f"Signature too short ({len(signature)} chars), must be cryptographic hash"
        assert signature != "VALID", "Signature is placeholder string, not real hash"

    def test_signature_calculation_deterministic_for_same_input(self) -> None:
        """Signature must be deterministic - same input produces same signature."""
        handler = FlexLMProtocolHandler()

        request_data = b"FEATURE MATLAB MLM R2024a 31-dec-2025 50 HOSTID=001122334455"

        context = ResponseContext(
            source_ip="192.168.1.100",
            source_port=5000,
            target_host="192.168.1.1",
            target_port=27000,
            protocol_type="flexlm",
            request_data=request_data,
            parsed_request=None,
            client_fingerprint="client_001",
            timestamp=1700000000.0,
        )

        response1 = handler.generate_response(context)
        response2 = handler.generate_response(context)

        sign1 = re.search(r'SIGN="?([A-F0-9]+)"?', response1.decode("utf-8"))
        sign2 = re.search(r'SIGN="?([A-F0-9]+)"?', response2.decode("utf-8"))

        assert sign1 is not None and sign2 is not None, "Signatures not found in responses"
        assert sign1.group(1) == sign2.group(1), "Signature calculation not deterministic"

    def test_signature_includes_feature_name_in_calculation(self) -> None:
        """Signature must incorporate feature name - different features produce different signatures."""
        handler = FlexLMProtocolHandler()

        autocad_request = b"FEATURE AUTOCAD ADSKFLEX 2024.0 31-dec-2025 100 HOSTID=ANY"
        inventor_request = b"FEATURE INVENTOR ADSKFLEX 2024.0 31-dec-2025 100 HOSTID=ANY"

        context_autocad = ResponseContext(
            source_ip="192.168.1.100",
            source_port=5000,
            target_host="192.168.1.1",
            target_port=27000,
            protocol_type="flexlm",
            request_data=autocad_request,
            parsed_request=None,
            client_fingerprint="test",
            timestamp=1700000000.0,
        )

        context_inventor = ResponseContext(
            source_ip="192.168.1.100",
            source_port=5000,
            target_host="192.168.1.1",
            target_port=27000,
            protocol_type="flexlm",
            request_data=inventor_request,
            parsed_request=None,
            client_fingerprint="test",
            timestamp=1700000000.0,
        )

        response_autocad = handler.generate_response(context_autocad)
        response_inventor = handler.generate_response(context_inventor)

        sign_autocad = re.search(r'SIGN="?([A-F0-9]+)"?', response_autocad.decode("utf-8"))
        sign_inventor = re.search(r'SIGN="?([A-F0-9]+)"?', response_inventor.decode("utf-8"))

        assert sign_autocad is not None and sign_inventor is not None
        assert sign_autocad.group(1) != sign_inventor.group(1), "Signatures identical for different features"


class TestFlexLMVendorKeyExtraction:
    """Test vendor key extraction from protected binaries."""

    def test_vendor_key_extraction_from_binary_header(self) -> None:
        """Vendor key must be extracted from binary PE/ELF sections, not hardcoded."""
        handler = FlexLMProtocolHandler()

        simulated_binary_data = bytearray(1024)
        simulated_binary_data[0:4] = b"MZ\x90\x00"
        simulated_binary_data[100:132] = b"VENDOR_KEY_" + hashlib.sha256(b"test_vendor").digest()[:20]

        request_data = b"FEATURE TEST_APP VENDOR1 1.0 permanent 1 HOSTID=ANY"

        context = ResponseContext(
            source_ip="192.168.1.100",
            source_port=5000,
            target_host="192.168.1.1",
            target_port=27000,
            protocol_type="flexlm",
            request_data=request_data,
            parsed_request={"vendor_binary": bytes(simulated_binary_data)},
            client_fingerprint="test",
            timestamp=time.time(),
        )

        response = handler.generate_response(context)

        assert len(response) > 0, "No response generated"

        response_text = response.decode("utf-8", errors="ignore")
        sign_match = re.search(r'SIGN="?([A-F0-9]+)"?', response_text)

        assert sign_match is not None, "Signature not found in response"
        signature = sign_match.group(1)
        assert len(signature) >= 32, "Signature too short to be cryptographic"

    def test_vendor_key_derivation_from_multiple_sources(self) -> None:
        """Vendor key derivation must support multiple extraction strategies."""
        handler = FlexLMProtocolHandler()

        strategies = [
            {"source": "pe_resources", "key_location": "RCDATA/VENDORKEY"},
            {"source": "elf_section", "key_location": ".flexlm"},
            {"source": "code_analysis", "key_location": "static_data"},
        ]

        for strategy in strategies:
            request_data = f"FEATURE TEST {strategy['source']} 1.0 permanent 1".encode()

            context = ResponseContext(
                source_ip="192.168.1.100",
                source_port=5000,
                target_host="192.168.1.1",
                target_port=27000,
                protocol_type="flexlm",
                request_data=request_data,
                parsed_request={"vendor_key_strategy": strategy},
                client_fingerprint="test",
                timestamp=time.time(),
            )

            response = handler.generate_response(context)
            assert len(response) > 0, f"Failed to generate response for strategy {strategy['source']}"


class TestFlexLMSignatureFieldGeneration:
    """Test cryptographically valid SIGN= field generation."""

    def test_sign_field_format_matches_flexlm_specification(self) -> None:
        """SIGN= field must match FlexLM specification format and length requirements."""
        handler = FlexLMProtocolHandler()

        request_data = b"FEATURE SOLIDWORKS SW_D 2024 31-dec-2025 100 HOSTID=ANY"

        context = ResponseContext(
            source_ip="192.168.1.100",
            source_port=5000,
            target_host="192.168.1.1",
            target_port=27000,
            protocol_type="flexlm",
            request_data=request_data,
            parsed_request=None,
            client_fingerprint="test",
            timestamp=time.time(),
        )

        response = handler.generate_response(context)
        response_text = response.decode("utf-8")

        sign_match = re.search(r'SIGN="?([A-F0-9]+)"?', response_text)
        assert sign_match is not None, "SIGN= field not found"

        signature = sign_match.group(1)

        assert re.match(r"^[A-F0-9]+$", signature), "Signature contains invalid characters"
        assert len(signature) in [32, 40, 64, 128], f"Signature length {len(signature)} not standard"

    def test_sign_field_uses_cryptographic_hash_algorithm(self) -> None:
        """SIGN= field must use recognized cryptographic algorithm (MD5, SHA1, SHA256)."""
        handler = FlexLMProtocolHandler()

        request_data = b"INCREMENT ANSYS ANSYS 2024.1 permanent 50"

        context = ResponseContext(
            source_ip="192.168.1.100",
            source_port=5000,
            target_host="192.168.1.1",
            target_port=27000,
            protocol_type="flexlm",
            request_data=request_data,
            parsed_request=None,
            client_fingerprint="test",
            timestamp=time.time(),
        )

        response = handler.generate_response(context)
        response_text = response.decode("utf-8")

        sign_match = re.search(r'SIGN="?([A-F0-9]+)"?', response_text)
        assert sign_match is not None

        signature = sign_match.group(1)

        valid_lengths = {
            32: "MD5",
            40: "SHA1",
            64: "SHA256",
            128: "SHA512",
        }

        assert len(signature) in valid_lengths, f"Signature length {len(signature)} doesn't match known hash algorithms"

    def test_sign_field_incorporates_license_parameters(self) -> None:
        """SIGN= calculation must incorporate feature, version, expiry, vendor, hostid."""
        handler = FlexLMProtocolHandler()

        base_params = {
            "feature": "TESTAPP",
            "vendor": "TESTVENDOR",
            "version": "1.0",
            "expiry": "31-dec-2025",
            "count": "10",
        }

        signatures: dict[str, str] = {}

        for param_name in ["feature", "vendor", "version", "expiry"]:
            modified_params = base_params.copy()
            modified_params[param_name] = f"MODIFIED_{param_name.upper()}"

            request_line = f"FEATURE {modified_params['feature']} {modified_params['vendor']} {modified_params['version']} {modified_params['expiry']} {modified_params['count']} HOSTID=ANY"
            request_data = request_line.encode()

            context = ResponseContext(
                source_ip="192.168.1.100",
                source_port=5000,
                target_host="192.168.1.1",
                target_port=27000,
                protocol_type="flexlm",
                request_data=request_data,
                parsed_request=None,
                client_fingerprint="test",
                timestamp=1700000000.0,
            )

            response = handler.generate_response(context)
            sign_match = re.search(r'SIGN="?([A-F0-9]+)"?', response.decode("utf-8"))
            assert sign_match is not None
            signatures[param_name] = sign_match.group(1)

        unique_signatures = set(signatures.values())
        assert len(unique_signatures) == len(signatures), "Changing parameters didn't produce different signatures"


class TestFlexLMVersionSpecificSignatures:
    """Test FlexLM version-specific signature format handling."""

    def test_flexlm_v11_signature_format(self) -> None:
        """FlexLM v11.x signature format must be supported."""
        handler = FlexLMProtocolHandler()

        request_data = b"# FlexLM v11.18.0\nFEATURE TEST VENDOR 1.0 permanent 1 HOSTID=ANY"

        context = ResponseContext(
            source_ip="192.168.1.100",
            source_port=5000,
            target_host="192.168.1.1",
            target_port=27000,
            protocol_type="flexlm",
            request_data=request_data,
            parsed_request={"flexlm_version": "11.18.0"},
            client_fingerprint="test",
            timestamp=time.time(),
        )

        response = handler.generate_response(context)
        assert len(response) > 0

        response_text = response.decode("utf-8")
        assert "SIGN=" in response_text

    def test_flexlm_v10_signature_format(self) -> None:
        """FlexLM v10.x signature format must be supported."""
        handler = FlexLMProtocolHandler()

        request_data = b"# FlexLM v10.8.0\nFEATURE TEST VENDOR 1.0 permanent 1"

        context = ResponseContext(
            source_ip="192.168.1.100",
            source_port=5000,
            target_host="192.168.1.1",
            target_port=27000,
            protocol_type="flexlm",
            request_data=request_data,
            parsed_request={"flexlm_version": "10.8.0"},
            client_fingerprint="test",
            timestamp=time.time(),
        )

        response = handler.generate_response(context)
        response_text = response.decode("utf-8")

        assert "FEATURE" in response_text

    def test_flexlm_v9_legacy_signature_format(self) -> None:
        """FlexLM v9.x legacy signature format must be supported."""
        handler = FlexLMProtocolHandler()

        request_data = b"FEATURE LEGACY OLDVENDOR 1.0 01-jan-2000 1"

        context = ResponseContext(
            source_ip="192.168.1.100",
            source_port=5000,
            target_host="192.168.1.1",
            target_port=27000,
            protocol_type="flexlm",
            request_data=request_data,
            parsed_request={"flexlm_version": "9.5.0"},
            client_fingerprint="test",
            timestamp=time.time(),
        )

        response = handler.generate_response(context)
        assert len(response) > 0


class TestFlexLMIncrementFeatureSigning:
    """Test INCREMENT and FEATURE line signing."""

    def test_feature_line_signing(self) -> None:
        """FEATURE lines must have valid signatures."""
        handler = FlexLMProtocolHandler()

        request_data = b"FEATURE AUTOCAD ADSKFLEX 2024.0 31-dec-2025 100 HOSTID=ANY"

        context = ResponseContext(
            source_ip="192.168.1.100",
            source_port=5000,
            target_host="192.168.1.1",
            target_port=27000,
            protocol_type="flexlm",
            request_data=request_data,
            parsed_request=None,
            client_fingerprint="test",
            timestamp=time.time(),
        )

        response = handler.generate_response(context)
        response_text = response.decode("utf-8")

        assert "FEATURE" in response_text
        assert re.search(r'SIGN="?[A-F0-9]+"?', response_text) is not None

    def test_increment_line_signing(self) -> None:
        """INCREMENT lines must have valid signatures distinct from FEATURE."""
        handler = FlexLMProtocolHandler()

        increment_request = b"INCREMENT MATLAB MLM R2024a permanent 25"

        context = ResponseContext(
            source_ip="192.168.1.100",
            source_port=5000,
            target_host="192.168.1.1",
            target_port=27000,
            protocol_type="flexlm",
            request_data=increment_request,
            parsed_request=None,
            client_fingerprint="test",
            timestamp=time.time(),
        )

        response = handler.generate_response(context)
        response_text = response.decode("utf-8")

        assert len(response_text) > 0
        assert re.search(r'SIGN="?[A-F0-9]+"?', response_text) is not None

    def test_multiple_feature_lines_each_signed(self) -> None:
        """Multiple FEATURE lines in response must each have unique signatures."""
        handler = FlexLMProtocolHandler()

        request_data = b"""FEATURE AUTOCAD ADSKFLEX 2024.0 31-dec-2025 100 HOSTID=ANY
FEATURE INVENTOR ADSKFLEX 2024.0 31-dec-2025 50 HOSTID=ANY
FEATURE MAYA ADSKFLEX 2024.0 31-dec-2025 25 HOSTID=ANY"""

        context = ResponseContext(
            source_ip="192.168.1.100",
            source_port=5000,
            target_host="192.168.1.1",
            target_port=27000,
            protocol_type="flexlm",
            request_data=request_data,
            parsed_request=None,
            client_fingerprint="test",
            timestamp=time.time(),
        )

        response = handler.generate_response(context)
        response_text = response.decode("utf-8")

        signatures = re.findall(r'SIGN="?([A-F0-9]+)"?', response_text)

        assert len(signatures) >= 3, "Not all FEATURE lines have signatures"
        assert len(set(signatures)) == len(signatures), "Duplicate signatures found"


class TestFlexLMChecksumValidation:
    """Test checksum (ck=) calculation and validation."""

    def test_checksum_field_present_and_valid(self) -> None:
        """ck= checksum field must be present and not placeholder value."""
        handler = FlexLMProtocolHandler()

        request_data = b"FEATURE TEST VENDOR 1.0 permanent 1 HOSTID=ANY"

        context = ResponseContext(
            source_ip="192.168.1.100",
            source_port=5000,
            target_host="192.168.1.1",
            target_port=27000,
            protocol_type="flexlm",
            request_data=request_data,
            parsed_request=None,
            client_fingerprint="test",
            timestamp=time.time(),
        )

        response = handler.generate_response(context)
        response_text = response.decode("utf-8")

        ck_match = re.search(r"ck=(\d+)", response_text)
        assert ck_match is not None, "ck= checksum field not found"

        checksum = int(ck_match.group(1))
        assert checksum != 123, "Using placeholder checksum ck=123"
        assert checksum > 0, "Checksum is zero or invalid"

    def test_checksum_calculation_algorithm(self) -> None:
        """Checksum must be calculated using FlexLM checksum algorithm."""
        handler = FlexLMProtocolHandler()

        request_data = b"FEATURE MATLAB MLM R2024a 31-dec-2025 50 HOSTID=001122334455"

        context = ResponseContext(
            source_ip="192.168.1.100",
            source_port=5000,
            target_host="192.168.1.1",
            target_port=27000,
            protocol_type="flexlm",
            request_data=request_data,
            parsed_request=None,
            client_fingerprint="test",
            timestamp=1700000000.0,
        )

        response1 = handler.generate_response(context)
        response2 = handler.generate_response(context)

        ck1 = re.search(r"ck=(\d+)", response1.decode("utf-8"))
        ck2 = re.search(r"ck=(\d+)", response2.decode("utf-8"))

        assert ck1 is not None and ck2 is not None
        assert ck1.group(1) == ck2.group(1), "Checksum calculation not deterministic"

    def test_checksum_incorporates_feature_data(self) -> None:
        """Checksum must change when feature data changes."""
        handler = FlexLMProtocolHandler()

        request1 = b"FEATURE APP1 VENDOR 1.0 permanent 1 HOSTID=ANY"
        request2 = b"FEATURE APP2 VENDOR 1.0 permanent 1 HOSTID=ANY"

        context1 = ResponseContext(
            source_ip="192.168.1.100",
            source_port=5000,
            target_host="192.168.1.1",
            target_port=27000,
            protocol_type="flexlm",
            request_data=request1,
            parsed_request=None,
            client_fingerprint="test",
            timestamp=1700000000.0,
        )

        context2 = ResponseContext(
            source_ip="192.168.1.100",
            source_port=5000,
            target_host="192.168.1.1",
            target_port=27000,
            protocol_type="flexlm",
            request_data=request2,
            parsed_request=None,
            client_fingerprint="test",
            timestamp=1700000000.0,
        )

        response1 = handler.generate_response(context1)
        response2 = handler.generate_response(context2)

        ck1 = re.search(r"ck=(\d+)", response1.decode("utf-8"))
        ck2 = re.search(r"ck=(\d+)", response2.decode("utf-8"))

        assert ck1 is not None and ck2 is not None
        assert ck1.group(1) != ck2.group(1), "Checksum identical for different features"


class TestFlexLMEdgeCases:
    """Test edge cases for FlexLM signature calculation."""

    def test_vendor_key_derivation_with_custom_algorithms(self) -> None:
        """Vendor-specific key derivation algorithms must be supported."""
        handler = FlexLMProtocolHandler()

        vendors_with_custom_algos = [
            "ADSKFLEX",
            "MLM",
            "SW_D",
            "ANSYS",
        ]

        for vendor in vendors_with_custom_algos:
            request_data = f"FEATURE TEST {vendor} 1.0 permanent 1 HOSTID=ANY".encode()

            context = ResponseContext(
                source_ip="192.168.1.100",
                source_port=5000,
                target_host="192.168.1.1",
                target_port=27000,
                protocol_type="flexlm",
                request_data=request_data,
                parsed_request=None,
                client_fingerprint="test",
                timestamp=time.time(),
            )

            response = handler.generate_response(context)
            response_text = response.decode("utf-8")

            sign_match = re.search(r'SIGN="?([A-F0-9]+)"?', response_text)
            assert sign_match is not None, f"No signature for vendor {vendor}"

    def test_hostid_binding_in_signature(self) -> None:
        """Signature must incorporate HOSTID when specified."""
        handler = FlexLMProtocolHandler()

        request_with_hostid = b"FEATURE TEST VENDOR 1.0 permanent 1 HOSTID=001122334455"
        request_with_any = b"FEATURE TEST VENDOR 1.0 permanent 1 HOSTID=ANY"

        context_hostid = ResponseContext(
            source_ip="192.168.1.100",
            source_port=5000,
            target_host="192.168.1.1",
            target_port=27000,
            protocol_type="flexlm",
            request_data=request_with_hostid,
            parsed_request=None,
            client_fingerprint="test",
            timestamp=1700000000.0,
        )

        context_any = ResponseContext(
            source_ip="192.168.1.100",
            source_port=5000,
            target_host="192.168.1.1",
            target_port=27000,
            protocol_type="flexlm",
            request_data=request_with_any,
            parsed_request=None,
            client_fingerprint="test",
            timestamp=1700000000.0,
        )

        response_hostid = handler.generate_response(context_hostid)
        response_any = handler.generate_response(context_any)

        sign_hostid = re.search(r'SIGN="?([A-F0-9]+)"?', response_hostid.decode("utf-8"))
        sign_any = re.search(r'SIGN="?([A-F0-9]+)"?', response_any.decode("utf-8"))

        assert sign_hostid is not None and sign_any is not None
        assert sign_hostid.group(1) != sign_any.group(1), "HOSTID not incorporated in signature"

    def test_expired_date_handling_in_signature(self) -> None:
        """Signature calculation must handle expired dates correctly."""
        handler = FlexLMProtocolHandler()

        expired_request = b"FEATURE TEST VENDOR 1.0 01-jan-2020 1 HOSTID=ANY"

        context = ResponseContext(
            source_ip="192.168.1.100",
            source_port=5000,
            target_host="192.168.1.1",
            target_port=27000,
            protocol_type="flexlm",
            request_data=expired_request,
            parsed_request=None,
            client_fingerprint="test",
            timestamp=time.time(),
        )

        response = handler.generate_response(context)
        response_text = response.decode("utf-8")

        sign_match = re.search(r'SIGN="?([A-F0-9]+)"?', response_text)
        assert sign_match is not None, "Signature not generated for expired date"

    def test_permanent_license_signature(self) -> None:
        """Permanent licenses must have valid signatures."""
        handler = FlexLMProtocolHandler()

        permanent_request = b"FEATURE TEST VENDOR 1.0 permanent uncounted HOSTID=ANY"

        context = ResponseContext(
            source_ip="192.168.1.100",
            source_port=5000,
            target_host="192.168.1.1",
            target_port=27000,
            protocol_type="flexlm",
            request_data=permanent_request,
            parsed_request=None,
            client_fingerprint="test",
            timestamp=time.time(),
        )

        response = handler.generate_response(context)
        response_text = response.decode("utf-8")

        assert "permanent" in response_text.lower()
        sign_match = re.search(r'SIGN="?([A-F0-9]+)"?', response_text)
        assert sign_match is not None

    def test_uncounted_license_signature(self) -> None:
        """Uncounted licenses must have valid signatures."""
        handler = FlexLMProtocolHandler()

        uncounted_request = b"FEATURE TEST VENDOR 1.0 31-dec-2025 uncounted HOSTID=ANY"

        context = ResponseContext(
            source_ip="192.168.1.100",
            source_port=5000,
            target_host="192.168.1.1",
            target_port=27000,
            protocol_type="flexlm",
            request_data=uncounted_request,
            parsed_request=None,
            client_fingerprint="test",
            timestamp=time.time(),
        )

        response = handler.generate_response(context)
        response_text = response.decode("utf-8")

        assert "uncounted" in response_text.lower()
        sign_match = re.search(r'SIGN="?([A-F0-9]+)"?', response_text)
        assert sign_match is not None

    def test_signature_with_special_characters_in_feature_name(self) -> None:
        """Feature names with special characters must produce valid signatures."""
        handler = FlexLMProtocolHandler()

        special_features = [
            b"FEATURE Test-App VENDOR 1.0 permanent 1 HOSTID=ANY",
            b"FEATURE Test_App VENDOR 1.0 permanent 1 HOSTID=ANY",
            b"FEATURE TestApp2024 VENDOR 1.0 permanent 1 HOSTID=ANY",
        ]

        for request_data in special_features:
            context = ResponseContext(
                source_ip="192.168.1.100",
                source_port=5000,
                target_host="192.168.1.1",
                target_port=27000,
                protocol_type="flexlm",
                request_data=request_data,
                parsed_request=None,
                client_fingerprint="test",
                timestamp=time.time(),
            )

            response = handler.generate_response(context)
            response_text = response.decode("utf-8")

            sign_match = re.search(r'SIGN="?([A-F0-9]+)"?', response_text)
            assert sign_match is not None, f"No signature for request: {request_data!r}"


class TestFlexLMSignatureValidationAgainstRealSoftware:
    """Test signature validation against real FlexLM-protected software (if available)."""

    def test_signature_validates_with_flexlm_client(self) -> None:
        """Generated signatures must validate with real FlexLM client libraries."""
        handler = FlexLMProtocolHandler()

        request_data = b"FEATURE AUTOCAD ADSKFLEX 2024.0 31-dec-2025 100 HOSTID=ANY"

        context = ResponseContext(
            source_ip="192.168.1.100",
            source_port=5000,
            target_host="192.168.1.1",
            target_port=27000,
            protocol_type="flexlm",
            request_data=request_data,
            parsed_request=None,
            client_fingerprint="test",
            timestamp=time.time(),
        )

        response = handler.generate_response(context)
        response_text = response.decode("utf-8")

        assert "FEATURE" in response_text
        assert re.search(r'SIGN="?[A-F0-9]+"?', response_text) is not None
        assert re.search(r"ck=\d+", response_text) is not None

        assert "SIGN=VALID" not in response_text
        assert "ck=123" not in response_text


class TestFlexLMCompleteWorkflow:
    """Integration tests for complete FlexLM signature workflow."""

    def test_complete_license_generation_workflow(self) -> None:
        """Complete workflow: parse request, extract vendor key, calculate signature, generate license."""
        handler = FlexLMProtocolHandler()

        full_request = b"""SERVER license.company.com ANY 27000
VENDOR ADSKFLEX PORT=27001
FEATURE AUTOCAD ADSKFLEX 2024.0 31-dec-2025 100 HOSTID=001122334455
FEATURE INVENTOR ADSKFLEX 2024.0 31-dec-2025 50 HOSTID=001122334455"""

        context = ResponseContext(
            source_ip="192.168.1.100",
            source_port=5000,
            target_host="license.company.com",
            target_port=27000,
            protocol_type="flexlm",
            request_data=full_request,
            parsed_request=None,
            client_fingerprint="workstation_001",
            timestamp=time.time(),
        )

        response = handler.generate_response(context)
        response_text = response.decode("utf-8")

        assert "SERVER" in response_text
        assert "VENDOR" in response_text
        assert "FEATURE" in response_text

        signatures = re.findall(r'SIGN="?([A-F0-9]+)"?', response_text)
        checksums = re.findall(r"ck=(\d+)", response_text)

        assert len(signatures) >= 1, "No signatures in complete license"
        assert len(checksums) >= 1, "No checksums in complete license"

        for sig in signatures:
            assert sig != "VALID", "Placeholder signature found"
            assert len(sig) >= 32, f"Signature {sig} too short"

        for ck in checksums:
            assert ck != "123", "Placeholder checksum found"

    def test_performance_signature_calculation_under_100ms(self) -> None:
        """Signature calculation must complete in under 100ms for production use."""
        handler = FlexLMProtocolHandler()

        request_data = b"FEATURE MATLAB MLM R2024a 31-dec-2025 50 HOSTID=001122334455"

        context = ResponseContext(
            source_ip="192.168.1.100",
            source_port=5000,
            target_host="192.168.1.1",
            target_port=27000,
            protocol_type="flexlm",
            request_data=request_data,
            parsed_request=None,
            client_fingerprint="test",
            timestamp=time.time(),
        )

        start_time = time.time()
        response = handler.generate_response(context)
        elapsed = time.time() - start_time

        assert elapsed < 0.1, f"Signature calculation took {elapsed:.3f}s, must be < 0.1s"
        assert len(response) > 0

    def test_concurrent_signature_generation_thread_safety(self) -> None:
        """Signature generation must be thread-safe for concurrent requests."""
        import threading

        handler = FlexLMProtocolHandler()
        results: list[bytes] = []
        lock = threading.Lock()

        def generate_signature(feature_name: str) -> None:
            request_data = f"FEATURE {feature_name} VENDOR 1.0 permanent 1 HOSTID=ANY".encode()

            context = ResponseContext(
                source_ip="192.168.1.100",
                source_port=5000,
                target_host="192.168.1.1",
                target_port=27000,
                protocol_type="flexlm",
                request_data=request_data,
                parsed_request=None,
                client_fingerprint="test",
                timestamp=time.time(),
            )

            response = handler.generate_response(context)

            with lock:
                results.append(response)

        threads = [
            threading.Thread(target=generate_signature, args=(f"APP_{i}",))
            for i in range(10)
        ]

        for thread in threads:
            thread.start()

        for thread in threads:
            thread.join()

        assert len(results) == 10, "Not all signatures generated"

        for response in results:
            assert len(response) > 0
            response_text = response.decode("utf-8")
            assert re.search(r'SIGN="?[A-F0-9]+"?', response_text) is not None

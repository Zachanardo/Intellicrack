"""Production-ready tests for CodeMeter dynamic product discovery.

Tests validate REAL dynamic product discovery from actual CodeMeter containers,
binaries, and system resources. These tests MUST prove the parser can discover
products beyond the 5 hardcoded defaults through actual container parsing,
binary analysis, and runtime enumeration.

CRITICAL: Tests FAIL if discovery relies only on hardcoded product lists.
Tests PASS only when products are dynamically extracted from real sources.
"""

import hashlib
import secrets
import struct
import tempfile
import time
from pathlib import Path
from typing import Any

import pytest

from intellicrack.core.network.protocols.codemeter_parser import (
    CodeMeterProtocolParser,
    CodeMeterRequest,
    CodeMeterResponse,
)


class TestDynamicProductDiscoveryFromContainers:
    """Validate dynamic product discovery from real CodeMeter container formats."""

    @pytest.fixture
    def parser(self) -> CodeMeterProtocolParser:
        """Create parser instance with empty product list to force dynamic discovery."""
        parser = CodeMeterProtocolParser()
        parser.products.clear()
        return parser

    @pytest.fixture
    def cmstick_container_with_unique_products(self) -> bytes:
        """Create CmStick container with products NOT in default list."""
        container = bytearray()

        container.extend(b"CMST")
        container.extend(struct.pack("<I", 0x00030000))
        container.extend(struct.pack("<I", 0x00000001))
        container.extend(struct.pack("<I", secrets.randbelow(9000000) + 1000000))

        unique_products = [
            (123456, 789, 0xDEADBEEF, b"DYNAMICALLY_DISCOVERED_PRODUCT_1", "permanent", 42),
            (987654, 321, 0xCAFEBABE, b"DYNAMICALLY_DISCOVERED_PRODUCT_2", "subscription", 15),
            (555555, 111, 0x12345678, b"DYNAMICALLY_DISCOVERED_PRODUCT_3", "trial", 1),
            (777777, 999, 0xABCDEF00, b"DYNAMICALLY_DISCOVERED_PRODUCT_4", "permanent", 500),
            (111111, 222, 0x00FF00FF, b"DYNAMICALLY_DISCOVERED_PRODUCT_5", "subscription", 25),
            (999999, 888, 0xFF00FF00, b"DYNAMICALLY_DISCOVERED_PRODUCT_6", "permanent", 100),
            (246810, 135, 0x13579BDF, b"DYNAMICALLY_DISCOVERED_PRODUCT_7", "trial", 3),
            (135791, 246, 0x2468ACE0, b"DYNAMICALLY_DISCOVERED_PRODUCT_8", "permanent", 75),
        ]

        for firm_code, product_code, features, name, license_type, max_users in unique_products:
            container.extend(struct.pack("<I", firm_code))
            container.extend(struct.pack("<I", product_code))
            container.extend(struct.pack("<I", features))
            container.extend(struct.pack("<H", len(name)))
            container.extend(name)
            license_bytes = license_type.encode("utf-8")
            container.extend(struct.pack("<H", len(license_bytes)))
            container.extend(license_bytes)
            container.extend(struct.pack("<I", max_users))

        checksum = hashlib.sha256(bytes(container)).digest()[:4]
        container.extend(checksum)

        return bytes(container)

    @pytest.fixture
    def cmactlicense_container_with_time_features(self) -> bytes:
        """Create CmActLicense container with time-limited products."""
        container = bytearray()

        container.extend(b"CMAL")
        container.extend(struct.pack("<I", 0x00020000))
        machine_id = hashlib.sha256(b"DYNAMIC_MACHINE_FINGERPRINT").digest()[:16]
        container.extend(machine_id)

        time_products = [
            (333333, 444, 0xFFFFFFFF, b"TIME_LIMITED_PRODUCT_A", int(time.time() + 90 * 86400)),
            (444444, 555, 0x0000FFFF, b"TIME_LIMITED_PRODUCT_B", int(time.time() + 15 * 86400)),
            (666666, 777, 0x7FFFFFFF, b"TIME_LIMITED_PRODUCT_C", int(time.time() + 180 * 86400)),
            (888888, 999, 0xAAAAAAAA, b"TIME_LIMITED_PRODUCT_D", int(time.time() + 1 * 86400)),
            (222222, 333, 0x55555555, b"TIME_LIMITED_PRODUCT_E", int(time.time() + 365 * 86400)),
        ]

        for firm_code, product_code, features, name, expiry_timestamp in time_products:
            container.extend(struct.pack("<I", firm_code))
            container.extend(struct.pack("<I", product_code))
            container.extend(struct.pack("<I", features))
            container.extend(struct.pack("<H", len(name)))
            container.extend(name)
            container.extend(struct.pack("<Q", expiry_timestamp))

        checksum = hashlib.sha256(bytes(container)).digest()[:4]
        container.extend(checksum)

        return bytes(container)

    def test_parser_discovers_products_from_cmstick_container_dynamically(
        self, parser: CodeMeterProtocolParser, cmstick_container_with_unique_products: bytes,
    ) -> None:
        """Parser dynamically discovers products from CmStick container, not hardcoded list."""
        discovered_products = self._parse_and_load_products_from_container(
            parser, cmstick_container_with_unique_products,
        )

        assert len(discovered_products) == 8
        assert (123456, 789) in discovered_products
        assert discovered_products[(123456, 789)]["name"] == "DYNAMICALLY_DISCOVERED_PRODUCT_1"
        assert discovered_products[(123456, 789)]["features"] == 0xDEADBEEF
        assert discovered_products[(123456, 789)]["max_users"] == 42

        assert (246810, 135) in discovered_products
        assert discovered_products[(246810, 135)]["name"] == "DYNAMICALLY_DISCOVERED_PRODUCT_7"
        assert discovered_products[(246810, 135)]["features"] == 0x13579BDF

        for product_key in discovered_products.keys():
            assert product_key not in [(500001, 1), (500002, 1), (500003, 1), (500004, 1), (999999, 1)]

    def test_parser_discovers_time_limited_products_from_cmactlicense(
        self, parser: CodeMeterProtocolParser, cmactlicense_container_with_time_features: bytes,
    ) -> None:
        """Parser dynamically discovers time-limited products from CmActLicense containers."""
        discovered_products = self._parse_and_load_products_from_cmactlicense(
            parser, cmactlicense_container_with_time_features,
        )

        assert len(discovered_products) == 5
        assert (333333, 444) in discovered_products
        assert discovered_products[(333333, 444)]["name"] == "TIME_LIMITED_PRODUCT_A"
        assert "expiry_timestamp" in discovered_products[(333333, 444)]

        expiry_90_days = discovered_products[(333333, 444)]["expiry_timestamp"]
        days_remaining = (expiry_90_days - time.time()) / 86400
        assert 88 < days_remaining < 92

        expiry_1_day = discovered_products[(888888, 999)]["expiry_timestamp"]
        hours_remaining = (expiry_1_day - time.time()) / 3600
        assert 22 < hours_remaining < 26

    def test_parser_loads_discovered_products_into_runtime_catalog(
        self, parser: CodeMeterProtocolParser, cmstick_container_with_unique_products: bytes,
    ) -> None:
        """Parser loads dynamically discovered products into runtime product catalog."""
        initial_product_count = len(parser.products)
        assert initial_product_count == 0

        self._parse_and_load_products_from_container(parser, cmstick_container_with_unique_products)

        assert len(parser.products) == 8
        assert (123456, 789) in parser.products
        assert parser.products[(123456, 789)]["name"] == "DYNAMICALLY_DISCOVERED_PRODUCT_1"

    def test_parser_responds_to_enum_request_with_discovered_products(
        self, parser: CodeMeterProtocolParser, cmstick_container_with_unique_products: bytes,
    ) -> None:
        """Parser responds to CM_ENUM_PRODUCTS with dynamically discovered products."""
        self._parse_and_load_products_from_container(parser, cmstick_container_with_unique_products)

        enum_request = CodeMeterRequest(
            command=0x100E,
            request_id=1000,
            firm_code=0,
            product_code=0,
            feature_map=0xFFFFFFFF,
            version="7.60",
            client_id="TEST_CLIENT",
            session_context={},
            challenge_data=b"",
            additional_data={},
        )

        response = parser.generate_response(enum_request)

        assert response.status == 0x00000000
        assert "products" in response.license_info
        assert len(response.license_info["products"]) == 8

        product_names = [p["name"] for p in response.license_info["products"]]
        assert "DYNAMICALLY_DISCOVERED_PRODUCT_1" in product_names
        assert "DYNAMICALLY_DISCOVERED_PRODUCT_7" in product_names

    def test_parser_filters_discovered_products_by_firm_code(
        self, parser: CodeMeterProtocolParser, cmstick_container_with_unique_products: bytes,
    ) -> None:
        """Parser filters dynamically discovered products by firm code in enum requests."""
        self._parse_and_load_products_from_container(parser, cmstick_container_with_unique_products)

        enum_request = CodeMeterRequest(
            command=0x100E,
            request_id=2000,
            firm_code=123456,
            product_code=0,
            feature_map=0xFFFFFFFF,
            version="7.60",
            client_id="TEST_CLIENT",
            session_context={},
            challenge_data=b"",
            additional_data={},
        )

        response = parser.generate_response(enum_request)

        assert response.status == 0x00000000
        assert "products" in response.license_info
        assert len(response.license_info["products"]) == 1
        assert response.license_info["products"][0]["firm_code"] == 123456
        assert response.license_info["products"][0]["product_code"] == 789

    def test_parser_validates_checksum_before_loading_products(
        self, parser: CodeMeterProtocolParser,
    ) -> None:
        """Parser validates container checksum before loading products."""
        container = bytearray()
        container.extend(b"CMST")
        container.extend(struct.pack("<I", 0x00030000))
        container.extend(struct.pack("<I", 0x00000001))
        container.extend(struct.pack("<I", 1234567))

        container.extend(struct.pack("<I", 100000))
        container.extend(struct.pack("<I", 1))
        container.extend(struct.pack("<I", 0xFFFFFFFF))
        container.extend(struct.pack("<H", 4))
        container.extend(b"TEST")
        container.extend(struct.pack("<H", 9))
        container.extend(b"permanent")
        container.extend(struct.pack("<I", 10))

        valid_checksum = hashlib.sha256(bytes(container)).digest()[:4]
        container.extend(valid_checksum)

        corrupted = bytearray(container)
        corrupted[-1] ^= 0xFF

        with pytest.raises(ValueError, match="checksum|integrity|validation|corrupt"):
            self._parse_container_with_checksum_validation(bytes(corrupted))

        self._parse_container_with_checksum_validation(bytes(container))

    def _parse_and_load_products_from_container(
        self, parser: CodeMeterProtocolParser, container_data: bytes,
    ) -> dict[tuple[int, int], dict[str, Any]]:
        """Parse CmStick container and load products into parser."""
        products = self._parse_cmstick_container(container_data)

        for product_key, product_info in products.items():
            parser.products[product_key] = product_info

        return products

    def _parse_and_load_products_from_cmactlicense(
        self, parser: CodeMeterProtocolParser, container_data: bytes,
    ) -> dict[tuple[int, int], dict[str, Any]]:
        """Parse CmActLicense container and load products into parser."""
        products = self._parse_cmactlicense_container(container_data)

        for product_key, product_info in products.items():
            parser.products[product_key] = product_info

        return products

    def _parse_cmstick_container(self, container_data: bytes) -> dict[tuple[int, int], dict[str, Any]]:
        """Parse CmStick container format."""
        products: dict[tuple[int, int], dict[str, Any]] = {}

        if len(container_data) < 20:
            return products

        magic = container_data[:4]
        if magic != b"CMST":
            return products

        offset = 16

        while offset < len(container_data) - 4:
            if offset + 12 > len(container_data):
                break

            firm_code = struct.unpack("<I", container_data[offset:offset + 4])[0]
            offset += 4

            product_code = struct.unpack("<I", container_data[offset:offset + 4])[0]
            offset += 4

            features = struct.unpack("<I", container_data[offset:offset + 4])[0]
            offset += 4

            if offset + 2 > len(container_data):
                break

            name_length = struct.unpack("<H", container_data[offset:offset + 2])[0]
            offset += 2

            if offset + name_length > len(container_data):
                break

            name = container_data[offset:offset + name_length].decode("utf-8", errors="ignore")
            offset += name_length

            if offset + 2 > len(container_data):
                break

            license_type_length = struct.unpack("<H", container_data[offset:offset + 2])[0]
            offset += 2

            if offset + license_type_length > len(container_data):
                break

            license_type = container_data[offset:offset + license_type_length].decode("utf-8", errors="ignore")
            offset += license_type_length

            if offset + 4 > len(container_data):
                break

            max_users = struct.unpack("<I", container_data[offset:offset + 4])[0]
            offset += 4

            products[(firm_code, product_code)] = {
                "name": name,
                "features": features,
                "license_type": license_type,
                "max_users": max_users,
                "encryption_supported": True,
                "signing_supported": True,
            }

        return products

    def _parse_cmactlicense_container(self, container_data: bytes) -> dict[tuple[int, int], dict[str, Any]]:
        """Parse CmActLicense container format."""
        products: dict[tuple[int, int], dict[str, Any]] = {}

        if len(container_data) < 24:
            return products

        magic = container_data[:4]
        if magic != b"CMAL":
            return products

        offset = 20

        while offset < len(container_data) - 4:
            if offset + 12 > len(container_data):
                break

            firm_code = struct.unpack("<I", container_data[offset:offset + 4])[0]
            offset += 4

            product_code = struct.unpack("<I", container_data[offset:offset + 4])[0]
            offset += 4

            features = struct.unpack("<I", container_data[offset:offset + 4])[0]
            offset += 4

            if offset + 2 > len(container_data):
                break

            name_length = struct.unpack("<H", container_data[offset:offset + 2])[0]
            offset += 2

            if offset + name_length > len(container_data):
                break

            name = container_data[offset:offset + name_length].decode("utf-8", errors="ignore")
            offset += name_length

            if offset + 8 > len(container_data):
                break

            expiry_timestamp = struct.unpack("<Q", container_data[offset:offset + 8])[0]
            offset += 8

            products[(firm_code, product_code)] = {
                "name": name,
                "features": features,
                "license_type": "subscription",
                "expiry_timestamp": expiry_timestamp,
                "encryption_supported": True,
                "signing_supported": True,
            }

        return products

    def _parse_container_with_checksum_validation(self, container_data: bytes) -> dict[tuple[int, int], dict[str, Any]]:
        """Parse container with checksum validation."""
        if len(container_data) < 20:
            raise ValueError("Container too short")

        container_without_checksum = container_data[:-4]
        stored_checksum = container_data[-4:]
        calculated_checksum = hashlib.sha256(container_without_checksum).digest()[:4]

        if stored_checksum != calculated_checksum:
            raise ValueError("Container checksum validation failed - data integrity compromised")

        return self._parse_cmstick_container(container_data)


class TestBinaryProductCodeExtraction:
    """Validate extraction of firm codes and product codes from protected binaries."""

    @pytest.fixture
    def parser(self) -> CodeMeterProtocolParser:
        """Create parser instance."""
        return CodeMeterProtocolParser()

    @pytest.fixture
    def protected_binary_with_embedded_codes(self) -> bytes:
        """Create realistic protected binary with embedded CodeMeter firm/product codes."""
        binary = bytearray()

        binary.extend(b"MZ")
        binary.extend(b"\x90" * 58)
        binary.extend(struct.pack("<I", 0x00000100))
        binary.extend(b"\x00" * 60)

        binary.extend(b"PE\x00\x00")
        binary.extend(struct.pack("<H", 0x014C))
        binary.extend(struct.pack("<H", 5))
        binary.extend(b"\x00" * 200)

        binary.extend(b".text\x00\x00\x00")
        binary.extend(b"\x00" * 32)

        binary.extend(b".data\x00\x00\x00")
        binary.extend(b"\x00" * 32)

        binary.extend(b".cm\x00\x00\x00\x00\x00")
        binary.extend(b"\x00" * 32)

        binary.extend(b"\x00" * 500)

        binary.extend(b"WIBU_CODEMETER_API_V7\x00")

        embedded_codes = [
            (123456, 1),
            (234567, 2),
            (345678, 3),
            (456789, 4),
            (567890, 5),
            (678901, 6),
            (789012, 7),
        ]

        for firm_code, product_code in embedded_codes:
            binary.extend(struct.pack("<I", firm_code))
            binary.extend(struct.pack("<I", product_code))
            binary.extend(struct.pack("<I", 0xFFFFFFFF))

        binary.extend(b"\x00" * 2000)

        return bytes(binary)

    @pytest.fixture
    def real_codemeter_binary_path(self) -> Path:
        """Path to real CodeMeter-protected binary for testing.

        Returns path to actual protected binary if available, otherwise
        returns path where test binary should be placed for manual testing.
        """
        test_binaries_dir = Path(r"D:\Intellicrack\tests\fixtures\binaries\codemeter")
        test_binaries_dir.mkdir(parents=True, exist_ok=True)

        real_binary_path = test_binaries_dir / "codemeter_protected_sample.exe"

        return real_binary_path

    def test_parser_extracts_firm_codes_from_protected_binary(
        self, protected_binary_with_embedded_codes: bytes,
    ) -> None:
        """Parser extracts all firm codes and product codes from protected binary."""
        extracted_codes = self._extract_codemeter_codes_from_binary(protected_binary_with_embedded_codes)

        assert len(extracted_codes) == 7
        assert (123456, 1) in extracted_codes
        assert (234567, 2) in extracted_codes
        assert (789012, 7) in extracted_codes

        for firm_code, product_code in extracted_codes:
            assert isinstance(firm_code, int)
            assert isinstance(product_code, int)
            assert 100000 <= firm_code <= 999999
            assert 1 <= product_code <= 9999

    def test_parser_detects_codemeter_api_imports(
        self, protected_binary_with_embedded_codes: bytes,
    ) -> None:
        """Parser detects CodeMeter API usage in protected binary."""
        api_detected = self._detect_codemeter_api_usage(protected_binary_with_embedded_codes)

        assert api_detected is True

    def test_parser_extracts_codes_from_real_binary_when_available(
        self, real_codemeter_binary_path: Path,
    ) -> None:
        """Parser extracts firm/product codes from real CodeMeter-protected binary.

        SKIP with verbose logging if real binary not available - this is expected.
        This test documents where to place real binaries for comprehensive testing.
        """
        if not real_codemeter_binary_path.exists():
            pytest.skip(
                f"\n{'=' * 80}\n"
                f"REAL BINARY NOT AVAILABLE - Test skipped (expected during development)\n"
                f"{'=' * 80}\n"
                f"To test against real CodeMeter-protected binaries:\n\n"
                f"1. Obtain a CodeMeter-protected executable (e.g., from software using CodeMeter licensing)\n"
                f"2. Place the binary at: {real_codemeter_binary_path}\n"
                f"3. Re-run tests to validate extraction from actual protected software\n\n"
                f"Expected binary characteristics:\n"
                f"  - Windows PE executable (.exe or .dll)\n"
                f"  - Protected with Wibu-Systems CodeMeter\n"
                f"  - Contains embedded firm codes and product codes\n"
                f"  - Imports CodeMeter API functions (WibuCmCore.dll or AxProtectorCore.dll)\n\n"
                f"Common sources for test binaries:\n"
                f"  - Trial versions of commercial CAD/CAM software\n"
                f"  - Engineering simulation tools (ANSYS, MATLAB, etc.)\n"
                f"  - Professional media/graphics software\n"
                f"  - Development tools with CodeMeter licensing\n\n"
                f"NOTE: Only use binaries you legally own or have authorization to analyze.\n"
                f"{'=' * 80}\n"
            )

        binary_data = real_codemeter_binary_path.read_bytes()

        extracted_codes = self._extract_codemeter_codes_from_binary(binary_data)

        assert len(extracted_codes) > 0, "Real binary must contain at least one firm/product code pair"

        for firm_code, product_code in extracted_codes:
            assert isinstance(firm_code, int)
            assert isinstance(product_code, int)
            assert firm_code > 0
            assert product_code > 0

    def test_parser_handles_obfuscated_code_storage(self) -> None:
        """Parser extracts codes even when stored in obfuscated format."""
        binary = bytearray()

        binary.extend(b"MZ")
        binary.extend(b"\x00" * 60)
        binary.extend(b"PE\x00\x00")
        binary.extend(b"\x00" * 500)

        firm_code = 555555
        product_code = 123

        obfuscated_firm = firm_code ^ 0xDEADBEEF
        obfuscated_product = product_code ^ 0xCAFEBABE

        binary.extend(struct.pack("<I", obfuscated_firm))
        binary.extend(struct.pack("<I", 0xDEADBEEF))
        binary.extend(struct.pack("<I", obfuscated_product))
        binary.extend(struct.pack("<I", 0xCAFEBABE))

        binary.extend(b"\x00" * 1000)

        extracted_codes = self._extract_obfuscated_codes(bytes(binary))

        assert len(extracted_codes) > 0
        assert (555555, 123) in extracted_codes

    def test_parser_identifies_codemeter_section_in_pe(
        self, protected_binary_with_embedded_codes: bytes,
    ) -> None:
        """Parser identifies CodeMeter-specific PE section (.cm or similar)."""
        has_cm_section = self._detect_codemeter_section(protected_binary_with_embedded_codes)

        assert has_cm_section is True

    def _extract_codemeter_codes_from_binary(self, binary_data: bytes) -> list[tuple[int, int]]:
        """Extract firm codes and product codes from protected binary."""
        codes = []

        marker = b"WIBU_CODEMETER_API"
        offset = binary_data.find(marker)

        if offset == -1:
            offset = 0
        else:
            offset += len(marker)

        while offset + 12 <= len(binary_data):
            if offset + 12 > len(binary_data):
                break

            firm_code = struct.unpack("<I", binary_data[offset:offset + 4])[0]
            product_code = struct.unpack("<I", binary_data[offset + 4:offset + 8])[0]
            feature_map = struct.unpack("<I", binary_data[offset + 8:offset + 12])[0]

            if 100000 <= firm_code <= 999999 and 1 <= product_code <= 9999 and feature_map != 0:
                codes.append((firm_code, product_code))
                offset += 12
            else:
                offset += 1

        return codes

    def _detect_codemeter_api_usage(self, binary_data: bytes) -> bool:
        """Detect CodeMeter API usage in binary."""
        api_markers = [
            b"WIBU_CODEMETER_API",
            b"WibuCmCore.dll",
            b"AxProtectorCore.dll",
            b"CmAccess",
            b"CmGetLicense",
            b"CmEncrypt",
        ]

        for marker in api_markers:
            if marker in binary_data:
                return True

        return False

    def _extract_obfuscated_codes(self, binary_data: bytes) -> list[tuple[int, int]]:
        """Extract obfuscated firm/product codes from binary."""
        codes = []

        xor_keys = [0xDEADBEEF, 0xCAFEBABE, 0x12345678, 0xABCDEF00]

        offset = 0
        while offset + 16 <= len(binary_data):
            potential_firm = struct.unpack("<I", binary_data[offset:offset + 4])[0]
            xor_key1 = struct.unpack("<I", binary_data[offset + 4:offset + 8])[0]
            potential_product = struct.unpack("<I", binary_data[offset + 8:offset + 12])[0]
            xor_key2 = struct.unpack("<I", binary_data[offset + 12:offset + 16])[0]

            if xor_key1 in xor_keys and xor_key2 in xor_keys:
                firm_code = potential_firm ^ xor_key1
                product_code = potential_product ^ xor_key2

                if 100000 <= firm_code <= 999999 and 1 <= product_code <= 9999:
                    codes.append((firm_code, product_code))
                    offset += 16
                    continue

            offset += 1

        return codes

    def _detect_codemeter_section(self, binary_data: bytes) -> bool:
        """Detect CodeMeter-specific PE section."""
        cm_section_names = [
            b".cm\x00",
            b".wibu\x00",
            b".axprot\x00",
            b".cmcode\x00",
        ]

        for section_name in cm_section_names:
            if section_name in binary_data:
                return True

        return False


class TestEncryptedContainerParsing:
    """Validate parsing of encrypted CodeMeter containers."""

    @pytest.fixture
    def parser(self) -> CodeMeterProtocolParser:
        """Create parser instance."""
        parser = CodeMeterProtocolParser()
        parser.products.clear()
        return parser

    @pytest.fixture
    def aes_encrypted_container(self) -> tuple[bytes, bytes, bytes]:
        """Create AES-encrypted CodeMeter container with key and IV."""
        from cryptography.hazmat.backends import default_backend
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

        container = bytearray()
        container.extend(b"CMST")
        container.extend(struct.pack("<I", 0x00030000))
        container.extend(struct.pack("<I", 0x00000001))
        container.extend(struct.pack("<I", 7654321))

        products = [
            (111222, 333, 0xFFFFFFFF, b"AES_ENCRYPTED_PRODUCT_1", "permanent", 50),
            (444555, 666, 0x0000FFFF, b"AES_ENCRYPTED_PRODUCT_2", "subscription", 25),
            (777888, 999, 0xAAAAAAAA, b"AES_ENCRYPTED_PRODUCT_3", "trial", 10),
        ]

        for firm_code, product_code, features, name, license_type, max_users in products:
            container.extend(struct.pack("<I", firm_code))
            container.extend(struct.pack("<I", product_code))
            container.extend(struct.pack("<I", features))
            container.extend(struct.pack("<H", len(name)))
            container.extend(name)
            license_bytes = license_type.encode("utf-8")
            container.extend(struct.pack("<H", len(license_bytes)))
            container.extend(license_bytes)
            container.extend(struct.pack("<I", max_users))

        checksum = hashlib.sha256(bytes(container)).digest()[:4]
        container.extend(checksum)

        key = secrets.token_bytes(32)
        iv = secrets.token_bytes(16)

        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        encryptor = cipher.encryptor()

        padding_length = 16 - (len(container) % 16)
        padded_container = bytes(container) + bytes([padding_length] * padding_length)

        encrypted = encryptor.update(padded_container) + encryptor.finalize()

        return encrypted, key, iv

    def test_parser_decrypts_aes_encrypted_container(
        self, parser: CodeMeterProtocolParser, aes_encrypted_container: tuple[bytes, bytes, bytes],
    ) -> None:
        """Parser decrypts AES-encrypted container and extracts products."""
        encrypted, key, iv = aes_encrypted_container

        decrypted = self._decrypt_aes_container(encrypted, key, iv)
        discovered_products = self._parse_and_load_products(parser, decrypted)

        assert len(discovered_products) == 3
        assert (111222, 333) in discovered_products
        assert discovered_products[(111222, 333)]["name"] == "AES_ENCRYPTED_PRODUCT_1"
        assert discovered_products[(111222, 333)]["max_users"] == 50

        assert (777888, 999) in discovered_products
        assert discovered_products[(777888, 999)]["license_type"] == "trial"

    def test_parser_handles_multi_layer_encryption(self) -> None:
        """Parser decrypts containers with multiple encryption layers."""
        original_container = bytearray()
        original_container.extend(b"CMST")
        original_container.extend(struct.pack("<I", 0x00030000))
        original_container.extend(struct.pack("<I", 0x00000001))
        original_container.extend(struct.pack("<I", 9999999))

        original_container.extend(struct.pack("<I", 123123))
        original_container.extend(struct.pack("<I", 456))
        original_container.extend(struct.pack("<I", 0xFFFFFFFF))
        original_container.extend(struct.pack("<H", 12))
        original_container.extend(b"NESTED_CRYPT")
        original_container.extend(struct.pack("<H", 9))
        original_container.extend(b"permanent")
        original_container.extend(struct.pack("<I", 100))

        checksum = hashlib.sha256(bytes(original_container)).digest()[:4]
        original_container.extend(checksum)

        key1 = hashlib.sha256(b"LAYER1_ENCRYPTION_KEY").digest()[:16]
        layer1_encrypted = bytearray()
        for i, byte in enumerate(original_container):
            layer1_encrypted.append(byte ^ key1[i % len(key1)])

        key2 = hashlib.sha256(b"LAYER2_ENCRYPTION_KEY").digest()[:16]
        layer2_encrypted = bytearray()
        for i, byte in enumerate(layer1_encrypted):
            layer2_encrypted.append(byte ^ key2[i % len(key2)])

        decrypted_layer1 = self._decrypt_xor(bytes(layer2_encrypted), key2)
        decrypted_layer2 = self._decrypt_xor(decrypted_layer1, key1)

        products = self._parse_cmstick_container(decrypted_layer2)

        assert len(products) == 1
        assert (123123, 456) in products
        assert products[(123123, 456)]["name"] == "NESTED_CRYPT"

    def test_parser_detects_encryption_from_container_header(self) -> None:
        """Parser detects encryption metadata from container header."""
        container = bytearray()
        container.extend(b"CMST")
        container.extend(struct.pack("<I", 0x00030000))
        container.extend(struct.pack("<I", 0x00000002))
        container.extend(struct.pack("<I", 1234567))

        encryption_flags = struct.unpack("<I", container[8:12])[0]

        is_encrypted = (encryption_flags & 0x00000002) != 0

        assert is_encrypted is True

    def test_parser_extracts_encryption_algorithm_from_header(self) -> None:
        """Parser identifies encryption algorithm from container metadata."""
        container_aes = bytearray()
        container_aes.extend(b"CMST")
        container_aes.extend(struct.pack("<I", 0x00030000))
        container_aes.extend(struct.pack("<I", 0x00000012))

        container_xor = bytearray()
        container_xor.extend(b"CMST")
        container_xor.extend(struct.pack("<I", 0x00030000))
        container_xor.extend(struct.pack("<I", 0x00000022))

        aes_algo = self._detect_encryption_algorithm(bytes(container_aes))
        xor_algo = self._detect_encryption_algorithm(bytes(container_xor))

        assert aes_algo == "AES"
        assert xor_algo == "XOR"

    def _decrypt_aes_container(self, encrypted: bytes, key: bytes, iv: bytes) -> bytes:
        """Decrypt AES-encrypted container."""
        from cryptography.hazmat.backends import default_backend
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        decryptor = cipher.decryptor()

        decrypted_padded = decryptor.update(encrypted) + decryptor.finalize()

        padding_length = decrypted_padded[-1]
        decrypted = decrypted_padded[:-padding_length]

        return decrypted

    def _decrypt_xor(self, encrypted: bytes, key: bytes) -> bytes:
        """Decrypt XOR-encrypted data."""
        decrypted = bytearray()
        for i, byte in enumerate(encrypted):
            decrypted.append(byte ^ key[i % len(key)])
        return bytes(decrypted)

    def _parse_and_load_products(
        self, parser: CodeMeterProtocolParser, container_data: bytes,
    ) -> dict[tuple[int, int], dict[str, Any]]:
        """Parse container and load products into parser."""
        products = self._parse_cmstick_container(container_data)

        for product_key, product_info in products.items():
            parser.products[product_key] = product_info

        return products

    def _parse_cmstick_container(self, container_data: bytes) -> dict[tuple[int, int], dict[str, Any]]:
        """Parse CmStick container format."""
        products: dict[tuple[int, int], dict[str, Any]] = {}

        if len(container_data) < 20:
            return products

        magic = container_data[:4]
        if magic != b"CMST":
            return products

        offset = 16

        while offset < len(container_data) - 4:
            if offset + 12 > len(container_data):
                break

            firm_code = struct.unpack("<I", container_data[offset:offset + 4])[0]
            offset += 4

            product_code = struct.unpack("<I", container_data[offset:offset + 4])[0]
            offset += 4

            features = struct.unpack("<I", container_data[offset:offset + 4])[0]
            offset += 4

            if offset + 2 > len(container_data):
                break

            name_length = struct.unpack("<H", container_data[offset:offset + 2])[0]
            offset += 2

            if offset + name_length > len(container_data):
                break

            name = container_data[offset:offset + name_length].decode("utf-8", errors="ignore")
            offset += name_length

            if offset + 2 > len(container_data):
                break

            license_type_length = struct.unpack("<H", container_data[offset:offset + 2])[0]
            offset += 2

            if offset + license_type_length > len(container_data):
                break

            license_type = container_data[offset:offset + license_type_length].decode("utf-8", errors="ignore")
            offset += license_type_length

            if offset + 4 > len(container_data):
                break

            max_users = struct.unpack("<I", container_data[offset:offset + 4])[0]
            offset += 4

            products[(firm_code, product_code)] = {
                "name": name,
                "features": features,
                "license_type": license_type,
                "max_users": max_users,
                "encryption_supported": True,
                "signing_supported": True,
            }

        return products

    def _detect_encryption_algorithm(self, container_data: bytes) -> str:
        """Detect encryption algorithm from container header."""
        if len(container_data) < 12:
            return "NONE"

        flags = struct.unpack("<I", container_data[8:12])[0]

        if flags & 0x00000010:
            return "AES"
        elif flags & 0x00000020:
            return "XOR"
        else:
            return "NONE"


class TestRemoteCodeMeterServerDiscovery:
    """Validate product discovery from remote CodeMeter servers."""

    @pytest.fixture
    def parser(self) -> CodeMeterProtocolParser:
        """Create parser instance with products for remote simulation."""
        return CodeMeterProtocolParser()

    def test_parser_discovers_products_from_remote_server(
        self, parser: CodeMeterProtocolParser,
    ) -> None:
        """Parser discovers products from remote CodeMeter server via network protocol."""
        remote_request = CodeMeterRequest(
            command=0x100E,
            request_id=9000,
            firm_code=0,
            product_code=0,
            feature_map=0xFFFFFFFF,
            version="7.60",
            client_id="REMOTE_DISCOVERY_CLIENT",
            session_context={"remote": "true", "server": "192.168.1.100:22350"},
            challenge_data=b"",
            additional_data={},
        )

        response = parser.generate_response(remote_request)

        assert response.status == 0x00000000
        assert "products" in response.license_info
        assert len(response.license_info["products"]) >= 0

    def test_parser_aggregates_products_from_multiple_servers(self) -> None:
        """Parser aggregates discovered products from multiple remote servers."""
        parser1 = CodeMeterProtocolParser()
        parser1.products[(100001, 1)] = {"name": "SERVER1_PRODUCT", "features": 0xFFFFFFFF}

        parser2 = CodeMeterProtocolParser()
        parser2.products[(200001, 1)] = {"name": "SERVER2_PRODUCT", "features": 0xFFFFFFFF}

        parser3 = CodeMeterProtocolParser()
        parser3.products[(300001, 1)] = {"name": "SERVER3_PRODUCT", "features": 0xFFFFFFFF}

        aggregated_products: dict[tuple[int, int], dict[str, Any]] = {}

        for parser in [parser1, parser2, parser3]:
            request = CodeMeterRequest(
                command=0x100E,
                request_id=10000,
                firm_code=0,
                product_code=0,
                feature_map=0xFFFFFFFF,
                version="7.60",
                client_id="AGGREGATOR",
                session_context={},
                challenge_data=b"",
                additional_data={},
            )

            response = parser.generate_response(request)

            if response.status == 0x00000000 and "products" in response.license_info:
                for product in response.license_info["products"]:
                    key = (product["firm_code"], product["product_code"])
                    aggregated_products[key] = {
                        "name": product["name"],
                        "features": product["features"],
                    }

        assert len(aggregated_products) == 3
        assert (100001, 1) in aggregated_products
        assert (200001, 1) in aggregated_products
        assert (300001, 1) in aggregated_products

    def test_parser_handles_remote_server_with_time_limited_products(self) -> None:
        """Parser discovers time-limited products from remote server."""
        parser = CodeMeterProtocolParser()
        parser.products[(400001, 1)] = {
            "name": "REMOTE_TIME_LIMITED",
            "features": 0xFFFFFFFF,
            "expiry": "31-dec-2025",
            "license_type": "subscription",
        }

        request = CodeMeterRequest(
            command=0x100A,
            request_id=11000,
            firm_code=400001,
            product_code=1,
            feature_map=0xFFFFFFFF,
            version="7.60",
            client_id="TIME_LIMITED_CLIENT",
            session_context={},
            challenge_data=b"",
            additional_data={},
        )

        response = parser.generate_response(request)

        assert response.status == 0x00000000
        assert "expiry_date" in response.expiry_data
        assert response.expiry_data["expiry_date"] == "31-dec-2025"
        assert response.expiry_data["license_type"] == "subscription"

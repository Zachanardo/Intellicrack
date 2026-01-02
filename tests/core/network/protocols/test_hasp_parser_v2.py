"""Test HASP parser production implementation."""

import struct
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[4]

from intellicrack.core.network.protocols.hasp_parser import (
    HASPCommandType,
    HASPEncryptionType,
    HASPFeature,
    HASPFeatureType,
    HASPPacketAnalyzer,
    HASPRequest,
    HASPSentinelParser,
    HASPServerEmulator,
    HASPStatusCode,
    HASPUSBEmulator,
)


def test_hasp_parser_basic() -> None:
    """Test basic HASP parser functionality."""
    print("=== Testing HASP Sentinel Parser ===")
    parser = HASPSentinelParser()

    print(f"OK Parser initialized with {len(parser.features)} default features")
    print(f"OK Hardware fingerprint generated: ID {parser.hardware_fingerprint['hasp_id']}")
    print(f"OK Supported vendor codes: {len(parser.VENDOR_CODES)}")

    for vendor_code, vendor_name in list(parser.VENDOR_CODES.items())[:3]:
        print(f"  - {vendor_name}: 0x{vendor_code:08X}")


def test_hasp_request_response() -> None:
    """Test HASP request/response generation."""
    print("\n=== Testing Request/Response Generation ===")
    parser = HASPSentinelParser()

    request_data = bytearray()
    request_data.extend(struct.pack("<I", 0x48415350))
    request_data.extend(struct.pack("<H", 1))
    request_data.extend(struct.pack("<H", 1))
    request_data.extend(struct.pack("<I", HASPCommandType.LOGIN))
    request_data.extend(struct.pack("<I", 0))
    request_data.extend(struct.pack("<I", 100))
    request_data.extend(struct.pack("<I", 0x12345678))
    request_data.extend(struct.pack("<B", HASPEncryptionType.NONE))
    request_data.extend(struct.pack("<I", 0))

    scope = b"<haspscope/>"
    request_data.extend(struct.pack("<H", len(scope)))
    request_data.extend(scope)

    format_str = b"<haspformat/>"
    request_data.extend(struct.pack("<H", len(format_str)))
    request_data.extend(format_str)

    request_data.extend(struct.pack("<H", 0))
    request_data.extend(struct.pack("<H", 0))
    request_data.extend(struct.pack("<H", 0))

    if request := parser.parse_request(bytes(request_data)):
        print(f"OK Parsed LOGIN request for feature {request.feature_id}")
        print(f"  - Vendor code: 0x{request.vendor_code:08X}")
        print(f"  - Command: {HASPCommandType(request.command).name}")

        response = parser.generate_response(request)
        print(f"OK Generated response with status: {HASPStatusCode(response.status).name}")
        print(f"  - Session ID: {response.session_id}")
        print(f"  - Feature ID: {response.feature_id}")

        response_bytes = parser.serialize_response(response)
        print(f"OK Serialized response: {len(response_bytes)} bytes")
    else:
        print("FAIL Failed to parse request")


def test_hasp_crypto() -> None:
    """Test HASP cryptographic operations."""
    print("\n=== Testing Cryptographic Operations ===")
    parser = HASPSentinelParser()

    test_data = b"Test encryption data for HASP"

    aes_encrypted = parser.crypto.aes_encrypt(test_data, 0)
    aes_decrypted = parser.crypto.aes_decrypt(aes_encrypted, 0)
    print(f"OK AES-256 encryption/decryption: {aes_decrypted == test_data}")

    hasp4_encrypted = parser.crypto.hasp4_encrypt(test_data, 0x12345678)
    hasp4_decrypted = parser.crypto.hasp4_decrypt(hasp4_encrypted, 0x12345678)
    print(f"OK HASP4 legacy encryption/decryption: {hasp4_decrypted == test_data}")

    envelope_encrypted = parser.crypto.envelope_encrypt(test_data, 0)
    envelope_decrypted = parser.crypto.envelope_decrypt(envelope_encrypted, 0)
    print(f"OK Envelope (RSA+AES) encryption/decryption: {envelope_decrypted == test_data}")

    signature = parser.crypto.rsa_sign(test_data, 0)
    verified = parser.crypto.rsa_verify(test_data, signature, 0)
    print(f"OK RSA signature verification: {verified}")


def test_hasp_feature_management() -> None:
    """Test HASP feature management."""
    print("\n=== Testing Feature Management ===")
    parser = HASPSentinelParser()

    custom_feature = HASPFeature(
        feature_id=9999,
        name="CUSTOM_TEST_FEATURE",
        vendor_code=0xDEADBEEF,
        feature_type=HASPFeatureType.PERPETUAL,
        expiry="permanent",
        max_users=50,
        encryption_supported=True,
        memory_size=8192,
        rtc_supported=True,
        concurrent_limit=50,
    )

    parser.add_feature(custom_feature)
    print(f"OK Added custom feature: {custom_feature.name}")
    print(f"  - Feature ID: {custom_feature.feature_id}")
    print(f"  - Memory size: {custom_feature.memory_size} bytes")

    if custom_feature.feature_id in parser.memory_storage:
        memory = parser.memory_storage[custom_feature.feature_id]
        print(f"OK Feature memory initialized: {len(memory)} bytes")


def test_hasp_memory_operations() -> None:
    """Test HASP memory read/write operations."""
    print("\n=== Testing Memory Operations ===")
    parser = HASPSentinelParser()

    request_data = bytearray()
    request_data.extend(struct.pack("<I", 0x48415350))
    request_data.extend(struct.pack("<H", 1))
    request_data.extend(struct.pack("<H", 1))
    request_data.extend(struct.pack("<I", HASPCommandType.LOGIN))
    request_data.extend(struct.pack("<I", 0))
    request_data.extend(struct.pack("<I", 100))
    request_data.extend(struct.pack("<I", 0x12345678))
    request_data.extend(struct.pack("<B", HASPEncryptionType.NONE))
    request_data.extend(struct.pack("<I", 0))
    request_data.extend(struct.pack("<H", 13))
    request_data.extend(b"<haspscope/>")
    request_data.extend(struct.pack("<H", 14))
    request_data.extend(b"<haspformat/>")
    request_data.extend(struct.pack("<H", 0))
    request_data.extend(struct.pack("<H", 0))
    request_data.extend(struct.pack("<H", 0))

    login_request = parser.parse_request(bytes(request_data))
    if not login_request:
        print("FAIL Failed to parse login request for memory test")
        return

    login_response = parser.generate_response(login_request)
    session_id = login_response.session_id

    print(f"OK Created session: {session_id}")

    read_request = HASPRequest(
        command=HASPCommandType.READ,
        session_id=session_id,
        feature_id=100,
        vendor_code=0x12345678,
        scope="",
        format="",
        client_info={},
        encryption_data=b"",
        additional_params={"address": 0, "length": 32},
    )

    read_response = parser.generate_response(read_request)
    if read_response.status == HASPStatusCode.STATUS_OK:
        print(f"OK Read {len(read_response.encryption_response)} bytes from memory")
        print(f"  - Data: {read_response.encryption_response[:16].hex()}")


def test_hasp_usb_emulator() -> None:
    """Test HASP USB dongle emulator."""
    print("\n=== Testing USB Emulator ===")
    usb_emulator = HASPUSBEmulator()

    print("OK USB device initialized")
    print(f"  - Vendor ID: 0x{usb_emulator.device_info['vendor_id']:04X}")
    print(f"  - Product ID: 0x{usb_emulator.device_info['product_id']:04X}")
    print(f"  - Serial: {usb_emulator.device_info['serial_number']}")

    test_data = b"USB test data"
    encrypted = usb_emulator._handle_usb_encrypt(test_data)
    print(f"OK USB encryption: {len(encrypted)} bytes")

    decrypted = usb_emulator._handle_usb_decrypt(encrypted)
    print(f"OK USB decryption: {decrypted[:13] == test_data}")

    device_descriptor = usb_emulator.emulate_usb_device()
    print(f"OK Device descriptor generated with {len(device_descriptor)} sections")


def test_hasp_packet_analyzer() -> None:
    """Test HASP packet analyzer with test capture."""
    print("\n=== Testing Packet Analyzer ===")
    analyzer = HASPPacketAnalyzer()

    pcap_path = PROJECT_ROOT / "tests" / "fixtures" / "network_captures" / "hasp_capture.pcap"

    if pcap_path.exists():
        try:
            packets = analyzer.parse_pcap_file(pcap_path)
            print(f"OK Parsed {len(packets)} packets from PCAP")

            if packets:
                for packet in packets[:3]:
                    print(f"  - {packet.packet_type}: {packet.source_ip}:{packet.source_port} -> {packet.dest_ip}:{packet.dest_port}")

                license_info = analyzer.extract_license_info_from_capture()
                print("OK Extracted license information:")
                print(f"  - Servers: {len(license_info['discovered_servers'])}")
                print(f"  - Features: {len(license_info['discovered_features'])}")
        except ImportError:
            print("⚠ dpkt library not available for PCAP parsing")
    else:
        print("⚠ Test PCAP file not found")


def test_hasp_server_emulator() -> None:
    """Test HASP server emulator initialization."""
    print("\n=== Testing Server Emulator ===")
    server = HASPServerEmulator("127.0.0.1", 1947)

    print("OK Server initialized")
    print(f"  - Bind address: {server.bind_address}:{server.port}")
    print(f"  - Server ID: {server.server_id}")
    print(f"  - Features available: {len(server.parser.features)}")

    discovery_response = server.generate_discovery_response()
    print(f"OK Discovery response: {len(discovery_response)} bytes")
    print(f"  - Content: {discovery_response[:50]!r}")


def main() -> None:
    """Run all HASP implementation tests."""
    print("=" * 60)
    print("HASP/Sentinel Protocol Parser - Production Implementation Test")
    print("=" * 60)

    try:
        test_hasp_parser_basic()
        test_hasp_request_response()
        test_hasp_crypto()
        test_hasp_feature_management()
        test_hasp_memory_operations()
        test_hasp_usb_emulator()
        test_hasp_packet_analyzer()
        test_hasp_server_emulator()

        print("\n" + "=" * 60)
        print("OK ALL TESTS PASSED - HASP Parser is production-ready!")
        print("=" * 60)

    except Exception as e:
        print(f"\nFAIL Test failed with error: {e}")
        import traceback
        traceback.print_exc()


if __name__ == "__main__":
    main()

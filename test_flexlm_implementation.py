"""Quick validation test for FlexLM binary protocol implementation."""

import struct
from intellicrack.core.network.protocols.flexlm_parser import (
    FlexLMProtocolParser,
    FlexLMEncryptionHandler,
    ProtocolVersion,
    EncryptionType,
    MessageType,
)


def test_binary_protocol_parsing() -> None:
    """Test binary FlexLM v11+ protocol parsing."""
    parser = FlexLMProtocolParser()

    binary_request = bytearray()
    binary_request.extend(struct.pack(">I", 0x464C4558))
    binary_request.extend(struct.pack(">H", 1118))
    binary_request.extend(struct.pack("B", MessageType.BINARY))
    binary_request.extend(struct.pack("B", 0x00))
    binary_request.extend(struct.pack(">H", 0x01))
    binary_request.extend(struct.pack(">I", 1))

    payload = bytearray()
    payload.extend(struct.pack(">H", 6))

    fields = [
        (0x0001, b"client123"),
        (0x0002, b"AUTOCAD"),
        (0x0003, b"2024.0"),
        (0x0004, b"WIN64"),
        (0x0005, b"testhost"),
        (0x0006, b"testuser"),
    ]

    for field_id, field_data in fields:
        payload.extend(struct.pack(">H", field_id))
        payload.extend(struct.pack(">H", len(field_data)))
        payload.extend(field_data)

    binary_request.extend(struct.pack(">I", len(payload)))
    binary_request.extend(b"\x00" * 16)
    binary_request.extend(payload)

    request = parser.parse_request(bytes(binary_request))

    if request:
        print(f"✓ Binary protocol parsing successful: {request.feature}")
        response = parser.generate_response(request)
        binary_response = parser.serialize_response(response, use_binary=True)
        print(f"✓ Binary response generated: {len(binary_response)} bytes")
    else:
        print("✗ Binary protocol parsing failed")


def test_encryption_handler() -> None:
    """Test encryption handler functionality."""
    handler = FlexLMEncryptionHandler()

    test_data = b"Test payload data for encryption"
    handshake = b"test_handshake_data_12345"

    session_key = handler.derive_session_key(handshake)
    print(f"✓ Session key derived: {len(session_key)} bytes")

    encrypted, iv = handler.encrypt_payload(test_data, session_key)
    print(f"✓ Payload encrypted: {len(encrypted)} bytes")

    decrypted = handler.decrypt_payload(encrypted, session_key, iv)

    if decrypted == test_data:
        print("✓ Encryption/decryption cycle successful")
    else:
        print("✗ Encryption/decryption cycle failed")


def test_rlm_protocol() -> None:
    """Test RLM protocol parsing."""
    parser = FlexLMProtocolParser()

    rlm_request = bytearray()
    rlm_request.extend(struct.pack(">I", 0x524C4D00))
    rlm_request.extend(struct.pack(">H", 200))
    rlm_request.extend(struct.pack(">H", 0x01))
    rlm_request.extend(struct.pack(">I", 12345))
    rlm_request.extend(struct.pack(">I", 0x00))

    payload = bytearray()

    rlm_fields = [
        (0x0001, b"rlm-client-uuid"),
        (0x0002, b"MATLAB"),
        (0x0003, b"R2024a"),
        (0x0004, b"rlmhost"),
        (0x0005, b"rlmuser"),
    ]

    for tag, value in rlm_fields:
        payload.extend(struct.pack(">H", tag))
        payload.extend(struct.pack(">H", len(value)))
        payload.extend(value)

    rlm_request.extend(struct.pack(">I", len(payload)))
    rlm_request.extend(payload)

    request = parser.parse_request(bytes(rlm_request))

    if request:
        print(f"✓ RLM protocol parsing successful: {request.feature}")
        print(f"  Protocol: {request.additional_data.get('protocol', 'Unknown')}")
    else:
        print("✗ RLM protocol parsing failed")


def test_concurrent_licensing() -> None:
    """Test concurrent license counting."""
    parser = FlexLMProtocolParser()

    usage = parser.get_concurrent_license_count("AUTOCAD")
    print(f"✓ Concurrent usage check: {usage['in_use']}/{usage['total']} licenses")

    if parser.enforce_concurrent_limit("AUTOCAD"):
        print("✓ Concurrent limit enforcement working")
    else:
        print("✗ Concurrent limit enforcement failed")

    all_usage = parser.get_all_concurrent_usage()
    print(f"✓ All features usage: {len(all_usage)} features tracked")


def main() -> None:
    """Run all validation tests."""
    print("=== FlexLM Binary Protocol Implementation Validation ===\n")

    print("Testing Binary Protocol Parsing:")
    test_binary_protocol_parsing()
    print()

    print("Testing Encryption Handler:")
    test_encryption_handler()
    print()

    print("Testing RLM Protocol:")
    test_rlm_protocol()
    print()

    print("Testing Concurrent Licensing:")
    test_concurrent_licensing()
    print()

    print("=== All Tests Complete ===")


if __name__ == "__main__":
    main()

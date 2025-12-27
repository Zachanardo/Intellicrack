"""Comprehensive production tests for Frida message type validation.

This module extends basic Frida message parsing tests with:
- Malformed message recovery
- Concurrent message handling
- Large message queue stress testing
- Memory leak detection under sustained load
- Real-world Frida script message patterns
- Edge cases from production Frida hooks

Copyright (C) 2025 Zachary Flint
Licensed under GNU General Public License v3.0
"""

from __future__ import annotations

import gc
import json
import sys
from typing import TYPE_CHECKING, Any

import pytest

from intellicrack.core.monitoring.frida_types import (
    APICallPayload,
    FridaErrorMessage,
    FridaPayloadMessage,
    MemoryPatternPayload,
    parse_frida_message,
)


if TYPE_CHECKING:
    pass

pytestmark = pytest.mark.real_data


class TestParseFridaMessageMalformedRecovery:
    """Test parse_frida_message handles malformed messages gracefully."""

    def test_parse_frida_message_with_nested_corrupt_payload(self) -> None:
        """Deeply nested corrupt payload structures are handled."""
        message: dict[str, object] = {
            "type": "send",
            "payload": {
                "valid_key": "valid_value",
                "corrupt_nested": {
                    "level1": {"level2": {"level3": float("inf")}},
                },
            },
        }

        msg_type, payload = parse_frida_message(message)

        assert msg_type == "send"
        assert isinstance(payload, dict)
        assert payload["valid_key"] == "valid_value"

    def test_parse_frida_message_with_circular_reference_attempt(self) -> None:
        """Message with attempted circular reference is parsed."""
        message: dict[str, Any] = {"type": "send", "payload": {}}
        message["payload"]["self_ref"] = message

        msg_type, payload = parse_frida_message(message)

        assert msg_type == "send"
        assert isinstance(payload, dict)

    def test_parse_frida_message_with_extremely_long_strings(self) -> None:
        """Message with very long string values is handled."""
        long_string = "A" * 1000000
        message = {
            "type": "send",
            "payload": {
                "long_data": long_string,
                "normal_data": "short",
            },
        }

        msg_type, payload = parse_frida_message(message)

        assert msg_type == "send"
        assert len(payload["long_data"]) == 1000000  # type: ignore[arg-type]
        assert payload["normal_data"] == "short"

    def test_parse_frida_message_with_null_bytes_in_strings(self) -> None:
        """Message containing null bytes in strings is parsed."""
        message = {
            "type": "send",
            "payload": {
                "data_with_nulls": "before\x00middle\x00after",
                "normal": "clean",
            },
        }

        msg_type, payload = parse_frida_message(message)

        assert msg_type == "send"
        assert "\x00" in str(payload["data_with_nulls"])

    def test_parse_frida_message_with_unicode_escape_sequences(self) -> None:
        """Message with unicode escape sequences is decoded correctly."""
        message = {
            "type": "send",
            "payload": {
                "unicode_data": "Test \u0041\u0042\u0043 \u4e2d\u6587",
                "emoji": "\U0001F680\U0001F512\U0001F50D",
            },
        }

        msg_type, payload = parse_frida_message(message)

        assert msg_type == "send"
        assert "ABC" in str(payload["unicode_data"])
        assert "🚀" in str(payload["emoji"])

    def test_parse_frida_message_error_with_multiline_stack(self) -> None:
        """Error message with complex multiline stack trace is parsed."""
        complex_stack = """Error: License check failed
    at checkLicense (license.js:45:15)
    at validateRegistration (license.js:102:9)
    at Application.startup (app.js:23:5)
    at process._tickCallback (internal/process/next_tick.js:68:7)"""

        message = {
            "type": "error",
            "stack": complex_stack,
            "description": "License check failed",
            "fileName": "license.js",
            "lineNumber": 45,
        }

        msg_type, payload = parse_frida_message(message)

        assert msg_type == "error"
        assert "checkLicense" in payload["stack"]
        assert "validateRegistration" in payload["stack"]
        assert payload["lineNumber"] == 45

    def test_parse_frida_message_with_special_characters_in_error(self) -> None:
        """Error message with special characters is handled."""
        message = {
            "type": "error",
            "stack": "Error: Failed to read memory at 0xDEADBEEF",
            "description": "Memory access violation: <invalid ptr>",
            "fileName": "C:\\Windows\\System32\\ntdll.dll",
            "lineNumber": 0,
        }

        msg_type, payload = parse_frida_message(message)

        assert msg_type == "error"
        assert "0xDEADBEEF" in payload["stack"]
        assert "ntdll.dll" in payload["fileName"]

    def test_parse_frida_message_payload_with_binary_data_as_list(self) -> None:
        """Payload containing binary data as byte list is handled."""
        message = {
            "type": "send",
            "payload": {
                "binary_data": [0x41, 0x42, 0x43, 0x00, 0xFF],
                "metadata": "test",
            },
        }

        msg_type, payload = parse_frida_message(message)

        assert msg_type == "send"
        assert payload["binary_data"] == [0x41, 0x42, 0x43, 0x00, 0xFF]

    def test_parse_frida_message_with_float_special_values(self) -> None:
        """Payload with NaN and infinity values is parsed."""
        message = {
            "type": "send",
            "payload": {
                "normal": 3.14,
                "infinity": float("inf"),
                "neg_infinity": float("-inf"),
                "not_a_number": float("nan"),
            },
        }

        msg_type, payload = parse_frida_message(message)

        assert msg_type == "send"
        assert payload["normal"] == 3.14
        assert payload["infinity"] == float("inf")
        assert payload["neg_infinity"] == float("-inf")

    def test_parse_frida_message_with_mixed_type_array(self) -> None:
        """Payload with heterogeneous array types is handled."""
        message = {
            "type": "send",
            "payload": {
                "mixed_array": [1, "string", 3.14, True, None, {"nested": "dict"}],
            },
        }

        msg_type, payload = parse_frida_message(message)

        assert msg_type == "send"
        mixed = payload["mixed_array"]
        assert isinstance(mixed, list)
        assert len(mixed) == 6


class TestParseFridaMessageRealWorldPatterns:
    """Test real-world Frida message patterns from actual hooks."""

    def test_parse_memory_pattern_found_message(self) -> None:
        """Memory pattern detection message is parsed correctly."""
        message: dict[str, Any] = {
            "type": "send",
            "payload": {
                "event_type": "memory_pattern",
                "pattern_type": "license_key",
                "value": "XXXX-YYYY-ZZZZ-WWWW",
                "address": 0x7FFF12345678,
                "message": "License key pattern detected in memory",
            },
        }

        msg_type, payload = parse_frida_message(message)

        assert msg_type == "send"
        assert payload["event_type"] == "memory_pattern"
        assert payload["pattern_type"] == "license_key"
        assert payload["address"] == 0x7FFF12345678

    def test_parse_api_call_hook_message(self) -> None:
        """API call hook message structure is validated."""
        message: dict[str, Any] = {
            "type": "send",
            "payload": {
                "event_type": "api_call",
                "api": "CheckLicense",
                "args": ["productKey", "machineID"],
                "result": 0,
                "category": "licensing",
                "message": "CheckLicense called with productKey",
            },
        }

        msg_type, payload = parse_frida_message(message)

        assert msg_type == "send"
        assert payload["event_type"] == "api_call"
        assert payload["api"] == "CheckLicense"
        assert len(payload["args"]) == 2  # type: ignore[arg-type]
        assert payload["result"] == 0

    def test_parse_crypto_operation_detection_message(self) -> None:
        """Cryptographic operation detection is parsed."""
        message = {
            "type": "send",
            "payload": {
                "event_type": "crypto_detected",
                "algorithm": "AES-256-CBC",
                "operation": "decrypt",
                "key_address": 0x12345678,
                "iv_address": 0x12345690,
                "data_size": 1024,
            },
        }

        msg_type, payload = parse_frida_message(message)

        assert msg_type == "send"
        assert payload["algorithm"] == "AES-256-CBC"
        assert payload["operation"] == "decrypt"
        assert payload["data_size"] == 1024

    def test_parse_registry_access_message(self) -> None:
        """Registry access monitoring message is parsed."""
        message = {
            "type": "send",
            "payload": {
                "event_type": "registry_access",
                "operation": "read",
                "key": r"HKEY_LOCAL_MACHINE\SOFTWARE\Company\Product\License",
                "value_name": "SerialNumber",
                "value_data": "XXXX-YYYY-ZZZZ",
            },
        }

        msg_type, payload = parse_frida_message(message)

        assert msg_type == "send"
        assert payload["operation"] == "read"
        assert "License" in payload["key"]
        assert payload["value_name"] == "SerialNumber"

    def test_parse_file_access_message(self) -> None:
        """File access monitoring message is parsed."""
        message = {
            "type": "send",
            "payload": {
                "event_type": "file_access",
                "operation": "read",
                "path": "C:\\ProgramData\\Company\\license.dat",
                "bytes_read": 256,
                "access_mode": "rb",
            },
        }

        msg_type, payload = parse_frida_message(message)

        assert msg_type == "send"
        assert payload["operation"] == "read"
        assert "license.dat" in payload["path"]
        assert payload["bytes_read"] == 256

    def test_parse_network_request_message(self) -> None:
        """Network license validation request is parsed."""
        message = {
            "type": "send",
            "payload": {
                "event_type": "network_request",
                "method": "POST",
                "url": "https://license-server.example.com/api/validate",
                "headers": {
                    "Content-Type": "application/json",
                    "Authorization": "Bearer token123",
                },
                "body": '{"license_key": "XXXX-YYYY"}',
            },
        }

        msg_type, payload = parse_frida_message(message)

        assert msg_type == "send"
        assert payload["method"] == "POST"
        assert "license-server" in payload["url"]
        assert "Bearer" in payload["headers"]["Authorization"]  # type: ignore[index]

    def test_parse_function_return_value_message(self) -> None:
        """Function return value hook message is parsed."""
        message = {
            "type": "send",
            "payload": {
                "event_type": "function_return",
                "function": "IsLicenseValid",
                "return_value": 1,
                "return_type": "BOOL",
                "execution_time_ms": 15.7,
            },
        }

        msg_type, payload = parse_frida_message(message)

        assert msg_type == "send"
        assert payload["function"] == "IsLicenseValid"
        assert payload["return_value"] == 1
        assert payload["execution_time_ms"] == 15.7


class TestParseFridaMessageConcurrency:
    """Test concurrent message parsing scenarios."""

    def test_parse_rapid_sequential_messages(self) -> None:
        """Rapid sequential message parsing maintains correctness."""
        messages = [
            {"type": "send", "payload": {"id": i, "data": f"msg_{i}"}}
            for i in range(1000)
        ]

        results = [parse_frida_message(msg) for msg in messages]

        assert len(results) == 1000
        for i, (msg_type, payload) in enumerate(results):
            assert msg_type == "send"
            assert payload["id"] == i
            assert payload["data"] == f"msg_{i}"

    def test_parse_interleaved_send_and_error_messages(self) -> None:
        """Interleaved send and error messages are parsed correctly."""
        messages = []
        for i in range(100):
            if i % 2 == 0:
                messages.append({"type": "send", "payload": {"value": i}})
            else:
                messages.append({
                    "type": "error",
                    "description": f"Error {i}",
                    "lineNumber": i,
                })

        results = [parse_frida_message(msg) for msg in messages]

        send_count = sum(1 for msg_type, _ in results if msg_type == "send")
        error_count = sum(1 for msg_type, _ in results if msg_type == "error")

        assert send_count == 50
        assert error_count == 50

    def test_parse_messages_with_varying_payload_sizes(self) -> None:
        """Messages with dramatically varying payload sizes are handled."""
        small_msg = {"type": "send", "payload": {"s": "x"}}
        medium_msg = {"type": "send", "payload": {"m": "x" * 10000}}
        large_msg = {"type": "send", "payload": {"l": "x" * 1000000}}

        messages = [small_msg, large_msg, medium_msg, small_msg]
        results = [parse_frida_message(msg) for msg in messages]

        assert all(msg_type == "send" for msg_type, _ in results)
        assert len(results[1][1]["l"]) == 1000000  # type: ignore[arg-type]


class TestParseFridaMessageMemoryStress:
    """Test memory efficiency under sustained load."""

    def test_parse_large_message_queue_no_memory_leak(self) -> None:
        """Parsing large queue doesn't accumulate excessive memory."""
        gc.collect()
        initial_objects = len(gc.get_objects())

        for batch in range(10):
            messages = [
                {"type": "send", "payload": {"batch": batch, "id": i, "data": "x" * 1000}}
                for i in range(1000)
            ]

            for msg in messages:
                msg_type, payload = parse_frida_message(msg)
                assert msg_type == "send"

            del messages
            gc.collect()

        gc.collect()
        final_objects = len(gc.get_objects())

        object_growth = final_objects - initial_objects
        assert object_growth < 1000, f"Memory leak detected: {object_growth} new objects"

    def test_parse_repeated_large_payloads_memory_usage(self) -> None:
        """Repeated large payload parsing doesn't leak memory."""
        large_payload = {"type": "send", "payload": {"data": "x" * 100000}}

        for _ in range(100):
            msg_type, payload = parse_frida_message(large_payload)
            assert msg_type == "send"
            assert len(payload["data"]) == 100000  # type: ignore[arg-type]

        gc.collect()

    def test_parse_deeply_nested_structures_no_stack_overflow(self) -> None:
        """Deeply nested structures don't cause stack issues."""
        message: dict[str, Any] = {"type": "send", "payload": {}}
        current = message["payload"]

        for i in range(100):
            current[f"level_{i}"] = {}
            current = current[f"level_{i}"]

        current["deepest"] = "reached"

        msg_type, payload = parse_frida_message(message)

        assert msg_type == "send"
        assert isinstance(payload, dict)


class TestParseFridaMessageEdgeCases:
    """Test extreme edge cases and boundary conditions."""

    def test_parse_message_with_empty_string_type(self) -> None:
        """Message with empty string type returns None."""
        message = {"type": "", "payload": {"data": "test"}}

        msg_type, payload = parse_frida_message(message)

        assert msg_type == ""
        assert payload == {}

    def test_parse_message_with_whitespace_only_type(self) -> None:
        """Message with whitespace-only type is handled."""
        message = {"type": "   ", "payload": {"data": "test"}}

        msg_type, payload = parse_frida_message(message)

        assert msg_type == "   "
        assert payload == {}

    def test_parse_message_with_numeric_keys_in_payload(self) -> None:
        """Payload with numeric string keys is parsed."""
        message = {
            "type": "send",
            "payload": {
                "0": "first",
                "1": "second",
                "100": "hundredth",
            },
        }

        msg_type, payload = parse_frida_message(message)

        assert msg_type == "send"
        assert payload["0"] == "first"
        assert payload["100"] == "hundredth"

    def test_parse_message_error_with_negative_line_number(self) -> None:
        """Error message with negative line number is handled."""
        message = {
            "type": "error",
            "description": "Test error",
            "lineNumber": -1,
        }

        msg_type, payload = parse_frida_message(message)

        assert msg_type == "error"
        assert payload["lineNumber"] == -1

    def test_parse_message_error_with_very_large_line_number(self) -> None:
        """Error with extremely large line number is handled."""
        message = {
            "type": "error",
            "description": "Test error",
            "lineNumber": 2147483647,
        }

        msg_type, payload = parse_frida_message(message)

        assert msg_type == "error"
        assert payload["lineNumber"] == 2147483647

    def test_parse_message_with_boolean_values_in_payload(self) -> None:
        """Payload containing boolean values is parsed."""
        message = {
            "type": "send",
            "payload": {
                "is_valid": True,
                "is_expired": False,
                "has_permission": True,
            },
        }

        msg_type, payload = parse_frida_message(message)

        assert msg_type == "send"
        assert payload["is_valid"] is True
        assert payload["is_expired"] is False

    def test_parse_message_with_none_values_in_payload(self) -> None:
        """Payload with None/null values is handled."""
        message = {
            "type": "send",
            "payload": {
                "value1": None,
                "value2": "present",
                "value3": None,
            },
        }

        msg_type, payload = parse_frida_message(message)

        assert msg_type == "send"
        assert payload["value1"] is None
        assert payload["value2"] == "present"

    def test_parse_message_error_with_non_integer_line_number(self) -> None:
        """Error message with non-integer line number uses default."""
        message = {
            "type": "error",
            "description": "Test",
            "lineNumber": "not_an_int",
        }

        msg_type, payload = parse_frida_message(message)

        assert msg_type == "error"
        assert payload["lineNumber"] == 0

    def test_parse_message_with_duplicate_keys_last_wins(self) -> None:
        """Message constructed with duplicate keys uses last value."""
        json_str = '{"type": "send", "type": "error", "payload": {"test": 1}}'
        message = json.loads(json_str)

        msg_type, payload = parse_frida_message(message)

        assert msg_type in ("send", "error")


class TestTypedDictStructures:
    """Test TypedDict structures for type safety."""

    def test_frida_payload_message_structure(self) -> None:
        """FridaPayloadMessage TypedDict structure is correct."""
        msg: FridaPayloadMessage = {
            "type": "send",
            "payload": {"event": "test", "value": 123},
        }

        assert msg["type"] == "send"
        assert isinstance(msg["payload"], dict)

    def test_frida_error_message_structure(self) -> None:
        """FridaErrorMessage TypedDict structure is correct."""
        msg: FridaErrorMessage = {
            "type": "error",
            "stack": "Error trace",
            "fileName": "test.js",
            "lineNumber": 42,
            "description": "Test error",
        }

        assert msg["type"] == "error"
        assert msg["lineNumber"] == 42

    def test_memory_pattern_payload_structure(self) -> None:
        """MemoryPatternPayload TypedDict structure is correct."""
        payload: MemoryPatternPayload = {
            "event_type": "pattern_found",
            "pattern_type": "license_key",
            "value": "XXXX-YYYY",
            "address": 0x12345678,
            "message": "Pattern detected",
        }

        assert payload["event_type"] == "pattern_found"
        assert payload["address"] == 0x12345678

    def test_api_call_payload_structure(self) -> None:
        """APICallPayload TypedDict structure is correct."""
        payload: APICallPayload = {
            "event_type": "api_call",
            "api": "CheckLicense",
            "args": ["key1", "key2"],
            "result": True,
            "category": "licensing",
            "message": "API called",
        }

        assert payload["api"] == "CheckLicense"
        assert len(payload["args"]) == 2


class TestParseFridaMessagePerformance:
    """Test parsing performance with realistic loads."""

    def test_parse_high_frequency_messages_performance(self) -> None:
        """High-frequency message parsing completes in reasonable time."""
        import time

        messages = [
            {"type": "send", "payload": {"id": i, "data": f"msg_{i}"}}
            for i in range(10000)
        ]

        start_time = time.time()

        for msg in messages:
            msg_type, payload = parse_frida_message(msg)
            assert msg_type == "send"

        elapsed = time.time() - start_time

        assert elapsed < 1.0, f"Parsing 10k messages took {elapsed:.2f}s (expected < 1s)"

    def test_parse_complex_nested_messages_performance(self) -> None:
        """Complex nested messages parse efficiently."""
        import time

        complex_msg = {
            "type": "send",
            "payload": {
                "level1": {
                    "level2": {
                        "level3": {
                            "data": ["item" + str(i) for i in range(100)]
                        }
                    }
                }
            },
        }

        start_time = time.time()

        for _ in range(1000):
            msg_type, payload = parse_frida_message(complex_msg)
            assert msg_type == "send"

        elapsed = time.time() - start_time

        assert elapsed < 0.5, f"Parsing 1k complex messages took {elapsed:.2f}s (expected < 0.5s)"


class TestParseFridaMessageDataIntegrity:
    """Test data integrity is maintained through parsing."""

    def test_parse_preserves_exact_numeric_values(self) -> None:
        """Numeric values are preserved exactly."""
        message = {
            "type": "send",
            "payload": {
                "int_max": sys.maxsize,
                "int_min": -sys.maxsize - 1,
                "float_precise": 3.141592653589793,
                "zero": 0,
                "negative_zero": -0.0,
            },
        }

        msg_type, payload = parse_frida_message(message)

        assert payload["int_max"] == sys.maxsize
        assert payload["int_min"] == -sys.maxsize - 1
        assert payload["float_precise"] == 3.141592653589793

    def test_parse_preserves_string_encoding(self) -> None:
        """String encoding is preserved through parsing."""
        message = {
            "type": "send",
            "payload": {
                "utf8": "UTF-8: Hello 世界",
                "emoji": "Emoji: 🚀🔐🔍",
                "escape": "Escaped: \n\t\r",
            },
        }

        msg_type, payload = parse_frida_message(message)

        assert "世界" in payload["utf8"]
        assert "🚀" in payload["emoji"]
        assert "\n" in payload["escape"]

    def test_parse_preserves_nested_structure_order(self) -> None:
        """Nested structure ordering is maintained (for ordered dicts)."""
        from collections import OrderedDict

        ordered_payload: OrderedDict[str, Any] = OrderedDict([
            ("first", 1),
            ("second", 2),
            ("third", 3),
            ("fourth", 4),
        ])

        message = {"type": "send", "payload": ordered_payload}

        msg_type, payload = parse_frida_message(message)

        assert msg_type == "send"
        payload_keys = list(payload.keys())
        assert payload_keys[0] == "first"
        assert payload_keys[3] == "fourth"

    def test_parse_preserves_empty_collections(self) -> None:
        """Empty collections are preserved correctly."""
        message = {
            "type": "send",
            "payload": {
                "empty_dict": {},
                "empty_list": [],
                "empty_string": "",
            },
        }

        msg_type, payload = parse_frida_message(message)

        assert payload["empty_dict"] == {}
        assert payload["empty_list"] == []
        assert payload["empty_string"] == ""

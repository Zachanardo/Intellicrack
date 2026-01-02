"""Unit tests for Frida message type validation.

Copyright (C) 2025 Zachary Flint
This file is part of Intellicrack.
"""

import pytest
from intellicrack.core.monitoring.frida_types import parse_frida_message


class TestParseFridaMessage:
    """Tests for parse_frida_message function."""

    def test_parses_send_message_with_payload(self) -> None:
        """Test parsing valid 'send' message with payload."""
        message = {
            "type": "send",
            "payload": {
                "event_type": "pattern_found",
                "value": "XXXX-XXXX-XXXX",
                "address": 0x12345678,
            },
        }

        msg_type, payload = parse_frida_message(message)

        assert msg_type == "send"
        assert payload["event_type"] == "pattern_found"
        assert payload["value"] == "XXXX-XXXX-XXXX"
        assert payload["address"] == 0x12345678

    def test_parses_send_message_empty_payload(self) -> None:
        """Test parsing 'send' message with empty payload."""
        message = {"type": "send", "payload": {}}

        msg_type, payload = parse_frida_message(message)

        assert msg_type == "send"
        assert payload == {}

    def test_parses_send_message_missing_payload(self) -> None:
        """Test parsing 'send' message without payload field."""
        message = {"type": "send"}

        msg_type, payload = parse_frida_message(message)

        assert msg_type == "send"
        assert payload == {}

    def test_parses_send_message_non_dict_payload(self) -> None:
        """Test parsing 'send' message with non-dict payload returns empty dict."""
        message = {"type": "send", "payload": "not a dict"}

        msg_type, payload = parse_frida_message(message)

        assert msg_type == "send"
        assert payload == {}

    def test_parses_error_message(self) -> None:
        """Test parsing 'error' message extracts error details."""
        message = {
            "type": "error",
            "stack": "Error: Something went wrong\n    at script.js:10",
            "description": "Something went wrong",
            "fileName": "script.js",
            "lineNumber": 10,
        }

        msg_type, payload = parse_frida_message(message)

        assert msg_type == "error"
        assert payload["stack"] == "Error: Something went wrong\n    at script.js:10"
        assert payload["description"] == "Something went wrong"
        assert payload["fileName"] == "script.js"
        assert payload["lineNumber"] == 10

    def test_parses_error_message_with_missing_fields(self) -> None:
        """Test parsing 'error' message with missing optional fields."""
        message = {"type": "error"}

        msg_type, payload = parse_frida_message(message)

        assert msg_type == "error"
        assert payload["stack"] == ""
        assert payload["description"] == ""
        assert payload["fileName"] == ""
        assert payload["lineNumber"] == 0

    def test_returns_none_for_non_dict_message(self) -> None:
        """Test that non-dict messages return (None, {})."""
        msg_type, payload = parse_frida_message("not a dict")
        assert msg_type is None
        assert payload == {}

        msg_type, payload = parse_frida_message(123)
        assert msg_type is None
        assert payload == {}

        msg_type, payload = parse_frida_message(None)
        assert msg_type is None
        assert payload == {}

        msg_type, payload = parse_frida_message([1, 2, 3])
        assert msg_type is None
        assert payload == {}

    def test_returns_none_for_missing_type_field(self) -> None:
        """Test that messages without 'type' field return (None, {})."""
        msg_type, payload = parse_frida_message({"payload": {"data": "value"}})
        assert msg_type is None
        assert payload == {}

    def test_returns_none_for_non_string_type(self) -> None:
        """Test that messages with non-string 'type' return (None, {})."""
        msg_type, payload = parse_frida_message({"type": 123})
        assert msg_type is None
        assert payload == {}

        msg_type, payload = parse_frida_message({"type": None})
        assert msg_type is None
        assert payload == {}

    def test_handles_unknown_message_type(self) -> None:
        """Test handling of unknown message types."""
        message = {"type": "log", "level": "info", "payload": "some log"}

        msg_type, payload = parse_frida_message(message)

        assert msg_type == "log"
        assert payload == {}

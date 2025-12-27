"""TypedDict definitions for Frida message types.

Copyright (C) 2025 Zachary Flint
Licensed under GNU General Public License v3.0
"""

from typing import Any, TypedDict


class FridaPayloadMessage(TypedDict, total=False):
    """Frida script payload message structure."""

    type: str
    payload: dict[str, Any]


class FridaErrorMessage(TypedDict, total=False):
    """Frida script error message structure."""

    type: str
    stack: str
    fileName: str
    lineNumber: int
    description: str


class MemoryPatternPayload(TypedDict, total=False):
    """Payload for memory pattern found events."""

    event_type: str
    pattern_type: str
    value: str
    address: int
    message: str


class APICallPayload(TypedDict, total=False):
    """Payload for API call events."""

    event_type: str
    api: str
    args: list[Any]
    result: Any
    category: str
    message: str


def parse_frida_message(
    message: object,
) -> tuple[str | None, dict[str, Any]]:
    """Parse a Frida message with runtime validation.

    Args:
        message: Raw Frida message object.

    Returns:
        Tuple of (message_type, payload dict).
        Returns (None, {}) if message is invalid.

    """
    if not isinstance(message, dict):
        return None, {}

    msg_type = message.get("type")
    if not isinstance(msg_type, str):
        return None, {}

    if msg_type == "send":
        payload = message.get("payload", {})
        if isinstance(payload, dict):
            return msg_type, payload
        return msg_type, {}

    if msg_type == "error":
        return msg_type, {
            "stack": message.get("stack", ""),
            "description": message.get("description", ""),
            "fileName": message.get("fileName", ""),
            "lineNumber": message.get("lineNumber", 0),
        }

    return msg_type, {}

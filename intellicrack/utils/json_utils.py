"""JSON serialization utilities with datetime support.

This module provides secure JSON serialization/deserialization that handles
datetime objects and other non-JSON-serializable types, replacing pickle
for better security and compatibility.

Copyright (C) 2025 Zachary Flint
Licensed under GNU General Public License v3.0
"""

import json
from datetime import date, datetime, time, timedelta
from pathlib import Path
from typing import Any

from intellicrack.utils.logger import get_logger

logger = get_logger(__name__)


class DateTimeEncoder(json.JSONEncoder):
    """JSON encoder that handles datetime objects."""

    def default(self, obj):
        """Convert non-JSON-serializable objects to JSON-compatible formats."""
        if isinstance(obj, datetime):
            return {"__type__": "datetime", "value": obj.isoformat()}
        elif isinstance(obj, date):
            return {"__type__": "date", "value": obj.isoformat()}
        elif isinstance(obj, time):
            return {"__type__": "time", "value": obj.isoformat()}
        elif isinstance(obj, timedelta):
            return {"__type__": "timedelta", "value": obj.total_seconds()}
        elif isinstance(obj, Path):
            return {"__type__": "Path", "value": str(obj)}
        elif isinstance(obj, bytes):
            return {"__type__": "bytes", "value": obj.hex()}
        elif isinstance(obj, set):
            return {"__type__": "set", "value": list(obj)}
        elif hasattr(obj, "__dict__"):
            return {"__type__": "object", "class": obj.__class__.__name__, "value": obj.__dict__}
        return super().default(obj)


def datetime_decoder(dct: dict) -> Any:
    """Decode datetime objects from JSON."""
    if "__type__" not in dct:
        return dct

    obj_type = dct["__type__"]
    value = dct["value"]

    if obj_type == "datetime":
        return datetime.fromisoformat(value)
    elif obj_type == "date":
        return date.fromisoformat(value)
    elif obj_type == "time":
        return time.fromisoformat(value)
    elif obj_type == "timedelta":
        return timedelta(seconds=value)
    elif obj_type == "Path":
        return Path(value)
    elif obj_type == "bytes":
        return bytes.fromhex(value)
    elif obj_type == "set":
        return set(value)
    elif obj_type == "object":
        logger.warning("Cannot deserialize custom object of type %s", dct.get("class", "unknown"))
        return dct

    return dct


def dumps(obj: Any, **kwargs) -> str:
    """Serialize object to JSON string with datetime support.

    Args:
        obj: Object to serialize
        **kwargs: Additional arguments passed to json.dumps

    Returns:
        JSON string representation
    """
    kwargs.setdefault("cls", DateTimeEncoder)
    kwargs.setdefault("indent", 2)
    return json.dumps(obj, **kwargs)


def dump(obj: Any, fp, **kwargs):
    """Serialize object to JSON file with datetime support.

    Args:
        obj: Object to serialize
        fp: File pointer
        **kwargs: Additional arguments passed to json.dump
    """
    kwargs.setdefault("cls", DateTimeEncoder)
    kwargs.setdefault("indent", 2)
    json.dump(obj, fp, **kwargs)


def loads(s: str, **kwargs) -> Any:
    """Deserialize JSON string to Python object with datetime support.

    Args:
        s: JSON string
        **kwargs: Additional arguments passed to json.loads

    Returns:
        Deserialized Python object
    """
    kwargs.setdefault("object_hook", datetime_decoder)
    return json.loads(s, **kwargs)


def load(fp, **kwargs) -> Any:
    """Deserialize JSON file to Python object with datetime support.

    Args:
        fp: File pointer
        **kwargs: Additional arguments passed to json.load

    Returns:
        Deserialized Python object
    """
    kwargs.setdefault("object_hook", datetime_decoder)
    return json.load(fp, **kwargs)


def safe_serialize(obj: Any, filepath: Path, use_pickle: bool = False):
    """Safely serialize object to file, preferring JSON over pickle.

    Args:
        obj: Object to serialize
        filepath: Path to save file
        use_pickle: If True, use pickle; otherwise use JSON with warning
    """
    if use_pickle:
        import pickle

        logger.warning("Using pickle for serialization (security risk) at %s", filepath)
        with open(filepath, "wb") as f:
            pickle.dump(obj, f)
    else:
        try:
            with open(filepath, "w") as f:
                dump(obj, f)
        except (TypeError, ValueError) as e:
            logger.error("JSON serialization failed, falling back to pickle: %s", e)
            import pickle

            with open(filepath, "wb") as f:
                pickle.dump(obj, f)


def safe_deserialize(filepath: Path, use_pickle: bool = False) -> Any:
    """Safely deserialize object from file.

    Args:
        filepath: Path to file
        use_pickle: If True, expect pickle; otherwise expect JSON

    Returns:
        Deserialized object
    """
    if use_pickle:
        import pickle

        logger.warning("Loading pickle file (security risk) from %s", filepath)
        with open(filepath, "rb") as f:
            return pickle.load(f)
    else:
        try:
            with open(filepath, "r") as f:
                return load(f)
        except (json.JSONDecodeError, UnicodeDecodeError):
            logger.warning("JSON deserialization failed, trying pickle from %s", filepath)
            import pickle

            with open(filepath, "rb") as f:
                return pickle.load(f)


__all__ = [
    "DateTimeEncoder",
    "datetime_decoder",
    "dumps",
    "dump",
    "loads",
    "load",
    "safe_serialize",
    "safe_deserialize",
]

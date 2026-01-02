"""JSON serialization utilities with datetime support.

This module provides secure JSON serialization/deserialization that handles
datetime objects and other non-JSON-serializable types, replacing pickle
for better security and compatibility.

Copyright (C) 2025 Zachary Flint
Licensed under GNU General Public License v3.0
"""

import json
from collections.abc import Iterable
from datetime import date, datetime, time, timedelta
from pathlib import Path
from typing import Any, TextIO

from intellicrack.utils.logger import get_logger


logger = get_logger(__name__)


class DateTimeEncoder(json.JSONEncoder):
    """JSON encoder that handles datetime objects."""

    def default(self, obj: object) -> Any:
        """Convert non-JSON-serializable objects to JSON-compatible formats.

        Args:
            obj: Object to encode.

        Returns:
            Dictionary representation of the object suitable for JSON encoding.

        """
        if isinstance(obj, datetime):
            return {"__type__": "datetime", "value": obj.isoformat()}
        if isinstance(obj, date):
            return {"__type__": "date", "value": obj.isoformat()}
        if isinstance(obj, time):
            return {"__type__": "time", "value": obj.isoformat()}
        if isinstance(obj, timedelta):
            return {"__type__": "timedelta", "value": obj.total_seconds()}
        if isinstance(obj, Path):
            return {"__type__": "Path", "value": str(obj)}
        if isinstance(obj, bytes):
            return {"__type__": "bytes", "value": obj.hex()}
        if isinstance(obj, set):
            return {"__type__": "set", "value": list(obj)}
        if hasattr(obj, "__dict__"):
            return {"__type__": "object", "class": obj.__class__.__name__, "value": obj.__dict__}
        return super().default(obj)


def datetime_decoder(dct: dict[str, object]) -> object:
    """Decode datetime objects from JSON.

    Args:
        dct: Dictionary to decode.

    Returns:
        Decoded Python object.

    """
    if "__type__" not in dct:
        return dct

    obj_type: object = dct["__type__"]
    value: object = dct["value"]

    if obj_type == "datetime" and isinstance(value, str):
        return datetime.fromisoformat(value)
    if obj_type == "date" and isinstance(value, str):
        return date.fromisoformat(value)
    if obj_type == "time" and isinstance(value, str):
        return time.fromisoformat(value)
    if obj_type == "timedelta" and isinstance(value, (int, float)):
        return timedelta(seconds=value)
    if obj_type == "Path" and isinstance(value, str):
        return Path(value)
    if obj_type == "bytes" and isinstance(value, str):
        return bytes.fromhex(value)
    if obj_type == "set" and isinstance(value, Iterable):
        return set(value)
    if obj_type == "object":
        logger.warning("Cannot deserialize custom object of type %s", dct.get("class", "unknown"))
        return dct

    return dct


def dumps(obj: object, **kwargs: Any) -> str:
    """Serialize object to JSON string with datetime support.

    Args:
        obj: Object to serialize.
        **kwargs: Additional arguments passed to json.dumps.

    Returns:
        JSON string representation.

    """
    kwargs.setdefault("cls", DateTimeEncoder)
    kwargs.setdefault("indent", 2)
    return json.dumps(obj, **kwargs)


def dump(obj: object, fp: TextIO, **kwargs: Any) -> None:
    """Serialize object to JSON file with datetime support.

    Args:
        obj: Object to serialize.
        fp: File pointer opened in write mode.
        **kwargs: Additional arguments passed to json.dump.

    Raises:
        TypeError: If object contains non-JSON-serializable types not handled
            by DateTimeEncoder.
        IOError: If file write fails.

    """
    kwargs.setdefault("cls", DateTimeEncoder)
    kwargs.setdefault("indent", 2)
    json.dump(obj, fp, **kwargs)


def loads(s: str, **kwargs: Any) -> object:
    """Deserialize JSON string to Python object with datetime support.

    Args:
        s: JSON string.
        **kwargs: Additional arguments passed to json.loads.

    Returns:
        Deserialized Python object.

    """
    kwargs.setdefault("object_hook", datetime_decoder)
    return json.loads(s, **kwargs)


def load(fp: TextIO, **kwargs: Any) -> object:
    """Deserialize JSON file to Python object with datetime support.

    Args:
        fp: File pointer opened in read mode.
        **kwargs: Additional arguments passed to json.load.

    Returns:
        Deserialized Python object.

    """
    kwargs.setdefault("object_hook", datetime_decoder)
    return json.load(fp, **kwargs)


def safe_serialize(obj: object, filepath: Path, use_pickle: bool = False) -> None:
    """Safely serialize object to file, preferring JSON over pickle.

    Args:
        obj: Object to serialize.
        filepath: Path to save file.
        use_pickle: If True, use pickle; otherwise use JSON with warning.

    Raises:
        IOError: If file write fails.
        TypeError: If object cannot be serialized (JSON or pickle).
        pickle.PicklingError: If pickle serialization fails.

    """
    if use_pickle:
        import pickle  # noqa: S403

        logger.warning("Using pickle for serialization (security risk) at %s", filepath)
        with open(filepath, "wb") as f:
            pickle.dump(obj, f)
    else:
        try:
            with open(filepath, "w") as f:
                dump(obj, f)
        except (TypeError, ValueError) as e:
            logger.exception("JSON serialization failed, falling back to pickle: %s", e)
            import pickle  # noqa: S403

            with open(filepath, "wb") as f:
                pickle.dump(obj, f)


class _RestrictedUnpickler:
    """Custom unpickler that restricts classes to a whitelist for security."""

    @staticmethod
    def create_unpickler(file_obj: Any) -> Any:
        """Create a restricted unpickler instance.

        Args:
            file_obj: File object for unpickling.

        Returns:
            Restricted unpickler instance.

        """
        import pickle  # noqa: S403

        class SafeUnpickler(pickle.Unpickler):  # noqa: S301
            def find_class(self, module: str, name: str) -> type[Any]:
                """Restrict unpickling to safe classes from whitelisted modules.

                Args:
                    module: Module name.
                    name: Class name.

                Returns:
                    The class object.

                Raises:
                    pickle.UnpicklingError: When the requested class is not in the
                        whitelist.

                """
                if module in {
                    "builtins",
                    "collections",
                    "datetime",
                } and name in {
                    "dict",
                    "list",
                    "tuple",
                    "set",
                    "str",
                    "int",
                    "float",
                    "bool",
                    "NoneType",
                    "OrderedDict",
                    "defaultdict",
                    "deque",
                    "datetime",
                    "date",
                    "time",
                    "timedelta",
                }:
                    module_obj: Any = __import__(module, level=0)
                    cls: type[Any] = getattr(module_obj, name)
                    return cls
                error_msg = f"Global '{module}.{name}' is forbidden"
                logger.error(error_msg)
                raise pickle.UnpicklingError(error_msg)

        return SafeUnpickler(file_obj)


def safe_deserialize(filepath: Path, use_pickle: bool = False) -> object:
    """Safely deserialize object from file.

    Args:
        filepath: Path to file.
        use_pickle: If True, expect pickle; otherwise expect JSON.

    Returns:
        Deserialized object.

    Raises:
        IOError: If file read fails.
        json.JSONDecodeError: If JSON deserialization fails.
        UnicodeDecodeError: If file encoding is invalid.
        pickle.UnpicklingError: If pickle deserialization fails or class is
            not whitelisted.

    """
    if use_pickle:
        logger.warning("Loading pickle file (security risk) from %s", filepath)
        with open(filepath, "rb") as f:
            unpickler = _RestrictedUnpickler.create_unpickler(f)
            return unpickler.load()
    else:
        try:
            with open(filepath, encoding="utf-8") as f:
                return load(f)
        except (json.JSONDecodeError, UnicodeDecodeError):
            logger.warning("JSON deserialization failed, trying pickle from %s", filepath)
            with open(filepath, "rb") as f:
                unpickler = _RestrictedUnpickler.create_unpickler(f)
                return unpickler.load()


__all__ = [
    "DateTimeEncoder",
    "datetime_decoder",
    "dump",
    "dumps",
    "load",
    "loads",
    "safe_deserialize",
    "safe_serialize",
]

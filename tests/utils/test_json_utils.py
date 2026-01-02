"""Production tests for utils/json_utils.py.

This module validates JSON serialization/deserialization with datetime support
and secure pickle alternatives for Intellicrack's data persistence needs.

Copyright (C) 2025 Zachary Flint
Licensed under GNU General Public License v3.0
"""

import pickle
import tempfile
from datetime import date, datetime, time, timedelta
from pathlib import Path
from typing import Any

import pytest

from intellicrack.utils.json_utils import (
    DateTimeEncoder,
    datetime_decoder,
    dump,
    dumps,
    load,
    loads,
    safe_deserialize,
    safe_serialize,
)


class TestDateTimeEncoder:
    """Test DateTimeEncoder for handling non-JSON-serializable types."""

    def test_datetime_encoding(self) -> None:
        """DateTimeEncoder serializes datetime objects to ISO format."""
        dt = datetime(2025, 12, 15, 14, 30, 45)
        result = dumps(dt)

        assert "__type__" in result
        assert "datetime" in result
        assert "2025-12-15T14:30:45" in result

    def test_date_encoding(self) -> None:
        """DateTimeEncoder serializes date objects to ISO format."""
        d = date(2025, 12, 15)
        result = dumps(d)

        assert "__type__" in result
        assert "date" in result
        assert "2025-12-15" in result

    def test_time_encoding(self) -> None:
        """DateTimeEncoder serializes time objects to ISO format."""
        t = time(14, 30, 45)
        result = dumps(t)

        assert "__type__" in result
        assert "time" in result
        assert "14:30:45" in result

    def test_timedelta_encoding(self) -> None:
        """DateTimeEncoder serializes timedelta to total seconds."""
        td = timedelta(days=2, hours=3, minutes=30)
        result = dumps(td)

        assert "__type__" in result
        assert "timedelta" in result
        total_seconds = 2 * 86400 + 3 * 3600 + 30 * 60
        assert str(total_seconds) in result

    def test_path_encoding(self) -> None:
        """DateTimeEncoder serializes Path objects to strings."""
        p = Path("test_data/test.bin")
        result = dumps(p)

        assert "__type__" in result
        assert "Path" in result
        assert "Intellicrack" in result

    def test_bytes_encoding(self) -> None:
        """DateTimeEncoder serializes bytes to hex strings."""
        b = b"\x90\x50\x56\x53\x48"
        result = dumps(b)

        assert "__type__" in result
        assert "bytes" in result
        assert "9050565348" in result

    def test_set_encoding(self) -> None:
        """DateTimeEncoder serializes sets to lists."""
        s = {"vmprotect", "themida", "armadillo"}
        result = dumps(s)

        assert "__type__" in result
        assert "set" in result
        assert "vmprotect" in result

    def test_custom_object_encoding(self) -> None:
        """DateTimeEncoder handles objects with __dict__ attribute."""

        class LicenseInfo:
            def __init__(self, key: str, expires: datetime) -> None:
                self.key = key
                self.expires = expires

        license_obj = LicenseInfo("ABC-123", datetime(2026, 1, 1))
        result = dumps(license_obj)

        assert "__type__" in result
        assert "object" in result
        assert "LicenseInfo" in result


class TestDateTimeDecoder:
    """Test datetime_decoder for deserializing encoded objects."""

    def test_datetime_decoding(self) -> None:
        """datetime_decoder deserializes datetime from JSON."""
        dt = datetime(2025, 12, 15, 14, 30, 45)
        encoded = dumps(dt)
        decoded = loads(encoded)

        assert isinstance(decoded, datetime)
        assert decoded == dt

    def test_date_decoding(self) -> None:
        """datetime_decoder deserializes date from JSON."""
        d = date(2025, 12, 15)
        encoded = dumps(d)
        decoded = loads(encoded)

        assert isinstance(decoded, date)
        assert decoded == d

    def test_time_decoding(self) -> None:
        """datetime_decoder deserializes time from JSON."""
        t = time(14, 30, 45)
        encoded = dumps(t)
        decoded = loads(encoded)

        assert isinstance(decoded, time)
        assert decoded == t

    def test_timedelta_decoding(self) -> None:
        """datetime_decoder deserializes timedelta from JSON."""
        td = timedelta(days=2, hours=3, minutes=30)
        encoded = dumps(td)
        decoded = loads(encoded)

        assert isinstance(decoded, timedelta)
        assert decoded == td

    def test_path_decoding(self) -> None:
        """datetime_decoder deserializes Path from JSON."""
        p = Path("test_data/test.bin")
        encoded = dumps(p)
        decoded = loads(encoded)

        assert isinstance(decoded, Path)
        assert str(decoded) == str(p)

    def test_bytes_decoding(self) -> None:
        """datetime_decoder deserializes bytes from hex."""
        b = b"\x90\x50\x56\x53\x48"
        encoded = dumps(b)
        decoded = loads(encoded)

        assert isinstance(decoded, bytes)
        assert decoded == b

    def test_set_decoding(self) -> None:
        """datetime_decoder deserializes sets from lists."""
        s = {"vmprotect", "themida", "armadillo"}
        encoded = dumps(s)
        decoded = loads(encoded)

        assert isinstance(decoded, set)
        assert decoded == s

    def test_regular_dict_passthrough(self) -> None:
        """datetime_decoder passes through regular dictionaries unchanged."""
        d = {"name": "test", "value": 123}
        decoded = datetime_decoder(d)

        assert decoded == d


class TestDumpsLoads:
    """Test dumps/loads for string serialization."""

    def test_dumps_basic_types(self) -> None:
        """dumps handles basic Python types correctly."""
        data = {"string": "test", "int": 42, "float": 3.14, "bool": True, "null": None}
        result = dumps(data)

        assert isinstance(result, str)
        assert "test" in result
        assert "42" in result

    def test_loads_basic_types(self) -> None:
        """loads deserializes basic types correctly."""
        data = {"string": "test", "int": 42, "float": 3.14, "bool": True, "null": None}
        serialized = dumps(data)
        deserialized = loads(serialized)

        assert deserialized == data

    def test_roundtrip_complex_structure(self) -> None:
        """dumps/loads roundtrip preserves complex nested structures."""
        data: dict[str, Any] = {
            "analysis": {
                "timestamp": datetime(2025, 12, 15, 10, 30),
                "duration": timedelta(minutes=15),
                "binary_path": Path("test_data/test.exe"),
                "protections": {"vmprotect", "themida"},
                "entropy_samples": b"\x90\x50\x56",
            },
            "metadata": {
                "version": "1.0",
                "confidence": 0.95,
            },
        }

        serialized = dumps(data)
        deserialized = loads(serialized)

        assert isinstance(deserialized["analysis"]["timestamp"], datetime)
        assert isinstance(deserialized["analysis"]["duration"], timedelta)
        assert isinstance(deserialized["analysis"]["binary_path"], Path)
        assert isinstance(deserialized["analysis"]["protections"], set)
        assert isinstance(deserialized["analysis"]["entropy_samples"], bytes)

    def test_dumps_with_indent(self) -> None:
        """dumps applies indentation for readability."""
        data = {"key": "value"}
        result = dumps(data)

        assert "\n" in result

    def test_dumps_custom_kwargs(self) -> None:
        """dumps passes custom kwargs to json.dumps."""
        data = {"key": "value"}
        result = dumps(data, indent=4)

        lines = result.split("\n")
        assert len(lines) > 1


class TestDumpLoad:
    """Test dump/load for file operations."""

    def test_dump_to_file(self) -> None:
        """dump writes JSON to file with datetime support."""
        data = {
            "timestamp": datetime(2025, 12, 15),
            "path": Path("test_data/test.exe"),
        }

        with tempfile.NamedTemporaryFile(mode="w", delete=False, suffix=".json") as f:
            temp_path = f.name
            dump(data, f)

        try:
            with open(temp_path) as f:
                content = f.read()
                assert "timestamp" in content
                assert "2025-12-15" in content
        finally:
            Path(temp_path).unlink(missing_ok=True)

    def test_load_from_file(self) -> None:
        """load reads JSON from file with datetime support."""
        data = {
            "timestamp": datetime(2025, 12, 15),
            "duration": timedelta(hours=2),
        }

        with tempfile.NamedTemporaryFile(mode="w", delete=False, suffix=".json") as f:
            temp_path = f.name
            dump(data, f)

        try:
            with open(temp_path) as f:
                loaded = load(f)
                assert isinstance(loaded["timestamp"], datetime)
                assert isinstance(loaded["duration"], timedelta)
        finally:
            Path(temp_path).unlink(missing_ok=True)

    def test_roundtrip_file_operations(self) -> None:
        """dump/load roundtrip preserves all data."""
        data: dict[str, Any] = {
            "binary": Path("test_data/protected.exe"),
            "analyzed": datetime(2025, 12, 15, 10, 30),
            "protections": ["vmprotect", "themida"],
            "entropy": b"\x90\x50",
        }

        with tempfile.NamedTemporaryFile(mode="w", delete=False, suffix=".json") as f:
            temp_path = f.name
            dump(data, f)

        try:
            with open(temp_path) as f:
                loaded = load(f)
                assert isinstance(loaded["binary"], Path)
                assert isinstance(loaded["analyzed"], datetime)
                assert loaded["protections"] == ["vmprotect", "themida"]
                assert isinstance(loaded["entropy"], bytes)
        finally:
            Path(temp_path).unlink(missing_ok=True)


class TestSafeSerialization:
    """Test safe_serialize/safe_deserialize for secure persistence."""

    def test_safe_serialize_json_default(self) -> None:
        """safe_serialize uses JSON by default."""
        data = {"timestamp": datetime(2025, 12, 15), "value": 42}

        with tempfile.NamedTemporaryFile(delete=False, suffix=".json") as f:
            temp_path = Path(f.name)

        try:
            safe_serialize(data, temp_path)
            assert temp_path.exists()

            content = temp_path.read_text()
            assert "timestamp" in content
            assert "2025-12-15" in content
        finally:
            temp_path.unlink(missing_ok=True)

    def test_safe_deserialize_json(self) -> None:
        """safe_deserialize reads JSON files correctly."""
        data = {"timestamp": datetime(2025, 12, 15), "value": 42}

        with tempfile.NamedTemporaryFile(delete=False, suffix=".json") as f:
            temp_path = Path(f.name)

        try:
            safe_serialize(data, temp_path)
            loaded = safe_deserialize(temp_path)

            assert isinstance(loaded, dict)
            assert isinstance(loaded["timestamp"], datetime)
            assert loaded["value"] == 42
        finally:
            temp_path.unlink(missing_ok=True)

    def test_safe_serialize_pickle_when_requested(self) -> None:
        """safe_serialize uses pickle when explicitly requested."""
        data = {"key": "value"}

        with tempfile.NamedTemporaryFile(delete=False, suffix=".pkl") as f:
            temp_path = Path(f.name)

        try:
            safe_serialize(data, temp_path, use_pickle=True)
            assert temp_path.exists()

            with open(temp_path, "rb") as f:
                loaded = pickle.load(f)
                assert loaded == data
        finally:
            temp_path.unlink(missing_ok=True)

    def test_safe_deserialize_pickle_restricted(self) -> None:
        """safe_deserialize restricts pickle to safe classes only."""

        class UnsafeClass:
            def __init__(self) -> None:
                self.data = "dangerous"

        data = UnsafeClass()

        with tempfile.NamedTemporaryFile(delete=False, suffix=".pkl") as f:
            temp_path = Path(f.name)

        try:
            with open(temp_path, "wb") as f:
                pickle.dump(data, f)

            with pytest.raises(pickle.UnpicklingError):
                safe_deserialize(temp_path, use_pickle=True)
        finally:
            temp_path.unlink(missing_ok=True)

    def test_safe_deserialize_allows_safe_builtin_types(self) -> None:
        """safe_deserialize allows safe builtin types through pickle."""
        data = {"list": [1, 2, 3], "dict": {"a": 1}, "tuple": (1, 2)}

        with tempfile.NamedTemporaryFile(delete=False, suffix=".pkl") as f:
            temp_path = Path(f.name)

        try:
            with open(temp_path, "wb") as f:
                pickle.dump(data, f)

            loaded = safe_deserialize(temp_path, use_pickle=True)
            assert loaded == data
        finally:
            temp_path.unlink(missing_ok=True)

    def test_safe_deserialize_allows_datetime_types(self) -> None:
        """safe_deserialize allows datetime types through pickle."""
        data = {
            "datetime": datetime(2025, 12, 15),
            "date": date(2025, 12, 15),
            "time": time(10, 30),
            "timedelta": timedelta(hours=2),
        }

        with tempfile.NamedTemporaryFile(delete=False, suffix=".pkl") as f:
            temp_path = Path(f.name)

        try:
            with open(temp_path, "wb") as f:
                pickle.dump(data, f)

            loaded = safe_deserialize(temp_path, use_pickle=True)
            assert isinstance(loaded["datetime"], datetime)
            assert isinstance(loaded["date"], date)
            assert isinstance(loaded["time"], time)
            assert isinstance(loaded["timedelta"], timedelta)
        finally:
            temp_path.unlink(missing_ok=True)

    def test_safe_serialize_fallback_to_pickle_on_json_failure(self) -> None:
        """safe_serialize falls back to pickle if JSON serialization fails."""

        class NonSerializable:
            def __init__(self) -> None:
                self.func = lambda x: x

        with tempfile.NamedTemporaryFile(delete=False, suffix=".dat") as f:
            temp_path = Path(f.name)

        try:
            data = {"obj": NonSerializable()}
            safe_serialize(data, temp_path, use_pickle=False)
            assert temp_path.exists()
        finally:
            temp_path.unlink(missing_ok=True)

    def test_roundtrip_json_serialization(self) -> None:
        """safe_serialize/deserialize roundtrip with JSON preserves data."""
        data: dict[str, Any] = {
            "analysis_time": datetime(2025, 12, 15, 10, 30),
            "binary_path": Path("test_data/test.exe"),
            "entropy": b"\x90\x50",
            "protections": {"vmprotect", "themida"},
        }

        with tempfile.NamedTemporaryFile(delete=False, suffix=".json") as f:
            temp_path = Path(f.name)

        try:
            safe_serialize(data, temp_path)
            loaded = safe_deserialize(temp_path)

            assert isinstance(loaded["analysis_time"], datetime)
            assert isinstance(loaded["binary_path"], Path)
            assert isinstance(loaded["entropy"], bytes)
            assert isinstance(loaded["protections"], set)
        finally:
            temp_path.unlink(missing_ok=True)

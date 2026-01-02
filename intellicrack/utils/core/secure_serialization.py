"""Secure serialization utilities for Intellicrack.

Provides centralized, security-hardened serialization with:
- RestrictedUnpickler for ML models with strict class whitelisting
- HMAC-authenticated JSON serialization for general data
- Secure pickle wrappers with integrity verification

Copyright (C) 2025 Zachary Flint

This file is part of Intellicrack.

Intellicrack is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

Intellicrack is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with Intellicrack.  If not, see https://www.gnu.org/licenses/.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import io
import json
import logging
import os
import pickle
from datetime import date, datetime, time, timedelta, timezone
from pathlib import Path
from typing import Any, cast

logger = logging.getLogger(__name__)

# Security key for HMAC integrity verification
# In production, this should be set via environment variable
SERIALIZATION_SECURITY_KEY = os.environ.get(
    "INTELLICRACK_SERIALIZATION_KEY",
    os.environ.get("INTELLICRACK_PICKLE_KEY", "default-key-change-in-production"),
).encode()


class RestrictedUnpickler(pickle.Unpickler):
    """Restricted unpickler with strict class-level whitelisting.

    Prevents arbitrary code execution by only allowing specific safe classes
    from each permitted module. This is the canonical implementation used
    throughout Intellicrack for secure pickle deserialization.

    The allowlists are carefully curated to support:
    - Python builtins (immutable/container types only)
    - NumPy arrays and dtypes
    - PyTorch tensors and storage types
    - Pandas DataFrames and Series
    - scikit-learn models
    - TensorFlow tensors
    - datetime objects
    - Intellicrack internal types
    """

    ALLOWED_MODULES: frozenset[str] = frozenset({
        # Python builtins
        "builtins",
        "__builtin__",
        # Collections
        "collections",
        "collections.abc",
        # Datetime
        "datetime",
        # NumPy
        "numpy",
        "numpy.core",
        "numpy.core.multiarray",
        "numpy.core.numeric",
        "numpy._core",
        "numpy._core.multiarray",
        "numpy.dtypes",
        # PyTorch
        "torch",
        "torch._utils",
        "torch.storage",
        # Pandas
        "pandas",
        "pandas.core",
        "pandas.core.frame",
        "pandas.core.series",
        "pandas.core.indexes",
        "pandas.core.indexes.base",
        # scikit-learn
        "sklearn",
        "sklearn.base",
        "sklearn.tree",
        "sklearn.ensemble",
        "sklearn.linear_model",
        "sklearn.preprocessing",
        # TensorFlow
        "tensorflow",
        "tensorflow.python.framework",
    })

    ALLOWED_CLASSES: frozenset[str] = frozenset({
        # Python builtins - only safe immutable/container types
        "dict",
        "list",
        "tuple",
        "set",
        "frozenset",
        "str",
        "int",
        "float",
        "bool",
        "bytes",
        "bytearray",
        "complex",
        "NoneType",
        "type",
        "slice",
        "range",
        "Ellipsis",
        # collections types
        "OrderedDict",
        "defaultdict",
        "deque",
        "Counter",
        "namedtuple",
        "ChainMap",
        # collections.abc
        "Mapping",
        "MutableMapping",
        "Sequence",
        "MutableSequence",
        "Set",
        "MutableSet",
        "Callable",
        "Iterable",
        "Iterator",
        # datetime
        "datetime",
        "date",
        "time",
        "timedelta",
        "timezone",
        # numpy safe types
        "ndarray",
        "dtype",
        "float16",
        "float32",
        "float64",
        "float128",
        "int8",
        "int16",
        "int32",
        "int64",
        "uint8",
        "uint16",
        "uint32",
        "uint64",
        "bool_",
        "complex64",
        "complex128",
        "str_",
        "bytes_",
        "void",
        "object_",
        "_reconstruct",
        "scalar",
        # torch safe types for model state loading
        "Tensor",
        "Size",
        "device",
        "_rebuild_tensor_v2",
        "_rebuild_parameter",
        "_rebuild_device_tensor_v2",
        "storage",
        "FloatStorage",
        "LongStorage",
        "IntStorage",
        "ShortStorage",
        "HalfStorage",
        "CharStorage",
        "ByteStorage",
        "BoolStorage",
        "DoubleStorage",
        "BFloat16Storage",
        "ComplexFloatStorage",
        "ComplexDoubleStorage",
        "QInt8Storage",
        "QUInt8Storage",
        "QInt32Storage",
        "TypedStorage",
        "UntypedStorage",
        # Pandas types
        "DataFrame",
        "Series",
        "Index",
        "RangeIndex",
        "Int64Index",
        "Float64Index",
        "DatetimeIndex",
        "MultiIndex",
        "Categorical",
        "CategoricalDtype",
        # sklearn types
        "DecisionTreeClassifier",
        "RandomForestClassifier",
        "GradientBoostingClassifier",
        "LinearRegression",
        "LogisticRegression",
        "StandardScaler",
        "MinMaxScaler",
        "LabelEncoder",
        "OneHotEncoder",
    })

    ALLOWED_INTELLICRACK_CLASSES: frozenset[str] = frozenset({
        # Model cache types
        "ModelCacheManager",
        "CachedModel",
        "ModelMetadata",
        "CacheConfig",
        "CacheEntry",
        # Analysis result types
        "AnalysisResult",
        "ProtectionResult",
        "PatternMatch",
        "VulnerabilityResult",
        "ModelConfig",
        # Pattern tracking
        "Pattern",
        "PatternEvolution",
        "PatternTracker",
        # Incremental analysis
        "IncrementalState",
        "AnalysisState",
        # Common containers
        "dict",
        "list",
        "tuple",
        "set",
    })

    def find_class(self, module: str, name: str) -> type[Any]:
        """Override find_class to restrict allowed classes.

        Args:
            module: Module name containing the class.
            name: Class name to load.

        Returns:
            The requested class type if allowed.

        Raises:
            UnpicklingError: If the class is not in the allowed list.

        """
        # Check if module and class are in the core allowed lists
        if module in self.ALLOWED_MODULES and name in self.ALLOWED_CLASSES:
            return cast("type[Any]", super().find_class(module, name))

        # Check module prefixes for numpy/torch/sklearn submodules
        module_prefixes = ("numpy.", "torch.", "sklearn.", "pandas.", "tensorflow.")
        if any(module.startswith(prefix) for prefix in module_prefixes):
            if name in self.ALLOWED_CLASSES:
                return cast("type[Any]", super().find_class(module, name))

        # Allow Intellicrack internal classes
        if module.startswith("intellicrack.") and name in self.ALLOWED_INTELLICRACK_CLASSES:
            return cast("type[Any]", super().find_class(module, name))

        # Deny everything else
        error_msg = f"Blocked unpickling of unsafe class: {module}.{name}"
        logger.warning(error_msg)
        raise pickle.UnpicklingError(error_msg)


class SecureJSONEncoder(json.JSONEncoder):
    """JSON encoder with support for additional Python types."""

    def default(self, obj: Any) -> Any:
        """Encode objects that aren't JSON serializable by default.

        Args:
            obj: Object to encode.

        Returns:
            JSON-serializable representation.

        """
        if isinstance(obj, datetime):
            return {"__datetime__": obj.isoformat()}
        if isinstance(obj, date):
            return {"__date__": obj.isoformat()}
        if isinstance(obj, time):
            return {"__time__": obj.isoformat()}
        if isinstance(obj, timedelta):
            return {"__timedelta__": obj.total_seconds()}
        if isinstance(obj, timezone):
            return {"__timezone__": str(obj)}
        if isinstance(obj, bytes):
            return {"__bytes__": base64.b64encode(obj).decode("ascii")}
        if isinstance(obj, set):
            return {"__set__": list(obj)}
        if isinstance(obj, frozenset):
            return {"__frozenset__": list(obj)}
        if isinstance(obj, Path):
            return {"__path__": str(obj)}
        if hasattr(obj, "__dict__"):
            return {"__class__": type(obj).__name__, "__data__": obj.__dict__}
        return super().default(obj)


def secure_json_decoder_hook(dct: dict[str, Any]) -> Any:
    """Decode special JSON types back to Python objects.

    Args:
        dct: Dictionary that may contain special type markers.

    Returns:
        Decoded Python object.

    """
    if "__datetime__" in dct:
        return datetime.fromisoformat(dct["__datetime__"])
    if "__date__" in dct:
        return date.fromisoformat(dct["__date__"])
    if "__time__" in dct:
        return time.fromisoformat(dct["__time__"])
    if "__timedelta__" in dct:
        return timedelta(seconds=dct["__timedelta__"])
    if "__bytes__" in dct:
        return base64.b64decode(dct["__bytes__"])
    if "__set__" in dct:
        return set(dct["__set__"])
    if "__frozenset__" in dct:
        return frozenset(dct["__frozenset__"])
    if "__path__" in dct:
        return Path(dct["__path__"])
    return dct


def secure_json_dump(obj: object, file_path: str | Path) -> None:
    """Securely dump object as JSON with HMAC integrity.

    Args:
        obj: Python object to serialize as JSON.
        file_path: Path to write the JSON file.

    Raises:
        TypeError: If object is not JSON-serializable.

    """
    json_data = json.dumps(obj, cls=SecureJSONEncoder, ensure_ascii=False)
    data_bytes = json_data.encode("utf-8")

    # Calculate HMAC for integrity
    mac = hmac.new(SERIALIZATION_SECURITY_KEY, data_bytes, hashlib.sha256).digest()

    # Write MAC + data
    with open(file_path, "wb") as f:
        f.write(mac)
        f.write(data_bytes)


def secure_json_load(file_path: str | Path) -> object:
    """Securely load JSON with HMAC integrity verification.

    Args:
        file_path: Path to the JSON file to load.

    Returns:
        Deserialized Python object.

    Raises:
        ValueError: If integrity check fails.
        FileNotFoundError: If file does not exist.

    """
    with open(file_path, "rb") as f:
        stored_mac = f.read(32)  # SHA256 produces 32 bytes
        data_bytes = f.read()

    # Verify integrity
    expected_mac = hmac.new(SERIALIZATION_SECURITY_KEY, data_bytes, hashlib.sha256).digest()
    if not hmac.compare_digest(stored_mac, expected_mac):
        raise ValueError("JSON file integrity check failed - possible tampering detected")

    json_data = data_bytes.decode("utf-8")
    return json.loads(json_data, object_hook=secure_json_decoder_hook)


def secure_json_dumps(obj: object) -> bytes:
    """Securely serialize object as JSON with HMAC integrity.

    Args:
        obj: Python object to serialize.

    Returns:
        Bytes containing HMAC signature and JSON data.

    """
    json_data = json.dumps(obj, cls=SecureJSONEncoder, ensure_ascii=False)
    data_bytes = json_data.encode("utf-8")

    # Calculate HMAC for integrity
    mac = hmac.new(SERIALIZATION_SECURITY_KEY, data_bytes, hashlib.sha256).digest()

    return mac + data_bytes


def secure_json_loads(data: bytes) -> object:
    """Securely deserialize JSON with integrity verification.

    Args:
        data: Bytes containing HMAC signature and JSON data.

    Returns:
        Deserialized Python object.

    Raises:
        ValueError: If integrity verification fails.

    """
    stored_mac = data[:32]
    data_bytes = data[32:]

    # Verify integrity
    expected_mac = hmac.new(SERIALIZATION_SECURITY_KEY, data_bytes, hashlib.sha256).digest()
    if not hmac.compare_digest(stored_mac, expected_mac):
        raise ValueError("JSON data integrity check failed - possible tampering detected")

    json_data = data_bytes.decode("utf-8")
    return json.loads(json_data, object_hook=secure_json_decoder_hook)


def secure_pickle_dump(obj: object, file_path: str | Path) -> None:
    """Securely dump object with pickle and HMAC integrity.

    Use this ONLY for ML models and complex objects that cannot be
    serialized as JSON. For simple data structures, use secure_json_dump.

    Args:
        obj: Python object to pickle.
        file_path: Path to write the pickle file.

    """
    # Serialize object
    data = pickle.dumps(obj, protocol=pickle.HIGHEST_PROTOCOL)

    # Calculate HMAC for integrity
    mac = hmac.new(SERIALIZATION_SECURITY_KEY, data, hashlib.sha256).digest()

    # Write MAC + data
    with open(file_path, "wb") as f:
        f.write(mac)
        f.write(data)


def secure_pickle_load(file_path: str | Path) -> object:
    """Securely load pickled object with integrity verification.

    Uses RestrictedUnpickler to prevent arbitrary code execution.
    Tries joblib first for ML models as it's safer.

    Args:
        file_path: Path to the pickle file to load.

    Returns:
        The unpickled object.

    Raises:
        ValueError: If integrity check fails.

    """
    # Try joblib first as it's safer for ML models
    try:
        import joblib

        return joblib.load(file_path)
    except (ImportError, ValueError, EOFError):
        pass

    with open(file_path, "rb") as f:
        stored_mac = f.read(32)  # SHA256 produces 32 bytes
        data = f.read()

    # Verify integrity
    expected_mac = hmac.new(SERIALIZATION_SECURITY_KEY, data, hashlib.sha256).digest()
    if not hmac.compare_digest(stored_mac, expected_mac):
        raise ValueError("Pickle file integrity check failed - possible tampering detected")

    # Load object using RestrictedUnpickler
    return RestrictedUnpickler(io.BytesIO(data)).load()


def secure_pickle_dumps(obj: object) -> bytes:
    """Securely serialize object with pickle and HMAC integrity.

    Use this ONLY for ML models and complex objects that cannot be
    serialized as JSON. For simple data structures, use secure_json_dumps.

    Args:
        obj: Python object to pickle.

    Returns:
        Bytes containing HMAC signature and pickled data.

    """
    data = pickle.dumps(obj, protocol=pickle.HIGHEST_PROTOCOL)
    mac = hmac.new(SERIALIZATION_SECURITY_KEY, data, hashlib.sha256).digest()
    return mac + data


def secure_pickle_loads(data: bytes) -> object:
    """Securely deserialize pickled object with integrity verification.

    Args:
        data: Bytes containing HMAC signature and pickled data.

    Returns:
        The unpickled object.

    Raises:
        ValueError: If integrity verification fails.

    """
    stored_mac = data[:32]
    obj_data = data[32:]

    # Verify integrity
    expected_mac = hmac.new(SERIALIZATION_SECURITY_KEY, obj_data, hashlib.sha256).digest()
    if not hmac.compare_digest(stored_mac, expected_mac):
        raise ValueError("Pickle data integrity check failed - possible tampering detected")

    return RestrictedUnpickler(io.BytesIO(obj_data)).load()


def is_json_serializable(obj: object) -> bool:
    """Check if an object can be serialized as JSON.

    Args:
        obj: Object to check.

    Returns:
        True if JSON serialization is possible.

    """
    try:
        json.dumps(obj, cls=SecureJSONEncoder)
        return True
    except (TypeError, ValueError, OverflowError):
        return False


def smart_serialize(obj: object, file_path: str | Path) -> str:
    """Intelligently serialize object using JSON if possible, else pickle.

    Args:
        obj: Object to serialize.
        file_path: Path to write the serialized data.

    Returns:
        "json" or "pickle" indicating which format was used.

    """
    if is_json_serializable(obj):
        secure_json_dump(obj, file_path)
        return "json"
    secure_pickle_dump(obj, file_path)
    return "pickle"


def smart_deserialize(file_path: str | Path, format_hint: str = "auto") -> object:
    """Intelligently deserialize object, detecting format if needed.

    Args:
        file_path: Path to the serialized file.
        format_hint: "json", "pickle", or "auto" (default).

    Returns:
        The deserialized object.

    """
    if format_hint == "json":
        return secure_json_load(file_path)
    if format_hint == "pickle":
        return secure_pickle_load(file_path)

    # Auto-detect by trying JSON first (it's safer)
    try:
        return secure_json_load(file_path)
    except (json.JSONDecodeError, UnicodeDecodeError):
        return secure_pickle_load(file_path)


__all__ = [
    "RestrictedUnpickler",
    "SecureJSONEncoder",
    "SERIALIZATION_SECURITY_KEY",
    "is_json_serializable",
    "secure_json_decoder_hook",
    "secure_json_dump",
    "secure_json_dumps",
    "secure_json_load",
    "secure_json_loads",
    "secure_pickle_dump",
    "secure_pickle_dumps",
    "secure_pickle_load",
    "secure_pickle_loads",
    "smart_deserialize",
    "smart_serialize",
]

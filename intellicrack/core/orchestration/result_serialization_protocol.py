"""Result Serialization Protocol for Cross-Tool Data Exchange.

This module provides a comprehensive serialization protocol for standardizing
analysis results across different tools, enabling seamless data exchange and
correlation of findings from Ghidra, IDA Pro, Radare2, Frida, and other tools.

Copyright (C) 2025 Zachary Flint

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <https://www.gnu.org/licenses/>.
"""

import base64
import hashlib
import json
import logging
import struct
import zlib
from dataclasses import asdict, dataclass, field
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Any

import msgpack

from intellicrack.utils.type_safety import validate_type


logger = logging.getLogger(__name__)


class DataFormat(Enum):
    """Supported serialization formats."""

    JSON = "json"
    MSGPACK = "msgpack"
    PROTOBUF = "protobuf"
    BINARY = "binary"
    XML = "xml"


class ResultType(Enum):
    """Types of analysis results."""

    FUNCTION = "function"
    STRING = "string"
    IMPORT = "import"
    EXPORT = "export"
    XREF = "cross_reference"
    PATCH = "patch"
    BREAKPOINT = "breakpoint"
    API_CALL = "api_call"
    MEMORY_DUMP = "memory_dump"
    REGISTER_STATE = "register_state"
    SYMBOL = "symbol"
    STRUCTURE = "structure"
    CRYPTO = "cryptographic"
    LICENSE = "license_check"
    PROTECTION = "protection_scheme"
    VULNERABILITY = "vulnerability"
    CONTROL_FLOW = "control_flow"
    DATA_FLOW = "data_flow"
    TAINT = "taint_analysis"
    CONSTRAINT = "path_constraint"


@dataclass
class BaseResult:
    """Base class for all analysis results."""

    id: str
    type: ResultType
    source_tool: str
    timestamp: float
    confidence: float = 1.0
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary representation.

        Returns:
            Dictionary representation of the result with type converted to string value.
        """
        result = asdict(self)
        result["type"] = self.type.value
        return result

    def calculate_hash(self) -> str:
        """Calculate unique hash for this result.

        Returns:
            SHA256 hexdigest of the result data.
        """
        data = json.dumps(self.to_dict(), sort_keys=True)
        return hashlib.sha256(data.encode()).hexdigest()


@dataclass
class FunctionResult(BaseResult):
    """Function analysis result."""

    address: int = 0
    name: str = ""
    size: int = 0
    return_type: str | None = None
    parameters: list[dict[str, Any]] = field(default_factory=list)
    calling_convention: str | None = None
    local_vars: list[dict[str, Any]] = field(default_factory=list)
    basic_blocks: list[dict[str, Any]] = field(default_factory=list)
    cyclomatic_complexity: int = 0
    xrefs_to: list[int] = field(default_factory=list)
    xrefs_from: list[int] = field(default_factory=list)
    decompiled_code: str | None = None
    assembly_code: str | None = None
    is_thunk: bool = False
    is_library: bool = False
    stack_frame_size: int = 0


@dataclass
class StringResult(BaseResult):
    """String discovery result."""

    address: int = 0
    value: str = ""
    encoding: str = "utf-8"
    length: int = 0
    references: list[int] = field(default_factory=list)
    is_unicode: bool = False
    is_path: bool = False
    is_url: bool = False
    is_registry_key: bool = False
    is_api_name: bool = False
    entropy: float = 0.0


@dataclass
class CryptoResult(BaseResult):
    """Cryptographic operation result."""

    address: int = 0
    algorithm: str = ""
    key_size: int | None = None
    mode: str | None = None
    key_location: int | None = None
    iv_location: int | None = None
    constants: list[int] = field(default_factory=list)
    implementation_type: str = "unknown"
    vulnerable: bool = False
    vulnerability_details: str | None = None


@dataclass
class LicenseCheckResult(BaseResult):
    """License validation detection result."""

    address: int = 0
    check_type: str = ""
    success_path: int | None = None
    failure_path: int | None = None
    validation_routine: int | None = None
    key_generation_algorithm: str | None = None
    bypass_method: str | None = None
    patch_locations: list[dict[str, Any]] = field(default_factory=list)
    extracted_keys: list[str] = field(default_factory=list)
    hwid_sources: list[str] = field(default_factory=list)


@dataclass
class ProtectionResult(BaseResult):
    """Protection scheme detection result."""

    protection_type: str = ""
    name: str = ""
    version: str | None = None
    entry_point: int | None = None
    protected_sections: list[dict[str, Any]] = field(default_factory=list)
    unpacking_method: str | None = None
    oep_address: int | None = None
    iat_address: int | None = None
    bypass_techniques: list[str] = field(default_factory=list)
    detection_signatures: list[str] = field(default_factory=list)


@dataclass
class PatchResult(BaseResult):
    """Binary patch result."""

    address: int = 0
    original_bytes: bytes = b""
    patched_bytes: bytes = b""
    patch_type: str = ""
    description: str = ""
    reversible: bool = True
    dependencies: list[int] = field(default_factory=list)
    side_effects: list[str] = field(default_factory=list)


@dataclass
class MemoryDumpResult(BaseResult):
    """Memory dump result."""

    start_address: int = 0
    end_address: int = 0
    size: int = 0
    data: bytes = b""
    permissions: str = ""
    section_name: str | None = None
    is_executable: bool = False
    is_writable: bool = False
    contains_code: bool = False
    entropy: float = 0.0
    compression_ratio: float = 0.0


@dataclass
class ControlFlowResult(BaseResult):
    """Control flow analysis result."""

    function_address: int = 0
    basic_blocks: list[dict[str, int]] = field(default_factory=list)
    edges: list[tuple[int, int]] = field(default_factory=list)
    loops: list[list[int]] = field(default_factory=list)
    dominators: dict[int, int] = field(default_factory=dict)
    post_dominators: dict[int, int] = field(default_factory=dict)
    cyclomatic_complexity: int = 0
    max_depth: int = 0
    has_recursion: bool = False
    unreachable_blocks: list[int] = field(default_factory=list)


class ResultSerializer:
    """Unified serialization handler for all result types.

    Handles serialization and deserialization of analysis results across
    multiple formats (JSON, MessagePack, binary) with optional compression
    and AES encryption.

    Attributes:
        format: The serialization format to use.
        compression_enabled: Whether to compress serialized data.
        encryption_key: Optional encryption key for AES encryption.
        result_classes: Mapping of result types to their class implementations.
    """

    format: DataFormat
    compression_enabled: bool
    encryption_key: bytes | None
    result_classes: dict[ResultType, type[BaseResult]]

    def __init__(self, format: DataFormat = DataFormat.MSGPACK) -> None:
        """Initialize serializer with specified format.

        Args:
            format: Serialization format to use (defaults to MSGPACK).
        """
        self.format = format
        self.compression_enabled = True
        self.encryption_key = None

        # Result type mapping
        self.result_classes = {
            ResultType.FUNCTION: FunctionResult,
            ResultType.STRING: StringResult,
            ResultType.CRYPTO: CryptoResult,
            ResultType.LICENSE: LicenseCheckResult,
            ResultType.PROTECTION: ProtectionResult,
            ResultType.PATCH: PatchResult,
            ResultType.MEMORY_DUMP: MemoryDumpResult,
            ResultType.CONTROL_FLOW: ControlFlowResult,
        }

    def serialize(self, result: BaseResult) -> bytes:
        """Serialize analysis result to bytes.

        Args:
            result: The analysis result to serialize.

        Returns:
            Serialized bytes of the result, optionally compressed and encrypted.

        Raises:
            ValueError: If the configured format is not supported.
        """
        # Convert to dictionary
        data = result.to_dict()

        # Add serialization metadata
        data["_serialization"] = {
            "version": "1.0",
            "format": self.format.value,
            "compressed": self.compression_enabled,
            "hash": result.calculate_hash(),
        }

        # Serialize based on format
        if self.format == DataFormat.JSON:
            serialized = json.dumps(data, cls=CustomJSONEncoder).encode()
        elif self.format == DataFormat.MSGPACK:
            serialized = msgpack.packb(data, use_bin_type=True)
        elif self.format == DataFormat.BINARY:
            serialized = self._binary_serialize(data)
        else:
            raise ValueError(f"Unsupported format: {self.format}")

        # Compress if enabled
        if self.compression_enabled:
            serialized = zlib.compress(serialized, level=9)

        # Encrypt if key provided
        if self.encryption_key:
            serialized = self._encrypt_data(serialized)

        return serialized

    def deserialize(self, data: bytes, result_type: ResultType) -> BaseResult:
        """Deserialize bytes to analysis result.

        Args:
            data: Serialized bytes to deserialize.
            result_type: Expected result type to instantiate.

        Returns:
            Deserialized result object of the specified type.

        Raises:
            ValueError: If the format is not supported or data is invalid.
        """
        # Decrypt if needed
        if self.encryption_key:
            data = self._decrypt_data(data)

        # Decompress if needed
        try:
            if data[:2] == b"\x78\x9c":  # zlib magic bytes
                data = zlib.decompress(data)
        except (zlib.error, ValueError):
            pass

        # Deserialize based on format
        if self.format == DataFormat.JSON:
            result_dict = json.loads(data.decode())
        elif self.format == DataFormat.MSGPACK:
            result_dict = msgpack.unpackb(data, raw=False)
        elif self.format == DataFormat.BINARY:
            result_dict = self._binary_deserialize(data)
        else:
            raise ValueError(f"Unsupported format: {self.format}")

        # Remove metadata
        if "_serialization" in result_dict:
            del result_dict["_serialization"]

        # Convert type string back to enum
        result_dict["type"] = ResultType(result_dict["type"])

        # Create appropriate result class
        result_class = self.result_classes.get(result_type, BaseResult)
        return result_class(**result_dict)

    def _binary_serialize(self, data: dict[str, Any]) -> bytes:
        """Serialize data with custom binary format for maximum efficiency.

        Args:
            data: Dictionary to serialize in binary format.

        Returns:
            Binary serialized data with header, version, and length prefix.
        """
        # Binary format: [header][type][data_length][data]
        header = b"ICRK"  # Intellicrack magic bytes
        version = struct.pack("H", 1)

        # Serialize data to msgpack first
        data_bytes = validate_type(msgpack.packb(data, use_bin_type=True), bytes)
        data_length = struct.pack("I", len(data_bytes))

        return header + version + data_length + data_bytes

    def _binary_deserialize(self, data: bytes) -> dict[str, Any]:
        """Deserialize custom binary format.

        Args:
            data: Binary serialized data with header, version, and msgpack payload.

        Returns:
            Deserialized dictionary from binary format.

        Raises:
            ValueError: If binary format is invalid or protocol version is not supported.
        """
        # Check header
        if data[:4] != b"ICRK":
            raise ValueError("Invalid binary format")

        # Parse header
        version = struct.unpack("H", data[4:6])[0]
        data_length = struct.unpack("I", data[6:10])[0]

        # Validate protocol version (support versions 1-3)
        SUPPORTED_VERSIONS = [1, 2, 3]
        if version not in SUPPORTED_VERSIONS:
            raise ValueError(f"Unsupported protocol version: {version}. Supported: {SUPPORTED_VERSIONS}")

        # Extract data with version-specific handling
        data_bytes = data[10 : 10 + data_length]

        # Version-specific deserialization
        if version == 1:
            # Version 1: Basic msgpack
            return validate_type(msgpack.unpackb(data_bytes, raw=False), dict)
        elif version == 2:
            # Version 2: msgpack with strict_map_key
            return validate_type(msgpack.unpackb(data_bytes, raw=False, strict_map_key=False), dict)
        else:
            # Version 3: msgpack with timestamp support
            return validate_type(msgpack.unpackb(data_bytes, raw=False, timestamp=3), dict)

    def _encrypt_data(self, data: bytes) -> bytes:
        """Encrypt data using AES.

        Args:
            data: Plaintext bytes to encrypt.

        Returns:
            IV prepended to AES-CBC encrypted ciphertext.
        """
        from Crypto.Cipher import AES  # noqa: S413
        from Crypto.Random import get_random_bytes  # noqa: S413
        from Crypto.Util.Padding import pad

        # Generate IV
        iv = get_random_bytes(16)

        # Create cipher
        cipher = AES.new(validate_type(self.encryption_key, bytes), AES.MODE_CBC, iv)

        # Encrypt
        encrypted = cipher.encrypt(pad(data, AES.block_size))

        return iv + encrypted

    def _decrypt_data(self, data: bytes) -> bytes:
        """Decrypt AES encrypted data.

        Args:
            data: IV prepended to AES-CBC encrypted ciphertext.

        Returns:
            Decrypted plaintext bytes.
        """
        from Crypto.Cipher import AES  # noqa: S413
        from Crypto.Util.Padding import unpad

        # Extract IV
        iv = data[:16]
        encrypted = data[16:]

        # Create cipher
        cipher = AES.new(validate_type(self.encryption_key, bytes), AES.MODE_CBC, iv)

        return unpad(cipher.decrypt(encrypted), AES.block_size)

    def batch_serialize(self, results: list[BaseResult]) -> bytes:
        """Serialize multiple results efficiently.

        Args:
            results: List of results to serialize as a batch.

        Returns:
            Serialized batch data with ID and count metadata.
        """
        batch_data = {
            "batch_id": hashlib.sha256(str(datetime.now()).encode()).hexdigest()[:16],
            "count": len(results),
            "results": [r.to_dict() for r in results],
        }

        return self.serialize_dict(batch_data)

    def serialize_dict(self, data: dict[str, Any]) -> bytes:
        """Serialize dictionary directly.

        Args:
            data: Dictionary to serialize.

        Returns:
            Serialized dictionary bytes, optionally compressed and encrypted.
        """
        if self.format == DataFormat.JSON:
            serialized = json.dumps(data, cls=CustomJSONEncoder).encode()
        elif self.format == DataFormat.MSGPACK:
            serialized = msgpack.packb(data, use_bin_type=True)
        else:
            serialized = self._binary_serialize(data)

        if self.compression_enabled:
            serialized = zlib.compress(serialized, level=9)

        return serialized


class CustomJSONEncoder(json.JSONEncoder):
    """Customize JSON encoder for complex types.

    Extends the standard JSON encoder to handle bytes, Enums, Path objects,
    and custom objects with to_dict methods.
    """

    def default(self, obj: object) -> object:
        """Encode complex objects to JSON-serializable format.

        Args:
            obj: Object to encode.

        Returns:
            JSON-serializable representation of the object.
        """
        if isinstance(obj, bytes):
            return base64.b64encode(obj).decode("ascii")
        if isinstance(obj, Enum):
            return obj.value
        if hasattr(obj, "to_dict"):
            return obj.to_dict()
        return str(obj) if isinstance(obj, Path) else super().default(obj)


class ResultConverter:
    """Convert between different tool formats.

    Provides static methods to convert analysis output from various tools
    (Ghidra, IDA Pro, Radare2, Frida) into a standardized result format.
    """

    @staticmethod
    def ghidra_to_standard(ghidra_data: dict[str, Any]) -> list[BaseResult]:
        """Convert Ghidra output to standard format.

        Args:
            ghidra_data: Ghidra analysis output dictionary.

        Returns:
            List of standardized result objects.
        """
        results: list[BaseResult] = []

        # Convert functions
        for func in ghidra_data.get("functions", []):
            result = FunctionResult(
                id=hashlib.sha256(f"{func['address']}".encode()).hexdigest(),
                type=ResultType.FUNCTION,
                source_tool="ghidra",
                timestamp=datetime.now().timestamp(),
                address=int(func["address"], 16) if isinstance(func["address"], str) else func["address"],
                name=func["name"],
                size=func.get("size", 0),
                return_type=func.get("return_type"),
                parameters=[{"name": p["name"], "type": p["type"]} for p in func.get("parameters", [])],
                calling_convention=func.get("calling_convention"),
                decompiled_code=func.get("decompiled"),
            )
            results.append(result)

        # Convert strings
        for string in ghidra_data.get("strings", []):
            result_str = StringResult(
                id=hashlib.sha256(f"{string['address']}".encode()).hexdigest(),
                type=ResultType.STRING,
                source_tool="ghidra",
                timestamp=datetime.now().timestamp(),
                address=int(string["address"], 16) if isinstance(string["address"], str) else string["address"],
                value=string["value"],
                length=len(string["value"]),
                references=string.get("xrefs", []),
            )
            results.append(result_str)

        return results

    @staticmethod
    def ida_to_standard(ida_data: dict[str, Any]) -> list[BaseResult]:
        """Convert IDA Pro output to standard format.

        Args:
            ida_data: IDA Pro analysis output dictionary.

        Returns:
            List of standardized result objects.
        """
        results: list[BaseResult] = []

        # Convert functions
        for addr, func in ida_data.get("functions", {}).items():
            result = FunctionResult(
                id=hashlib.sha256(f"{addr}".encode()).hexdigest(),
                type=ResultType.FUNCTION,
                source_tool="ida_pro",
                timestamp=datetime.now().timestamp(),
                address=int(addr, 16) if isinstance(addr, str) else addr,
                name=func.get("name", f"sub_{addr:x}"),
                size=func.get("end_ea", addr) - addr,
                stack_frame_size=func.get("frame_size", 0),
                xrefs_to=func.get("xrefs_to", []),
                xrefs_from=func.get("xrefs_from", []),
            )
            results.append(result)

        # Convert structures
        for struct_name, struct_data in ida_data.get("structures", {}).items():
            # Store as metadata since we don't have a dedicated structure result
            result_base = BaseResult(
                id=hashlib.sha256(struct_name.encode()).hexdigest(),
                type=ResultType.STRUCTURE,
                source_tool="ida_pro",
                timestamp=datetime.now().timestamp(),
                metadata={
                    "name": struct_name,
                    "size": struct_data.get("size", 0),
                    "members": struct_data.get("members", []),
                },
            )
            results.append(result_base)

        return results

    @staticmethod
    def radare2_to_standard(r2_data: dict[str, Any]) -> list[BaseResult]:
        """Convert Radare2 output to standard format.

        Args:
            r2_data: Radare2 analysis output dictionary.

        Returns:
            List of standardized result objects.
        """
        results: list[BaseResult] = []

        # Convert functions from aflj output
        for func in r2_data.get("functions", []):
            result = FunctionResult(
                id=hashlib.sha256(f"{func['offset']}".encode()).hexdigest(),
                type=ResultType.FUNCTION,
                source_tool="radare2",
                timestamp=datetime.now().timestamp(),
                address=func["offset"],
                name=func["name"],
                size=func.get("size", 0),
                cyclomatic_complexity=func.get("cc", 0),
                basic_blocks=[{"start": bb["addr"], "size": bb["size"]} for bb in func.get("bbs", [])],
            )
            results.append(result)

        # Convert strings from izj output
        for string in r2_data.get("strings", []):
            result_str = StringResult(
                id=hashlib.sha256(f"{string['vaddr']}".encode()).hexdigest(),
                type=ResultType.STRING,
                source_tool="radare2",
                timestamp=datetime.now().timestamp(),
                address=string["vaddr"],
                value=string["string"],
                length=string["length"],
                encoding=string.get("type", "ascii"),
            )
            results.append(result_str)

        return results

    @staticmethod
    def frida_to_standard(frida_data: dict[str, Any]) -> list[BaseResult]:
        """Convert Frida output to standard format.

        Args:
            frida_data: Frida instrumentation output dictionary.

        Returns:
            List of standardized result objects.
        """
        results: list[BaseResult] = []

        # Convert API calls
        for call in frida_data.get("api_calls", []):
            result = BaseResult(
                id=hashlib.sha256(f"{call['timestamp']}".encode()).hexdigest(),
                type=ResultType.API_CALL,
                source_tool="frida",
                timestamp=call["timestamp"],
                metadata={
                    "function": call["function"],
                    "arguments": call["args"],
                    "return_value": call.get("retval"),
                    "thread_id": call.get("tid"),
                    "process_id": call.get("pid"),
                },
            )
            results.append(result)

        # Convert memory dumps
        for dump in frida_data.get("memory_dumps", []):
            result = MemoryDumpResult(
                id=hashlib.sha256(f"{dump['address']}".encode()).hexdigest(),
                type=ResultType.MEMORY_DUMP,
                source_tool="frida",
                timestamp=datetime.now().timestamp(),
                start_address=dump["address"],
                end_address=dump["address"] + dump["size"],
                size=dump["size"],
                data=base64.b64decode(dump["data"]),
                permissions=dump.get("protection", "rwx"),
            )
            results.append(result)

        return results

    @staticmethod
    def standard_to_json(results: list[BaseResult]) -> str:
        """Convert standard results to JSON for export.

        Args:
            results: List of standardized result objects.

        Returns:
            JSON string with results and summary statistics.
        """
        export_data: dict[str, Any] = {
            "version": "1.0",
            "timestamp": datetime.now().isoformat(),
            "results": [r.to_dict() for r in results],
            "summary": {"total": len(results), "by_type": {}, "by_tool": {}},
        }

        # Calculate summary statistics
        for result in results:
            result_type = result.type.value
            source_tool = result.source_tool

            summary_dict = validate_type(export_data["summary"], dict)
            by_type_dict = validate_type(summary_dict["by_type"], dict)
            by_tool_dict = validate_type(summary_dict["by_tool"], dict)

            by_type_dict[result_type] = by_type_dict.get(result_type, 0) + 1
            by_tool_dict[source_tool] = by_tool_dict.get(source_tool, 0) + 1

        return json.dumps(export_data, indent=2, cls=CustomJSONEncoder)

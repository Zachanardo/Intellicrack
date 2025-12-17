"""Production tests for Result Serialization Protocol.

Validates all serialization formats (JSON, MsgPack, Binary, XML),
compression, hashing, and cross-tool result conversion.
"""

import base64
import hashlib
import json
import zlib
from datetime import datetime
from typing import Any

import msgpack
import pytest

from intellicrack.core.orchestration.result_serialization_protocol import (
    BaseResult,
    ControlFlowResult,
    CryptoResult,
    CustomJSONEncoder,
    DataFormat,
    FunctionResult,
    LicenseCheckResult,
    MemoryDumpResult,
    PatchResult,
    ProtectionResult,
    ResultConverter,
    ResultSerializer,
    ResultType,
    StringResult,
)


class TestResultSerialization:
    """Test serialization protocol for cross-tool data exchange."""

    @pytest.fixture
    def function_result(self) -> FunctionResult:
        """Create comprehensive function result for testing."""
        return FunctionResult(
            id=hashlib.sha256(b"test_func_0x401000").hexdigest(),
            type=ResultType.FUNCTION,
            source_tool="ghidra",
            timestamp=datetime.now().timestamp(),
            address=0x401000,
            name="validate_license_key",
            size=512,
            return_type="bool",
            parameters=[{"name": "key", "type": "char*"}, {"name": "length", "type": "int"}],
            calling_convention="__stdcall",
            local_vars=[{"name": "result", "type": "int"}, {"name": "hash", "type": "uint32_t"}],
            basic_blocks=[{"start": 0x401000, "size": 64}, {"start": 0x401040, "size": 128}],
            cyclomatic_complexity=12,
            xrefs_to=[0x400500, 0x400800],
            xrefs_from=[0x402000, 0x403000, 0x404000],
            decompiled_code="bool validate_license_key(char* key, int length) { return check_hwid(key); }",
            assembly_code="push ebp\nmov ebp, esp\nsub esp, 0x20",
            is_thunk=False,
            is_library=False,
            stack_frame_size=32,
            confidence=0.95,
        )

    @pytest.fixture
    def crypto_result(self) -> CryptoResult:
        """Create crypto detection result."""
        return CryptoResult(
            id=hashlib.sha256(b"crypto_aes_0x410000").hexdigest(),
            type=ResultType.CRYPTO,
            source_tool="yara",
            timestamp=datetime.now().timestamp(),
            address=0x410000,
            algorithm="aes",
            key_size=256,
            mode="CBC",
            key_location=0x420000,
            iv_location=0x420100,
            constants=[0x63, 0x7C, 0x77, 0x7B, 0xC66363A5, 0xF87C7C84],
            implementation_type="standard",
            vulnerable=False,
            confidence=0.92,
        )

    @pytest.fixture
    def license_check_result(self) -> LicenseCheckResult:
        """Create license check detection result."""
        return LicenseCheckResult(
            id=hashlib.sha256(b"license_check_0x405000").hexdigest(),
            type=ResultType.LICENSE,
            source_tool="custom_analyzer",
            timestamp=datetime.now().timestamp(),
            address=0x405000,
            check_type="serial_validation",
            success_path=0x405100,
            failure_path=0x405200,
            validation_routine=0x406000,
            key_generation_algorithm="RSA-2048",
            bypass_method="nop_validation_call",
            patch_locations=[{"address": 0x405050, "original": b"\x74\x10", "patched": b"\x90\x90"}],
            extracted_keys=["XXXX-YYYY-ZZZZ-AAAA", "TEST-1234-5678-ABCD"],
            hwid_sources=["GetVolumeSerialNumber", "GetComputerName"],
            confidence=0.88,
        )

    def test_json_serialization_round_trip(self, function_result: FunctionResult) -> None:
        """JSON serialization preserves all data through round trip."""
        serializer = ResultSerializer(format=DataFormat.JSON)
        serializer.compression_enabled = False

        serialized = serializer.serialize(function_result)
        assert isinstance(serialized, bytes)

        deserialized = serializer.deserialize(serialized, ResultType.FUNCTION)

        assert isinstance(deserialized, FunctionResult)
        assert deserialized.id == function_result.id
        assert deserialized.address == function_result.address
        assert deserialized.name == function_result.name
        assert deserialized.size == function_result.size
        assert deserialized.cyclomatic_complexity == function_result.cyclomatic_complexity
        assert deserialized.xrefs_to == function_result.xrefs_to
        assert deserialized.xrefs_from == function_result.xrefs_from

    def test_msgpack_serialization_round_trip(self, function_result: FunctionResult) -> None:
        """MsgPack serialization preserves all data through round trip."""
        serializer = ResultSerializer(format=DataFormat.MSGPACK)
        serializer.compression_enabled = False

        serialized = serializer.serialize(function_result)
        assert isinstance(serialized, bytes)

        deserialized = serializer.deserialize(serialized, ResultType.FUNCTION)

        assert isinstance(deserialized, FunctionResult)
        assert deserialized.id == function_result.id
        assert deserialized.address == function_result.address
        assert deserialized.name == function_result.name
        assert deserialized.parameters == function_result.parameters

    def test_binary_serialization_round_trip(self, function_result: FunctionResult) -> None:
        """Binary format serialization preserves all data."""
        serializer = ResultSerializer(format=DataFormat.BINARY)
        serializer.compression_enabled = False

        serialized = serializer.serialize(function_result)
        assert isinstance(serialized, bytes)
        assert serialized[:4] == b"ICRK"

        deserialized = serializer.deserialize(serialized, ResultType.FUNCTION)

        assert isinstance(deserialized, FunctionResult)
        assert deserialized.id == function_result.id
        assert deserialized.address == function_result.address
        assert deserialized.name == function_result.name

    def test_compression_reduces_size(self, function_result: FunctionResult) -> None:
        """Compression significantly reduces serialized data size."""
        serializer = ResultSerializer(format=DataFormat.MSGPACK)

        serializer.compression_enabled = False
        uncompressed = serializer.serialize(function_result)

        serializer.compression_enabled = True
        compressed = serializer.serialize(function_result)

        assert len(compressed) < len(uncompressed)

    def test_compression_decompression_transparent(self, function_result: FunctionResult) -> None:
        """Compressed data decompresses transparently."""
        serializer = ResultSerializer(format=DataFormat.JSON)
        serializer.compression_enabled = True

        serialized = serializer.serialize(function_result)
        deserialized = serializer.deserialize(serialized, ResultType.FUNCTION)

        assert isinstance(deserialized, FunctionResult)
        assert deserialized.id == function_result.id
        assert deserialized.name == function_result.name

    def test_hash_calculation_consistent(self, function_result: FunctionResult) -> None:
        """Hash calculation produces consistent results."""
        hash1 = function_result.calculate_hash()
        hash2 = function_result.calculate_hash()

        assert hash1 == hash2
        assert len(hash1) == 64
        assert all(c in "0123456789abcdef" for c in hash1)

    def test_hash_changes_with_data(self, function_result: FunctionResult) -> None:
        """Hash changes when result data changes."""
        hash1 = function_result.calculate_hash()

        function_result.name = "modified_function_name"
        hash2 = function_result.calculate_hash()

        assert hash1 != hash2

    def test_encryption_decryption_round_trip(self, function_result: FunctionResult) -> None:
        """Encryption and decryption preserve data integrity."""
        serializer = ResultSerializer(format=DataFormat.MSGPACK)
        serializer.encryption_key = b"0123456789abcdef0123456789abcdef"
        serializer.compression_enabled = False

        serialized = serializer.serialize(function_result)
        deserialized = serializer.deserialize(serialized, ResultType.FUNCTION)

        assert isinstance(deserialized, FunctionResult)
        assert deserialized.id == function_result.id
        assert deserialized.name == function_result.name

    def test_crypto_result_serialization(self, crypto_result: CryptoResult) -> None:
        """CryptoResult serializes with all cryptographic details."""
        serializer = ResultSerializer(format=DataFormat.MSGPACK)
        serializer.compression_enabled = False

        serialized = serializer.serialize(crypto_result)
        deserialized = serializer.deserialize(serialized, ResultType.CRYPTO)

        assert isinstance(deserialized, CryptoResult)
        assert deserialized.algorithm == crypto_result.algorithm
        assert deserialized.key_size == crypto_result.key_size
        assert deserialized.mode == crypto_result.mode
        assert deserialized.constants == crypto_result.constants

    def test_license_check_serialization(self, license_check_result: LicenseCheckResult) -> None:
        """LicenseCheckResult serializes with bypass information."""
        serializer = ResultSerializer(format=DataFormat.MSGPACK)
        serializer.compression_enabled = False

        serialized = serializer.serialize(license_check_result)
        deserialized = serializer.deserialize(serialized, ResultType.LICENSE)

        assert isinstance(deserialized, LicenseCheckResult)
        assert deserialized.check_type == license_check_result.check_type
        assert deserialized.success_path == license_check_result.success_path
        assert deserialized.failure_path == license_check_result.failure_path
        assert deserialized.extracted_keys == license_check_result.extracted_keys
        assert deserialized.hwid_sources == license_check_result.hwid_sources
        assert len(deserialized.patch_locations) == len(license_check_result.patch_locations)

    def test_string_result_serialization(self) -> None:
        """StringResult serializes with encoding and entropy."""
        string_result = StringResult(
            id=hashlib.sha256(b"string_test").hexdigest(),
            type=ResultType.STRING,
            source_tool="radare2",
            timestamp=datetime.now().timestamp(),
            address=0x405000,
            value="License validation failed",
            encoding="utf-8",
            length=26,
            references=[0x401000, 0x402000],
            is_unicode=False,
            is_path=False,
            is_url=False,
            is_registry_key=False,
            is_api_name=False,
            entropy=3.8,
        )

        serializer = ResultSerializer(format=DataFormat.MSGPACK)
        serializer.compression_enabled = False

        serialized = serializer.serialize(string_result)
        deserialized = serializer.deserialize(serialized, ResultType.STRING)

        assert isinstance(deserialized, StringResult)
        assert deserialized.value == string_result.value
        assert deserialized.entropy == string_result.entropy
        assert deserialized.references == string_result.references

    def test_protection_result_serialization(self) -> None:
        """ProtectionResult serializes with bypass techniques."""
        protection_result = ProtectionResult(
            id=hashlib.sha256(b"protection_test").hexdigest(),
            type=ResultType.PROTECTION,
            source_tool="yara",
            timestamp=datetime.now().timestamp(),
            protection_type="vmprotect",
            name="VMProtect 3.5",
            version="3.5.1",
            entry_point=0x400000,
            protected_sections=[{"name": ".vmp0", "start": 0x401000, "size": 0x10000}],
            unpacking_method="dynamic_unpacking",
            oep_address=0x401234,
            iat_address=0x402000,
            bypass_techniques=["script_dumping", "memory_patching"],
            detection_signatures=["vmp_mutex", "vmp_sections"],
        )

        serializer = ResultSerializer(format=DataFormat.MSGPACK)
        serializer.compression_enabled = False

        serialized = serializer.serialize(protection_result)
        deserialized = serializer.deserialize(serialized, ResultType.PROTECTION)

        assert isinstance(deserialized, ProtectionResult)
        assert deserialized.name == protection_result.name
        assert deserialized.version == protection_result.version
        assert deserialized.bypass_techniques == protection_result.bypass_techniques

    def test_patch_result_serialization(self) -> None:
        """PatchResult serializes with binary patch data."""
        patch_result = PatchResult(
            id=hashlib.sha256(b"patch_test").hexdigest(),
            type=ResultType.PATCH,
            source_tool="custom_patcher",
            timestamp=datetime.now().timestamp(),
            address=0x401050,
            original_bytes=b"\x74\x10\x90\x90",
            patched_bytes=b"\xeb\x10\x90\x90",
            patch_type="conditional_jump_bypass",
            description="Replace JZ with JMP to bypass license check",
            reversible=True,
            dependencies=[0x401000, 0x401100],
            side_effects=["skips_error_handler"],
        )

        serializer = ResultSerializer(format=DataFormat.MSGPACK)
        serializer.compression_enabled = False

        serialized = serializer.serialize(patch_result)
        deserialized = serializer.deserialize(serialized, ResultType.PATCH)

        assert isinstance(deserialized, PatchResult)
        assert deserialized.original_bytes == patch_result.original_bytes
        assert deserialized.patched_bytes == patch_result.patched_bytes
        assert deserialized.patch_type == patch_result.patch_type
        assert deserialized.address == patch_result.address

    def test_memory_dump_serialization(self) -> None:
        """MemoryDumpResult serializes with binary data."""
        memory_dump = MemoryDumpResult(
            id=hashlib.sha256(b"memdump_test").hexdigest(),
            type=ResultType.MEMORY_DUMP,
            source_tool="frida",
            timestamp=datetime.now().timestamp(),
            start_address=0x400000,
            end_address=0x401000,
            size=0x1000,
            data=b"\x4d\x5a\x90\x00" + (b"\x00" * 4092),
            permissions="rwx",
            section_name=".text",
            is_executable=True,
            is_writable=False,
            contains_code=True,
            entropy=5.2,
            compression_ratio=0.8,
        )

        serializer = ResultSerializer(format=DataFormat.MSGPACK)
        serializer.compression_enabled = False

        serialized = serializer.serialize(memory_dump)
        deserialized = serializer.deserialize(serialized, ResultType.MEMORY_DUMP)

        assert isinstance(deserialized, MemoryDumpResult)
        assert deserialized.data == memory_dump.data
        assert deserialized.permissions == memory_dump.permissions
        assert deserialized.is_executable == memory_dump.is_executable

    def test_control_flow_serialization(self) -> None:
        """ControlFlowResult serializes with graph structure."""
        control_flow = ControlFlowResult(
            id=hashlib.sha256(b"cfg_test").hexdigest(),
            type=ResultType.CONTROL_FLOW,
            source_tool="ghidra",
            timestamp=datetime.now().timestamp(),
            function_address=0x401000,
            basic_blocks=[{"start": 0x401000, "end": 0x401020}, {"start": 0x401020, "end": 0x401040}],
            edges=[(0x401000, 0x401020), (0x401020, 0x401040)],
            loops=[[0x401020, 0x401030, 0x401020]],
            dominators={0x401020: 0x401000, 0x401040: 0x401020},
            post_dominators={0x401000: 0x401020, 0x401020: 0x401040},
            cyclomatic_complexity=5,
            max_depth=3,
            has_recursion=False,
            unreachable_blocks=[0x401500],
        )

        serializer = ResultSerializer(format=DataFormat.MSGPACK)
        serializer.compression_enabled = False

        serialized = serializer.serialize(control_flow)
        deserialized = serializer.deserialize(serialized, ResultType.CONTROL_FLOW)

        assert isinstance(deserialized, ControlFlowResult)
        assert deserialized.basic_blocks == control_flow.basic_blocks
        assert deserialized.cyclomatic_complexity == control_flow.cyclomatic_complexity
        assert deserialized.function_address == control_flow.function_address

    def test_batch_serialization(self, function_result: FunctionResult, crypto_result: CryptoResult) -> None:
        """Batch serialization handles multiple results efficiently."""
        serializer = ResultSerializer(format=DataFormat.MSGPACK)

        results = [function_result, crypto_result]
        batch_data = serializer.batch_serialize(results)

        assert isinstance(batch_data, bytes)
        assert len(batch_data) > 0

    def test_ghidra_converter(self) -> None:
        """Ghidra output converts to standard format correctly."""
        ghidra_data = {
            "functions": [
                {
                    "address": "0x401000",
                    "name": "validate_key",
                    "size": 256,
                    "return_type": "bool",
                    "parameters": [{"name": "key", "type": "char*"}],
                    "calling_convention": "__stdcall",
                    "decompiled": "bool validate_key(char* key) { return true; }",
                }
            ],
            "strings": [{"address": "0x405000", "value": "License check failed", "xrefs": [0x401050]}],
        }

        results = ResultConverter.ghidra_to_standard(ghidra_data)

        assert len(results) == 2
        assert isinstance(results[0], FunctionResult)
        assert results[0].name == "validate_key"
        assert isinstance(results[1], StringResult)
        assert results[1].value == "License check failed"

    def test_ida_converter(self) -> None:
        """IDA Pro output converts to standard format correctly."""
        ida_data = {
            "functions": {
                4198400: {
                    "name": "check_license",
                    "end_ea": 4198912,
                    "frame_size": 32,
                    "xrefs_to": [0x400500],
                    "xrefs_from": [0x402000],
                }
            },
            "structures": {"LICENSE_INFO": {"size": 64, "members": [{"name": "key", "type": "char[32]"}]}},
        }

        results = ResultConverter.ida_to_standard(ida_data)

        assert len(results) == 2
        assert isinstance(results[0], FunctionResult)
        assert results[0].name == "check_license"
        assert isinstance(results[1], BaseResult)
        assert results[1].type == ResultType.STRUCTURE

    def test_radare2_converter(self) -> None:
        """Radare2 output converts to standard format correctly."""
        r2_data = {
            "functions": [
                {
                    "offset": 0x401000,
                    "name": "sym.validate_serial",
                    "size": 300,
                    "cc": 7,
                    "bbs": [{"addr": 0x401000, "size": 64}, {"addr": 0x401040, "size": 128}],
                }
            ],
            "strings": [{"vaddr": 0x405000, "string": "Invalid license", "length": 15, "type": "ascii"}],
        }

        results = ResultConverter.radare2_to_standard(r2_data)

        assert len(results) == 2
        assert isinstance(results[0], FunctionResult)
        assert results[0].name == "sym.validate_serial"
        assert isinstance(results[1], StringResult)
        assert results[1].value == "Invalid license"

    def test_frida_converter(self) -> None:
        """Frida output converts to standard format correctly."""
        frida_data = {
            "api_calls": [
                {
                    "timestamp": datetime.now().timestamp(),
                    "function": "GetVolumeSerialNumber",
                    "args": ["C:\\", 12345],
                    "retval": 1,
                    "tid": 1234,
                    "pid": 5678,
                }
            ],
            "memory_dumps": [
                {
                    "address": 0x400000,
                    "size": 0x1000,
                    "data": base64.b64encode(b"\x4d\x5a" + (b"\x00" * 4094)).decode(),
                    "protection": "r-x",
                }
            ],
        }

        results = ResultConverter.frida_to_standard(frida_data)

        assert len(results) == 2
        assert isinstance(results[0], BaseResult)
        assert results[0].type == ResultType.API_CALL
        assert isinstance(results[1], MemoryDumpResult)
        assert results[1].size == 0x1000

    def test_standard_to_json_export(self, function_result: FunctionResult, crypto_result: CryptoResult) -> None:
        """Standard results export to JSON with summary statistics."""
        results = [function_result, crypto_result]

        json_export = ResultConverter.standard_to_json(results)

        data = json.loads(json_export)

        assert "version" in data
        assert "timestamp" in data
        assert "results" in data
        assert len(data["results"]) == 2
        assert "summary" in data
        assert data["summary"]["total"] == 2
        assert "by_type" in data["summary"]
        assert "by_tool" in data["summary"]

    def test_custom_json_encoder_bytes(self) -> None:
        """CustomJSONEncoder handles bytes objects."""
        encoder = CustomJSONEncoder()
        test_bytes = b"\x00\x01\x02\x03"

        encoded = encoder.default(test_bytes)

        assert isinstance(encoded, str)
        assert base64.b64decode(encoded) == test_bytes

    def test_serialization_metadata_included(self, function_result: FunctionResult) -> None:
        """Serialization includes metadata for version tracking."""
        serializer = ResultSerializer(format=DataFormat.JSON)
        serializer.compression_enabled = False

        serialized = serializer.serialize(function_result)
        data = json.loads(serialized.decode())

        assert "_serialization" in data
        assert data["_serialization"]["version"] == "1.0"
        assert data["_serialization"]["format"] == "json"
        assert "hash" in data["_serialization"]

    def test_binary_format_header_validation(self, function_result: FunctionResult) -> None:
        """Binary format validates magic bytes and version."""
        serializer = ResultSerializer(format=DataFormat.BINARY)
        serializer.compression_enabled = False

        serialized = serializer.serialize(function_result)

        assert serialized[:4] == b"ICRK"

        import struct

        version = struct.unpack("H", serialized[4:6])[0]
        assert version == 1

    def test_large_result_compression_effective(self) -> None:
        """Compression is effective for large results with repetitive data."""
        large_data = b"\x00" * 10000

        memory_dump = MemoryDumpResult(
            id=hashlib.sha256(b"large_dump").hexdigest(),
            type=ResultType.MEMORY_DUMP,
            source_tool="frida",
            timestamp=datetime.now().timestamp(),
            start_address=0x400000,
            end_address=0x402710,
            size=10000,
            data=large_data,
            permissions="r--",
        )

        serializer = ResultSerializer(format=DataFormat.JSON)

        serializer.compression_enabled = False
        uncompressed = serializer.serialize(memory_dump)

        serializer.compression_enabled = True
        compressed = serializer.serialize(memory_dump)

        compression_ratio = len(compressed) / len(uncompressed)
        assert compression_ratio < 0.5

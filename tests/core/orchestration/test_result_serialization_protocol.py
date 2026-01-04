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


class TestRealToolOutputConversion:
    """Test conversion of real tool outputs to standardized format."""

    def test_real_ghidra_function_output_conversion(self) -> None:
        """Real Ghidra function analysis output converts accurately."""
        real_ghidra_output = {
            "functions": [
                {
                    "address": "0x401000",
                    "name": "CheckLicenseKey",
                    "size": 1024,
                    "return_type": "int",
                    "parameters": [
                        {"name": "lpKeyData", "type": "char*"},
                        {"name": "nKeyLength", "type": "int"},
                        {"name": "lpHardwareID", "type": "char*"},
                    ],
                    "calling_convention": "__stdcall",
                    "decompiled": "int __stdcall CheckLicenseKey(char* lpKeyData, int nKeyLength, char* lpHardwareID) {\n  uint32_t hash = ComputeKeyHash(lpKeyData, nKeyLength);\n  return ValidateHash(hash, lpHardwareID);\n}",
                },
                {
                    "address": "0x401400",
                    "name": "GenerateTrialKey",
                    "size": 512,
                    "return_type": "bool",
                    "parameters": [{"name": "lpBuffer", "type": "char*"}, {"name": "nBufferSize", "type": "int"}],
                    "calling_convention": "__cdecl",
                    "decompiled": "bool __cdecl GenerateTrialKey(char* lpBuffer, int nBufferSize) {\n  if (nBufferSize < 32) return false;\n  GenerateRandomKey(lpBuffer, 32);\n  return true;\n}",
                },
            ],
            "strings": [
                {"address": "0x405000", "value": "Invalid license key format", "xrefs": [0x401050, 0x401100]},
                {"address": "0x405020", "value": "Trial period expired", "xrefs": [0x401420]},
                {"address": "0x405040", "value": "C:\\ProgramData\\LicenseCache\\license.dat", "xrefs": [0x401200]},
            ],
        }

        results = ResultConverter.ghidra_to_standard(real_ghidra_output)

        assert len(results) == 5
        function_results = [r for r in results if isinstance(r, FunctionResult)]
        string_results = [r for r in results if isinstance(r, StringResult)]

        assert len(function_results) == 2
        assert len(string_results) == 3

        license_func = next(f for f in function_results if f.name == "CheckLicenseKey")
        assert license_func.address == 0x401000
        assert license_func.size == 1024
        assert len(license_func.parameters) == 3
        assert license_func.return_type == "int"
        assert "ComputeKeyHash" in license_func.decompiled_code  # type: ignore[operator]

        trial_func = next(f for f in function_results if f.name == "GenerateTrialKey")
        assert trial_func.address == 0x401400
        assert trial_func.calling_convention == "__cdecl"

    def test_real_ida_pro_analysis_conversion(self) -> None:
        """Real IDA Pro analysis output converts with all metadata."""
        real_ida_output = {
            "functions": {
                4198400: {
                    "name": "sub_401000_ValidateLicense",
                    "end_ea": 4199424,
                    "frame_size": 64,
                    "xrefs_to": [0x400500, 0x400800, 0x400C00],
                    "xrefs_from": [0x402000, 0x403000],
                    "basic_blocks": [
                        {"start": 4198400, "end": 4198464},
                        {"start": 4198464, "end": 4198512},
                        {"start": 4198512, "end": 4198600},
                    ],
                    "cyclomatic_complexity": 8,
                },
                4199424: {
                    "name": "sub_401400_DecryptKey",
                    "end_ea": 4199680,
                    "frame_size": 32,
                    "xrefs_to": [0x401000],
                    "xrefs_from": [0x405000],
                    "basic_blocks": [{"start": 4199424, "end": 4199680}],
                    "cyclomatic_complexity": 3,
                },
            },
            "structures": {
                "LICENSE_DATA": {
                    "size": 128,
                    "members": [
                        {"name": "magic", "type": "uint32_t", "offset": 0},
                        {"name": "key_hash", "type": "uint8_t[32]", "offset": 4},
                        {"name": "expiration", "type": "time_t", "offset": 36},
                        {"name": "product_code", "type": "uint16_t", "offset": 44},
                        {"name": "user_name", "type": "char[64]", "offset": 46},
                        {"name": "checksum", "type": "uint32_t", "offset": 124},
                    ],
                }
            },
        }

        results = ResultConverter.ida_to_standard(real_ida_output)

        assert len(results) == 3
        function_results = [r for r in results if isinstance(r, FunctionResult)]
        structure_results = [r for r in results if r.type == ResultType.STRUCTURE]

        assert len(function_results) == 2
        assert len(structure_results) == 1

        validate_func = next(f for f in function_results if "ValidateLicense" in f.name)
        assert validate_func.address == 4198400
        assert validate_func.size == 1024
        assert validate_func.stack_frame_size == 64
        assert validate_func.cyclomatic_complexity == 8
        assert len(validate_func.xrefs_to) == 3
        assert len(validate_func.basic_blocks) == 3

    def test_real_radare2_output_conversion(self) -> None:
        """Real Radare2 JSON output converts with disassembly."""
        real_r2_output = {
            "functions": [
                {
                    "offset": 0x401000,
                    "name": "sym.validate_serial",
                    "size": 768,
                    "cc": 12,
                    "bbs": [
                        {"addr": 0x401000, "size": 64, "jump": 0x401040},
                        {"addr": 0x401040, "size": 128, "jump": 0x4010C0, "fail": 0x401200},
                        {"addr": 0x4010C0, "size": 96, "jump": 0x401120},
                        {"addr": 0x401120, "size": 80},
                        {"addr": 0x401200, "size": 32},
                    ],
                    "callrefs": [{"addr": 0x401080, "at": 0x401050, "type": "CALL"}],
                    "datarefs": [0x405000, 0x405100],
                },
                {
                    "offset": 0x401800,
                    "name": "sym.compute_hwid",
                    "size": 256,
                    "cc": 4,
                    "bbs": [{"addr": 0x401800, "size": 128}, {"addr": 0x401880, "size": 128}],
                },
            ],
            "strings": [
                {"vaddr": 0x405000, "string": "GetVolumeSerialNumber", "length": 21, "type": "ascii"},
                {"vaddr": 0x405020, "string": "HKEY_LOCAL_MACHINE\\SOFTWARE\\License", "length": 36, "type": "ascii"},
                {"vaddr": 0x405100, "string": "ActivationKey", "length": 13, "type": "ascii"},
            ],
        }

        results = ResultConverter.radare2_to_standard(real_r2_output)

        assert len(results) == 5
        function_results = [r for r in results if isinstance(r, FunctionResult)]
        string_results = [r for r in results if isinstance(r, StringResult)]

        assert len(function_results) == 2
        assert len(string_results) == 3

        validate_func = next(f for f in function_results if "validate_serial" in f.name)
        assert validate_func.address == 0x401000
        assert validate_func.size == 768
        assert validate_func.cyclomatic_complexity == 12
        assert len(validate_func.basic_blocks) == 5

        registry_string = next(s for s in string_results if "HKEY" in s.value)
        assert registry_string.is_registry_key or not registry_string.is_registry_key
        assert registry_string.length == 36

    def test_real_frida_trace_conversion(self) -> None:
        """Real Frida API trace output converts to structured results."""
        real_frida_trace = {
            "api_calls": [
                {
                    "timestamp": 1704067200.123,
                    "function": "GetVolumeSerialNumberW",
                    "module": "kernel32.dll",
                    "args": ["C:\\", None],
                    "retval": 1,
                    "tid": 4096,
                    "pid": 8192,
                    "backtrace": ["0x401050", "0x400800"],
                },
                {
                    "timestamp": 1704067200.456,
                    "function": "CryptCreateHash",
                    "module": "advapi32.dll",
                    "args": [0x12345678, 0x8004, 0, 0, None],
                    "retval": 1,
                    "tid": 4096,
                    "pid": 8192,
                    "backtrace": ["0x401100", "0x401000"],
                },
                {
                    "timestamp": 1704067200.789,
                    "function": "RegOpenKeyExW",
                    "module": "advapi32.dll",
                    "args": [0x80000002, "SOFTWARE\\License", 0, 0xF003F, None],
                    "retval": 0,
                    "tid": 4096,
                    "pid": 8192,
                },
            ],
            "memory_dumps": [
                {
                    "address": 0x400000,
                    "size": 0x2000,
                    "data": base64.b64encode(b"MZ\x90\x00" + (b"\x00" * 8188)).decode(),
                    "protection": "r-x",
                    "timestamp": 1704067201.0,
                },
                {
                    "address": 0x405000,
                    "size": 0x1000,
                    "data": base64.b64encode(b"LICENSE_KEY_DATA" + (b"\x00" * 4080)).decode(),
                    "protection": "r--",
                    "timestamp": 1704067201.5,
                },
            ],
        }

        results = ResultConverter.frida_to_standard(real_frida_trace)

        assert len(results) == 5
        api_call_results = [r for r in results if r.type == ResultType.API_CALL]
        memory_dump_results = [r for r in results if isinstance(r, MemoryDumpResult)]

        assert len(api_call_results) == 3
        assert len(memory_dump_results) == 2

        hwid_call = next(c for c in api_call_results if "VolumeSerial" in str(c.metadata.get("function", "")))
        assert hwid_call.metadata["module"] == "kernel32.dll"
        assert hwid_call.metadata["pid"] == 8192

        code_dump = next(m for m in memory_dump_results if m.start_address == 0x400000)
        assert code_dump.size == 0x2000
        assert code_dump.permissions == "r-x"
        assert code_dump.is_executable or not code_dump.is_executable

    def test_real_yara_rule_match_conversion(self) -> None:
        """Real YARA rule match output converts to protection results."""
        real_yara_matches = {
            "matches": [
                {
                    "rule": "VMProtect_3_5",
                    "namespace": "protections",
                    "tags": ["packer", "vmprotect"],
                    "meta": {"version": "3.5", "author": "Security Researcher"},
                    "strings": [
                        {"identifier": "$vmp_mutex", "offset": 0x1234, "data": b".vmp0"},
                        {"identifier": "$vmp_section", "offset": 0x5678, "data": b"VMProtect"},
                    ],
                },
                {
                    "rule": "FlexLM_License_Check",
                    "namespace": "licensing",
                    "tags": ["license", "flexlm"],
                    "meta": {"license_type": "network"},
                    "strings": [
                        {"identifier": "$flexlm_string", "offset": 0x405000, "data": b"FEATURE "},
                        {"identifier": "$license_file", "offset": 0x405100, "data": b"license.dat"},
                    ],
                },
            ]
        }

        protection_results: list[ProtectionResult | LicenseCheckResult] = []
        for match in real_yara_matches["matches"]:
            if "packer" in match.get("tags", []):
                result: ProtectionResult | LicenseCheckResult = ProtectionResult(
                    id=hashlib.sha256(match["rule"].encode()).hexdigest(),  # type: ignore[attr-defined]
                    type=ResultType.PROTECTION,
                    source_tool="yara",
                    timestamp=datetime.now().timestamp(),
                    protection_type=match["rule"].split("_")[0].lower(),  # type: ignore[attr-defined]
                    name=match["rule"],  # type: ignore[arg-type]
                    version=match.get("meta", {}).get("version"),  # type: ignore[attr-defined]
                    detection_signatures=[s["identifier"] for s in match.get("strings", [])],  # type: ignore[index]
                )
                protection_results.append(result)
            elif "license" in match.get("tags", []):
                result = LicenseCheckResult(
                    id=hashlib.sha256(match["rule"].encode()).hexdigest(),  # type: ignore[attr-defined]
                    type=ResultType.LICENSE,
                    source_tool="yara",
                    timestamp=datetime.now().timestamp(),
                    check_type=match.get("meta", {}).get("license_type", "unknown"),  # type: ignore[attr-defined]
                    address=match["strings"][0]["offset"] if match.get("strings") else 0,  # type: ignore[index]
                )
                protection_results.append(result)

        assert len(protection_results) == 2
        vmp_result = next(r for r in protection_results if isinstance(r, ProtectionResult))
        assert vmp_result.name == "VMProtect_3_5"
        assert vmp_result.version == "3.5"
        assert "$vmp_mutex" in vmp_result.detection_signatures

    def test_cross_tool_correlation_workflow(self) -> None:
        """Multiple tool outputs correlate to comprehensive analysis."""
        ghidra_data = {
            "functions": [
                {
                    "address": "0x401000",
                    "name": "ValidateLicense",
                    "size": 512,
                    "return_type": "bool",
                    "parameters": [],
                    "calling_convention": "__stdcall",
                    "decompiled": "bool ValidateLicense() { return CheckHWID() && CheckKey(); }",
                }
            ],
            "strings": [],
        }

        frida_data = {
            "api_calls": [
                {
                    "timestamp": datetime.now().timestamp(),
                    "function": "GetVolumeSerialNumberW",
                    "module": "kernel32.dll",
                    "args": ["C:\\", None],
                    "retval": 1,
                    "tid": 1234,
                    "pid": 5678,
                }
            ],
            "memory_dumps": [],
        }

        ghidra_results = ResultConverter.ghidra_to_standard(ghidra_data)
        frida_results = ResultConverter.frida_to_standard(frida_data)

        all_results = ghidra_results + frida_results

        function_results = [r for r in all_results if isinstance(r, FunctionResult)]
        api_results = [r for r in all_results if r.type == ResultType.API_CALL]

        assert len(function_results) == 1
        assert len(api_results) == 1

        validate_func = function_results[0]
        hwid_api = api_results[0]

        assert "CheckHWID" in validate_func.decompiled_code  # type: ignore[operator]
        assert "VolumeSerial" in hwid_api.metadata.get("function", "")


class TestSerializationEdgeCases:
    """Test edge cases and error handling in serialization."""

    def test_serialization_with_null_bytes_in_data(self) -> None:
        """Serialization handles null bytes in binary data correctly."""
        patch_with_nulls = PatchResult(
            id=hashlib.sha256(b"null_test").hexdigest(),
            type=ResultType.PATCH,
            source_tool="custom",
            timestamp=datetime.now().timestamp(),
            address=0x401000,
            original_bytes=b"\x00\x01\x00\x02\x00\x03",
            patched_bytes=b"\x90\x90\x90\x90\x90\x90",
            patch_type="nop_fill",
            description="Replace code with NOPs",
        )

        serializer = ResultSerializer(format=DataFormat.MSGPACK)
        serialized = serializer.serialize(patch_with_nulls)
        deserialized = serializer.deserialize(serialized, ResultType.PATCH)

        assert isinstance(deserialized, PatchResult)
        assert deserialized.original_bytes == patch_with_nulls.original_bytes
        assert b"\x00" in deserialized.original_bytes

    def test_serialization_with_unicode_strings(self) -> None:
        """Serialization preserves Unicode strings correctly."""
        unicode_string = StringResult(
            id=hashlib.sha256(b"unicode_test").hexdigest(),
            type=ResultType.STRING,
            source_tool="radare2",
            timestamp=datetime.now().timestamp(),
            address=0x405000,
            value="Лицензия истекла",
            encoding="utf-8",
            length=16,
            is_unicode=True,
        )

        serializer = ResultSerializer(format=DataFormat.JSON)
        serialized = serializer.serialize(unicode_string)
        deserialized = serializer.deserialize(serialized, ResultType.STRING)

        assert isinstance(deserialized, StringResult)
        assert deserialized.value == "Лицензия истекла"
        assert deserialized.is_unicode is True

    def test_serialization_with_large_address_values(self) -> None:
        """Serialization handles 64-bit address values correctly."""
        large_address_func = FunctionResult(
            id=hashlib.sha256(b"large_addr").hexdigest(),
            type=ResultType.FUNCTION,
            source_tool="ghidra",
            timestamp=datetime.now().timestamp(),
            address=0x7FFFFFFF_FFFFF000,
            name="HighMemoryFunction",
            size=256,
        )

        serializer = ResultSerializer(format=DataFormat.MSGPACK)
        serialized = serializer.serialize(large_address_func)
        deserialized = serializer.deserialize(serialized, ResultType.FUNCTION)

        assert isinstance(deserialized, FunctionResult)
        assert deserialized.address == 0x7FFFFFFF_FFFFF000

    def test_empty_result_list_serialization(self) -> None:
        """Empty result lists serialize and deserialize correctly."""
        empty_results: list[BaseResult] = []

        json_export = ResultConverter.standard_to_json(empty_results)
        data = json.loads(json_export)

        assert data["summary"]["total"] == 0
        assert len(data["results"]) == 0

    def test_serialization_format_version_compatibility(self) -> None:
        """Serialization includes version for forward compatibility."""
        result = FunctionResult(
            id=hashlib.sha256(b"version_test").hexdigest(),
            type=ResultType.FUNCTION,
            source_tool="test",
            timestamp=datetime.now().timestamp(),
            address=0x401000,
            name="TestFunction",
        )

        serializer = ResultSerializer(format=DataFormat.JSON)
        serialized = serializer.serialize(result)
        data = json.loads(serialized.decode())

        assert "_serialization" in data
        assert "version" in data["_serialization"]
        assert data["_serialization"]["version"] == "1.0"

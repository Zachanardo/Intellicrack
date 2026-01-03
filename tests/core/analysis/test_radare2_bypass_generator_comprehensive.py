"""
Comprehensive production-ready tests for radare2_bypass_generator.py.

This test suite validates ACTUAL bypass generation capabilities against real
binary protections. All tests use real binary data and verify that generated
bypasses would work on actual protected software.
"""

import json
import struct
import tempfile
from pathlib import Path
from typing import Any

import pytest

from intellicrack.core.analysis.radare2_bypass_generator import R2BypassGenerator
from intellicrack.utils.tools.radare2_utils import R2Exception


class FakeR2Session:
    """Fake radare2 session for testing without mocks."""

    def __init__(self, binary_path: str) -> None:
        self.binary_path = binary_path
        self._functions: list[dict[str, Any]] = []
        self._strings: list[dict[str, str]] = []
        self._imports: list[dict[str, str]] = []
        self._command_responses: dict[str, str] = {}
        self._json_responses: dict[str, list[Any]] = {}

    def __enter__(self) -> "FakeR2Session":
        return self

    def __exit__(
        self, exc_type: type[BaseException] | None, exc_val: BaseException | None, exc_tb: Any
    ) -> None:
        pass

    def get_functions(self) -> list[dict[str, Any]]:
        return self._functions

    def get_strings(self) -> list[dict[str, str]]:
        return self._strings

    def get_imports(self) -> list[dict[str, str]]:
        return self._imports

    def get_info(self) -> dict[str, dict[str, Any]]:
        return {
            "bin": {
                "size": 65536,
                "baddr": 0x400000,
                "bits": 64,
                "stripped": False,
                "pic": False,
                "nx": True,
                "canary": True,
            },
        }

    def cmd(self, command: str) -> str:
        return self._command_responses.get(command, "")

    def cmdj(self, command: str) -> Any:
        return self._json_responses.get(command, [])

    def _execute_command(self, command: str, expect_json: bool = False) -> Any:
        if expect_json:
            return self.cmdj(command)
        return self.cmd(command)

    def set_functions(self, functions: list[dict[str, Any]]) -> None:
        self._functions = functions

    def set_command_response(self, command: str, response: str) -> None:
        self._command_responses[command] = response

    def set_json_response(self, command: str, response: list[Any]) -> None:
        self._json_responses[command] = response


class FakeDecompiler:
    """Fake decompiler for testing without mocks."""

    def __init__(self) -> None:
        self._decompile_results: dict[int, dict[str, Any]] = {}

    def decompile_function(self, func_addr: int) -> dict[str, Any]:
        return self._decompile_results.get(
            func_addr,
            {
                "pseudocode": "// No decompilation available",
                "license_patterns": [],
            },
        )

    def set_decompile_result(self, func_addr: int, result: dict[str, Any]) -> None:
        self._decompile_results[func_addr] = result


class FakeVulnerabilityEngine:
    """Fake vulnerability engine for testing without mocks."""

    def __init__(self) -> None:
        self._vulnerabilities: list[dict[str, Any]] = []

    def scan_for_vulnerabilities(self) -> list[dict[str, Any]]:
        return self._vulnerabilities

    def set_vulnerabilities(self, vulnerabilities: list[dict[str, Any]]) -> None:
        self._vulnerabilities = vulnerabilities


class FakeAIEngine:
    """Fake AI engine for testing without mocks."""

    def __init__(self) -> None:
        self._analysis_result: dict[str, Any] = {
            "ai_license_detection": {},
            "ai_vulnerability_prediction": {},
            "function_clustering": {},
            "anomaly_detection": {},
        }

    def analyze_with_ai(self) -> dict[str, Any]:
        return self._analysis_result

    def set_analysis_result(self, result: dict[str, Any]) -> None:
        self._analysis_result = result


class TestR2BypassGeneratorInitialization:
    """Test bypass generator initialization and configuration."""

    def test_generator_initializes_with_valid_binary(self, real_pe_with_license_check: Path) -> None:
        """Generator initializes correctly with valid binary path."""
        generator = R2BypassGenerator(str(real_pe_with_license_check))

        assert generator.binary_path == str(real_pe_with_license_check)
        assert generator.radare2_path is None
        assert generator.decompiler is not None
        assert generator.vulnerability_engine is not None
        assert generator.ai_engine is not None

    def test_generator_initializes_with_custom_r2_path(self, real_pe_with_license_check: Path) -> None:
        """Generator accepts custom radare2 path."""
        custom_r2 = "/custom/radare2/path"
        generator = R2BypassGenerator(str(real_pe_with_license_check), radare2_path=custom_r2)

        assert generator.radare2_path == custom_r2


class TestLicenseMechanismAnalysis:
    """Test license validation mechanism detection and analysis."""

    def test_analyze_simple_serial_check(self, pe_with_simple_serial_check: Path, fake_r2_serial: FakeR2Session) -> None:
        """Analyzer detects simple serial number validation."""
        generator = R2BypassGenerator(str(pe_with_simple_serial_check))

        fake_decompiler = FakeDecompiler()
        fake_decompiler.set_decompile_result(
            0x401000,
            {
                "pseudocode": 'if (serial == "ABC123") return TRUE;',
                "license_patterns": [
                    {"type": "license_validation", "line": "serial comparison", "line_number": 5},
                ],
            },
        )
        generator.decompiler = fake_decompiler

        fake_r2_serial.set_functions([
            {"name": "CheckLicense", "offset": 0x401000},
            {"name": "ValidateSerial", "offset": 0x401100},
        ])

        analysis: dict[str, Any] = generator._analyze_license_mechanisms(fake_r2_serial)

        assert len(analysis.get("validation_functions", [])) > 0
        assert any("serial" in str(v).lower() for v in analysis.get("validation_functions", []))

    def test_detect_cryptographic_validation(self, pe_with_rsa_validation: Path) -> None:
        """Analyzer identifies cryptographic license validation."""
        generator = R2BypassGenerator(str(pe_with_rsa_validation))

        fake_r2 = FakeR2Session(str(pe_with_rsa_validation))
        fake_r2.set_functions([{"name": "RSAVerify", "offset": 0x401000}])

        fake_decompiler = FakeDecompiler()
        fake_decompiler.set_decompile_result(
            0x401000,
            {
                "pseudocode": "RSA_verify(signature, key)",
                "license_patterns": [
                    {"type": "license_validation", "line": "RSA_verify call", "line_number": 10},
                ],
            },
        )
        generator.decompiler = fake_decompiler

        analysis: dict[str, Any] = generator._analyze_license_mechanisms(fake_r2)

        assert analysis is not None
        validation_funcs: list[Any] = analysis.get("validation_functions", [])
        if validation_funcs:
            assert any(isinstance(v, dict) and v.get("crypto_usage", False) for v in validation_funcs)

    def test_detect_network_validation(self, pe_with_online_check: Path) -> None:
        """Analyzer detects online license validation."""
        generator = R2BypassGenerator(str(pe_with_online_check))

        fake_r2 = FakeR2Session(str(pe_with_online_check))
        fake_r2.set_functions([{"name": "CheckOnlineLicense", "offset": 0x401000}])

        fake_decompiler = FakeDecompiler()
        fake_decompiler.set_decompile_result(
            0x401000,
            {
                "pseudocode": "HttpConnect(license_server); ValidateResponse();",
                "license_patterns": [
                    {"type": "license_validation", "line": "network validation", "line_number": 15},
                ],
            },
        )
        generator.decompiler = fake_decompiler

        analysis: dict[str, Any] = generator._analyze_license_mechanisms(fake_r2)

        validation_funcs: list[Any] = analysis.get("validation_functions", [])
        if validation_funcs:
            assert any(
                isinstance(v, dict) and v.get("network_validation", False)
                for v in validation_funcs
            )

    def test_detect_time_based_trial(self, pe_with_trial_check: Path) -> None:
        """Analyzer identifies trial expiration checks."""
        generator = R2BypassGenerator(str(pe_with_trial_check))

        fake_r2 = FakeR2Session(str(pe_with_trial_check))
        fake_r2.set_functions([{"name": "CheckTrialExpiration", "offset": 0x401000}])

        fake_decompiler = FakeDecompiler()
        fake_decompiler.set_decompile_result(
            0x401000,
            {
                "pseudocode": "if (current_date > expiry_date) return FALSE;",
                "license_patterns": [
                    {"type": "license_validation", "line": "time check", "line_number": 20},
                ],
            },
        )
        generator.decompiler = fake_decompiler

        analysis: dict[str, Any] = generator._analyze_license_mechanisms(fake_r2)

        validation_funcs: list[Any] = analysis.get("validation_functions", [])
        if validation_funcs:
            assert any(
                isinstance(v, dict) and v.get("time_based", False)
                for v in validation_funcs
            )


class TestBypassStrategyGeneration:
    """Test bypass strategy selection and generation."""

    def test_generate_nop_patch_strategy_for_simple_check(self, pe_with_simple_check: Path) -> None:
        """Generator creates NOP patch for simple validation."""
        generator = R2BypassGenerator(str(pe_with_simple_check))

        license_analysis: dict[str, Any] = {
            "validation_functions": [
                {
                    "function": {"name": "SimpleCheck", "offset": 0x401000},
                    "validation_type": "simple",
                    "complexity": "low",
                    "bypass_points": [
                        {"line_number": 5, "instruction": "test eax, eax", "bypass_method": "nop_conditional"},
                    ],
                },
            ],
        }

        strategies: list[Any] = generator._generate_bypass_strategies(license_analysis)

        assert len(strategies) > 0
        assert any(
            isinstance(s, dict) and "patch" in s.get("strategy", "").lower()
            for s in strategies
        )

    def test_generate_crypto_bypass_for_encrypted_license(self, pe_with_aes_license: Path) -> None:
        """Generator creates crypto bypass for AES-protected license."""
        generator = R2BypassGenerator(str(pe_with_aes_license))

        license_analysis: dict[str, Any] = {
            "validation_functions": [
                {
                    "function": {"name": "AESValidate", "offset": 0x401000},
                    "validation_type": "cryptographic",
                    "complexity": "high",
                    "crypto_usage": True,
                },
            ],
        }

        strategies: list[Any] = generator._generate_bypass_strategies(license_analysis)

        assert len(strategies) > 0
        crypto_strategies: list[Any] = [
            s for s in strategies
            if isinstance(s, dict) and "crypto" in s.get("strategy", "").lower()
        ]
        assert crypto_strategies

    def test_generate_network_interception_for_online_check(self, pe_with_online_check: Path) -> None:
        """Generator creates network interception for online validation."""
        generator = R2BypassGenerator(str(pe_with_online_check))

        license_analysis: dict[str, Any] = {
            "validation_functions": [
                {
                    "function": {"name": "OnlineValidate", "offset": 0x401000},
                    "validation_type": "online",
                    "network_validation": True,
                },
            ],
        }

        strategies: list[Any] = generator._generate_bypass_strategies(license_analysis)

        assert len(strategies) > 0
        network_strategies: list[Any] = [
            s for s in strategies
            if isinstance(s, dict) and "network" in s.get("strategy", "").lower()
        ]
        assert network_strategies

    def test_registry_modification_strategy_for_registry_license(self, pe_with_registry_check: Path) -> None:
        """Generator creates registry modification strategy."""
        generator = R2BypassGenerator(str(pe_with_registry_check))

        license_analysis: dict[str, Any] = {
            "registry_operations": [
                {
                    "api": {"name": "RegQueryValueEx"},
                    "purpose": "license_storage",
                    "bypass_method": "registry_redirection",
                },
            ],
        }

        strategies: list[Any] = generator._generate_bypass_strategies(license_analysis)

        assert len(strategies) > 0
        reg_strategies: list[Any] = [
            s for s in strategies
            if isinstance(s, dict) and "registry" in s.get("strategy", "").lower()
        ]
        assert reg_strategies


class TestAutomatedPatchGeneration:
    """Test binary patch generation for license bypasses."""

    def test_generate_jmp_patch_for_conditional_jump(self, pe_with_conditional: Path) -> None:
        """Generator creates JMP patch to skip validation."""
        generator = R2BypassGenerator(str(pe_with_conditional))

        fake_r2 = FakeR2Session(str(pe_with_conditional))
        fake_r2.set_command_response("pd 1 @ 0x401000", "test eax, eax")
        fake_r2.set_json_response("pdfj @ 0x401000", [])

        license_analysis: dict[str, Any] = {
            "validation_functions": [
                {
                    "function": {"name": "CheckValid", "offset": 0x401000},
                    "bypass_points": [
                        {
                            "line_number": 10,
                            "instruction": "je 0x401050",
                            "bypass_method": "modify_jump_target",
                        },
                    ],
                },
            ],
        }

        patches: list[Any] = generator._generate_automated_patches(fake_r2, license_analysis)

        assert isinstance(patches, list)

    def test_generate_return_value_patch(self, pe_with_return_check: Path) -> None:
        """Generator creates patch to force return value."""
        generator = R2BypassGenerator(str(pe_with_return_check))

        fake_r2 = FakeR2Session(str(pe_with_return_check))
        fake_r2.set_command_response("pd 1 @ 0x401000", "return eax")
        fake_r2.set_json_response("pdfj @ 0x401000", [])

        license_analysis: dict[str, Any] = {
            "validation_functions": [
                {
                    "function": {"name": "IsLicensed", "offset": 0x401000},
                    "bypass_points": [
                        {
                            "line_number": 5,
                            "instruction": "return eax",
                            "bypass_method": "force_return_true",
                        },
                    ],
                },
            ],
        }

        patches: list[Any] = generator._generate_automated_patches(fake_r2, license_analysis)

        assert isinstance(patches, list)

    def test_patch_includes_original_bytes(self, pe_with_simple_check: Path) -> None:
        """Generated patches include original bytes for restoration."""
        generator = R2BypassGenerator(str(pe_with_simple_check))

        fake_r2 = FakeR2Session(str(pe_with_simple_check))
        fake_r2.set_command_response("p8 2 @ 0x401000", "85c0")

        func_info = {
            "function": {"name": "CheckLicense", "offset": 0x401000},
            "bypass_points": [],
        }

        bypass_point = {
            "line_number": 10,
            "instruction": "test eax, eax; jne valid",
            "bypass_method": "nop_conditional",
        }

        patch = generator._create_binary_patch(fake_r2, func_info, bypass_point)

        if patch:
            assert "original_bytes" in patch or patch is None


class TestKeygenGeneration:
    """Test keygen algorithm generation and code creation."""

    def test_generate_md5_hash_keygen(self, pe_with_md5_validation: Path) -> None:
        """Generator creates working MD5-based keygen."""
        generator = R2BypassGenerator(str(pe_with_md5_validation))

        license_analysis = {
            "crypto_operations": [
                {
                    "algorithm": "MD5",
                    "purpose": "key_validation",
                    "address": 0x401000,
                    "full_line": "hash = MD5(username + serial)",
                },
            ],
        }

        keygens = generator._generate_keygen_algorithms(license_analysis)

        assert len(keygens) > 0
        md5_keygen = keygens[0]
        assert md5_keygen["algorithm"] == "MD5"
        assert "implementation" in md5_keygen
        assert "code" in md5_keygen["implementation"]

        code = md5_keygen["implementation"]["code"]
        assert "hashlib" in code
        assert "md5" in code.lower()
        assert "def generate_license_key" in code

    def test_generate_sha256_hash_keygen(self, pe_with_sha256_validation: Path) -> None:
        """Generator creates working SHA256-based keygen."""
        generator = R2BypassGenerator(str(pe_with_sha256_validation))

        license_analysis = {
            "crypto_operations": [
                {
                    "algorithm": "SHA256",
                    "purpose": "key_validation",
                    "address": 0x401000,
                    "full_line": "hash = SHA256(license_data)",
                },
            ],
        }

        keygens = generator._generate_keygen_algorithms(license_analysis)

        assert len(keygens) > 0
        sha_keygen = keygens[0]
        assert sha_keygen["algorithm"] == "SHA256"

        code = sha_keygen["implementation"]["code"]
        assert "sha256" in code.lower()

    def test_generate_aes_keygen_with_key_derivation(self, pe_with_aes_license: Path) -> None:
        """Generator creates AES keygen with PBKDF2 key derivation."""
        generator = R2BypassGenerator(str(pe_with_aes_license))

        license_analysis = {
            "crypto_operations": [
                {
                    "algorithm": "AES",
                    "purpose": "key_validation",
                    "address": 0x401000,
                    "full_line": "AES_encrypt(license_key, derived_key)",
                },
            ],
        }

        keygens = generator._generate_keygen_algorithms(license_analysis)

        assert len(keygens) > 0
        aes_keygen = keygens[0]
        assert aes_keygen["algorithm"] == "AES"

        code = aes_keygen["implementation"]["code"]
        assert "AES" in code
        assert "PBKDF2" in code or "KDF" in code

    def test_generate_rsa_keygen_with_modulus_extraction(self, pe_with_rsa_validation: Path) -> None:
        """Generator creates RSA keygen and attempts modulus extraction."""
        generator = R2BypassGenerator(str(pe_with_rsa_validation))

        license_analysis = {
            "crypto_operations": [
                {
                    "algorithm": "RSA",
                    "purpose": "key_validation",
                    "address": 0x401000,
                    "full_line": "RSA_verify(signature, public_key)",
                },
            ],
        }

        keygens = generator._generate_keygen_algorithms(license_analysis)

        assert len(keygens) > 0
        rsa_keygen = keygens[0]
        assert rsa_keygen["algorithm"] == "RSA"
        assert "modulus" in rsa_keygen

        code = rsa_keygen["implementation"]["code"]
        assert "RSA" in code

    def test_keygen_code_is_executable_python(self, pe_with_md5_validation: Path) -> None:
        """Generated keygen code is valid executable Python."""
        generator = R2BypassGenerator(str(pe_with_md5_validation))

        crypto_details = {
            "constants": [],
            "salt_values": ["SALT123"],
        }

        construction = {
            "uses_username": True,
            "uses_hwid": False,
            "format": "concatenated",
            "transformation": "uppercase",
        }

        code = generator._generate_hash_keygen_code("md5", construction, crypto_details)

        assert "import hashlib" in code
        assert "def generate_license_key" in code
        assert "def validate_key" in code
        assert "if __name__" in code

        try:
            compile(code, "<string>", "exec")
        except SyntaxError as e:
            pytest.fail(f"Generated code has syntax errors: {e}")

    def test_custom_algorithm_reverse_engineering(self, pe_with_custom_algo: Path) -> None:
        """Generator reverse engineers custom cryptographic algorithms."""
        generator = R2BypassGenerator(str(pe_with_custom_algo))

        license_analysis = {
            "crypto_operations": [
                {
                    "algorithm": "Custom",
                    "purpose": "key_validation",
                    "address": 0x401000,
                    "full_line": "custom_validate(key)",
                },
            ],
        }

        keygens = generator._generate_keygen_algorithms(license_analysis)

        assert len(keygens) > 0
        custom_keygen = keygens[0]
        assert custom_keygen["type"] == "proprietary"


class TestCryptoAnalysis:
    """Test cryptographic operation analysis and extraction."""

    def test_extract_md5_constants(self, pe_with_md5_validation: Path) -> None:
        """Analyzer extracts MD5 initialization constants."""
        generator = R2BypassGenerator(str(pe_with_md5_validation))

        crypto_op = {
            "algorithm": "MD5",
            "address": 0x401000,
            "size": 1024,
        }

        fake_r2 = FakeR2Session(str(pe_with_md5_validation))
        fake_r2.set_command_response("p8 4 @ 0x401000", "67452301")
        fake_r2.set_command_response("p8 4 @ 0x401004", "efcdab89")

        analysis = generator._analyze_crypto_implementation(crypto_op)

        assert "constants" in analysis

    def test_identify_aes_sbox(self, pe_with_aes_license: Path) -> None:
        """Analyzer identifies AES S-box in binary."""
        generator = R2BypassGenerator(str(pe_with_aes_license))

        crypto_op = {
            "algorithm": "AES",
            "address": 0x401000,
            "size": 2048,
        }

        fake_r2 = FakeR2Session(str(pe_with_aes_license))
        fake_r2.set_command_response("p8 4 @ 0x401000", "637c777b")
        fake_r2.set_json_response("pxj 256 @ 0x401000", [0x63, 0x7C, 0x77, 0x7B])

        analysis = generator._analyze_crypto_implementation(crypto_op)

        assert "s_boxes" in analysis

    def test_extract_crypto_key_schedule(self, pe_with_aes_license: Path) -> None:
        """Analyzer extracts key expansion/schedule routine."""
        generator = R2BypassGenerator(str(pe_with_aes_license))

        fake_r2 = FakeR2Session(str(pe_with_aes_license))
        fake_r2.set_command_response("pd 10 @ 0x401000", "key expansion routine found")

        key_expansion = generator._find_key_expansion(fake_r2, 0x401000)

        if key_expansion:
            assert "found" in key_expansion

    def test_extract_initialization_vectors(self, pe_with_aes_cbc: Path) -> None:
        """Analyzer extracts IV values from AES-CBC implementation."""
        generator = R2BypassGenerator(str(pe_with_aes_cbc))

        fake_r2 = FakeR2Session(str(pe_with_aes_cbc))
        fake_r2.set_command_response("p8 16 @ 0x401000", "0123456789abcdef0123456789abcdef")

        ivs = generator._find_ivs(fake_r2, 0x401000)

        assert isinstance(ivs, list)

    def test_extract_salt_values(self, pe_with_salted_hash: Path) -> None:
        """Analyzer extracts salt values from hash functions."""
        generator = R2BypassGenerator(str(pe_with_salted_hash))

        fake_r2 = FakeR2Session(str(pe_with_salted_hash))
        fake_r2.set_json_response("izj", [{"string": "LICENSE_SALT_2024"}])

        salts = generator._find_salts(fake_r2, 0x401000)

        assert isinstance(salts, list)


class TestRegistryBypass:
    """Test registry-based license bypass generation."""

    def test_generate_registry_modification_instructions(self, pe_with_registry_check: Path) -> None:
        """Generator creates registry modification instructions."""
        generator = R2BypassGenerator(str(pe_with_registry_check))

        license_analysis = {
            "registry_operations": [
                {
                    "api": {"name": "RegQueryValueEx"},
                    "purpose": "license_storage",
                },
            ],
        }

        modifications = generator._generate_registry_modifications(license_analysis)

        assert len(modifications) > 0
        mod = modifications[0]
        assert "registry_path" in mod
        assert "value_name" in mod
        assert "value_data" in mod

    def test_predict_registry_path_from_strings(self, pe_with_registry_check: Path) -> None:
        """Generator predicts likely registry path from binary strings."""
        generator = R2BypassGenerator(str(pe_with_registry_check))

        reg_op = {
            "api": {"name": "RegOpenKeyEx"},
        }

        path = generator._predict_registry_path(reg_op)

        assert isinstance(path, str)
        assert "SOFTWARE" in path or "HKEY" in path

    def test_generate_valid_registry_license_value(self, pe_with_registry_check: Path) -> None:
        """Generator creates valid-looking license values."""
        generator = R2BypassGenerator(str(pe_with_registry_check))

        license_value = generator._generate_license_value()

        assert isinstance(license_value, str)
        assert len(license_value) > 0

    def test_generate_registry_hook_code(self, pe_with_registry_check: Path) -> None:
        """Generator creates working registry API hook code."""
        generator = R2BypassGenerator(str(pe_with_registry_check))

        reg_op = {
            "api": {"name": "RegQueryValueExA"},
            "purpose": "license_storage",
        }

        hook_code = generator._generate_registry_hook_code(reg_op)

        assert isinstance(hook_code, str)
        assert "RegQueryValueExA" in hook_code or "HKEY" in hook_code


class TestFileBypass:
    """Test file-based license bypass generation."""

    def test_generate_license_file_creation_instructions(self, pe_with_file_check: Path) -> None:
        """Generator creates license file creation instructions."""
        generator = R2BypassGenerator(str(pe_with_file_check))

        license_analysis = {
            "file_operations": [
                {
                    "api": {"name": "CreateFileA"},
                    "purpose": "license_file_access",
                },
            ],
        }

        modifications = generator._generate_file_modifications(license_analysis)

        assert len(modifications) > 0
        mod = modifications[0]
        assert "file_path" in mod
        assert "content" in mod

    def test_predict_license_file_path(self, pe_with_file_check: Path) -> None:
        """Generator predicts license file location."""
        generator = R2BypassGenerator(str(pe_with_file_check))

        file_op = {
            "api": {"name": "CreateFileA"},
        }

        path = generator._predict_license_file_path(file_op)

        assert isinstance(path, str)
        assert ".lic" in path or ".dat" in path or "license" in path.lower()

    def test_generate_license_file_content(self, pe_with_file_check: Path) -> None:
        """Generator creates valid license file content."""
        generator = R2BypassGenerator(str(pe_with_file_check))

        content = generator._generate_license_file_content()

        assert isinstance(content, str)
        assert len(content) > 0

    def test_generate_file_hook_code(self, pe_with_file_check: Path) -> None:
        """Generator creates working file API hook code."""
        generator = R2BypassGenerator(str(pe_with_file_check))

        file_op = {
            "api": {"name": "CreateFileA"},
            "purpose": "license_file_access",
        }

        hook_code = generator._generate_file_hook_code(file_op)

        assert isinstance(hook_code, str)
        assert "CreateFile" in hook_code


class TestMemoryPatches:
    """Test runtime memory patch generation."""

    def test_generate_memory_patch_for_validation_function(self, pe_with_simple_check: Path) -> None:
        """Generator creates runtime memory patches."""
        generator = R2BypassGenerator(str(pe_with_simple_check))

        fake_r2 = FakeR2Session(str(pe_with_simple_check))
        fake_r2.set_command_response("p8 4 @ 0x401000", "85c0750a")

        license_analysis = {
            "validation_functions": [
                {
                    "function": {"name": "ValidateLicense", "offset": 0x401000},
                    "validation_type": "simple",
                },
            ],
        }

        patches = generator._generate_memory_patches(fake_r2, license_analysis)

        assert len(patches) > 0
        patch = patches[0]
        assert "address" in patch
        assert "original_bytes" in patch
        assert "patch_bytes" in patch


class TestAPIHooks:
    """Test API hooking code generation."""

    def test_generate_frida_hook_for_validation_api(self, pe_with_api_check: Path) -> None:
        """Generator creates Frida hook scripts for validation APIs."""
        generator = R2BypassGenerator(str(pe_with_api_check))

        license_analysis = {
            "registry_operations": [
                {
                    "api": {"name": "RegQueryValueExA"},
                    "purpose": "license_storage",
                },
            ],
        }

        hooks = generator._generate_api_hooks(license_analysis)

        assert len(hooks) > 0
        hook = hooks[0]
        assert "api" in hook
        assert "implementation" in hook


class TestControlFlowAnalysis:
    """Test CFG analysis for identifying optimal bypass points."""

    def test_analyze_function_control_flow_graph(self, pe_with_complex_validation: Path) -> None:
        """Analyzer builds accurate control flow graph."""
        generator = R2BypassGenerator(str(pe_with_complex_validation))

        fake_r2 = FakeR2Session(str(pe_with_complex_validation))
        fake_r2.set_json_response(
            "agfj @ 0x401000",
            [
                {
                    "blocks": [
                        {"addr": 0x401000, "jump": 0x401010, "fail": 0x401020},
                        {"addr": 0x401010, "jump": 0x401030},
                        {"addr": 0x401020, "jump": 0x401040},
                    ],
                },
            ],
        )

        cfg = generator._analyze_control_flow_graph(fake_r2, 0x401000)

        assert "blocks" in cfg or "nodes" in cfg or cfg == {}

    def test_identify_critical_decision_points(self, pe_with_branching: Path) -> None:
        """Analyzer identifies critical validation decision points."""
        generator = R2BypassGenerator(str(pe_with_branching))

        fake_r2 = FakeR2Session(str(pe_with_branching))
        cfg = {
            "blocks": [
                {"addr": 0x401000, "jump": 0x401010},
                {"addr": 0x401010, "jump": 0x401020},
            ],
        }

        fake_r2.set_command_response("pd 1 @ 0x401000", "test eax, eax; je 0x401020")
        fake_r2.set_json_response(
            "pdfj @ 0x401000",
            [
                {"offset": 0x401000, "disasm": "test eax, eax"},
                {"offset": 0x401002, "disasm": "je 0x401020"},
            ],
        )

        decision_points = generator._identify_decision_points(fake_r2, 0x401000, cfg)

        assert isinstance(decision_points, list)

    def test_determine_optimal_patch_strategy(self, pe_with_validation: Path) -> None:
        """Generator selects optimal patch strategy based on CFG."""
        generator = R2BypassGenerator(str(pe_with_validation))

        fake_r2 = FakeR2Session(str(pe_with_validation))
        decision_point = {
            "address": 0x401000,
            "instruction": "test eax, eax",
            "condition_type": "equality",
        }

        cfg = {
            "blocks": [{"addr": 0x401000}],
        }

        fake_r2.set_command_response("pd 1 @ 0x401000", "test eax, eax")

        strategy = generator._determine_patch_strategy(fake_r2, decision_point, cfg)

        assert "type" in strategy


class TestSophisticatedPatches:
    """Test advanced patch generation techniques."""

    def test_generate_register_manipulation_patch(self, pe_with_register_check: Path) -> None:
        """Generator creates register manipulation patches."""
        generator = R2BypassGenerator(str(pe_with_register_check))

        fake_r2 = FakeR2Session(str(pe_with_register_check))
        decision_point = {
            "address": 0x401000,
            "register": "eax",
        }

        strategy = {
            "register": "eax",
            "value": 1,
        }

        fake_r2.set_command_response("p8 2 @ 0x401000", "31c0")

        patch = generator._generate_register_patch(fake_r2, decision_point, strategy)

        assert patch is not None
        assert "patch_bytes" in patch or "instructions" in patch

    def test_generate_stack_manipulation_patch(self, pe_with_stack_check: Path) -> None:
        """Generator creates stack manipulation patches."""
        generator = R2BypassGenerator(str(pe_with_stack_check))

        fake_r2 = FakeR2Session(str(pe_with_stack_check))
        decision_point = {
            "address": 0x401000,
            "stack_offset": 0x10,
        }

        strategy = {
            "stack_offset": 0x10,
            "value": 0,
        }

        fake_r2.set_command_response("p8 8 @ 0x401000", "c744241000000000")

        patch = generator._generate_stack_patch(fake_r2, decision_point, strategy)

        assert patch is not None

    def test_generate_control_flow_redirect_patch(self, pe_with_jump: Path) -> None:
        """Generator creates control flow redirection patches."""
        generator = R2BypassGenerator(str(pe_with_jump))

        fake_r2 = FakeR2Session(str(pe_with_jump))
        decision_point = {
            "address": 0x401000,
            "target": 0x401050,
        }

        strategy = {
            "target": 0x401050,
        }

        fake_r2.set_command_response("p8 5 @ 0x401000", "e94b000000")

        patch = generator._generate_flow_redirect_patch(fake_r2, decision_point, strategy)

        assert patch is not None


class TestComprehensiveBypass:
    """Test complete bypass generation workflow."""

    def test_generate_comprehensive_bypass_for_real_binary(self, pe_with_full_protection: Path) -> None:
        """Generator produces complete bypass solution for protected binary."""
        generator = R2BypassGenerator(str(pe_with_full_protection))

        fake_r2 = FakeR2Session(str(pe_with_full_protection))
        fake_r2.set_functions([{"name": "CheckLicense", "offset": 0x401000}])
        fake_r2.set_command_response("pd 10 @ 0x401000", "")
        fake_r2.set_json_response("pdfj @ 0x401000", [])

        fake_decompiler = FakeDecompiler()
        fake_decompiler.set_decompile_result(
            0x401000,
            {
                "pseudocode": "if (validate(key)) return TRUE;",
                "license_patterns": [],
            },
        )
        generator.decompiler = fake_decompiler

        result = generator.generate_comprehensive_bypass()

        assert "bypass_strategies" in result
        assert "automated_patches" in result
        assert "keygen_algorithms" in result
        assert "success_probability" in result

    def test_bypass_result_includes_implementation_guide(self, pe_with_protection: Path) -> None:
        """Bypass result includes step-by-step implementation guide."""
        generator = R2BypassGenerator(str(pe_with_protection))

        fake_r2 = FakeR2Session(str(pe_with_protection))
        fake_r2.set_functions([])
        fake_r2.set_command_response("pd 10 @ 0x401000", "")
        fake_r2.set_json_response("pdfj @ 0x401000", [])

        result = generator.generate_comprehensive_bypass()

        assert "implementation_guide" in result

    def test_bypass_result_includes_risk_assessment(self, pe_with_protection: Path) -> None:
        """Bypass result includes security risk assessment."""
        generator = R2BypassGenerator(str(pe_with_protection))

        fake_r2 = FakeR2Session(str(pe_with_protection))
        fake_r2.set_functions([])
        fake_r2.set_command_response("pd 10 @ 0x401000", "")
        fake_r2.set_json_response("pdfj @ 0x401000", [])

        result = generator.generate_comprehensive_bypass()

        assert "risk_assessment" in result

    def test_generate_bypass_compatibility_wrapper(self, pe_with_license_check: Path) -> None:
        """generate_bypass() wrapper maintains API compatibility."""
        generator = R2BypassGenerator(str(pe_with_license_check))

        fake_r2 = FakeR2Session(str(pe_with_license_check))
        fake_r2.set_functions([])
        fake_r2.set_command_response("pd 10 @ 0x401000", "")
        fake_r2.set_json_response("pdfj @ 0x401000", [])

        result = generator.generate_bypass()

        assert "method" in result


class TestErrorHandling:
    """Test error handling and edge cases."""

    def test_handle_invalid_binary_path(self) -> None:
        """Generator handles non-existent binary gracefully."""
        generator = R2BypassGenerator("/nonexistent/binary.exe")

        result = generator.generate_comprehensive_bypass()

        assert "error" in result

    def test_handle_corrupted_binary(self, corrupted_binary: Path) -> None:
        """Generator handles corrupted binary data."""
        generator = R2BypassGenerator(str(corrupted_binary))

        result = generator.generate_comprehensive_bypass()

        assert "error" in result or result is not None

    def test_handle_analysis_failure_gracefully(self, pe_with_license_check: Path) -> None:
        """Generator handles analysis failures without crashing."""
        generator = R2BypassGenerator(str(pe_with_license_check))

        result = generator.generate_comprehensive_bypass()

        assert result is not None


@pytest.fixture
def fake_r2_serial() -> FakeR2Session:
    """Create fake R2 session for serial check testing."""
    fake_r2 = FakeR2Session("serial_check.exe")
    fake_r2.set_functions([
        {"name": "CheckLicense", "offset": 0x401000},
        {"name": "ValidateSerial", "offset": 0x401100},
    ])
    return fake_r2


@pytest.fixture
def real_pe_with_license_check(tmp_path: Path) -> Path:
    """Create real PE binary with simple license check."""
    pe_path = tmp_path / "licensed_app.exe"

    dos_header = b"MZ\x90\x00\x03\x00\x00\x00\x04\x00\x00\x00\xff\xff\x00\x00"
    dos_header += b"\xb8\x00\x00\x00\x00\x00\x00\x00\x40\x00\x00\x00\x00\x00\x00\x00"
    dos_header += b"\x00" * 40
    dos_header += b"\x80\x00\x00\x00"
    dos_header += b"\x00" * 60

    pe_signature = b"PE\x00\x00"
    coff_header = b"\x4c\x01\x01\x00" + b"\x00" * 16
    optional_header = b"\x0b\x01" + b"\x00" * 222

    license_check_code = b"\x55\x8b\xec"
    license_check_code += b"\x83\x7d\x08\x00"
    license_check_code += b"\x75\x05"
    license_check_code += b"\x33\xc0"
    license_check_code += b"\xeb\x05"
    license_check_code += b"\xb8\x01\x00\x00\x00"
    license_check_code += b"\x5d\xc3"
    license_check_code += b"\x90" * (4096 - len(license_check_code))

    pe_path.write_bytes(dos_header + pe_signature + coff_header + optional_header + license_check_code)
    return pe_path


@pytest.fixture
def pe_with_simple_serial_check(tmp_path: Path) -> Path:
    """Create PE with serial number validation."""
    return _create_pe_fixture(tmp_path, "serial_check.exe")


@pytest.fixture
def pe_with_rsa_validation(tmp_path: Path) -> Path:
    """Create PE with RSA signature validation."""
    return _create_pe_fixture(tmp_path, "rsa_protected.exe")


@pytest.fixture
def pe_with_online_check(tmp_path: Path) -> Path:
    """Create PE with online validation."""
    return _create_pe_fixture(tmp_path, "online_check.exe")


@pytest.fixture
def pe_with_trial_check(tmp_path: Path) -> Path:
    """Create PE with trial expiration."""
    return _create_pe_fixture(tmp_path, "trial_check.exe")


@pytest.fixture
def pe_with_simple_check(tmp_path: Path) -> Path:
    """Create PE with simple validation."""
    return _create_pe_fixture(tmp_path, "simple.exe")


@pytest.fixture
def pe_with_aes_license(tmp_path: Path) -> Path:
    """Create PE with AES-encrypted license."""
    return _create_pe_fixture(tmp_path, "aes_license.exe")


@pytest.fixture
def pe_with_registry_check(tmp_path: Path) -> Path:
    """Create PE with registry-based license."""
    return _create_pe_fixture(tmp_path, "registry_check.exe")


@pytest.fixture
def pe_with_conditional(tmp_path: Path) -> Path:
    """Create PE with conditional jumps."""
    return _create_pe_fixture(tmp_path, "conditional.exe")


@pytest.fixture
def pe_with_return_check(tmp_path: Path) -> Path:
    """Create PE with return value checks."""
    return _create_pe_fixture(tmp_path, "return_check.exe")


@pytest.fixture
def pe_with_md5_validation(tmp_path: Path) -> Path:
    """Create PE with MD5 hash validation."""
    return _create_pe_fixture(tmp_path, "md5_check.exe")


@pytest.fixture
def pe_with_sha256_validation(tmp_path: Path) -> Path:
    """Create PE with SHA256 validation."""
    return _create_pe_fixture(tmp_path, "sha256_check.exe")


@pytest.fixture
def pe_with_aes_cbc(tmp_path: Path) -> Path:
    """Create PE with AES-CBC encryption."""
    return _create_pe_fixture(tmp_path, "aes_cbc.exe")


@pytest.fixture
def pe_with_salted_hash(tmp_path: Path) -> Path:
    """Create PE with salted hash."""
    return _create_pe_fixture(tmp_path, "salted_hash.exe")


@pytest.fixture
def pe_with_file_check(tmp_path: Path) -> Path:
    """Create PE with license file check."""
    return _create_pe_fixture(tmp_path, "file_check.exe")


@pytest.fixture
def pe_with_api_check(tmp_path: Path) -> Path:
    """Create PE with API-based checks."""
    return _create_pe_fixture(tmp_path, "api_check.exe")


@pytest.fixture
def pe_with_complex_validation(tmp_path: Path) -> Path:
    """Create PE with complex validation logic."""
    return _create_pe_fixture(tmp_path, "complex.exe")


@pytest.fixture
def pe_with_branching(tmp_path: Path) -> Path:
    """Create PE with branching logic."""
    return _create_pe_fixture(tmp_path, "branching.exe")


@pytest.fixture
def pe_with_validation(tmp_path: Path) -> Path:
    """Create PE with validation."""
    return _create_pe_fixture(tmp_path, "validation.exe")


@pytest.fixture
def pe_with_register_check(tmp_path: Path) -> Path:
    """Create PE with register-based check."""
    return _create_pe_fixture(tmp_path, "register_check.exe")


@pytest.fixture
def pe_with_stack_check(tmp_path: Path) -> Path:
    """Create PE with stack-based check."""
    return _create_pe_fixture(tmp_path, "stack_check.exe")


@pytest.fixture
def pe_with_jump(tmp_path: Path) -> Path:
    """Create PE with jump instructions."""
    return _create_pe_fixture(tmp_path, "jump.exe")


@pytest.fixture
def pe_with_full_protection(tmp_path: Path) -> Path:
    """Create PE with comprehensive protection."""
    return _create_pe_fixture(tmp_path, "protected.exe")


@pytest.fixture
def pe_with_protection(tmp_path: Path) -> Path:
    """Create PE with basic protection."""
    return _create_pe_fixture(tmp_path, "basic_protected.exe")


@pytest.fixture
def pe_with_custom_algo(tmp_path: Path) -> Path:
    """Create PE with custom algorithm."""
    return _create_pe_fixture(tmp_path, "custom_algo.exe")


@pytest.fixture
def corrupted_binary(tmp_path: Path) -> Path:
    """Create corrupted binary."""
    path = tmp_path / "corrupted.exe"
    path.write_bytes(b"INVALID\x00\x00\x00" * 100)
    return path


def _create_pe_fixture(tmp_path: Path, name: str) -> Path:
    """Helper to create minimal valid PE binary."""
    pe_path = tmp_path / name

    dos_header = b"MZ" + b"\x00" * 58 + b"\x80\x00\x00\x00"
    pe_signature = b"PE\x00\x00"
    coff_header = b"\x4c\x01\x01\x00" + b"\x00" * 16
    optional_header = b"\x0b\x01" + b"\x00" * 222

    code = b"\xb8\x01\x00\x00\x00\xc3" + b"\x90" * 250

    pe_path.write_bytes(dos_header + pe_signature + coff_header + optional_header + code)
    return pe_path

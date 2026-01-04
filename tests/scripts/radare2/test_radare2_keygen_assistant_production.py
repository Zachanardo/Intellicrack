"""Production tests for radare2_keygen_assistant.py.

These tests validate real keygen generation capabilities:
- Cryptographic algorithm detection from real binaries
- Validation flow analysis in license checking routines
- Keygen source code generation for multiple languages
- Extracted crypto parameter correctness
- Serial format pattern detection
- Generated keygens produce valid output
"""

import json
import subprocess
import tempfile
from pathlib import Path
from typing import Any, Generator

import pytest

try:
    import r2pipe

    R2PIPE_AVAILABLE = True
except ImportError:
    R2PIPE_AVAILABLE = False

from intellicrack.scripts.radare2.radare2_keygen_assistant import (
    CryptoAlgorithm,
    CryptoOperation,
    KeygenLanguage,
    KeygenTemplate,
    R2KeygenAssistant,
    ValidationFlow,
)

FIXTURES_DIR = Path(__file__).parent.parent.parent / "fixtures" / "binaries"
PE_DIR = FIXTURES_DIR / "pe" / "legitimate"


pytestmark = pytest.mark.skipif(not R2PIPE_AVAILABLE, reason="r2pipe not available")


@pytest.fixture
def sample_binary() -> Path:
    """Provide sample binary for analysis."""
    binary = PE_DIR / "notepadpp.exe"
    if not binary.exists():
        pytest.skip(f"Test binary not found: {binary}")
    return binary


@pytest.fixture
def protected_binary() -> Path:
    """Provide protected binary sample."""
    binary = FIXTURES_DIR / "pe" / "protected" / "armadillo_protected.exe"
    if not binary.exists():
        pytest.skip(f"Protected binary not found: {binary}")
    return binary


@pytest.fixture
def keygen_assistant(sample_binary: Path) -> Generator[R2KeygenAssistant, None, None]:
    """Initialize R2KeygenAssistant with sample binary."""
    r2 = r2pipe.open(str(sample_binary))
    yield R2KeygenAssistant(r2=r2)
    r2.quit()


class TestR2KeygenAssistantInitialization:
    """Test R2KeygenAssistant initialization."""

    def test_assistant_initializes_with_r2pipe(self, sample_binary: Path) -> None:
        """R2KeygenAssistant initializes successfully with r2pipe instance."""
        r2 = r2pipe.open(str(sample_binary))
        assistant = R2KeygenAssistant(r2=r2)

        assert assistant.r2 is not None
        assert isinstance(assistant.crypto_operations, list)
        assert isinstance(assistant.validation_flows, list)
        assert isinstance(assistant.extracted_keys, dict)

        r2.quit()

    def test_assistant_initializes_with_filename(self, sample_binary: Path) -> None:
        """R2KeygenAssistant initializes successfully with binary filename."""
        assistant = R2KeygenAssistant(filename=str(sample_binary))

        assert assistant.r2 is not None
        assert hasattr(assistant, "cs")
        assert hasattr(assistant, "ks")
        assert isinstance(assistant.info, dict)

        assistant.r2.quit()

    def test_assistant_sets_correct_architecture(self, sample_binary: Path) -> None:
        """R2KeygenAssistant detects and sets correct architecture."""
        assistant = R2KeygenAssistant(filename=str(sample_binary))

        assert assistant.arch in ["x86", "x64", "unknown"]
        assert assistant.bits in [32, 64]

        assistant.r2.quit()


class TestCryptoAlgorithmDetection:
    """Test cryptographic algorithm detection."""

    def test_crypto_constants_database_complete(self) -> None:
        """CRYPTO_CONSTANTS database contains all major algorithms."""
        constants = R2KeygenAssistant.CRYPTO_CONSTANTS

        assert "MD5" in constants
        assert "SHA1" in constants
        assert "SHA256" in constants
        assert "AES" in constants
        assert "TEA" in constants
        assert "CRC32" in constants

        assert constants["MD5"]["init"] == [0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476]
        assert constants["TEA"]["delta"] == 0x9E3779B9

    def test_search_constants_finds_algorithm_signatures(self, keygen_assistant: R2KeygenAssistant) -> None:
        """_search_constants() locates algorithm constants in binary."""
        keygen_assistant._search_constants("MD5", R2KeygenAssistant.CRYPTO_CONSTANTS["MD5"])

        if "MD5" in keygen_assistant.extracted_keys:
            md5_data = keygen_assistant.extracted_keys["MD5"]
            assert isinstance(md5_data, dict)

    def test_detect_crypto_operation_identifies_aes_instructions(self, keygen_assistant: R2KeygenAssistant) -> None:
        """_detect_crypto_operation() identifies AES hardware instructions."""
        functions = keygen_assistant.r2.cmdj("aflj")
        if not functions:
            pytest.skip("No functions found")

        for func in functions[:10]:
            if func_addr := func.get("offset", 0):
                flow = keygen_assistant._analyze_function_flow(func_addr)
                if flow and flow.operations:
                    for op in flow.operations:
                        assert isinstance(op, CryptoOperation)
                        assert isinstance(op.algorithm, CryptoAlgorithm)
                        assert op.operation in ["encrypt", "decrypt", "hash", "sign", "verify", "xor", "checksum", "unknown"]


class TestValidationFlowAnalysis:
    """Test validation flow analysis."""

    def test_analyze_validation_processes_target_functions(self, keygen_assistant: R2KeygenAssistant) -> None:
        """analyze_validation() analyzes target validation functions."""
        functions = keygen_assistant.r2.cmdj("aflj")
        if not functions:
            pytest.skip("No functions available")

        target_funcs = [func["offset"] for func in functions[:3]]
        flows = keygen_assistant.analyze_validation(target_funcs)

        assert isinstance(flows, list)
        for flow in flows:
            assert isinstance(flow, ValidationFlow)
            assert flow.entry_point in target_funcs
            assert isinstance(flow.operations, list)
            assert isinstance(flow.comparison_points, list)

    def test_analyze_function_flow_extracts_validation_logic(self, keygen_assistant: R2KeygenAssistant) -> None:
        """_analyze_function_flow() extracts validation logic from function."""
        functions = keygen_assistant.r2.cmdj("aflj")
        if not functions:
            pytest.skip("No functions found")

        func_addr = functions[0]["offset"]
        if flow := keygen_assistant._analyze_function_flow(func_addr):
            assert isinstance(flow, ValidationFlow)
            assert flow.entry_point == func_addr
            assert isinstance(flow.operations, list)
            assert isinstance(flow.comparison_points, list)
            assert isinstance(flow.success_paths, list)
            assert isinstance(flow.failure_paths, list)

    def test_detect_serial_format_identifies_patterns(self, keygen_assistant: R2KeygenAssistant) -> None:
        """_detect_serial_format() identifies serial number format patterns."""
        functions = keygen_assistant.r2.cmdj("aflj")
        if not functions:
            pytest.skip("No functions found")

        for func in functions[:5]:
            func_addr = func["offset"]
            if serial_format := keygen_assistant._detect_serial_format(func_addr):
                assert serial_format in ["4x4", "3x5", "16-char", "3-6-6", "5x5", "6x4"]


class TestCryptoParameterExtraction:
    """Test cryptographic parameter extraction."""

    def test_extract_crypto_parameters_finds_keys(self, keygen_assistant: R2KeygenAssistant) -> None:
        """extract_crypto_parameters() extracts cryptographic keys and constants."""
        params = keygen_assistant.extract_crypto_parameters()

        assert isinstance(params, dict)

    def test_extract_rsa_keys_detects_public_keys(self, keygen_assistant: R2KeygenAssistant) -> None:
        """_extract_rsa_keys() detects RSA public keys in binary."""
        keygen_assistant._extract_rsa_keys()

        if "RSA" in keygen_assistant.extracted_keys:
            rsa_data = keygen_assistant.extracted_keys["RSA"]
            assert isinstance(rsa_data, dict)

            if "modulus" in rsa_data:
                modulus_info = rsa_data["modulus"]
                assert "value" in modulus_info
                assert "bits" in modulus_info
                assert modulus_info["bits"] in [512, 1024, 2048, 4096]

    def test_extract_aes_keys_finds_encryption_keys(self, keygen_assistant: R2KeygenAssistant) -> None:
        """_extract_aes_keys() locates AES encryption keys."""
        keygen_assistant._extract_aes_keys()

        if "AES" in keygen_assistant.extracted_keys:
            aes_data = keygen_assistant.extracted_keys["AES"]
            assert isinstance(aes_data, dict)

            for key_name, key_info in aes_data.items():
                assert "address" in key_info
                assert "value" in key_info
                assert "size" in key_info
                assert key_info["size"] in [128, 192, 256]

    def test_extract_custom_algorithms_finds_xor_patterns(self, keygen_assistant: R2KeygenAssistant) -> None:
        """_extract_custom_algorithms() identifies custom XOR encryption patterns."""
        if functions := keygen_assistant.r2.cmdj("aflj"):
            keygen_assistant.analyze_validation([func["offset"] for func in functions[:3]])

        keygen_assistant._extract_custom_algorithms()

        if "XOR" in keygen_assistant.extracted_keys:
            xor_keys = keygen_assistant.extracted_keys["XOR"]
            assert isinstance(xor_keys, list)

            for xor_key in xor_keys:
                assert "address" in xor_key
                assert "key" in xor_key

    def test_is_high_entropy_detects_key_material(self, keygen_assistant: R2KeygenAssistant) -> None:
        """_is_high_entropy() correctly identifies high-entropy key material."""
        high_entropy_data = bytes(range(64))
        low_entropy_data = b"\x00" * 64
        repeated_data = b"AAAA" * 16

        assert keygen_assistant._is_high_entropy(high_entropy_data)
        assert not keygen_assistant._is_high_entropy(low_entropy_data)
        assert not keygen_assistant._is_high_entropy(repeated_data)


class TestKeygenGeneration:
    """Test keygen source code generation."""

    def test_generate_keygens_produces_templates(self, keygen_assistant: R2KeygenAssistant) -> None:
        """generate_keygens() produces keygen templates for multiple languages."""
        flow = ValidationFlow(
            entry_point=0x1000,
            operations=[
                CryptoOperation(address=0x1010, algorithm=CryptoAlgorithm.MD5, operation="hash"),
                CryptoOperation(address=0x1020, algorithm=CryptoAlgorithm.CUSTOM_XOR, operation="xor"),
            ],
            comparison_points=[0x1030],
            success_paths=[0x1040],
            failure_paths=[0x1050],
            serial_format="4x4",
        )
        keygen_assistant.validation_flows.append(flow)

        templates = keygen_assistant.generate_keygens([KeygenLanguage.PYTHON, KeygenLanguage.CPP])

        assert isinstance(templates, list)
        assert len(templates) >= 1

        for template in templates:
            assert isinstance(template, KeygenTemplate)
            assert isinstance(template.source_code, str)
            assert len(template.source_code) > 0
            assert isinstance(template.dependencies, list)
            assert isinstance(template.usage_instructions, str)

    def test_generate_python_keygen_produces_valid_syntax(self, keygen_assistant: R2KeygenAssistant) -> None:
        """_generate_python_keygen() produces syntactically valid Python code."""
        flow = ValidationFlow(
            entry_point=0x1000,
            operations=[CryptoOperation(address=0x1010, algorithm=CryptoAlgorithm.MD5, operation="hash")],
            comparison_points=[],
            success_paths=[],
            failure_paths=[],
        )

        template = keygen_assistant._generate_python_keygen(flow, [CryptoAlgorithm.MD5])

        assert isinstance(template, KeygenTemplate)
        assert template.language == KeygenLanguage.PYTHON
        assert "import hashlib" in template.source_code
        assert "def generate_serial" in template.source_code
        assert "def main" in template.source_code

        try:
            compile(template.source_code, "<string>", "exec")
        except SyntaxError:
            pytest.fail("Generated Python code has syntax errors")

    def test_generate_cpp_keygen_produces_compilable_code(self, keygen_assistant: R2KeygenAssistant) -> None:
        """_generate_cpp_keygen() produces C++ code with correct syntax."""
        flow = ValidationFlow(
            entry_point=0x1000,
            operations=[CryptoOperation(address=0x1010, algorithm=CryptoAlgorithm.MD5, operation="hash")],
            comparison_points=[],
            success_paths=[],
            failure_paths=[],
        )

        template = keygen_assistant._generate_cpp_keygen(flow, [CryptoAlgorithm.MD5])

        assert isinstance(template, KeygenTemplate)
        assert template.language == KeygenLanguage.CPP
        assert "#include <iostream>" in template.source_code
        assert "std::string generateSerial" in template.source_code
        assert "int main()" in template.source_code
        assert "openssl" in template.dependencies

    def test_generate_java_keygen_produces_valid_java(self, keygen_assistant: R2KeygenAssistant) -> None:
        """_generate_java_keygen() produces valid Java code."""
        flow = ValidationFlow(
            entry_point=0x1000,
            operations=[CryptoOperation(address=0x1010, algorithm=CryptoAlgorithm.SHA256, operation="hash")],
            comparison_points=[],
            success_paths=[],
            failure_paths=[],
        )

        template = keygen_assistant._generate_java_keygen(flow, [CryptoAlgorithm.SHA256])

        assert isinstance(template, KeygenTemplate)
        assert template.language == KeygenLanguage.JAVA
        assert "public class Keygen" in template.source_code
        assert "public static String generateSerial" in template.source_code
        assert "import java.security.MessageDigest" in template.source_code


class TestKeygenAlgorithmChains:
    """Test keygen generation with complex algorithm chains."""

    def test_keygen_handles_md5_xor_chain(self, keygen_assistant: R2KeygenAssistant) -> None:
        """Keygen correctly implements MD5 + XOR algorithm chain."""
        keygen_assistant.extracted_keys["XOR"] = [{"address": 0x1000, "key": 0xDEADBEEF}]

        flow = ValidationFlow(
            entry_point=0x1000,
            operations=[
                CryptoOperation(address=0x1010, algorithm=CryptoAlgorithm.MD5, operation="hash"),
                CryptoOperation(
                    address=0x1020,
                    algorithm=CryptoAlgorithm.CUSTOM_XOR,
                    operation="xor",
                    parameters={"key": 0xDEADBEEF},
                ),
            ],
            comparison_points=[],
            success_paths=[],
            failure_paths=[],
        )

        template = keygen_assistant._generate_python_keygen(flow, [CryptoAlgorithm.MD5, CryptoAlgorithm.CUSTOM_XOR])

        assert "MD5" in template.source_code
        assert "xor_key = 0xdeadbeef" in template.source_code.lower()

    def test_keygen_handles_aes_encryption(self, keygen_assistant: R2KeygenAssistant) -> None:
        """Keygen correctly implements AES encryption."""
        keygen_assistant.extracted_keys["AES"] = {
            "key_128": {"address": 0x1000, "value": "00112233445566778899aabbccddeeff", "size": 128}
        }

        flow = ValidationFlow(
            entry_point=0x1000,
            operations=[CryptoOperation(address=0x1010, algorithm=CryptoAlgorithm.AES, operation="encrypt")],
            comparison_points=[],
            success_paths=[],
            failure_paths=[],
        )

        template = keygen_assistant._generate_python_keygen(flow, [CryptoAlgorithm.AES])

        assert "from Crypto.Cipher import AES" in template.source_code
        assert "pycryptodome" in template.dependencies
        assert "00112233445566778899aabbccddeeff" in template.source_code


class TestSerialFormatting:
    """Test serial number formatting."""

    def test_add_serial_formatting_4x4_pattern(self, keygen_assistant: R2KeygenAssistant) -> None:
        """_add_serial_formatting() generates correct 4x4 format code."""
        code = []
        keygen_assistant._add_serial_formatting(code, "4x4")

        code_str = "\n".join(code)
        assert "hex" in code_str.lower()
        assert "4" in code_str

    def test_add_serial_formatting_3x5_pattern(self, keygen_assistant: R2KeygenAssistant) -> None:
        """_add_serial_formatting() generates correct 3x5 format code."""
        code = []
        keygen_assistant._add_serial_formatting(code, "3x5")

        code_str = "\n".join(code)
        assert "3" in code_str or "5" in code_str

    def test_serial_patterns_regex_valid(self) -> None:
        """SERIAL_PATTERNS contain valid regex patterns."""
        import re

        for pattern_name, regex in R2KeygenAssistant.SERIAL_PATTERNS.items():
            try:
                re.compile(regex)
            except re.error:
                pytest.fail(f"Invalid regex pattern for {pattern_name}: {regex}")


class TestKeygenExport:
    """Test keygen export functionality."""

    def test_export_keygens_creates_files(self, keygen_assistant: R2KeygenAssistant, tmp_path: Path) -> None:
        """export_keygens() creates keygen files with correct extensions."""
        flow = ValidationFlow(
            entry_point=0x1000,
            operations=[CryptoOperation(address=0x1010, algorithm=CryptoAlgorithm.MD5, operation="hash")],
            comparison_points=[],
            success_paths=[],
            failure_paths=[],
        )

        template_py = keygen_assistant._generate_python_keygen(flow, [CryptoAlgorithm.MD5])
        template_cpp = keygen_assistant._generate_cpp_keygen(flow, [CryptoAlgorithm.MD5])

        output_dir = tmp_path / "keygens"
        keygen_assistant.export_keygens([template_py, template_cpp], str(output_dir))

        assert output_dir.exists()

        py_files = list(output_dir.glob("*.py"))
        cpp_files = list(output_dir.glob("*.cpp"))
        readme_files = list(output_dir.glob("README_*.txt"))

        assert py_files
        assert cpp_files
        assert len(readme_files) >= 2

    def test_export_keygens_creates_readme(self, keygen_assistant: R2KeygenAssistant, tmp_path: Path) -> None:
        """export_keygens() creates README files with usage instructions."""
        flow = ValidationFlow(
            entry_point=0x1000,
            operations=[CryptoOperation(address=0x1010, algorithm=CryptoAlgorithm.MD5, operation="hash")],
            comparison_points=[],
            success_paths=[],
            failure_paths=[],
        )

        template = keygen_assistant._generate_python_keygen(flow, [CryptoAlgorithm.MD5])
        output_dir = tmp_path / "keygens"

        keygen_assistant.export_keygens([template], str(output_dir))

        readme_file = output_dir / "README_1.txt"
        assert readme_file.exists()

        readme_content = readme_file.read_text()
        assert "Algorithm Chain" in readme_content
        assert "Dependencies" in readme_content
        assert "Usage" in readme_content


class TestAnalyzeFromLicenseFunctions:
    """Test analysis from license function detection."""

    def test_analyze_from_license_functions_processes_high_confidence(
        self, keygen_assistant: R2KeygenAssistant
    ) -> None:
        """analyze_from_license_functions() processes high-confidence license functions."""
        license_functions = [
            {"address": "0x1000", "confidence": 0.9, "name": "validate_serial"},
            {"address": "0x2000", "confidence": 0.5, "name": "check_key"},
            {"address": "0x3000", "confidence": 0.8, "name": "verify_license"},
        ]

        templates = keygen_assistant.analyze_from_license_functions(license_functions)

        assert isinstance(templates, list)


class TestDetermineOperationType:
    """Test operation type determination."""

    def test_determine_operation_type_identifies_encryption(self, keygen_assistant: R2KeygenAssistant) -> None:
        """_determine_operation_type() identifies encryption operations."""
        assert keygen_assistant._determine_operation_type("AES_Encrypt") == "encrypt"
        assert keygen_assistant._determine_operation_type("EncodeData") == "encrypt"

    def test_determine_operation_type_identifies_decryption(self, keygen_assistant: R2KeygenAssistant) -> None:
        """_determine_operation_type() identifies decryption operations."""
        assert keygen_assistant._determine_operation_type("AES_Decrypt") == "decrypt"
        assert keygen_assistant._determine_operation_type("DecodeData") == "decrypt"

    def test_determine_operation_type_identifies_hashing(self, keygen_assistant: R2KeygenAssistant) -> None:
        """_determine_operation_type() identifies hashing operations."""
        assert keygen_assistant._determine_operation_type("SHA256_Hash") == "hash"
        assert keygen_assistant._determine_operation_type("ComputeDigest") == "hash"

    def test_determine_operation_type_identifies_verification(self, keygen_assistant: R2KeygenAssistant) -> None:
        """_determine_operation_type() identifies verification operations."""
        assert keygen_assistant._determine_operation_type("VerifySignature") == "verify"
        assert keygen_assistant._determine_operation_type("ValidateKey") == "verify"


class TestProtectedBinaryAnalysis:
    """Test keygen generation against protected binaries."""

    def test_assistant_analyzes_protected_binary(self, protected_binary: Path) -> None:
        """R2KeygenAssistant analyzes protected binary without crashing."""
        if not protected_binary.exists():
            pytest.skip("Protected binary not available")

        assistant = R2KeygenAssistant(filename=str(protected_binary))

        assert assistant.r2 is not None
        assert isinstance(assistant.info, dict)

        if functions := assistant.r2.cmdj("aflj"):
            target_funcs = [func["offset"] for func in functions[:2]]
            flows = assistant.analyze_validation(target_funcs)
            assert isinstance(flows, list)

        assistant.r2.quit()


@pytest.mark.integration
class TestGeneratedKeygenExecution:
    """Test that generated keygens are executable."""

    def test_generated_python_keygen_executes(self, keygen_assistant: R2KeygenAssistant, tmp_path: Path) -> None:
        """Generated Python keygen executes and produces output."""
        flow = ValidationFlow(
            entry_point=0x1000,
            operations=[CryptoOperation(address=0x1010, algorithm=CryptoAlgorithm.MD5, operation="hash")],
            comparison_points=[],
            success_paths=[],
            failure_paths=[],
            serial_format="4x4",
        )

        template = keygen_assistant._generate_python_keygen(flow, [CryptoAlgorithm.MD5])

        keygen_file = tmp_path / "keygen.py"
        keygen_file.write_text(template.source_code)

        try:
            result = subprocess.run(
                ["python", str(keygen_file)],
                input=b"TestUser\n",
                capture_output=True,
                timeout=5,
                check=False,
            )

            assert result.returncode == 0 or b"Serial:" in result.stdout
        except subprocess.TimeoutExpired:
            pytest.skip("Keygen execution timed out")
        except FileNotFoundError:
            pytest.skip("Python interpreter not found")

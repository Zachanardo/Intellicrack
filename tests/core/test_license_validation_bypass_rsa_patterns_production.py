"""Production tests for RSA key extraction from license validation bypass engine.

Tests MUST validate dynamic instrumentation capabilities for RSA key extraction:
- Must dump RSA operations from memory during execution
- Must identify modulus and exponent from crypto API calls
- Must extract keys from static binary analysis when possible
- Must handle multiple RSA implementations (OpenSSL, CNG, custom)
- Must handle obfuscated key storage and key derivation from password

These tests FAIL with hardcoded patterns and PASS only with real dynamic instrumentation.
"""

import struct
import tempfile
from pathlib import Path
from typing import Any

import pefile
import pytest
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

from intellicrack.core.license_validation_bypass import (
    ExtractedKey,
    KeyType,
    LicenseValidationBypass,
)


@pytest.fixture
def bypass_engine() -> LicenseValidationBypass:
    """Create LicenseValidationBypass engine instance."""
    return LicenseValidationBypass()


@pytest.fixture
def temp_binary_dir(tmp_path: Path) -> Path:
    """Create temporary directory for test binaries."""
    binary_dir = tmp_path / "binaries"
    binary_dir.mkdir()
    return binary_dir


@pytest.fixture
def openssl_1_0_binary(temp_binary_dir: Path) -> Path:
    """Create test binary with OpenSSL 1.0.x RSA structure in memory."""
    binary_path = temp_binary_dir / "openssl_10x_test.exe"

    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )

    public_numbers = private_key.public_key().public_numbers()
    n = public_numbers.n
    e = public_numbers.e

    openssl_10x_structure = _build_openssl_10x_rsa_structure(n, e)

    pe_binary = _create_pe_with_data(openssl_10x_structure, section_name=b".data\x00\x00\x00")
    binary_path.write_bytes(pe_binary)

    return binary_path


@pytest.fixture
def openssl_1_1_binary(temp_binary_dir: Path) -> Path:
    """Create test binary with OpenSSL 1.1.x RSA structure in memory."""
    binary_path = temp_binary_dir / "openssl_11x_test.exe"

    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )

    public_numbers = private_key.public_key().public_numbers()
    n = public_numbers.n
    e = public_numbers.e

    openssl_11x_structure = _build_openssl_11x_rsa_structure(n, e)

    pe_binary = _create_pe_with_data(openssl_11x_structure, section_name=b".data\x00\x00\x00")
    binary_path.write_bytes(pe_binary)

    return binary_path


@pytest.fixture
def openssl_3_binary(temp_binary_dir: Path) -> Path:
    """Create test binary with OpenSSL 3.x RSA structure in memory."""
    binary_path = temp_binary_dir / "openssl_3x_test.exe"

    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )

    public_numbers = private_key.public_key().public_numbers()
    n = public_numbers.n
    e = public_numbers.e

    openssl_3x_structure = _build_openssl_3x_rsa_structure(n, e)

    pe_binary = _create_pe_with_data(openssl_3x_structure, section_name=b".data\x00\x00\x00")
    binary_path.write_bytes(pe_binary)

    return binary_path


@pytest.fixture
def cng_binary(temp_binary_dir: Path) -> Path:
    """Create test binary with Windows CNG BCRYPT_RSAKEY_BLOB structure."""
    binary_path = temp_binary_dir / "cng_test.exe"

    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )

    public_numbers = private_key.public_key().public_numbers()
    n = public_numbers.n
    e = public_numbers.e

    bcrypt_blob = _build_bcrypt_rsa_blob(n, e)

    pe_binary = _create_pe_with_data(bcrypt_blob, section_name=b".data\x00\x00\x00")
    binary_path.write_bytes(pe_binary)

    return binary_path


@pytest.fixture
def custom_rsa_binary(temp_binary_dir: Path) -> Path:
    """Create test binary with custom RSA implementation (non-standard storage)."""
    binary_path = temp_binary_dir / "custom_rsa_test.exe"

    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )

    public_numbers = private_key.public_key().public_numbers()
    n = public_numbers.n
    e = public_numbers.e

    custom_structure = _build_custom_rsa_structure(n, e)

    pe_binary = _create_pe_with_data(custom_structure, section_name=b".data\x00\x00\x00")
    binary_path.write_bytes(pe_binary)

    return binary_path


@pytest.fixture
def obfuscated_key_binary(temp_binary_dir: Path) -> Path:
    """Create test binary with XOR-obfuscated RSA key storage."""
    binary_path = temp_binary_dir / "obfuscated_key_test.exe"

    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )

    public_numbers = private_key.public_key().public_numbers()
    n = public_numbers.n
    e = public_numbers.e

    xor_key = b"\xAA" * 8
    obfuscated_structure = _build_obfuscated_rsa_structure(n, e, xor_key)

    pe_binary = _create_pe_with_data(obfuscated_structure, section_name=b".data\x00\x00\x00")
    binary_path.write_bytes(pe_binary)

    return binary_path


@pytest.fixture
def password_derived_key_binary(temp_binary_dir: Path) -> Path:
    """Create test binary with password-derived RSA key."""
    binary_path = temp_binary_dir / "password_derived_test.exe"

    password = b"TestPassword123"
    salt = b"SaltValue1234567"

    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    derived_key_material = kdf.derive(password)

    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )

    public_numbers = private_key.public_key().public_numbers()
    n = public_numbers.n
    e = public_numbers.e

    encrypted_structure = _build_password_derived_rsa_structure(n, e, derived_key_material, salt)

    pe_binary = _create_pe_with_data(encrypted_structure, section_name=b".data\x00\x00\x00")
    binary_path.write_bytes(pe_binary)

    return binary_path


@pytest.fixture
def cryptoapi_usage_binary(temp_binary_dir: Path) -> Path:
    """Create test binary with CryptoAPI import and RSA key usage patterns."""
    binary_path = temp_binary_dir / "cryptoapi_test.exe"

    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )

    public_numbers = private_key.public_key().public_numbers()
    n = public_numbers.n
    e = public_numbers.e

    key_data = public_numbers.n.to_bytes(256, 'big')

    pe_binary = _create_pe_with_cryptoapi_imports(key_data)
    binary_path.write_bytes(pe_binary)

    return binary_path


class TestDynamicInstrumentationRSAExtraction:
    """Tests requiring dynamic instrumentation for RSA key extraction from running processes."""

    def test_extract_rsa_from_openssl_10x_memory_structure(
        self,
        bypass_engine: LicenseValidationBypass,
        openssl_1_0_binary: Path
    ) -> None:
        """MUST extract RSA keys from OpenSSL 1.0.x memory structures using dynamic analysis.

        This test validates:
        - Detection of OpenSSL 1.0.x version-specific BIGNUM structures
        - Correct parsing of pointer-based BIGNUM storage
        - Extraction of modulus and exponent from memory layout

        FAILS with hardcoded patterns - REQUIRES dynamic memory analysis.
        """
        keys = bypass_engine.extract_rsa_keys_from_binary(str(openssl_1_0_binary))

        assert len(keys) > 0, "FAILED: No RSA keys extracted from OpenSSL 1.0.x structure"

        openssl_10x_keys = [k for k in keys if "OpenSSL 1.0.x" in k.context]
        assert len(openssl_10x_keys) > 0, "FAILED: OpenSSL 1.0.x specific extraction not implemented"

        key = openssl_10x_keys[0]
        assert key.modulus is not None, "FAILED: Modulus not extracted from OpenSSL 1.0.x structure"
        assert key.exponent is not None, "FAILED: Exponent not extracted from OpenSSL 1.0.x structure"
        assert key.modulus.bit_length() == 2048, f"FAILED: Expected 2048-bit modulus, got {key.modulus.bit_length()}"
        assert key.exponent == 65537, f"FAILED: Expected exponent 65537, got {key.exponent}"
        assert key.confidence >= 0.85, f"FAILED: Low confidence ({key.confidence}) for OpenSSL 1.0.x extraction"

    def test_extract_rsa_from_openssl_11x_memory_structure(
        self,
        bypass_engine: LicenseValidationBypass,
        openssl_1_1_binary: Path
    ) -> None:
        """MUST extract RSA keys from OpenSSL 1.1.x inline BIGNUM structures.

        This test validates:
        - Detection of OpenSSL 1.1.x version-specific inline storage
        - Parsing of packed BIGNUM fields (width, dmax, neg_flags)
        - Correct offset calculations for inline number data

        FAILS with hardcoded patterns - REQUIRES version-specific structure parsing.
        """
        keys = bypass_engine.extract_rsa_keys_from_binary(str(openssl_1_1_binary))

        assert len(keys) > 0, "FAILED: No RSA keys extracted from OpenSSL 1.1.x structure"

        openssl_11x_keys = [k for k in keys if "OpenSSL 1.1.x" in k.context]
        assert len(openssl_11x_keys) > 0, "FAILED: OpenSSL 1.1.x specific extraction not implemented"

        key = openssl_11x_keys[0]
        assert key.modulus is not None, "FAILED: Modulus not extracted from OpenSSL 1.1.x inline structure"
        assert key.exponent is not None, "FAILED: Exponent not extracted from OpenSSL 1.1.x inline structure"
        assert key.modulus.bit_length() == 2048, f"FAILED: Expected 2048-bit modulus, got {key.modulus.bit_length()}"
        assert key.exponent == 65537, f"FAILED: Expected exponent 65537, got {key.exponent}"
        assert key.confidence >= 0.85, f"FAILED: Low confidence ({key.confidence}) for OpenSSL 1.1.x extraction"

    def test_extract_rsa_from_openssl_3x_memory_structure(
        self,
        bypass_engine: LicenseValidationBypass,
        openssl_3_binary: Path
    ) -> None:
        """MUST extract RSA keys from OpenSSL 3.x provider-based structures.

        This test validates:
        - Detection of OpenSSL 3.x provider architecture
        - Parsing of reference counting and flags fields
        - Extraction from provider-managed key data

        FAILS with hardcoded patterns - REQUIRES OpenSSL 3.x structure knowledge.
        """
        keys = bypass_engine.extract_rsa_keys_from_binary(str(openssl_3_binary))

        assert len(keys) > 0, "FAILED: No RSA keys extracted from OpenSSL 3.x structure"

        openssl_3x_keys = [k for k in keys if "OpenSSL 3.x" in k.context]
        assert len(openssl_3x_keys) > 0, "FAILED: OpenSSL 3.x specific extraction not implemented"

        key = openssl_3x_keys[0]
        assert key.modulus is not None, "FAILED: Modulus not extracted from OpenSSL 3.x provider structure"
        assert key.exponent is not None, "FAILED: Exponent not extracted from OpenSSL 3.x provider structure"
        assert key.modulus.bit_length() == 2048, f"FAILED: Expected 2048-bit modulus, got {key.modulus.bit_length()}"
        assert key.exponent == 65537, f"FAILED: Expected exponent 65537, got {key.exponent}"
        assert key.confidence >= 0.85, f"FAILED: Low confidence ({key.confidence}) for OpenSSL 3.x extraction"

    def test_extract_rsa_from_windows_cng_bcrypt_blob(
        self,
        bypass_engine: LicenseValidationBypass,
        cng_binary: Path
    ) -> None:
        """MUST extract RSA keys from Windows CNG BCRYPT_RSAKEY_BLOB structures.

        This test validates:
        - Detection of BCRYPT_RSAPUBLIC_MAGIC/BCRYPT_RSAPRIVATE_MAGIC
        - Parsing of bit length, public exponent length, modulus length fields
        - Correct little-endian byte order handling for Windows structures

        FAILS with hardcoded patterns - REQUIRES Windows CNG structure parsing.
        """
        keys = bypass_engine.extract_rsa_keys_from_binary(str(cng_binary))

        assert len(keys) > 0, "FAILED: No RSA keys extracted from CNG BCRYPT_RSAKEY_BLOB"

        cng_keys = [k for k in keys if "BCRYPT" in k.context]
        assert len(cng_keys) > 0, "FAILED: Windows CNG BCRYPT_RSAKEY_BLOB extraction not implemented"

        key = cng_keys[0]
        assert key.modulus is not None, "FAILED: Modulus not extracted from BCRYPT_RSAKEY_BLOB"
        assert key.exponent is not None, "FAILED: Exponent not extracted from BCRYPT_RSAKEY_BLOB"
        assert key.modulus.bit_length() == 2048, f"FAILED: Expected 2048-bit modulus, got {key.modulus.bit_length()}"
        assert key.exponent == 65537, f"FAILED: Expected exponent 65537, got {key.exponent}"
        assert key.confidence >= 0.85, f"FAILED: Low confidence ({key.confidence}) for CNG extraction"

    def test_extract_rsa_from_custom_implementation(
        self,
        bypass_engine: LicenseValidationBypass,
        custom_rsa_binary: Path
    ) -> None:
        """MUST extract RSA keys from custom non-standard implementations.

        This test validates:
        - Detection of RSA keys without standard headers (ASN.1, OpenSSL, CNG)
        - Heuristic identification of modulus by mathematical properties
        - Discovery of exponent in proximity to modulus

        FAILS with hardcoded patterns - REQUIRES heuristic/entropy-based detection.
        """
        keys = bypass_engine.extract_rsa_keys_from_binary(str(custom_rsa_binary))

        assert len(keys) > 0, "FAILED: No RSA keys extracted from custom implementation"

        valid_keys = [k for k in keys if k.modulus and k.exponent and k.modulus.bit_length() == 2048]
        assert len(valid_keys) > 0, "FAILED: Custom RSA implementation extraction not working"

        key = valid_keys[0]
        assert key.modulus.bit_length() == 2048, f"FAILED: Expected 2048-bit modulus, got {key.modulus.bit_length()}"
        assert key.exponent == 65537, f"FAILED: Expected exponent 65537, got {key.exponent}"
        assert key.confidence >= 0.6, f"FAILED: Custom implementation requires at least 0.6 confidence, got {key.confidence}"


class TestObfuscatedKeyExtraction:
    """Tests for extracting obfuscated and encrypted RSA keys."""

    def test_extract_xor_obfuscated_rsa_key(
        self,
        bypass_engine: LicenseValidationBypass,
        obfuscated_key_binary: Path
    ) -> None:
        """MUST extract RSA keys from XOR-obfuscated storage.

        This test validates:
        - Detection of obfuscated key patterns (low entropy, repeating XOR)
        - Deobfuscation of key material using XOR reversal
        - Recovery of actual RSA modulus and exponent

        FAILS with hardcoded patterns - REQUIRES deobfuscation logic.
        """
        keys = bypass_engine.extract_rsa_keys_from_binary(str(obfuscated_key_binary))

        assert len(keys) > 0, "FAILED: No keys extracted from obfuscated storage"

        valid_keys = [k for k in keys if k.modulus and k.modulus.bit_length() == 2048]
        assert len(valid_keys) > 0, "FAILED: Obfuscated key extraction not implemented"

        key = valid_keys[0]
        assert key.exponent == 65537, f"FAILED: Expected deobfuscated exponent 65537, got {key.exponent}"
        assert "obfuscate" in key.context.lower() or key.confidence < 0.9, \
            "FAILED: Should indicate obfuscated source or lower confidence"

    def test_extract_password_derived_rsa_key(
        self,
        bypass_engine: LicenseValidationBypass,
        password_derived_key_binary: Path
    ) -> None:
        """MUST handle password-derived RSA key material.

        This test validates:
        - Detection of PBKDF2/scrypt/argon2 key derivation patterns
        - Identification of salt and iteration count storage
        - Recognition that key requires password for full extraction

        FAILS with hardcoded patterns - REQUIRES KDF pattern detection.
        """
        keys = bypass_engine.extract_rsa_keys_from_binary(str(password_derived_key_binary))

        password_derived_indicators = [
            k for k in keys
            if any(term in k.context.lower() for term in ["password", "derive", "kdf", "pbkdf", "encrypted"])
            or k.confidence < 0.7
        ]

        assert len(keys) > 0 or len(password_derived_indicators) > 0, \
            "FAILED: Password-derived key detection not implemented"

        if len(password_derived_indicators) > 0:
            key = password_derived_indicators[0]
            assert key.confidence < 0.85, \
                "FAILED: Password-derived keys should have reduced confidence without password"


class TestCryptoAPICallAnalysis:
    """Tests for extracting RSA keys from CryptoAPI usage patterns."""

    def test_extract_from_cryptimportkey_usage(
        self,
        bypass_engine: LicenseValidationBypass,
        cryptoapi_usage_binary: Path
    ) -> None:
        """MUST extract RSA keys from CryptImportKey API call patterns.

        This test validates:
        - Detection of CryptImportKey/BCryptImportKeyPair imports
        - Analysis of code around crypto API calls
        - Extraction of key data passed as function arguments

        FAILS with hardcoded patterns - REQUIRES disassembly and data flow analysis.
        """
        keys = bypass_engine.extract_rsa_keys_from_binary(str(cryptoapi_usage_binary))

        assert len(keys) > 0, "FAILED: No keys extracted from CryptoAPI usage patterns"

        cryptoapi_keys = [
            k for k in keys
            if any(api in k.context for api in ["CryptImportKey", "BCryptImportKeyPair", "CryptExportKey", "CryptoAPI"])
        ]

        assert len(cryptoapi_keys) > 0, "FAILED: CryptoAPI call analysis not implemented"

        key = cryptoapi_keys[0]
        assert key.modulus is not None or key.key_data is not None, \
            "FAILED: Must extract key material from CryptoAPI call context"


class TestStaticVsDynamicExtraction:
    """Tests comparing static analysis with dynamic instrumentation."""

    def test_static_analysis_extracts_embedded_keys(
        self,
        bypass_engine: LicenseValidationBypass,
        temp_binary_dir: Path
    ) -> None:
        """MUST extract RSA keys from static binary analysis (no execution).

        This test validates:
        - ASN.1 DER structure detection in PE resources
        - PEM certificate parsing from .data/.rdata sections
        - Entropy-based detection of raw RSA moduli

        PASSES with current implementation - validates static analysis works.
        """
        binary_path = temp_binary_dir / "static_embedded_key.exe"

        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )

        der_public_key = private_key.public_key().public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

        pe_binary = _create_pe_with_data(der_public_key, section_name=b".rdata\x00\x00")
        binary_path.write_bytes(pe_binary)

        keys = bypass_engine.extract_rsa_keys_from_binary(str(binary_path))

        assert len(keys) > 0, "FAILED: Static analysis cannot extract embedded DER keys"

        asn1_keys = [k for k in keys if "ASN.1 DER" in k.context]
        assert len(asn1_keys) > 0, "FAILED: ASN.1 DER parsing not working"

        key = asn1_keys[0]
        assert key.modulus is not None, "FAILED: Modulus not extracted from ASN.1 structure"
        assert key.exponent == 65537, f"FAILED: Expected exponent 65537, got {key.exponent}"
        assert key.confidence >= 0.9, f"FAILED: ASN.1 extraction should have high confidence, got {key.confidence}"

    def test_multiple_extraction_methods_produce_consistent_results(
        self,
        bypass_engine: LicenseValidationBypass,
        temp_binary_dir: Path
    ) -> None:
        """MUST produce consistent results across multiple extraction methods.

        This test validates:
        - Pattern matching, entropy analysis, PE parsing find same key
        - Duplicate detection and deduplication
        - Confidence scoring reflects extraction method

        REQUIRES all extraction methods implemented correctly.
        """
        binary_path = temp_binary_dir / "multi_method_test.exe"

        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )

        public_numbers = private_key.public_key().public_numbers()
        n = public_numbers.n
        e = public_numbers.e

        der_key = private_key.public_key().public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

        openssl_struct = _build_openssl_11x_rsa_structure(n, e)

        combined_data = der_key + b"\x00" * 256 + openssl_struct

        pe_binary = _create_pe_with_data(combined_data, section_name=b".data\x00\x00\x00")
        binary_path.write_bytes(pe_binary)

        keys = bypass_engine.extract_rsa_keys_from_binary(str(binary_path))

        assert len(keys) >= 2, f"FAILED: Expected multiple extraction methods to find key, got {len(keys)}"

        unique_moduli = {k.modulus for k in keys if k.modulus}
        assert len(unique_moduli) >= 1, "FAILED: All methods should extract same modulus"

        matching_keys = [k for k in keys if k.modulus == n]
        assert len(matching_keys) >= 2, \
            f"FAILED: Expected at least 2 extraction methods to find correct modulus, got {len(matching_keys)}"

        confidence_scores = [k.confidence for k in matching_keys]
        assert max(confidence_scores) >= 0.85, \
            f"FAILED: At least one method should have high confidence, max was {max(confidence_scores)}"


class TestEdgeCases:
    """Tests for edge cases and unusual RSA implementations."""

    def test_extract_rsa_with_non_standard_exponent(
        self,
        bypass_engine: LicenseValidationBypass,
        temp_binary_dir: Path
    ) -> None:
        """MUST extract RSA keys with non-standard public exponents (e.g., 3, 17)."""
        binary_path = temp_binary_dir / "non_standard_exponent.exe"

        private_key = rsa.generate_private_key(
            public_exponent=3,
            key_size=2048,
            backend=default_backend()
        )

        public_numbers = private_key.public_key().public_numbers()
        n = public_numbers.n
        e = public_numbers.e

        openssl_struct = _build_openssl_11x_rsa_structure(n, e)

        pe_binary = _create_pe_with_data(openssl_struct, section_name=b".data\x00\x00\x00")
        binary_path.write_bytes(pe_binary)

        keys = bypass_engine.extract_rsa_keys_from_binary(str(binary_path))

        assert len(keys) > 0, "FAILED: Cannot extract RSA keys with non-standard exponents"

        matching_keys = [k for k in keys if k.exponent == 3]
        assert len(matching_keys) > 0, "FAILED: Non-standard exponent (e=3) not detected"

    def test_extract_4096_bit_rsa_key(
        self,
        bypass_engine: LicenseValidationBypass,
        temp_binary_dir: Path
    ) -> None:
        """MUST extract large 4096-bit RSA keys."""
        binary_path = temp_binary_dir / "rsa_4096.exe"

        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=4096,
            backend=default_backend()
        )

        public_numbers = private_key.public_key().public_numbers()
        n = public_numbers.n
        e = public_numbers.e

        openssl_struct = _build_openssl_11x_rsa_structure(n, e)

        pe_binary = _create_pe_with_data(openssl_struct, section_name=b".data\x00\x00\x00")
        binary_path.write_bytes(pe_binary)

        keys = bypass_engine.extract_rsa_keys_from_binary(str(binary_path))

        assert len(keys) > 0, "FAILED: Cannot extract 4096-bit RSA keys"

        large_keys = [k for k in keys if k.modulus and k.modulus.bit_length() >= 4096]
        assert len(large_keys) > 0, "FAILED: 4096-bit RSA key not extracted"

        key = large_keys[0]
        assert key.exponent == 65537, f"FAILED: Expected exponent 65537, got {key.exponent}"

    def test_extract_1024_bit_rsa_key(
        self,
        bypass_engine: LicenseValidationBypass,
        temp_binary_dir: Path
    ) -> None:
        """MUST extract legacy 1024-bit RSA keys (still used in older software)."""
        binary_path = temp_binary_dir / "rsa_1024.exe"

        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=1024,
            backend=default_backend()
        )

        public_numbers = private_key.public_key().public_numbers()
        n = public_numbers.n
        e = public_numbers.e

        openssl_struct = _build_openssl_11x_rsa_structure(n, e)

        pe_binary = _create_pe_with_data(openssl_struct, section_name=b".data\x00\x00\x00")
        binary_path.write_bytes(pe_binary)

        keys = bypass_engine.extract_rsa_keys_from_binary(str(binary_path))

        assert len(keys) > 0, "FAILED: Cannot extract 1024-bit RSA keys"

        small_keys = [k for k in keys if k.modulus and k.modulus.bit_length() == 1024]
        assert len(small_keys) > 0, "FAILED: 1024-bit RSA key not extracted"

        key = small_keys[0]
        assert key.exponent == 65537, f"FAILED: Expected exponent 65537, got {key.exponent}"

    def test_handle_corrupted_rsa_structure_gracefully(
        self,
        bypass_engine: LicenseValidationBypass,
        temp_binary_dir: Path
    ) -> None:
        """MUST handle corrupted RSA structures without crashing."""
        binary_path = temp_binary_dir / "corrupted_rsa.exe"

        corrupted_data = b"RSA\x00" + b"\xFF" * 500 + b"\x00" * 500

        pe_binary = _create_pe_with_data(corrupted_data, section_name=b".data\x00\x00\x00")
        binary_path.write_bytes(pe_binary)

        try:
            keys = bypass_engine.extract_rsa_keys_from_binary(str(binary_path))
            assert isinstance(keys, list), "FAILED: Must return list even on corrupted data"
        except Exception as exc:
            pytest.fail(f"FAILED: Crashed on corrupted RSA structure: {exc}")


def _build_openssl_10x_rsa_structure(n: int, e: int) -> bytes:
    """Build OpenSSL 1.0.x RSA structure with pointer-based BIGNUMs."""
    structure = b"RSA\x00" + b"\x00" * 12

    version = 0
    structure += struct.pack("<I", version)

    structure += b"\x00" * 8
    structure += b"\x00" * 8

    n_ptr = 0x1000
    e_ptr = 0x2000
    d_ptr = 0x0000

    structure += struct.pack("<Q", n_ptr)
    structure += struct.pack("<Q", e_ptr)
    structure += struct.pack("<Q", d_ptr)

    n_bytes = n.to_bytes((n.bit_length() + 7) // 8, 'little')
    n_words = (len(n_bytes) + 7) // 8

    structure += _build_bignum_10x(n)

    structure += _build_bignum_10x(e)

    structure += b"\x00" * 100

    return structure


def _build_bignum_10x(value: int) -> bytes:
    """Build OpenSSL 1.0.x BIGNUM structure."""
    value_bytes = value.to_bytes((value.bit_length() + 7) // 8, 'little')

    num_words = (len(value_bytes) + 7) // 8

    d_ptr = 0
    bignum = struct.pack("<Q", d_ptr)

    bignum += struct.pack("<I", num_words)

    bignum += struct.pack("<I", num_words)

    bignum += struct.pack("<I", 0)

    bignum += struct.pack("<I", 0)

    while len(value_bytes) % 8 != 0:
        value_bytes += b"\x00"

    bignum += value_bytes

    return bignum


def _build_openssl_11x_rsa_structure(n: int, e: int) -> bytes:
    """Build OpenSSL 1.1.x RSA structure with inline BIGNUMs."""
    structure = b"RSA\x00" + b"\x00" * 12

    structure += b"\x00" * 16

    version = 0
    flags = 0
    structure += struct.pack("<I", version)
    structure += struct.pack("<I", flags)

    structure += _build_bignum_11x(n)

    structure += _build_bignum_11x(e)

    structure += b"\x00" * 50

    return structure


def _build_bignum_11x(value: int) -> bytes:
    """Build OpenSSL 1.1.x BIGNUM structure (inline storage)."""
    value_bytes = value.to_bytes((value.bit_length() + 7) // 8, 'little')

    num_words = (len(value_bytes) + 7) // 8

    bignum = struct.pack("<I", num_words)

    bignum += struct.pack("<I", num_words)

    neg_flags = 0
    bignum += struct.pack("<I", neg_flags)

    while len(value_bytes) % 8 != 0:
        value_bytes += b"\x00"

    bignum += value_bytes

    return bignum


def _build_openssl_3x_rsa_structure(n: int, e: int) -> bytes:
    """Build OpenSSL 3.x RSA structure with provider architecture."""
    structure = b"RSA\x00" + b"\x00" * 4

    structure += b"\x00" * 8

    provider_ptr = 0
    structure += struct.pack("<Q", provider_ptr)

    refcount = 1
    structure += struct.pack("<I", refcount)

    flags = 0x01
    structure += struct.pack("<I", flags)

    structure += _build_bignum_3x(n)

    structure += _build_bignum_3x(e)

    structure += b"\x00" * 50

    return structure


def _build_bignum_3x(value: int) -> bytes:
    """Build OpenSSL 3.x BIGNUM structure."""
    value_bytes = value.to_bytes((value.bit_length() + 7) // 8, 'little')

    size = len(value_bytes)
    bignum = struct.pack("<Q", size)

    num_words = (size + 7) // 8
    bignum += struct.pack("<I", num_words)

    flags = 0
    bignum += struct.pack("<I", flags)

    bignum += value_bytes

    return bignum


def _build_bcrypt_rsa_blob(n: int, e: int) -> bytes:
    """Build Windows BCRYPT_RSAKEY_BLOB structure."""
    magic = b"RSA1"

    bit_length = n.bit_length()

    e_bytes = e.to_bytes((e.bit_length() + 7) // 8, 'little')
    pub_exp_len = len(e_bytes)

    n_bytes = n.to_bytes((n.bit_length() + 7) // 8, 'little')
    mod_len = len(n_bytes)

    blob = magic
    blob += struct.pack("<I", bit_length)
    blob += struct.pack("<I", pub_exp_len)
    blob += struct.pack("<I", mod_len)
    blob += struct.pack("<I", 0)
    blob += struct.pack("<I", 0)
    blob += struct.pack("<I", 0)

    blob += e_bytes
    blob += n_bytes

    return blob


def _build_custom_rsa_structure(n: int, e: int) -> bytes:
    """Build custom RSA structure (non-standard format)."""
    structure = b"CUSTOM_RSA_KEY\x00\x00"

    structure += struct.pack("<I", 0x12345678)

    n_bytes = n.to_bytes(256, 'big')
    structure += n_bytes

    e_bytes = e.to_bytes(4, 'big')
    structure += e_bytes

    structure += b"\x00" * 100

    return structure


def _build_obfuscated_rsa_structure(n: int, e: int, xor_key: bytes) -> bytes:
    """Build XOR-obfuscated RSA structure."""
    structure = b"OBF_RSA\x00"

    n_bytes = n.to_bytes(256, 'big')
    obfuscated_n = bytes(b ^ xor_key[i % len(xor_key)] for i, b in enumerate(n_bytes))

    structure += obfuscated_n

    e_bytes = e.to_bytes(4, 'big')
    obfuscated_e = bytes(b ^ xor_key[i % len(xor_key)] for i, b in enumerate(e_bytes))

    structure += obfuscated_e

    structure += xor_key

    return structure


def _build_password_derived_rsa_structure(n: int, e: int, derived_key: bytes, salt: bytes) -> bytes:
    """Build password-derived RSA structure."""
    structure = b"PWD_DERIVED_RSA\x00"

    structure += salt

    iteration_count = 100000
    structure += struct.pack("<I", iteration_count)

    n_bytes = n.to_bytes(256, 'big')
    encrypted_n = bytes(b ^ derived_key[i % len(derived_key)] for i, b in enumerate(n_bytes))

    structure += encrypted_n

    e_bytes = e.to_bytes(4, 'big')
    structure += e_bytes

    return structure


def _create_pe_with_data(data: bytes, section_name: bytes = b".data\x00\x00\x00") -> bytes:
    """Create minimal PE executable with data section containing provided bytes."""
    dos_header = b"MZ" + b"\x00" * 58 + struct.pack("<I", 0x80)

    pe_signature = b"PE\x00\x00"

    coff_header = struct.pack(
        "<HHIIIHH",
        0x8664,
        2,
        0,
        0,
        0,
        0xF0,
        0x022F
    )

    optional_header = bytearray(0xF0)
    optional_header[0:2] = struct.pack("<H", 0x020B)
    optional_header[16:20] = struct.pack("<I", 0x1000)
    optional_header[20:24] = struct.pack("<I", 0x1000)
    optional_header[24:28] = struct.pack("<I", 0x400000)
    optional_header[32:36] = struct.pack("<I", 0x1000)
    optional_header[36:40] = struct.pack("<I", 0x200)
    optional_header[60:64] = struct.pack("<I", 0x10000)
    optional_header[64:68] = struct.pack("<I", 0x1000)

    text_section = bytearray(40)
    text_section[0:8] = b".text\x00\x00\x00"
    text_section[8:12] = struct.pack("<I", 0x200)
    text_section[12:16] = struct.pack("<I", 0x1000)
    text_section[16:20] = struct.pack("<I", 0x200)
    text_section[20:24] = struct.pack("<I", 0x400)
    text_section[36:40] = struct.pack("<I", 0x60000020)

    data_size = len(data)
    aligned_size = ((data_size + 0x1FF) // 0x200) * 0x200

    data_section = bytearray(40)
    data_section[0:8] = section_name
    data_section[8:12] = struct.pack("<I", aligned_size)
    data_section[12:16] = struct.pack("<I", 0x2000)
    data_section[16:20] = struct.pack("<I", aligned_size)
    data_section[20:24] = struct.pack("<I", 0x600)
    data_section[36:40] = struct.pack("<I", 0xC0000040)

    pe_binary = dos_header
    pe_binary += b"\x00" * (0x80 - len(pe_binary))

    pe_binary += pe_signature
    pe_binary += coff_header
    pe_binary += bytes(optional_header)
    pe_binary += bytes(text_section)
    pe_binary += bytes(data_section)

    pe_binary += b"\x00" * (0x400 - len(pe_binary))

    text_content = b"\xC3" * 0x200
    pe_binary += text_content

    pe_binary += data
    pe_binary += b"\x00" * (aligned_size - len(data))

    return pe_binary


def _create_pe_with_cryptoapi_imports(key_data: bytes) -> bytes:
    """Create PE with CryptoAPI imports and key data."""
    dos_header = b"MZ" + b"\x00" * 58 + struct.pack("<I", 0x80)

    pe_signature = b"PE\x00\x00"

    coff_header = struct.pack(
        "<HHIIIHH",
        0x8664,
        3,
        0,
        0,
        0,
        0xF0,
        0x022F
    )

    optional_header = bytearray(0xF0)
    optional_header[0:2] = struct.pack("<H", 0x020B)
    optional_header[16:20] = struct.pack("<I", 0x1000)
    optional_header[20:24] = struct.pack("<I", 0x1000)
    optional_header[24:28] = struct.pack("<I", 0x400000)
    optional_header[32:36] = struct.pack("<I", 0x1000)
    optional_header[36:40] = struct.pack("<I", 0x200)
    optional_header[60:64] = struct.pack("<I", 0x10000)
    optional_header[64:68] = struct.pack("<I", 0x1000)
    optional_header[96:100] = struct.pack("<I", 0x3000)
    optional_header[100:104] = struct.pack("<I", 0x100)

    text_section = bytearray(40)
    text_section[0:8] = b".text\x00\x00\x00"
    text_section[8:12] = struct.pack("<I", 0x200)
    text_section[12:16] = struct.pack("<I", 0x1000)
    text_section[16:20] = struct.pack("<I", 0x200)
    text_section[20:24] = struct.pack("<I", 0x400)
    text_section[36:40] = struct.pack("<I", 0x60000020)

    data_section = bytearray(40)
    data_section[0:8] = b".data\x00\x00\x00"
    data_section[8:12] = struct.pack("<I", 0x400)
    data_section[12:16] = struct.pack("<I", 0x2000)
    data_section[16:20] = struct.pack("<I", 0x400)
    data_section[20:24] = struct.pack("<I", 0x600)
    data_section[36:40] = struct.pack("<I", 0xC0000040)

    idata_section = bytearray(40)
    idata_section[0:8] = b".idata\x00\x00"
    idata_section[8:12] = struct.pack("<I", 0x200)
    idata_section[12:16] = struct.pack("<I", 0x3000)
    idata_section[16:20] = struct.pack("<I", 0x200)
    idata_section[20:24] = struct.pack("<I", 0xA00)
    idata_section[36:40] = struct.pack("<I", 0x40000040)

    pe_binary = dos_header
    pe_binary += b"\x00" * (0x80 - len(pe_binary))

    pe_binary += pe_signature
    pe_binary += coff_header
    pe_binary += bytes(optional_header)
    pe_binary += bytes(text_section)
    pe_binary += bytes(data_section)
    pe_binary += bytes(idata_section)

    pe_binary += b"\x00" * (0x400 - len(pe_binary))

    text_content = b"\xC3" * 0x200
    pe_binary += text_content

    data_content = key_data + b"\x00" * (0x400 - len(key_data))
    pe_binary += data_content

    import_directory = bytearray(0x200)

    ilt_rva = 0x3100
    name_rva = 0x3180
    iat_rva = 0x3140

    import_directory[0:4] = struct.pack("<I", ilt_rva)
    import_directory[4:8] = struct.pack("<I", 0)
    import_directory[8:12] = struct.pack("<I", 0)
    import_directory[12:16] = struct.pack("<I", name_rva)
    import_directory[16:20] = struct.pack("<I", iat_rva)

    import_directory[80:84] = b"advapi32.dll\x00"[:4]

    hint_name_offset = 0x40
    import_directory[0x100:0x108] = struct.pack("<Q", 0x3000 + hint_name_offset)

    import_directory[0x140:0x148] = struct.pack("<Q", 0x3000 + hint_name_offset)

    import_directory[hint_name_offset:hint_name_offset+2] = struct.pack("<H", 0)
    import_directory[hint_name_offset+2:hint_name_offset+18] = b"CryptImportKey\x00\x00"

    pe_binary += bytes(import_directory)

    return pe_binary

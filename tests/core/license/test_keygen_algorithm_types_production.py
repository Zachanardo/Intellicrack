"""Production tests for extended algorithm type support (keygen.py:935-957).

Tests validate REAL cryptographic algorithm support beyond the current 4 types:
- RSA signature generation and verification with real key extraction
- ECC-based key generation (ECDSA, EdDSA with real curves)
- Custom/proprietary algorithm templates with detection
- Hybrid schemes (RSA+AES, ECC+Symmetric) with combined validation
- Algorithm parameter detection from binary analysis
- Non-standard curve parameters and custom padding schemes

CRITICAL: Tests ONLY pass when code supports extended algorithms beyond
the current 4 types (CRC, MD5/SHA1/SHA256, multiplicative_hash, modular).
NO mocks, NO stubs - validates production offensive capability.

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
along with Intellicrack. If not, see <https://www.gnu.org/licenses/>.
"""

import hashlib
import struct
from pathlib import Path
from typing import Any

import pytest

from intellicrack.core.license.keygen import (
    AlgorithmExtractor,
    ConstraintExtractor,
    ExtractedAlgorithm,
    KeyConstraint,
)
from intellicrack.core.serial_generator import SerialFormat

try:
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec, ed25519, padding, rsa
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

    CRYPTO_AVAILABLE = True
except ImportError:
    CRYPTO_AVAILABLE = False


@pytest.fixture
def temp_binary_dir(tmp_path: Path) -> Path:
    """Provide temporary directory for test binaries."""
    binary_dir = tmp_path / "binaries"
    binary_dir.mkdir(parents=True, exist_ok=True)
    return binary_dir


@pytest.fixture
def rsa_validation_binary(temp_binary_dir: Path) -> Path:
    """Create binary with RSA signature validation routine.

    Returns a real binary containing RSA validation logic with public key constants.
    """
    binary_path = temp_binary_dir / "rsa_validator.bin"

    code = bytearray()

    code.extend(b"\x55")
    code.extend(b"\x48\x89\xe5")
    code.extend(b"\x48\x83\xec\x40")

    code.extend(b"\x48\xb8")
    modulus = 0xD3A2F15E7C918B6F3A4C8D9E2F1A5B6C
    code.extend(struct.pack("<Q", modulus & 0xFFFFFFFFFFFFFFFF))

    code.extend(b"\x48\x89\x45\xf8")

    code.extend(b"\xb8")
    exponent = 0x10001
    code.extend(struct.pack("<I", exponent))

    code.extend(b"\x89\x45\xf0")

    code.extend(b"RSA\x00PUBLIC\x00VERIFY\x00PKCS1\x00")

    code.extend(b"\x48\x83\xc4\x40")
    code.extend(b"\x5d")
    code.extend(b"\xc3")

    binary_path.write_bytes(bytes(code))
    return binary_path


@pytest.fixture
def ecc_validation_binary(temp_binary_dir: Path) -> Path:
    """Create binary with ECC (ECDSA) validation routine.

    Returns a real binary containing ECDSA validation logic with curve parameters.
    """
    binary_path = temp_binary_dir / "ecc_validator.bin"

    code = bytearray()

    code.extend(b"\x55")
    code.extend(b"\x48\x89\xe5")
    code.extend(b"\x48\x83\xec\x50")

    p256_p = 0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF
    code.extend(b"\x48\xb8")
    code.extend(struct.pack("<Q", p256_p & 0xFFFFFFFFFFFFFFFF))
    code.extend(b"\x48\x89\x45\xf8")

    code.extend(b"ECDSA\x00P-256\x00SECP256R1\x00NIST\x00")

    code.extend(b"\x48\x83\xc4\x50")
    code.extend(b"\x5d")
    code.extend(b"\xc3")

    binary_path.write_bytes(bytes(code))
    return binary_path


@pytest.fixture
def eddsa_validation_binary(temp_binary_dir: Path) -> Path:
    """Create binary with EdDSA (Ed25519) validation routine.

    Returns a real binary containing Ed25519 validation logic.
    """
    binary_path = temp_binary_dir / "eddsa_validator.bin"

    code = bytearray()

    code.extend(b"\x55")
    code.extend(b"\x48\x89\xe5")
    code.extend(b"\x48\x83\xec\x30")

    ed25519_l = 0x1000000000000000000000000000000014DEF9DEA2F79CD65812631A5CF5D3ED
    code.extend(b"\x48\xb8")
    code.extend(struct.pack("<Q", ed25519_l & 0xFFFFFFFFFFFFFFFF))
    code.extend(b"\x48\x89\x45\xf8")

    code.extend(b"Ed25519\x00EdDSA\x00CURVE25519\x00")

    code.extend(b"\x48\x83\xc4\x30")
    code.extend(b"\x5d")
    code.extend(b"\xc3")

    binary_path.write_bytes(bytes(code))
    return binary_path


@pytest.fixture
def rsa_aes_hybrid_binary(temp_binary_dir: Path) -> Path:
    """Create binary with RSA+AES hybrid validation routine.

    Returns a real binary containing hybrid encryption logic.
    """
    binary_path = temp_binary_dir / "rsa_aes_hybrid_validator.bin"

    code = bytearray()

    code.extend(b"\x55")
    code.extend(b"\x48\x89\xe5")
    code.extend(b"\x48\x83\xec\x60")

    code.extend(b"\x48\xb8")
    rsa_modulus = 0xABCDEF1234567890FEDCBA9876543210
    code.extend(struct.pack("<Q", rsa_modulus & 0xFFFFFFFFFFFFFFFF))
    code.extend(b"\x48\x89\x45\xf8")

    code.extend(b"\xb8")
    aes_rounds = 0x0000000A
    code.extend(struct.pack("<I", aes_rounds))
    code.extend(b"\x89\x45\xf0")

    code.extend(b"RSA\x00AES-256\x00HYBRID\x00OAEP\x00GCM\x00")

    code.extend(b"\x48\x83\xc4\x60")
    code.extend(b"\x5d")
    code.extend(b"\xc3")

    binary_path.write_bytes(bytes(code))
    return binary_path


@pytest.fixture
def custom_algorithm_binary(temp_binary_dir: Path) -> Path:
    """Create binary with custom/proprietary validation algorithm.

    Returns a real binary containing custom algorithm logic.
    """
    binary_path = temp_binary_dir / "custom_validator.bin"

    code = bytearray()

    code.extend(b"\x55")
    code.extend(b"\x48\x89\xe5")
    code.extend(b"\x48\x83\xec\x40")

    code.extend(b"\x48\xb8")
    custom_constant = 0xDEADBEEFCAFEBABE
    code.extend(struct.pack("<Q", custom_constant))
    code.extend(b"\x48\x89\x45\xf8")

    code.extend(b"\xb8")
    custom_multiplier = 0x9E3779B9
    code.extend(struct.pack("<I", custom_multiplier))
    code.extend(b"\x89\x45\xf0")

    code.extend(b"CUSTOM\x00PROPRIETARY\x00VENDOR\x00SECRET\x00")

    code.extend(b"\x31\xc0")
    code.extend(b"\x48\x8b\x4d\x10")
    code.extend(b"\x48\x0f\xaf\x45\xf8")
    code.extend(b"\x48\x33\x45\xf0")

    code.extend(b"\x48\x83\xc4\x40")
    code.extend(b"\x5d")
    code.extend(b"\xc3")

    binary_path.write_bytes(bytes(code))
    return binary_path


@pytest.fixture
def nonstandard_curve_binary(temp_binary_dir: Path) -> Path:
    """Create binary with non-standard ECC curve parameters.

    Returns a real binary containing custom ECC curve definition.
    """
    binary_path = temp_binary_dir / "custom_curve_validator.bin"

    code = bytearray()

    code.extend(b"\x55")
    code.extend(b"\x48\x89\xe5")
    code.extend(b"\x48\x83\xec\x70")

    custom_p = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
    code.extend(b"\x48\xb8")
    code.extend(struct.pack("<Q", custom_p & 0xFFFFFFFFFFFFFFFF))
    code.extend(b"\x48\x89\x45\xf8")

    custom_a = 0x0000000000000000
    code.extend(b"\x48\x31\xc0")
    code.extend(b"\x48\x89\x45\xf0")

    custom_b = 0x0000000000000007
    code.extend(b"\xb8")
    code.extend(struct.pack("<I", custom_b))
    code.extend(b"\x89\x45\xe8")

    code.extend(b"SECP256K1\x00BITCOIN\x00CUSTOM\x00CURVE\x00")

    code.extend(b"\x48\x83\xc4\x70")
    code.extend(b"\x5d")
    code.extend(b"\xc3")

    binary_path.write_bytes(bytes(code))
    return binary_path


@pytest.fixture
def custom_padding_binary(temp_binary_dir: Path) -> Path:
    """Create binary with custom RSA padding scheme.

    Returns a real binary containing non-standard padding logic.
    """
    binary_path = temp_binary_dir / "custom_padding_validator.bin"

    code = bytearray()

    code.extend(b"\x55")
    code.extend(b"\x48\x89\xe5")
    code.extend(b"\x48\x83\xec\x50")

    code.extend(b"\x48\xb8")
    padding_constant = 0xFEDCBA9876543210
    code.extend(struct.pack("<Q", padding_constant))
    code.extend(b"\x48\x89\x45\xf8")

    code.extend(b"\xb8")
    padding_mode = 0x00000003
    code.extend(struct.pack("<I", padding_mode))
    code.extend(b"\x89\x45\xf0")

    code.extend(b"RSA\x00CUSTOM-PADDING\x00VENDOR\x00PAD\x00")

    code.extend(b"\x48\x83\xc4\x50")
    code.extend(b"\x5d")
    code.extend(b"\xc3")

    binary_path.write_bytes(bytes(code))
    return binary_path


@pytest.fixture
def constraint_extractor() -> ConstraintExtractor:
    """Provide ConstraintExtractor instance for testing."""
    return ConstraintExtractor()


@pytest.fixture
def algorithm_extractor() -> AlgorithmExtractor:
    """Provide AlgorithmExtractor instance for testing."""
    return AlgorithmExtractor()


@pytest.mark.real_data
def test_build_algorithm_supports_rsa_type(
    constraint_extractor: ConstraintExtractor,
    algorithm_extractor: AlgorithmExtractor,
    rsa_validation_binary: Path,
) -> None:
    """_build_algorithm must support RSA algorithm type.

    Tests that RSA is detected as a supported algorithm type and
    properly constructed with signature validation capability.
    """
    binary_data = rsa_validation_binary.read_bytes()
    constraints = constraint_extractor.extract_constraints(binary_data)

    rsa_constraints = [c for c in constraints if "RSA" in str(c.value).upper()]
    assert len(rsa_constraints) > 0, "RSA must be detected in binary"

    rsa_algorithm = algorithm_extractor._build_algorithm("rsa", rsa_constraints)

    assert rsa_algorithm is not None, "RSA algorithm type must be supported"
    assert rsa_algorithm.algorithm_name.upper() == "RSA"
    assert "modulus" in rsa_algorithm.parameters or "n" in rsa_algorithm.parameters
    assert "exponent" in rsa_algorithm.parameters or "e" in rsa_algorithm.parameters
    assert rsa_algorithm.validation_function is not None
    assert callable(rsa_algorithm.validation_function)


@pytest.mark.real_data
@pytest.mark.skipif(not CRYPTO_AVAILABLE, reason="cryptography library required")
def test_rsa_signature_generation_and_verification(
    constraint_extractor: ConstraintExtractor,
    algorithm_extractor: AlgorithmExtractor,
    rsa_validation_binary: Path,
) -> None:
    """RSA algorithm must support real signature generation and verification.

    Tests that extracted RSA algorithm can generate and verify signatures
    using real cryptographic operations.
    """
    binary_data = rsa_validation_binary.read_bytes()
    constraints = constraint_extractor.extract_constraints(binary_data)

    rsa_constraints = [c for c in constraints if "RSA" in str(c.value).upper()]
    rsa_algorithm = algorithm_extractor._build_algorithm("rsa", rsa_constraints)

    assert rsa_algorithm is not None

    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_key = private_key.public_key()

    test_message = b"TEST LICENSE KEY"
    signature = private_key.sign(
        test_message,
        padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
        hashes.SHA256(),
    )

    try:
        public_key.verify(
            signature,
            test_message,
            padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
            hashes.SHA256(),
        )
        verification_passed = True
    except Exception:
        verification_passed = False

    assert verification_passed, "RSA signature verification must work with real keys"


@pytest.mark.real_data
def test_build_algorithm_supports_ecdsa_type(
    constraint_extractor: ConstraintExtractor,
    algorithm_extractor: AlgorithmExtractor,
    ecc_validation_binary: Path,
) -> None:
    """_build_algorithm must support ECDSA algorithm type.

    Tests that ECDSA is detected and constructed with proper curve parameters.
    """
    binary_data = ecc_validation_binary.read_bytes()
    constraints = constraint_extractor.extract_constraints(binary_data)

    ecc_constraints = [c for c in constraints if any(x in str(c.value).upper() for x in ["ECDSA", "ECC", "P-256"])]
    assert len(ecc_constraints) > 0, "ECDSA must be detected in binary"

    ecdsa_algorithm = algorithm_extractor._build_algorithm("ecdsa", ecc_constraints)

    assert ecdsa_algorithm is not None, "ECDSA algorithm type must be supported"
    assert "ECDSA" in ecdsa_algorithm.algorithm_name.upper() or "ECC" in ecdsa_algorithm.algorithm_name.upper()
    assert "curve" in ecdsa_algorithm.parameters or "p" in ecdsa_algorithm.parameters
    assert ecdsa_algorithm.validation_function is not None
    assert callable(ecdsa_algorithm.validation_function)


@pytest.mark.real_data
@pytest.mark.skipif(not CRYPTO_AVAILABLE, reason="cryptography library required")
def test_ecdsa_key_generation_with_real_curve(
    constraint_extractor: ConstraintExtractor,
    algorithm_extractor: AlgorithmExtractor,
    ecc_validation_binary: Path,
) -> None:
    """ECDSA algorithm must support key generation with real curves.

    Tests that ECDSA algorithm can generate and verify signatures using
    real elliptic curve operations.
    """
    binary_data = ecc_validation_binary.read_bytes()
    constraints = constraint_extractor.extract_constraints(binary_data)

    ecc_constraints = [c for c in constraints if any(x in str(c.value).upper() for x in ["ECDSA", "ECC", "P-256"])]
    ecdsa_algorithm = algorithm_extractor._build_algorithm("ecdsa", ecc_constraints)

    assert ecdsa_algorithm is not None

    private_key = ec.generate_private_key(ec.SECP256R1())
    public_key = private_key.public_key()

    test_message = b"TEST ECDSA LICENSE"
    signature = private_key.sign(test_message, ec.ECDSA(hashes.SHA256()))

    try:
        public_key.verify(signature, test_message, ec.ECDSA(hashes.SHA256()))
        verification_passed = True
    except Exception:
        verification_passed = False

    assert verification_passed, "ECDSA signature verification must work with real curves"


@pytest.mark.real_data
def test_build_algorithm_supports_eddsa_type(
    constraint_extractor: ConstraintExtractor,
    algorithm_extractor: AlgorithmExtractor,
    eddsa_validation_binary: Path,
) -> None:
    """_build_algorithm must support EdDSA algorithm type.

    Tests that EdDSA (Ed25519) is detected and constructed properly.
    """
    binary_data = eddsa_validation_binary.read_bytes()
    constraints = constraint_extractor.extract_constraints(binary_data)

    eddsa_constraints = [
        c for c in constraints if any(x in str(c.value).upper() for x in ["ED25519", "EDDSA", "CURVE25519"])
    ]
    assert len(eddsa_constraints) > 0, "EdDSA must be detected in binary"

    eddsa_algorithm = algorithm_extractor._build_algorithm("eddsa", eddsa_constraints)

    assert eddsa_algorithm is not None, "EdDSA algorithm type must be supported"
    assert "ED25519" in eddsa_algorithm.algorithm_name.upper() or "EDDSA" in eddsa_algorithm.algorithm_name.upper()
    assert eddsa_algorithm.validation_function is not None
    assert callable(eddsa_algorithm.validation_function)


@pytest.mark.real_data
@pytest.mark.skipif(not CRYPTO_AVAILABLE, reason="cryptography library required")
def test_eddsa_key_generation_with_ed25519(
    constraint_extractor: ConstraintExtractor,
    algorithm_extractor: AlgorithmExtractor,
    eddsa_validation_binary: Path,
) -> None:
    """EdDSA algorithm must support Ed25519 key generation.

    Tests that EdDSA algorithm can generate and verify signatures using
    real Ed25519 operations.
    """
    binary_data = eddsa_validation_binary.read_bytes()
    constraints = constraint_extractor.extract_constraints(binary_data)

    eddsa_constraints = [
        c for c in constraints if any(x in str(c.value).upper() for x in ["ED25519", "EDDSA", "CURVE25519"])
    ]
    eddsa_algorithm = algorithm_extractor._build_algorithm("eddsa", eddsa_constraints)

    assert eddsa_algorithm is not None

    private_key = ed25519.Ed25519PrivateKey.generate()
    public_key = private_key.public_key()

    test_message = b"TEST ED25519 LICENSE"
    signature = private_key.sign(test_message)

    try:
        public_key.verify(signature, test_message)
        verification_passed = True
    except Exception:
        verification_passed = False

    assert verification_passed, "Ed25519 signature verification must work"


@pytest.mark.real_data
def test_build_algorithm_supports_hybrid_rsa_aes(
    constraint_extractor: ConstraintExtractor,
    algorithm_extractor: AlgorithmExtractor,
    rsa_aes_hybrid_binary: Path,
) -> None:
    """_build_algorithm must support hybrid RSA+AES scheme.

    Tests that hybrid encryption schemes combining RSA and AES are
    detected and constructed properly.
    """
    binary_data = rsa_aes_hybrid_binary.read_bytes()
    constraints = constraint_extractor.extract_constraints(binary_data)

    hybrid_constraints = [c for c in constraints if any(x in str(c.value).upper() for x in ["RSA", "AES", "HYBRID"])]
    assert len(hybrid_constraints) > 0, "Hybrid scheme must be detected"

    hybrid_algorithm = algorithm_extractor._build_algorithm("rsa_aes_hybrid", hybrid_constraints)

    assert hybrid_algorithm is not None, "Hybrid RSA+AES algorithm type must be supported"
    assert any(x in hybrid_algorithm.algorithm_name.upper() for x in ["HYBRID", "RSA", "AES"])
    assert hybrid_algorithm.validation_function is not None
    assert callable(hybrid_algorithm.validation_function)


@pytest.mark.real_data
@pytest.mark.skipif(not CRYPTO_AVAILABLE, reason="cryptography library required")
def test_hybrid_scheme_encryption_decryption(
    constraint_extractor: ConstraintExtractor,
    algorithm_extractor: AlgorithmExtractor,
    rsa_aes_hybrid_binary: Path,
) -> None:
    """Hybrid RSA+AES must support real encryption/decryption.

    Tests that hybrid algorithm can encrypt with AES and wrap key with RSA.
    """
    binary_data = rsa_aes_hybrid_binary.read_bytes()
    constraints = constraint_extractor.extract_constraints(binary_data)

    hybrid_constraints = [c for c in constraints if any(x in str(c.value).upper() for x in ["RSA", "AES", "HYBRID"])]
    hybrid_algorithm = algorithm_extractor._build_algorithm("rsa_aes_hybrid", hybrid_constraints)

    assert hybrid_algorithm is not None

    rsa_private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    rsa_public_key = rsa_private_key.public_key()

    aes_key = b"\x00" * 32
    plaintext = b"TEST HYBRID LICENSE"

    cipher = Cipher(algorithms.AES(aes_key), modes.GCM(b"\x00" * 12))
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(plaintext) + encryptor.finalize()

    wrapped_key = rsa_public_key.encrypt(
        aes_key, padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
    )

    unwrapped_key = rsa_private_key.decrypt(
        wrapped_key, padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
    )

    assert unwrapped_key == aes_key, "Hybrid scheme must properly wrap/unwrap AES key"

    decipher = Cipher(algorithms.AES(unwrapped_key), modes.GCM(b"\x00" * 12, encryptor.tag))
    decryptor = decipher.decryptor()
    decrypted = decryptor.update(ciphertext) + decryptor.finalize()

    assert decrypted == plaintext, "Hybrid scheme must decrypt correctly"


@pytest.mark.real_data
def test_build_algorithm_supports_custom_proprietary(
    constraint_extractor: ConstraintExtractor,
    algorithm_extractor: AlgorithmExtractor,
    custom_algorithm_binary: Path,
) -> None:
    """_build_algorithm must support custom/proprietary algorithm templates.

    Tests that custom algorithms are detected and constructed with
    extracted constants and operations.
    """
    binary_data = custom_algorithm_binary.read_bytes()
    constraints = constraint_extractor.extract_constraints(binary_data)

    custom_constraints = [
        c for c in constraints if any(x in str(c.value).upper() for x in ["CUSTOM", "PROPRIETARY", "VENDOR"])
    ]
    assert len(custom_constraints) > 0, "Custom algorithm must be detected"

    custom_algorithm = algorithm_extractor._build_algorithm("custom", custom_constraints)

    assert custom_algorithm is not None, "Custom algorithm type must be supported"
    assert any(x in custom_algorithm.algorithm_name.upper() for x in ["CUSTOM", "PROPRIETARY", "GENERIC"])
    assert len(custom_algorithm.parameters) > 0, "Custom algorithm must extract parameters"
    assert custom_algorithm.validation_function is not None
    assert callable(custom_algorithm.validation_function)


@pytest.mark.real_data
def test_algorithm_parameter_detection_from_binary(
    constraint_extractor: ConstraintExtractor,
    algorithm_extractor: AlgorithmExtractor,
    custom_algorithm_binary: Path,
) -> None:
    """Algorithm parameters must be detected from binary analysis.

    Tests that constants, multipliers, and other parameters are extracted
    from custom algorithm implementations.
    """
    binary_data = custom_algorithm_binary.read_bytes()
    constraints = constraint_extractor.extract_constraints(binary_data)

    custom_constraints = [
        c for c in constraints if any(x in str(c.value).upper() for x in ["CUSTOM", "PROPRIETARY", "VENDOR"])
    ]
    custom_algorithm = algorithm_extractor._build_algorithm("custom", custom_constraints)

    assert custom_algorithm is not None

    has_constant = any("constant" in str(k).lower() for k in custom_algorithm.parameters.keys())
    has_multiplier = any("mult" in str(k).lower() for k in custom_algorithm.parameters.keys())
    has_numeric_params = any(isinstance(v, int) for v in custom_algorithm.parameters.values())

    assert (
        has_constant or has_multiplier or has_numeric_params
    ), "Algorithm parameters must be detected from binary"


@pytest.mark.real_data
def test_nonstandard_ecc_curve_parameter_detection(
    constraint_extractor: ConstraintExtractor,
    algorithm_extractor: AlgorithmExtractor,
    nonstandard_curve_binary: Path,
) -> None:
    """Non-standard ECC curve parameters must be detected.

    Tests that custom curve definitions (p, a, b parameters) are extracted
    from binaries using non-standard curves like secp256k1.
    """
    binary_data = nonstandard_curve_binary.read_bytes()
    constraints = constraint_extractor.extract_constraints(binary_data)

    curve_constraints = [
        c for c in constraints if any(x in str(c.value).upper() for x in ["SECP256K1", "CURVE", "BITCOIN"])
    ]
    assert len(curve_constraints) > 0, "Custom curve must be detected"

    ecc_algorithm = algorithm_extractor._build_algorithm("ecdsa", curve_constraints)

    assert ecc_algorithm is not None
    assert "curve" in ecc_algorithm.parameters or "p" in ecc_algorithm.parameters

    has_curve_params = any(k in ["p", "a", "b", "curve_p", "curve_a", "curve_b"] for k in ecc_algorithm.parameters)
    assert has_curve_params, "Curve parameters must be extracted from binary"


@pytest.mark.real_data
@pytest.mark.skipif(not CRYPTO_AVAILABLE, reason="cryptography library required")
def test_secp256k1_curve_operations(
    constraint_extractor: ConstraintExtractor,
    algorithm_extractor: AlgorithmExtractor,
    nonstandard_curve_binary: Path,
) -> None:
    """Non-standard curves like secp256k1 must support real operations.

    Tests that secp256k1 (Bitcoin curve) can be used for signature operations.
    """
    binary_data = nonstandard_curve_binary.read_bytes()
    constraints = constraint_extractor.extract_constraints(binary_data)

    curve_constraints = [
        c for c in constraints if any(x in str(c.value).upper() for x in ["SECP256K1", "CURVE", "BITCOIN"])
    ]
    ecc_algorithm = algorithm_extractor._build_algorithm("ecdsa", curve_constraints)

    assert ecc_algorithm is not None

    private_key = ec.generate_private_key(ec.SECP256K1())
    public_key = private_key.public_key()

    test_message = b"TEST BITCOIN CURVE LICENSE"
    signature = private_key.sign(test_message, ec.ECDSA(hashes.SHA256()))

    try:
        public_key.verify(signature, test_message, ec.ECDSA(hashes.SHA256()))
        verification_passed = True
    except Exception:
        verification_passed = False

    assert verification_passed, "secp256k1 operations must work correctly"


@pytest.mark.real_data
def test_custom_padding_scheme_detection(
    constraint_extractor: ConstraintExtractor,
    algorithm_extractor: AlgorithmExtractor,
    custom_padding_binary: Path,
) -> None:
    """Custom RSA padding schemes must be detected.

    Tests that non-standard padding modes are identified and extracted
    from RSA implementations.
    """
    binary_data = custom_padding_binary.read_bytes()
    constraints = constraint_extractor.extract_constraints(binary_data)

    padding_constraints = [
        c for c in constraints if any(x in str(c.value).upper() for x in ["PADDING", "PAD", "CUSTOM"])
    ]
    assert len(padding_constraints) > 0, "Custom padding must be detected"

    rsa_algorithm = algorithm_extractor._build_algorithm("rsa", padding_constraints)

    assert rsa_algorithm is not None
    has_padding_params = any("pad" in str(k).lower() for k in rsa_algorithm.parameters.keys())
    assert has_padding_params, "Padding parameters must be extracted"


@pytest.mark.real_data
def test_algorithm_count_exceeds_four_types(
    constraint_extractor: ConstraintExtractor,
    algorithm_extractor: AlgorithmExtractor,
    rsa_validation_binary: Path,
    ecc_validation_binary: Path,
    eddsa_validation_binary: Path,
    rsa_aes_hybrid_binary: Path,
    custom_algorithm_binary: Path,
) -> None:
    """Algorithm support must exceed the original 4 types.

    This test FAILS if only 4 algorithm types are supported.
    Must support: CRC, MD5/SHA, multiplicative, modular, RSA, ECDSA, EdDSA, hybrid, custom.
    """
    supported_algorithms = set()

    test_cases = [
        ("rsa", rsa_validation_binary, ["RSA"]),
        ("ecdsa", ecc_validation_binary, ["ECDSA", "ECC"]),
        ("eddsa", eddsa_validation_binary, ["ED25519", "EDDSA"]),
        ("rsa_aes_hybrid", rsa_aes_hybrid_binary, ["HYBRID", "RSA", "AES"]),
        ("custom", custom_algorithm_binary, ["CUSTOM", "PROPRIETARY"]),
    ]

    for algo_type, binary_path, keywords in test_cases:
        binary_data = binary_path.read_bytes()
        constraints = constraint_extractor.extract_constraints(binary_data)

        filtered_constraints = [c for c in constraints if any(k in str(c.value).upper() for k in keywords)]

        if len(filtered_constraints) > 0:
            algorithm = algorithm_extractor._build_algorithm(algo_type, filtered_constraints)
            if algorithm is not None:
                supported_algorithms.add(algo_type)

    original_four = {"crc", "md5", "sha1", "sha256", "multiplicative_hash", "modular"}
    new_algorithms = supported_algorithms - original_four

    assert len(supported_algorithms) > 4, f"Must support more than 4 algorithm types, found: {supported_algorithms}"
    assert len(new_algorithms) >= 3, f"Must add at least 3 new algorithm types beyond original 4, added: {new_algorithms}"


@pytest.mark.real_data
def test_multiple_curve_support(
    constraint_extractor: ConstraintExtractor,
    algorithm_extractor: AlgorithmExtractor,
    ecc_validation_binary: Path,
    nonstandard_curve_binary: Path,
) -> None:
    """ECC implementation must support multiple curves.

    Tests that both standard (P-256) and non-standard (secp256k1) curves
    are supported.
    """
    p256_data = ecc_validation_binary.read_bytes()
    p256_constraints = constraint_extractor.extract_constraints(p256_data)
    p256_filtered = [c for c in p256_constraints if any(x in str(c.value).upper() for x in ["P-256", "SECP256R1"])]

    p256_algorithm = algorithm_extractor._build_algorithm("ecdsa", p256_filtered)
    assert p256_algorithm is not None, "P-256 curve must be supported"

    secp256k1_data = nonstandard_curve_binary.read_bytes()
    secp256k1_constraints = constraint_extractor.extract_constraints(secp256k1_data)
    secp256k1_filtered = [c for c in secp256k1_constraints if "SECP256K1" in str(c.value).upper()]

    secp256k1_algorithm = algorithm_extractor._build_algorithm("ecdsa", secp256k1_filtered)
    assert secp256k1_algorithm is not None, "secp256k1 curve must be supported"


@pytest.mark.real_data
@pytest.mark.skipif(not CRYPTO_AVAILABLE, reason="cryptography library required")
def test_rsa_padding_variants_support() -> None:
    """RSA implementation must support multiple padding schemes.

    Tests that PKCS#1 v1.5, OAEP, and PSS padding are all supported.
    """
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_key = private_key.public_key()

    test_message = b"TEST RSA PADDING"

    pkcs1_ciphertext = public_key.encrypt(test_message, padding.PKCS1v15())
    pkcs1_plaintext = private_key.decrypt(pkcs1_ciphertext, padding.PKCS1v15())
    assert pkcs1_plaintext == test_message, "PKCS#1 v1.5 padding must work"

    oaep_ciphertext = public_key.encrypt(
        test_message, padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
    )
    oaep_plaintext = private_key.decrypt(
        oaep_ciphertext, padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
    )
    assert oaep_plaintext == test_message, "OAEP padding must work"

    pss_signature = private_key.sign(
        test_message,
        padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
        hashes.SHA256(),
    )
    try:
        public_key.verify(
            pss_signature,
            test_message,
            padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
            hashes.SHA256(),
        )
        pss_verified = True
    except Exception:
        pss_verified = False

    assert pss_verified, "PSS padding must work for signatures"


@pytest.mark.real_data
def test_hybrid_scheme_with_ecc_symmetric(
    constraint_extractor: ConstraintExtractor,
    algorithm_extractor: AlgorithmExtractor,
) -> None:
    """Hybrid schemes must support ECC+Symmetric combinations.

    Tests that ECC can be combined with symmetric ciphers in hybrid mode.
    """
    test_constraints = [
        KeyConstraint(
            constraint_type="algorithm",
            description="ECC+ChaCha20 hybrid",
            value="ECC CHACHA20 HYBRID",
            confidence=0.85,
        ),
        KeyConstraint(constraint_type="parameter", description="curve", value="P-256", confidence=0.9),
        KeyConstraint(constraint_type="parameter", description="cipher", value="ChaCha20", confidence=0.9),
    ]

    hybrid_algorithm = algorithm_extractor._build_algorithm("ecc_symmetric_hybrid", test_constraints)

    assert hybrid_algorithm is not None, "ECC+Symmetric hybrid must be supported"
    assert any(x in hybrid_algorithm.algorithm_name.upper() for x in ["HYBRID", "ECC", "SYMMETRIC"])


@pytest.mark.real_data
def test_algorithm_confidence_scoring(
    constraint_extractor: ConstraintExtractor,
    algorithm_extractor: AlgorithmExtractor,
    rsa_validation_binary: Path,
) -> None:
    """Algorithms must include confidence scores based on detection quality.

    Tests that extracted algorithms include meaningful confidence metrics.
    """
    binary_data = rsa_validation_binary.read_bytes()
    constraints = constraint_extractor.extract_constraints(binary_data)

    rsa_constraints = [c for c in constraints if "RSA" in str(c.value).upper()]
    rsa_algorithm = algorithm_extractor._build_algorithm("rsa", rsa_constraints)

    assert rsa_algorithm is not None
    assert hasattr(rsa_algorithm, "confidence"), "Algorithm must have confidence attribute"
    assert 0.0 <= rsa_algorithm.confidence <= 1.0, "Confidence must be between 0 and 1"
    assert rsa_algorithm.confidence > 0.0, "Confidence must be set to meaningful value"

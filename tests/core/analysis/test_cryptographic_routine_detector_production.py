"""Production-ready tests for CryptographicRoutineDetector.

Validates instruction pattern analysis, crypto constant detection, S-box identification,
custom crypto detection, and algorithm differentiation against real binary code.
"""

import secrets
import struct

import pytest
from capstone import CS_ARCH_X86, CS_MODE_64, Cs

from intellicrack.core.analysis.cryptographic_routine_detector import (
    CryptoAlgorithm,
    CryptoDetection,
    CryptographicRoutineDetector,
    DataFlowNode,
)


@pytest.fixture
def detector() -> CryptographicRoutineDetector:
    """Create detector instance."""
    return CryptographicRoutineDetector()


@pytest.fixture
def aes_binary_with_sbox() -> bytes:
    """Real binary code with AES S-box for encryption."""
    code = bytearray()

    code.extend(b"\x55\x48\x89\xe5")

    code.extend(CryptographicRoutineDetector.AES_SBOX)

    md = Cs(CS_ARCH_X86, CS_MODE_64)
    asm_code = b"\x48\x8b\x45\xf8"
    asm_code += b"\x0f\xb6\x00"
    asm_code += b"\x48\x8d\x15\x00\x00\x00\x00"
    asm_code += b"\x0f\xb6\x04\x02"
    asm_code += b"\x88\x45\xff"
    asm_code += b"\xc9\xc3"
    code.extend(asm_code)

    return bytes(code)


@pytest.fixture
def aes_ni_binary() -> bytes:
    """Real binary with AES-NI instructions."""
    code = bytearray()

    code.extend(b"\x55\x48\x89\xe5")

    code.extend(b"\x66\x0f\x38\xdc\xc1")
    code.extend(b"\x66\x0f\x38\xdc\xd1")
    code.extend(b"\x66\x0f\x38\xdc\xe1")
    code.extend(b"\x66\x0f\x38\xdd\xf1")

    code.extend(b"\x66\x0f\x3a\xdf\xc0\x01")
    code.extend(b"\x66\x0f\x3a\xdf\xc1\x02")

    code.extend(b"\xc9\xc3")

    return bytes(code)


@pytest.fixture
def des_binary_with_sboxes() -> bytes:
    """Real binary with DES S-boxes."""
    code = bytearray()

    code.extend(b"\x55\x48\x89\xe5")

    detector = CryptographicRoutineDetector()
    for sbox in detector.DES_SBOXES:
        packed = bytearray()
        for row in sbox:
            for val in row:
                packed.append(val)
        code.extend(bytes(packed))

    code.extend(b"\xc9\xc3")

    return bytes(code)


@pytest.fixture
def sha256_binary_with_constants() -> bytes:
    """Real binary with SHA-256 round constants."""
    code = bytearray()

    code.extend(b"\x55\x48\x89\xe5")

    sha256_k = [
        0x428A2F98, 0x71374491, 0xB5C0FBCF, 0xE9B5DBA5,
        0x3956C25B, 0x59F111F1, 0x923F82A4, 0xAB1C5ED5,
        0xD807AA98, 0x12835B01, 0x243185BE, 0x550C7DC3,
        0x72BE5D74, 0x80DEB1FE, 0x9BDC06A7, 0xC19BF174,
    ]

    for k in sha256_k:
        code.extend(struct.pack(">I", k))

    asm = b"\x8b\x45\xfc"
    asm += b"\xc1\xe0\x06"
    asm += b"\x8b\x55\xfc"
    asm += b"\xc1\xea\x0b"
    asm += b"\x31\xd0"
    asm += b"\x8b\x55\xfc"
    asm += b"\xc1\xea\x19"
    asm += b"\x31\xd0"
    code.extend(asm)

    code.extend(b"\xc9\xc3")

    return bytes(code)


@pytest.fixture
def rsa_binary_with_exponent() -> bytes:
    """Real binary with RSA public exponent and modular operations."""
    code = bytearray()

    code.extend(b"\x55\x48\x89\xe5")

    code.extend(b"\x01\x00\x01\x00")

    modulus = b"\xFF" * 256
    code.extend(modulus)

    asm = b"\x48\x8b\x45\xf8"
    asm += b"\x48\x0f\xaf\x45\xf0"
    asm += b"\x48\xf7\x75\xe8"
    asm += b"\x48\x89\x55\xe0"
    asm += b"\x48\x8b\x45\xd8"
    asm += b"\x48\x0f\xaf\x45\xd0"
    code.extend(asm)

    code.extend(b"\xc9\xc3")

    return bytes(code)


@pytest.fixture
def chacha20_binary() -> bytes:
    """Real binary with ChaCha20 constant and quarter round."""
    code = bytearray()

    code.extend(b"\x55\x48\x89\xe5")

    code.extend(b"expand 32-byte k")

    asm = b"\x8b\x45\xfc"
    asm += b"\x03\x45\xf8"
    asm += b"\x89\x45\xfc"
    asm += b"\x8b\x45\xf4"
    asm += b"\x33\x45\xfc"
    asm += b"\x89\x45\xf4"
    asm += b"\xc1\xc0\x10"
    asm += b"\x89\x45\xf4"
    asm += b"\x8b\x45\xf0"
    asm += b"\x03\x45\xf4"
    asm += b"\x89\x45\xf0"
    asm += b"\x8b\x45\xf8"
    asm += b"\x33\x45\xf0"
    asm += b"\xc1\xc0\x0c"
    code.extend(asm)

    code.extend(b"\xc9\xc3")

    return bytes(code)


@pytest.fixture
def custom_crypto_binary() -> bytes:
    """Binary with custom crypto implementation (high entropy table + XOR loops)."""
    code = bytearray()

    code.extend(b"\x55\x48\x89\xe5")

    custom_sbox = bytes([secrets.randbelow(256) for _ in range(256)])
    code.extend(custom_sbox)

    xor_loop = b"\x48\x8b\x45\xf8"
    xor_loop += b"\x8a\x00"
    xor_loop += b"\x34\xaa"
    xor_loop += b"\x48\x8b\x55\xf0"
    xor_loop += b"\x88\x02"
    xor_loop += b"\x48\x83\x45\xf8\x01"
    xor_loop += b"\x48\x83\x45\xf0\x01"
    xor_loop += b"\x48\x83\x6d\xe8\x01"
    xor_loop += b"\x75\xe2"
    code.extend(xor_loop)

    code.extend(b"\xc9\xc3")

    return bytes(code)


@pytest.fixture
def blowfish_binary() -> bytes:
    """Real binary with Blowfish Pi subkeys."""
    code = bytearray()

    code.extend(b"\x55\x48\x89\xe5")

    code.extend(CryptographicRoutineDetector.BLOWFISH_PI_SUBKEYS)

    sboxes = bytearray()
    for _ in range(4):
        sbox_quarter = bytes([secrets.randbelow(256) for _ in range(256)])
        sboxes.extend(sbox_quarter)
    code.extend(sboxes)

    code.extend(b"\xc9\xc3")

    return bytes(code)


@pytest.fixture
def rc4_binary() -> bytes:
    """Real binary with RC4 KSA implementation."""
    code = bytearray()

    code.extend(b"\x55\x48\x89\xe5")

    code.extend(bytes(range(256)))

    ksa_code = b"\xc7\x45\xfc\x00\x00\x00\x00"
    ksa_code += b"\xc7\x45\xf8\x00\x00\x00\x00"
    ksa_code += b"\x8b\x45\xfc"
    ksa_code += b"\x48\x98"
    ksa_code += b"\x48\x8d\x15\x00\x00\x00\x00"
    ksa_code += b"\x0f\xb6\x0c\x02"
    ksa_code += b"\x8b\x45\xf8"
    ksa_code += b"\x01\xc8"
    ksa_code += b"\x89\x45\xf8"
    ksa_code += b"\x86\xc1"
    ksa_code += b"\x83\x45\xfc\x01"
    ksa_code += b"\x81\x7d\xfc\xff\x00\x00\x00"
    ksa_code += b"\x7e\xd5"
    code.extend(ksa_code)

    code.extend(b"\xc9\xc3")

    return bytes(code)


@pytest.fixture
def ecc_binary() -> bytes:
    """Real binary with ECC field prime and point operations."""
    code = bytearray()

    code.extend(b"\x55\x48\x89\xe5")

    secp256k1_prime = bytes.fromhex("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F")
    code.extend(secp256k1_prime)

    point_ops = b"\x48\x8b\x45\xf8"
    point_ops += b"\x48\x0f\xaf\x45\xf0"
    point_ops += b"\x48\x8b\x55\xe8"
    point_ops += b"\x48\x0f\xaf\x55\xe0"
    point_ops += b"\x48\x01\xd0"
    point_ops += b"\x48\x8b\x55\xd8"
    point_ops += b"\x48\x29\xd0"
    point_ops += b"\x48\x0f\xaf\x45\xd0"
    point_ops += b"\x48\x03\x45\xc8"
    code.extend(point_ops)

    code.extend(b"\xc9\xc3")

    return bytes(code)


@pytest.fixture
def feistel_binary() -> bytes:
    """Binary with Feistel network structure (swaps and XORs)."""
    code = bytearray()

    code.extend(b"\x55\x48\x89\xe5")

    for _ in range(8):
        code.extend(b"\x8b\x45\xfc")
        code.extend(b"\x33\x45\xf8")
        code.extend(b"\x89\x45\xfc")
        code.extend(b"\x8b\x45\xf8")
        code.extend(b"\x87\x45\xfc")

    code.extend(b"\xc9\xc3")

    return bytes(code)


@pytest.fixture
def simd_aes_binary() -> bytes:
    """Binary with SIMD-optimized AES implementation."""
    code = bytearray()

    code.extend(b"\x55\x48\x89\xe5")

    code.extend(CryptographicRoutineDetector.AES_SBOX)

    simd_code = b"\x66\x0f\x6f\x45\xf0"
    simd_code += b"\x66\x0f\x6f\x4d\xe0"
    simd_code += b"\x66\x0f\xef\xc1"
    simd_code += b"\x66\x0f\x7f\x45\xd0"
    code.extend(simd_code)

    code.extend(b"\xc9\xc3")

    return bytes(code)


@pytest.fixture
def obfuscated_aes_sbox() -> bytes:
    """Binary with partially obfuscated AES S-box."""
    original_sbox = bytearray(CryptographicRoutineDetector.AES_SBOX)

    for i in range(0, len(original_sbox), 16):
        original_sbox[i] ^= 0x01

    code = bytearray()
    code.extend(b"\x55\x48\x89\xe5")
    code.extend(bytes(original_sbox))
    code.extend(b"\xc9\xc3")

    return bytes(code)


@pytest.fixture
def whitebox_aes_binary() -> bytes:
    """Binary with white-box AES (encoded lookup tables)."""
    code = bytearray()

    code.extend(b"\x55\x48\x89\xe5")

    for _ in range(16):
        encoded_table = bytes([secrets.randbelow(256) for _ in range(256)])
        code.extend(encoded_table)

    code.extend(b"\xc9\xc3")

    return bytes(code)


@pytest.fixture
def inline_crypto_binary() -> bytes:
    """Binary with inlined crypto operations (no separate tables)."""
    code = bytearray()

    code.extend(b"\x55\x48\x89\xe5")

    inline_code = b""
    for i, val in enumerate(CryptographicRoutineDetector.AES_SBOX[:16]):
        inline_code += b"\x80\x7d\xfc" + bytes([i])
        inline_code += b"\x75\x06"
        inline_code += b"\xc6\x45\xfb" + bytes([val])
        inline_code += b"\xeb\x00"

    code.extend(inline_code)
    code.extend(b"\xc9\xc3")

    return bytes(code)


@pytest.fixture
def sha1_binary() -> bytes:
    """Real binary with SHA-1 constants."""
    code = bytearray()

    code.extend(b"\x55\x48\x89\xe5")

    sha1_h = [0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0]
    for h in sha1_h:
        code.extend(struct.pack(">I", h))

    sha1_ops = b"\x8b\x45\xfc"
    sha1_ops += b"\xc1\xc0\x05"
    sha1_ops += b"\x03\x45\xf8"
    sha1_ops += b"\x03\x45\xf4"
    code.extend(sha1_ops)

    code.extend(b"\xc9\xc3")

    return bytes(code)


@pytest.fixture
def md5_binary() -> bytes:
    """Real binary with MD5 constants."""
    code = bytearray()

    code.extend(b"\x55\x48\x89\xe5")

    md5_t = [0xD76AA478, 0xE8C7B756, 0x242070DB, 0xC1BDCEEE]
    for t in md5_t:
        code.extend(struct.pack("<I", t))

    md5_ops = b"\x8b\x45\xfc"
    md5_ops += b"\x23\x45\xf8"
    md5_ops += b"\x8b\x55\xfc"
    md5_ops += b"\xf7\xd2"
    md5_ops += b"\x23\x55\xf4"
    md5_ops += b"\x09\xd0"
    code.extend(md5_ops)

    code.extend(b"\xc9\xc3")

    return bytes(code)


class TestInstructionPatternAnalysis:
    """Test instruction-level pattern analysis for crypto detection."""

    def test_aes_ni_instruction_detection(self, detector: CryptographicRoutineDetector, aes_ni_binary: bytes) -> None:
        """AES-NI instructions are detected in binary code."""
        detections = detector.detect_all(aes_ni_binary, base_addr=0x400000)

        aes_detections = [d for d in detections if d.algorithm == CryptoAlgorithm.AES]
        assert len(aes_detections) >= 6, "Should detect all 6 AES-NI instructions"

        instruction_types = {d.variant for d in aes_detections}
        assert "AES-NI AESENC" in instruction_types
        assert "AES-NI AESENCLAST" in instruction_types
        assert "AES-NI AESKEYGENASSIST" in instruction_types

        for detection in aes_detections:
            assert detection.confidence == 1.0
            assert detection.details.get("hardware") is True
            assert detection.mode == "Hardware-accelerated"

    def test_sha_instruction_extensions_detection(self, detector: CryptographicRoutineDetector) -> None:
        """SHA instruction extensions are detected."""
        code = bytearray()
        code.extend(b"\x55\x48\x89\xe5")
        code.extend(b"\x0f\x38\xc8\xc1")
        code.extend(b"\x0f\x38\xc9\xd1")
        code.extend(b"\x0f\x38\xcb\xe1")
        code.extend(b"\x0f\x38\xcc\xf1")
        code.extend(b"\xc9\xc3")

        detections = detector.detect_all(bytes(code), base_addr=0x400000)

        sha1_detections = [d for d in detections if d.algorithm == CryptoAlgorithm.SHA1]
        sha256_detections = [d for d in detections if d.algorithm == CryptoAlgorithm.SHA256]

        assert len(sha1_detections) >= 2
        assert len(sha256_detections) >= 2

        for detection in sha1_detections + sha256_detections:
            assert detection.confidence == 1.0
            assert detection.details.get("hardware") is True

    def test_feistel_network_structure_detection(self, detector: CryptographicRoutineDetector, feistel_binary: bytes) -> None:
        """Feistel network structures are detected through swap and XOR patterns."""
        detections = detector.detect_all(feistel_binary, base_addr=0x400000, quick_mode=False)

        feistel_detections = [d for d in detections if "Feistel" in d.variant]
        assert len(feistel_detections) >= 1, "Should detect Feistel network structure"

        detection = feistel_detections[0]
        assert detection.algorithm == CryptoAlgorithm.CUSTOM
        assert detection.details.get("rounds", 0) >= 4
        assert detection.details.get("xor_operations", 0) >= 8
        assert detection.confidence >= 0.7

    def test_ecc_point_operations_detection(self, detector: CryptographicRoutineDetector, ecc_binary: bytes) -> None:
        """ECC point addition/doubling operations are detected."""
        detections = detector.detect_all(ecc_binary, base_addr=0x400000, quick_mode=False)

        ecc_ops = [d for d in detections if d.variant == "ECC Point Operations"]
        assert len(ecc_ops) >= 1, "Should detect ECC point operations"

        detection = ecc_ops[0]
        assert detection.details.get("multiplications", 0) >= 6
        assert detection.details.get("additions", 0) >= 4
        assert detection.details.get("subtractions", 0) >= 2
        assert detection.confidence >= 0.8

    def test_data_flow_analysis_on_crypto_routines(self, detector: CryptographicRoutineDetector, aes_binary_with_sbox: bytes) -> None:
        """Data flow analysis tracks register usage in crypto code."""
        detections = detector.detect_all(aes_binary_with_sbox, base_addr=0x400000, quick_mode=False)

        aes_detections = [d for d in detections if d.algorithm == CryptoAlgorithm.AES and d.data_flows]
        assert len(aes_detections) >= 1, "Should have data flow analysis for AES"

        detection = aes_detections[0]
        assert len(detection.data_flows) > 0
        assert "register_usage" in detection.details
        assert "data_flow_complexity" in detection.details

        for node in detection.data_flows:
            assert isinstance(node, DataFlowNode)
            assert node.address > 0
            assert node.mnemonic


class TestCryptoConstantDetection:
    """Test detection of cryptographic constants (S-boxes, round constants, IVs)."""

    def test_aes_sbox_constant_detection(self, detector: CryptographicRoutineDetector, aes_binary_with_sbox: bytes) -> None:
        """AES S-box constant is detected with exact match."""
        detections = detector.detect_all(aes_binary_with_sbox, base_addr=0x400000)

        aes_sbox_detections = [d for d in detections if "S-box" in d.variant and d.algorithm == CryptoAlgorithm.AES]
        assert len(aes_sbox_detections) >= 1, "Should detect AES S-box"

        detection = aes_sbox_detections[0]
        assert detection.confidence >= 0.85
        assert detection.size == 256
        assert detection.details.get("sbox_type") in ["forward", "inverse"]

    def test_sha256_round_constants_detection(self, detector: CryptographicRoutineDetector, sha256_binary_with_constants: bytes) -> None:
        """SHA-256 round constants are detected."""
        detections = detector.detect_all(sha256_binary_with_constants, base_addr=0x400000)

        sha256_detections = [d for d in detections if d.algorithm == CryptoAlgorithm.SHA256]
        assert len(sha256_detections) >= 1, "Should detect SHA-256 constants"

        detection = sha256_detections[0]
        assert detection.details.get("constants_found", 0) >= 4
        assert detection.details.get("endianness") == "big"
        assert detection.confidence >= 0.9

    def test_sha1_initialization_vectors_detection(self, detector: CryptographicRoutineDetector, sha1_binary: bytes) -> None:
        """SHA-1 initialization vectors are detected."""
        detections = detector.detect_all(sha1_binary, base_addr=0x400000)

        sha1_detections = [d for d in detections if d.algorithm == CryptoAlgorithm.SHA1]
        assert len(sha1_detections) >= 1, "Should detect SHA-1 constants"

        detection = sha1_detections[0]
        assert detection.details.get("constants_found", 0) >= 3
        assert detection.confidence >= 0.9

    def test_md5_sine_table_detection(self, detector: CryptographicRoutineDetector, md5_binary: bytes) -> None:
        """MD5 sine table constants are detected."""
        detections = detector.detect_all(md5_binary, base_addr=0x400000)

        md5_detections = [d for d in detections if d.algorithm == CryptoAlgorithm.MD5]
        assert len(md5_detections) >= 1, "Should detect MD5 constants"

        detection = md5_detections[0]
        assert detection.details.get("constants_found", 0) >= 2
        assert detection.confidence >= 0.85

    def test_des_sbox_detection(self, detector: CryptographicRoutineDetector, des_binary_with_sboxes: bytes) -> None:
        """DES S-boxes are detected in binary."""
        detections = detector.detect_all(des_binary_with_sboxes, base_addr=0x400000)

        des_detections = [d for d in detections if d.algorithm in [CryptoAlgorithm.DES, CryptoAlgorithm.TRIPLE_DES]]
        assert len(des_detections) >= 1, "Should detect DES S-boxes"

        detection = des_detections[0]
        assert detection.details.get("sbox_count", 0) >= 4
        assert detection.confidence >= 0.5

    def test_blowfish_pi_subkeys_detection(self, detector: CryptographicRoutineDetector, blowfish_binary: bytes) -> None:
        """Blowfish Pi-based subkeys are detected."""
        detections = detector.detect_all(blowfish_binary, base_addr=0x400000)

        blowfish_detections = [d for d in detections if d.algorithm == CryptoAlgorithm.BLOWFISH]
        assert len(blowfish_detections) >= 1, "Should detect Blowfish constants"

        pi_detections = [d for d in blowfish_detections if "Pi" in d.variant]
        assert len(pi_detections) >= 1
        assert pi_detections[0].confidence >= 0.95

    def test_chacha20_constant_detection(self, detector: CryptographicRoutineDetector, chacha20_binary: bytes) -> None:
        """ChaCha20 'expand 32-byte k' constant is detected."""
        detections = detector.detect_all(chacha20_binary, base_addr=0x400000)

        chacha20_detections = [d for d in detections if d.algorithm == CryptoAlgorithm.CHACHA20]
        assert len(chacha20_detections) >= 1, "Should detect ChaCha20 constant"

        detection = chacha20_detections[0]
        assert detection.details.get("constant") == "expand 32-byte k"
        assert detection.confidence >= 0.95

    def test_rsa_public_exponent_detection(self, detector: CryptographicRoutineDetector, rsa_binary_with_exponent: bytes) -> None:
        """RSA public exponent 65537 is detected."""
        detections = detector.detect_all(rsa_binary_with_exponent, base_addr=0x400000)

        rsa_detections = [d for d in detections if d.algorithm == CryptoAlgorithm.RSA]
        assert len(rsa_detections) >= 1, "Should detect RSA exponent"

        exponent_detections = [d for d in rsa_detections if d.details.get("exponent") == 65537]
        assert len(exponent_detections) >= 1
        assert exponent_detections[0].confidence >= 0.85

    def test_ecc_field_prime_detection(self, detector: CryptographicRoutineDetector, ecc_binary: bytes) -> None:
        """ECC field primes for standard curves are detected."""
        detections = detector.detect_all(ecc_binary, base_addr=0x400000)

        ecc_detections = [d for d in detections if d.algorithm == CryptoAlgorithm.ECC and "Field Prime" in d.variant]
        assert len(ecc_detections) >= 1, "Should detect ECC field prime"

        detection = ecc_detections[0]
        assert detection.details.get("curve") == "secp256k1"
        assert detection.confidence >= 0.95


class TestSboxIdentification:
    """Test S-box identification including fuzzy matching for obfuscated implementations."""

    def test_exact_aes_sbox_match(self, detector: CryptographicRoutineDetector, aes_binary_with_sbox: bytes) -> None:
        """Exact AES S-box is matched with 100% confidence."""
        detections = detector.detect_all(aes_binary_with_sbox, base_addr=0x400000)

        exact_matches = [d for d in detections if d.algorithm == CryptoAlgorithm.AES and d.confidence >= 0.99]
        assert len(exact_matches) >= 1, "Should have exact S-box match"

        detection = exact_matches[0]
        assert detection.details.get("obfuscated") is False or detection.details.get("obfuscated") is None

    def test_obfuscated_aes_sbox_fuzzy_match(self, detector: CryptographicRoutineDetector, obfuscated_aes_sbox: bytes) -> None:
        """Obfuscated AES S-box is detected with fuzzy matching."""
        detections = detector.detect_all(obfuscated_aes_sbox, base_addr=0x400000)

        fuzzy_matches = [d for d in detections if d.algorithm == CryptoAlgorithm.AES and 0.85 <= d.confidence < 0.99]
        assert len(fuzzy_matches) >= 1, "Should detect obfuscated S-box"

        detection = fuzzy_matches[0]
        assert detection.details.get("obfuscated") is True
        assert detection.details.get("completeness", 0) >= 0.85

    def test_inverse_sbox_differentiation(self, detector: CryptographicRoutineDetector) -> None:
        """Forward and inverse S-boxes are differentiated."""
        code = bytearray()
        code.extend(b"\x55\x48\x89\xe5")
        code.extend(CryptographicRoutineDetector.AES_SBOX)
        code.extend(b"\x90" * 64)
        code.extend(CryptographicRoutineDetector.AES_INV_SBOX)
        code.extend(b"\xc9\xc3")

        detections = detector.detect_all(bytes(code), base_addr=0x400000)

        forward_sbox = [d for d in detections if d.details.get("sbox_type") == "forward"]
        inverse_sbox = [d for d in detections if d.details.get("sbox_type") == "inverse"]

        assert len(forward_sbox) >= 1
        assert len(inverse_sbox) >= 1
        assert forward_sbox[0].offset != inverse_sbox[0].offset

    def test_des_multiple_sbox_detection(self, detector: CryptographicRoutineDetector, des_binary_with_sboxes: bytes) -> None:
        """All 8 DES S-boxes are detected."""
        detections = detector.detect_all(des_binary_with_sboxes, base_addr=0x400000)

        des_detections = [d for d in detections if d.algorithm in [CryptoAlgorithm.DES, CryptoAlgorithm.TRIPLE_DES]]
        assert len(des_detections) >= 1

        detection = des_detections[0]
        assert detection.details.get("complete") is True
        assert detection.details.get("sbox_count") == 8

    def test_blowfish_sbox_structure_detection(self, detector: CryptographicRoutineDetector, blowfish_binary: bytes) -> None:
        """Blowfish 4x256 S-box structure is detected."""
        detections = detector.detect_all(blowfish_binary, base_addr=0x400000)

        sbox_detections = [d for d in detections if d.algorithm == CryptoAlgorithm.BLOWFISH and "S-boxes" in d.variant]
        assert len(sbox_detections) >= 1

        detection = sbox_detections[0]
        assert detection.details.get("sbox_structure") == "4x256"
        assert detection.size == 1024


class TestCustomCryptoDetection:
    """Test detection of custom and modified crypto implementations."""

    def test_custom_high_entropy_table_detection(self, detector: CryptographicRoutineDetector, custom_crypto_binary: bytes) -> None:
        """Custom crypto tables are detected via entropy analysis."""
        detections = detector.detect_all(custom_crypto_binary, base_addr=0x400000)

        custom_detections = [d for d in detections if d.algorithm == CryptoAlgorithm.CUSTOM]
        assert len(custom_detections) >= 1, "Should detect custom crypto table"

        table_detections = [d for d in custom_detections if "Table" in d.variant]
        assert len(table_detections) >= 1

        detection = table_detections[0]
        assert detection.details.get("entropy", 0) > 7.5
        assert detection.details.get("structure") == "lookup_table"

    def test_xor_cipher_detection(self, detector: CryptographicRoutineDetector, custom_crypto_binary: bytes) -> None:
        """XOR-based ciphers are detected from instruction patterns."""
        detections = detector.detect_all(custom_crypto_binary, base_addr=0x400000, quick_mode=False)

        xor_detections = [d for d in detections if "XOR" in d.variant]
        assert len(xor_detections) >= 1, "Should detect XOR cipher"

        detection = xor_detections[0]
        assert detection.details.get("xor_operations", 0) >= 8
        assert detection.confidence >= 0.65

    def test_lfsr_cipher_detection(self, detector: CryptographicRoutineDetector) -> None:
        """LFSR-based stream ciphers are detected."""
        code = bytearray()
        code.extend(b"\x55\x48\x89\xe5")

        for _ in range(8):
            code.extend(b"\x8b\x45\xfc")
            code.extend(b"\xd1\xe0")
            code.extend(b"\x33\x45\xf8")
            code.extend(b"\x89\x45\xfc")

        code.extend(b"\xc9\xc3")

        detections = detector.detect_all(bytes(code), base_addr=0x400000, quick_mode=False)

        lfsr_detections = [d for d in detections if "LFSR" in d.variant]
        assert len(lfsr_detections) >= 1, "Should detect LFSR cipher"

        detection = lfsr_detections[0]
        assert detection.details.get("shift_operations", 0) >= 4
        assert detection.details.get("xor_operations", 0) >= 4

    def test_whitebox_crypto_detection(self, detector: CryptographicRoutineDetector, whitebox_aes_binary: bytes) -> None:
        """White-box crypto with encoded tables is detected."""
        detections = detector.detect_all(whitebox_aes_binary, base_addr=0x400000)

        custom_detections = [d for d in detections if d.algorithm == CryptoAlgorithm.CUSTOM]
        assert len(custom_detections) >= 1, "Should detect multiple custom tables for white-box"

    def test_inline_crypto_detection(self, detector: CryptographicRoutineDetector, inline_crypto_binary: bytes) -> None:
        """Inlined crypto operations without lookup tables are detected."""
        detections = detector.detect_all(inline_crypto_binary, base_addr=0x400000, quick_mode=False)

        assert len(detections) >= 1, "Should detect crypto patterns even without tables"


class TestAlgorithmDifferentiation:
    """Test differentiation between hash, cipher, MAC, and other crypto operations."""

    def test_hash_vs_cipher_differentiation(self, detector: CryptographicRoutineDetector, sha256_binary_with_constants: bytes, aes_binary_with_sbox: bytes) -> None:
        """Hash algorithms are differentiated from ciphers."""
        sha_detections = detector.detect_all(sha256_binary_with_constants, base_addr=0x400000)
        aes_detections = detector.detect_all(aes_binary_with_sbox, base_addr=0x400000)

        sha_algos = {d.algorithm for d in sha_detections}
        aes_algos = {d.algorithm for d in aes_detections}

        assert CryptoAlgorithm.SHA256 in sha_algos
        assert CryptoAlgorithm.AES in aes_algos
        assert CryptoAlgorithm.SHA256 not in aes_algos
        assert CryptoAlgorithm.AES not in sha_algos

    def test_symmetric_vs_asymmetric_differentiation(self, detector: CryptographicRoutineDetector, aes_binary_with_sbox: bytes, rsa_binary_with_exponent: bytes) -> None:
        """Symmetric and asymmetric crypto are differentiated."""
        aes_detections = detector.detect_all(aes_binary_with_sbox, base_addr=0x400000)
        rsa_detections = detector.detect_all(rsa_binary_with_exponent, base_addr=0x400000)

        assert any(d.algorithm == CryptoAlgorithm.AES for d in aes_detections)
        assert any(d.algorithm == CryptoAlgorithm.RSA for d in rsa_detections)

    def test_block_cipher_mode_detection(self, detector: CryptographicRoutineDetector, aes_ni_binary: bytes) -> None:
        """Block cipher modes are identified from context."""
        detections = detector.detect_all(aes_ni_binary, base_addr=0x400000)

        aes_detections = [d for d in detections if d.algorithm == CryptoAlgorithm.AES]
        assert len(aes_detections) >= 1

        for detection in aes_detections:
            if detection.mode:
                assert detection.mode in ["Hardware-accelerated", "Hardware (AES-NI)", "Software", "Software (T-tables)"]

    def test_hash_algorithm_differentiation(self, detector: CryptographicRoutineDetector, sha1_binary: bytes, sha256_binary_with_constants: bytes, md5_binary: bytes) -> None:
        """SHA-1, SHA-256, and MD5 are correctly differentiated."""
        sha1_dets = detector.detect_all(sha1_binary, base_addr=0x400000)
        sha256_dets = detector.detect_all(sha256_binary_with_constants, base_addr=0x400000)
        md5_dets = detector.detect_all(md5_binary, base_addr=0x400000)

        assert any(d.algorithm == CryptoAlgorithm.SHA1 for d in sha1_dets)
        assert any(d.algorithm == CryptoAlgorithm.SHA256 for d in sha256_dets)
        assert any(d.algorithm == CryptoAlgorithm.MD5 for d in md5_dets)


class TestKeyDerivationAndRNG:
    """Test identification of key derivation functions and random number generation."""

    def test_rc4_ksa_detection(self, detector: CryptographicRoutineDetector, rc4_binary: bytes) -> None:
        """RC4 Key Scheduling Algorithm is detected."""
        detections = detector.detect_all(rc4_binary, base_addr=0x400000)

        rc4_detections = [d for d in detections if d.algorithm == CryptoAlgorithm.RC4]
        assert len(rc4_detections) >= 1, "Should detect RC4 KSA"

        detection = rc4_detections[0]
        assert detection.details.get("ksa_detected") is True
        assert detection.confidence >= 0.95

    def test_rsa_key_size_estimation(self, detector: CryptographicRoutineDetector, rsa_binary_with_exponent: bytes) -> None:
        """RSA key size is estimated from modulus."""
        detections = detector.detect_all(rsa_binary_with_exponent, base_addr=0x400000)

        rsa_detections = [d for d in detections if d.algorithm == CryptoAlgorithm.RSA]

        key_size_detections = [d for d in rsa_detections if d.key_size is not None]
        if key_size_detections:
            assert key_size_detections[0].key_size >= 1024


class TestEdgeCases:
    """Test edge cases: inline crypto, SIMD implementations, white-box crypto."""

    def test_inline_crypto_without_tables(self, detector: CryptographicRoutineDetector, inline_crypto_binary: bytes) -> None:
        """Inline crypto operations are detected without separate lookup tables."""
        detections = detector.detect_all(inline_crypto_binary, base_addr=0x400000, quick_mode=False)

        assert len(detections) >= 1, "Should detect crypto even when inlined"

    def test_simd_optimized_crypto(self, detector: CryptographicRoutineDetector, simd_aes_binary: bytes) -> None:
        """SIMD-optimized crypto implementations are detected."""
        detections = detector.detect_all(simd_aes_binary, base_addr=0x400000)

        aes_detections = [d for d in detections if d.algorithm == CryptoAlgorithm.AES]
        assert len(aes_detections) >= 1, "Should detect AES in SIMD code"

    def test_whitebox_crypto_multiple_tables(self, detector: CryptographicRoutineDetector, whitebox_aes_binary: bytes) -> None:
        """White-box crypto with multiple encoded tables is detected."""
        detections = detector.detect_all(whitebox_aes_binary, base_addr=0x400000)

        custom_detections = [d for d in detections if d.algorithm == CryptoAlgorithm.CUSTOM]
        assert len(custom_detections) >= 1, "Should detect white-box tables"

    def test_empty_binary(self, detector: CryptographicRoutineDetector) -> None:
        """Empty binary produces no detections."""
        detections = detector.detect_all(b"", base_addr=0x400000)
        assert len(detections) == 0

    def test_non_crypto_binary(self, detector: CryptographicRoutineDetector) -> None:
        """Non-crypto binary produces no false positives."""
        code = bytearray()
        code.extend(b"\x55\x48\x89\xe5")
        code.extend(b"\x48\x83\xec\x10")
        code.extend(b"\x48\x89\x7d\xf8")
        code.extend(b"\x48\x8b\x45\xf8")
        code.extend(b"\x48\x83\xc0\x01")
        code.extend(b"\xc9\xc3")

        detections = detector.detect_all(bytes(code), base_addr=0x400000)

        high_confidence_detections = [d for d in detections if d.confidence >= 0.8]
        assert len(high_confidence_detections) == 0, "Should not detect crypto in simple code"

    def test_corrupted_sbox(self, detector: CryptographicRoutineDetector) -> None:
        """Heavily corrupted S-box is not detected."""
        corrupted = bytes([secrets.randbelow(256) for _ in range(256)])

        code = bytearray()
        code.extend(b"\x55\x48\x89\xe5")
        code.extend(corrupted)
        code.extend(b"\xc9\xc3")

        detections = detector.detect_all(bytes(code), base_addr=0x400000)

        aes_sbox_detections = [d for d in detections if d.algorithm == CryptoAlgorithm.AES and "S-box" in d.variant]
        assert len(aes_sbox_detections) == 0, "Should not detect completely corrupted S-box"

    def test_mixed_crypto_algorithms(self, detector: CryptographicRoutineDetector) -> None:
        """Multiple crypto algorithms in same binary are all detected."""
        code = bytearray()
        code.extend(b"\x55\x48\x89\xe5")
        code.extend(CryptographicRoutineDetector.AES_SBOX)
        code.extend(b"\x90" * 64)

        for h in [0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0]:
            code.extend(struct.pack(">I", h))

        code.extend(b"\x90" * 64)
        code.extend(b"\x01\x00\x01\x00")
        code.extend(b"\xc9\xc3")

        detections = detector.detect_all(bytes(code), base_addr=0x400000)

        algorithms = {d.algorithm for d in detections}
        assert CryptoAlgorithm.AES in algorithms
        assert CryptoAlgorithm.SHA1 in algorithms
        assert CryptoAlgorithm.RSA in algorithms


class TestAnalysisReporting:
    """Test crypto usage analysis and reporting functionality."""

    def test_analyze_crypto_usage(self, detector: CryptographicRoutineDetector, aes_binary_with_sbox: bytes) -> None:
        """Crypto usage analysis provides accurate statistics."""
        detections = detector.detect_all(aes_binary_with_sbox, base_addr=0x400000)

        analysis = detector.analyze_crypto_usage(detections)

        assert analysis["total_detections"] == len(detections)
        assert analysis["unique_algorithms"] >= 1
        assert "algorithms" in analysis
        assert isinstance(analysis["algorithms"], dict)
        assert analysis["protection_likelihood"] >= 0.0

    def test_protection_likelihood_scoring(self, detector: CryptographicRoutineDetector, obfuscated_aes_sbox: bytes) -> None:
        """Protection likelihood is scored based on obfuscation."""
        detections = detector.detect_all(obfuscated_aes_sbox, base_addr=0x400000)

        analysis = detector.analyze_crypto_usage(detections)

        if analysis["obfuscated_crypto"]:
            assert analysis["protection_likelihood"] >= 0.85

    def test_yara_rule_generation(self, detector: CryptographicRoutineDetector, aes_binary_with_sbox: bytes) -> None:
        """YARA rules are generated from detections."""
        detections = detector.detect_all(aes_binary_with_sbox, base_addr=0x400000)

        yara_rules = detector.export_yara_rules(detections)

        assert isinstance(yara_rules, str)
        assert len(yara_rules) > 0

        if any(d.algorithm == CryptoAlgorithm.AES for d in detections):
            assert "rule AES_Crypto_Detection" in yara_rules
            assert "meta:" in yara_rules
            assert "strings:" in yara_rules
            assert "condition:" in yara_rules


class TestFailureConditions:
    """Test that detection fails appropriately when crypto is not present."""

    def test_no_crypto_returns_empty(self, detector: CryptographicRoutineDetector) -> None:
        """Binary without crypto returns empty detections."""
        code = b"\x55\x48\x89\xe5\x48\x83\xec\x10\xc9\xc3"

        detections = detector.detect_all(code, base_addr=0x400000)

        high_confidence = [d for d in detections if d.confidence >= 0.8]
        assert len(high_confidence) == 0

    def test_string_only_checking_fails(self, detector: CryptographicRoutineDetector) -> None:
        """String-only detection would fail without instruction analysis."""
        code = bytearray()
        code.extend(b"\x55\x48\x89\xe5")

        aes_string = b"AES"
        sha_string = b"SHA256"
        code.extend(aes_string)
        code.extend(b"\x90" * 64)
        code.extend(sha_string)
        code.extend(b"\xc9\xc3")

        detections = detector.detect_all(bytes(code), base_addr=0x400000)

        aes_detections = [d for d in detections if d.algorithm == CryptoAlgorithm.AES and d.confidence >= 0.8]
        sha_detections = [d for d in detections if d.algorithm == CryptoAlgorithm.SHA256 and d.confidence >= 0.8]

        assert len(aes_detections) == 0, "String 'AES' should not trigger detection"
        assert len(sha_detections) == 0, "String 'SHA256' should not trigger detection"

    def test_import_only_checking_fails(self, detector: CryptographicRoutineDetector) -> None:
        """Import table references without implementation should not detect crypto."""
        code = bytearray()
        code.extend(b"\x55\x48\x89\xe5")

        import_names = b"CryptEncrypt\x00CryptDecrypt\x00AES_set_encrypt_key\x00"
        code.extend(import_names)
        code.extend(b"\xc9\xc3")

        detections = detector.detect_all(bytes(code), base_addr=0x400000)

        high_confidence_detections = [d for d in detections if d.confidence >= 0.8]
        assert len(high_confidence_detections) == 0, "Import names should not trigger detection without constants/instructions"

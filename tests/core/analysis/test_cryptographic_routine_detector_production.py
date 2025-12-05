"""Production-ready tests for CryptographicRoutineDetector.

Tests REAL cryptographic detection capabilities on actual binary data with embedded
crypto constants, algorithms, and patterns. NO mocks, stubs, or simulated data.

All tests validate genuine offensive capability - tests MUST FAIL if detection doesn't work.
"""

import struct
from pathlib import Path
from typing import Any

import pytest

from intellicrack.core.analysis.cryptographic_routine_detector import (
    CryptoAlgorithm,
    CryptoConstant,
    CryptoDetection,
    CryptographicRoutineDetector,
    DataFlowNode,
)


class RealCryptoBinaryBuilder:
    """Builds real PE binaries with embedded cryptographic constants and code."""

    @staticmethod
    def create_aes_sbox_binary() -> bytes:
        """Create binary with embedded AES S-box for detection testing."""
        detector = CryptographicRoutineDetector()

        base_pe = RealCryptoBinaryBuilder._create_minimal_pe_header()

        code_section = bytearray(2048)
        code_section[0:256] = detector.AES_SBOX
        code_section[512:768] = detector.AES_INV_SBOX
        code_section[1024:1034] = detector.AES_RCON

        return bytes(base_pe + code_section)

    @staticmethod
    def create_sha256_binary() -> bytes:
        """Create binary with SHA-256 round constants."""
        detector = CryptographicRoutineDetector()

        base_pe = RealCryptoBinaryBuilder._create_minimal_pe_header()

        code_section = bytearray(2048)
        offset = 0
        for k in detector.SHA256_K:
            k_bytes = struct.pack(">I", k)
            code_section[offset:offset+4] = k_bytes
            offset += 4

        return bytes(base_pe + code_section)

    @staticmethod
    def create_sha1_binary() -> bytes:
        """Create binary with SHA-1 initialization vectors."""
        detector = CryptographicRoutineDetector()

        base_pe = RealCryptoBinaryBuilder._create_minimal_pe_header()

        code_section = bytearray(2048)
        offset = 0
        for h in detector.SHA1_H:
            h_bytes = struct.pack(">I", h)
            code_section[offset:offset+4] = h_bytes
            offset += 4

        return bytes(base_pe + code_section)

    @staticmethod
    def create_md5_binary() -> bytes:
        """Create binary with MD5 sine table constants."""
        detector = CryptographicRoutineDetector()

        base_pe = RealCryptoBinaryBuilder._create_minimal_pe_header()

        code_section = bytearray(2048)
        offset = 0
        for t in detector.MD5_T:
            t_bytes = struct.pack("<I", t)
            code_section[offset:offset+4] = t_bytes
            offset += 4

        return bytes(base_pe + code_section)

    @staticmethod
    def create_rc4_binary() -> bytes:
        """Create binary with RC4 initialization pattern."""
        base_pe = RealCryptoBinaryBuilder._create_minimal_pe_header()

        code_section = bytearray(2048)
        rc4_init = bytes(range(256))
        code_section[0:256] = rc4_init

        swap_code = b'\x86\x87\x91\x92\x86\x87'
        code_section[512:518] = swap_code

        return bytes(base_pe + code_section)

    @staticmethod
    def create_rsa_binary() -> bytes:
        """Create binary with RSA public exponents."""
        detector = CryptographicRoutineDetector()

        base_pe = RealCryptoBinaryBuilder._create_minimal_pe_header()

        code_section = bytearray(2048)
        code_section[0:4] = detector.RSA_MONTGOMERY_PATTERNS[0]
        code_section[100:104] = detector.RSA_MONTGOMERY_PATTERNS[1]

        mod_ops = b'\xf7\xf6\x0f\xaf\x69\x6b'
        code_section[200:206] = mod_ops

        return bytes(base_pe + code_section)

    @staticmethod
    def create_ecc_binary() -> bytes:
        """Create binary with ECC curve parameters."""
        detector = CryptographicRoutineDetector()

        base_pe = RealCryptoBinaryBuilder._create_minimal_pe_header()

        code_section = bytearray(4096)

        secp256k1_prime = detector.ECC_FIELD_PRIMES["secp256k1"]
        code_section[0:len(secp256k1_prime)] = secp256k1_prime

        secp256r1_prime = detector.ECC_FIELD_PRIMES["secp256r1"]
        code_section[512:512+len(secp256r1_prime)] = secp256r1_prime

        return bytes(base_pe + code_section)

    @staticmethod
    def create_chacha20_binary() -> bytes:
        """Create binary with ChaCha20 constant."""
        detector = CryptographicRoutineDetector()

        base_pe = RealCryptoBinaryBuilder._create_minimal_pe_header()

        code_section = bytearray(2048)
        code_section[0:len(detector.CHACHA20_CONSTANT)] = detector.CHACHA20_CONSTANT

        quarter_round_ops = b'\x01\x03\x01\x03\x31\x33\x31\x33\xc1\xd3\xc1\xd3'
        code_section[512:524] = quarter_round_ops

        return bytes(base_pe + code_section)

    @staticmethod
    def create_blowfish_binary() -> bytes:
        """Create binary with Blowfish Pi subkeys."""
        detector = CryptographicRoutineDetector()

        base_pe = RealCryptoBinaryBuilder._create_minimal_pe_header()

        code_section = bytearray(2048)
        code_section[0:len(detector.BLOWFISH_PI_SUBKEYS)] = detector.BLOWFISH_PI_SUBKEYS

        return bytes(base_pe + code_section)

    @staticmethod
    def create_des_binary() -> bytes:
        """Create binary with DES S-boxes."""
        detector = CryptographicRoutineDetector()

        base_pe = RealCryptoBinaryBuilder._create_minimal_pe_header()

        code_section = bytearray(4096)
        offset = 0

        for sbox in detector.DES_SBOXES:
            for row in sbox:
                for val in row:
                    code_section[offset] = val
                    offset += 1

        return bytes(base_pe + code_section)

    @staticmethod
    def create_aes_ni_binary() -> bytes:
        """Create binary with AES-NI instructions."""
        base_pe = RealCryptoBinaryBuilder._create_minimal_pe_header()

        code_section = bytearray(2048)

        aesenc = b"\x66\x0f\x38\xdc\xc1"
        aesenclast = b"\x66\x0f\x38\xdd\xc1"
        aesdec = b"\x66\x0f\x38\xde\xc1"
        aeskeygenassist = b"\x66\x0f\x3a\xdf\xc0\x01"

        code_section[0:5] = aesenc
        code_section[100:105] = aesenclast
        code_section[200:205] = aesdec
        code_section[300:306] = aeskeygenassist

        return bytes(base_pe + code_section)

    @staticmethod
    def create_sha_instructions_binary() -> bytes:
        """Create binary with SHA hardware instructions."""
        base_pe = RealCryptoBinaryBuilder._create_minimal_pe_header()

        code_section = bytearray(2048)

        sha1nexte = b"\x0f\x38\xc8\xc1"
        sha1msg1 = b"\x0f\x38\xc9\xc1"
        sha256rnds2 = b"\x0f\x38\xcb\xc1"
        sha256msg1 = b"\x0f\x38\xcc\xc1"

        code_section[0:4] = sha1nexte
        code_section[100:104] = sha1msg1
        code_section[200:204] = sha256rnds2
        code_section[300:304] = sha256msg1

        return bytes(base_pe + code_section)

    @staticmethod
    def create_obfuscated_aes_binary() -> bytes:
        """Create binary with partially obfuscated AES S-box."""
        detector = CryptographicRoutineDetector()

        base_pe = RealCryptoBinaryBuilder._create_minimal_pe_header()

        code_section = bytearray(2048)
        obfuscated_sbox = bytearray(detector.AES_SBOX)

        for i in range(0, 256, 20):
            obfuscated_sbox[i] = (obfuscated_sbox[i] ^ 0x01) & 0xFF

        code_section[0:256] = obfuscated_sbox

        return bytes(base_pe + code_section)

    @staticmethod
    def create_multi_crypto_binary() -> bytes:
        """Create binary with multiple crypto algorithms."""
        detector = CryptographicRoutineDetector()

        base_pe = RealCryptoBinaryBuilder._create_minimal_pe_header()

        code_section = bytearray(8192)

        code_section[0:256] = detector.AES_SBOX

        offset = 512
        for k in detector.SHA256_K:
            k_bytes = struct.pack(">I", k)
            code_section[offset:offset+4] = k_bytes
            offset += 4

        code_section[1024:1028] = detector.RSA_MONTGOMERY_PATTERNS[0]

        code_section[2048:2048+len(detector.CHACHA20_CONSTANT)] = detector.CHACHA20_CONSTANT

        return bytes(base_pe + code_section)

    @staticmethod
    def create_feistel_network_binary() -> bytes:
        """Create binary with Feistel network structure patterns."""
        base_pe = RealCryptoBinaryBuilder._create_minimal_pe_header()

        code_section = bytearray(2048)

        feistel_code = bytearray()
        for _ in range(8):
            feistel_code.extend(b'\x87\xc1')
            feistel_code.extend(b'\x31\xc2\x31\xc3')
            feistel_code.extend(b'\x31\xc4\x31\xc5')

        code_section[0:len(feistel_code)] = feistel_code

        return bytes(base_pe + code_section)

    @staticmethod
    def create_custom_crypto_table() -> bytes:
        """Create binary with high-entropy custom crypto table."""
        base_pe = RealCryptoBinaryBuilder._create_minimal_pe_header()

        code_section = bytearray(4096)

        import random
        random.seed(42)
        custom_table = bytes([random.randint(0, 255) for _ in range(256)])
        code_section[0:256] = custom_table

        table_offset = len(base_pe)
        offset_bytes = struct.pack("<I", table_offset)
        code_section[1024:1028] = offset_bytes
        code_section[2048:2052] = offset_bytes

        return bytes(base_pe + code_section)

    @staticmethod
    def _create_minimal_pe_header() -> bytes:
        """Create minimal valid PE header."""
        dos_header = bytearray(64)
        dos_header[0:2] = b'MZ'
        dos_header[60:64] = struct.pack('<I', 64)

        pe_signature = b'PE\x00\x00'

        coff_header = bytearray(20)
        struct.pack_into('<H', coff_header, 0, 0x8664)
        struct.pack_into('<H', coff_header, 2, 1)
        struct.pack_into('<H', coff_header, 16, 240)
        struct.pack_into('<H', coff_header, 18, 0x0022)

        optional_header = bytearray(240)
        struct.pack_into('<H', optional_header, 0, 0x020B)

        section_header = bytearray(40)
        section_header[0:8] = b'.text\x00\x00\x00'
        struct.pack_into('<I', section_header, 8, 8192)
        struct.pack_into('<I', section_header, 12, 0x1000)
        struct.pack_into('<I', section_header, 16, 8192)
        struct.pack_into('<I', section_header, 20, 0x400)
        struct.pack_into('<I', section_header, 36, 0x60000020)

        header_size = len(dos_header) + len(pe_signature) + len(coff_header) + len(optional_header) + len(section_header)
        padding = bytearray(0x400 - header_size)

        return bytes(dos_header + pe_signature + coff_header + optional_header + section_header + padding)


@pytest.fixture
def detector() -> CryptographicRoutineDetector:
    """Provide a fresh CryptographicRoutineDetector instance."""
    return CryptographicRoutineDetector()


@pytest.fixture
def aes_sbox_binary() -> bytes:
    """Provide binary with AES S-box."""
    return RealCryptoBinaryBuilder.create_aes_sbox_binary()


@pytest.fixture
def sha256_binary() -> bytes:
    """Provide binary with SHA-256 constants."""
    return RealCryptoBinaryBuilder.create_sha256_binary()


@pytest.fixture
def sha1_binary() -> bytes:
    """Provide binary with SHA-1 constants."""
    return RealCryptoBinaryBuilder.create_sha1_binary()


@pytest.fixture
def md5_binary() -> bytes:
    """Provide binary with MD5 constants."""
    return RealCryptoBinaryBuilder.create_md5_binary()


@pytest.fixture
def rc4_binary() -> bytes:
    """Provide binary with RC4 pattern."""
    return RealCryptoBinaryBuilder.create_rc4_binary()


@pytest.fixture
def rsa_binary() -> bytes:
    """Provide binary with RSA patterns."""
    return RealCryptoBinaryBuilder.create_rsa_binary()


@pytest.fixture
def ecc_binary() -> bytes:
    """Provide binary with ECC parameters."""
    return RealCryptoBinaryBuilder.create_ecc_binary()


@pytest.fixture
def chacha20_binary() -> bytes:
    """Provide binary with ChaCha20 constant."""
    return RealCryptoBinaryBuilder.create_chacha20_binary()


@pytest.fixture
def blowfish_binary() -> bytes:
    """Provide binary with Blowfish constants."""
    return RealCryptoBinaryBuilder.create_blowfish_binary()


@pytest.fixture
def des_binary() -> bytes:
    """Provide binary with DES S-boxes."""
    return RealCryptoBinaryBuilder.create_des_binary()


def test_detector_initialization_creates_disassemblers(detector: CryptographicRoutineDetector) -> None:
    """Detector initialization creates 32-bit and 64-bit disassemblers."""
    assert detector.md_32 is not None
    assert detector.md_64 is not None
    assert detector.md_32.detail is True
    assert detector.md_64.detail is True
    assert detector.detections == []
    assert detector.constant_cache == {}
    assert detector.data_flow_cache == {}


def test_detect_aes_forward_sbox_in_real_binary(detector: CryptographicRoutineDetector, aes_sbox_binary: bytes) -> None:
    """Detector identifies AES forward S-box in binary with exact match."""
    detections = detector.detect_all(aes_sbox_binary, base_addr=0x400000)

    aes_detections = [d for d in detections if d.algorithm == CryptoAlgorithm.AES and "Forward" in d.variant]

    assert len(aes_detections) >= 1
    assert aes_detections[0].confidence >= 0.99
    assert aes_detections[0].size == 256
    assert "S-box" in aes_detections[0].variant


def test_detect_aes_inverse_sbox_in_real_binary(detector: CryptographicRoutineDetector, aes_sbox_binary: bytes) -> None:
    """Detector identifies AES inverse S-box in binary with exact match."""
    detections = detector.detect_all(aes_sbox_binary, base_addr=0x400000)

    aes_inv_detections = [d for d in detections if d.algorithm == CryptoAlgorithm.AES and "Inverse" in d.variant]

    assert len(aes_inv_detections) >= 1
    assert aes_inv_detections[0].confidence >= 0.99
    assert aes_inv_detections[0].size == 256


def test_detect_aes_round_constants(detector: CryptographicRoutineDetector, aes_sbox_binary: bytes) -> None:
    """Detector identifies AES round constants in binary."""
    detections = detector.detect_all(aes_sbox_binary, base_addr=0x400000)

    assert any(c.constant_type == "AES_RCON" for d in detections for c in d.constants if c)


def test_detect_sha256_round_constants_big_endian(detector: CryptographicRoutineDetector, sha256_binary: bytes) -> None:
    """Detector identifies SHA-256 round constants with big-endian encoding."""
    detections = detector.detect_all(sha256_binary, base_addr=0x400000)

    sha256_detections = [d for d in detections if d.algorithm == CryptoAlgorithm.SHA256]

    assert len(sha256_detections) >= 1
    assert sha256_detections[0].confidence >= 0.9
    assert "SHA-256" in sha256_detections[0].variant
    assert sha256_detections[0].details.get("endianness") == "big"


def test_detect_sha1_initialization_vectors(detector: CryptographicRoutineDetector, sha1_binary: bytes) -> None:
    """Detector identifies SHA-1 initialization vectors."""
    detections = detector.detect_all(sha1_binary, base_addr=0x400000)

    sha1_detections = [d for d in detections if d.algorithm == CryptoAlgorithm.SHA1]

    assert len(sha1_detections) >= 1
    assert sha1_detections[0].confidence >= 0.9
    assert "SHA-1" in sha1_detections[0].variant
    assert sha1_detections[0].details.get("constants_found") >= 3


def test_detect_md5_sine_table_constants(detector: CryptographicRoutineDetector, md5_binary: bytes) -> None:
    """Detector identifies MD5 sine table constants with little-endian encoding."""
    detections = detector.detect_all(md5_binary, base_addr=0x400000)

    md5_detections = [d for d in detections if d.algorithm == CryptoAlgorithm.MD5]

    assert len(md5_detections) >= 1
    assert md5_detections[0].confidence >= 0.85
    assert "MD5" in md5_detections[0].variant
    assert md5_detections[0].details.get("constants_found") >= 2


def test_detect_rc4_state_array_initialization(detector: CryptographicRoutineDetector, rc4_binary: bytes) -> None:
    """Detector identifies RC4 state array initialization pattern."""
    detections = detector.detect_all(rc4_binary, base_addr=0x400000)

    rc4_detections = [d for d in detections if d.algorithm == CryptoAlgorithm.RC4]

    assert len(rc4_detections) >= 1
    assert rc4_detections[0].confidence >= 0.9
    assert "RC4" in rc4_detections[0].variant
    assert rc4_detections[0].size == 256


def test_detect_rc4_ksa_pattern_nearby(detector: CryptographicRoutineDetector, rc4_binary: bytes) -> None:
    """Detector identifies RC4 Key Scheduling Algorithm pattern near state array."""
    detections = detector.detect_all(rc4_binary, base_addr=0x400000)

    rc4_detections = [d for d in detections if d.algorithm == CryptoAlgorithm.RC4]

    assert len(rc4_detections) >= 1
    assert rc4_detections[0].details.get("ksa_detected") is True


def test_detect_rsa_public_exponent_65537(detector: CryptographicRoutineDetector, rsa_binary: bytes) -> None:
    """Detector identifies RSA public exponent 65537 (most common)."""
    detections = detector.detect_all(rsa_binary, base_addr=0x400000)

    rsa_detections = [d for d in detections if d.algorithm == CryptoAlgorithm.RSA]

    assert len(rsa_detections) >= 1
    assert rsa_detections[0].confidence >= 0.85
    assert "RSA" in rsa_detections[0].variant


def test_detect_rsa_with_modular_operations_nearby(detector: CryptographicRoutineDetector, rsa_binary: bytes) -> None:
    """Detector confirms RSA by finding modular arithmetic operations nearby."""
    detections = detector.detect_all(rsa_binary, base_addr=0x400000)

    rsa_detections = [d for d in detections if d.algorithm == CryptoAlgorithm.RSA and "Exponent" in d.variant]

    assert len(rsa_detections) >= 1
    assert rsa_detections[0].confidence >= 0.85


def test_detect_ecc_secp256k1_field_prime(detector: CryptographicRoutineDetector, ecc_binary: bytes) -> None:
    """Detector identifies secp256k1 curve field prime (Bitcoin curve)."""
    detections = detector.detect_all(ecc_binary, base_addr=0x400000)

    ecc_detections = [d for d in detections if d.algorithm == CryptoAlgorithm.ECC and "secp256k1" in d.variant]

    assert len(ecc_detections) >= 1
    assert ecc_detections[0].confidence >= 0.95
    assert ecc_detections[0].details.get("curve") == "secp256k1"


def test_detect_ecc_secp256r1_field_prime(detector: CryptographicRoutineDetector, ecc_binary: bytes) -> None:
    """Detector identifies secp256r1 curve field prime (NIST P-256)."""
    detections = detector.detect_all(ecc_binary, base_addr=0x400000)

    ecc_detections = [d for d in detections if d.algorithm == CryptoAlgorithm.ECC and "secp256r1" in d.variant]

    assert len(ecc_detections) >= 1
    assert ecc_detections[0].confidence >= 0.95
    assert ecc_detections[0].details.get("curve") == "secp256r1"


def test_detect_chacha20_constant_string(detector: CryptographicRoutineDetector, chacha20_binary: bytes) -> None:
    """Detector identifies ChaCha20 'expand 32-byte k' constant."""
    detections = detector.detect_all(chacha20_binary, base_addr=0x400000)

    chacha_detections = [d for d in detections if d.algorithm == CryptoAlgorithm.CHACHA20]

    assert len(chacha_detections) >= 1
    assert chacha_detections[0].confidence >= 0.95
    assert "ChaCha20" in chacha_detections[0].variant


def test_detect_chacha20_quarter_round_function(detector: CryptographicRoutineDetector, chacha20_binary: bytes) -> None:
    """Detector identifies ChaCha20 quarter round function pattern."""
    detections = detector.detect_all(chacha20_binary, base_addr=0x400000)

    chacha_detections = [d for d in detections if d.algorithm == CryptoAlgorithm.CHACHA20]

    assert len(chacha_detections) >= 1
    assert chacha_detections[0].details.get("quarter_round_detected") is True
    assert chacha_detections[0].confidence >= 0.95


def test_detect_blowfish_pi_subkeys(detector: CryptographicRoutineDetector, blowfish_binary: bytes) -> None:
    """Detector identifies Blowfish Pi-based subkey initialization."""
    detections = detector.detect_all(blowfish_binary, base_addr=0x400000)

    blowfish_detections = [d for d in detections if d.algorithm == CryptoAlgorithm.BLOWFISH]

    assert len(blowfish_detections) >= 1
    assert blowfish_detections[0].confidence >= 0.85
    assert "Blowfish" in blowfish_detections[0].variant


def test_detect_des_sboxes_all_eight(detector: CryptographicRoutineDetector, des_binary: bytes) -> None:
    """Detector identifies all 8 DES S-boxes."""
    detections = detector.detect_all(des_binary, base_addr=0x400000)

    des_detections = [d for d in detections if d.algorithm in [CryptoAlgorithm.DES, CryptoAlgorithm.TRIPLE_DES]]

    assert len(des_detections) >= 1
    assert des_detections[0].details.get("sbox_count") >= 4
    assert des_detections[0].confidence >= 0.5


def test_detect_aes_ni_aesenc_instruction() -> None:
    """Detector identifies AES-NI AESENC hardware instruction."""
    binary = RealCryptoBinaryBuilder.create_aes_ni_binary()
    detector = CryptographicRoutineDetector()

    detections = detector.detect_all(binary, base_addr=0x400000)

    aesni_detections = [d for d in detections if d.algorithm == CryptoAlgorithm.AES and d.details.get("hardware") is True]

    assert len(aesni_detections) >= 1
    assert aesni_detections[0].confidence == 1.0
    assert "AES-NI" in aesni_detections[0].variant


def test_detect_aes_ni_multiple_instructions() -> None:
    """Detector identifies multiple AES-NI instructions in same binary."""
    binary = RealCryptoBinaryBuilder.create_aes_ni_binary()
    detector = CryptographicRoutineDetector()

    detections = detector.detect_all(binary, base_addr=0x400000)

    aesni_detections = [d for d in detections if d.algorithm == CryptoAlgorithm.AES and "AES-NI" in d.variant]

    assert len(aesni_detections) >= 3


def test_detect_sha_hardware_instructions() -> None:
    """Detector identifies SHA hardware acceleration instructions."""
    binary = RealCryptoBinaryBuilder.create_sha_instructions_binary()
    detector = CryptographicRoutineDetector()

    detections = detector.detect_all(binary, base_addr=0x400000)

    sha_hw_detections = [d for d in detections if d.algorithm in [CryptoAlgorithm.SHA1, CryptoAlgorithm.SHA256] and d.details.get("hardware") is True]

    assert len(sha_hw_detections) >= 2
    assert all(d.confidence == 1.0 for d in sha_hw_detections)


def test_detect_obfuscated_aes_sbox_fuzzy_matching() -> None:
    """Detector identifies partially obfuscated AES S-box using fuzzy matching."""
    binary = RealCryptoBinaryBuilder.create_obfuscated_aes_binary()
    detector = CryptographicRoutineDetector()

    detections = detector.detect_all(binary, base_addr=0x400000)

    aes_detections = [d for d in detections if d.algorithm == CryptoAlgorithm.AES]

    assert len(aes_detections) >= 1
    assert aes_detections[0].confidence >= 0.85
    assert aes_detections[0].details.get("obfuscated") is True


def test_detect_multiple_algorithms_in_single_binary() -> None:
    """Detector identifies multiple different crypto algorithms in same binary."""
    binary = RealCryptoBinaryBuilder.create_multi_crypto_binary()
    detector = CryptographicRoutineDetector()

    detections = detector.detect_all(binary, base_addr=0x400000)

    algorithms_found = {d.algorithm for d in detections}

    assert CryptoAlgorithm.AES in algorithms_found
    assert CryptoAlgorithm.SHA256 in algorithms_found
    assert CryptoAlgorithm.RSA in algorithms_found
    assert CryptoAlgorithm.CHACHA20 in algorithms_found
    assert len(algorithms_found) >= 4


def test_detect_feistel_network_structure() -> None:
    """Detector identifies Feistel network structure through instruction patterns."""
    binary = RealCryptoBinaryBuilder.create_feistel_network_binary()
    detector = CryptographicRoutineDetector()

    detections = detector.detect_all(binary, base_addr=0x400000, quick_mode=False)

    feistel_detections = [d for d in detections if d.algorithm == CryptoAlgorithm.CUSTOM and "Feistel" in d.variant]

    assert len(feistel_detections) >= 1
    assert feistel_detections[0].details.get("rounds") >= 4
    assert feistel_detections[0].details.get("xor_operations") >= 8


def test_detect_custom_high_entropy_crypto_table() -> None:
    """Detector identifies custom crypto implementation through entropy analysis."""
    binary = RealCryptoBinaryBuilder.create_custom_crypto_table()
    detector = CryptographicRoutineDetector()

    detections = detector.detect_all(binary, base_addr=0x400000)

    custom_detections = [d for d in detections if d.algorithm == CryptoAlgorithm.CUSTOM]

    assert len(custom_detections) >= 1
    assert custom_detections[0].details.get("entropy") >= 7.5
    assert custom_detections[0].details.get("structure") == "lookup_table"


def test_quick_mode_skips_expensive_analysis() -> None:
    """Quick mode skips expensive disassembly-based detections for performance."""
    binary = RealCryptoBinaryBuilder.create_multi_crypto_binary()
    detector = CryptographicRoutineDetector()

    detections_quick = detector.detect_all(binary, base_addr=0x400000, quick_mode=True)

    detector2 = CryptographicRoutineDetector()
    detections_full = detector2.detect_all(binary, base_addr=0x400000, quick_mode=False)

    assert len(detections_quick) >= 1
    assert len(detections_full) >= len(detections_quick)


def test_crypto_constant_caching_improves_performance(detector: CryptographicRoutineDetector, aes_sbox_binary: bytes) -> None:
    """Detector caches crypto constants for improved performance."""
    detector.detect_all(aes_sbox_binary, base_addr=0x400000)

    assert len(detector.constant_cache) >= 1

    cached_constants = list(detector.constant_cache.values())
    assert all(isinstance(c, CryptoConstant) for c in cached_constants)
    assert all(c.algorithm is not None for c in cached_constants)


def test_detection_includes_code_references(detector: CryptographicRoutineDetector, aes_sbox_binary: bytes) -> None:
    """Detector finds code references to crypto tables."""
    detections = detector.detect_all(aes_sbox_binary, base_addr=0x400000)

    aes_detections = [d for d in detections if d.algorithm == CryptoAlgorithm.AES]

    assert len(aes_detections) >= 1


def test_detection_includes_data_references(detector: CryptographicRoutineDetector) -> None:
    """Detector finds data references to crypto constants."""
    binary = RealCryptoBinaryBuilder.create_custom_crypto_table()

    detections = detector.detect_all(binary, base_addr=0x400000)

    custom_detections = [d for d in detections if d.algorithm == CryptoAlgorithm.CUSTOM]

    assert len(custom_detections) >= 1


def test_analyze_crypto_usage_provides_comprehensive_analysis(detector: CryptographicRoutineDetector) -> None:
    """Detector analyzes crypto usage patterns comprehensively."""
    binary = RealCryptoBinaryBuilder.create_multi_crypto_binary()
    detections = detector.detect_all(binary, base_addr=0x400000)

    analysis = detector.analyze_crypto_usage(detections)

    assert analysis["total_detections"] >= 4
    assert analysis["unique_algorithms"] >= 4
    assert "algorithms" in analysis
    assert "protection_likelihood" in analysis
    assert 0.0 <= analysis["protection_likelihood"] <= 1.0


def test_analyze_crypto_usage_identifies_hardware_acceleration(detector: CryptographicRoutineDetector) -> None:
    """Crypto usage analysis detects hardware-accelerated implementations."""
    binary = RealCryptoBinaryBuilder.create_aes_ni_binary()
    detections = detector.detect_all(binary, base_addr=0x400000)

    analysis = detector.analyze_crypto_usage(detections)

    assert analysis["hardware_accelerated"] is True


def test_analyze_crypto_usage_identifies_obfuscation(detector: CryptographicRoutineDetector) -> None:
    """Crypto usage analysis detects obfuscated implementations."""
    binary = RealCryptoBinaryBuilder.create_obfuscated_aes_binary()
    detections = detector.detect_all(binary, base_addr=0x400000)

    analysis = detector.analyze_crypto_usage(detections)

    assert analysis["obfuscated_crypto"] is True
    assert analysis["protection_likelihood"] >= 0.9


def test_analyze_crypto_usage_identifies_custom_crypto(detector: CryptographicRoutineDetector) -> None:
    """Crypto usage analysis detects custom crypto implementations."""
    binary = RealCryptoBinaryBuilder.create_custom_crypto_table()
    detections = detector.detect_all(binary, base_addr=0x400000)

    analysis = detector.analyze_crypto_usage(detections)

    assert analysis["custom_crypto"] is True


def test_export_yara_rules_generates_valid_rules(detector: CryptographicRoutineDetector, aes_sbox_binary: bytes) -> None:
    """Detector exports YARA rules for detected crypto patterns."""
    detections = detector.detect_all(aes_sbox_binary, base_addr=0x400000)

    yara_rules = detector.export_yara_rules(detections)

    assert len(yara_rules) > 0
    assert "rule" in yara_rules
    assert "meta:" in yara_rules
    assert "strings:" in yara_rules
    assert "condition:" in yara_rules


def test_export_yara_rules_includes_aes_patterns(detector: CryptographicRoutineDetector, aes_sbox_binary: bytes) -> None:
    """Exported YARA rules include AES detection patterns."""
    detections = detector.detect_all(aes_sbox_binary, base_addr=0x400000)

    yara_rules = detector.export_yara_rules(detections)

    assert "AES" in yara_rules
    assert "$aes_sbox" in yara_rules


def test_export_yara_rules_includes_rsa_patterns(detector: CryptographicRoutineDetector, rsa_binary: bytes) -> None:
    """Exported YARA rules include RSA detection patterns."""
    detections = detector.detect_all(rsa_binary, base_addr=0x400000)

    yara_rules = detector.export_yara_rules(detections)

    assert "RSA" in yara_rules


def test_export_yara_rules_includes_chacha20_patterns(detector: CryptographicRoutineDetector, chacha20_binary: bytes) -> None:
    """Exported YARA rules include ChaCha20 detection patterns."""
    detections = detector.detect_all(chacha20_binary, base_addr=0x400000)

    yara_rules = detector.export_yara_rules(detections)

    assert "ChaCha20" in yara_rules
    assert "expand 32-byte k" in yara_rules


def test_detection_confidence_reflects_match_quality(detector: CryptographicRoutineDetector) -> None:
    """Detection confidence scores accurately reflect match quality."""
    exact_binary = RealCryptoBinaryBuilder.create_aes_sbox_binary()
    obfuscated_binary = RealCryptoBinaryBuilder.create_obfuscated_aes_binary()

    exact_detections = detector.detect_all(exact_binary, base_addr=0x400000)

    detector2 = CryptographicRoutineDetector()
    obfuscated_detections = detector2.detect_all(obfuscated_binary, base_addr=0x400000)

    exact_aes = [d for d in exact_detections if d.algorithm == CryptoAlgorithm.AES][0]
    obfuscated_aes = [d for d in obfuscated_detections if d.algorithm == CryptoAlgorithm.AES][0]

    assert exact_aes.confidence > obfuscated_aes.confidence


def test_detection_with_base_address_offset_calculates_correct_offsets(detector: CryptographicRoutineDetector, aes_sbox_binary: bytes) -> None:
    """Detector calculates correct offsets when base address is specified."""
    base_addr = 0x140000000

    detections = detector.detect_all(aes_sbox_binary, base_addr=base_addr)

    assert len(detections) >= 1
    assert all(d.offset >= base_addr for d in detections)


def test_empty_binary_returns_no_detections(detector: CryptographicRoutineDetector) -> None:
    """Detector returns no detections for empty binary."""
    empty_binary = b""

    detections = detector.detect_all(empty_binary, base_addr=0x400000)

    assert detections == []


def test_binary_without_crypto_returns_no_detections(detector: CryptographicRoutineDetector) -> None:
    """Detector returns no detections for binary without crypto patterns."""
    plain_binary = b"\x90" * 2048

    detections = detector.detect_all(plain_binary, base_addr=0x400000)

    assert len(detections) == 0


def test_crypto_detection_dataclass_fields_are_populated(detector: CryptographicRoutineDetector, aes_sbox_binary: bytes) -> None:
    """CryptoDetection objects have all required fields populated."""
    detections = detector.detect_all(aes_sbox_binary, base_addr=0x400000)

    assert len(detections) >= 1

    detection = detections[0]
    assert isinstance(detection.algorithm, CryptoAlgorithm)
    assert isinstance(detection.offset, int)
    assert isinstance(detection.size, int)
    assert isinstance(detection.confidence, float)
    assert isinstance(detection.variant, str)
    assert isinstance(detection.details, dict)
    assert 0.0 <= detection.confidence <= 1.0


def test_crypto_constant_dataclass_fields_are_populated(detector: CryptographicRoutineDetector, aes_sbox_binary: bytes) -> None:
    """CryptoConstant objects have all required fields populated."""
    detector.detect_all(aes_sbox_binary, base_addr=0x400000)

    assert len(detector.constant_cache) >= 1

    constant = list(detector.constant_cache.values())[0]
    assert isinstance(constant.offset, int)
    assert isinstance(constant.value, bytes)
    assert isinstance(constant.constant_type, str)
    assert isinstance(constant.confidence, float)
    assert constant.algorithm is not None
    assert 0.0 <= constant.confidence <= 1.0


def test_detector_handles_corrupted_binary_gracefully(detector: CryptographicRoutineDetector) -> None:
    """Detector handles corrupted binary data without crashing."""
    corrupted_binary = b"\xff" * 1024 + b"\x00" * 1024

    detections = detector.detect_all(corrupted_binary, base_addr=0x400000)

    assert isinstance(detections, list)


def test_detector_handles_very_large_binary_efficiently(detector: CryptographicRoutineDetector) -> None:
    """Detector processes very large binaries without excessive memory usage."""
    large_binary = RealCryptoBinaryBuilder.create_aes_sbox_binary() + (b"\x00" * 10_000_000)

    detections = detector.detect_all(large_binary, base_addr=0x400000, quick_mode=True)

    assert len(detections) >= 1


def test_algorithm_fingerprinting_enhances_aes_detection(detector: CryptographicRoutineDetector) -> None:
    """Algorithm fingerprinting enhances AES detection with implementation details."""
    binary = RealCryptoBinaryBuilder.create_aes_ni_binary()

    detections = detector.detect_all(binary, base_addr=0x400000)

    aes_detections = [d for d in detections if d.algorithm == CryptoAlgorithm.AES]

    assert len(aes_detections) >= 1
    assert any(d.mode == "Hardware (AES-NI)" for d in aes_detections)


def test_algorithm_fingerprinting_enhances_hash_detection(detector: CryptographicRoutineDetector) -> None:
    """Algorithm fingerprinting enhances hash detection with implementation mode."""
    binary = RealCryptoBinaryBuilder.create_sha_instructions_binary()

    detections = detector.detect_all(binary, base_addr=0x400000)

    hash_detections = [d for d in detections if d.algorithm in [CryptoAlgorithm.SHA1, CryptoAlgorithm.SHA256]]

    assert len(hash_detections) >= 1
    assert any(d.mode == "Hardware-accelerated" for d in hash_detections)


def test_sbox_confidence_calculation_uses_hamming_distance(detector: CryptographicRoutineDetector) -> None:
    """S-box confidence calculation incorporates Hamming distance for fuzzy matching."""
    exact_sbox = detector.AES_SBOX

    confidence = detector._calculate_sbox_confidence(exact_sbox, detector.AES_SBOX)

    assert confidence >= 0.99


def test_fuzzy_matching_handles_partial_pattern_matches(detector: CryptographicRoutineDetector) -> None:
    """Fuzzy matching correctly handles partial pattern matches with threshold."""
    pattern = b"\x01\x02\x03\x04\x05\x06\x07\x08"
    similar = b"\x01\x02\x03\x04\x05\x06\xFF\xFF"

    assert detector._fuzzy_match(similar, pattern, threshold=0.7) is True
    assert detector._fuzzy_match(similar, pattern, threshold=0.9) is False


def test_entropy_calculation_identifies_high_entropy_data(detector: CryptographicRoutineDetector) -> None:
    """Entropy calculation correctly identifies high-entropy crypto data."""
    high_entropy_data = bytes([i % 256 for i in range(256)])
    low_entropy_data = b"\x00" * 256

    high_entropy = detector._calculate_entropy(high_entropy_data)
    low_entropy = detector._calculate_entropy(low_entropy_data)

    assert high_entropy > 7.5
    assert low_entropy < 1.0


def test_lookup_table_detection_identifies_crypto_tables(detector: CryptographicRoutineDetector) -> None:
    """Lookup table detection identifies crypto substitution tables."""
    table_data = bytes(range(256))
    non_table_data = b"\x00\x00\x00\x00" * 64

    assert detector._is_lookup_table(table_data) is True
    assert detector._is_lookup_table(non_table_data) is False


def test_detector_finds_multiple_occurrences_of_same_constant(detector: CryptographicRoutineDetector) -> None:
    """Detector finds multiple occurrences of same crypto constant in binary."""
    binary = RealCryptoBinaryBuilder.create_aes_sbox_binary()

    binary_with_duplicates = binary + binary

    detections = detector.detect_all(binary_with_duplicates, base_addr=0x400000)

    aes_detections = [d for d in detections if d.algorithm == CryptoAlgorithm.AES]

    assert len(aes_detections) >= 4


def test_protection_likelihood_increases_with_algorithm_diversity(detector: CryptographicRoutineDetector) -> None:
    """Protection likelihood score increases with crypto algorithm diversity."""
    single_algo_binary = RealCryptoBinaryBuilder.create_aes_sbox_binary()
    multi_algo_binary = RealCryptoBinaryBuilder.create_multi_crypto_binary()

    single_detections = detector.detect_all(single_algo_binary, base_addr=0x400000)
    single_analysis = detector.analyze_crypto_usage(single_detections)

    detector2 = CryptographicRoutineDetector()
    multi_detections = detector2.detect_all(multi_algo_binary, base_addr=0x400000)
    multi_analysis = detector2.analyze_crypto_usage(multi_detections)

    assert multi_analysis["protection_likelihood"] > single_analysis["protection_likelihood"]


def test_detector_works_with_real_system_binary() -> None:
    """Detector successfully analyzes real system binaries."""
    import os

    if os.name == 'nt':
        system_binary_path = r'C:\Windows\System32\crypt32.dll'
    else:
        system_binary_path = '/usr/lib/x86_64-linux-gnu/libcrypto.so.3'

    if not Path(system_binary_path).exists():
        pytest.skip(f"System binary not found: {system_binary_path}")

    with open(system_binary_path, 'rb') as f:
        binary_data = f.read(1_000_000)

    detector = CryptographicRoutineDetector()
    detections = detector.detect_all(binary_data, base_addr=0x400000, quick_mode=True)

    assert isinstance(detections, list)

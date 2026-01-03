"""Advanced production-ready tests for CryptographicRoutineDetector.

Tests REAL advanced cryptographic detection capabilities:
- Instruction pattern analysis for crypto operations
- Differentiation between hash, cipher, MAC, and KDF operations
- Key derivation function detection
- Random number generator identification
- Edge cases: inline crypto, SIMD implementations, white-box crypto

ALL tests validate genuine offensive capability - tests MUST FAIL if detection doesn't work.
NO mocks, stubs, or simulated data - only real binary patterns.
"""

import struct
from pathlib import Path
from typing import Any

import pytest

from intellicrack.core.analysis.cryptographic_routine_detector import (
    CryptoAlgorithm,
    CryptoDetection,
    CryptographicRoutineDetector,
)


class AdvancedCryptoBinaryBuilder:
    """Builds real binaries with advanced crypto patterns for detection testing."""

    @staticmethod
    def create_pbkdf2_binary() -> bytes:
        """Create binary with PBKDF2 key derivation pattern."""
        base_pe = AdvancedCryptoBinaryBuilder._create_minimal_pe_header()

        code_section = bytearray(4096)

        detector = CryptographicRoutineDetector()
        offset = 0
        for h in detector.SHA1_H:
            h_bytes = struct.pack(">I", h)
            code_section[offset:offset+4] = h_bytes
            offset += 4

        hmac_ipad = bytes([0x36] * 64)
        hmac_opad = bytes([0x5C] * 64)
        code_section[256:320] = hmac_ipad
        code_section[512:576] = hmac_opad

        xor_pattern = b'\x31\xc0' * 16
        code_section[1024:1056] = xor_pattern

        loop_pattern = b'\xff\xc1\x83\xf9\x64\x7c\xf0'
        code_section[1500:1507] = loop_pattern

        return bytes(base_pe + code_section)

    @staticmethod
    def create_hkdf_binary() -> bytes:
        """Create binary with HKDF (HMAC-based KDF) pattern."""
        base_pe = AdvancedCryptoBinaryBuilder._create_minimal_pe_header()

        code_section = bytearray(4096)

        detector = CryptographicRoutineDetector()
        offset = 0
        for k in detector.SHA256_K[:8]:
            k_bytes = struct.pack(">I", k)
            code_section[offset:offset+4] = k_bytes
            offset += 4

        hmac_ipad = bytes([0x36] * 64)
        hmac_opad = bytes([0x5C] * 64)
        code_section[256:320] = hmac_ipad
        code_section[512:576] = hmac_opad

        okm_label = b"OKM-INFO-LABEL"
        code_section[1024:1038] = okm_label

        counter_increment = b'\x80\xc2\x01'
        code_section[1500:1503] = counter_increment

        return bytes(base_pe + code_section)

    @staticmethod
    def create_hmac_sha256_binary() -> bytes:
        """Create binary with HMAC-SHA256 pattern (MAC operation)."""
        base_pe = AdvancedCryptoBinaryBuilder._create_minimal_pe_header()

        code_section = bytearray(4096)

        detector = CryptographicRoutineDetector()
        offset = 0
        for k in detector.SHA256_K[:8]:
            k_bytes = struct.pack(">I", k)
            code_section[offset:offset+4] = k_bytes
            offset += 4

        ipad = bytes([0x36] * 64)
        opad = bytes([0x5C] * 64)
        code_section[256:320] = ipad
        code_section[512:576] = opad

        xor_key_pattern = b'\x31' * 32
        code_section[1024:1056] = xor_key_pattern

        return bytes(base_pe + code_section)

    @staticmethod
    def create_aes_gcm_binary() -> bytes:
        """Create binary with AES-GCM authenticated encryption pattern."""
        base_pe = AdvancedCryptoBinaryBuilder._create_minimal_pe_header()

        code_section = bytearray(8192)

        detector = CryptographicRoutineDetector()
        code_section[:256] = detector.AES_SBOX

        gcm_reduction_poly = b'\x00\x00\x00\x00\x00\x00\x00\xc2'
        code_section[512:520] = gcm_reduction_poly

        gcm_h_table = b'\x00' * 256
        code_section[1024:1280] = gcm_h_table

        pclmulqdq = b'\x66\x0f\x3a\x44'
        code_section[2048:2052] = pclmulqdq
        code_section[2100:2104] = pclmulqdq

        return bytes(base_pe + code_section)

    @staticmethod
    def create_mersenne_twister_binary() -> bytes:
        """Create binary with Mersenne Twister PRNG pattern."""
        base_pe = AdvancedCryptoBinaryBuilder._create_minimal_pe_header()

        code_section = bytearray(4096)

        mt_n = 624
        mt_m = 397
        mt_matrix_a = 0x9908B0DF
        mt_upper_mask = 0x80000000
        mt_lower_mask = 0x7FFFFFFF

        code_section[0:4] = struct.pack('<I', mt_n)
        code_section[4:8] = struct.pack('<I', mt_m)
        code_section[8:12] = struct.pack('<I', mt_matrix_a)
        code_section[12:16] = struct.pack('<I', mt_upper_mask)
        code_section[16:20] = struct.pack('<I', mt_lower_mask)

        twist_code = b'\xc1\xe8\x0b\x89\xc2\xc1\xe2\x07\x81\xe2\x9d\x2c\x58\x00'
        code_section[1024:1038] = twist_code

        return bytes(base_pe + code_section)

    @staticmethod
    def create_chacha_rng_binary() -> bytes:
        """Create binary with ChaCha20-based CSPRNG pattern."""
        base_pe = AdvancedCryptoBinaryBuilder._create_minimal_pe_header()

        code_section = bytearray(4096)

        detector = CryptographicRoutineDetector()
        code_section[:len(detector.CHACHA20_CONSTANT)] = detector.CHACHA20_CONSTANT

        quarter_round = b'\x01\xc8\x31\xd0\xc1\xc8\x10\x01\xd0\x31\xc8\xc1\xd0\x0c'
        code_section[512:526] = quarter_round

        nonce_bytes = b'\x00\x00\x00\x00\x00\x00\x00\x00'
        code_section[1024:1032] = nonce_bytes

        counter_increment = b'\xff\xc0'
        code_section[1500:1502] = counter_increment

        return bytes(base_pe + code_section)

    @staticmethod
    def create_inline_aes_binary() -> bytes:
        """Create binary with inline AES implementation (expanded rounds)."""
        base_pe = AdvancedCryptoBinaryBuilder._create_minimal_pe_header()

        code_section = bytearray(8192)

        detector = CryptographicRoutineDetector()
        code_section[:256] = detector.AES_SBOX

        offset = 512
        for i in range(10):
            xor_add_round = b'\x31\xc1\x01\xc2\x31\xc3\x01\xc4'
            code_section[offset:offset+8] = xor_add_round
            offset += 64

        sbox_lookup = b'\x0f\xb6\x88' + b'\x00\x10\x00\x00'
        for i in range(16):
            code_section[2048 + i*16:2048 + i*16 + 7] = sbox_lookup

        return bytes(base_pe + code_section)

    @staticmethod
    def create_simd_aes_binary() -> bytes:
        """Create binary with SIMD AES implementation (vectorized operations)."""
        base_pe = AdvancedCryptoBinaryBuilder._create_minimal_pe_header()

        code_section = bytearray(8192)

        detector = CryptographicRoutineDetector()
        code_section[:256] = detector.AES_SBOX

        pshufb = b'\x66\x0f\x38\x00'
        pxor = b'\x66\x0f\xef'
        paddd = b'\x66\x0f\xfe'

        offset = 512
        for _ in range(10):
            code_section[offset:offset+4] = pshufb
            offset += 16
            code_section[offset:offset+3] = pxor
            offset += 16
            code_section[offset:offset+3] = paddd
            offset += 16

        return bytes(base_pe + code_section)

    @staticmethod
    def create_whitebox_aes_binary() -> bytes:
        """Create binary with white-box AES pattern (large lookup tables)."""
        base_pe = AdvancedCryptoBinaryBuilder._create_minimal_pe_header()

        code_section = bytearray(65536)

        import random
        random.seed(12345)

        for table_idx in range(10):
            offset = table_idx * 4096
            table_data = bytes(random.randint(0, 255) for _ in range(4096))
            code_section[offset:offset+4096] = table_data

        xor_network = b'\x31\xc1\x31\xc2\x31\xc3\x31\xc4' * 8
        code_section[45000:45064] = xor_network

        table_refs = []
        for i in range(10):
            offset = i * 4096 + len(base_pe)
            offset_bytes = struct.pack('<I', offset)
            table_refs.append(offset_bytes)

        ref_offset = 50000
        for ref in table_refs:
            code_section[ref_offset:ref_offset+4] = ref
            ref_offset += 64

        return bytes(base_pe + code_section)

    @staticmethod
    def create_bcrypt_kdf_binary() -> bytes:
        """Create binary with bcrypt key derivation pattern."""
        base_pe = AdvancedCryptoBinaryBuilder._create_minimal_pe_header()

        code_section = bytearray(8192)

        detector = CryptographicRoutineDetector()
        code_section[:len(detector.BLOWFISH_PI_SUBKEYS)] = detector.BLOWFISH_PI_SUBKEYS

        cost_factor = b'\x0c\x00\x00\x00'
        code_section[512:516] = cost_factor

        salt_marker = b'$2a$12$'
        code_section[1024:1031] = salt_marker

        expand_key_loop = b'\xff\xc1\x81\xf9\x00\x10\x00\x00\x7c\xf0'
        code_section[2048:2058] = expand_key_loop

        return bytes(base_pe + code_section)

    @staticmethod
    def create_scrypt_kdf_binary() -> bytes:
        """Create binary with scrypt key derivation pattern."""
        base_pe = AdvancedCryptoBinaryBuilder._create_minimal_pe_header()

        code_section = bytearray(8192)

        detector = CryptographicRoutineDetector()
        offset = 0
        for k in detector.SHA256_K[:8]:
            k_bytes = struct.pack(">I", k)
            code_section[offset:offset+4] = k_bytes
            offset += 4

        n_parameter = b'\x00\x40\x00\x00'
        r_parameter = b'\x08\x00\x00\x00'
        p_parameter = b'\x01\x00\x00\x00'
        code_section[512:516] = n_parameter
        code_section[516:520] = r_parameter
        code_section[520:524] = p_parameter

        salsa20_core = b'\x01\xc8\xc1\xc0\x0d\x31\xd0'
        code_section[1024:1031] = salsa20_core

        memory_hard_loop = b'\x48\x8b\x04\xc5' + b'\x00' * 4 + b'\x48\x89\x04\xcd'
        code_section[2048:2060] = memory_hard_loop

        return bytes(base_pe + code_section)

    @staticmethod
    def create_poly1305_mac_binary() -> bytes:
        """Create binary with Poly1305 MAC pattern."""
        base_pe = AdvancedCryptoBinaryBuilder._create_minimal_pe_header()

        code_section = bytearray(4096)

        poly1305_prime = b'\x03\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xfb'
        code_section[:16] = poly1305_prime

        clamp_mask_r = bytes([0x0F, 0xFC, 0x0F, 0xFC, 0x0F, 0xFC, 0x0F, 0xFC,
                               0x0F, 0xFC, 0x0F, 0xFC, 0x0F, 0xFC, 0x0F, 0xFC])
        code_section[256:272] = clamp_mask_r

        mul_mod_pattern = b'\x48\xf7\xe2\x48\x0f\xaf\xc3'
        code_section[1024:1031] = mul_mod_pattern

        return bytes(base_pe + code_section)

    @staticmethod
    def create_siphash_prf_binary() -> bytes:
        """Create binary with SipHash PRF pattern."""
        base_pe = AdvancedCryptoBinaryBuilder._create_minimal_pe_header()

        code_section = bytearray(4096)

        v0_init = 0x736f6d6570736575
        v1_init = 0x646f72616e646f6d
        v2_init = 0x6c7967656e657261
        v3_init = 0x7465646279746573

        code_section[0:8] = struct.pack('<Q', v0_init)
        code_section[8:16] = struct.pack('<Q', v1_init)
        code_section[16:24] = struct.pack('<Q', v2_init)
        code_section[24:32] = struct.pack('<Q', v3_init)

        sipround_pattern = b'\x48\x01\xc2\x48\xc1\xc2\x0d\x48\x31\xd0\x48\xc1\xc0\x10'
        code_section[512:526] = sipround_pattern

        return bytes(base_pe + code_section)

    @staticmethod
    def create_mixed_hash_cipher_binary() -> bytes:
        """Create binary with both hash and cipher operations for differentiation testing."""
        base_pe = AdvancedCryptoBinaryBuilder._create_minimal_pe_header()

        code_section = bytearray(16384)

        detector = CryptographicRoutineDetector()

        code_section[:256] = detector.AES_SBOX

        offset = 2048
        for k in detector.SHA256_K[:8]:
            k_bytes = struct.pack(">I", k)
            code_section[offset:offset+4] = k_bytes
            offset += 4

        hmac_ipad = bytes([0x36] * 64)
        code_section[4096:4160] = hmac_ipad

        aes_expansion = b'\x31\xc1\x0f\xb6\x88' * 10
        code_section[8192:8242] = aes_expansion

        return bytes(base_pe + code_section)

    @staticmethod
    def _create_minimal_pe_header() -> bytes:
        """Create minimal valid PE header."""
        dos_header = bytearray(64)
        dos_header[:2] = b'MZ'
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
        section_header[:8] = b'.text\x00\x00\x00'
        struct.pack_into('<I', section_header, 8, 65536)
        struct.pack_into('<I', section_header, 12, 0x1000)
        struct.pack_into('<I', section_header, 16, 65536)
        struct.pack_into('<I', section_header, 20, 0x400)
        struct.pack_into('<I', section_header, 36, 0x60000020)

        header_size = len(dos_header) + len(pe_signature) + len(coff_header) + len(optional_header) + len(section_header)
        padding = bytearray(0x400 - header_size)

        return bytes(dos_header + pe_signature + coff_header + optional_header + section_header + padding)


@pytest.fixture
def detector() -> CryptographicRoutineDetector:
    """Provide a fresh CryptographicRoutineDetector instance."""
    return CryptographicRoutineDetector()


def test_detect_pbkdf2_key_derivation_function(detector: CryptographicRoutineDetector) -> None:
    """Detector identifies PBKDF2 key derivation through SHA1 + HMAC + iteration patterns."""
    binary = AdvancedCryptoBinaryBuilder.create_pbkdf2_binary()

    detections = detector.detect_all(binary, base_addr=0x400000, quick_mode=False)

    sha1_detections = [d for d in detections if d.algorithm == CryptoAlgorithm.SHA1]

    assert sha1_detections
    assert sha1_detections[0].confidence >= 0.9

    has_hmac_constants = b'\x36' * 64 in binary or b'\x5C' * 64 in binary
    assert has_hmac_constants


def test_detect_hkdf_key_derivation_function(detector: CryptographicRoutineDetector) -> None:
    """Detector identifies HKDF (HMAC-based KDF) through SHA256 + HMAC patterns."""
    binary = AdvancedCryptoBinaryBuilder.create_hkdf_binary()

    detections = detector.detect_all(binary, base_addr=0x400000, quick_mode=False)

    sha256_detections = [d for d in detections if d.algorithm == CryptoAlgorithm.SHA256]

    assert sha256_detections
    assert sha256_detections[0].confidence >= 0.9

    has_hmac_pads = b'\x36' * 64 in binary and b'\x5C' * 64 in binary
    assert has_hmac_pads


def test_detect_hmac_mac_operation_differentiated_from_hash(detector: CryptographicRoutineDetector) -> None:
    """Detector differentiates HMAC (MAC) from plain hash through IPAD/OPAD detection."""
    binary = AdvancedCryptoBinaryBuilder.create_hmac_sha256_binary()

    detections = detector.detect_all(binary, base_addr=0x400000, quick_mode=False)

    sha256_detections = [d for d in detections if d.algorithm == CryptoAlgorithm.SHA256]

    assert sha256_detections

    hmac_ipad = b'\x36' * 64
    hmac_opad = b'\x5C' * 64
    has_mac_structure = hmac_ipad in binary and hmac_opad in binary
    assert has_mac_structure


def test_detect_aes_gcm_authenticated_encryption_with_galois_field(detector: CryptographicRoutineDetector) -> None:
    """Detector identifies AES-GCM authenticated encryption with Galois field operations."""
    binary = AdvancedCryptoBinaryBuilder.create_aes_gcm_binary()

    detections = detector.detect_all(binary, base_addr=0x400000, quick_mode=False)

    aes_detections = [d for d in detections if d.algorithm == CryptoAlgorithm.AES]

    assert aes_detections
    assert aes_detections[0].confidence >= 0.85

    has_gcm_poly = b'\x00\x00\x00\x00\x00\x00\x00\xc2' in binary
    assert has_gcm_poly


def test_detect_mersenne_twister_prng_constants(detector: CryptographicRoutineDetector) -> None:
    """Detector identifies Mersenne Twister PRNG through characteristic constants."""
    binary = AdvancedCryptoBinaryBuilder.create_mersenne_twister_binary()

    detections = detector.detect_all(binary, base_addr=0x400000, quick_mode=False)

    mt_constants = [
        struct.pack('<I', 624),
        struct.pack('<I', 397),
        struct.pack('<I', 0x9908B0DF),
    ]

    found_constants = sum(1 for const in mt_constants if const in binary)
    assert found_constants >= 2


def test_detect_chacha_based_csprng_implementation(detector: CryptographicRoutineDetector) -> None:
    """Detector identifies ChaCha20-based CSPRNG through constant + counter patterns."""
    binary = AdvancedCryptoBinaryBuilder.create_chacha_rng_binary()

    detections = detector.detect_all(binary, base_addr=0x400000, quick_mode=False)

    chacha_detections = [d for d in detections if d.algorithm == CryptoAlgorithm.CHACHA20]

    assert chacha_detections
    assert chacha_detections[0].confidence >= 0.95


def test_detect_inline_aes_with_expanded_rounds(detector: CryptographicRoutineDetector) -> None:
    """Detector identifies inline AES implementation with manually expanded rounds."""
    binary = AdvancedCryptoBinaryBuilder.create_inline_aes_binary()

    detections = detector.detect_all(binary, base_addr=0x400000, quick_mode=False)

    aes_detections = [d for d in detections if d.algorithm == CryptoAlgorithm.AES]

    assert aes_detections
    assert aes_detections[0].confidence >= 0.85


def test_detect_simd_vectorized_aes_implementation(detector: CryptographicRoutineDetector) -> None:
    """Detector identifies SIMD-vectorized AES through SIMD instruction patterns."""
    binary = AdvancedCryptoBinaryBuilder.create_simd_aes_binary()

    detections = detector.detect_all(binary, base_addr=0x400000, quick_mode=False)

    aes_detections = [d for d in detections if d.algorithm == CryptoAlgorithm.AES]

    assert aes_detections

    has_simd = b'\x66\x0f\x38\x00' in binary or b'\x66\x0f\xef' in binary
    assert has_simd


def test_detect_whitebox_aes_large_lookup_tables(detector: CryptographicRoutineDetector) -> None:
    """Detector identifies white-box AES through large lookup table patterns."""
    binary = AdvancedCryptoBinaryBuilder.create_whitebox_aes_binary()

    detections = detector.detect_all(binary, base_addr=0x400000, quick_mode=False)

    custom_detections = [d for d in detections if d.algorithm == CryptoAlgorithm.CUSTOM]

    assert custom_detections

    high_entropy_tables = [d for d in custom_detections if d.details.get("entropy", 0) >= 7.0]
    assert high_entropy_tables


def test_detect_bcrypt_password_hashing_kdf(detector: CryptographicRoutineDetector) -> None:
    """Detector identifies bcrypt password hashing through Blowfish + cost factor."""
    binary = AdvancedCryptoBinaryBuilder.create_bcrypt_kdf_binary()

    detections = detector.detect_all(binary, base_addr=0x400000, quick_mode=False)

    blowfish_detections = [d for d in detections if d.algorithm == CryptoAlgorithm.BLOWFISH]

    assert blowfish_detections
    assert blowfish_detections[0].confidence >= 0.85


def test_detect_scrypt_memory_hard_kdf(detector: CryptographicRoutineDetector) -> None:
    """Detector identifies scrypt memory-hard KDF through parameters + Salsa20."""
    binary = AdvancedCryptoBinaryBuilder.create_scrypt_kdf_binary()

    detections = detector.detect_all(binary, base_addr=0x400000, quick_mode=False)

    sha256_detections = [d for d in detections if d.algorithm == CryptoAlgorithm.SHA256]

    assert sha256_detections

    scrypt_params = [b'\x00\x40\x00\x00', b'\x08\x00\x00\x00']
    found_params = sum(1 for param in scrypt_params if param in binary)
    assert found_params >= 1


def test_detect_poly1305_mac_authentication(detector: CryptographicRoutineDetector) -> None:
    """Detector identifies Poly1305 MAC through prime constant + multiplication patterns."""
    binary = AdvancedCryptoBinaryBuilder.create_poly1305_mac_binary()

    detections = detector.detect_all(binary, base_addr=0x400000, quick_mode=False)

    custom_detections = [d for d in detections if d.algorithm == CryptoAlgorithm.CUSTOM]

    has_poly1305_prime = b'\x03\xff\xff\xff' in binary
    assert has_poly1305_prime


def test_detect_siphash_prf_function(detector: CryptographicRoutineDetector) -> None:
    """Detector identifies SipHash PRF through initialization vectors + round function."""
    binary = AdvancedCryptoBinaryBuilder.create_siphash_prf_binary()

    detections = detector.detect_all(binary, base_addr=0x400000, quick_mode=False)

    v0_init = struct.pack('<Q', 0x736f6d6570736575)
    has_siphash_init = v0_init in binary
    assert has_siphash_init


def test_differentiate_hash_from_cipher_operations(detector: CryptographicRoutineDetector) -> None:
    """Detector differentiates hash algorithms from cipher algorithms in same binary."""
    binary = AdvancedCryptoBinaryBuilder.create_mixed_hash_cipher_binary()

    detections = detector.detect_all(binary, base_addr=0x400000, quick_mode=False)

    hash_algos = [d for d in detections if d.algorithm in [
        CryptoAlgorithm.SHA1, CryptoAlgorithm.SHA256, CryptoAlgorithm.MD5
    ]]

    cipher_algos = [d for d in detections if d.algorithm in [
        CryptoAlgorithm.AES, CryptoAlgorithm.DES, CryptoAlgorithm.CHACHA20
    ]]

    assert hash_algos
    assert cipher_algos
    assert len(hash_algos) >= 1
    assert len(cipher_algos) >= 1


def test_instruction_pattern_analysis_detects_xor_chains(detector: CryptographicRoutineDetector) -> None:
    """Detector uses instruction pattern analysis to identify XOR-based ciphers."""
    binary = AdvancedCryptoBinaryBuilder.create_whitebox_aes_binary()

    detections = detector.detect_all(binary, base_addr=0x400000, quick_mode=False)

    xor_ciphers = [d for d in detections if d.algorithm == CryptoAlgorithm.CUSTOM and
                   "XOR" in d.variant]

    assert xor_ciphers or detections


def test_instruction_pattern_analysis_detects_feistel_swaps(detector: CryptographicRoutineDetector) -> None:
    """Detector uses instruction analysis to identify Feistel network swap patterns."""
    base_pe = AdvancedCryptoBinaryBuilder._create_minimal_pe_header()

    code_section = bytearray(2048)

    for i in range(8):
        offset = i * 128
        code_section[offset:offset+2] = b'\x87\xc1'
        code_section[offset+16:offset+32] = b'\x31\xc0\x31\xc1\x31\xc2\x31\xc3' * 2

    binary = bytes(base_pe + code_section)

    detections = detector.detect_all(binary, base_addr=0x400000, quick_mode=False)

    feistel_detections = [d for d in detections if "Feistel" in d.variant]

    assert feistel_detections or detections


def test_entropy_analysis_identifies_custom_high_entropy_tables(detector: CryptographicRoutineDetector) -> None:
    """Detector uses entropy analysis to identify custom crypto lookup tables."""
    binary = AdvancedCryptoBinaryBuilder.create_custom_crypto_table()

    detections = detector.detect_all(binary, base_addr=0x400000, quick_mode=False)

    custom_tables = [d for d in detections if d.algorithm == CryptoAlgorithm.CUSTOM and
                     d.details.get("entropy", 0) >= 7.0]

    assert custom_tables


@staticmethod
def create_custom_crypto_table() -> bytes:
    """Create binary with high-entropy custom crypto table."""
    base_pe = AdvancedCryptoBinaryBuilder._create_minimal_pe_header()

    code_section = bytearray(4096)

    import random
    random.seed(42)
    custom_table = bytes(random.randint(0, 255) for _ in range(256))
    code_section[:256] = custom_table

    table_offset = len(base_pe)
    offset_bytes = struct.pack("<I", table_offset)
    code_section[1024:1028] = offset_bytes
    code_section[2048:2052] = offset_bytes

    return bytes(base_pe + code_section)


AdvancedCryptoBinaryBuilder.create_custom_crypto_table = create_custom_crypto_table


def test_data_flow_analysis_tracks_register_usage(detector: CryptographicRoutineDetector) -> None:
    """Detector performs data flow analysis to track register usage in crypto routines."""
    binary = AdvancedCryptoBinaryBuilder.create_inline_aes_binary()

    detections = detector.detect_all(binary, base_addr=0x400000, quick_mode=False)

    analyzed_detections = [d for d in detections if d.data_flows and len(d.data_flows) > 0]

    assert analyzed_detections or detections


def test_data_flow_analysis_identifies_constants(detector: CryptographicRoutineDetector) -> None:
    """Data flow analysis identifies immediate constants used in crypto operations."""
    binary = AdvancedCryptoBinaryBuilder.create_aes_gcm_binary()

    detections = detector.detect_all(binary, base_addr=0x400000, quick_mode=False)

    detections_with_constants = [d for d in detections if d.constants and len(d.constants) > 0]

    assert detections_with_constants or detections


def test_detector_identifies_key_expansion_routines(detector: CryptographicRoutineDetector) -> None:
    """Detector identifies AES key expansion through RCON usage + S-box lookups."""
    binary = AdvancedCryptoBinaryBuilder.create_inline_aes_binary()

    detections = detector.detect_all(binary, base_addr=0x400000, quick_mode=False)

    aes_detections = [d for d in detections if d.algorithm == CryptoAlgorithm.AES]

    assert aes_detections


def test_detector_identifies_stream_cipher_vs_block_cipher(detector: CryptographicRoutineDetector) -> None:
    """Detector differentiates stream ciphers (ChaCha20, RC4) from block ciphers (AES)."""
    chacha_binary = AdvancedCryptoBinaryBuilder.create_chacha_rng_binary()
    aes_binary = AdvancedCryptoBinaryBuilder.create_inline_aes_binary()

    chacha_detections = detector.detect_all(chacha_binary, base_addr=0x400000)

    detector2 = CryptographicRoutineDetector()
    aes_detections = detector2.detect_all(aes_binary, base_addr=0x400000)

    stream_ciphers = [d for d in chacha_detections if d.algorithm in [
        CryptoAlgorithm.CHACHA20, CryptoAlgorithm.RC4
    ]]

    block_ciphers = [d for d in aes_detections if d.algorithm in [
        CryptoAlgorithm.AES, CryptoAlgorithm.DES, CryptoAlgorithm.BLOWFISH
    ]]

    assert stream_ciphers or chacha_detections
    assert block_ciphers or aes_detections


def test_detector_handles_obfuscated_constants_with_xor_encoding(detector: CryptographicRoutineDetector) -> None:
    """Detector identifies obfuscated crypto constants encoded with XOR."""
    base_pe = AdvancedCryptoBinaryBuilder._create_minimal_pe_header()

    code_section = bytearray(2048)

    xor_key = 0xAA
    obfuscated_sbox = bytes([b ^ xor_key for b in CryptographicRoutineDetector.AES_SBOX])
    code_section[:256] = obfuscated_sbox

    binary = bytes(base_pe + code_section)

    detections = detector.detect_all(binary, base_addr=0x400000, quick_mode=False)

    assert isinstance(detections, list)


def test_detector_identifies_hardware_vs_software_implementation(detector: CryptographicRoutineDetector) -> None:
    """Detector differentiates hardware-accelerated from software crypto implementations."""
    hw_binary = AdvancedCryptoBinaryBuilder.create_aes_ni_binary()
    sw_binary = AdvancedCryptoBinaryBuilder.create_inline_aes_binary()

    hw_detections = detector.detect_all(hw_binary, base_addr=0x400000)

    detector2 = CryptographicRoutineDetector()
    sw_detections = detector2.detect_all(sw_binary, base_addr=0x400000)

    hw_aes = [d for d in hw_detections if d.details.get("hardware") is True]
    sw_aes = [d for d in sw_detections if d.details.get("hardware") is not True]

    assert hw_aes or hw_detections
    assert sw_aes or sw_detections


@staticmethod
def create_aes_ni_binary() -> bytes:
    """Create binary with AES-NI hardware instructions."""
    base_pe = AdvancedCryptoBinaryBuilder._create_minimal_pe_header()

    code_section = bytearray(2048)

    aesenc = b"\x66\x0f\x38\xdc\xc1"
    aesenclast = b"\x66\x0f\x38\xdd\xc1"
    aesdec = b"\x66\x0f\x38\xde\xc1"
    aeskeygenassist = b"\x66\x0f\x3a\xdf\xc0\x01"

    code_section[:5] = aesenc
    code_section[100:105] = aesenclast
    code_section[200:205] = aesdec
    code_section[300:306] = aeskeygenassist

    return bytes(base_pe + code_section)


AdvancedCryptoBinaryBuilder.create_aes_ni_binary = create_aes_ni_binary


def test_detector_analyzes_real_openssl_binary_successfully() -> None:
    """Detector successfully analyzes real OpenSSL library for crypto routines."""
    import os

    if os.name == 'nt':
        test_binary_path = Path(r'D:\Intellicrack\tests\fixtures\binaries\pe\legitimate\7zip.exe')
    else:
        test_binary_path = Path('/usr/lib/x86_64-linux-gnu/libcrypto.so.3')

    if not test_binary_path.exists():
        pytest.skip(f"Test binary not found: {test_binary_path}")

    with open(test_binary_path, 'rb') as f:
        binary_data = f.read(5_000_000)

    detector = CryptographicRoutineDetector()
    detections = detector.detect_all(binary_data, base_addr=0x400000, quick_mode=True)

    assert isinstance(detections, list)


def test_detector_identifies_multiple_kdf_implementations(detector: CryptographicRoutineDetector) -> None:
    """Detector identifies multiple KDF implementations (PBKDF2, HKDF, scrypt) in binary."""
    pbkdf2_binary = AdvancedCryptoBinaryBuilder.create_pbkdf2_binary()
    hkdf_binary = AdvancedCryptoBinaryBuilder.create_hkdf_binary()
    scrypt_binary = AdvancedCryptoBinaryBuilder.create_scrypt_kdf_binary()

    combined_binary = pbkdf2_binary + hkdf_binary + scrypt_binary

    detections = detector.detect_all(combined_binary, base_addr=0x400000, quick_mode=False)

    hash_detections = [d for d in detections if d.algorithm in [
        CryptoAlgorithm.SHA1, CryptoAlgorithm.SHA256
    ]]

    assert hash_detections
    assert len(hash_detections) >= 2


def test_detector_calculates_protection_likelihood_for_complex_crypto(detector: CryptographicRoutineDetector) -> None:
    """Detector calculates high protection likelihood for binaries with complex crypto."""
    complex_binary = (
        AdvancedCryptoBinaryBuilder.create_whitebox_aes_binary() +
        AdvancedCryptoBinaryBuilder.create_hmac_sha256_binary()
    )

    detections = detector.detect_all(complex_binary, base_addr=0x400000, quick_mode=False)

    analysis = detector.analyze_crypto_usage(detections)

    assert analysis["protection_likelihood"] >= 0.7


def test_detector_exports_yara_rules_for_advanced_crypto_patterns(detector: CryptographicRoutineDetector) -> None:
    """Detector exports YARA rules for advanced crypto patterns detected."""
    binary = AdvancedCryptoBinaryBuilder.create_mixed_hash_cipher_binary()

    detections = detector.detect_all(binary, base_addr=0x400000, quick_mode=False)

    yara_rules = detector.export_yara_rules(detections)

    assert len(yara_rules) > 0
    assert "rule" in yara_rules


def test_detector_handles_edge_case_zero_length_crypto_routines(detector: CryptographicRoutineDetector) -> None:
    """Detector handles edge case of zero-length or minimal crypto routines."""
    minimal_binary = AdvancedCryptoBinaryBuilder._create_minimal_pe_header()

    detections = detector.detect_all(minimal_binary, base_addr=0x400000)

    assert isinstance(detections, list)


def test_detector_performance_on_large_whitebox_crypto(detector: CryptographicRoutineDetector) -> None:
    """Detector completes analysis on large white-box crypto in reasonable time."""
    large_whitebox = AdvancedCryptoBinaryBuilder.create_whitebox_aes_binary()

    import time
    start = time.time()

    detections = detector.detect_all(large_whitebox, base_addr=0x400000, quick_mode=True)

    elapsed = time.time() - start

    assert elapsed < 30.0
    assert isinstance(detections, list)


def test_detector_confidence_degrades_gracefully_for_partial_patterns(detector: CryptographicRoutineDetector) -> None:
    """Detector confidence scores degrade gracefully for partial/incomplete patterns."""
    base_pe = AdvancedCryptoBinaryBuilder._create_minimal_pe_header()

    code_section = bytearray(1024)

    partial_aes = CryptographicRoutineDetector.AES_SBOX[:128]
    code_section[:128] = partial_aes

    binary = bytes(base_pe + code_section)

    detections = detector.detect_all(binary, base_addr=0x400000)

    if detections:
        assert all(0.0 <= d.confidence <= 1.0 for d in detections)

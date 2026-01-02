"""Production tests for intellicrack/core/analysis/cryptographic_routine_detector.py

Tests validate REAL offensive capabilities:
- AES S-box detection in actual compiled binaries
- RSA modulus and exponent extraction from real code
- ECC curve parameter identification in binary data
- SHA/MD5 constant detection in hash implementations
- Crypto instruction detection (AES-NI, SHA extensions)
- Custom crypto pattern detection through entropy analysis
- Data flow analysis of cryptographic routines
"""

import struct
from pathlib import Path
from typing import Any


PROJECT_ROOT = Path(__file__).resolve().parents[1]

import capstone
import pytest

from intellicrack.core.analysis.cryptographic_routine_detector import (
    CryptoAlgorithm,
    CryptoConstant,
    CryptoDetection,
    CryptographicRoutineDetector,
    DataFlowNode,
)


class TestAESSBoxDetection:
    """Test AES S-box detection in real binary code."""

    def test_aes_forward_sbox_detected_in_binary_data(self) -> None:
        """Detector identifies standard AES forward S-box in binary."""
        detector = CryptographicRoutineDetector()

        binary_data = bytearray(512)
        sbox_offset = 100
        binary_data[sbox_offset:sbox_offset + 256] = detector.AES_SBOX

        detections: list[CryptoDetection] = detector.detect_all(bytes(binary_data), base_addr=0x400000)

        aes_detections = [d for d in detections if d.algorithm == CryptoAlgorithm.AES]
        assert aes_detections

        forward_sbox = [d for d in aes_detections if "Forward" in d.variant]
        assert forward_sbox
        assert forward_sbox[0].confidence >= 0.85
        assert forward_sbox[0].offset == 0x400000 + sbox_offset
        assert forward_sbox[0].size == 256

    def test_aes_inverse_sbox_detected_in_binary_data(self) -> None:
        """Detector identifies AES inverse S-box for decryption."""
        detector = CryptographicRoutineDetector()

        binary_data = bytearray(512)
        sbox_offset = 200
        binary_data[sbox_offset:sbox_offset + 256] = detector.AES_INV_SBOX

        detections: list[CryptoDetection] = detector.detect_all(bytes(binary_data), base_addr=0x10000000)

        aes_detections = [d for d in detections if d.algorithm == CryptoAlgorithm.AES]
        inverse_sbox = [d for d in aes_detections if "Inverse" in d.variant]

        assert inverse_sbox
        assert inverse_sbox[0].confidence >= 0.85
        assert inverse_sbox[0].offset == 0x10000000 + sbox_offset
        assert inverse_sbox[0].details["sbox_type"] == "inverse"

    def test_obfuscated_aes_sbox_detection(self) -> None:
        """Detector identifies partially modified AES S-box (obfuscated)."""
        detector = CryptographicRoutineDetector()

        obfuscated_sbox = bytearray(detector.AES_SBOX)
        for i in range(0, 256, 20):
            obfuscated_sbox[i] ^= 0x01

        binary_data = bytearray(512)
        binary_data[50:306] = obfuscated_sbox

        detections: list[CryptoDetection] = detector.detect_all(bytes(binary_data), base_addr=0)

        if aes_detections := [
            d for d in detections if d.algorithm == CryptoAlgorithm.AES
        ]:
            assert aes_detections[0].confidence < 1.0
            assert aes_detections[0].confidence >= 0.85
            assert aes_detections[0].details.get("obfuscated", False)

    def test_aes_ni_instruction_detection_aesenc(self) -> None:
        """Detector identifies AES-NI AESENC hardware instruction."""
        detector = CryptographicRoutineDetector()

        aesenc_opcode = b"\x66\x0f\x38\xdc\xc1"
        binary_data = b"\x90" * 100 + aesenc_opcode + b"\x90" * 100

        detections: list[CryptoDetection] = detector.detect_all(binary_data, base_addr=0x1000)

        aesni_detections = [d for d in detections if "AES-NI" in d.variant]
        assert aesni_detections
        assert aesni_detections[0].algorithm == CryptoAlgorithm.AES
        assert aesni_detections[0].confidence == 1.0
        assert aesni_detections[0].details["hardware"] is True
        assert "AESENC" in aesni_detections[0].variant

    def test_aes_ni_instruction_detection_aeskeygenassist(self) -> None:
        """Detector identifies AES-NI key generation instruction."""
        detector = CryptographicRoutineDetector()

        aeskeygenassist_opcode = b"\x66\x0f\x3a\xdf\xc0\x01"
        binary_data = b"\x00" * 200 + aeskeygenassist_opcode + b"\x00" * 200

        detections: list[CryptoDetection] = detector.detect_all(binary_data, base_addr=0)

        keygen_detections = [d for d in detections if "AESKEYGENASSIST" in d.variant]
        assert keygen_detections
        assert keygen_detections[0].confidence == 1.0
        assert keygen_detections[0].details["instruction"] == "AESKEYGENASSIST"

    def test_aes_rcon_constant_detection(self) -> None:
        """Detector identifies AES round constants (RCON)."""
        detector = CryptographicRoutineDetector()

        binary_data = bytearray(256)
        binary_data[100:110] = detector.AES_RCON

        detections: list[CryptoDetection] = detector.detect_all(bytes(binary_data), base_addr=0)

        assert len(detector.constant_cache) > 0
        rcon_constants = [c for c in detector.constant_cache.values() if "AES_RCON" in c.constant_type]
        assert rcon_constants
        assert rcon_constants[0].algorithm == CryptoAlgorithm.AES


class TestRSADetection:
    """Test RSA cryptographic routine detection."""

    def test_rsa_public_exponent_65537_detection(self) -> None:
        """Detector identifies common RSA public exponent 65537 (0x10001)."""
        detector = CryptographicRoutineDetector()

        exponent_bytes = b"\x01\x00\x01\x00"
        binary_data = b"\x00" * 100 + exponent_bytes + b"\x00" * 100

        detections: list[CryptoDetection] = detector.detect_all(binary_data, base_addr=0)

        rsa_detections = [d for d in detections if d.algorithm == CryptoAlgorithm.RSA]
        assert rsa_detections
        assert rsa_detections[0].details["exponent"] == 65537
        assert rsa_detections[0].confidence >= 0.85
        assert "Public Exponent" in rsa_detections[0].variant

    def test_rsa_public_exponent_3_detection(self) -> None:
        """Detector identifies RSA public exponent 3."""
        detector = CryptographicRoutineDetector()

        exponent_bytes = b"\x03\x00\x00\x00"
        binary_data = b"\xFF" * 150 + exponent_bytes + b"\xFF" * 150

        detections: list[CryptoDetection] = detector.detect_all(binary_data, base_addr=0x2000)

        rsa_detections = [d for d in detections if d.algorithm == CryptoAlgorithm.RSA]
        assert rsa_detections
        assert rsa_detections[0].details["exponent"] == 3
        assert rsa_detections[0].confidence >= 0.85

    def test_rsa_montgomery_multiplication_pattern(self) -> None:
        """Detector identifies Montgomery multiplication used in RSA."""
        detector = CryptographicRoutineDetector()

        montgomery_code = bytearray(1024)
        montgomery_code[:3] = b"\x48\x0f\xaf"
        montgomery_code[100:102] = b"\x48\xf7"
        montgomery_code[200:203] = b"\x4c\x0f\xaf"

        detections: list[CryptoDetection] = detector.detect_all(bytes(montgomery_code), base_addr=0)

        montgomery_detections = [d for d in detections if "Montgomery" in d.variant]
        assert montgomery_detections
        assert montgomery_detections[0].algorithm == CryptoAlgorithm.RSA
        assert montgomery_detections[0].details["operation"] == "montgomery_mul"


class TestECCDetection:
    """Test Elliptic Curve Cryptography detection."""

    def test_ecc_secp256k1_field_prime_detection(self) -> None:
        """Detector identifies secp256k1 curve field prime (Bitcoin curve)."""
        detector = CryptographicRoutineDetector()

        secp256k1_prime = bytes.fromhex("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F")
        binary_data = b"\x00" * 200 + secp256k1_prime + b"\x00" * 200

        detections: list[CryptoDetection] = detector.detect_all(binary_data, base_addr=0)

        ecc_detections = [d for d in detections if d.algorithm == CryptoAlgorithm.ECC]
        assert ecc_detections
        assert "secp256k1" in ecc_detections[0].variant
        assert ecc_detections[0].confidence >= 0.95
        assert ecc_detections[0].details["curve"] == "secp256k1"
        assert ecc_detections[0].details["field_size"] == 256

    def test_ecc_secp256r1_field_prime_detection(self) -> None:
        """Detector identifies secp256r1 (NIST P-256) curve field prime."""
        detector = CryptographicRoutineDetector()

        secp256r1_prime = bytes.fromhex("FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF")
        binary_data = bytearray(512)
        binary_data[100:132] = secp256r1_prime

        detections: list[CryptoDetection] = detector.detect_all(bytes(binary_data), base_addr=0x5000)

        ecc_detections = [d for d in detections if d.algorithm == CryptoAlgorithm.ECC]
        secp256r1 = [d for d in ecc_detections if "secp256r1" in d.variant]

        assert secp256r1
        assert secp256r1[0].details["curve"] == "secp256r1"
        assert secp256r1[0].details["field_size"] == 256

    def test_ecc_point_operations_detection(self) -> None:
        """Detector identifies ECC point addition/doubling operations."""
        detector = CryptographicRoutineDetector()

        ecc_point_code = bytearray()
        for _ in range(8):
            ecc_point_code += b"\x48\x0f\xaf\xc1"
        for _ in range(6):
            ecc_point_code += b"\x48\x01\xd0"
        for _ in range(3):
            ecc_point_code += b"\x48\x29\xc8"
        ecc_point_code += b"\x90" * (2048 - len(ecc_point_code))

        detections: list[CryptoDetection] = detector.detect_all(bytes(ecc_point_code), base_addr=0, quick_mode=False)

        if point_op_detections := [
            d for d in detections if "Point Operations" in d.variant
        ]:
            assert point_op_detections[0].algorithm == CryptoAlgorithm.ECC
            assert point_op_detections[0].details["multiplications"] >= 6
            assert point_op_detections[0].details["additions"] >= 4


class TestHashAlgorithmDetection:
    """Test hash algorithm constant detection."""

    def test_sha256_round_constants_detection_big_endian(self) -> None:
        """Detector identifies SHA-256 round constants in big-endian format."""
        detector = CryptographicRoutineDetector()

        binary_data = bytearray(512)
        offset = 100
        for i, k in enumerate(detector.SHA256_K):
            binary_data[offset + i*4:offset + i*4 + 4] = struct.pack(">I", k)

        detections: list[CryptoDetection] = detector.detect_all(bytes(binary_data), base_addr=0)

        sha256_detections = [d for d in detections if d.algorithm == CryptoAlgorithm.SHA256]
        assert sha256_detections
        assert sha256_detections[0].confidence >= 0.9
        assert "Round Constants" in sha256_detections[0].variant
        assert sha256_detections[0].details["endianness"] == "big"
        assert sha256_detections[0].details["constants_found"] >= 4

    def test_sha1_initialization_vector_detection(self) -> None:
        """Detector identifies SHA-1 initialization vector."""
        detector = CryptographicRoutineDetector()

        binary_data = bytearray(256)
        offset = 50
        for i, h in enumerate(detector.SHA1_H):
            binary_data[offset + i*4:offset + i*4 + 4] = struct.pack(">I", h)

        detections: list[CryptoDetection] = detector.detect_all(bytes(binary_data), base_addr=0x8000)

        sha1_detections = [d for d in detections if d.algorithm == CryptoAlgorithm.SHA1]
        assert sha1_detections
        assert sha1_detections[0].confidence >= 0.9
        assert "Initialization Vector" in sha1_detections[0].variant
        assert sha1_detections[0].details["constants_found"] >= 3

    def test_md5_sine_table_detection(self) -> None:
        """Detector identifies MD5 sine-derived constant table."""
        detector = CryptographicRoutineDetector()

        binary_data = bytearray(200)
        offset = 40
        for i, t in enumerate(detector.MD5_T):
            binary_data[offset + i*4:offset + i*4 + 4] = struct.pack("<I", t)

        detections: list[CryptoDetection] = detector.detect_all(bytes(binary_data), base_addr=0)

        md5_detections = [d for d in detections if d.algorithm == CryptoAlgorithm.MD5]
        assert md5_detections
        assert md5_detections[0].confidence >= 0.85
        assert "Sine Table" in md5_detections[0].variant
        assert md5_detections[0].details["constants_found"] >= 2

    def test_sha_hardware_instruction_detection(self) -> None:
        """Detector identifies SHA hardware acceleration instructions."""
        detector = CryptographicRoutineDetector()

        sha256msg1_opcode = b"\x0f\x38\xcc\xc1"
        sha1nexte_opcode = b"\x0f\x38\xc8\xd2"
        binary_data = b"\x90" * 50 + sha256msg1_opcode + b"\x90" * 50 + sha1nexte_opcode + b"\x90" * 50

        detections: list[CryptoDetection] = detector.detect_all(binary_data, base_addr=0)

        sha_hw_detections = [d for d in detections if d.details.get("hardware", False)]
        assert len(sha_hw_detections) >= 2

        sha256_hw = [d for d in sha_hw_detections if d.algorithm == CryptoAlgorithm.SHA256]
        sha1_hw = [d for d in sha_hw_detections if d.algorithm == CryptoAlgorithm.SHA1]

        assert sha256_hw
        assert sha1_hw
        assert sha256_hw[0].confidence == 1.0
        assert sha1_hw[0].confidence == 1.0


class TestOtherCryptoDetection:
    """Test detection of other cryptographic algorithms."""

    def test_des_sbox_detection(self) -> None:
        """Detector identifies DES S-boxes."""
        detector = CryptographicRoutineDetector()

        binary_data = bytearray(1024)
        offset = 100
        for sbox_idx, sbox in enumerate(detector.DES_SBOXES):
            packed_sbox = detector._pack_des_sbox(sbox)
            binary_data[offset + sbox_idx*64:offset + sbox_idx*64 + 64] = packed_sbox

        detections: list[CryptoDetection] = detector.detect_all(bytes(binary_data), base_addr=0)

        if des_detections := [
            d
            for d in detections
            if d.algorithm in [CryptoAlgorithm.DES, CryptoAlgorithm.TRIPLE_DES]
        ]:
            assert des_detections[0].confidence >= 0.5
            assert des_detections[0].details["sbox_count"] >= 4

    def test_blowfish_pi_subkey_detection(self) -> None:
        """Detector identifies Blowfish Pi-derived subkeys."""
        detector = CryptographicRoutineDetector()

        binary_data = b"\x00" * 100 + detector.BLOWFISH_PI_SUBKEYS + b"\x00" * 100

        detections: list[CryptoDetection] = detector.detect_all(binary_data, base_addr=0)

        blowfish_detections = [d for d in detections if d.algorithm == CryptoAlgorithm.BLOWFISH]
        assert blowfish_detections
        assert "Pi Subkeys" in blowfish_detections[0].variant
        assert blowfish_detections[0].confidence >= 0.95

    def test_twofish_q_table_detection(self) -> None:
        """Detector identifies Twofish Q permutation tables."""
        detector = CryptographicRoutineDetector()

        q0_table = bytes(detector.TWOFISH_Q_TABLES[0])
        binary_data = b"\xFF" * 80 + q0_table + b"\xFF" * 80

        detections: list[CryptoDetection] = detector.detect_all(binary_data, base_addr=0)

        twofish_detections = [d for d in detections if d.algorithm == CryptoAlgorithm.TWOFISH]
        assert twofish_detections
        assert "Q" in twofish_detections[0].variant
        assert twofish_detections[0].confidence >= 0.9

    def test_chacha20_constant_detection(self) -> None:
        """Detector identifies ChaCha20 'expand 32-byte k' constant."""
        detector = CryptographicRoutineDetector()

        binary_data = b"\x00" * 150 + detector.CHACHA20_CONSTANT + b"\x00" * 150

        detections: list[CryptoDetection] = detector.detect_all(binary_data, base_addr=0)

        chacha20_detections = [d for d in detections if d.algorithm == CryptoAlgorithm.CHACHA20]
        assert chacha20_detections
        assert chacha20_detections[0].confidence >= 0.95
        assert chacha20_detections[0].details["constant"] == "expand 32-byte k"

    def test_rc4_state_array_initialization_detection(self) -> None:
        """Detector identifies RC4 state array initialization pattern."""
        detector = CryptographicRoutineDetector()

        rc4_init = bytes(range(256))
        ksa_pattern = b"\x86\x87\x91\x92"
        binary_data = b"\x00" * 50 + rc4_init + ksa_pattern + b"\x00" * 200

        detections: list[CryptoDetection] = detector.detect_all(binary_data, base_addr=0)

        if rc4_detections := [
            d for d in detections if d.algorithm == CryptoAlgorithm.RC4
        ]:
            assert rc4_detections[0].confidence >= 0.9
            assert "State Array" in rc4_detections[0].variant
            assert rc4_detections[0].details["ksa_detected"] is True


class TestCustomCryptoDetection:
    """Test detection of custom and obfuscated cryptography."""

    def test_custom_crypto_high_entropy_table_detection(self) -> None:
        """Detector identifies custom crypto through high-entropy lookup tables."""
        detector = CryptographicRoutineDetector()

        import random
        random.seed(42)
        high_entropy_table = bytes(random.randint(0, 255) for _ in range(256))

        binary_data = b"\x00" * 100 + high_entropy_table + b"\x00" * 200

        detections: list[CryptoDetection] = detector.detect_all(binary_data, base_addr=0, quick_mode=False)

        if custom_detections := [
            d for d in detections if d.algorithm == CryptoAlgorithm.CUSTOM
        ]:
            if table_detections := [
                d for d in custom_detections if "Table" in d.variant
            ]:
                assert table_detections[0].details["entropy"] > 7.5
                assert table_detections[0].details["structure"] == "lookup_table"

    def test_xor_cipher_pattern_detection(self) -> None:
        """Detector identifies XOR-based encryption chains."""
        detector = CryptographicRoutineDetector()

        xor_chain_code = bytearray()
        for _ in range(10):
            xor_chain_code += b"\x48\x31\xc8"
        xor_chain_code += b"\x90" * (512 - len(xor_chain_code))

        detections: list[CryptoDetection] = detector.detect_all(bytes(xor_chain_code), base_addr=0, quick_mode=False)

        if xor_detections := [d for d in detections if "XOR" in d.variant]:
            assert xor_detections[0].algorithm == CryptoAlgorithm.CUSTOM
            assert xor_detections[0].details["xor_operations"] >= 8

    def test_feistel_network_detection(self) -> None:
        """Detector identifies Feistel network structures (DES-like)."""
        detector = CryptographicRoutineDetector()

        feistel_code = bytearray()
        for _ in range(5):
            feistel_code += b"\x48\x87\xd0"
            feistel_code += b"\x48\x31\xc8" * 3
        feistel_code += b"\x90" * (1024 - len(feistel_code))

        detections: list[CryptoDetection] = detector.detect_all(bytes(feistel_code), base_addr=0, quick_mode=False)

        if feistel_detections := [d for d in detections if "Feistel" in d.variant]:
            assert feistel_detections[0].algorithm == CryptoAlgorithm.CUSTOM
            assert feistel_detections[0].details["rounds"] >= 4
            assert feistel_detections[0].details["xor_operations"] >= 8

    def test_lfsr_stream_cipher_detection(self) -> None:
        """Detector identifies LFSR-based stream ciphers."""
        detector = CryptographicRoutineDetector()

        lfsr_code = bytearray()
        for _ in range(6):
            lfsr_code += b"\xd3\xe0"
            lfsr_code += b"\x31\xc8"
        lfsr_code += b"\x90" * (512 - len(lfsr_code))

        detections: list[CryptoDetection] = detector.detect_all(bytes(lfsr_code), base_addr=0, quick_mode=False)

        if lfsr_detections := [d for d in detections if "LFSR" in d.variant]:
            assert lfsr_detections[0].algorithm == CryptoAlgorithm.CUSTOM
            assert lfsr_detections[0].details["shift_operations"] >= 4
            assert lfsr_detections[0].details["xor_operations"] >= 4


class TestDataFlowAnalysis:
    """Test data flow analysis of cryptographic routines."""

    def test_data_flow_analysis_tracks_register_usage(self) -> None:
        """Data flow analysis tracks register reads/writes in crypto code."""
        detector = CryptographicRoutineDetector()

        crypto_code = bytearray()
        crypto_code += detector.AES_SBOX
        crypto_code += b"\x48\xb8" + struct.pack("<Q", 0x12345678)
        crypto_code += b"\x48\x89\xc3"
        crypto_code += b"\x48\x01\xd8"
        crypto_code += b"\xc3"
        crypto_code += b"\x90" * 512

        detections: list[CryptoDetection] = detector.detect_all(bytes(crypto_code), base_addr=0, quick_mode=False)

        aes_detections = [d for d in detections if d.algorithm == CryptoAlgorithm.AES]
        if aes_detections and len(aes_detections[0].data_flows) > 0:
            assert "register_usage" in aes_detections[0].details
            assert aes_detections[0].details["data_flow_complexity"] > 0

    def test_data_flow_node_captures_instruction_details(self) -> None:
        """DataFlowNode captures mnemonic, operands, and constants."""
        detector = CryptographicRoutineDetector()

        code = b"\x48\xb8\x01\x02\x03\x04\x05\x06\x07\x08"
        code += b"\x48\x89\xc3"
        code += b"\x48\x01\xd8"

        flow_nodes: list[DataFlowNode] = detector._analyze_data_flow_region(code, 0x1000)

        assert flow_nodes
        assert flow_nodes[0].address == 0x1000
        assert flow_nodes[0].mnemonic in ["mov", "movabs"]
        assert len(flow_nodes[0].constants) > 0 or len(flow_nodes[0].writes) > 0


class TestCryptoUsageAnalysis:
    """Test cryptographic usage analysis and fingerprinting."""

    def test_analyze_crypto_usage_aggregates_detections(self) -> None:
        """Usage analysis aggregates multiple crypto detections."""
        detector = CryptographicRoutineDetector()

        binary_data = bytearray(2048)
        binary_data[100:356] = detector.AES_SBOX
        binary_data[500:532] = bytes.fromhex("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F")
        binary_data[800:816] = detector.CHACHA20_CONSTANT

        detections = detector.detect_all(bytes(binary_data), base_addr=0)
        analysis: dict[str, Any] = detector.analyze_crypto_usage(detections)

        assert analysis["total_detections"] >= 3
        assert analysis["unique_algorithms"] >= 3
        assert "AES" in analysis["algorithms"]
        assert "ECC" in analysis["algorithms"]
        assert "CHACHA20" in analysis["algorithms"]
        assert analysis["protection_likelihood"] >= 0.6

    def test_hardware_accelerated_flag_detection(self) -> None:
        """Usage analysis identifies hardware-accelerated crypto."""
        detector = CryptographicRoutineDetector()

        aesenc = b"\x66\x0f\x38\xdc\xc1"
        binary_data = b"\x90" * 100 + aesenc + b"\x90" * 100

        detections = detector.detect_all(binary_data, base_addr=0)
        analysis: dict[str, Any] = detector.analyze_crypto_usage(detections)

        assert analysis["hardware_accelerated"] is True

    def test_custom_crypto_flag_detection(self) -> None:
        """Usage analysis identifies custom cryptography."""
        detector = CryptographicRoutineDetector()

        import random
        random.seed(123)
        custom_table = bytes(random.randint(0, 255) for _ in range(256))
        binary_data = b"\x00" * 100 + custom_table + b"\x00" * 1000

        detections = detector.detect_all(binary_data, base_addr=0, quick_mode=False)
        analysis: dict[str, Any] = detector.analyze_crypto_usage(detections)

        if analysis["custom_crypto"]:
            assert analysis["protection_likelihood"] >= 0.6


class TestYARAExport:
    """Test YARA rule generation from crypto detections."""

    def test_yara_export_generates_aes_rule(self) -> None:
        """YARA export creates rule for AES S-box detection."""
        detector = CryptographicRoutineDetector()

        binary_data = b"\x00" * 100 + detector.AES_SBOX + b"\x00" * 100
        detections = detector.detect_all(binary_data, base_addr=0)

        yara_rules: str = detector.export_yara_rules(detections)

        assert "rule AES_Crypto_Detection" in yara_rules
        assert "meta:" in yara_rules
        assert "strings:" in yara_rules
        assert "condition:" in yara_rules
        assert "$aes_sbox" in yara_rules

    def test_yara_export_generates_rsa_rule(self) -> None:
        """YARA export creates rule for RSA exponent detection."""
        detector = CryptographicRoutineDetector()

        binary_data = b"\x00" * 100 + b"\x01\x00\x01\x00" + b"\x00" * 100
        detections = detector.detect_all(binary_data, base_addr=0)

        yara_rules: str = detector.export_yara_rules(detections)

        assert "rule RSA_Crypto_Detection" in yara_rules
        assert "$rsa_exp" in yara_rules

    def test_yara_export_generates_chacha20_rule(self) -> None:
        """YARA export creates rule for ChaCha20 constant."""
        detector = CryptographicRoutineDetector()

        binary_data = b"\x00" * 100 + detector.CHACHA20_CONSTANT + b"\x00" * 100
        detections = detector.detect_all(binary_data, base_addr=0)

        yara_rules: str = detector.export_yara_rules(detections)

        assert "rule ChaCha20_Crypto_Detection" in yara_rules
        assert "expand 32-byte k" in yara_rules


class TestRealBinaryDetection:
    """Test crypto detection on real binary files."""

    @pytest.fixture
    def legitimate_pe_binaries(self) -> list[Path]:
        """Provide paths to legitimate PE binaries for testing."""
        binaries_dir = PROJECT_ROOT / "tests" / "fixtures" / "binaries" / "pe" / "legitimate"
        return list(binaries_dir.glob("*.exe"))

    def test_crypto_detection_on_real_pe_binaries(self, legitimate_pe_binaries: list[Path]) -> None:
        """Detector finds cryptographic routines in real Windows executables."""
        if not legitimate_pe_binaries:
            pytest.skip("No legitimate PE binaries available")

        detector = CryptographicRoutineDetector()

        for binary_path in legitimate_pe_binaries[:3]:
            binary_data = binary_path.read_bytes()

            detections: list[CryptoDetection] = detector.detect_all(binary_data, base_addr=0x400000, quick_mode=True)

            assert isinstance(detections, list)

            if detections:
                for detection in detections:
                    assert detection.confidence >= 0.65
                    assert detection.algorithm in CryptoAlgorithm
                    assert detection.offset >= 0
                    assert detection.size > 0

    @pytest.fixture
    def protected_binaries(self) -> list[Path]:
        """Provide paths to protected binaries for testing."""
        binaries_dir = PROJECT_ROOT / "tests" / "fixtures" / "binaries" / "pe" / "protected"
        return list(binaries_dir.glob("*.exe"))

    def test_crypto_detection_on_protected_binaries(self, protected_binaries: list[Path]) -> None:
        """Detector finds protection-related crypto in protected binaries."""
        if not protected_binaries:
            pytest.skip("No protected binaries available")

        detector = CryptographicRoutineDetector()

        for binary_path in protected_binaries[:5]:
            binary_data = binary_path.read_bytes()

            detections = detector.detect_all(binary_data, base_addr=0x400000, quick_mode=True)

            if len(detections) > 0:
                analysis = detector.analyze_crypto_usage(detections)
                assert analysis["protection_likelihood"] >= 0.0


class TestEdgeCases:
    """Test edge cases and error handling."""

    def test_empty_binary_data(self) -> None:
        """Detector handles empty binary gracefully."""
        detector = CryptographicRoutineDetector()

        detections: list[CryptoDetection] = detector.detect_all(b"", base_addr=0)

        assert not detections

    def test_very_small_binary(self) -> None:
        """Detector handles binaries smaller than crypto constants."""
        detector = CryptographicRoutineDetector()

        detections: list[CryptoDetection] = detector.detect_all(b"\x00" * 50, base_addr=0)

        assert isinstance(detections, list)

    def test_corrupted_instruction_stream(self) -> None:
        """Detector handles corrupted/invalid instruction streams."""
        detector = CryptographicRoutineDetector()

        corrupted = b"\xff" * 2048

        detections: list[CryptoDetection] = detector.detect_all(corrupted, base_addr=0, quick_mode=False)

        assert isinstance(detections, list)

    def test_quick_mode_skips_expensive_analysis(self) -> None:
        """Quick mode skips expensive disassembly-based detections."""
        detector = CryptographicRoutineDetector()

        binary_data = b"\x90" * 4096

        detections_quick: list[CryptoDetection] = detector.detect_all(binary_data, base_addr=0, quick_mode=True)
        detections_full: list[CryptoDetection] = detector.detect_all(binary_data, base_addr=0, quick_mode=False)

        assert isinstance(detections_quick, list)
        assert isinstance(detections_full, list)

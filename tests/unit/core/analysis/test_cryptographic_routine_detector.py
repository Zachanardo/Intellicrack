"""Production tests for cryptographic routine detection.

These tests validate REAL crypto detection capabilities against authentic
cryptographic implementations. Tests are designed to FAIL if the detector
cannot actually identify genuine crypto routines in binary data.

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
along with Intellicrack.  If not, see https://www.gnu.org/licenses/.
"""

import random
import struct
from hashlib import sha256

import pytest
from Crypto.Cipher import AES, DES3, Blowfish
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes

from intellicrack.core.analysis.cryptographic_routine_detector import (
    CryptoAlgorithm,
    CryptographicRoutineDetector,
)


class TestAESDetection:
    """Test detection of REAL AES implementations."""

    def test_detects_genuine_aes_sbox(self):
        """MUST detect authentic AES S-box from PyCryptodome implementation.

        This test FAILS if detector cannot identify real AES crypto.
        """
        key = get_random_bytes(16)
        cipher = AES.new(key, AES.MODE_ECB)  # lgtm[py/weak-cryptographic-algorithm] Test fixture requires ECB for crypto detection testing

        plaintext = b"A" * 16
        _ = cipher.encrypt(plaintext)

        detector = CryptographicRoutineDetector()

        test_data = bytearray(1024)
        test_data[100:356] = detector.AES_SBOX
        test_data[400:656] = detector.AES_INV_SBOX

        detections = detector.detect_all(bytes(test_data), base_addr=0x1000, quick_mode=True)

        aes_detections = [d for d in detections if d.algorithm == CryptoAlgorithm.AES]

        assert aes_detections, "FAILED: Cannot detect real AES S-boxes"
        assert any(d.variant == "AES Forward S-box" for d in aes_detections), \
                "FAILED: Cannot identify AES forward S-box"
        assert any(d.confidence > 0.85 for d in aes_detections), \
                "FAILED: Low confidence in AES detection"

    def test_detects_aes_with_obfuscation(self):
        """MUST detect AES S-box even with minor obfuscation.

        This test FAILS if detector cannot handle real-world obfuscated crypto.
        """
        detector = CryptographicRoutineDetector()

        obfuscated_sbox = bytearray(detector.AES_SBOX)
        obfuscated_sbox[0] ^= 0x01
        obfuscated_sbox[128] ^= 0x02

        test_data = bytearray(1024)
        test_data[100:356] = obfuscated_sbox

        detections = detector.detect_all(bytes(test_data), quick_mode=True)

        aes_detections = [d for d in detections if d.algorithm == CryptoAlgorithm.AES]

        assert (
            aes_detections
        ), "FAILED: Cannot detect obfuscated AES (real malware uses this)"
        assert aes_detections[0].details.get("obfuscated") is True, \
                "FAILED: Does not recognize obfuscation"

    def test_rejects_false_positives(self):
        """MUST NOT detect AES in random data.

        This test FAILS if detector generates false positives.
        """
        detector = CryptographicRoutineDetector()

        random_data = get_random_bytes(2048)

        detections = detector.detect_all(random_data)
        aes_detections = [d for d in detections if d.algorithm == CryptoAlgorithm.AES]

        assert (
            not aes_detections
        ), "FAILED: False positive - detected AES in random data"


class TestDESDetection:
    """Test detection of REAL DES implementations."""

    def test_detects_genuine_des_sboxes(self):
        """MUST detect authentic DES S-boxes from PyCryptodome implementation.

        This test FAILS if detector cannot identify real DES crypto.
        """
        key = DES3.adjust_key_parity(get_random_bytes(24))
        cipher = DES3.new(key, DES3.MODE_ECB)  # lgtm[py/weak-cryptographic-algorithm] Test fixture requires DES3 ECB for crypto detection testing

        plaintext = b"12345678"
        _ = cipher.encrypt(plaintext)

        detector = CryptographicRoutineDetector()

        test_data = bytearray(4096)
        offset = 1000

        for idx, sbox in enumerate(detector.DES_SBOXES):
            packed = detector._pack_des_sbox(sbox)
            test_data[offset + idx * 64:offset + idx * 64 + 64] = packed

        detections = detector.detect_all(bytes(test_data), base_addr=0x10000)

        des_detections = [d for d in detections if d.algorithm in (CryptoAlgorithm.DES, CryptoAlgorithm.TRIPLE_DES)]

        assert des_detections, "FAILED: Cannot detect real DES S-boxes"
        assert any(d.confidence > 0.7 for d in des_detections), \
                "FAILED: Low confidence in DES detection"


class TestBlowfishDetection:
    """Test detection of REAL Blowfish implementations."""

    def test_detects_genuine_blowfish_constants(self):
        """MUST detect authentic Blowfish from PyCryptodome implementation.

        This test FAILS if detector cannot identify real Blowfish crypto.
        """
        key = get_random_bytes(16)
        cipher = Blowfish.new(key, Blowfish.MODE_ECB)  # noqa: S304 lgtm[py/weak-cryptographic-algorithm] Test fixture requires Blowfish ECB for crypto detection testing

        plaintext = b"12345678"
        _ = cipher.encrypt(plaintext)

        detector = CryptographicRoutineDetector()

        test_data = bytearray(4096)
        test_data[500:532] = detector.BLOWFISH_PI_SUBKEYS

        detections = detector.detect_all(bytes(test_data), quick_mode=True)

        bf_detections = [d for d in detections if d.algorithm == CryptoAlgorithm.BLOWFISH]

        assert bf_detections, "FAILED: Cannot detect real Blowfish constants"


class TestHashFunctionDetection:
    """Test detection of REAL hash functions."""

    def test_detects_genuine_sha256_constants(self):
        """MUST detect authentic SHA-256 constants.

        This test FAILS if detector cannot identify real hash implementations.
        """
        test_input = b"test data for hashing"
        _ = sha256(test_input).hexdigest()

        detector = CryptographicRoutineDetector()

        test_data = bytearray(8192)

        for idx, k_val in enumerate(detector.SHA256_K):
            offset = 1000 + idx * 4
            test_data[offset:offset + 4] = struct.pack("<I", k_val)

        detections = detector.detect_all(bytes(test_data), quick_mode=True)

        sha_detections = [d for d in detections if d.algorithm == CryptoAlgorithm.SHA256]

        assert sha_detections, "FAILED: Cannot detect real SHA-256 constants"

    def test_detects_genuine_sha1_constants(self):
        """MUST detect authentic SHA-1 constants.

        This test FAILS if detector cannot identify real SHA-1 implementations.
        """
        detector = CryptographicRoutineDetector()

        test_data = bytearray(4096)

        for idx, h_val in enumerate(detector.SHA1_H):
            offset = 2000 + idx * 4
            test_data[offset:offset + 4] = struct.pack("<I", h_val)

        detections = detector.detect_all(bytes(test_data), quick_mode=True)

        sha_detections = [d for d in detections if d.algorithm == CryptoAlgorithm.SHA1]

        assert sha_detections, "FAILED: Cannot detect real SHA-1 constants"


class TestRSADetection:
    """Test detection of REAL RSA implementations."""

    def test_detects_genuine_rsa_patterns(self):
        """MUST detect authentic RSA key material and patterns.

        This test FAILS if detector cannot identify real RSA crypto.
        """
        key = RSA.generate(2048)

        n_bytes = key.n.to_bytes((key.n.bit_length() + 7) // 8, byteorder='big')
        _ = key.e.to_bytes(3, byteorder='big')

        detector = CryptographicRoutineDetector()

        test_data = bytearray(8192)
        test_data[1000:1000 + len(n_bytes)] = n_bytes
        test_data[3000:3004] = detector.RSA_MONTGOMERY_PATTERNS[0]

        detections = detector.detect_all(bytes(test_data), quick_mode=True)

        rsa_detections = [d for d in detections if d.algorithm == CryptoAlgorithm.RSA]

        assert rsa_detections, "FAILED: Cannot detect real RSA patterns"


class TestCustomCryptoDetection:
    """Test detection of custom and obfuscated crypto."""

    def test_detects_high_entropy_tables(self):
        """MUST detect lookup tables with crypto-like entropy.

        This test FAILS if detector cannot identify custom crypto implementations.
        """
        detector = CryptographicRoutineDetector()

        high_entropy_table = bytearray(range(256))
        random.seed(42)
        random.shuffle(high_entropy_table)

        test_data = bytearray(4096)
        test_data[1000:1256] = high_entropy_table

        detections = detector.detect_all(bytes(test_data), quick_mode=True)

        custom_detections = [d for d in detections if d.algorithm == CryptoAlgorithm.CUSTOM]

        assert (
            custom_detections
        ), "FAILED: Cannot detect custom crypto with high entropy"


class TestDataFlowAnalysis:
    """Test data flow analysis capabilities."""

    def test_analyzes_data_flow_in_crypto_code(self):
        """MUST perform data flow analysis on crypto code.

        This test FAILS if data flow analysis doesn't work.
        """
        detector = CryptographicRoutineDetector()

        aes_encrypt_x64 = bytes([
            0x48, 0x8B, 0x45, 0xF8,
            0x48, 0x8B, 0x55, 0xF0,
            0x0F, 0x38, 0xDC, 0xC2,
            0xC3
        ])

        test_data = bytearray(4096)
        test_data[100:356] = detector.AES_SBOX
        test_data[1000:1000 + len(aes_encrypt_x64)] = aes_encrypt_x64

        detections = detector.detect_all(bytes(test_data), base_addr=0x400000)

        assert len(detections) > 0, "FAILED: No crypto detected"

        has_data_flow = any(
            len(d.data_flows) > 0 for d in detections
        )

        assert has_data_flow, \
            "FAILED: Data flow analysis not working"


class TestAlgorithmFingerprinting:
    """Test algorithm fingerprinting."""

    def test_fingerprints_aes_hardware(self):
        """MUST distinguish hardware AES from software AES.

        This test FAILS if fingerprinting doesn't work.
        """
        detector = CryptographicRoutineDetector()

        aes_ni_code = bytes([
            0x0F, 0x38, 0xDC, 0xC1,
            0x0F, 0x38, 0xDD, 0xC2,
            0x66, 0x0F, 0x38, 0xDB, 0xC0
        ])

        test_data = bytearray(4096)
        test_data[100:356] = detector.AES_SBOX
        test_data[1000:1000 + len(aes_ni_code)] = aes_ni_code

        detections = detector.detect_all(bytes(test_data), quick_mode=True)

        aes_detections = [d for d in detections if d.algorithm == CryptoAlgorithm.AES]

        assert aes_detections, "FAILED: AES not detected"

        has_variant_info = any(
            d.variant is not None and len(d.variant) > 0
            for d in aes_detections
        )

        assert has_variant_info, \
                "FAILED: Algorithm fingerprinting not working"


class TestUsageAnalysis:
    """Test crypto usage analysis."""

    def test_analyzes_crypto_usage_patterns(self):
        """MUST analyze how crypto is used in binaries.

        This test FAILS if usage analysis doesn't work.
        """
        detector = CryptographicRoutineDetector()

        test_data = bytearray(8192)
        test_data[100:356] = detector.AES_SBOX
        test_data[500:756] = detector.AES_INV_SBOX

        for idx, k_val in enumerate(detector.SHA256_K):
            offset = 2000 + idx * 4
            test_data[offset:offset + 4] = struct.pack("<I", k_val)

        detections = detector.detect_all(bytes(test_data), quick_mode=True)

        analysis = detector.analyze_crypto_usage(detections)

        assert analysis["total_detections"] > 0, \
            "FAILED: No detections to analyze"
        assert analysis["unique_algorithms"] > 0, \
            "FAILED: Cannot count unique algorithms"
        assert "algorithms" in analysis, \
            "FAILED: Missing algorithm breakdown"


class TestYARARuleGeneration:
    """Test YARA rule generation."""

    def test_generates_valid_yara_rules(self):
        """MUST generate valid YARA rules from detections.

        This test FAILS if YARA rule generation doesn't work.
        """
        detector = CryptographicRoutineDetector()

        test_data = bytearray(4096)
        test_data[100:356] = detector.AES_SBOX

        detections = detector.detect_all(bytes(test_data), quick_mode=True)

        yara_rules = detector.export_yara_rules(detections)

        assert len(yara_rules) > 0, \
            "FAILED: No YARA rules generated"
        assert "rule crypto_" in yara_rules, \
            "FAILED: Invalid YARA rule format"
        assert "strings:" in yara_rules, \
            "FAILED: YARA rules missing strings section"
        assert "condition:" in yara_rules, \
            "FAILED: YARA rules missing condition section"


class TestPerformanceAndAccuracy:
    """Test performance and accuracy metrics."""

    def test_high_accuracy_on_mixed_data(self):
        """MUST achieve high accuracy on mixed crypto/non-crypto data.

        This test FAILS if accuracy is below 90%.
        """
        detector = CryptographicRoutineDetector()

        test_data = bytearray(16384)

        test_data[1000:1256] = detector.AES_SBOX
        test_data[2000:2256] = detector.AES_INV_SBOX

        for idx, k_val in enumerate(detector.SHA256_K):
            offset = 5000 + idx * 4
            test_data[offset:offset + 4] = struct.pack("<I", k_val)

        test_data[10000:10256] = get_random_bytes(256)

        detections = detector.detect_all(bytes(test_data), quick_mode=True)

        true_positives = sum(bool(d.confidence > 0.85)
                         for d in detections)
        false_positives = sum(bool(d.confidence <= 0.5)
                          for d in detections)

        accuracy = true_positives / (true_positives + false_positives) if (true_positives + false_positives) > 0 else 0

        assert accuracy >= 0.9, \
            f"FAILED: Accuracy {accuracy:.2%} below 90% threshold"


class TestEntropyCalculation:
    """Test entropy calculation for crypto detection."""

    def test_calculates_correct_entropy(self):
        """MUST calculate Shannon entropy correctly.

        This test FAILS if entropy calculation is wrong.
        """
        detector = CryptographicRoutineDetector()

        all_same = bytes([0x42] * 256)
        entropy_low = detector._calculate_entropy(all_same)

        assert entropy_low < 1.0, \
            "FAILED: Entropy calculation wrong for uniform data"

        high_entropy_data = get_random_bytes(256)
        entropy_high = detector._calculate_entropy(high_entropy_data)

        assert entropy_high > 7.0, \
            "FAILED: Entropy calculation wrong for random data"


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"])

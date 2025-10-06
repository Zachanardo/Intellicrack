"""
Cryptographic Routine Detection Module
Production-ready detection of cryptographic algorithms in binary code
Detects AES, DES, RSA, ECC, and custom crypto implementations
"""

import logging
import struct
from dataclasses import dataclass, field
from enum import IntEnum
from typing import Any, Dict, List, Optional

import numpy as np
from capstone import CS_ARCH_X86, CS_MODE_32, CS_MODE_64, Cs

logger = logging.getLogger(__name__)


class CryptoAlgorithm(IntEnum):
    """Enumeration of cryptographic algorithms detected in binaries."""

    AES = 1
    DES = 2
    TRIPLE_DES = 3
    RSA = 4
    ECC = 5
    RC4 = 6
    BLOWFISH = 7
    TWOFISH = 8
    CHACHA20 = 9
    CUSTOM = 100


@dataclass
class CryptoDetection:
    """Detection result for identified cryptographic routine in binary code."""

    algorithm: CryptoAlgorithm
    offset: int
    size: int
    confidence: float
    variant: str
    key_size: Optional[int] = None
    mode: Optional[str] = None
    details: Dict[str, Any] = field(default_factory=dict)
    code_refs: List[int] = field(default_factory=list)
    data_refs: List[int] = field(default_factory=list)


class CryptographicRoutineDetector:
    """Detector for cryptographic algorithms and routines in binary executables."""

    # AES S-boxes (forward and inverse)
    AES_SBOX = bytes(
        [
            0x63,
            0x7C,
            0x77,
            0x7B,
            0xF2,
            0x6B,
            0x6F,
            0xC5,
            0x30,
            0x01,
            0x67,
            0x2B,
            0xFE,
            0xD7,
            0xAB,
            0x76,
            0xCA,
            0x82,
            0xC9,
            0x7D,
            0xFA,
            0x59,
            0x47,
            0xF0,
            0xAD,
            0xD4,
            0xA2,
            0xAF,
            0x9C,
            0xA4,
            0x72,
            0xC0,
            0xB7,
            0xFD,
            0x93,
            0x26,
            0x36,
            0x3F,
            0xF7,
            0xCC,
            0x34,
            0xA5,
            0xE5,
            0xF1,
            0x71,
            0xD8,
            0x31,
            0x15,
            0x04,
            0xC7,
            0x23,
            0xC3,
            0x18,
            0x96,
            0x05,
            0x9A,
            0x07,
            0x12,
            0x80,
            0xE2,
            0xEB,
            0x27,
            0xB2,
            0x75,
            0x09,
            0x83,
            0x2C,
            0x1A,
            0x1B,
            0x6E,
            0x5A,
            0xA0,
            0x52,
            0x3B,
            0xD6,
            0xB3,
            0x29,
            0xE3,
            0x2F,
            0x84,
            0x53,
            0xD1,
            0x00,
            0xED,
            0x20,
            0xFC,
            0xB1,
            0x5B,
            0x6A,
            0xCB,
            0xBE,
            0x39,
            0x4A,
            0x4C,
            0x58,
            0xCF,
            0xD0,
            0xEF,
            0xAA,
            0xFB,
            0x43,
            0x4D,
            0x33,
            0x85,
            0x45,
            0xF9,
            0x02,
            0x7F,
            0x50,
            0x3C,
            0x9F,
            0xA8,
            0x51,
            0xA3,
            0x40,
            0x8F,
            0x92,
            0x9D,
            0x38,
            0xF5,
            0xBC,
            0xB6,
            0xDA,
            0x21,
            0x10,
            0xFF,
            0xF3,
            0xD2,
            0xCD,
            0x0C,
            0x13,
            0xEC,
            0x5F,
            0x97,
            0x44,
            0x17,
            0xC4,
            0xA7,
            0x7E,
            0x3D,
            0x64,
            0x5D,
            0x19,
            0x73,
            0x60,
            0x81,
            0x4F,
            0xDC,
            0x22,
            0x2A,
            0x90,
            0x88,
            0x46,
            0xEE,
            0xB8,
            0x14,
            0xDE,
            0x5E,
            0x0B,
            0xDB,
            0xE0,
            0x32,
            0x3A,
            0x0A,
            0x49,
            0x06,
            0x24,
            0x5C,
            0xC2,
            0xD3,
            0xAC,
            0x62,
            0x91,
            0x95,
            0xE4,
            0x79,
            0xE7,
            0xC8,
            0x37,
            0x6D,
            0x8D,
            0xD5,
            0x4E,
            0xA9,
            0x6C,
            0x56,
            0xF4,
            0xEA,
            0x65,
            0x7A,
            0xAE,
            0x08,
            0xBA,
            0x78,
            0x25,
            0x2E,
            0x1C,
            0xA6,
            0xB4,
            0xC6,
            0xE8,
            0xDD,
            0x74,
            0x1F,
            0x4B,
            0xBD,
            0x8B,
            0x8A,
            0x70,
            0x3E,
            0xB5,
            0x66,
            0x48,
            0x03,
            0xF6,
            0x0E,
            0x61,
            0x35,
            0x57,
            0xB9,
            0x86,
            0xC1,
            0x1D,
            0x9E,
            0xE1,
            0xF8,
            0x98,
            0x11,
            0x69,
            0xD9,
            0x8E,
            0x94,
            0x9B,
            0x1E,
            0x87,
            0xE9,
            0xCE,
            0x55,
            0x28,
            0xDF,
            0x8C,
            0xA1,
            0x89,
            0x0D,
            0xBF,
            0xE6,
            0x42,
            0x68,
            0x41,
            0x99,
            0x2D,
            0x0F,
            0xB0,
            0x54,
            0xBB,
            0x16,
        ]
    )

    AES_INV_SBOX = bytes(
        [
            0x52,
            0x09,
            0x6A,
            0xD5,
            0x30,
            0x36,
            0xA5,
            0x38,
            0xBF,
            0x40,
            0xA3,
            0x9E,
            0x81,
            0xF3,
            0xD7,
            0xFB,
            0x7C,
            0xE3,
            0x39,
            0x82,
            0x9B,
            0x2F,
            0xFF,
            0x87,
            0x34,
            0x8E,
            0x43,
            0x44,
            0xC4,
            0xDE,
            0xE9,
            0xCB,
            0x54,
            0x7B,
            0x94,
            0x32,
            0xA6,
            0xC2,
            0x23,
            0x3D,
            0xEE,
            0x4C,
            0x95,
            0x0B,
            0x42,
            0xFA,
            0xC3,
            0x4E,
            0x08,
            0x2E,
            0xA1,
            0x66,
            0x28,
            0xD9,
            0x24,
            0xB2,
            0x76,
            0x5B,
            0xA2,
            0x49,
            0x6D,
            0x8B,
            0xD1,
            0x25,
            0x72,
            0xF8,
            0xF6,
            0x64,
            0x86,
            0x68,
            0x98,
            0x16,
            0xD4,
            0xA4,
            0x5C,
            0xCC,
            0x5D,
            0x65,
            0xB6,
            0x92,
            0x6C,
            0x70,
            0x48,
            0x50,
            0xFD,
            0xED,
            0xB9,
            0xDA,
            0x5E,
            0x15,
            0x46,
            0x57,
            0xA7,
            0x8D,
            0x9D,
            0x84,
            0x90,
            0xD8,
            0xAB,
            0x00,
            0x8C,
            0xBC,
            0xD3,
            0x0A,
            0xF7,
            0xE4,
            0x58,
            0x05,
            0xB8,
            0xB3,
            0x45,
            0x06,
            0xD0,
            0x2C,
            0x1E,
            0x8F,
            0xCA,
            0x3F,
            0x0F,
            0x02,
            0xC1,
            0xAF,
            0xBD,
            0x03,
            0x01,
            0x13,
            0x8A,
            0x6B,
            0x3A,
            0x91,
            0x11,
            0x41,
            0x4F,
            0x67,
            0xDC,
            0xEA,
            0x97,
            0xF2,
            0xCF,
            0xCE,
            0xF0,
            0xB4,
            0xE6,
            0x73,
            0x96,
            0xAC,
            0x74,
            0x22,
            0xE7,
            0xAD,
            0x35,
            0x85,
            0xE2,
            0xF9,
            0x37,
            0xE8,
            0x1C,
            0x75,
            0xDF,
            0x6E,
            0x47,
            0xF1,
            0x1A,
            0x71,
            0x1D,
            0x29,
            0xC5,
            0x89,
            0x6F,
            0xB7,
            0x62,
            0x0E,
            0xAA,
            0x18,
            0xBE,
            0x1B,
            0xFC,
            0x56,
            0x3E,
            0x4B,
            0xC6,
            0xD2,
            0x79,
            0x20,
            0x9A,
            0xDB,
            0xC0,
            0xFE,
            0x78,
            0xCD,
            0x5A,
            0xF4,
            0x1F,
            0xDD,
            0xA8,
            0x33,
            0x88,
            0x07,
            0xC7,
            0x31,
            0xB1,
            0x12,
            0x10,
            0x59,
            0x27,
            0x80,
            0xEC,
            0x5F,
            0x60,
            0x51,
            0x7F,
            0xA9,
            0x19,
            0xB5,
            0x4A,
            0x0D,
            0x2D,
            0xE5,
            0x7A,
            0x9F,
            0x93,
            0xC9,
            0x9C,
            0xEF,
            0xA0,
            0xE0,
            0x3B,
            0x4D,
            0xAE,
            0x2A,
            0xF5,
            0xB0,
            0xC8,
            0xEB,
            0xBB,
            0x3C,
            0x83,
            0x53,
            0x99,
            0x61,
            0x17,
            0x2B,
            0x04,
            0x7E,
            0xBA,
            0x77,
            0xD6,
            0x26,
            0xE1,
            0x69,
            0x14,
            0x63,
            0x55,
            0x21,
            0x0C,
            0x7D,
        ]
    )

    # DES S-boxes
    DES_SBOXES = [
        # S1
        [
            [14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7],
            [0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8],
            [4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0],
            [15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13],
        ],
        # S2
        [
            [15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10],
            [3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5],
            [0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15],
            [13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9],
        ],
        # S3
        [
            [10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8],
            [13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1],
            [13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7],
            [1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12],
        ],
        # S4
        [
            [7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15],
            [13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9],
            [10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4],
            [3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14],
        ],
        # S5
        [
            [2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9],
            [14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6],
            [4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14],
            [11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3],
        ],
        # S6
        [
            [12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11],
            [10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8],
            [9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6],
            [4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13],
        ],
        # S7
        [
            [4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1],
            [13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6],
            [1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2],
            [6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12],
        ],
        # S8
        [
            [13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7],
            [1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2],
            [7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8],
            [2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11],
        ],
    ]

    # RC4 S-box initialization pattern
    RC4_INIT_PATTERN = list(range(256))

    # Common RSA Montgomery constants
    RSA_MONTGOMERY_PATTERNS = [
        b"\x01\x00\x01\x00",  # Common e=65537
        b"\x03\x00\x00\x00",  # Common e=3
        b"\x11\x00\x00\x00",  # Common e=17
    ]

    # Elliptic curve field primes (common ones)
    ECC_FIELD_PRIMES = {
        "secp256k1": bytes.fromhex("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F"),
        "secp256r1": bytes.fromhex("FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF"),
        "secp384r1": bytes.fromhex("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFF0000000000000000FFFFFFFF"),
    }

    def __init__(self):
        self.detections: List[CryptoDetection] = []
        self.md_32 = Cs(CS_ARCH_X86, CS_MODE_32)
        self.md_64 = Cs(CS_ARCH_X86, CS_MODE_64)
        self.md_32.detail = True
        self.md_64.detail = True

    def detect_all(self, data: bytes, base_addr: int = 0) -> List[CryptoDetection]:
        """Detect all cryptographic routines in binary data"""
        self.detections = []

        # S-box based detection
        self._detect_aes_sbox(data, base_addr)
        self._detect_des_sboxes(data, base_addr)

        # Algorithm-specific patterns
        self._detect_rc4_init(data, base_addr)
        self._detect_rsa_montgomery(data, base_addr)
        self._detect_ecc_operations(data, base_addr)

        # Instruction-based detection
        self._detect_aes_ni_instructions(data, base_addr)
        self._detect_sha_instructions(data, base_addr)

        # Custom crypto detection
        self._detect_custom_crypto(data, base_addr)

        # Round function detection
        self._detect_feistel_structure(data, base_addr)
        self._detect_substitution_permutation(data, base_addr)

        return self.detections

    def _detect_aes_sbox(self, data: bytes, base_addr: int) -> None:
        """Detect AES S-box tables in binary"""
        # Search for forward S-box
        for i in range(len(data) - 256):
            if self._check_sbox_pattern(data[i : i + 256], self.AES_SBOX):
                confidence = self._calculate_sbox_confidence(data[i : i + 256], self.AES_SBOX)
                if confidence > 0.85:
                    detection = CryptoDetection(
                        algorithm=CryptoAlgorithm.AES,
                        offset=base_addr + i,
                        size=256,
                        confidence=confidence,
                        variant="AES Forward S-box",
                        details={"sbox_type": "forward", "completeness": confidence},
                    )
                    self._find_crypto_references(data, i, detection)
                    self.detections.append(detection)

        # Search for inverse S-box
        for i in range(len(data) - 256):
            if self._check_sbox_pattern(data[i : i + 256], self.AES_INV_SBOX):
                confidence = self._calculate_sbox_confidence(data[i : i + 256], self.AES_INV_SBOX)
                if confidence > 0.85:
                    detection = CryptoDetection(
                        algorithm=CryptoAlgorithm.AES,
                        offset=base_addr + i,
                        size=256,
                        confidence=confidence,
                        variant="AES Inverse S-box",
                        details={"sbox_type": "inverse", "completeness": confidence},
                    )
                    self._find_crypto_references(data, i, detection)
                    self.detections.append(detection)

    def _detect_des_sboxes(self, data: bytes, base_addr: int) -> None:
        """Detect DES S-boxes in binary"""
        for i in range(len(data) - 512):
            sbox_matches = 0
            sbox_positions = []

            # Check for DES S-box patterns (each is 64 bytes when packed)
            for sbox_idx, sbox in enumerate(self.DES_SBOXES):
                packed_sbox = self._pack_des_sbox(sbox)
                for j in range(i, min(i + 512, len(data) - 64)):
                    if self._fuzzy_match(data[j : j + 64], packed_sbox, threshold=0.8):
                        sbox_matches += 1
                        sbox_positions.append((sbox_idx + 1, j))
                        break

            if sbox_matches >= 4:  # At least 4 S-boxes detected
                confidence = sbox_matches / 8.0  # 8 S-boxes total
                variant = "DES" if sbox_matches == 8 else f"DES (partial, {sbox_matches}/8 S-boxes)"
                detection = CryptoDetection(
                    algorithm=CryptoAlgorithm.DES if sbox_matches == 8 else CryptoAlgorithm.TRIPLE_DES,
                    offset=base_addr + i,
                    size=512,
                    confidence=confidence,
                    variant=variant,
                    details={"sbox_count": sbox_matches, "sbox_positions": sbox_positions},
                )
                self.detections.append(detection)

    def _detect_rc4_init(self, data: bytes, base_addr: int) -> None:
        """Detect RC4 initialization pattern"""
        # Look for sequential 0-255 pattern
        pattern = bytes(range(256))
        for i in range(len(data) - 256):
            if self._fuzzy_match(data[i : i + 256], pattern, threshold=0.9):
                # Check for KSA-like operations nearby
                if self._check_rc4_ksa_pattern(data, i):
                    detection = CryptoDetection(
                        algorithm=CryptoAlgorithm.RC4,
                        offset=base_addr + i,
                        size=256,
                        confidence=0.95,
                        variant="RC4 State Array",
                        details={"ksa_detected": True},
                    )
                    self.detections.append(detection)

    def _detect_rsa_montgomery(self, data: bytes, base_addr: int) -> None:
        """Detect RSA Montgomery multiplication patterns"""
        # Search for Montgomery reduction constants
        for i in range(len(data) - 8):
            # Check for common RSA exponents
            for pattern in self.RSA_MONTGOMERY_PATTERNS:
                if data[i : i + len(pattern)] == pattern:
                    # Look for modular arithmetic operations nearby
                    if self._check_modular_ops_nearby(data, i):
                        detection = CryptoDetection(
                            algorithm=CryptoAlgorithm.RSA,
                            offset=base_addr + i,
                            size=len(pattern),
                            confidence=0.85,
                            variant="RSA Public Exponent",
                            details={"exponent": int.from_bytes(pattern, "little")},
                        )
                        self.detections.append(detection)

            # Check for Montgomery multiplication patterns in code
            if self._detect_montgomery_mul_code(data[max(0, i - 512) : i + 512]):
                detection = CryptoDetection(
                    algorithm=CryptoAlgorithm.RSA,
                    offset=base_addr + i,
                    size=512,
                    confidence=0.8,
                    variant="RSA Montgomery Multiplication",
                    details={"operation": "montgomery_mul"},
                )
                self.detections.append(detection)

    def _detect_ecc_operations(self, data: bytes, base_addr: int) -> None:
        """Detect elliptic curve cryptography operations"""
        # Search for known curve parameters
        for curve_name, prime in self.ECC_FIELD_PRIMES.items():
            idx = data.find(prime)
            if idx != -1:
                detection = CryptoDetection(
                    algorithm=CryptoAlgorithm.ECC,
                    offset=base_addr + idx,
                    size=len(prime),
                    confidence=0.95,
                    variant=f"ECC {curve_name} Field Prime",
                    details={"curve": curve_name, "field_size": len(prime) * 8},
                )
                self.detections.append(detection)

        # Detect point addition/doubling operations
        self._detect_ecc_point_ops(data, base_addr)

    def _detect_aes_ni_instructions(self, data: bytes, base_addr: int) -> None:
        """Detect AES-NI instruction usage"""
        # AES-NI opcodes
        aesni_opcodes = {
            b"\x66\x0f\x38\xdc": "AESENC",
            b"\x66\x0f\x38\xdd": "AESENCLAST",
            b"\x66\x0f\x38\xde": "AESDEC",
            b"\x66\x0f\x38\xdf": "AESDECLAST",
            b"\x66\x0f\x38\xdb": "AESIMC",
            b"\x66\x0f\x3a\xdf": "AESKEYGENASSIST",
        }

        for opcode, instruction in aesni_opcodes.items():
            idx = 0
            while True:
                idx = data.find(opcode, idx)
                if idx == -1:
                    break

                detection = CryptoDetection(
                    algorithm=CryptoAlgorithm.AES,
                    offset=base_addr + idx,
                    size=len(opcode),
                    confidence=1.0,
                    variant=f"AES-NI {instruction}",
                    mode="Hardware-accelerated",
                    details={"instruction": instruction, "hardware": True},
                )
                self.detections.append(detection)
                idx += len(opcode)

    def _detect_sha_instructions(self, data: bytes, base_addr: int) -> None:
        """Detect SHA instruction extensions"""
        sha_opcodes = {
            b"\x0f\x38\xc8": "SHA1NEXTE",
            b"\x0f\x38\xc9": "SHA1MSG1",
            b"\x0f\x38\xca": "SHA1MSG2",
            b"\x0f\x38\xcb": "SHA256RNDS2",
            b"\x0f\x38\xcc": "SHA256MSG1",
            b"\x0f\x38\xcd": "SHA256MSG2",
        }

        for opcode, instruction in sha_opcodes.items():
            if opcode in data:
                idx = data.find(opcode)
                detection = CryptoDetection(
                    algorithm=CryptoAlgorithm.CUSTOM,
                    offset=base_addr + idx,
                    size=len(opcode),
                    confidence=1.0,
                    variant=f"SHA {instruction}",
                    details={"hash_type": "SHA1" if "SHA1" in instruction else "SHA256", "hardware": True},
                )
                self.detections.append(detection)

    def _detect_custom_crypto(self, data: bytes, base_addr: int) -> None:
        """Detect custom or unknown cryptographic implementations"""
        # Detect high entropy regions that might be crypto tables
        window_size = 256
        for i in range(0, len(data) - window_size, 64):
            window = data[i : i + window_size]
            entropy = self._calculate_entropy(window)

            if entropy > 7.5:  # Very high entropy
                # Check for table-like structure
                if self._is_lookup_table(window):
                    # Check for crypto-like access patterns
                    if self._has_crypto_access_pattern(data, i):
                        detection = CryptoDetection(
                            algorithm=CryptoAlgorithm.CUSTOM,
                            offset=base_addr + i,
                            size=window_size,
                            confidence=0.7,
                            variant="Custom Crypto Table",
                            details={"entropy": entropy, "structure": "lookup_table"},
                        )
                        self.detections.append(detection)

        # Detect XOR-based custom crypto
        self._detect_xor_crypto(data, base_addr)

        # Detect LFSR-based stream ciphers
        self._detect_lfsr_cipher(data, base_addr)

    def _detect_feistel_structure(self, data: bytes, base_addr: int) -> None:
        """Detect Feistel network structures"""
        # Look for characteristic swap operations after rounds
        try:
            # Disassemble and look for Feistel patterns
            md = self.md_64 if len(data) > 0x100000 else self.md_32

            for i in range(0, len(data) - 1024, 256):
                swap_count = 0
                xor_count = 0

                try:
                    for insn in md.disasm(data[i : i + 1024], base_addr + i):
                        # Look for swap patterns (XCHG or MOV sequences)
                        if insn.mnemonic == "xchg":
                            swap_count += 1
                        elif insn.mnemonic == "xor":
                            xor_count += 1
                except (capstone.CsError, ValueError):
                    continue

                if swap_count >= 4 and xor_count >= 8:
                    detection = CryptoDetection(
                        algorithm=CryptoAlgorithm.CUSTOM,
                        offset=base_addr + i,
                        size=1024,
                        confidence=0.75,
                        variant="Feistel Network",
                        details={"rounds": swap_count, "xor_operations": xor_count},
                    )
                    self.detections.append(detection)
        except (TypeError, ValueError, AttributeError):
            pass

    def _detect_substitution_permutation(self, data: bytes, base_addr: int) -> None:
        """Detect substitution-permutation network patterns"""
        # Look for alternating substitution (table lookup) and permutation (bit shuffling)
        for i in range(0, len(data) - 2048, 512):
            if self._has_sp_network_pattern(data[i : i + 2048]):
                detection = CryptoDetection(
                    algorithm=CryptoAlgorithm.CUSTOM,
                    offset=base_addr + i,
                    size=2048,
                    confidence=0.7,
                    variant="SP-Network Cipher",
                    details={"structure": "substitution_permutation"},
                )
                self.detections.append(detection)

    def _detect_ecc_point_ops(self, data: bytes, base_addr: int) -> None:
        """Detect ECC point addition and doubling operations"""
        # Look for modular arithmetic patterns characteristic of ECC
        try:
            md = self.md_64 if len(data) > 0x100000 else self.md_32

            for i in range(0, len(data) - 2048, 512):
                mul_count = 0
                add_count = 0
                sub_count = 0

                try:
                    for insn in md.disasm(data[i : i + 2048], base_addr + i):
                        if insn.mnemonic in ["mul", "imul", "mulx"]:
                            mul_count += 1
                        elif insn.mnemonic in ["add", "adc"]:
                            add_count += 1
                        elif insn.mnemonic in ["sub", "sbb"]:
                            sub_count += 1
                except (capstone.CsError, ValueError):
                    continue

                # ECC operations have characteristic patterns
                if mul_count >= 6 and add_count >= 4 and sub_count >= 2:
                    ratio = mul_count / (add_count + sub_count)
                    if 0.8 <= ratio <= 2.0:  # Typical for ECC
                        detection = CryptoDetection(
                            algorithm=CryptoAlgorithm.ECC,
                            offset=base_addr + i,
                            size=2048,
                            confidence=0.8,
                            variant="ECC Point Operations",
                            details={"multiplications": mul_count, "additions": add_count, "subtractions": sub_count},
                        )
                        self.detections.append(detection)
        except (TypeError, ValueError, AttributeError):
            pass

    def _detect_xor_crypto(self, data: bytes, base_addr: int) -> None:
        """Detect XOR-based encryption"""
        try:
            md = self.md_64 if len(data) > 0x100000 else self.md_32

            for i in range(0, len(data) - 512, 128):
                xor_chain_length = 0

                try:
                    for insn in md.disasm(data[i : i + 512], base_addr + i):
                        if insn.mnemonic == "xor":
                            # Check if it's not zeroing (xor eax, eax)
                            if len(insn.operands) == 2:
                                if insn.operands[0].reg != insn.operands[1].reg:
                                    xor_chain_length += 1
                except (capstone.CsError, ValueError):
                    continue

                if xor_chain_length >= 8:
                    detection = CryptoDetection(
                        algorithm=CryptoAlgorithm.CUSTOM,
                        offset=base_addr + i,
                        size=512,
                        confidence=0.65,
                        variant="XOR Cipher",
                        details={"xor_operations": xor_chain_length},
                    )
                    self.detections.append(detection)
        except (TypeError, ValueError, AttributeError):
            pass

    def _detect_lfsr_cipher(self, data: bytes, base_addr: int) -> None:
        """Detect Linear Feedback Shift Register based ciphers"""
        try:
            md = self.md_64 if len(data) > 0x100000 else self.md_32

            for i in range(0, len(data) - 512, 128):
                shift_count = 0
                xor_count = 0

                try:
                    for insn in md.disasm(data[i : i + 512], base_addr + i):
                        if insn.mnemonic in ["shl", "shr", "sal", "sar", "rol", "ror"]:
                            shift_count += 1
                        elif insn.mnemonic == "xor":
                            xor_count += 1
                except (capstone.CsError, ValueError):
                    continue

                if shift_count >= 4 and xor_count >= 4:
                    ratio = shift_count / xor_count if xor_count > 0 else 0
                    if 0.5 <= ratio <= 2.0:
                        detection = CryptoDetection(
                            algorithm=CryptoAlgorithm.CUSTOM,
                            offset=base_addr + i,
                            size=512,
                            confidence=0.7,
                            variant="LFSR Stream Cipher",
                            details={"shift_operations": shift_count, "xor_operations": xor_count},
                        )
                        self.detections.append(detection)
        except (TypeError, ValueError, AttributeError):
            pass

    def _check_sbox_pattern(self, data: bytes, reference: bytes) -> bool:
        """Check if data matches an S-box pattern"""
        matches = sum(1 for i in range(min(len(data), len(reference))) if data[i] == reference[i])
        return matches >= len(reference) * 0.85

    def _calculate_sbox_confidence(self, data: bytes, reference: bytes) -> float:
        """Calculate confidence score for S-box match"""
        matches = sum(1 for i in range(min(len(data), len(reference))) if data[i] == reference[i])
        return matches / len(reference)

    def _pack_des_sbox(self, sbox: List[List[int]]) -> bytes:
        """Pack DES S-box into byte format"""
        packed = bytearray()
        for row in sbox:
            for val in row:
                packed.append(val)
        return bytes(packed)

    def _fuzzy_match(self, data: bytes, pattern: bytes, threshold: float = 0.8) -> bool:
        """Fuzzy matching for byte patterns"""
        if len(data) != len(pattern):
            return False
        matches = sum(1 for i in range(len(data)) if data[i] == pattern[i])
        return (matches / len(pattern)) >= threshold

    def _check_rc4_ksa_pattern(self, data: bytes, offset: int) -> bool:
        """Check for RC4 Key Scheduling Algorithm pattern nearby"""
        # Look for characteristic swap operations in surrounding code
        search_range = min(1024, len(data) - offset)
        window = data[offset : offset + search_range]

        # Look for swap patterns (simplified check)
        swap_indicators = [b"\x86", b"\x87", b"\x91", b"\x92"]  # XCHG opcodes
        swap_count = sum(1 for indicator in swap_indicators if indicator in window)

        return swap_count >= 2

    def _check_modular_ops_nearby(self, data: bytes, offset: int) -> bool:
        """Check for modular arithmetic operations near offset"""
        search_start = max(0, offset - 512)
        search_end = min(len(data), offset + 512)
        window = data[search_start:search_end]

        # Look for DIV, MUL, IMUL instructions (simplified)
        mod_indicators = [b"\xf7", b"\xf6", b"\x0f\xaf", b"\x69", b"\x6b"]
        return any(indicator in window for indicator in mod_indicators)

    def _detect_montgomery_mul_code(self, data: bytes) -> bool:
        """Detect Montgomery multiplication code patterns"""
        # Look for characteristic instruction sequences
        montgomery_patterns = [
            b"\x48\x0f\xaf",  # IMUL with 64-bit registers
            b"\x48\xf7",  # MUL/DIV with 64-bit
            b"\x4c\x0f\xaf",  # IMUL with extended registers
        ]

        pattern_count = sum(1 for pattern in montgomery_patterns if pattern in data)
        return pattern_count >= 2

    def _calculate_entropy(self, data: bytes) -> float:
        """Calculate Shannon entropy of data"""
        if not data:
            return 0.0

        counts = np.bincount(np.frombuffer(data, dtype=np.uint8), minlength=256)
        probs = counts / len(data)
        probs = probs[probs > 0]

        entropy = -np.sum(probs * np.log2(probs))
        return entropy

    def _is_lookup_table(self, data: bytes) -> bool:
        """Check if data appears to be a lookup table"""
        # Check for non-repeating values (characteristic of S-boxes)
        unique_values = len(set(data))

        # Good lookup tables have high uniqueness
        uniqueness_ratio = unique_values / len(data)

        # Check for byte-aligned structure
        byte_aligned = all(0 <= b <= 255 for b in data)

        return uniqueness_ratio > 0.6 and byte_aligned

    def _has_crypto_access_pattern(self, data: bytes, table_offset: int) -> bool:
        """Check if table is accessed in crypto-like patterns"""
        # Look for indexed access patterns to the table
        search_start = max(0, table_offset - 4096)
        search_end = min(len(data), table_offset + 4096)

        # Convert table offset to bytes for pattern matching
        offset_bytes = struct.pack("<I", table_offset)

        # Check for references to the table address
        references = data[search_start:search_end].count(offset_bytes)

        return references >= 2

    def _has_sp_network_pattern(self, data: bytes) -> bool:
        """Check for substitution-permutation network patterns"""
        # Look for alternating table lookups and bit permutations
        try:
            md = self.md_64 if len(data) > 0x100000 else self.md_32

            mov_count = 0
            shift_count = 0
            and_count = 0

            for insn in md.disasm(data, 0):
                if insn.mnemonic in ["mov", "movzx", "movsx"]:
                    mov_count += 1
                elif insn.mnemonic in ["shl", "shr", "rol", "ror"]:
                    shift_count += 1
                elif insn.mnemonic in ["and", "or", "xor"]:
                    and_count += 1

            # SP networks have characteristic ratio of operations
            total_ops = mov_count + shift_count + and_count
            if total_ops > 20:
                mov_ratio = mov_count / total_ops
                shift_ratio = shift_count / total_ops
                return 0.3 <= mov_ratio <= 0.6 and 0.1 <= shift_ratio <= 0.4
        except (TypeError, ValueError, AttributeError):
            pass

        return False

    def _find_crypto_references(self, data: bytes, table_offset: int, detection: CryptoDetection) -> None:
        """Find code and data references to crypto tables"""
        # Search for direct references
        offset_le = struct.pack("<I", table_offset)
        offset_be = struct.pack(">I", table_offset)

        for i in range(len(data) - 4):
            if data[i : i + 4] in [offset_le, offset_be]:
                detection.data_refs.append(i)

        # Search for relative references (simplified)
        for i in range(max(0, table_offset - 0x10000), min(len(data), table_offset + 0x10000)):
            # Check for LEA, MOV with RIP-relative addressing
            if i != table_offset and self._is_relative_reference(data, i, table_offset):
                detection.code_refs.append(i)

    def _is_relative_reference(self, data: bytes, pos: int, target: int) -> bool:
        """Check if position contains a relative reference to target"""
        if pos + 4 > len(data):
            return False

        # Calculate relative offset
        offset = target - (pos + 4)

        # Check if offset matches
        try:
            rel_offset = struct.unpack("<i", data[pos : pos + 4])[0]
            return abs(rel_offset - offset) < 16  # Allow some tolerance
        except (struct.error, IndexError):
            return False

    def analyze_crypto_usage(self, detections: List[CryptoDetection]) -> Dict[str, Any]:
        """Analyze how detected crypto is being used"""
        analysis = {
            "algorithms": {},
            "total_detections": len(detections),
            "unique_algorithms": len(set(d.algorithm for d in detections)),
            "hardware_accelerated": False,
            "custom_crypto": False,
            "protection_likelihood": 0.0,
        }

        # Group by algorithm
        for detection in detections:
            algo_name = detection.algorithm.name
            if algo_name not in analysis["algorithms"]:
                analysis["algorithms"][algo_name] = {"count": 0, "variants": [], "confidence": 0.0}

            analysis["algorithms"][algo_name]["count"] += 1
            if detection.variant not in analysis["algorithms"][algo_name]["variants"]:
                analysis["algorithms"][algo_name]["variants"].append(detection.variant)
            analysis["algorithms"][algo_name]["confidence"] = max(analysis["algorithms"][algo_name]["confidence"], detection.confidence)

            # Check for hardware acceleration
            if detection.details.get("hardware", False):
                analysis["hardware_accelerated"] = True

            # Check for custom crypto
            if detection.algorithm == CryptoAlgorithm.CUSTOM:
                analysis["custom_crypto"] = True

        # Calculate protection likelihood
        if analysis["unique_algorithms"] >= 2:
            analysis["protection_likelihood"] = 0.8
        elif analysis["custom_crypto"]:
            analysis["protection_likelihood"] = 0.9
        elif analysis["unique_algorithms"] == 1:
            analysis["protection_likelihood"] = 0.6

        return analysis

    def export_yara_rules(self, detections: List[CryptoDetection]) -> str:
        """Generate YARA rules from crypto detections"""
        rules = []

        for detection in detections:
            if detection.algorithm == CryptoAlgorithm.AES:
                rule = f"""
rule AES_Crypto_Detection {{
    meta:
        description = "Detects AES cryptographic implementation"
        confidence = {detection.confidence}
    strings:
        $aes_sbox = {{ {" ".join(f"{b:02x}" for b in self.AES_SBOX[:32])} }}
    condition:
        $aes_sbox
}}"""
                rules.append(rule)

            elif detection.algorithm == CryptoAlgorithm.RSA:
                rule = f"""
rule RSA_Crypto_Detection {{
    meta:
        description = "Detects RSA cryptographic implementation"
        confidence = {detection.confidence}
    strings:
        $rsa_exp1 = {{ 01 00 01 00 }}  // e=65537
        $rsa_exp2 = {{ 03 00 00 00 }}  // e=3
    condition:
        any of ($rsa_exp*)
}}"""
                rules.append(rule)

        return "\n".join(rules)


def main():
    """Example usage"""
    detector = CryptographicRoutineDetector()

    # Example: analyze a binary file
    with open("sample_binary.exe", "rb") as f:
        data = f.read()

    detections = detector.detect_all(data)

    print(f"Found {len(detections)} cryptographic implementations:")
    for detection in detections:
        print(f"  - {detection.algorithm.name} at 0x{detection.offset:08x}")
        print(f"    Variant: {detection.variant}")
        print(f"    Confidence: {detection.confidence:.2%}")
        if detection.details:
            print(f"    Details: {detection.details}")

    # Analyze usage
    analysis = detector.analyze_crypto_usage(detections)
    print("\nAnalysis Summary:")
    print(f"  Protection Likelihood: {analysis['protection_likelihood']:.1%}")
    print(f"  Hardware Accelerated: {analysis['hardware_accelerated']}")
    print(f"  Custom Crypto: {analysis['custom_crypto']}")


if __name__ == "__main__":
    main()

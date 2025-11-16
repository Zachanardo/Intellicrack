"""Cryptographic Routine Detection Module.

Production-ready detection of cryptographic algorithms in binary code with
advanced data flow analysis, constant detection, S-box identification, and
algorithm fingerprinting capabilities.

Detects AES, DES, RSA, ECC, SHA, Blowfish, Twofish, ChaCha20, and custom
crypto implementations through sophisticated pattern matching and behavioral analysis.
"""

import logging
import re
import struct
from collections import defaultdict
from dataclasses import dataclass, field
from enum import IntEnum
from typing import Any

import numpy as np
from capstone import CS_ARCH_X86, CS_MODE_32, CS_MODE_64, Cs

try:
    from capstone import CsError
except ImportError:
    CsError = Exception

try:
    import r2pipe
    R2PIPE_AVAILABLE = True
except ImportError:
    R2PIPE_AVAILABLE = False

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
    SHA1 = 10
    SHA256 = 11
    SHA512 = 12
    MD5 = 13
    CUSTOM = 100


@dataclass
class DataFlowNode:
    """Represents a node in data flow analysis for crypto detection."""

    address: int
    instruction: str
    mnemonic: str
    operands: list[str]
    reads: set[str] = field(default_factory=set)
    writes: set[str] = field(default_factory=set)
    constants: set[int] = field(default_factory=set)
    memory_refs: list[int] = field(default_factory=list)


@dataclass
class CryptoConstant:
    """Represents a cryptographic constant found in binary."""

    offset: int
    value: bytes
    constant_type: str
    algorithm: CryptoAlgorithm | None = None
    confidence: float = 0.0
    context: dict[str, Any] = field(default_factory=dict)


@dataclass
class CryptoDetection:
    """Detection result for identified cryptographic routine in binary code."""

    algorithm: CryptoAlgorithm
    offset: int
    size: int
    confidence: float
    variant: str
    key_size: int | None = None
    mode: str | None = None
    details: dict[str, Any] = field(default_factory=dict)
    code_refs: list[int] = field(default_factory=list)
    data_refs: list[int] = field(default_factory=list)
    constants: list[CryptoConstant] = field(default_factory=list)
    data_flows: list[DataFlowNode] = field(default_factory=list)


class CryptographicRoutineDetector:
    """Advanced detector for cryptographic algorithms and routines in binary executables.

    Features:
    - Data flow analysis for tracking crypto operations
    - Crypto-specific constant detection (S-boxes, round constants, IVs)
    - S-box identification for AES, DES, Blowfish, etc.
    - Custom and obfuscated crypto detection
    - Algorithm fingerprinting based on operation patterns
    """

    AES_SBOX = bytes([
        0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76,
        0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0,
        0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15,
        0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75,
        0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84,
        0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF,
        0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8,
        0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2,
        0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73,
        0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB,
        0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79,
        0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08,
        0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A,
        0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E,
        0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF,
        0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16,
    ])

    AES_INV_SBOX = bytes([
        0x52, 0x09, 0x6A, 0xD5, 0x30, 0x36, 0xA5, 0x38, 0xBF, 0x40, 0xA3, 0x9E, 0x81, 0xF3, 0xD7, 0xFB,
        0x7C, 0xE3, 0x39, 0x82, 0x9B, 0x2F, 0xFF, 0x87, 0x34, 0x8E, 0x43, 0x44, 0xC4, 0xDE, 0xE9, 0xCB,
        0x54, 0x7B, 0x94, 0x32, 0xA6, 0xC2, 0x23, 0x3D, 0xEE, 0x4C, 0x95, 0x0B, 0x42, 0xFA, 0xC3, 0x4E,
        0x08, 0x2E, 0xA1, 0x66, 0x28, 0xD9, 0x24, 0xB2, 0x76, 0x5B, 0xA2, 0x49, 0x6D, 0x8B, 0xD1, 0x25,
        0x72, 0xF8, 0xF6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xD4, 0xA4, 0x5C, 0xCC, 0x5D, 0x65, 0xB6, 0x92,
        0x6C, 0x70, 0x48, 0x50, 0xFD, 0xED, 0xB9, 0xDA, 0x5E, 0x15, 0x46, 0x57, 0xA7, 0x8D, 0x9D, 0x84,
        0x90, 0xD8, 0xAB, 0x00, 0x8C, 0xBC, 0xD3, 0x0A, 0xF7, 0xE4, 0x58, 0x05, 0xB8, 0xB3, 0x45, 0x06,
        0xD0, 0x2C, 0x1E, 0x8F, 0xCA, 0x3F, 0x0F, 0x02, 0xC1, 0xAF, 0xBD, 0x03, 0x01, 0x13, 0x8A, 0x6B,
        0x3A, 0x91, 0x11, 0x41, 0x4F, 0x67, 0xDC, 0xEA, 0x97, 0xF2, 0xCF, 0xCE, 0xF0, 0xB4, 0xE6, 0x73,
        0x96, 0xAC, 0x74, 0x22, 0xE7, 0xAD, 0x35, 0x85, 0xE2, 0xF9, 0x37, 0xE8, 0x1C, 0x75, 0xDF, 0x6E,
        0x47, 0xF1, 0x1A, 0x71, 0x1D, 0x29, 0xC5, 0x89, 0x6F, 0xB7, 0x62, 0x0E, 0xAA, 0x18, 0xBE, 0x1B,
        0xFC, 0x56, 0x3E, 0x4B, 0xC6, 0xD2, 0x79, 0x20, 0x9A, 0xDB, 0xC0, 0xFE, 0x78, 0xCD, 0x5A, 0xF4,
        0x1F, 0xDD, 0xA8, 0x33, 0x88, 0x07, 0xC7, 0x31, 0xB1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xEC, 0x5F,
        0x60, 0x51, 0x7F, 0xA9, 0x19, 0xB5, 0x4A, 0x0D, 0x2D, 0xE5, 0x7A, 0x9F, 0x93, 0xC9, 0x9C, 0xEF,
        0xA0, 0xE0, 0x3B, 0x4D, 0xAE, 0x2A, 0xF5, 0xB0, 0xC8, 0xEB, 0xBB, 0x3C, 0x83, 0x53, 0x99, 0x61,
        0x17, 0x2B, 0x04, 0x7E, 0xBA, 0x77, 0xD6, 0x26, 0xE1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0C, 0x7D,
    ])

    AES_RCON = bytes([
        0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36,
    ])

    DES_SBOXES = [
        [[14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7],
         [0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8],
         [4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0],
         [15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13]],
        [[15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10],
         [3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5],
         [0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15],
         [13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9]],
        [[10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8],
         [13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1],
         [13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7],
         [1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12]],
        [[7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15],
         [13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9],
         [10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4],
         [3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14]],
        [[2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9],
         [14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6],
         [4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14],
         [11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3]],
        [[12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11],
         [10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8],
         [9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6],
         [4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13]],
        [[4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1],
         [13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6],
         [1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2],
         [6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12]],
        [[13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7],
         [1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2],
         [7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8],
         [2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11]],
    ]

    BLOWFISH_PI_SUBKEYS = bytes([
        0x24, 0x3F, 0x6A, 0x88, 0x85, 0xA3, 0x08, 0xD3,
        0x13, 0x19, 0x8A, 0x2E, 0x03, 0x70, 0x73, 0x44,
        0xA4, 0x09, 0x38, 0x22, 0x29, 0x9F, 0x31, 0xD0,
        0x08, 0x2E, 0xFA, 0x98, 0xEC, 0x4E, 0x6C, 0x89,
    ])

    TWOFISH_Q_TABLES = [
        [0xA9, 0x67, 0xB3, 0xE8, 0x04, 0xFD, 0xA3, 0x76],
        [0x75, 0xF3, 0xC6, 0xF4, 0xDB, 0x7B, 0xFB, 0xC8],
    ]

    SHA256_K = [
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
        0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    ]

    SHA1_H = [
        0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0,
    ]

    MD5_T = [
        0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee,
    ]

    RC4_INIT_PATTERN = list(range(256))

    RSA_MONTGOMERY_PATTERNS = [
        b"\x01\x00\x01\x00",
        b"\x03\x00\x00\x00",
        b"\x11\x00\x00\x00",
    ]

    ECC_FIELD_PRIMES = {
        "secp256k1": bytes.fromhex("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F"),
        "secp256r1": bytes.fromhex("FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF"),
        "secp384r1": bytes.fromhex("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFF0000000000000000FFFFFFFF"),
    }

    CHACHA20_CONSTANT = b"expand 32-byte k"

    def __init__(self) -> None:
        """Initialize the CryptographicRoutineDetector with disassemblers."""
        self.detections: list[CryptoDetection] = []
        self.md_32 = Cs(CS_ARCH_X86, CS_MODE_32)
        self.md_64 = Cs(CS_ARCH_X86, CS_MODE_64)
        self.md_32.detail = True
        self.md_64.detail = True
        self.constant_cache: dict[bytes, CryptoConstant] = {}
        self.data_flow_cache: dict[int, list[DataFlowNode]] = {}

    def detect_all(self, data: bytes, base_addr: int = 0, use_radare2: bool = False, binary_path: str | None = None, quick_mode: bool = False) -> list[CryptoDetection]:
        """Detect all cryptographic routines in binary data with advanced analysis.

        Args:
            data: Binary data to analyze
            base_addr: Base address for offset calculations
            use_radare2: Whether to use radare2 for enhanced analysis
            binary_path: Path to binary file (required if use_radare2=True)
            quick_mode: Skip expensive disassembly-based detections for faster analysis

        Returns:
            List of CryptoDetection objects

        """
        self.detections = []
        self.constant_cache = {}
        self.data_flow_cache = {}

        logger.info(f"Starting cryptographic routine detection on {len(data)} bytes")

        self._detect_crypto_constants(data, base_addr)

        self._detect_aes_sbox(data, base_addr)
        self._detect_des_sboxes(data, base_addr)
        self._detect_blowfish_constants(data, base_addr)
        self._detect_twofish_constants(data, base_addr)

        self._detect_hash_constants(data, base_addr)

        self._detect_rc4_init(data, base_addr)
        self._detect_rsa_montgomery(data, base_addr)
        self._detect_ecc_operations(data, base_addr)
        self._detect_chacha20(data, base_addr)

        self._detect_aes_ni_instructions(data, base_addr)
        self._detect_sha_instructions(data, base_addr)

        self._detect_custom_crypto(data, base_addr)

        if not quick_mode:
            self._detect_feistel_structure(data, base_addr)
            self._detect_substitution_permutation(data, base_addr)

            if use_radare2 and R2PIPE_AVAILABLE and binary_path:
                self._enhance_with_radare2(binary_path, base_addr)

            self._perform_data_flow_analysis(data, base_addr)

        self._fingerprint_algorithms()

        logger.info(f"Detection complete: found {len(self.detections)} cryptographic routines")

        return self.detections

    def _detect_crypto_constants(self, data: bytes, base_addr: int) -> None:
        """Detect cryptographic constants throughout the binary."""
        constant_patterns = {
            "AES_SBOX": (self.AES_SBOX, CryptoAlgorithm.AES),
            "AES_INV_SBOX": (self.AES_INV_SBOX, CryptoAlgorithm.AES),
            "AES_RCON": (self.AES_RCON, CryptoAlgorithm.AES),
            "BLOWFISH_PI": (self.BLOWFISH_PI_SUBKEYS, CryptoAlgorithm.BLOWFISH),
            "CHACHA20_CONST": (self.CHACHA20_CONSTANT, CryptoAlgorithm.CHACHA20),
        }

        for const_name, (const_bytes, algorithm) in constant_patterns.items():
            idx = 0
            while True:
                idx = data.find(const_bytes, idx)
                if idx == -1:
                    break

                crypto_const = CryptoConstant(
                    offset=base_addr + idx,
                    value=const_bytes,
                    constant_type=const_name,
                    algorithm=algorithm,
                    confidence=1.0,
                    context={"pattern_match": "exact"},
                )
                self.constant_cache[const_bytes] = crypto_const

                logger.debug(f"Found {const_name} constant at 0x{base_addr + idx:08x}")
                idx += len(const_bytes)

        for i in range(len(self.SHA256_K)):
            k_bytes = struct.pack(">I", self.SHA256_K[i])
            idx = data.find(k_bytes)
            if idx != -1:
                crypto_const = CryptoConstant(
                    offset=base_addr + idx,
                    value=k_bytes,
                    constant_type=f"SHA256_K[{i}]",
                    algorithm=CryptoAlgorithm.SHA256,
                    confidence=0.9,
                    context={"round_constant": i},
                )
                self.constant_cache[k_bytes] = crypto_const

        for i in range(len(self.SHA1_H)):
            h_bytes = struct.pack(">I", self.SHA1_H[i])
            idx = data.find(h_bytes)
            if idx != -1:
                crypto_const = CryptoConstant(
                    offset=base_addr + idx,
                    value=h_bytes,
                    constant_type=f"SHA1_H[{i}]",
                    algorithm=CryptoAlgorithm.SHA1,
                    confidence=0.9,
                    context={"init_vector": i},
                )
                self.constant_cache[h_bytes] = crypto_const

        for i in range(len(self.MD5_T)):
            t_bytes = struct.pack("<I", self.MD5_T[i])
            idx = data.find(t_bytes)
            if idx != -1:
                crypto_const = CryptoConstant(
                    offset=base_addr + idx,
                    value=t_bytes,
                    constant_type=f"MD5_T[{i}]",
                    algorithm=CryptoAlgorithm.MD5,
                    confidence=0.9,
                    context={"sine_table": i},
                )
                self.constant_cache[t_bytes] = crypto_const

    def _detect_aes_sbox(self, data: bytes, base_addr: int) -> None:
        """Detect AES S-box tables with fuzzy matching for obfuscated implementations."""
        for i in range(len(data) - 256):
            fwd_confidence = self._calculate_sbox_confidence(data[i:i + 256], self.AES_SBOX)
            if fwd_confidence > 0.85:
                constant = self.constant_cache.get(data[i:i + 256])
                detection = CryptoDetection(
                    algorithm=CryptoAlgorithm.AES,
                    offset=base_addr + i,
                    size=256,
                    confidence=fwd_confidence,
                    variant="AES Forward S-box",
                    details={
                        "sbox_type": "forward",
                        "completeness": fwd_confidence,
                        "obfuscated": fwd_confidence < 0.995,
                    },
                    constants=[constant] if constant else [],
                )
                self._find_crypto_references(data, i, detection)
                self.detections.append(detection)
                logger.debug(f"AES forward S-box detected at 0x{base_addr + i:08x} (confidence: {fwd_confidence:.2%})")

            inv_confidence = self._calculate_sbox_confidence(data[i:i + 256], self.AES_INV_SBOX)
            if inv_confidence > 0.85:
                constant = self.constant_cache.get(data[i:i + 256])
                detection = CryptoDetection(
                    algorithm=CryptoAlgorithm.AES,
                    offset=base_addr + i,
                    size=256,
                    confidence=inv_confidence,
                    variant="AES Inverse S-box",
                    details={
                        "sbox_type": "inverse",
                        "completeness": inv_confidence,
                        "obfuscated": inv_confidence < 0.995,
                    },
                    constants=[constant] if constant else [],
                )
                self._find_crypto_references(data, i, detection)
                self.detections.append(detection)
                logger.debug(f"AES inverse S-box detected at 0x{base_addr + i:08x} (confidence: {inv_confidence:.2%})")

    def _detect_des_sboxes(self, data: bytes, base_addr: int) -> None:
        """Detect DES S-boxes with support for various packing formats."""
        for i in range(len(data) - 512):
            sbox_matches = 0
            sbox_positions = []

            for sbox_idx, sbox in enumerate(self.DES_SBOXES):
                packed_sbox = self._pack_des_sbox(sbox)
                for j in range(i, min(i + 512, len(data) - 64)):
                    if self._fuzzy_match(data[j:j + 64], packed_sbox, threshold=0.75):
                        sbox_matches += 1
                        sbox_positions.append((sbox_idx + 1, j))
                        break

            if sbox_matches >= 4:
                confidence = sbox_matches / 8.0
                variant = "DES" if sbox_matches == 8 else f"DES (partial, {sbox_matches}/8 S-boxes)"
                detection = CryptoDetection(
                    algorithm=CryptoAlgorithm.DES if sbox_matches == 8 else CryptoAlgorithm.TRIPLE_DES,
                    offset=base_addr + i,
                    size=512,
                    confidence=confidence,
                    variant=variant,
                    details={
                        "sbox_count": sbox_matches,
                        "sbox_positions": sbox_positions,
                        "complete": sbox_matches == 8,
                    },
                )
                self.detections.append(detection)
                logger.debug(f"DES S-boxes detected at 0x{base_addr + i:08x} ({sbox_matches}/8 S-boxes)")

    def _detect_blowfish_constants(self, data: bytes, base_addr: int) -> None:
        """Detect Blowfish Pi-based subkey initialization."""
        idx = data.find(self.BLOWFISH_PI_SUBKEYS)
        if idx != -1:
            detection = CryptoDetection(
                algorithm=CryptoAlgorithm.BLOWFISH,
                offset=base_addr + idx,
                size=len(self.BLOWFISH_PI_SUBKEYS),
                confidence=0.95,
                variant="Blowfish Pi Subkeys",
                details={"constant_type": "pi_subkeys"},
            )
            self.detections.append(detection)
            logger.debug(f"Blowfish Pi subkeys detected at 0x{base_addr + idx:08x}")

        for i in range(len(data) - 1024):
            if self._detect_blowfish_sbox_pattern(data[i:i + 1024]):
                detection = CryptoDetection(
                    algorithm=CryptoAlgorithm.BLOWFISH,
                    offset=base_addr + i,
                    size=1024,
                    confidence=0.85,
                    variant="Blowfish S-boxes",
                    details={"sbox_structure": "4x256"},
                )
                self.detections.append(detection)
                logger.debug(f"Blowfish S-boxes detected at 0x{base_addr + i:08x}")
                break

    def _detect_twofish_constants(self, data: bytes, base_addr: int) -> None:
        """Detect Twofish Q tables."""
        for table_idx, q_table in enumerate(self.TWOFISH_Q_TABLES):
            q_bytes = bytes(q_table)
            idx = data.find(q_bytes)
            if idx != -1:
                detection = CryptoDetection(
                    algorithm=CryptoAlgorithm.TWOFISH,
                    offset=base_addr + idx,
                    size=len(q_bytes),
                    confidence=0.9,
                    variant=f"Twofish Q{table_idx} Table",
                    details={"table_index": table_idx},
                )
                self.detections.append(detection)
                logger.debug(f"Twofish Q{table_idx} table detected at 0x{base_addr + idx:08x}")

    def _detect_hash_constants(self, data: bytes, base_addr: int) -> None:
        """Detect hash algorithm initialization vectors and constants."""
        sha256_k_count_be = 0
        sha256_k_count_le = 0
        for i in range(len(self.SHA256_K)):
            k_bytes_be = struct.pack(">I", self.SHA256_K[i])
            k_bytes_le = struct.pack("<I", self.SHA256_K[i])
            if k_bytes_be in data:
                sha256_k_count_be += 1
            if k_bytes_le in data:
                sha256_k_count_le += 1

        sha256_k_count = max(sha256_k_count_be, sha256_k_count_le)
        endianness = "big" if sha256_k_count_be >= sha256_k_count_le else "little"

        if sha256_k_count >= 4:
            k_bytes = struct.pack(">I" if endianness == "big" else "<I", self.SHA256_K[0])
            idx = data.find(k_bytes)
            detection = CryptoDetection(
                algorithm=CryptoAlgorithm.SHA256,
                offset=base_addr + idx,
                size=256,
                confidence=0.9,
                variant="SHA-256 Round Constants",
                details={"constants_found": sha256_k_count, "total_constants": len(self.SHA256_K), "endianness": endianness},
            )
            self.detections.append(detection)
            logger.debug(f"SHA-256 constants detected ({sha256_k_count}/{len(self.SHA256_K)} found, {endianness} endian)")

        sha1_h_count_be = 0
        sha1_h_count_le = 0
        for i in range(len(self.SHA1_H)):
            h_bytes_be = struct.pack(">I", self.SHA1_H[i])
            h_bytes_le = struct.pack("<I", self.SHA1_H[i])
            if h_bytes_be in data:
                sha1_h_count_be += 1
            if h_bytes_le in data:
                sha1_h_count_le += 1

        sha1_h_count = max(sha1_h_count_be, sha1_h_count_le)
        endianness = "big" if sha1_h_count_be >= sha1_h_count_le else "little"

        if sha1_h_count >= 3:
            h_bytes = struct.pack(">I" if endianness == "big" else "<I", self.SHA1_H[0])
            idx = data.find(h_bytes)
            detection = CryptoDetection(
                algorithm=CryptoAlgorithm.SHA1,
                offset=base_addr + idx,
                size=20,
                confidence=0.9,
                variant="SHA-1 Initialization Vector",
                details={"constants_found": sha1_h_count, "total_constants": len(self.SHA1_H), "endianness": endianness},
            )
            self.detections.append(detection)
            logger.debug(f"SHA-1 constants detected ({sha1_h_count}/{len(self.SHA1_H)} found, {endianness} endian)")

        md5_t_count = 0
        for i in range(len(self.MD5_T)):
            t_bytes = struct.pack("<I", self.MD5_T[i])
            if t_bytes in data:
                md5_t_count += 1

        if md5_t_count >= 2:
            idx = data.find(struct.pack("<I", self.MD5_T[0]))
            detection = CryptoDetection(
                algorithm=CryptoAlgorithm.MD5,
                offset=base_addr + idx,
                size=16,
                confidence=0.85,
                variant="MD5 Sine Table",
                details={"constants_found": md5_t_count},
            )
            self.detections.append(detection)
            logger.debug(f"MD5 constants detected ({md5_t_count} found)")

    def _detect_rc4_init(self, data: bytes, base_addr: int) -> None:
        """Detect RC4 initialization pattern with KSA detection."""
        pattern = bytes(range(256))
        for i in range(len(data) - 256):
            if self._fuzzy_match(data[i:i + 256], pattern, threshold=0.9):
                if self._check_rc4_ksa_pattern(data, i):
                    detection = CryptoDetection(
                        algorithm=CryptoAlgorithm.RC4,
                        offset=base_addr + i,
                        size=256,
                        confidence=0.95,
                        variant="RC4 State Array",
                        details={"ksa_detected": True, "prga_nearby": self._check_rc4_prga_pattern(data, i)},
                    )
                    self.detections.append(detection)
                    logger.debug(f"RC4 state array detected at 0x{base_addr + i:08x}")

    def _detect_rsa_montgomery(self, data: bytes, base_addr: int) -> None:
        """Detect RSA Montgomery multiplication patterns and public exponents."""
        well_known_exponents = {b"\x01\x00\x01\x00": 65537, b"\x03\x00\x00\x00": 3}

        for i in range(len(data) - 8):
            for pattern in self.RSA_MONTGOMERY_PATTERNS:
                if data[i:i + len(pattern)] == pattern:
                    exponent = int.from_bytes(pattern, "little")

                    if pattern in well_known_exponents:
                        confidence = 0.95
                    elif self._check_modular_ops_nearby(data, i):
                        confidence = 0.85
                    else:
                        continue

                    detection = CryptoDetection(
                        algorithm=CryptoAlgorithm.RSA,
                        offset=base_addr + i,
                        size=len(pattern),
                        confidence=confidence,
                        variant="RSA Public Exponent",
                        key_size=self._estimate_rsa_key_size(data, i),
                        details={"exponent": exponent},
                    )
                    self.detections.append(detection)
                    logger.debug(f"RSA exponent {exponent} detected at 0x{base_addr + i:08x}")

        for i in range(0, len(data) - 512, 256):
            if self._detect_montgomery_mul_code(data[i:i + 512]):
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
        """Detect elliptic curve cryptography operations and curve parameters."""
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
                logger.debug(f"ECC {curve_name} field prime detected at 0x{base_addr + idx:08x}")

        self._detect_ecc_point_ops(data, base_addr)

    def _detect_chacha20(self, data: bytes, base_addr: int) -> None:
        """Detect ChaCha20 stream cipher constant."""
        idx = data.find(self.CHACHA20_CONSTANT)
        if idx != -1:
            detection = CryptoDetection(
                algorithm=CryptoAlgorithm.CHACHA20,
                offset=base_addr + idx,
                size=len(self.CHACHA20_CONSTANT),
                confidence=0.95,
                variant="ChaCha20 Constant",
                details={"constant": self.CHACHA20_CONSTANT.decode('ascii')},
            )
            self.detections.append(detection)
            logger.debug(f"ChaCha20 constant detected at 0x{base_addr + idx:08x}")

            if self._detect_chacha20_quarter_round(data, idx):
                detection.confidence = 1.0
                detection.details["quarter_round_detected"] = True

    def _detect_aes_ni_instructions(self, data: bytes, base_addr: int) -> None:
        """Detect AES-NI instruction usage."""
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
                logger.debug(f"AES-NI {instruction} detected at 0x{base_addr + idx:08x}")
                idx += len(opcode)

    def _detect_sha_instructions(self, data: bytes, base_addr: int) -> None:
        """Detect SHA instruction extensions."""
        sha_opcodes = {
            b"\x0f\x38\xc8": ("SHA1NEXTE", CryptoAlgorithm.SHA1),
            b"\x0f\x38\xc9": ("SHA1MSG1", CryptoAlgorithm.SHA1),
            b"\x0f\x38\xca": ("SHA1MSG2", CryptoAlgorithm.SHA1),
            b"\x0f\x38\xcb": ("SHA256RNDS2", CryptoAlgorithm.SHA256),
            b"\x0f\x38\xcc": ("SHA256MSG1", CryptoAlgorithm.SHA256),
            b"\x0f\x38\xcd": ("SHA256MSG2", CryptoAlgorithm.SHA256),
        }

        for opcode, (instruction, algorithm) in sha_opcodes.items():
            idx = 0
            while True:
                idx = data.find(opcode, idx)
                if idx == -1:
                    break

                detection = CryptoDetection(
                    algorithm=algorithm,
                    offset=base_addr + idx,
                    size=len(opcode),
                    confidence=1.0,
                    variant=f"SHA {instruction}",
                    details={"instruction": instruction, "hardware": True},
                )
                self.detections.append(detection)
                logger.debug(f"SHA {instruction} detected at 0x{base_addr + idx:08x}")
                idx += len(opcode)

    def _detect_custom_crypto(self, data: bytes, base_addr: int) -> None:
        """Detect custom or unknown cryptographic implementations using entropy and structural analysis."""
        window_size = 256
        for i in range(0, len(data) - window_size, 64):
            window = data[i:i + window_size]
            entropy = self._calculate_entropy(window)

            if entropy > 7.5:
                if self._is_lookup_table(window):
                    if self._has_crypto_access_pattern(data, i):
                        detection = CryptoDetection(
                            algorithm=CryptoAlgorithm.CUSTOM,
                            offset=base_addr + i,
                            size=window_size,
                            confidence=0.7,
                            variant="Custom Crypto Table",
                            details={
                                "entropy": entropy,
                                "structure": "lookup_table",
                                "uniqueness": len(set(window)) / len(window),
                            },
                        )
                        self.detections.append(detection)
                        logger.debug(f"Custom crypto table detected at 0x{base_addr + i:08x} (entropy: {entropy:.2f})")

        self._detect_xor_crypto(data, base_addr)
        self._detect_lfsr_cipher(data, base_addr)

    def _detect_feistel_structure(self, data: bytes, base_addr: int) -> None:
        """Detect Feistel network structures through instruction pattern analysis."""
        try:
            md = self.md_64 if len(data) > 0x100000 else self.md_32

            for i in range(0, len(data) - 1024, 256):
                swap_count = 0
                xor_count = 0
                round_indicators = []

                try:
                    for insn in md.disasm(data[i:i + 1024], base_addr + i):
                        if insn.mnemonic == "xchg":
                            swap_count += 1
                            round_indicators.append(insn.address)
                        elif insn.mnemonic == "xor" and len(insn.operands) == 2:
                            if insn.operands[0].reg != insn.operands[1].reg:
                                xor_count += 1
                except (CsError, ValueError):
                    continue

                if swap_count >= 4 and xor_count >= 8:
                    detection = CryptoDetection(
                        algorithm=CryptoAlgorithm.CUSTOM,
                        offset=base_addr + i,
                        size=1024,
                        confidence=0.75,
                        variant="Feistel Network",
                        details={
                            "rounds": swap_count,
                            "xor_operations": xor_count,
                            "round_positions": round_indicators,
                        },
                    )
                    self.detections.append(detection)
                    logger.debug(f"Feistel network detected at 0x{base_addr + i:08x}")
        except (TypeError, ValueError, AttributeError) as e:
            logger.debug(f"Error in Feistel detection: {e}")

    def _detect_substitution_permutation(self, data: bytes, base_addr: int) -> None:
        """Detect substitution-permutation network patterns."""
        for i in range(0, len(data) - 2048, 512):
            if self._has_sp_network_pattern(data[i:i + 2048]):
                detection = CryptoDetection(
                    algorithm=CryptoAlgorithm.CUSTOM,
                    offset=base_addr + i,
                    size=2048,
                    confidence=0.7,
                    variant="SP-Network Cipher",
                    details={"structure": "substitution_permutation"},
                )
                self.detections.append(detection)
                logger.debug(f"SP-network detected at 0x{base_addr + i:08x}")

    def _detect_ecc_point_ops(self, data: bytes, base_addr: int) -> None:
        """Detect ECC point addition and doubling operations."""
        try:
            md = self.md_64 if len(data) > 0x100000 else self.md_32

            for i in range(0, len(data) - 2048, 512):
                mul_count = 0
                add_count = 0
                sub_count = 0

                try:
                    for insn in md.disasm(data[i:i + 2048], base_addr + i):
                        if insn.mnemonic in ["mul", "imul", "mulx"]:
                            mul_count += 1
                        elif insn.mnemonic in ["add", "adc"]:
                            add_count += 1
                        elif insn.mnemonic in ["sub", "sbb"]:
                            sub_count += 1
                except (CsError, ValueError):
                    continue

                if mul_count >= 6 and add_count >= 4 and sub_count >= 2:
                    ratio = mul_count / (add_count + sub_count)
                    if 0.8 <= ratio <= 2.0:
                        detection = CryptoDetection(
                            algorithm=CryptoAlgorithm.ECC,
                            offset=base_addr + i,
                            size=2048,
                            confidence=0.8,
                            variant="ECC Point Operations",
                            details={
                                "multiplications": mul_count,
                                "additions": add_count,
                                "subtractions": sub_count,
                                "ratio": ratio,
                            },
                        )
                        self.detections.append(detection)
                        logger.debug(f"ECC point operations detected at 0x{base_addr + i:08x}")
        except (TypeError, ValueError, AttributeError) as e:
            logger.debug(f"Error in ECC detection: {e}")

    def _detect_xor_crypto(self, data: bytes, base_addr: int) -> None:
        """Detect XOR-based encryption patterns."""
        try:
            md = self.md_64 if len(data) > 0x100000 else self.md_32

            for i in range(0, len(data) - 512, 128):
                xor_chain_length = 0
                xor_registers = set()

                try:
                    for insn in md.disasm(data[i:i + 512], base_addr + i):
                        if insn.mnemonic == "xor" and len(insn.operands) == 2:
                            if insn.operands[0].reg != insn.operands[1].reg:
                                xor_chain_length += 1
                                xor_registers.add(insn.operands[0].reg)
                except (CsError, ValueError):
                    continue

                if xor_chain_length >= 8:
                    detection = CryptoDetection(
                        algorithm=CryptoAlgorithm.CUSTOM,
                        offset=base_addr + i,
                        size=512,
                        confidence=0.65,
                        variant="XOR Cipher",
                        details={
                            "xor_operations": xor_chain_length,
                            "registers_used": len(xor_registers),
                        },
                    )
                    self.detections.append(detection)
                    logger.debug(f"XOR cipher detected at 0x{base_addr + i:08x}")
        except (TypeError, ValueError, AttributeError) as e:
            logger.debug(f"Error in XOR detection: {e}")

    def _detect_lfsr_cipher(self, data: bytes, base_addr: int) -> None:
        """Detect Linear Feedback Shift Register based ciphers."""
        try:
            md = self.md_64 if len(data) > 0x100000 else self.md_32

            for i in range(0, len(data) - 512, 128):
                shift_count = 0
                xor_count = 0

                try:
                    for insn in md.disasm(data[i:i + 512], base_addr + i):
                        if insn.mnemonic in ["shl", "shr", "sal", "sar", "rol", "ror"]:
                            shift_count += 1
                        elif insn.mnemonic == "xor":
                            xor_count += 1
                except (CsError, ValueError):
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
                            details={
                                "shift_operations": shift_count,
                                "xor_operations": xor_count,
                                "ratio": ratio,
                            },
                        )
                        self.detections.append(detection)
                        logger.debug(f"LFSR cipher detected at 0x{base_addr + i:08x}")
        except (TypeError, ValueError, AttributeError) as e:
            logger.debug(f"Error in LFSR detection: {e}")

    def _perform_data_flow_analysis(self, data: bytes, base_addr: int) -> None:
        """Perform data flow analysis on detected crypto routines to track value propagation."""
        for detection in self.detections:
            if detection.algorithm in [CryptoAlgorithm.CUSTOM, CryptoAlgorithm.AES, CryptoAlgorithm.DES]:
                offset = detection.offset - base_addr
                if offset < 0 or offset >= len(data):
                    continue

                flow_nodes = self._analyze_data_flow_region(
                    data[max(0, offset - 512):min(len(data), offset + detection.size + 512)],
                    base_addr + max(0, offset - 512),
                )

                detection.data_flows = flow_nodes
                self.data_flow_cache[detection.offset] = flow_nodes

                register_usage = defaultdict(int)
                for node in flow_nodes:
                    for reg in node.writes:
                        register_usage[reg] += 1

                if register_usage:
                    detection.details["register_usage"] = dict(register_usage)
                    detection.details["data_flow_complexity"] = len(flow_nodes)

    def _analyze_data_flow_region(self, data: bytes, base_addr: int) -> list[DataFlowNode]:
        """Analyze data flow in a specific region of code."""
        flow_nodes = []

        try:
            md = self.md_64 if len(data) > 0x100000 else self.md_32

            for insn in md.disasm(data, base_addr):
                node = DataFlowNode(
                    address=insn.address,
                    instruction=insn.bytes.hex(),
                    mnemonic=insn.mnemonic,
                    operands=[str(op) for op in insn.operands] if hasattr(insn, 'operands') else [],
                )

                if hasattr(insn, 'regs_read'):
                    node.reads = {insn.reg_name(r) for r in insn.regs_read}
                if hasattr(insn, 'regs_write'):
                    node.writes = {insn.reg_name(r) for r in insn.regs_write}

                for op in insn.operands if hasattr(insn, 'operands') else []:
                    if op.type == 2:
                        node.constants.add(op.imm)
                    elif op.type == 3:
                        if hasattr(op, 'mem') and hasattr(op.mem, 'disp'):
                            node.memory_refs.append(op.mem.disp)

                flow_nodes.append(node)

        except (CsError, ValueError, AttributeError) as e:
            logger.debug(f"Error in data flow analysis: {e}")

        return flow_nodes

    def _fingerprint_algorithms(self) -> None:
        """Fingerprint algorithms based on detected patterns and operation sequences."""
        algorithm_groups = defaultdict(list)

        for detection in self.detections:
            algorithm_groups[detection.algorithm].append(detection)

        for algorithm, detections in algorithm_groups.items():
            if algorithm == CryptoAlgorithm.AES:
                self._fingerprint_aes(detections)
            elif algorithm == CryptoAlgorithm.RSA:
                self._fingerprint_rsa(detections)
            elif algorithm == CryptoAlgorithm.ECC:
                self._fingerprint_ecc(detections)
            elif algorithm in [CryptoAlgorithm.SHA1, CryptoAlgorithm.SHA256, CryptoAlgorithm.MD5]:
                self._fingerprint_hash(detections)

    def _fingerprint_aes(self, detections: list[CryptoDetection]) -> None:
        """Fingerprint AES implementation details."""
        has_sbox = any("S-box" in d.variant for d in detections)
        has_aesni = any("AES-NI" in d.variant for d in detections)
        has_rcon = any(c.constant_type == "AES_RCON" for d in detections for c in d.constants)

        for detection in detections:
            if has_aesni:
                detection.mode = "Hardware (AES-NI)"
                detection.confidence = min(1.0, detection.confidence + 0.1)
            elif has_sbox and has_rcon:
                detection.mode = "Software (T-tables)"
                detection.confidence = min(1.0, detection.confidence + 0.05)

            if detection.details.get("obfuscated"):
                detection.details["implementation"] = "obfuscated"

    def _fingerprint_rsa(self, detections: list[CryptoDetection]) -> None:
        """Fingerprint RSA implementation details."""
        has_montgomery = any("Montgomery" in d.variant for d in detections)

        for detection in detections:
            if has_montgomery:
                detection.details["optimization"] = "Montgomery multiplication"
                detection.confidence = min(1.0, detection.confidence + 0.05)

    def _fingerprint_ecc(self, detections: list[CryptoDetection]) -> None:
        """Fingerprint ECC implementation details."""
        curve_detections = [d for d in detections if "Field Prime" in d.variant]

        for detection in detections:
            if curve_detections:
                detection.details["curves_present"] = [d.details.get("curve") for d in curve_detections]

    def _fingerprint_hash(self, detections: list[CryptoDetection]) -> None:
        """Fingerprint hash algorithm implementation details."""
        for detection in detections:
            if detection.details.get("hardware", False):
                detection.mode = "Hardware-accelerated"
            else:
                detection.mode = "Software"

    def _enhance_with_radare2(self, binary_path: str, base_addr: int) -> None:
        """Enhance detections using radare2 analysis."""
        try:
            r2 = r2pipe.open(binary_path)
            r2.cmd("aaa")

            for detection in self.detections:
                r2.cmd(f"s {detection.offset}")

                xrefs = r2.cmdj("axtj")
                if xrefs:
                    detection.code_refs.extend([ref.get("from", 0) for ref in xrefs if isinstance(ref, dict)])

                func_info = r2.cmdj("afij")
                if func_info and isinstance(func_info, list) and len(func_info) > 0:
                    detection.details["function_name"] = func_info[0].get("name", "unknown")
                    detection.details["function_size"] = func_info[0].get("size", 0)

            r2.quit()
            logger.info("Enhanced detections with radare2 analysis")
        except Exception as e:
            logger.warning(f"Could not enhance with radare2: {e}")

    def _check_sbox_pattern(self, data: bytes, reference: bytes) -> bool:
        """Check if data matches an S-box pattern."""
        matches = sum(1 for i in range(min(len(data), len(reference))) if data[i] == reference[i])
        return matches >= len(reference) * 0.85

    def _calculate_sbox_confidence(self, data: bytes, reference: bytes) -> float:
        """Calculate confidence score for S-box match with position weighting."""
        if len(data) != len(reference):
            return 0.0

        exact_matches = sum(1 for i in range(len(reference)) if data[i] == reference[i])
        base_confidence = exact_matches / len(reference)

        hamming_distances = [bin(data[i] ^ reference[i]).count('1') for i in range(len(reference))]
        avg_hamming = sum(hamming_distances) / len(hamming_distances)
        hamming_factor = max(0, 1.0 - (avg_hamming / 8.0))

        final_confidence = (base_confidence * 0.7) + (hamming_factor * 0.3)
        return final_confidence

    def _pack_des_sbox(self, sbox: list[list[int]]) -> bytes:
        """Pack DES S-box into byte format."""
        packed = bytearray()
        for row in sbox:
            for val in row:
                packed.append(val)
        return bytes(packed)

    def _fuzzy_match(self, data: bytes, pattern: bytes, threshold: float = 0.8) -> bool:
        """Fuzzy matching for byte patterns with length tolerance."""
        if len(data) != len(pattern):
            return False
        matches = sum(1 for i in range(len(data)) if data[i] == pattern[i])
        return (matches / len(pattern)) >= threshold

    def _detect_blowfish_sbox_pattern(self, data: bytes) -> bool:
        """Detect Blowfish S-box structure (4 S-boxes of 256 entries each)."""
        if len(data) < 1024:
            return False

        entropy_per_quarter = []
        for i in range(4):
            quarter = data[i * 256:(i + 1) * 256]
            entropy = self._calculate_entropy(quarter)
            entropy_per_quarter.append(entropy)

        return all(e > 7.0 for e in entropy_per_quarter)

    def _check_rc4_ksa_pattern(self, data: bytes, offset: int) -> bool:
        """Check for RC4 Key Scheduling Algorithm pattern nearby."""
        search_range = min(1024, len(data) - offset)
        window = data[offset:offset + search_range]

        swap_indicators = [b"\x86", b"\x87", b"\x91", b"\x92"]
        swap_count = sum(1 for indicator in swap_indicators if indicator in window)

        return swap_count >= 2

    def _check_rc4_prga_pattern(self, data: bytes, offset: int) -> bool:
        """Check for RC4 Pseudo-Random Generation Algorithm pattern."""
        search_start = max(0, offset - 512)
        search_end = min(len(data), offset + 1024)
        window = data[search_start:search_end]

        add_indicators = [b"\x00", b"\x01", b"\x02", b"\x03"]
        xor_indicators = [b"\x30", b"\x31", b"\x32", b"\x33"]

        has_add = any(ind in window for ind in add_indicators)
        has_xor = any(ind in window for ind in xor_indicators)

        return has_add and has_xor

    def _check_modular_ops_nearby(self, data: bytes, offset: int) -> bool:
        """Check for modular arithmetic operations near offset."""
        search_start = max(0, offset - 512)
        search_end = min(len(data), offset + 512)
        window = data[search_start:search_end]

        mod_indicators = [b"\xf7", b"\xf6", b"\x0f\xaf", b"\x69", b"\x6b"]
        return any(indicator in window for indicator in mod_indicators)

    def _estimate_rsa_key_size(self, data: bytes, offset: int) -> int | None:
        """Estimate RSA key size from nearby modulus."""
        search_start = max(0, offset - 2048)
        search_end = min(len(data), offset + 2048)
        window = data[search_start:search_end]

        large_number_pattern = re.compile(rb'[\x80-\xFF]{64,}')
        matches = large_number_pattern.findall(window)

        if matches:
            max_len = max(len(m) for m in matches)
            return max_len * 8

        return None

    def _detect_montgomery_mul_code(self, data: bytes) -> bool:
        """Detect Montgomery multiplication code patterns."""
        montgomery_patterns = [
            b"\x48\x0f\xaf",
            b"\x48\xf7",
            b"\x4c\x0f\xaf",
        ]

        pattern_count = sum(1 for pattern in montgomery_patterns if pattern in data)
        return pattern_count >= 2

    def _detect_chacha20_quarter_round(self, data: bytes, offset: int) -> bool:
        """Detect ChaCha20 quarter round function pattern."""
        search_start = max(0, offset - 1024)
        search_end = min(len(data), offset + 1024)
        window = data[search_start:search_end]

        add_count = window.count(b"\x01") + window.count(b"\x03")
        xor_count = window.count(b"\x31") + window.count(b"\x33")
        rol_count = window.count(b"\xc1") + window.count(b"\xd3")

        return add_count >= 4 and xor_count >= 4 and rol_count >= 4

    def _calculate_entropy(self, data: bytes) -> float:
        """Calculate Shannon entropy of data."""
        if not data:
            return 0.0

        counts = np.bincount(np.frombuffer(data, dtype=np.uint8), minlength=256)
        probs = counts / len(data)
        probs = probs[probs > 0]

        entropy = -np.sum(probs * np.log2(probs))
        return entropy

    def _is_lookup_table(self, data: bytes) -> bool:
        """Check if data appears to be a lookup table."""
        unique_values = len(set(data))
        uniqueness_ratio = unique_values / len(data)
        byte_aligned = all(0 <= b <= 255 for b in data)

        return uniqueness_ratio > 0.6 and byte_aligned

    def _has_crypto_access_pattern(self, data: bytes, table_offset: int) -> bool:
        """Check if table is accessed in crypto-like patterns."""
        search_start = max(0, table_offset - 4096)
        search_end = min(len(data), table_offset + 4096)

        offset_bytes = struct.pack("<I", table_offset)
        references = data[search_start:search_end].count(offset_bytes)

        return references >= 2

    def _has_sp_network_pattern(self, data: bytes) -> bool:
        """Check for substitution-permutation network patterns."""
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

            total_ops = mov_count + shift_count + and_count
            if total_ops > 20:
                mov_ratio = mov_count / total_ops
                shift_ratio = shift_count / total_ops
                return 0.3 <= mov_ratio <= 0.6 and 0.1 <= shift_ratio <= 0.4
        except (TypeError, ValueError, AttributeError) as e:
            logger.debug(f"Error detecting Montgomery multiplication: {e}")

        return False

    def _find_crypto_references(self, data: bytes, table_offset: int, detection: CryptoDetection) -> None:
        """Find code and data references to crypto tables."""
        offset_le = struct.pack("<I", table_offset)
        offset_be = struct.pack(">I", table_offset)

        for i in range(len(data) - 4):
            if data[i:i + 4] in [offset_le, offset_be]:
                detection.data_refs.append(i)

        for i in range(max(0, table_offset - 0x10000), min(len(data), table_offset + 0x10000)):
            if i != table_offset and self._is_relative_reference(data, i, table_offset):
                detection.code_refs.append(i)

    def _is_relative_reference(self, data: bytes, pos: int, target: int) -> bool:
        """Check if position contains a relative reference to target."""
        if pos + 4 > len(data):
            return False

        offset = target - (pos + 4)

        try:
            rel_offset = struct.unpack("<i", data[pos:pos + 4])[0]
            return abs(rel_offset - offset) < 16
        except (struct.error, IndexError):
            return False

    def analyze_crypto_usage(self, detections: list[CryptoDetection]) -> dict[str, Any]:
        """Analyze how detected crypto is being used in the binary.

        Args:
            detections: List of crypto detections to analyze

        Returns:
            Dictionary containing usage analysis

        """
        analysis = {
            "algorithms": {},
            "total_detections": len(detections),
            "unique_algorithms": len({d.algorithm for d in detections}),
            "hardware_accelerated": False,
            "custom_crypto": False,
            "obfuscated_crypto": False,
            "protection_likelihood": 0.0,
            "key_sizes": set(),
            "modes": set(),
        }

        for detection in detections:
            algo_name = detection.algorithm.name
            if algo_name not in analysis["algorithms"]:
                analysis["algorithms"][algo_name] = {
                    "count": 0,
                    "variants": [],
                    "confidence": 0.0,
                    "locations": [],
                }

            analysis["algorithms"][algo_name]["count"] += 1
            if detection.variant not in analysis["algorithms"][algo_name]["variants"]:
                analysis["algorithms"][algo_name]["variants"].append(detection.variant)
            analysis["algorithms"][algo_name]["confidence"] = max(
                analysis["algorithms"][algo_name]["confidence"],
                detection.confidence,
            )
            analysis["algorithms"][algo_name]["locations"].append(detection.offset)

            if detection.details.get("hardware", False):
                analysis["hardware_accelerated"] = True

            if detection.algorithm == CryptoAlgorithm.CUSTOM:
                analysis["custom_crypto"] = True

            if detection.details.get("obfuscated", False):
                analysis["obfuscated_crypto"] = True

            if detection.key_size:
                analysis["key_sizes"].add(detection.key_size)

            if detection.mode:
                analysis["modes"].add(detection.mode)

        if analysis["obfuscated_crypto"]:
            analysis["protection_likelihood"] = 0.95
        elif analysis["unique_algorithms"] >= 2:
            analysis["protection_likelihood"] = 0.85
        elif analysis["custom_crypto"]:
            analysis["protection_likelihood"] = 0.9
        elif analysis["unique_algorithms"] == 1:
            analysis["protection_likelihood"] = 0.6

        return analysis

    def export_yara_rules(self, detections: list[CryptoDetection]) -> str:
        """Generate YARA rules from crypto detections.

        Args:
            detections: List of crypto detections

        Returns:
            YARA rules as string

        """
        rules = []

        for idx, detection in enumerate(detections):
            if detection.algorithm == CryptoAlgorithm.AES:
                rule = f"""rule AES_Crypto_Detection_{idx} {{
    meta:
        description = "Detects AES cryptographic implementation"
        variant = "{detection.variant}"
        confidence = {detection.confidence}
    strings:
        $aes_sbox = {{ {" ".join(f"{b:02x}" for b in self.AES_SBOX[:32])} }}
    condition:
        $aes_sbox
}}"""
                rules.append(rule)

            elif detection.algorithm == CryptoAlgorithm.RSA:
                rule = f"""rule RSA_Crypto_Detection_{idx} {{
    meta:
        description = "Detects RSA cryptographic implementation"
        confidence = {detection.confidence}
    strings:
        $rsa_exp1 = {{ 01 00 01 00 }}
        $rsa_exp2 = {{ 03 00 00 00 }}
    condition:
        any of ($rsa_exp*)
}}"""
                rules.append(rule)

            elif detection.algorithm == CryptoAlgorithm.CHACHA20:
                rule = f"""rule ChaCha20_Crypto_Detection_{idx} {{
    meta:
        description = "Detects ChaCha20 stream cipher"
        confidence = {detection.confidence}
    strings:
        $chacha_const = "expand 32-byte k"
    condition:
        $chacha_const
}}"""
                rules.append(rule)

        return "\n\n".join(rules)


def main() -> None:
    """Demonstrate crypto detection capabilities with example usage."""
    import sys

    if len(sys.argv) < 2:
        print("Usage: python cryptographic_routine_detector.py <binary_file> [--use-radare2]")
        sys.exit(1)

    binary_path = sys.argv[1]
    use_radare2 = "--use-radare2" in sys.argv

    detector = CryptographicRoutineDetector()

    with open(binary_path, "rb") as f:
        data = f.read()

    print(f"Analyzing binary: {binary_path}")
    print(f"Size: {len(data)} bytes")
    print(f"Using radare2: {use_radare2}")
    print()

    detections = detector.detect_all(data, use_radare2=use_radare2, binary_path=binary_path if use_radare2 else None)

    print(f"Found {len(detections)} cryptographic implementations:\n")
    for detection in detections:
        print(f"  [{detection.algorithm.name}] at 0x{detection.offset:08x}")
        print(f"    Variant: {detection.variant}")
        print(f"    Confidence: {detection.confidence:.2%}")
        if detection.key_size:
            print(f"    Key Size: {detection.key_size} bits")
        if detection.mode:
            print(f"    Mode: {detection.mode}")
        if detection.constants:
            print(f"    Constants: {len(detection.constants)} found")
        if detection.data_flows:
            print(f"    Data Flow Nodes: {len(detection.data_flows)}")
        if detection.details:
            print(f"    Details: {detection.details}")
        print()

    analysis = detector.analyze_crypto_usage(detections)
    print("=" * 60)
    print("Analysis Summary:")
    print(f"  Total Detections: {analysis['total_detections']}")
    print(f"  Unique Algorithms: {analysis['unique_algorithms']}")
    print(f"  Hardware Accelerated: {analysis['hardware_accelerated']}")
    print(f"  Custom Crypto: {analysis['custom_crypto']}")
    print(f"  Obfuscated Crypto: {analysis['obfuscated_crypto']}")
    print(f"  Protection Likelihood: {analysis['protection_likelihood']:.1%}")
    if analysis['key_sizes']:
        print(f"  Key Sizes: {sorted(analysis['key_sizes'])}")
    print()

    print("Algorithms Detected:")
    for algo_name, algo_info in analysis['algorithms'].items():
        print(f"  {algo_name}:")
        print(f"    Count: {algo_info['count']}")
        print(f"    Variants: {', '.join(algo_info['variants'])}")
        print(f"    Confidence: {algo_info['confidence']:.2%}")
    print()

    yara_output = binary_path.replace(".", "_") + "_crypto.yar"
    with open(yara_output, "w") as f:
        f.write(detector.export_yara_rules(detections))
    print(f"YARA rules exported to: {yara_output}")


if __name__ == "__main__":
    main()

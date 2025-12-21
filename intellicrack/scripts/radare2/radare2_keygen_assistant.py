#!/usr/bin/env python3
"""Radare2 keygen assistant script for Intellicrack.

This file is part of Intellicrack.
Copyright (C) 2025 Zachary Flint.

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see https://www.gnu.org/licenses/.
"""

# Standard library imports
import json
import logging
import os
import re
import struct
import sys
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

import keystone
import r2pipe


logger = logging.getLogger(__name__)

# Third-party imports
from intellicrack.handlers.capstone_handler import capstone


try:
    from capstone import CsInsn
except ImportError:
    CsInsn = object

"""
Radare2 Keygen Assistant Module

Advanced keygen generation assistant for Radare2 that analyzes cryptographic
validation routines and generates working keygen source code in multiple languages.

Author: Intellicrack Framework
Version: 2.0.0
License: GPL v3
"""


class CryptoAlgorithm(Enum):
    """Supported cryptographic algorithms."""

    RSA = "RSA"
    ECC = "Elliptic Curve"
    AES = "AES"
    DES = "DES/3DES"
    MD5 = "MD5"
    SHA1 = "SHA-1"
    SHA256 = "SHA-256"
    SHA512 = "SHA-512"
    CRC32 = "CRC32"
    CUSTOM_XOR = "Custom XOR"
    CUSTOM_ALGO = "Custom Algorithm"
    TEA = "TEA/XTEA"
    RC4 = "RC4"
    BLOWFISH = "Blowfish"


class KeygenLanguage(Enum):
    """Target languages for keygen generation."""

    PYTHON = "Python"
    CPP = "C++"
    JAVA = "Java"
    CSHARP = "C#"
    JAVASCRIPT = "JavaScript"
    RUST = "Rust"
    GO = "Go"


@dataclass
class CryptoOperation:
    """Represents a cryptographic operation."""

    address: int
    algorithm: CryptoAlgorithm
    operation: str  # encrypt, decrypt, hash, sign, verify
    key_size: int | None = None
    parameters: dict[str, Any] = field(default_factory=dict)
    constants: list[int] = field(default_factory=list)


@dataclass
class ValidationFlow:
    """Represents the validation flow."""

    entry_point: int
    operations: list[CryptoOperation]
    comparison_points: list[int]
    success_paths: list[int]
    failure_paths: list[int]
    serial_format: str | None = None


@dataclass
class KeygenTemplate:
    """Generated keygen template."""

    language: KeygenLanguage
    algorithm_chain: list[CryptoAlgorithm]
    source_code: str
    dependencies: list[str]
    usage_instructions: str


class R2KeygenAssistant:
    """Advanced keygen generation assistant for Radare2."""

    # Crypto constants database
    CRYPTO_CONSTANTS = {
        "MD5": {
            "init": [0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476],
            "k": [0xD76AA478, 0xE8C7B756, 0x242070DB, 0xC1BDCEEE],
        },
        "SHA1": {
            "init": [0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0],
        },
        "SHA256": {
            "init": [0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A],
            "k": [0x428A2F98, 0x71374491, 0xB5C0FBCF, 0xE9B5DBA5],
        },
        "AES": {
            "sbox": [0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5],
            "rcon": [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80],
        },
        "TEA": {
            "delta": 0x9E3779B9,
            "sum": 0xC6EF3720,
        },
        "CRC32": {
            "poly": 0xEDB88320,
            "init": 0xFFFFFFFF,
        },
    }

    # Serial format patterns
    SERIAL_PATTERNS = {
        "4x4": r"^[A-Z0-9]{4}-[A-Z0-9]{4}-[A-Z0-9]{4}-[A-Z0-9]{4}$",
        "3x5": r"^[A-Z0-9]{5}-[A-Z0-9]{5}-[A-Z0-9]{5}$",
        "16-char": r"^[A-Z0-9]{16}$",
        "3-6-6": r"^[A-Z0-9]{3}-[A-Z0-9]{6}-[A-Z0-9]{6}$",
        "5x5": r"^[A-Z0-9]{5}-[A-Z0-9]{5}-[A-Z0-9]{5}-[A-Z0-9]{5}-[A-Z0-9]{5}$",
        "6x4": r"^[A-Z0-9]{4}-[A-Z0-9]{4}-[A-Z0-9]{4}-[A-Z0-9]{4}-[A-Z0-9]{4}-[A-Z0-9]{4}$",
    }

    def __init__(self, r2: r2pipe.open = None, filename: str = None) -> None:
        """Initialize the keygen assistant."""
        self.r2 = r2 or r2pipe.open(filename)
        self.crypto_operations: list[CryptoOperation] = []
        self.validation_flows: list[ValidationFlow] = []
        self.extracted_keys: dict[str, Any] = {}
        self.serial_format: str | None = None

        # Initialize disassemblers
        self._init_disassemblers()

        # Initialize analysis
        self._init_analysis()

    def _init_disassemblers(self) -> None:
        """Initialize disassembly engines."""
        info = self.r2.cmdj("ij")
        arch = info.get("bin", {}).get("arch", "x86")
        bits = info.get("bin", {}).get("bits", 32)

        # Capstone for disassembly
        if arch == "x86" and bits == 64:
            self.cs = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
        else:
            self.cs = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
        self.cs.detail = True

        # Keystone for assembly (patching)
        if arch == "x86":
            if bits == 64:
                self.ks = keystone.Ks(keystone.KS_ARCH_X86, keystone.KS_MODE_64)
            else:
                self.ks = keystone.Ks(keystone.KS_ARCH_X86, keystone.KS_MODE_32)

    def _init_analysis(self) -> None:
        """Initialize r2 analysis."""
        logger.info("Initializing analysis...")
        self.r2.cmd("aaa")

        # Get binary info
        self.info = self.r2.cmdj("ij")
        self.arch = self.info.get("bin", {}).get("arch", "unknown")
        self.bits = self.info.get("bin", {}).get("bits", 32)

    def analyze_validation(self, target_functions: list[int]) -> list[ValidationFlow]:
        """Analyze validation routines for keygen generation."""
        logger.info("Analyzing validation routines...")

        for func_addr in target_functions:
            logger.info("Analyzing function at 0x%x", func_addr)

            # Analyze crypto operations
            flow = self._analyze_function_flow(func_addr)

            if flow and flow.operations:
                self.validation_flows.append(flow)

        return self.validation_flows

    def _analyze_function_flow(self, func_addr: int) -> ValidationFlow | None:
        """Analyze validation flow in function."""
        flow = ValidationFlow(
            entry_point=func_addr,
            operations=[],
            comparison_points=[],
            success_paths=[],
            failure_paths=[],
        )

        # Get function basic blocks
        blocks = self.r2.cmdj(f"afbj @ {func_addr}")
        if not blocks:
            return None

        # Analyze each block
        for block in blocks:
            addr = block.get("addr", 0)
            size = block.get("size", 0)

            # Get block bytes
            block_bytes = bytes(self.r2.cmdj(f"p8j {size} @ {addr}"))

            # Disassemble and analyze
            self._analyze_block_instructions(addr, block_bytes, flow)

        # Detect serial format
        flow.serial_format = self._detect_serial_format(func_addr)

        return flow

    def _analyze_block_instructions(self, addr: int, block_bytes: bytes, flow: ValidationFlow) -> None:
        """Analyze instructions in a basic block."""
        for insn in self.cs.disasm(block_bytes, addr):
            if crypto_op := self._detect_crypto_operation(insn):
                flow.operations.append(crypto_op)
                self.crypto_operations.append(crypto_op)

            # Check for comparisons
            if insn.mnemonic in ["cmp", "test"]:
                flow.comparison_points.append(insn.address)

            # Check for function calls
            if insn.mnemonic in ["call"]:
                self._analyze_call(insn, flow)

    def _detect_crypto_operation(self, insn: CsInsn) -> CryptoOperation | None:
        """Detect cryptographic operations from instruction."""
        # Check for crypto-specific instructions
        crypto_instructions = {
            "aesenc": (CryptoAlgorithm.AES, "encrypt"),
            "aesdec": (CryptoAlgorithm.AES, "decrypt"),
            "sha256msg1": (CryptoAlgorithm.SHA256, "hash"),
            "sha1msg1": (CryptoAlgorithm.SHA1, "hash"),
            "pclmulqdq": (CryptoAlgorithm.CRC32, "checksum"),
        }

        if insn.mnemonic in crypto_instructions:
            algo, op = crypto_instructions[insn.mnemonic]
            return CryptoOperation(
                address=insn.address,
                algorithm=algo,
                operation=op,
            )

        # Check for XOR patterns (common in simple crypto)
        if insn.mnemonic == "xor" and len(insn.operands) == 2 and insn.operands[1].type == capstone.x86.X86_OP_IMM:
            return CryptoOperation(
                address=insn.address,
                algorithm=CryptoAlgorithm.CUSTOM_XOR,
                operation="xor",
                parameters={"key": insn.operands[1].imm},
            )

        return None

    def _analyze_call(self, insn: CsInsn, flow: ValidationFlow) -> None:
        """Analyze function calls for crypto operations."""
        if insn.operands[0].type == capstone.x86.X86_OP_IMM:
            target = insn.operands[0].imm

            # Get function name
            func_info = self.r2.cmdj(f"afij @ {target}")
            if func_info and func_info[0]:
                func_name = func_info[0].get("name", "")

                # Check for crypto function patterns
                crypto_patterns = {
                    "md5": CryptoAlgorithm.MD5,
                    "sha": CryptoAlgorithm.SHA1,
                    "sha256": CryptoAlgorithm.SHA256,
                    "aes": CryptoAlgorithm.AES,
                    "des": CryptoAlgorithm.DES,
                    "rsa": CryptoAlgorithm.RSA,
                    "ecc": CryptoAlgorithm.ECC,
                    "crc": CryptoAlgorithm.CRC32,
                }

                func_lower = func_name.lower()
                for pattern, algo in crypto_patterns.items():
                    if pattern in func_lower:
                        op_type = self._determine_operation_type(func_name)

                        crypto_op = CryptoOperation(
                            address=insn.address,
                            algorithm=algo,
                            operation=op_type,
                        )
                        flow.operations.append(crypto_op)
                        break

    def _determine_operation_type(self, func_name: str) -> str:
        """Determine crypto operation type from function name."""
        func_lower = func_name.lower()

        if any(x in func_lower for x in ["encrypt", "encode", "encipher"]):
            return "encrypt"
        if any(x in func_lower for x in ["decrypt", "decode", "decipher"]):
            return "decrypt"
        if any(x in func_lower for x in ["hash", "digest", "checksum"]):
            return "hash"
        if any(x in func_lower for x in ["sign", "signature"]):
            return "sign"
        if any(x in func_lower for x in ["verify", "validate", "check"]):
            return "verify"
        return "unknown"

    def _detect_serial_format(self, func_addr: int) -> str | None:
        """Detect serial number format from function."""
        # Look for string patterns in function
        strings = self.r2.cmd(f"iz~{func_addr}")

        for pattern, regex in self.SERIAL_PATTERNS.items():
            if re.search(regex, strings, re.MULTILINE):
                return pattern

        # Look for format strings
        format_patterns = [
            r"%[0-9]*[xX]",  # Hex format
            r"%[0-9]*d",  # Decimal format
            r"%[0-9]*s",  # String format
        ]

        return next(
            ("4x4" if "x" in fmt or "X" in fmt else "3x5" for fmt in format_patterns if re.search(fmt, strings)),
            None,
        )

    def extract_crypto_parameters(self) -> dict[str, Any]:
        """Extract cryptographic parameters from binary."""
        logger.info("Extracting cryptographic parameters...")

        # Search for known crypto constants
        for name, constants in self.CRYPTO_CONSTANTS.items():
            self._search_constants(name, constants)

        # Extract RSA keys
        self._extract_rsa_keys()

        # Extract AES keys
        self._extract_aes_keys()

        # Extract custom algorithms
        self._extract_custom_algorithms()

        return self.extracted_keys

    def _search_constants(self, algo_name: str, constants: dict[str, Any]) -> None:
        """Search for algorithm-specific constants."""
        for const_type, values in constants.items():
            if isinstance(values, list):
                for val in values:
                    self._search_constant_value(algo_name, const_type, val)
            else:
                self._search_constant_value(algo_name, const_type, values)

    def _search_constant_value(self, algo_name: str, const_type: str, value: int) -> None:
        """Search for a specific constant value."""
        # Search in different endianness
        search_values = []

        if value <= 0xFFFFFFFF:
            # 32-bit value
            search_values.extend(
                [
                    struct.pack("<I", value).hex(),  # Little endian
                    struct.pack(">I", value).hex(),  # Big endian
                ],
            )
        else:
            # 64-bit value
            search_values.extend(
                [
                    struct.pack("<Q", value).hex(),
                    struct.pack(">Q", value).hex(),
                ],
            )

        for hex_val in search_values:
            if results := self.r2.cmd(f"/x {hex_val}"):
                if algo_name not in self.extracted_keys:
                    self.extracted_keys[algo_name] = {}

                if const_type not in self.extracted_keys[algo_name]:
                    self.extracted_keys[algo_name][const_type] = []

                for line in results.strip().split("\n"):
                    if line.startswith("0x"):
                        addr = int(line.split()[0], 16)
                        self.extracted_keys[algo_name][const_type].append(
                            {
                                "address": addr,
                                "value": value,
                            },
                        )

    def _extract_rsa_keys(self) -> None:
        """Extract RSA keys from binary."""
        logger.info("Searching for RSA keys...")

        # Common RSA public exponents
        common_exponents = [3, 17, 65537]

        for exp in common_exponents:
            # Search for the exponent
            exp_bytes = struct.pack(">I", exp)
            if results := self.r2.cmd(f"/x {exp_bytes.hex()}"):
                # Found potential RSA exponent
                # Look for nearby large integers (modulus)
                for line in results.strip().split("\n"):
                    if line.startswith("0x"):
                        addr = int(line.split()[0], 16)

                        # Search around this address for large integers
                        self._search_rsa_modulus(addr, exp)

    def _search_rsa_modulus(self, exp_addr: int, exponent: int) -> None:
        """Search for RSA modulus near exponent."""
        # RSA modulus is typically 128-512 bytes
        search_range = 0x1000

        # Look before and after exponent
        start_addr = max(0, exp_addr - search_range)

        # Read memory region
        data = bytes(self.r2.cmdj(f"p8j {search_range * 2} @ {start_addr}"))

        # Look for sequences of non-zero bytes (potential modulus)
        for i in range(0, len(data) - 128, 4):
            # Check if this could be a modulus
            chunk = data[i : i + 256]

            # RSA modulus characteristics:
            # - Starts with high bit set
            # - No long sequences of zeros
            # - Appropriate length (power of 2)

            if chunk[0] & 0x80 and chunk.count(b"\x00") < 10:
                # Potential modulus found
                modulus = int.from_bytes(chunk, "big")

                # Verify it's a valid RSA modulus (basic check)
                if modulus.bit_length() in [512, 1024, 2048, 4096]:
                    if "RSA" not in self.extracted_keys:
                        self.extracted_keys["RSA"] = {}

                    self.extracted_keys["RSA"]["modulus"] = {
                        "address": start_addr + i,
                        "value": modulus,
                        "bits": modulus.bit_length(),
                        "exponent": exponent,
                    }

                    logger.info("Found potential RSA-%d key at 0x%x", modulus.bit_length(), start_addr + i)

    def _extract_aes_keys(self) -> None:
        """Extract AES keys from binary."""
        logger.info("Searching for AES keys...")

        # AES S-box pattern
        aes_sbox = bytes(
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
            ],
        )

        if results := self.r2.cmd(f"/x {aes_sbox.hex()}"):
            # Found AES S-box, look for keys nearby
            for line in results.strip().split("\n"):
                if line.startswith("0x"):
                    sbox_addr = int(line.split()[0], 16)

                    # Keys are often near S-box
                    self._search_aes_keys_near(sbox_addr)

    def _search_aes_keys_near(self, sbox_addr: int) -> None:
        """Search for AES keys near S-box."""
        # AES keys are 16, 24, or 32 bytes
        key_sizes = [16, 24, 32]
        search_range = 0x1000

        for key_size in key_sizes:
            # Search before S-box (common pattern)
            for offset in range(search_range, 0, -key_size):
                addr = sbox_addr - offset

                # Read potential key
                key_data = bytes(self.r2.cmdj(f"p8j {key_size} @ {addr}"))

                # Check if it looks like a key (high entropy)
                if self._is_high_entropy(key_data):
                    if "AES" not in self.extracted_keys:
                        self.extracted_keys["AES"] = {}

                    self.extracted_keys["AES"][f"key_{key_size * 8}"] = {
                        "address": addr,
                        "value": key_data.hex(),
                        "size": key_size * 8,
                    }

                    logger.info("Found potential AES-%d key at 0x%x", key_size * 8, addr)

    def _is_high_entropy(self, data: bytes) -> bool:
        """Check if data has high entropy (potential key material)."""
        return False if len(data) < 8 else len(set(data)) > len(data) * 0.6

    def _extract_custom_algorithms(self) -> None:
        """Extract custom algorithm patterns."""
        logger.info("Analyzing custom algorithms...")

        # Look for XOR key patterns
        self._extract_xor_keys()

        # Look for custom constants
        self._extract_custom_constants()

    def _extract_xor_keys(self) -> None:
        """Extract XOR keys from validation routines."""
        for flow in self.validation_flows:
            for op in flow.operations:
                if op.algorithm == CryptoAlgorithm.CUSTOM_XOR:
                    if "XOR" not in self.extracted_keys:
                        self.extracted_keys["XOR"] = []

                    self.extracted_keys["XOR"].append(
                        {
                            "address": op.address,
                            "key": op.parameters.get("key", 0),
                        },
                    )

    def _extract_custom_constants(self) -> None:
        """Extract custom constants from validation."""
        # Look for repeated constants in validation functions
        for flow in self.validation_flows:
            if func_constants := self._get_function_constants(flow.entry_point):
                if "CUSTOM" not in self.extracted_keys:
                    self.extracted_keys["CUSTOM"] = []

                self.extracted_keys["CUSTOM"].extend(func_constants)

    def _get_function_constants(self, func_addr: int) -> list[dict[str, Any]]:
        """Extract constants from function."""
        constants = []

        # Get function size
        func_info = self.r2.cmdj(f"afij @ {func_addr}")
        if not func_info or not func_info[0]:
            return constants

        size = func_info[0].get("size", 0)

        # Disassemble function
        disasm = self.r2.cmd(f"pd {size} @ {func_addr}")

        # Extract immediate values
        for line in disasm.split("\n"):
            # Look for mov instructions with immediates
            if "mov" in line and "0x" in line:
                if hex_match := re.search(r"0x[0-9a-fA-F]+", line):
                    value = int(hex_match.group(), 16)

                    # Filter out small values and addresses
                    if 0x100 <= value <= 0xFFFFFFFF:
                        constants.append(
                            {
                                "value": value,
                                "hex": hex(value),
                                "context": line.strip(),
                            },
                        )

        return constants

    def generate_keygens(self, languages: list[KeygenLanguage] = None) -> list[KeygenTemplate]:
        """Generate keygen source code."""
        if not languages:
            languages = [KeygenLanguage.PYTHON, KeygenLanguage.CPP, KeygenLanguage.JAVA]

        logger.info("Generating keygens...")

        templates = []

        for flow in self.validation_flows:
            # Determine algorithm chain
            algo_chain = [op.algorithm for op in flow.operations]

            for lang in languages:
                if template := self._generate_keygen_template(flow, algo_chain, lang):
                    templates.append(template)

        return templates

    def _generate_keygen_template(
        self,
        flow: ValidationFlow,
        algo_chain: list[CryptoAlgorithm],
        language: KeygenLanguage,
    ) -> KeygenTemplate | None:
        """Generate keygen template for specific language."""
        logger.info("Generating %s keygen...", language.value)

        if language == KeygenLanguage.PYTHON:
            return self._generate_python_keygen(flow, algo_chain)
        if language == KeygenLanguage.CPP:
            return self._generate_cpp_keygen(flow, algo_chain)
        if language == KeygenLanguage.JAVA:
            return self._generate_java_keygen(flow, algo_chain)
        # Add more languages as needed
        return None

    def _generate_python_keygen(self, flow: ValidationFlow, algo_chain: list[CryptoAlgorithm]) -> KeygenTemplate:
        """Generate Python keygen."""
        code = []
        dependencies = []

        code.extend(
            (
                "#!/usr/bin/env python3",
                '"""',
                "Keygen generated by Intellicrack Keygen Assistant",
                f"Algorithm chain: {' -> '.join(a.value for a in algo_chain)}",
                '"""',
                "",
            )
        )
        code.extend(("import hashlib", "import struct"))
        code.extend(("import random", "import string"))
        # Add crypto imports based on algorithms
        if CryptoAlgorithm.RSA in algo_chain:
            code.append("from Crypto.PublicKey import RSA")
            code.append("from Crypto.Cipher import PKCS1_OAEP")
            dependencies.append("pycryptodome")

        if CryptoAlgorithm.AES in algo_chain:
            code.append("from Crypto.Cipher import AES")
            code.append("from Crypto.Util.Padding import pad, unpad")
            dependencies.append("pycryptodome")

        code.append("")

        # Add extracted keys as constants
        self._add_python_constants(code)

        code.extend(
            (
                "def generate_serial(name: str) -> str:",
                '    """Generate serial key for given name"""',
            )
        )
        # Build algorithm chain
        for i, algo in enumerate(algo_chain):
            if algo == CryptoAlgorithm.MD5:
                code.append(f"    # Step {i + 1}: MD5 hash")
                code.append("    hash_obj = hashlib.md5()")
                code.append("    hash_obj.update(name.encode('utf-8'))")
                code.append("    digest = hash_obj.digest()")

            elif algo == CryptoAlgorithm.SHA256:
                code.append(f"    # Step {i + 1}: SHA-256 hash")
                code.append("    digest = hashlib.sha256(name.encode('utf-8')).digest()")

            elif algo == CryptoAlgorithm.CUSTOM_XOR:
                code.append(f"    # Step {i + 1}: XOR encryption")
                if self.extracted_keys.get("XOR"):
                    xor_key = self.extracted_keys["XOR"][0]["key"]
                    code.append(f"    xor_key = 0x{xor_key:08x}")
                else:
                    code.append("    xor_key = 0xDEADBEEF  # Default key")

                code.append("    result = []")
                code.append("    for i in range(0, len(digest), 4):")
                code.append("        chunk = struct.unpack('<I', digest[i:i+4])[0]")
                code.append("        result.append(struct.pack('<I', chunk ^ xor_key))")
                code.append("    digest = b''.join(result)")

            elif algo == CryptoAlgorithm.AES:
                code.append(f"    # Step {i + 1}: AES encryption")
                if "AES" in self.extracted_keys:
                    # Use extracted key
                    key_info = next(iter(self.extracted_keys["AES"].values()))
                    key_hex = key_info["value"]
                    code.append(f"    aes_key = bytes.fromhex('{key_hex}')")
                else:
                    code.append("    aes_key = b'\\x00' * 16  # Default key")

                code.append("    cipher = AES.new(aes_key, AES.MODE_ECB)")
                code.append("    padded = pad(digest, 16)")
                code.append("    digest = cipher.encrypt(padded)")

        code.extend(("", "    # Format serial"))
        if flow.serial_format:
            code.append(f"    # Format: {flow.serial_format}")
            self._add_serial_formatting(code, flow.serial_format)
        else:
            # Default formatting
            code.append("    serial_hex = digest[:8].hex().upper()")
            code.append("    serial = '-'.join(serial_hex[i:i+4] for i in range(0, 16, 4))")

        code.extend(("    return serial", ""))
        code.extend(("def main():", '    """Run keygen function"""'))
        code.extend(
            (
                '    print("Keygen - Generated by Intellicrack")',
                '    name = input("Enter name: ")',
            )
        )
        code.extend(
            (
                "    serial = generate_serial(name)",
                '    print(f"Serial: {serial}")',
            )
        )
        code.extend(("", 'if __name__ == "__main__":', "    main()"))
        # Create template
        template = KeygenTemplate(
            language=KeygenLanguage.PYTHON,
            algorithm_chain=algo_chain,
            source_code="\n".join(code),
            dependencies=dependencies,
            usage_instructions="Run with: python keygen.py",
        )

        return template

    def _add_python_constants(self, code: list[str]) -> None:
        """Add extracted constants to Python code."""
        code.append("# Extracted constants")

        if "RSA" in self.extracted_keys and "modulus" in self.extracted_keys["RSA"]:
            modulus_info = self.extracted_keys["RSA"]["modulus"]
            code.extend((
                f"RSA_MODULUS = {modulus_info['value']}",
                f"RSA_EXPONENT = {modulus_info['exponent']}",
                "",
            ))
        if "CUSTOM" in self.extracted_keys:
            code.append("CUSTOM_CONSTANTS = [")
            code.extend(f"    {const['hex']},  # {const['context']}" for const in self.extracted_keys["CUSTOM"][:10])
            code.extend(("]", ""))

    def _add_serial_formatting(self, code: list[str], format_pattern: str) -> None:
        """Add serial formatting code."""
        if format_pattern == "3x5":
            code.extend((
                "    # Convert to base32-like format",
                "    chars = string.ascii_uppercase + string.digits",
            ))
            code.extend(("    serial_parts = []", "    for i in range(3):"))
            code.extend(
                (
                    "        val = struct.unpack('<I', digest[i*4:i*4+4])[0]",
                    "        part = ''",
                )
            )
            code.extend(
                (
                    "        for j in range(5):",
                    "            part += chars[val % len(chars)]",
                )
            )
            code.extend(
                (
                    "            val //= len(chars)",
                    "        serial_parts.append(part)",
                    "    serial = '-'.join(serial_parts)",
                )
            )
        elif format_pattern == "4x4":
            code.append("    hex_str = digest.hex().upper()[:16]")
            code.append("    parts = [hex_str[i:i+4] for i in range(0, 16, 4)]")
            code.append("    serial = '-'.join(parts)")

        else:
            # Generic hex format
            code.append("    serial = digest.hex().upper()[:16]")

    def _generate_cpp_keygen(self, flow: ValidationFlow, algo_chain: list[CryptoAlgorithm]) -> KeygenTemplate:
        """Generate C++ keygen."""
        code = []
        dependencies = []

        code.extend(
            (
                "// Keygen generated by Intellicrack Keygen Assistant",
                f"// Algorithm chain: {' -> '.join(a.value for a in algo_chain)}",
                "",
                "#include <iostream>",
            )
        )
        code.extend(("#include <string>", "#include <sstream>"))
        code.extend(("#include <iomanip>", "#include <cstring>"))
        if CryptoAlgorithm.MD5 in algo_chain:
            code.append("#include <openssl/md5.h>")
            dependencies.append("openssl")

        if CryptoAlgorithm.SHA256 in algo_chain:
            code.append("#include <openssl/sha.h>")
            dependencies.append("openssl")

        if CryptoAlgorithm.AES in algo_chain:
            code.append("#include <openssl/aes.h>")
            dependencies.append("openssl")

        code.append("")

        # Add constants
        self._add_cpp_constants(code)

        # Generate function
        code.append("std::string generateSerial(const std::string& name) {")

        # Build algorithm chain
        current_var = "name"

        for i, algo in enumerate(algo_chain):
            if algo == CryptoAlgorithm.MD5:
                code.append(f"    // Step {i + 1}: MD5 hash")
                code.append("    unsigned char md5_digest[MD5_DIGEST_LENGTH];")
                code.append(f"    MD5((unsigned char*){current_var}.c_str(), {current_var}.length(), md5_digest);")
                current_var = "md5_digest"

            elif algo == CryptoAlgorithm.CUSTOM_XOR:
                code.append(f"    // Step {i + 1}: XOR encryption")
                if self.extracted_keys.get("XOR"):
                    xor_key = self.extracted_keys["XOR"][0]["key"]
                    code.append(f"    uint32_t xor_key = 0x{xor_key:08x};")
                else:
                    code.append("    uint32_t xor_key = 0xDEADBEEF;")

                code.append("    unsigned char xor_result[16];")
                code.append("    for (int i = 0; i < 16; i += 4) {")
                code.append(f"        uint32_t chunk = *(uint32_t*)({current_var} + i);")
                code.append("        *(uint32_t*)(xor_result + i) = chunk ^ xor_key;")
                code.append("    }")
                current_var = "xor_result"

        code.extend(("", "    // Format serial"))
        code.extend(
            (
                "    std::stringstream ss;",
                "    ss << std::hex << std::uppercase << std::setfill('0');",
            )
        )
        if flow.serial_format == "4x4":
            code.append("    for (int i = 0; i < 4; i++) {")
            code.append("        if (i > 0) ss << '-';")
            code.append(f"        ss << std::setw(4) << *(uint16_t*)({current_var} + i*2);")
        else:
            code.append("    for (int i = 0; i < 8; i++) {")
            code.append(f"        ss << std::setw(2) << (int){current_var}[i];")
        code.extend(("    }", "    return ss.str();"))
        code.extend(("}", ""))
        code.extend(
            (
                "int main() {",
                '    std::cout << "Keygen - Generated by Intellicrack" << std::endl;',
            )
        )
        code.extend(("    std::string name;", '    std::cout << "Enter name: ";'))
        code.extend(
            (
                "    std::getline(std::cin, name);",
                "    std::string serial = generateSerial(name);",
            )
        )
        code.extend(
            (
                '    std::cout << "Serial: " << serial << std::endl;',
                "    return 0;",
                "}",
            )
        )
        template = KeygenTemplate(
            language=KeygenLanguage.CPP,
            algorithm_chain=algo_chain,
            source_code="\n".join(code),
            dependencies=dependencies,
            usage_instructions="Compile with: g++ -o keygen keygen.cpp -lcrypto",
        )

        return template

    def _add_cpp_constants(self, code: list[str]) -> None:
        """Add extracted constants to C++ code."""
        code.append("// Extracted constants")

        if "RSA" in self.extracted_keys and "modulus" in self.extracted_keys["RSA"]:
            modulus_info = self.extracted_keys["RSA"]["modulus"]
            code.extend((
                "// RSA modulus extracted but requires big integer library",
                f"// Modulus bits: {modulus_info['bits']}",
                f"// Exponent: {modulus_info['exponent']}",
                "",
            ))
        if "CUSTOM" in self.extracted_keys:
            code.append("const uint32_t CUSTOM_CONSTANTS[] = {")
            code.extend(f"    {const['hex']}," for const in self.extracted_keys["CUSTOM"][:10])
            code.extend(("};", ""))

    def _generate_java_keygen(self, flow: ValidationFlow, algo_chain: list[CryptoAlgorithm]) -> KeygenTemplate:
        """Generate Java keygen."""
        code = []
        dependencies = []

        code.extend((
            "// Keygen generated by Intellicrack Keygen Assistant",
            f"// Algorithm chain: {' -> '.join(a.value for a in algo_chain)}",
        ))
        code.extend(("", "import java.util.Scanner;"))
        code.append("import java.security.MessageDigest;")

        if CryptoAlgorithm.AES in algo_chain:
            code.append("import javax.crypto.Cipher;")
            code.append("import javax.crypto.spec.SecretKeySpec;")

        code.extend(("", "public class Keygen {"))
        # Add constants
        self._add_java_constants(code)

        # Generate method
        code.append("    public static String generateSerial(String name) throws Exception {")

        # Build algorithm chain
        current_var = 'name.getBytes("UTF-8")'

        for i, algo in enumerate(algo_chain):
            if algo == CryptoAlgorithm.MD5:
                code.append(f"        // Step {i + 1}: MD5 hash")
                code.append('        MessageDigest md = MessageDigest.getInstance("MD5");')
                code.append(f"        byte[] digest = md.digest({current_var});")
                current_var = "digest"

            elif algo == CryptoAlgorithm.SHA256:
                code.append(f"        // Step {i + 1}: SHA-256 hash")
                code.append('        MessageDigest sha = MessageDigest.getInstance("SHA-256");')
                code.append(f"        byte[] digest = sha.digest({current_var});")
                current_var = "digest"

            elif algo == CryptoAlgorithm.CUSTOM_XOR:
                code.append(f"        // Step {i + 1}: XOR encryption")
                if self.extracted_keys.get("XOR"):
                    xor_key = self.extracted_keys["XOR"][0]["key"]
                    code.append(f"        int xorKey = 0x{xor_key:08x};")
                else:
                    code.append("        int xorKey = 0xDEADBEEF;")

                code.append(f"        byte[] xorResult = new byte[{current_var}.length];")
                code.append(f"        for (int i = 0; i < {current_var}.length; i += 4) {{")
                code.append("            int chunk = 0;")
                code.append("            for (int j = 0; j < 4 && i+j < " + current_var + ".length; j++) {")
                code.append(f"                chunk |= ({current_var}[i+j] & 0xFF) << (j*8);")
                code.append("            }")
                code.append("            chunk ^= xorKey;")
                code.append("            for (int j = 0; j < 4 && i+j < xorResult.length; j++) {")
                code.append("                xorResult[i+j] = (byte)((chunk >> (j*8)) & 0xFF);")
                code.append("            }")
                code.append("        }")
                current_var = "xorResult"

        code.extend(("", "        // Format serial"))
        code.extend(
            (
                "        StringBuilder serial = new StringBuilder();",
                "        for (int i = 0; i < 8 && i < "
                + current_var
                + ".length; i++) {",
            )
        )
        if flow.serial_format == "4x4":
            code.append("            if (i > 0 && i % 2 == 0) serial.append('-');")
        code.extend(
            (
                f'            serial.append(String.format("%02X", {current_var}[i] & 0xFF));',
                "        }",
            )
        )
        code.extend(("        return serial.toString();", "    }"))
        code.extend(("", "    public static void main(String[] args) {"))
        code.extend(
            (
                "        try {",
                '            System.out.println("Keygen - Generated by Intellicrack");',
            )
        )
        code.extend(
            (
                "            Scanner scanner = new Scanner(System.in);",
                '            System.out.print("Enter name: ");',
            )
        )
        code.extend(
            (
                "            String name = scanner.nextLine();",
                "            String serial = generateSerial(name);",
            )
        )
        code.extend(
            (
                '            System.out.println("Serial: " + serial);',
                "        } catch (Exception e) {",
            )
        )
        code.append("            e.printStackTrace();")
        code.append("        }")
        code.append("    }")
        code.append("}")

        template = KeygenTemplate(
            language=KeygenLanguage.JAVA,
            algorithm_chain=algo_chain,
            source_code="\n".join(code),
            dependencies=dependencies,
            usage_instructions="Compile: javac Keygen.java\nRun: java Keygen",
        )

        return template

    def _add_java_constants(self, code: list[str]) -> None:
        """Add extracted constants to Java code."""
        code.append("    // Extracted constants")

        if "CUSTOM" in self.extracted_keys:
            code.append("    private static final int[] CUSTOM_CONSTANTS = {")
            code.extend(f"        {const['hex']}," for const in self.extracted_keys["CUSTOM"][:10])
            code.extend(("    };", ""))

    def export_keygens(self, templates: list[KeygenTemplate], output_dir: str = "keygens") -> None:
        """Export generated keygens to files."""
        os.makedirs(output_dir, exist_ok=True)

        for i, template in enumerate(templates):
            # Determine file extension
            ext_map = {
                KeygenLanguage.PYTHON: ".py",
                KeygenLanguage.CPP: ".cpp",
                KeygenLanguage.JAVA: ".java",
                KeygenLanguage.CSHARP: ".cs",
                KeygenLanguage.JAVASCRIPT: ".js",
                KeygenLanguage.RUST: ".rs",
                KeygenLanguage.GO: ".go",
            }

            ext = ext_map.get(template.language, ".txt")
            filename = f"keygen_{i + 1}{ext}"
            filepath = os.path.join(output_dir, filename)

            with open(filepath, "w") as f:
                f.write(template.source_code)

            logger.info("Exported %s keygen to %s", template.language.value, filepath)

            # Write usage instructions
            readme_path = os.path.join(output_dir, f"README_{i + 1}.txt")
            with open(readme_path, "w") as f:
                f.write(f"Keygen {i + 1} - {template.language.value}\n")
                f.write("=" * 50 + "\n\n")
                f.write("Algorithm Chain:\n")
                f.writelines(f"  - {algo.value}\n" for algo in template.algorithm_chain)
                f.write("\n")
                f.write("Dependencies:\n")
                f.writelines(f"  - {dep}\n" for dep in template.dependencies)
                f.write("\n")
                f.write("Usage:\n")
                f.write(template.usage_instructions + "\n")

    def analyze_from_license_functions(self, license_functions: list[dict]) -> list[KeygenTemplate]:
        """Analyze validation from detected license functions."""
        logger.info("Analyzing license functions for keygen generation...")

        # Convert to addresses
        target_addrs = [int(f["address"], 16) for f in license_functions if f.get("confidence", 0) > 0.7]

        # Analyze validation flows
        self.analyze_validation(target_addrs)

        # Extract parameters
        self.extract_crypto_parameters()

        return self.generate_keygens()


def main() -> None:
    """Run the Radare2 keygen assistant."""
    if len(sys.argv) < 2:
        logger.error("Usage: radare2_keygen_assistant.py <binary> [license_analysis.json]")
        sys.exit(1)

    binary = sys.argv[1]

    logger.info("Analyzing %s for keygen generation", binary)

    # Create assistant
    assistant = R2KeygenAssistant(filename=binary)

    # Check if we have license analysis results
    if len(sys.argv) > 2:
        # Load license analysis
        with open(sys.argv[2]) as f:
            analysis = json.load(f)

        # Use detected functions
        templates = assistant.analyze_from_license_functions(analysis["functions"])

    else:
        # Manual mode - analyze common patterns
        logger.info("No license analysis provided, using heuristics...")

        # Find potential validation functions
        functions = assistant.r2.cmdj("aflj")
        target_funcs = []

        for func in functions:
            name = func.get("name", "").lower()
            if any(x in name for x in ["check", "valid", "verify", "auth"]):
                target_funcs.append(func["offset"])

        if target_funcs:
            assistant.analyze_validation(target_funcs[:5])  # Limit to 5
            assistant.extract_crypto_parameters()
            templates = assistant.generate_keygens()
        else:
            logger.warning("No validation functions found")
            templates = []

    # Export keygens
    if templates:
        assistant.export_keygens(templates)
        logger.info("Generated %d keygens!", len(templates))
    else:
        logger.warning("No keygens generated")

    logger.info("Analysis complete!")


if __name__ == "__main__":
    main()

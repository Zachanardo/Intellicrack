"""License key generation and validation analysis."""

import hashlib
import logging
import struct
import subprocess
import sys
import tempfile
import threading
import time
import zlib
from collections.abc import Callable
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any

import capstone
import z3

from intellicrack.core.serial_generator import GeneratedSerial, SerialConstraints, SerialFormat, SerialNumberGenerator

CREATE_SUSPENDED = 0x00000004 if sys.platform == "win32" else 0


@dataclass
class KeyConstraint:
    """Represents a constraint on license key generation."""

    constraint_type: str
    description: str
    value: Any
    confidence: float
    source_address: int | None = None
    assembly_context: str | None = None


@dataclass
class ValidationRoutine:
    """Represents a license validation routine found in binary."""

    address: int
    size: int
    instructions: list[tuple[int, str, str]]
    constraints: list[KeyConstraint] = field(default_factory=list)
    algorithm_type: str | None = None
    confidence: float = 0.0
    entry_points: list[int] = field(default_factory=list)
    xrefs: list[int] = field(default_factory=list)


class CryptoType(Enum):
    """Types of cryptographic primitives."""

    HASH = "hash"
    CIPHER = "cipher"
    SIGNATURE = "signature"
    CHECKSUM = "checksum"
    CUSTOM = "custom"


class AlgorithmType(Enum):
    """Types of validation algorithms."""

    MD5 = "md5"
    SHA1 = "sha1"
    SHA256 = "sha256"
    CRC32 = "crc32"
    RSA = "rsa"
    AES = "aes"
    CUSTOM = "custom"
    UNKNOWN = "unknown"


@dataclass
class CryptoPrimitive:
    """Represents a detected cryptographic primitive."""

    crypto_type: CryptoType
    algorithm: str
    offset: int
    constants: list[int] = field(default_factory=list)
    confidence: float = 0.0


@dataclass
class ValidationConstraint:
    """Represents a constraint extracted from validation code."""

    constraint_type: str
    value: Any
    offset: int
    description: str = ""


@dataclass
class PatchLocation:
    """Represents a location that can be patched to bypass validation."""

    offset: int
    instruction: str
    patch_type: str
    original_bytes: bytes
    suggested_patch: bytes
    description: str = ""


@dataclass
class ValidationAnalysis:
    """Complete analysis of a validation routine."""

    algorithm_type: AlgorithmType
    confidence: float
    crypto_primitives: list[CryptoPrimitive] = field(default_factory=list)
    constraints: list[ValidationConstraint] = field(default_factory=list)
    patch_points: list[PatchLocation] = field(default_factory=list)
    api_calls: list[str] = field(default_factory=list)
    embedded_constants: dict[str, bytes] = field(default_factory=dict)
    recommendations: list[str] = field(default_factory=list)


@dataclass
class ExtractedAlgorithm:
    """Represents an extracted license validation algorithm."""

    algorithm_name: str
    parameters: dict[str, Any]
    validation_function: Callable[[str], Any] | None = None
    key_format: SerialFormat | None = None
    constraints: list[KeyConstraint] = field(default_factory=list)
    confidence: float = 0.0


class ValidationAnalyzer:
    """Analyzes binary validation routines to extract algorithm and constraints."""

    MD5_CONSTANTS = [0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476]
    SHA1_CONSTANTS = [0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0]
    SHA256_CONSTANTS = [
        0x6A09E667,
        0xBB67AE85,
        0x3C6EF372,
        0xA54FF53A,
        0x510E527F,
        0x9B05688C,
        0x1F83D9AB,
        0x5BE0CD19,
    ]
    CRC32_POLYNOMIALS = [0xEDB88320, 0x04C11DB7]
    RSA_COMMON_EXPONENTS = [3, 17, 65537]

    def __init__(self) -> None:
        """Initialize the validation analyzer."""
        self.logger = logging.getLogger(__name__)
        self.md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
        self.md.detail = True

    def analyze(self, binary_code: bytes, entry_point: int = 0, arch: str = "x64") -> ValidationAnalysis:
        """Analyze binary validation routine and extract algorithm details.

        Args:
            binary_code: Raw bytes of the validation routine
            entry_point: Starting offset within binary_code
            arch: Architecture ("x64" or "x86")

        Returns:
            Analysis result with detected algorithm and constraints.

        """
        if arch == "x86":
            self.md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
        else:
            self.md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
        self.md.detail = True

        instructions = self._disassemble_routine(binary_code, entry_point)

        crypto_primitives = self._detect_crypto_constants(instructions, binary_code)

        api_calls = self._identify_api_calls(instructions)

        constraints = self._extract_constraints(instructions)

        patch_points = self._find_patch_points(instructions)

        algorithm_type, confidence = self._determine_algorithm(crypto_primitives, api_calls, constraints)

        embedded_constants = self._extract_embedded_constants(binary_code, instructions)

        recommendations = self._generate_recommendations(algorithm_type, crypto_primitives, patch_points)

        return ValidationAnalysis(
            algorithm_type=algorithm_type,
            confidence=confidence,
            crypto_primitives=crypto_primitives,
            constraints=constraints,
            patch_points=patch_points,
            api_calls=api_calls,
            embedded_constants=embedded_constants,
            recommendations=recommendations,
        )

    def _disassemble_routine(self, code: bytes, start: int, max_instructions: int = 500) -> list[Any]:
        """Disassemble validation routine code.

        Args:
            code: Binary code to disassemble
            start: Starting offset
            max_instructions: Maximum instructions to disassemble

        Returns:
            List of Capstone instruction objects.

        """
        instructions = []
        try:
            for i, instruction in enumerate(self.md.disasm(code[start:], start)):
                instructions.append(instruction)
                if i >= max_instructions:
                    break
                if instruction.mnemonic == "ret":
                    break
        except capstone.CsError as e:
            self.logger.warning("Disassembly error: %s", e)

        return instructions

    def _detect_crypto_constants(self, instructions: list[Any], binary_code: bytes) -> list[CryptoPrimitive]:
        """Detect cryptographic constants in disassembled code.

        Args:
            instructions: List of disassembled instructions
            binary_code: Original binary data for scanning

        Returns:
            List of detected cryptographic primitives.

        """
        primitives = []

        for instr in instructions:
            if instr.mnemonic in {"mov", "movabs", "lea"}:
                for operand in instr.operands:
                    if operand.type == capstone.x86.X86_OP_IMM:
                        imm_value = operand.imm

                        if imm_value in self.MD5_CONSTANTS:
                            primitives.append(
                                CryptoPrimitive(
                                    crypto_type=CryptoType.HASH,
                                    algorithm="MD5",
                                    offset=instr.address,
                                    constants=[imm_value],
                                    confidence=0.9,
                                ),
                            )
                        elif imm_value in self.SHA1_CONSTANTS:
                            primitives.append(
                                CryptoPrimitive(
                                    crypto_type=CryptoType.HASH,
                                    algorithm="SHA1",
                                    offset=instr.address,
                                    constants=[imm_value],
                                    confidence=0.85,
                                ),
                            )
                        elif imm_value in self.SHA256_CONSTANTS:
                            primitives.append(
                                CryptoPrimitive(
                                    crypto_type=CryptoType.HASH,
                                    algorithm="SHA256",
                                    offset=instr.address,
                                    constants=[imm_value],
                                    confidence=0.95,
                                ),
                            )
                        elif imm_value in self.CRC32_POLYNOMIALS:
                            primitives.append(
                                CryptoPrimitive(
                                    crypto_type=CryptoType.CHECKSUM,
                                    algorithm="CRC32",
                                    offset=instr.address,
                                    constants=[imm_value],
                                    confidence=0.9,
                                ),
                            )
                        elif imm_value in self.RSA_COMMON_EXPONENTS:
                            primitives.append(
                                CryptoPrimitive(
                                    crypto_type=CryptoType.SIGNATURE,
                                    algorithm="RSA",
                                    offset=instr.address,
                                    constants=[imm_value],
                                    confidence=0.8,
                                ),
                            )

        xor_chain_count = sum(
            all(instructions[j].mnemonic == "xor" for j in range(i, min(i + 3, len(instructions)))) for i in range(len(instructions) - 3)
        )
        if xor_chain_count > 5:
            primitives.append(
                CryptoPrimitive(
                    crypto_type=CryptoType.CHECKSUM,
                    algorithm="CUSTOM_XOR",
                    offset=instructions[0].address if instructions else 0,
                    constants=[],
                    confidence=0.7,
                ),
            )

        return primitives

    def _identify_api_calls(self, instructions: list[Any]) -> list[str]:
        """Identify cryptographic API calls in code.

        Args:
            instructions: List of disassembled instructions

        Returns:
            List of identified API function names.

        """
        api_calls: list[str] = []
        crypto_apis = {
            "CryptVerifySignature": "RSA signature verification",
            "CryptDecrypt": "Decryption operation",
            "CryptEncrypt": "Encryption operation",
            "CryptHashData": "Hash computation",
            "CryptCreateHash": "Hash object creation",
            "BCryptEncrypt": "Modern encryption (BCrypt)",
            "BCryptDecrypt": "Modern decryption (BCrypt)",
            "BCryptHashData": "Modern hash (BCrypt)",
            "MD5Init": "MD5 initialization",
            "SHA1Init": "SHA1 initialization",
            "SHA256Init": "SHA256 initialization",
        }

        for instr in instructions:
            if instr.mnemonic == "call":
                for op in instr.operands:
                    if op.type == capstone.x86.X86_OP_IMM:
                        api_calls.extend(crypto_apis)

        return api_calls

    def _extract_constraints(self, instructions: list[Any]) -> list[ValidationConstraint]:
        """Extract validation constraints from assembly instructions.

        Args:
            instructions: List of disassembled instructions

        Returns:
            List of extracted constraints.

        """
        constraints = []

        for idx, instr in enumerate(instructions):
            if instr.mnemonic == "cmp":
                if len(instr.operands) >= 2 and instr.operands[1].type == capstone.x86.X86_OP_IMM:
                    imm_value = instr.operands[1].imm

                    if 8 <= imm_value <= 64:
                        constraints.append(
                            ValidationConstraint(
                                constraint_type="length",
                                value=imm_value,
                                offset=instr.address,
                                description=f"Key length must be {imm_value}",
                            ),
                        )

                    if imm_value == 0x2D:
                        constraints.append(
                            ValidationConstraint(
                                constraint_type="separator",
                                value="-",
                                offset=instr.address,
                                description="Dash separator detected",
                            ),
                        )

                    if 0x30 <= imm_value <= 0x39:
                        constraints.append(
                            ValidationConstraint(
                                constraint_type="charset",
                                value="numeric",
                                offset=instr.address,
                                description=f"Numeric character check: {chr(imm_value)}",
                            ),
                        )
                    elif 0x41 <= imm_value <= 0x5A:
                        constraints.append(
                            ValidationConstraint(
                                constraint_type="charset",
                                value="uppercase",
                                offset=instr.address,
                                description=f"Uppercase letter check: {chr(imm_value)}",
                            ),
                        )

            elif instr.mnemonic == "test":
                if idx + 1 < len(instructions):
                    next_instr = instructions[idx + 1]
                    if next_instr.mnemonic in {"je", "jz"}:
                        constraints.append(
                            ValidationConstraint(
                                constraint_type="null_check",
                                value=True,
                                offset=instr.address,
                                description="Null/empty validation",
                            ),
                        )

        return constraints

    def _find_patch_points(self, instructions: list[Any]) -> list[PatchLocation]:
        """Find locations that can be patched to bypass validation.

        Args:
            instructions: List of disassembled instructions

        Returns:
            List of patchable locations.

        """
        patch_points = []

        for idx, instr in enumerate(instructions):
            if instr.mnemonic in {"je", "jne", "jz", "jnz", "jg", "jl", "jge", "jle"}:
                if idx > 0 and instructions[idx - 1].mnemonic in {"cmp", "test"}:
                    nop_patch = b"\x90" * instr.size

                    patch_points.append(
                        PatchLocation(
                            offset=instr.address,
                            instruction=f"{instr.mnemonic} {instr.op_str}",
                            patch_type="nop_conditional",
                            original_bytes=instr.bytes,
                            suggested_patch=nop_patch,
                            description=f"NOP out conditional jump at {hex(instr.address)}",
                        ),
                    )

                    if instr.mnemonic in {"je", "jz"}:
                        jmp_bytes = bytearray(instr.bytes)
                        if instr.size == 2:
                            jmp_bytes[0] = 0xEB
                        elif instr.size >= 5:
                            jmp_bytes[0] = 0xE9

                        patch_points.append(
                            PatchLocation(
                                offset=instr.address,
                                instruction=f"{instr.mnemonic} {instr.op_str}",
                                patch_type="force_jump",
                                original_bytes=instr.bytes,
                                suggested_patch=bytes(jmp_bytes),
                                description=f"Force unconditional jump at {hex(instr.address)}",
                            ),
                        )

            elif instr.mnemonic in {"mov", "movabs"}:
                if len(instr.operands) >= 2 and instr.operands[0].type == capstone.x86.X86_OP_REG:
                    reg_name = instr.reg_name(instr.operands[0].reg)
                    if reg_name in {"eax", "rax", "al"} and (idx + 1 < len(instructions) and instructions[idx + 1].mnemonic == "ret"):
                        success_patch = b"\xb8\x01\x00\x00\x00" if instr.size >= 5 else b"\xb0\x01"

                        patch_points.append(
                            PatchLocation(
                                offset=instr.address,
                                instruction=f"{instr.mnemonic} {instr.op_str}",
                                patch_type="force_success",
                                original_bytes=instr.bytes,
                                suggested_patch=success_patch,
                                description=f"Force return value to success at {hex(instr.address)}",
                            ),
                        )

        return patch_points

    def _determine_algorithm(
        self,
        crypto_primitives: list[CryptoPrimitive],
        api_calls: list[str],
        constraints: list[ValidationConstraint],
    ) -> tuple[AlgorithmType, float]:
        """Determine the validation algorithm type with confidence.

        Args:
            crypto_primitives: Detected cryptographic primitives
            api_calls: Identified API calls
            constraints: Extracted constraints

        Returns:
            Algorithm type and confidence score.

        """
        if not crypto_primitives and not api_calls:
            return (AlgorithmType.CUSTOM, 0.5)

        algorithm_votes: dict[AlgorithmType, float] = {}

        for primitive in crypto_primitives:
            if primitive.algorithm == "CRC32":
                algorithm_votes[AlgorithmType.CRC32] = max(
                    algorithm_votes.get(AlgorithmType.CRC32, 0.0),
                    primitive.confidence,
                )
            elif primitive.algorithm == "MD5":
                algorithm_votes[AlgorithmType.MD5] = max(
                    algorithm_votes.get(AlgorithmType.MD5, 0.0),
                    primitive.confidence,
                )
            elif primitive.algorithm == "RSA":
                algorithm_votes[AlgorithmType.RSA] = max(
                    algorithm_votes.get(AlgorithmType.RSA, 0.0),
                    primitive.confidence,
                )

            elif primitive.algorithm == "SHA1":
                algorithm_votes[AlgorithmType.SHA1] = max(
                    algorithm_votes.get(AlgorithmType.SHA1, 0.0),
                    primitive.confidence,
                )
            elif primitive.algorithm == "SHA256":
                algorithm_votes[AlgorithmType.SHA256] = max(
                    algorithm_votes.get(AlgorithmType.SHA256, 0.0),
                    primitive.confidence,
                )
        for api_call in api_calls:
            if "MD5" in api_call:
                algorithm_votes[AlgorithmType.MD5] = max(algorithm_votes.get(AlgorithmType.MD5, 0.0), 0.8)
            elif "SHA1" in api_call:
                algorithm_votes[AlgorithmType.SHA1] = max(algorithm_votes.get(AlgorithmType.SHA1, 0.0), 0.8)
            elif "SHA256" in api_call:
                algorithm_votes[AlgorithmType.SHA256] = max(algorithm_votes.get(AlgorithmType.SHA256, 0.0), 0.8)
            elif "Crypt" in api_call and "Signature" in api_call:
                algorithm_votes[AlgorithmType.RSA] = max(algorithm_votes.get(AlgorithmType.RSA, 0.0), 0.85)

        if algorithm_votes:
            return max(algorithm_votes.items(), key=lambda x: x[1])
        return (AlgorithmType.UNKNOWN, 0.3)

    def _extract_embedded_constants(self, binary_code: bytes, instructions: list[Any]) -> dict[str, bytes]:
        """Extract embedded constants from binary code.

        Args:
            binary_code: Raw binary data
            instructions: Disassembled instructions for reference

        Returns:
            Dictionary of named constants.

        """
        constants = {}

        for idx in range(0, len(binary_code) - 16, 4):
            dword = struct.unpack("<I", binary_code[idx : idx + 4])[0]

            if dword in self.MD5_CONSTANTS:
                constants[f"md5_const_{hex(dword)}"] = binary_code[idx : idx + 4]
            elif dword in self.SHA256_CONSTANTS:
                constants[f"sha256_const_{hex(dword)}"] = binary_code[idx : idx + 4]
            elif dword in self.CRC32_POLYNOMIALS:
                constants[f"crc32_poly_{hex(dword)}"] = binary_code[idx : idx + 4]

        for idx in range(len(binary_code) - 32):
            chunk = binary_code[idx : idx + 32]
            if len(set(chunk)) > 16 and all(32 <= b < 127 or b in {9, 10, 13} for b in chunk):
                try:
                    ascii_str = chunk.decode("ascii").rstrip("\x00")
                    if len(ascii_str) >= 8:
                        constants[f"string_{hex(idx)}"] = chunk
                except ValueError:
                    pass

        return constants

    def _generate_recommendations(
        self,
        algorithm_type: AlgorithmType,
        crypto_primitives: list[CryptoPrimitive],
        patch_points: list[PatchLocation],
    ) -> list[str]:
        """Generate actionable recommendations for cracking.

        Args:
            algorithm_type: Detected algorithm type
            crypto_primitives: List of crypto primitives found
            patch_points: List of patchable locations

        Returns:
            List of recommendation strings.

        """
        recommendations: list[str] = []

        if algorithm_type == AlgorithmType.MD5:
            recommendations.extend((
                "MD5 hash detected - consider rainbow table attack or keygen with hash matching",
                "Look for input transformation before MD5 - may reveal key format requirements",
            ))
        elif algorithm_type == AlgorithmType.SHA1:
            recommendations.append("SHA1 hash detected - analyze input preparation for keygen creation")
        elif algorithm_type == AlgorithmType.SHA256:
            recommendations.append("SHA256 hash detected - strong algorithm, focus on input analysis or patching")
        elif algorithm_type == AlgorithmType.CRC32:
            recommendations.extend((
                "CRC32 checksum detected - easily reversible, create keygen with CRC matching",
                "Extract CRC polynomial and generate valid checksums",
            ))
        elif algorithm_type == AlgorithmType.RSA:
            recommendations.extend((
                "RSA signature detected - extract public key and analyze key format",
                "Consider patching signature verification instead of key generation",
            ))
        elif algorithm_type == AlgorithmType.CUSTOM:
            recommendations.extend((
                "Custom algorithm detected - perform dynamic analysis to trace validation logic",
                "Use debugger to capture input/output of validation function",
            ))
        if patch_points:
            recommendations.extend((
                f"Found {len(patch_points)} potential patch points for binary modification",
                "Priority: Patch conditional jumps to bypass validation checks",
            ))
        if crypto_primitives:
            hash_primitives = [p for p in crypto_primitives if p.crypto_type == CryptoType.HASH]
            if len(hash_primitives) > 1:
                recommendations.append("Multiple hash algorithms detected - composite validation scheme")

        if not patch_points and algorithm_type == AlgorithmType.UNKNOWN:
            recommendations.extend((
                "Limited information - recommend dynamic analysis with debugger",
                "Set breakpoints on string comparison functions (strcmp, memcmp)",
            ))
        return recommendations


class ConstraintExtractor:
    """Extracts license key constraints from binary files."""

    def __init__(self, binary_path: Path) -> None:
        """Initialize the constraint extractor.

        Args:
            binary_path: Path to the binary file to analyze

        """
        self.binary_path = Path(binary_path)
        self.logger = logging.getLogger(__name__)
        self.algorithms: list[ExtractedAlgorithm] = []
        self._binary_data: bytes | None = None
        self._md: capstone.Cs | None = None

    def extract_constraints(self) -> list[KeyConstraint]:
        """Extract license key constraints from the binary file.

        Analyzes the binary to identify validation routines and extracts
        constraints that govern key format, length, character sets, and
        validation algorithms.

        Returns:
            List of KeyConstraint objects describing validation requirements.

        """
        constraints: list[KeyConstraint] = []

        try:
            if not self.binary_path.exists():
                self.logger.error("Binary file not found: %s", self.binary_path)
                return constraints

            with open(self.binary_path, "rb") as f:
                self._binary_data = f.read()

            self._md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
            self._md.detail = True

            constraints.extend(self._extract_string_constraints())
            constraints.extend(self._extract_crypto_constraints())
            constraints.extend(self._extract_format_constraints())
            constraints.extend(self._extract_length_constraints())

        except OSError as e:
            self.logger.exception("Failed to read binary file: %s", e)
        except Exception as e:
            self.logger.exception("Constraint extraction failed: %s", e)

        return constraints

    def _extract_string_constraints(self) -> list[KeyConstraint]:
        """Extract constraints from string patterns in the binary.

        Scans the binary for license-related keywords and format patterns
        that may indicate key structure or validation requirements.

        Returns:
            List of extracted string pattern constraints.

        """
        constraints: list[KeyConstraint] = []

        if not self._binary_data:
            return constraints

        license_patterns = [
            (b"LICENSE", "license_keyword"),
            (b"SERIAL", "serial_keyword"),
            (b"KEY", "key_keyword"),
            (b"ACTIVATION", "activation_keyword"),
            (b"REGISTRATION", "registration_keyword"),
        ]

        format_patterns = [
            (rb"[A-Z0-9]{5}-[A-Z0-9]{5}-[A-Z0-9]{5}-[A-Z0-9]{5}-[A-Z0-9]{5}", "microsoft_format"),
            (rb"[A-Z0-9]{4}-[A-Z0-9]{4}-[A-Z0-9]{4}-[A-Z0-9]{4}", "standard_format"),
            (rb"[0-9]{4}-[0-9]{4}-[0-9]{4}", "numeric_format"),
        ]

        import re

        for pattern, pattern_type in license_patterns:
            if pattern in self._binary_data:
                offset = self._binary_data.find(pattern)
                constraints.append(
                    KeyConstraint(
                        constraint_type="keyword",
                        description=f"Found {pattern_type} at offset {hex(offset)}",
                        value=pattern.decode("utf-8", errors="ignore"),
                        confidence=0.6,
                        source_address=offset,
                    )
                )

        for regex_pattern, format_type in format_patterns:
            if matches := list(re.finditer(regex_pattern, self._binary_data)):
                constraints.extend(
                    KeyConstraint(
                        constraint_type="format",
                        description=f"Detected {format_type} pattern",
                        value=format_type,
                        confidence=0.75,
                        source_address=match.start(),
                    )
                    for match in matches[:3]
                )
        return constraints

    def _extract_crypto_constraints(self) -> list[KeyConstraint]:
        """Extract constraints from cryptographic constants.

        Identifies cryptographic algorithm signatures and constants in the
        binary that indicate which hashing or encryption algorithms are used
        for license validation.

        Returns:
            List of cryptographic algorithm constraints.

        """
        constraints: list[KeyConstraint] = []

        if not self._binary_data:
            return constraints

        crypto_signatures = {
            bytes([0x67, 0x45, 0x23, 0x01]): ("md5", "MD5 initialization constant"),
            bytes([0x01, 0x23, 0x45, 0x67]): ("md5_be", "MD5 big-endian constant"),
            bytes([0xF0, 0xE1, 0xD2, 0xC3]): ("sha1", "SHA1 constant"),
            bytes([0x67, 0xE6, 0x09, 0x6A]): ("sha256", "SHA256 constant"),
            bytes([0x20, 0x83, 0xB8, 0xED]): ("crc32", "CRC32 polynomial (reversed)"),
            bytes([0xB7, 0x1D, 0xC1, 0x04]): ("crc32_norm", "CRC32 polynomial (normal)"),
        }

        for signature, (algo_name, description) in crypto_signatures.items():
            offset = self._binary_data.find(signature)
            if offset != -1:
                constraints.append(
                    KeyConstraint(
                        constraint_type="algorithm",
                        description=description,
                        value=algo_name,
                        confidence=0.85,
                        source_address=offset,
                    )
                )

        rsa_exponents = [
            (b"\x01\x00\x01\x00", 65537, "RSA public exponent 65537"),
            (b"\x11\x00\x00\x00", 17, "RSA public exponent 17"),
            (b"\x03\x00\x00\x00", 3, "RSA public exponent 3"),
        ]

        for pattern, value, description in rsa_exponents:
            offset = self._binary_data.find(pattern)
            if offset != -1:
                constraints.append(
                    KeyConstraint(
                        constraint_type="rsa_exponent",
                        description=description,
                        value=value,
                        confidence=0.7,
                        source_address=offset,
                    )
                )

        return constraints

    def _extract_format_constraints(self) -> list[KeyConstraint]:
        """Extract key format constraints from binary patterns.

        Analyzes the binary for separator characters and patterns that
        indicate the expected format and structure of license keys.

        Returns:
            List of key format constraints.

        """
        constraints: list[KeyConstraint] = []

        if not self._binary_data:
            return constraints

        separator_patterns = [
            (b"-", "dash"),
            (b"_", "underscore"),
            (b":", "colon"),
        ]

        for sep, sep_name in separator_patterns:
            sep_count = self._binary_data.count(sep)
            if sep_count > 100:
                constraints.append(
                    KeyConstraint(
                        constraint_type="separator",
                        description=f"Frequent {sep_name} separator detected",
                        value=sep.decode(),
                        confidence=0.5,
                    )
                )

        return constraints

    def _extract_length_constraints(self) -> list[KeyConstraint]:
        """Extract key length constraints from comparison operations.

        Scans for length validation checks in the binary that indicate
        expected license key lengths.

        Returns:
            List of key length constraints.

        """
        constraints: list[KeyConstraint] = []

        if not self._binary_data or not self._md:
            return constraints

        common_lengths = [16, 20, 25, 29, 32, 36]

        for length in common_lengths:
            length_bytes_le = struct.pack("<I", length)
            length_bytes_be = struct.pack(">I", length)

            for length_pattern in [length_bytes_le, length_bytes_be]:
                offset = 0
                while True:
                    pos = self._binary_data.find(length_pattern, offset)
                    if pos == -1:
                        break

                    context_start = max(0, pos - 16)
                    context_end = min(len(self._binary_data), pos + 20)
                    context = self._binary_data[context_start:context_end]

                    cmp_indicators = [b"\x83", b"\x3d", b"\x81", b"\x39"]
                    if any(ind in context for ind in cmp_indicators):
                        constraints.append(
                            KeyConstraint(
                                constraint_type="length",
                                description=f"Possible key length check: {length}",
                                value=length,
                                confidence=0.6,
                                source_address=pos,
                            )
                        )
                        break

                    offset = pos + 1

        return constraints

    def analyze_validation_algorithms(self) -> list[ExtractedAlgorithm]:
        """Analyze and extract validation algorithms from constraints.

        Returns:
            List of extracted validation algorithms.

        """
        constraints = self.extract_constraints()

        algorithm_types = self._group_constraints_by_algorithm(constraints)

        for algo_type, algo_constraints in algorithm_types.items():
            if algorithm := self._build_algorithm(algo_type, algo_constraints):
                self.algorithms.append(algorithm)

        if not self.algorithms:
            self.algorithms.append(self._create_generic_algorithm(constraints))

        return self.algorithms

    def _group_constraints_by_algorithm(self, constraints: list[KeyConstraint]) -> dict[str, list[KeyConstraint]]:
        """Group extracted constraints by their associated algorithm type.

        Organizes constraints into algorithm-specific groups to facilitate
        algorithm detection and selection.

        Args:
            constraints: List of extracted constraints to group.

        Returns:
            Constraints grouped by algorithm name.

        """
        groups: dict[str, list[KeyConstraint]] = {}

        for constraint in constraints:
            if constraint.constraint_type == "algorithm":
                algo_name = constraint.value
                if algo_name not in groups:
                    groups[algo_name] = []
                groups[algo_name].append(constraint)

        if "generic" not in groups:
            groups["generic"] = [c for c in constraints if c.constraint_type != "algorithm"]

        return groups

    def _build_algorithm(self, algo_type: str, constraints: list[KeyConstraint]) -> ExtractedAlgorithm | None:
        """Build an algorithm object from type and constraints.

        Constructs an ExtractedAlgorithm instance based on the identified
        algorithm type and its associated constraints.

        Args:
            algo_type: The type of algorithm to build.
            constraints: List of constraints associated with the algorithm.

        Returns:
            The built algorithm or None if unsupported.

        """
        if algo_type == "crc":
            return self._build_crc_algorithm(constraints)
        if algo_type in {"md5", "sha1", "sha256"}:
            return self._build_hash_algorithm(algo_type, constraints)
        if algo_type == "multiplicative_hash":
            return self._build_multiplicative_algorithm(constraints)
        if algo_type == "modular":
            return self._build_modular_algorithm(constraints)
        return self._build_generic_algorithm(constraints)

    def _build_crc_algorithm(self, constraints: list[KeyConstraint]) -> ExtractedAlgorithm:
        """Build a CRC32 validation algorithm.

        Constructs a CRC32-based algorithm from extracted constraints,
        including polynomial detection and validation function setup.

        Args:
            constraints: List of constraints associated with CRC32.

        Returns:
            The constructed CRC32 algorithm.

        """
        polynomial = 0xEDB88320

        for constraint in constraints:
            if "CRC32" in str(constraint.value):
                polynomial = 0xEDB88320 if "reversed" in str(constraint.value) else 0x04C11DB7

        def crc32_validate(key: str) -> int:
            """Validate key using CRC32 checksum.

            Args:
                key: The license key to validate.

            Returns:
                The CRC32 checksum value.

            """
            return zlib.crc32(key.encode()) & 0xFFFFFFFF

        return ExtractedAlgorithm(
            algorithm_name="CRC32",
            parameters={"polynomial": polynomial},
            validation_function=crc32_validate,
            key_format=SerialFormat.ALPHANUMERIC,
            constraints=constraints,
            confidence=0.85,
        )

    def _build_hash_algorithm(self, algo_type: str, constraints: list[KeyConstraint]) -> ExtractedAlgorithm:
        """Build a hash-based validation algorithm.

        Constructs a hash algorithm (MD5, SHA1, or SHA256) from extracted
        constraints with appropriate validation function.

        Args:
            algo_type: The hash algorithm type (md5, sha1, or sha256).
            constraints: List of constraints associated with the hash.

        Returns:
            The constructed hash algorithm.

        """
        hash_functions = {
            "md5": hashlib.md5,
            "sha1": hashlib.sha1,
            "sha256": hashlib.sha256,
        }

        hash_func = hash_functions.get(algo_type, hashlib.sha256)

        def hash_validate(key: str) -> str:
            """Validate key using hash algorithm.

            Args:
                key: The license key to validate.

            Returns:
                The hex digest of the hash.

            """
            return hash_func(key.encode()).hexdigest()

        return ExtractedAlgorithm(
            algorithm_name=algo_type.upper(),
            parameters={"hash_function": algo_type},
            validation_function=hash_validate,
            key_format=SerialFormat.HEXADECIMAL,
            constraints=constraints,
            confidence=0.9,
        )

    def _build_multiplicative_algorithm(self, constraints: list[KeyConstraint]) -> ExtractedAlgorithm:
        """Build a multiplicative hash validation algorithm.

        Constructs a multiplicative hash-based algorithm for key validation
        using a constant multiplier.

        Args:
            constraints: List of constraints associated with the algorithm.

        Returns:
            The constructed multiplicative algorithm.

        """
        def multiplicative_validate(key: str) -> int:
            """Validate key using multiplicative hash.

            Args:
                key: The license key to validate.

            Returns:
                The multiplicative hash value.

            """
            result = 0
            multiplier = 31
            for char in key:
                result = result * multiplier + ord(char)
            return result & 0xFFFFFFFF

        return ExtractedAlgorithm(
            algorithm_name="Multiplicative Hash",
            parameters={"multiplier": 31},
            validation_function=multiplicative_validate,
            key_format=SerialFormat.ALPHANUMERIC,
            constraints=constraints,
            confidence=0.75,
        )

    def _build_modular_algorithm(self, constraints: list[KeyConstraint]) -> ExtractedAlgorithm:
        """Build a modular arithmetic validation algorithm.

        Constructs a modular arithmetic-based algorithm for license key
        validation using a constant modulus.

        Args:
            constraints: List of constraints associated with the algorithm.

        Returns:
            The constructed modular algorithm.

        """
        modulus = 97

        def modular_validate(key: str) -> int:
            """Validate key using modular arithmetic.

            Args:
                key: The license key to validate.

            Returns:
                The modular arithmetic result.

            """
            numeric = "".join(c if c.isdigit() else str(ord(c) - ord("A") + 10) for c in key)
            return int(numeric) % modulus

        return ExtractedAlgorithm(
            algorithm_name="Modular Arithmetic",
            parameters={"modulus": modulus},
            validation_function=modular_validate,
            key_format=SerialFormat.ALPHANUMERIC,
            constraints=constraints,
            confidence=0.7,
        )

    def _build_generic_algorithm(self, constraints: list[KeyConstraint]) -> ExtractedAlgorithm:
        """Build a generic fallback validation algorithm.

        Creates a basic algorithm when no specific algorithm type can be
        determined from constraints.

        Args:
            constraints: List of extracted constraints.

        Returns:
            ExtractedAlgorithm: A generic algorithm with default parameters.

        """
        return ExtractedAlgorithm(
            algorithm_name="Generic",
            parameters={},
            validation_function=None,
            key_format=SerialFormat.ALPHANUMERIC,
            constraints=constraints,
            confidence=0.5,
        )

    def _create_generic_algorithm(self, constraints: list[KeyConstraint]) -> ExtractedAlgorithm:
        """Create a generic algorithm for fallback key generation.

        Wraps the algorithm building logic to provide a clean interface for
        creating a generic algorithm when no specific algorithm is identified.

        Args:
            constraints: List of extracted constraints.

        Returns:
            ExtractedAlgorithm: A generic algorithm with default settings.

        """
        return self._build_generic_algorithm(constraints)


class KeySynthesizer:
    """Synthesizes license keys based on extracted algorithms."""

    def __init__(self) -> None:
        """Initialize the key synthesizer."""
        self.logger = logging.getLogger(__name__)
        self.generator = SerialNumberGenerator()
        self.solver = z3.Solver()

    def synthesize_key(
        self,
        algorithm: ExtractedAlgorithm,
        target_data: dict[str, Any] | None = None,
    ) -> GeneratedSerial:
        """Synthesize a license key from the extracted algorithm.

        Creates a license key based on the algorithm's validation function
        and constraints, optionally using target data as a seed.

        Args:
            algorithm: The algorithm to use for key generation.
            target_data: Optional dictionary of target data to influence generation.

        Returns:
            GeneratedSerial: The synthesized license key.

        """
        if algorithm.validation_function:
            return self._synthesize_with_validation(algorithm, target_data)
        return self._synthesize_from_constraints(algorithm, target_data)

    def _synthesize_with_validation(
        self,
        algorithm: ExtractedAlgorithm,
        target_data: dict[str, Any] | None = None,
    ) -> GeneratedSerial:
        """Synthesize a key using the algorithm's validation function.

        Generates candidate keys and validates them against the algorithm's
        validation function, returning the first valid candidate or a default.

        Args:
            algorithm: The algorithm with validation function to use.
            target_data: Optional target data to seed generation.

        Returns:
            GeneratedSerial: A valid synthesized serial or default fallback.

        """
        constraints = self._build_serial_constraints(algorithm)

        if target_data:
            hash_digest = hashlib.sha256(str(target_data).encode()).digest()
            seed_value = int.from_bytes(hash_digest[:16], byteorder="big")
        else:
            seed_value = 0

        max_attempts = 10000
        for attempt in range(max_attempts):
            deterministic_seed = seed_value + attempt
            candidate = self.generator.generate_serial(constraints, seed=deterministic_seed)

            try:
                if algorithm.validation_function is not None and algorithm.validation_function(candidate.serial):
                    candidate.confidence = algorithm.confidence
                    candidate.algorithm = algorithm.algorithm_name
                    return candidate
            except Exception as e:
                self.logger.debug("Validation failed for candidate %s: %s", candidate.serial, e)
                continue

        return self.generator.generate_serial(constraints)

    def _synthesize_from_constraints(
        self,
        algorithm: ExtractedAlgorithm,
        target_data: dict[str, Any] | None = None,
    ) -> GeneratedSerial:
        """Synthesize a key from algorithm constraints only.

        Generates a key using only the algorithm's constraint specifications
        without validation, used when no validation function is available.

        Args:
            algorithm: The algorithm with constraints to use.
            target_data: Optional target data to seed generation.

        Returns:
            GeneratedSerial: The synthesized serial based on constraints.

        """
        constraints = self._build_serial_constraints(algorithm)

        seed_value: int | None = None
        if target_data:
            hash_digest = hashlib.sha256(str(target_data).encode()).digest()
            seed_value = int.from_bytes(hash_digest[:16], byteorder="big")

        return self.generator.generate_serial(constraints, seed=seed_value)

    def _build_serial_constraints(self, algorithm: ExtractedAlgorithm) -> SerialConstraints:
        """Build serial number constraints from an algorithm.

        Extracts and interprets algorithm-specific constraints to create
        a SerialConstraints object for key generation.

        Args:
            algorithm: The algorithm to extract constraints from.

        Returns:
            SerialConstraints: The configured serial generation constraints.

        """
        length = 16
        format_type = algorithm.key_format or SerialFormat.ALPHANUMERIC
        groups = 1
        separator = "-"
        checksum_algo = None

        for constraint in algorithm.constraints:
            if constraint.constraint_type == "length":
                length = constraint.value
            elif constraint.constraint_type == "format":
                if "microsoft" in str(constraint.value).lower():
                    format_type = SerialFormat.MICROSOFT
                    length = 25
                    groups = 5
            elif constraint.constraint_type == "separator":
                separator = constraint.value
            elif constraint.constraint_type == "checksum":
                checksum_algo = constraint.value

        return SerialConstraints(
            length=length,
            format=format_type,
            groups=groups,
            group_separator=separator,
            checksum_algorithm=checksum_algo,
        )

    def synthesize_batch(
        self,
        algorithm: ExtractedAlgorithm,
        count: int,
        unique: bool = True,
    ) -> list[GeneratedSerial]:
        """Synthesize a batch of license keys.

        Args:
            algorithm: The algorithm to use for key generation
            count: Number of keys to generate
            unique: Whether keys should be unique

        Returns:
            list[GeneratedSerial]: List of generated serial keys.

        """
        keys = []
        generated_set = set()

        max_retries = 10
        for i in range(count):
            target_data = {"index": i} if unique else None

            for retry in range(max_retries):
                key = self.synthesize_key(algorithm, target_data)

                if not unique or key.serial not in generated_set:
                    keys.append(key)
                    generated_set.add(key.serial)
                    break

                target_data = {"index": i, "retry": retry}

        return keys

    def synthesize_for_user(
        self,
        algorithm: ExtractedAlgorithm,
        username: str,
        email: str | None = None,
        hardware_id: str | None = None,
    ) -> GeneratedSerial:
        """Synthesize a license key for a specific user.

        Args:
            algorithm: The algorithm to use for key generation
            username: Username for the license
            email: Optional email address
            hardware_id: Optional hardware identifier

        Returns:
            GeneratedSerial: Generated serial key for the user.

        """
        user_data = {"username": username}
        if email:
            user_data["email"] = email
        if hardware_id:
            user_data["hardware_id"] = hardware_id

        key = self.synthesize_key(algorithm, user_data)
        key.hardware_id = hardware_id

        return key

    def synthesize_with_z3(self, constraints: list[KeyConstraint]) -> str | None:
        """Synthesize a key using Z3 constraint solver.

        Uses the Z3 SMT solver to find a key that satisfies all extracted
        constraints from the validation routine.

        Args:
            constraints: List of constraints extracted from validation code.

        Returns:
            str | None: A synthesized key satisfying constraints, or None if unsatisfiable.

        """
        self.solver.reset()

        key_length = next(
            (constraint.value for constraint in constraints if constraint.constraint_type == "length"),
            16,
        )
        key_vars = [z3.BitVec(f"k{i}", 8) for i in range(key_length)]

        for constraint in constraints:
            if constraint.constraint_type == "charset":
                charset_type = constraint.value
                if charset_type == "numeric":
                    for var in key_vars:
                        self.solver.add(z3.And(var >= ord("0"), var <= ord("9")))
                elif charset_type == "uppercase":
                    for var in key_vars:
                        self.solver.add(z3.And(var >= ord("A"), var <= ord("Z")))
                elif charset_type == "alphanumeric":
                    for var in key_vars:
                        self.solver.add(
                            z3.Or(
                                z3.And(var >= ord("0"), var <= ord("9")),
                                z3.And(var >= ord("A"), var <= ord("Z")),
                            ),
                        )

        if self.solver.check() == z3.sat:
            model = self.solver.model()
            key_chars = []

            for var in key_vars:
                value = model.eval(var)
                if value is not None:
                    key_chars.append(chr(value.as_long()))
                else:
                    key_chars.append("A")

            return "".join(key_chars)

        return None


@dataclass
class ValidationResult:
    """Result from testing a generated key against a target binary."""

    key: str
    is_valid: bool
    validation_method: str
    execution_time: float
    error_message: str | None = None
    stdout_output: str | None = None
    stderr_output: str | None = None
    return_code: int | None = None
    frida_logs: list[str] = field(default_factory=list)
    memory_snapshots: dict[str, bytes] = field(default_factory=dict)
    register_states: dict[str, int] = field(default_factory=dict)


@dataclass
class ValidationConfig:
    """Configuration for key validation testing."""

    timeout_seconds: int = 30
    use_frida: bool = True
    use_debugger: bool = False
    use_patching: bool = False
    capture_stdout: bool = True
    capture_stderr: bool = True
    save_memory_dumps: bool = False
    architecture: str = "x64"
    validation_functions: list[str] = field(default_factory=list)
    success_indicators: list[str] = field(default_factory=list)
    failure_indicators: list[str] = field(default_factory=list)


class KeyValidator:
    """Validates generated license keys against real protected binaries."""

    def __init__(self, binary_path: Path, config: ValidationConfig | None = None) -> None:
        """Initialize the key validator.

        Args:
            binary_path: Path to the binary to test keys against
            config: Optional validation configuration

        """
        self.binary_path = Path(binary_path)
        self.config = config or ValidationConfig()
        self.logger = logging.getLogger(__name__)
        self._frida_session: Any = None
        self._debugger: Any = None
        self._lock = threading.Lock()

    def _safe_terminate_process(self, process: subprocess.Popen[bytes]) -> None:
        """Safely terminate a subprocess, handling errors gracefully.

        Args:
            process: The subprocess to terminate

        """
        try:
            process.terminate()
            try:
                process.wait(timeout=2)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=1)
        except Exception as e:
            self.logger.debug("Process termination error (may already be terminated): %s", e)

    def validate_key(self, key: str) -> ValidationResult:
        """Validate a license key against the target binary.

        Tests whether a generated key is accepted by the protected binary
        using dynamic analysis, debugging, or patching techniques.

        Args:
            key: The license key to validate

        Returns:
            ValidationResult containing validation outcome and details.

        """
        start_time = time.time()

        if self.config.use_frida:
            result = self._validate_with_frida(key)
        elif self.config.use_debugger:
            result = self._validate_with_debugger(key)
        else:
            result = self._validate_with_execution(key)

        result.execution_time = time.time() - start_time
        return result

    def _validate_with_frida(self, key: str) -> ValidationResult:
        """Validate key using Frida dynamic instrumentation.

        Attaches to the target process with Frida and intercepts license
        validation functions to determine if the key is accepted.

        Args:
            key: The license key to validate

        Returns:
            ValidationResult with Frida-based validation outcome.

        """
        try:
            import frida
        except ImportError:
            self.logger.error("Frida not available, falling back to execution testing")
            return self._validate_with_execution(key)

        frida_script = self._generate_validation_script(key)
        logs: list[str] = []
        validation_passed = False
        error_msg = None
        completion_event = threading.Event()
        process: subprocess.Popen[bytes] | None = None

        try:
            process = subprocess.Popen(
                [str(self.binary_path), key],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )

            session = frida.attach(process.pid)

            script = session.create_script(frida_script)

            def on_message(message: dict[str, Any], data: Any) -> None:
                nonlocal validation_passed, logs
                if message.get("type") == "send":
                    payload = message.get("payload", {})
                    log_entry = str(payload)
                    logs.append(log_entry)

                    if payload.get("validation") == "success":
                        validation_passed = True
                        if payload.get("final"):
                            completion_event.set()
                    elif payload.get("validation") == "failure":
                        validation_passed = False
                        if payload.get("final"):
                            completion_event.set()

            script.on("message", on_message)
            script.load()

            completion_event.wait(timeout=self.config.timeout_seconds)

            session.detach()
            self._safe_terminate_process(process)

        except frida.ProcessNotFoundError:
            error_msg = "Process terminated before Frida could attach"
            if process:
                self._safe_terminate_process(process)
        except Exception as e:
            error_msg = f"Frida validation error: {e!s}"
            self.logger.exception("Frida validation failed")
            if process:
                self._safe_terminate_process(process)

        return ValidationResult(
            key=key,
            is_valid=validation_passed,
            validation_method="frida",
            execution_time=0.0,
            error_message=error_msg,
            frida_logs=logs,
        )

    def _validate_with_debugger(self, key: str) -> ValidationResult:
        """Validate key using debugger-based analysis.

        Attaches a debugger to monitor the license validation routine
        and capture register/memory states to determine key acceptance.

        Args:
            key: The license key to validate

        Returns:
            ValidationResult with debugger-based validation outcome.

        """
        try:
            from intellicrack.core.debugging_engine import LicenseDebugger
        except ImportError:
            self.logger.error("Debugger not available, falling back to execution testing")
            return self._validate_with_execution(key)

        validation_passed = False
        error_msg = None
        register_states: dict[str, int] = {}
        memory_snapshots: dict[str, bytes] = {}
        completion_event = threading.Event()
        process: subprocess.Popen[bytes] | None = None

        try:
            debugger = LicenseDebugger()

            process = subprocess.Popen(
                [str(self.binary_path), key],
                creationflags=CREATE_SUSPENDED,
            )

            debugger.attach_to_process(process.pid)

            validation_functions = self._find_validation_functions()

            for func_addr in validation_functions:
                debugger.set_breakpoint(func_addr)

            debugger.continue_execution()

            completion_event.wait(timeout=self.config.timeout_seconds)

            registers = debugger.get_registers()
            register_states = {
                "rax": registers.get("rax", 0),
                "rbx": registers.get("rbx", 0),
                "rcx": registers.get("rcx", 0),
                "rdx": registers.get("rdx", 0),
            }

            if register_states.get("rax", 0) == 1:
                validation_passed = True

            debugger.detach()
            self._safe_terminate_process(process)

        except Exception as e:
            error_msg = f"Debugger validation error: {e!s}"
            self.logger.exception("Debugger validation failed")
            if process:
                self._safe_terminate_process(process)

        return ValidationResult(
            key=key,
            is_valid=validation_passed,
            validation_method="debugger",
            execution_time=0.0,
            error_message=error_msg,
            register_states=register_states,
            memory_snapshots=memory_snapshots,
        )

    def _validate_with_execution(self, key: str) -> ValidationResult:
        """Validate key by executing the binary and analyzing output.

        Runs the target binary with the key and analyzes return code,
        stdout, and stderr to determine if the key was accepted.

        Args:
            key: The license key to validate

        Returns:
            ValidationResult with execution-based validation outcome.

        """
        validation_passed = False
        stdout_output = ""
        stderr_output = ""
        return_code = -1
        error_msg = None

        try:
            result = subprocess.run(
                [str(self.binary_path), key],
                capture_output=True,
                text=True,
                timeout=self.config.timeout_seconds,
                check=False,
            )

            stdout_output = result.stdout
            stderr_output = result.stderr
            return_code = result.returncode

            indicator_checked = False

            for success_indicator in self.config.success_indicators:
                indicator_checked = True
                if success_indicator in stdout_output or success_indicator in stderr_output:
                    validation_passed = True
                    break

            for failure_indicator in self.config.failure_indicators:
                indicator_checked = True
                if failure_indicator in stdout_output or failure_indicator in stderr_output:
                    validation_passed = False
                    break

            if not indicator_checked:
                if return_code == 0:
                    validation_passed = True
                self.logger.warning(
                    "Using return code for validation (not reliable). "
                    "Configure success_indicators and failure_indicators for accurate results."
                )

        except subprocess.TimeoutExpired:
            error_msg = f"Validation timed out after {self.config.timeout_seconds} seconds"
        except FileNotFoundError:
            error_msg = f"Binary not found: {self.binary_path}"
        except Exception as e:
            error_msg = f"Execution validation error: {e!s}"
            self.logger.exception("Execution validation failed")

        return ValidationResult(
            key=key,
            is_valid=validation_passed,
            validation_method="execution",
            execution_time=0.0,
            error_message=error_msg,
            stdout_output=stdout_output,
            stderr_output=stderr_output,
            return_code=return_code,
        )

    def _generate_validation_script(self, key: str) -> str:
        """Generate Frida script for license validation interception.

        Creates a JavaScript/Frida script that hooks into license validation
        functions and reports whether the provided key is accepted.

        Args:
            key: The license key being tested

        Returns:
            Frida JavaScript code for validation monitoring.

        """
        timeout_ms = self.config.timeout_seconds * 1000
        script_template = f"""
        var validationPassed = false;
        var completionSent = false;

        function sendCompletion(status) {{
            if (!completionSent) {{
                completionSent = true;
                send({{validation: status, final: true}});
            }}
        }}

        // Dynamically discover and hook validation-related functions from all modules
        var validationKeywords = [
            "license", "valid", "check", "serial", "register", "activate",
            "verify", "auth", "key", "trial", "product", "crack"
        ];

        Process.enumerateModules().forEach(function(module) {{
            // Hook exported functions
            module.enumerateExports().forEach(function(exp) {{
                if (exp.type === "function") {{
                    var name = exp.name.toLowerCase();
                    var isValidationFunc = validationKeywords.some(function(keyword) {{
                        return name.includes(keyword);
                    }});

                    if (isValidationFunc) {{
                        try {{
                            Interceptor.attach(exp.address, {{
                                onEnter: function(args) {{
                                    send({{type: "hook", function: exp.name, event: "enter", module: module.name}});
                                }},
                                onLeave: function(retval) {{
                                    var result = retval.toInt32();
                                    send({{type: "hook", function: exp.name, event: "leave", return: result, module: module.name}});

                                    if (result === 1) {{
                                        validationPassed = true;
                                        sendCompletion("success");
                                    }} else if (result === 0) {{
                                        sendCompletion("failure");
                                    }}
                                }}
                            }});
                        }} catch (e) {{
                            send({{error: e.message, function: exp.name}});
                        }}
                    }}
                }}
            }});

            // Hook symbols (includes non-exported functions)
            module.enumerateSymbols().forEach(function(symbol) {{
                if (symbol.type === "function") {{
                    var name = symbol.name.toLowerCase();
                    var isValidationFunc = validationKeywords.some(function(keyword) {{
                        return name.includes(keyword);
                    }});

                    if (isValidationFunc) {{
                        try {{
                            Interceptor.attach(symbol.address, {{
                                onLeave: function(retval) {{
                                    try {{
                                        var ret = retval.toInt32();
                                        if (ret === 1) {{
                                            send({{validation: "success", symbol: symbol.name, return: ret}});
                                            validationPassed = true;
                                            sendCompletion("success");
                                        }} else if (ret === 0 && validationPassed === false) {{
                                            sendCompletion("failure");
                                        }}
                                    }} catch (e) {{
                                        // Ignore type conversion errors
                                    }}
                                }}
                            }});
                        }} catch (e) {{
                            // Symbol may not be hookable
                        }}
                    }}
                }}
            }});
        }});

        // Hook string comparison functions
        var stringCompFunctions = ["strcmp", "wcscmp", "lstrcmp", "lstrcmpi", "memcmp"];
        stringCompFunctions.forEach(function(funcName) {{
            var funcPtr = Module.findExportByName(null, funcName);
            if (funcPtr) {{
                Interceptor.attach(funcPtr, {{
                    onEnter: function(args) {{
                        try {{
                            var str1 = Memory.readUtf8String(args[0]);
                            var str2 = Memory.readUtf8String(args[1]);

                            var keywords = ["key", "license", "serial", "code", "product"];
                            var isRelevant = keywords.some(function(kw) {{
                                return (str1 && str1.toLowerCase().includes(kw)) ||
                                       (str2 && str2.toLowerCase().includes(kw));
                            }});

                            if (isRelevant) {{
                                send({{type: "strcmp", function: funcName, str1: str1, str2: str2}});
                            }}
                        }} catch (e) {{
                            // Ignore string read errors
                        }}
                    }},
                    onLeave: function(retval) {{
                        if (retval.toInt32() === 0) {{
                            send({{validation: "success", method: funcName}});
                            validationPassed = true;
                            sendCompletion("success");
                        }}
                    }}
                }});
            }}
        }});

        // Report final result after timeout
        setTimeout(function() {{
            sendCompletion(validationPassed ? "success" : "failure");
        }}, {timeout_ms});
        """

        return script_template

    def _find_validation_functions(self) -> list[int]:
        """Find addresses of license validation functions in the binary.

        Scans the binary for function addresses that are likely involved
        in license validation based on patterns and signatures.

        Returns:
            List of function addresses to monitor during debugging.

        """
        validation_addrs: list[int] = []

        if self.config.validation_functions:
            for func_name in self.config.validation_functions:
                try:
                    addr = int(func_name, 16) if func_name.startswith("0x") else int(func_name)
                    validation_addrs.append(addr)
                except ValueError:
                    self.logger.warning("Invalid address format: %s", func_name)

        if not validation_addrs:
            validation_addrs = self._discover_validation_functions_from_binary()

        return validation_addrs

    def _discover_validation_functions_from_binary(self) -> list[int]:
        """Discover validation function addresses by analyzing the binary.

        Uses binary analysis to find functions that likely perform license
        validation based on string references, API imports, and code patterns.

        Returns:
            List of discovered function addresses.

        """
        discovered_addrs: list[int] = []

        try:
            import lief
        except ImportError:
            self.logger.warning("LIEF not available for binary analysis, using basic pattern matching")
            return self._discover_validation_functions_basic()

        try:
            binary = lief.parse(str(self.binary_path))
            if binary is None:
                self.logger.warning("Failed to parse binary with LIEF")
                return []

            validation_keywords = [
                "license", "valid", "check", "serial", "register", "activate",
                "verify", "auth", "key", "trial", "product"
            ]

            if hasattr(binary, "symbols"):
                for symbol in binary.symbols:
                    if hasattr(symbol, "name") and hasattr(symbol, "value"):
                        name_lower = symbol.name.lower()
                        if any(keyword in name_lower for keyword in validation_keywords):
                            discovered_addrs.append(symbol.value)

            if hasattr(binary, "exported_functions"):
                for func in binary.exported_functions:
                    if hasattr(func, "name") and hasattr(func, "address"):
                        name_lower = func.name.lower()
                        if any(keyword in name_lower for keyword in validation_keywords):
                            discovered_addrs.append(func.address)

            self.logger.info("Discovered %d validation function candidates", len(discovered_addrs))

        except Exception as e:
            self.logger.warning("Binary analysis failed: %s", e)
            return self._discover_validation_functions_basic()

        return discovered_addrs[:20]

    def _discover_validation_functions_basic(self) -> list[int]:
        """Fallback method to discover validation functions using basic pattern matching.

        Scans binary for validation-related string references and returns
        addresses near those strings as function candidates.

        Returns:
            List of candidate function addresses.

        """
        discovered_addrs: list[int] = []

        try:
            with open(self.binary_path, "rb") as f:
                binary_data = f.read()

            validation_strings = [
                b"license", b"LICENSE", b"License",
                b"serial", b"SERIAL", b"Serial",
                b"key", b"KEY", b"Key",
                b"valid", b"VALID", b"Valid",
                b"register", b"REGISTER", b"Register",
            ]

            for search_str in validation_strings:
                offset = 0
                while True:
                    pos = binary_data.find(search_str, offset)
                    if pos == -1:
                        break

                    func_candidate = (pos // 0x1000) * 0x1000
                    if func_candidate not in discovered_addrs and func_candidate > 0:
                        discovered_addrs.append(func_candidate)

                    offset = pos + 1

            self.logger.info("Basic scan discovered %d validation function candidates", len(discovered_addrs))

        except Exception as e:
            self.logger.warning("Basic function discovery failed: %s", e)

        return discovered_addrs[:10]

    def validate_batch(self, keys: list[str], parallel: bool = False) -> list[ValidationResult]:
        """Validate multiple keys against the target binary.

        Tests a batch of generated keys to find valid ones, optionally
        using parallel execution for faster validation.

        Args:
            keys: List of license keys to validate
            parallel: Whether to validate keys in parallel

        Returns:
            List of ValidationResult objects for each key.

        """
        results: list[ValidationResult] = []

        if parallel:
            import concurrent.futures

            def validate_with_new_instance(key: str) -> ValidationResult:
                """Validate a key with a thread-local validator instance.

                Args:
                    key: The license key to validate

                Returns:
                    ValidationResult for the key.

                """
                thread_validator = KeyValidator(self.binary_path, self.config)
                return thread_validator.validate_key(key)

            with concurrent.futures.ThreadPoolExecutor(max_workers=4) as executor:
                future_to_key = {executor.submit(validate_with_new_instance, key): key for key in keys}

                for future in concurrent.futures.as_completed(future_to_key):
                    try:
                        result = future.result()
                        results.append(result)
                    except Exception as e:
                        key = future_to_key[future]
                        self.logger.exception("Validation failed for key %s: %s", key, e)
                        results.append(
                            ValidationResult(
                                key=key,
                                is_valid=False,
                                validation_method="error",
                                execution_time=0.0,
                                error_message=str(e),
                            )
                        )
        else:
            for key in keys:
                result = self.validate_key(key)
                results.append(result)

        return results

    def find_valid_key(
        self,
        algorithm: "ExtractedAlgorithm",
        synthesizer: "KeySynthesizer",
        max_attempts: int = 1000,
    ) -> ValidationResult | None:
        """Generate and test keys until a valid one is found.

        Iteratively generates keys using the algorithm and tests them
        against the binary until a valid key is discovered or max attempts reached.

        Args:
            algorithm: The algorithm to use for key generation
            synthesizer: KeySynthesizer instance for generating candidates
            max_attempts: Maximum number of keys to try

        Returns:
            ValidationResult for the first valid key, or None if none found.

        """
        for attempt in range(max_attempts):
            target_data = {"attempt": attempt}
            candidate_key = synthesizer.synthesize_key(algorithm, target_data)

            result = self.validate_key(candidate_key.serial)

            if result.is_valid:
                self.logger.info("Found valid key after %d attempts: %s", attempt + 1, candidate_key.serial)
                return result

            if attempt % 100 == 0:
                self.logger.info("Tested %d keys, no valid key yet...", attempt)

        self.logger.warning("No valid key found after %d attempts", max_attempts)
        return None


class LicenseKeygen:
    """Main license key generation engine."""

    def __init__(self, binary_path: Path | None = None) -> None:
        """Initialize the license key generator.

        Args:
            binary_path: Optional path to binary file for analysis

        """
        self.logger = logging.getLogger(__name__)
        self.binary_path = Path(binary_path) if binary_path else None
        self.extractor = ConstraintExtractor(self.binary_path) if self.binary_path else None
        self.analyzer = ConstraintExtractor(self.binary_path) if self.binary_path else None
        self.synthesizer = KeySynthesizer()
        self.generator = SerialNumberGenerator()
        self.validator = KeyValidator(self.binary_path) if self.binary_path else None

    def crack_license_from_binary(self, count: int = 1) -> list[GeneratedSerial]:
        """Crack license keys from binary analysis.

        Analyzes the binary file to extract validation algorithms and
        generates valid license keys based on detected constraints.

        Args:
            count: Number of license keys to generate.

        Returns:
            list[GeneratedSerial]: List of generated valid license keys.

        Raises:
            ValueError: If binary path is not provided or no algorithms detected.

        """
        if not self.analyzer:
            raise ValueError("Binary path required for analysis")

        algorithms = self.analyzer.analyze_validation_algorithms()

        if not algorithms:
            raise ValueError("No validation algorithms detected")

        best_algorithm = max(algorithms, key=lambda a: a.confidence)

        return self.synthesizer.synthesize_batch(best_algorithm, count, unique=True)

    def generate_key_from_algorithm(
        self,
        algorithm_name: str,
        **kwargs: object,
    ) -> GeneratedSerial:
        """Generate a key from a known algorithm.

        Creates a license key using a specific algorithm by name, supporting
        CRC32, Luhn, Microsoft, and UUID formats.

        Args:
            algorithm_name: Name of the algorithm (crc32, luhn, microsoft, uuid).
            **kwargs: Optional parameters like length and groups.

        Returns:
            GeneratedSerial: The generated serial key.

        """
        length_arg = kwargs.get("length", 16)
        length_val = int(length_arg) if isinstance(length_arg, (int, float, str)) else 16

        groups_arg = kwargs.get("groups", 4)
        groups_val = int(groups_arg) if isinstance(groups_arg, (int, float, str)) else 4

        if algorithm_name == "crc32":
            return GeneratedSerial(
                serial=self.generator._generate_crc32_serial(length_val),
                algorithm="crc32",
                confidence=0.85,
            )
        elif algorithm_name == "luhn":
            return GeneratedSerial(
                serial=self.generator._generate_luhn_serial(length_val),
                algorithm="luhn",
                confidence=0.9,
            )
        elif algorithm_name == "microsoft":
            constraints = SerialConstraints(
                length=25,
                format=SerialFormat.MICROSOFT,
                groups=5,
            )
        elif algorithm_name == "uuid":
            constraints = SerialConstraints(
                length=36,
                format=SerialFormat.UUID,
            )
        else:
            constraints = SerialConstraints(
                length=length_val,
                format=SerialFormat.ALPHANUMERIC,
                groups=groups_val,
            )

        return self.generator.generate_serial(constraints)

    def generate_volume_license(
        self,
        product_id: str,
        count: int = 100,
    ) -> list[GeneratedSerial]:
        """Generate volume license keys.

        Creates multiple RSA-signed license keys for volume licensing scenarios,
        with enterprise-level features and unlimited usage rights.

        Args:
            product_id: The product identifier for the licenses.
            count: Number of volume licenses to generate.

        Returns:
            list[GeneratedSerial]: List of generated volume license keys.

        """
        from cryptography.hazmat.primitives.asymmetric import rsa

        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
        )

        licenses = []
        for i in range(count):
            license_key = self.generator.generate_rsa_signed(
                private_key,
                product_id,
                f"Volume-{i:04d}",
                features=["enterprise", "unlimited", "support"],
            )
            licenses.append(license_key)

        return licenses

    def generate_hardware_locked_key(
        self,
        hardware_id: str,
        product_id: str,
    ) -> GeneratedSerial:
        """Generate a hardware-locked license key.

        Creates a license key that is cryptographically bound to a specific
        hardware identifier, preventing license portability.

        Args:
            hardware_id: The hardware identifier to bind the key to.
            product_id: The product identifier for the license.

        Returns:
            GeneratedSerial: A hardware-locked serial key.

        """
        combined_data = f"{product_id}:{hardware_id}".encode()
        hash_result = hashlib.sha256(combined_data).hexdigest()

        key_base = hash_result[:20].upper()
        formatted = "-".join(key_base[i : i + 5] for i in range(0, 20, 5))

        checksum = self.generator._calculate_crc16(formatted)
        final_key = f"{formatted}-{checksum}"

        return GeneratedSerial(
            serial=final_key,
            hardware_id=hardware_id,
            algorithm="hardware_locked",
            confidence=0.95,
        )

    def generate_time_limited_key(
        self,
        product_id: str,
        days_valid: int = 30,
    ) -> GeneratedSerial:
        """Generate a time-limited license key.

        Creates a time-based license key with an expiration date, commonly
        used for trial or subscription-based licensing.

        Args:
            product_id: The product identifier for the license.
            days_valid: Number of days the license remains valid.

        Returns:
            GeneratedSerial: A time-limited serial key.

        """
        import secrets

        secret_key = secrets.token_bytes(32)

        return self.generator.generate_time_based(
            secret_key,
            validity_days=days_valid,
            product_id=product_id,
        )

    def generate_feature_key(
        self,
        base_product: str,
        features: list[str],
    ) -> GeneratedSerial:
        """Generate a feature-encoded license key.

        Creates a license key with embedded feature flags that control
        access to specific product capabilities.

        Args:
            base_product: The base product identifier.
            features: List of features to enable in the key.

        Returns:
            GeneratedSerial: A feature-encoded serial key.

        """
        base_serial = self.generate_key_from_algorithm("alphanumeric", length=16, groups=4).serial

        return self.generator.generate_feature_encoded(
            base_serial,
            features,
        )

    def brute_force_key(
        self,
        partial_key: str,
        missing_positions: list[int],
        validation_func: Callable[[str], bool],
        charset: str = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789",
    ) -> str | None:
        """Brute force a partial license key.

        Attempts to complete a partial license key by testing all possible
        character combinations at specified positions against a validation function.

        Args:
            partial_key: The partial license key with unknown positions.
            missing_positions: List of character positions to brute force.
            validation_func: Function that validates a complete key.
            charset: Character set to use for brute forcing.

        Returns:
            str | None: A valid completed key or None if no solution found.

        """
        import itertools

        key_list = list(partial_key)
        max_combinations = len(charset) ** len(missing_positions)

        if max_combinations > 1000000:
            return None

        for combination in itertools.product(charset, repeat=len(missing_positions)):
            for i, pos in enumerate(missing_positions):
                key_list[pos] = combination[i]

            candidate = "".join(key_list)

            if validation_func(candidate):
                return candidate

        return None

    def reverse_engineer_keygen(
        self,
        valid_keys: list[str],
        invalid_keys: list[str] | None = None,
    ) -> dict[str, Any]:
        """Reverse engineer key generation algorithm.

        Analyzes valid and invalid keys to identify patterns and constraints
        in the underlying key generation algorithm.

        Args:
            valid_keys: List of known valid license keys.
            invalid_keys: Optional list of known invalid keys for contrast analysis.

        Returns:
            dict[str, Any]: Dictionary containing identified algorithm patterns.

        """
        return self.generator.reverse_engineer_algorithm(
            valid_keys,
            invalid_keys,
        )

    def crack_with_validation(
        self,
        max_attempts: int = 1000,
        validation_config: ValidationConfig | None = None,
    ) -> list[GeneratedSerial]:
        """Crack license keys with real-time validation against the binary.

        Generates candidate keys and validates them against the actual binary
        until valid keys are found, providing a complete cracking solution.

        Args:
            max_attempts: Maximum number of keys to generate and test.
            validation_config: Optional configuration for validation behavior.

        Returns:
            list[GeneratedSerial]: List of validated working license keys.

        Raises:
            ValueError: If binary path is not provided or no algorithms detected.

        """
        if not self.binary_path:
            raise ValueError("Binary path required for validation-based cracking")

        if not self.analyzer:
            raise ValueError("Analyzer not initialized")

        algorithms = self.analyzer.analyze_validation_algorithms()

        if not algorithms:
            raise ValueError("No validation algorithms detected in binary")

        best_algorithm = max(algorithms, key=lambda a: a.confidence)

        if validation_config:
            validator = KeyValidator(self.binary_path, validation_config)
        else:
            validator = self.validator

        if not validator:
            raise ValueError("Validator not initialized")

        valid_keys: list[GeneratedSerial] = []

        for attempt in range(max_attempts):
            target_data = {"attempt": attempt, "timestamp": time.time()}
            candidate = self.synthesizer.synthesize_key(best_algorithm, target_data)

            result = validator.validate_key(candidate.serial)

            if result.is_valid:
                candidate.confidence = 1.0
                candidate.metadata = {
                    "validated": True,
                    "validation_method": result.validation_method,
                    "validation_time": result.execution_time,
                }
                valid_keys.append(candidate)
                self.logger.info("Found valid key #%d: %s", len(valid_keys), candidate.serial)

                if len(valid_keys) >= 10:
                    break

            if attempt % 100 == 0 and attempt > 0:
                self.logger.info("Progress: Tested %d keys, found %d valid", attempt, len(valid_keys))

        if not valid_keys:
            self.logger.warning("No valid keys found after %d attempts", max_attempts)

        return valid_keys

    def validate_generated_key(
        self,
        key: str | GeneratedSerial,
        validation_config: ValidationConfig | None = None,
    ) -> ValidationResult:
        """Validate a previously generated key against the binary.

        Tests a specific generated key to verify it actually works with
        the protected binary using dynamic analysis.

        Args:
            key: The license key to validate (string or GeneratedSerial).
            validation_config: Optional configuration for validation behavior.

        Returns:
            ValidationResult containing validation outcome and details.

        Raises:
            ValueError: If binary path or validator not available.

        """
        if not self.binary_path:
            raise ValueError("Binary path required for key validation")

        key_str = key.serial if isinstance(key, GeneratedSerial) else key

        if validation_config:
            validator = KeyValidator(self.binary_path, validation_config)
        else:
            validator = self.validator

        if not validator:
            raise ValueError("Validator not initialized")

        return validator.validate_key(key_str)

    def validate_batch_keys(
        self,
        keys: list[str] | list[GeneratedSerial],
        validation_config: ValidationConfig | None = None,
        parallel: bool = False,
    ) -> list[ValidationResult]:
        """Validate multiple generated keys against the binary.

        Tests a batch of generated keys to determine which ones actually
        work with the protected binary.

        Args:
            keys: List of license keys to validate.
            validation_config: Optional configuration for validation behavior.
            parallel: Whether to validate keys in parallel for speed.

        Returns:
            list[ValidationResult]: Validation results for each key.

        Raises:
            ValueError: If binary path or validator not available.

        """
        if not self.binary_path:
            raise ValueError("Binary path required for key validation")

        key_strings = [
            k.serial if isinstance(k, GeneratedSerial) else k
            for k in keys
        ]

        if validation_config:
            validator = KeyValidator(self.binary_path, validation_config)
        else:
            validator = self.validator

        if not validator:
            raise ValueError("Validator not initialized")

        return validator.validate_batch(key_strings, parallel=parallel)

    def crack_with_feedback_loop(
        self,
        initial_attempts: int = 100,
        max_iterations: int = 10,
        validation_config: ValidationConfig | None = None,
    ) -> list[GeneratedSerial]:
        """Advanced cracking with iterative algorithm refinement.

        Uses a feedback loop approach: generate keys, validate them, analyze
        patterns in successful keys, refine the algorithm, and repeat until
        optimal key generation is achieved.

        Args:
            initial_attempts: Number of keys to try per iteration.
            max_iterations: Maximum refinement iterations.
            validation_config: Optional configuration for validation behavior.

        Returns:
            list[GeneratedSerial]: All validated working license keys discovered.

        Raises:
            ValueError: If binary path is not provided or no algorithms detected.

        """
        if not self.binary_path:
            raise ValueError("Binary path required for feedback-loop cracking")

        if not self.analyzer:
            raise ValueError("Analyzer not initialized")

        algorithms = self.analyzer.analyze_validation_algorithms()

        if not algorithms:
            raise ValueError("No validation algorithms detected in binary")

        current_algorithm = max(algorithms, key=lambda a: a.confidence)

        if validation_config:
            validator = KeyValidator(self.binary_path, validation_config)
        else:
            validator = self.validator

        if not validator:
            raise ValueError("Validator not initialized")

        all_valid_keys: list[GeneratedSerial] = []
        valid_key_strings: list[str] = []

        for iteration in range(max_iterations):
            self.logger.info("Feedback iteration %d/%d", iteration + 1, max_iterations)

            candidates = self.synthesizer.synthesize_batch(
                current_algorithm,
                initial_attempts,
                unique=True,
            )

            candidate_strings = [c.serial for c in candidates]
            results = validator.validate_batch(candidate_strings, parallel=True)

            new_valid_count = 0
            for idx, result in enumerate(results):
                if result.is_valid:
                    candidate = candidates[idx]
                    candidate.confidence = 1.0
                    candidate.metadata = {
                        "validated": True,
                        "iteration": iteration,
                        "validation_method": result.validation_method,
                    }
                    all_valid_keys.append(candidate)
                    valid_key_strings.append(result.key)
                    new_valid_count += 1

            self.logger.info(
                "Iteration %d: Found %d new valid keys (total: %d)",
                iteration + 1,
                new_valid_count,
                len(all_valid_keys),
            )

            if new_valid_count == 0:
                self.logger.info("No new valid keys found, attempting algorithm refinement")

                if len(valid_key_strings) >= 2:
                    pattern_analysis = self.generator.reverse_engineer_algorithm(
                        valid_key_strings,
                        candidate_strings[:20],
                    )

                    if "common_patterns" in pattern_analysis:
                        current_algorithm.confidence = min(
                            current_algorithm.confidence + 0.1,
                            0.99,
                        )

                        new_constraints = self._extract_constraints_from_valid_keys(valid_key_strings)
                        for constraint in new_constraints:
                            if constraint not in current_algorithm.constraints:
                                current_algorithm.constraints.append(constraint)

                        self.logger.info("Refined algorithm based on valid key patterns with %d new constraints", len(new_constraints))
                else:
                    self.logger.warning("Insufficient valid keys for pattern analysis")

            if len(all_valid_keys) >= 50:
                self.logger.info("Reached target of 50 valid keys, stopping")
                break

        return all_valid_keys

    def _extract_constraints_from_valid_keys(self, valid_keys: list[str]) -> list[KeyConstraint]:
        """Extract common constraints from a list of valid keys.

        Analyzes valid keys to identify patterns and constraints that can
        be used to improve key generation accuracy.

        Args:
            valid_keys: List of known valid license keys

        Returns:
            List of extracted constraints from the valid keys.

        """
        constraints: list[KeyConstraint] = []

        if not valid_keys:
            return constraints

        common_length = len(valid_keys[0])
        if all(len(key) == common_length for key in valid_keys):
            constraints.append(
                KeyConstraint(
                    constraint_type="length",
                    description=f"All valid keys have length {common_length}",
                    value=common_length,
                    confidence=0.95,
                )
            )

        separator_chars = {"-", "_", ":", "."}
        for sep in separator_chars:
            if all(sep in key for key in valid_keys):
                constraints.append(
                    KeyConstraint(
                        constraint_type="separator",
                        description=f"All valid keys contain separator '{sep}'",
                        value=sep,
                        confidence=0.9,
                    )
                )

        all_uppercase = all(c.isupper() for key in valid_keys for c in key if c.isalpha())
        all_numeric = all(c.isdigit() for key in valid_keys for c in key if c.isalnum())

        if all_uppercase and not all_numeric:
            constraints.append(
                KeyConstraint(
                    constraint_type="charset",
                    description="All alphabetic characters are uppercase",
                    value="uppercase",
                    confidence=0.85,
                )
            )
        elif all_numeric:
            constraints.append(
                KeyConstraint(
                    constraint_type="charset",
                    description="All keys are purely numeric",
                    value="numeric",
                    confidence=0.9,
                )
            )

        return constraints

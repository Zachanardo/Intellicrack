"""License key generation and validation analysis."""

import hashlib
import logging
import struct
import zlib
from collections.abc import Callable
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any

import capstone
import z3

from intellicrack.core.serial_generator import GeneratedSerial, SerialConstraints, SerialFormat, SerialNumberGenerator


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
    validation_function: Callable | None = None
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
            ValidationAnalysis with detected algorithm and constraints

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
            List of Capstone instruction objects

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
            self.logger.warning(f"Disassembly error: {e}")

        return instructions

    def _detect_crypto_constants(self, instructions: list[Any], binary_code: bytes) -> list[CryptoPrimitive]:
        """Detect cryptographic constants in disassembled code.

        Args:
            instructions: List of disassembled instructions
            binary_code: Original binary data for scanning

        Returns:
            List of detected cryptographic primitives

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
            bool(all(instructions[j].mnemonic == "xor" for j in range(i, min(i + 3, len(instructions)))))
            for i in range(len(instructions) - 3)
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
            List of identified API function names

        """
        api_calls = []
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
            List of extracted constraints

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
            List of patchable locations

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
            Tuple of (algorithm type, confidence score)

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
            Dictionary of named constants

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
            List of recommendation strings

        """
        recommendations = []

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
            recommendations.append("Limited information - recommend dynamic analysis with debugger")
            recommendations.append("Set breakpoints on string comparison functions (strcmp, memcmp)")

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
                self.logger.error(f"Binary file not found: {self.binary_path}")
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
            self.logger.error(f"Failed to read binary file: {e}")
        except Exception as e:
            self.logger.error(f"Constraint extraction failed: {e}")

        return constraints

    def _extract_string_constraints(self) -> list[KeyConstraint]:
        """Extract constraints from string patterns in the binary."""
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
            matches = list(re.finditer(regex_pattern, self._binary_data))
            if matches:
                for match in matches[:3]:
                    constraints.append(
                        KeyConstraint(
                            constraint_type="format",
                            description=f"Detected {format_type} pattern",
                            value=format_type,
                            confidence=0.75,
                            source_address=match.start(),
                        )
                    )

        return constraints

    def _extract_crypto_constraints(self) -> list[KeyConstraint]:
        """Extract constraints from cryptographic constants."""
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
        """Extract key format constraints from binary patterns."""
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
        """Extract key length constraints from comparison operations."""
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
            List of extracted validation algorithms

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
        groups = {}

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
        polynomial = 0xEDB88320

        for constraint in constraints:
            if "CRC32" in str(constraint.value):
                polynomial = 0xEDB88320 if "reversed" in str(constraint.value) else 0x04C11DB7

        def crc32_validate(key: str) -> int:
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
        hash_functions = {
            "md5": hashlib.md5,
            "sha1": hashlib.sha1,
            "sha256": hashlib.sha256,
        }

        hash_func = hash_functions.get(algo_type, hashlib.sha256)

        def hash_validate(key: str) -> str:
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
        def multiplicative_validate(key: str) -> int:
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
        modulus = 97

        def modular_validate(key: str) -> int:
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
        return ExtractedAlgorithm(
            algorithm_name="Generic",
            parameters={},
            validation_function=None,
            key_format=SerialFormat.ALPHANUMERIC,
            constraints=constraints,
            confidence=0.5,
        )

    def _create_generic_algorithm(self, constraints: list[KeyConstraint]) -> ExtractedAlgorithm:
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
        """Synthesize a license key from the extracted algorithm."""
        if algorithm.validation_function:
            return self._synthesize_with_validation(algorithm, target_data)
        return self._synthesize_from_constraints(algorithm, target_data)

    def _synthesize_with_validation(
        self,
        algorithm: ExtractedAlgorithm,
        target_data: dict[str, Any] | None = None,
    ) -> GeneratedSerial:
        constraints = self._build_serial_constraints(algorithm)

        if target_data:
            base_seed = hashlib.sha256(str(target_data).encode()).hexdigest()[:16]
            seed_value = int(base_seed, 16)
        else:
            seed_value = 0

        max_attempts = 10000
        for attempt in range(max_attempts):
            deterministic_seed = seed_value + attempt
            candidate = self.generator.generate_serial(constraints, seed=deterministic_seed)

            try:
                if algorithm.validation_function(candidate.serial):
                    candidate.confidence = algorithm.confidence
                    candidate.algorithm = algorithm.algorithm_name
                    return candidate
            except Exception as e:
                self.logger.debug(f"Validation failed for candidate {candidate.serial}: {e}")
                continue

        return self.generator.generate_serial(constraints)

    def _synthesize_from_constraints(
        self,
        algorithm: ExtractedAlgorithm,
        target_data: dict[str, Any] | None = None,
    ) -> GeneratedSerial:
        constraints = self._build_serial_constraints(algorithm)

        seed = target_data or None
        return self.generator.generate_serial(constraints, seed=seed)

    def _build_serial_constraints(self, algorithm: ExtractedAlgorithm) -> SerialConstraints:
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
            List of generated serial keys

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
            Generated serial key for the user

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
        """Synthesize a key using Z3 constraint solver."""
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


class LicenseKeygen:
    """Main license key generation engine."""

    def __init__(self, binary_path: Path | None = None) -> None:
        """Initialize the license key generator.

        Args:
            binary_path: Optional path to binary file for analysis

        """
        self.binary_path = Path(binary_path) if binary_path else None
        self.extractor = ConstraintExtractor(self.binary_path) if self.binary_path else None
        self.analyzer = ConstraintExtractor(self.binary_path) if self.binary_path else None
        self.synthesizer = KeySynthesizer()
        self.generator = SerialNumberGenerator()

    def crack_license_from_binary(self, count: int = 1) -> list[GeneratedSerial]:
        """Crack license keys from binary analysis."""
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
        """Generate a key from a known algorithm."""
        if algorithm_name == "crc32":
            return GeneratedSerial(
                serial=self.generator._generate_crc32_serial(kwargs.get("length", 16)),
                algorithm="crc32",
                confidence=0.85,
            )
        elif algorithm_name == "luhn":
            return GeneratedSerial(
                serial=self.generator._generate_luhn_serial(kwargs.get("length", 16)),
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
                length=kwargs.get("length", 16),
                format=SerialFormat.ALPHANUMERIC,
                groups=kwargs.get("groups", 4),
            )

        return self.generator.generate_serial(constraints)

    def generate_volume_license(
        self,
        product_id: str,
        count: int = 100,
    ) -> list[GeneratedSerial]:
        """Generate volume license keys."""
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
        """Generate a hardware-locked license key."""
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
        """Generate a time-limited license key."""
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
        """Generate a feature-encoded license key."""
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
        """Brute force a partial license key."""
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
        """Reverse engineer key generation algorithm."""
        return self.generator.reverse_engineer_algorithm(
            valid_keys,
            invalid_keys,
        )

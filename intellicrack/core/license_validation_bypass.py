"""License validation bypass engine for extracting and manipulating cryptographic keys."""

import re
import struct
from dataclasses import dataclass
from enum import Enum
from typing import Any

import capstone
import keystone
import numpy as np
import pefile
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurvePrivateKey, EllipticCurvePublicKey
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey, RSAPublicKey

from intellicrack.utils.logger import log_all_methods, log_function_call, logger


class KeyType(Enum):
    """Enumeration of cryptographic key types found in license validation code."""

    RSA_PUBLIC = "rsa_public"
    RSA_PRIVATE = "rsa_private"
    ECC_PUBLIC = "ecc_public"
    ECC_PRIVATE = "ecc_private"
    AES = "aes"
    DES = "des"
    RC4 = "rc4"
    CUSTOM = "custom"


@dataclass
class ExtractedKey:
    """Container for extracted cryptographic key from binary analysis."""

    key_type: KeyType
    key_data: bytes
    modulus: int | None = None
    exponent: int | None = None
    curve: str | None = None
    address: int = 0
    confidence: float = 0.0
    context: str = ""
    key_object: Any | None = None


@log_all_methods
class LicenseValidationBypass:
    """Production-ready license validation bypass engine with real cryptographic operations."""

    def __init__(self) -> None:
        """Initialize the LicenseValidationBypassEngine with cryptographic engines and patterns."""
        logger.info("Initializing LicenseValidationBypass engine")
        self.backend = default_backend()
        self.cs_x86 = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
        self.cs_x64 = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
        self.ks_x86 = keystone.Ks(keystone.KS_ARCH_X86, keystone.KS_MODE_32)
        self.ks_x64 = keystone.Ks(keystone.KS_ARCH_X86, keystone.KS_MODE_64)

        self.rsa_patterns = self._build_rsa_patterns()
        self.ecc_patterns = self._build_ecc_patterns()
        self.cert_patterns = self._build_cert_patterns()

    def _build_rsa_patterns(self) -> list[re.Pattern]:
        """Build patterns for RSA key detection in binary data."""
        logger.debug("Building RSA key detection patterns.")
        patterns = [re.compile(rb"\x30[\x81\x82][\x01-\x02][\x00-\xff]\x30\x0d\x06\x09\x2a\x86\x48\x86\xf7\x0d\x01\x01\x01")]

        logger.debug("Added ASN.1 DER RSA public key pattern.")

        # PKCS#1 RSA private key
        patterns.append(re.compile(rb"\x30[\x82][\x04-\x09][\x00-\xff]\x02\x01\x00"))
        logger.debug("Added PKCS#1 RSA private key pattern.")

        # Common RSA exponents
        patterns.append(re.compile(rb"\x01\x00\x01"))  # 65537
        patterns.append(re.compile(rb"\x00\x00\x00\x03"))  # 3
        logger.debug("Added common RSA exponent patterns.")

        # OpenSSL RSA structure markers
        patterns.append(re.compile(rb"RSA\x00"))
        patterns.append(re.compile(rb"-----BEGIN RSA"))
        patterns.append(re.compile(rb"-----BEGIN PUBLIC KEY"))
        logger.debug("Added OpenSSL RSA structure marker patterns.")

        # Microsoft CryptoAPI markers
        patterns.append(re.compile(rb"RSA1"))  # PUBLICKEYSTRUC
        patterns.append(re.compile(rb"RSA2"))  # PRIVATEKEYSTRUC
        logger.debug("Added Microsoft CryptoAPI marker patterns.")

        logger.info("Built %s RSA key patterns.", len(patterns))
        return patterns

    @log_function_call
    def _build_ecc_patterns(self) -> list[re.Pattern]:
        """Build patterns for ECC key detection."""
        logger.debug("Building ECC key detection patterns.")
        patterns = [
            re.compile(rb"\x30\x59\x30\x13\x06\x07\x2a\x86\x48\xce\x3d\x02\x01"),
            re.compile(rb"\x30\x76\x30\x13\x06\x07\x2a\x86\x48\xce\x3d\x02\x01"),
            re.compile(rb"\x30\x81\x9b\x30\x13\x06\x07\x2a\x86\x48\xce\x3d\x02\x01"),
        ]

        logger.debug("Added ASN.1 DER ECC public key pattern.")

        # Named curves OIDs
        patterns.append(re.compile(rb"\x06\x08\x2a\x86\x48\xce\x3d\x03\x01\x07"))  # P-256
        patterns.append(re.compile(rb"\x06\x05\x2b\x81\x04\x00\x22"))  # P-384
        patterns.append(re.compile(rb"\x06\x05\x2b\x81\x04\x00\x23"))  # P-521
        patterns.append(re.compile(rb"\x06\x05\x2b\x81\x04\x00\x0a"))  # secp256k1
        logger.debug("Added named curve OID patterns.")

        # OpenSSL EC markers
        patterns.append(re.compile(rb"EC\x00"))
        patterns.append(re.compile(rb"-----BEGIN EC"))
        logger.debug("Added OpenSSL EC marker patterns.")

        logger.info("Built %s ECC key patterns.", len(patterns))
        return patterns

    @log_function_call
    def _build_cert_patterns(self) -> list[re.Pattern]:
        """Build patterns for certificate detection."""
        logger.debug("Building certificate detection patterns.")
        patterns = [re.compile(rb"\x30\x82[\x03-\x08][\x00-\xff]\x30\x82")]

        logger.debug("Added X.509 certificate pattern.")

        # Certificate markers
        patterns.append(re.compile(rb"-----BEGIN CERTIFICATE"))
        patterns.append(re.compile(rb"-----END CERTIFICATE"))
        logger.debug("Added certificate marker patterns.")

        logger.info("Built %s certificate patterns.", len(patterns))
        return patterns

    def extract_rsa_keys_from_binary(self, binary_path: str) -> list[ExtractedKey]:
        """Extract RSA keys from binary with advanced heuristics."""
        logger.info("Starting RSA key extraction from %s", binary_path)
        keys = []

        with open(binary_path, "rb") as f:
            data = f.read()

        logger.debug("Method 1: Searching for ASN.1 structures.")
        # Method 1: Pattern matching for ASN.1 structures
        for pattern in self.rsa_patterns:
            for match in pattern.finditer(data):
                offset = match.start()
                if key_candidate := self._extract_asn1_key(data[offset : offset + 4096]):
                    logger.debug("Found potential ASN.1 key at offset %s", offset)
                    key_candidate.address = offset
                    keys.append(key_candidate)
        logger.debug("Method 1 (ASN.1 structures) completed. Found %s keys so far.", len(keys))

        logger.debug("Method 2: Scanning for large prime numbers (RSA moduli).")
        # Method 2: Scan for large prime numbers (RSA moduli)
        initial_keys_count = len(keys)
        keys.extend(self._scan_for_rsa_moduli(data))
        logger.debug("Method 2 (RSA moduli scan) completed. Added %s keys.", len(keys) - initial_keys_count)

        # Method 3: Parse PE imports for CryptoAPI
        if binary_path.endswith((".exe", ".dll")):
            logger.debug("Method 3: Parsing PE resources and CryptoAPI calls.")
            initial_keys_count = len(keys)
            keys.extend(self._extract_from_pe_resources(binary_path))
            keys.extend(self._extract_from_crypto_api_calls(binary_path))
            logger.debug("Method 3 (PE resources and CryptoAPI) completed. Added %s keys.", len(keys) - initial_keys_count)

        logger.debug("Method 4: Analyzing memory patterns for in-memory key structures.")
        # Method 4: Memory pattern analysis
        initial_keys_count = len(keys)
        keys.extend(self._analyze_memory_patterns(data))
        logger.debug("Method 4 (Memory pattern analysis) completed. Added %s keys.", len(keys) - initial_keys_count)

        logger.debug("Method 5: Detecting keys based on entropy analysis.")
        # Method 5: Entropy-based detection
        initial_keys_count = len(keys)
        keys.extend(self._entropy_based_key_detection(data))
        logger.debug("Method 5 (Entropy-based detection) completed. Added %s keys.", len(keys) - initial_keys_count)

        logger.info("Found %s potential RSA keys in %s", len(keys), binary_path)
        return keys

    def _extract_asn1_key(self, data: bytes) -> ExtractedKey | None:
        """Parse ASN.1 encoded RSA key."""
        try:
            # Try to parse as public key
            if data[:9] == b"\x30\x82\x01\x22\x30\x0d\x06\x09\x2a":
                key = serialization.load_der_public_key(data[:294], backend=self.backend)
                if isinstance(key, RSAPublicKey):
                    numbers = key.public_numbers()
                    return ExtractedKey(
                        key_type=KeyType.RSA_PUBLIC,
                        key_data=data[:294],
                        modulus=numbers.n,
                        exponent=numbers.e,
                        confidence=0.95,
                        context="ASN.1 DER encoded public key",
                        key_object=key,
                    )

            # Try to parse as private key
            if data[:4] == b"\x30\x82" and data[4] == 0x02:
                try:
                    key = serialization.load_der_private_key(data, password=None, backend=self.backend)
                    if isinstance(key, RSAPrivateKey):
                        numbers = key.private_numbers()
                        return ExtractedKey(
                            key_type=KeyType.RSA_PRIVATE,
                            key_data=data[:],
                            modulus=numbers.public_numbers.n,
                            exponent=numbers.public_numbers.e,
                            confidence=0.98,
                            context="ASN.1 DER encoded private key",
                            key_object=key,
                        )
                except (AttributeError, KeyError, ValueError):
                    logger.warning("Failed to process PKCS#1 RSA private key", exc_info=True)

        except Exception:
            logger.warning("Private key extraction failed with an unexpected error", exc_info=True)

        return None

    def _scan_for_rsa_moduli(self, data: bytes) -> list[ExtractedKey]:
        """Scan for potential RSA moduli using mathematical properties."""
        keys = []

        # Look for 128, 256, 512-byte sequences with high entropy
        for key_size in [128, 256, 512]:
            logger.debug("Scanning for RSA moduli of size %s bytes.", key_size)
            for offset in range(0, len(data) - key_size, 4):
                chunk = data[offset : offset + key_size]

                # Check entropy
                entropy = self._calculate_entropy(chunk)
                logger.debug("Chunk at offset %s (size %s) has entropy: %.2f", offset, key_size, entropy)
                if entropy < 7.5:  # RSA keys have high entropy
                    continue

                # Convert to integer and check properties
                n = int.from_bytes(chunk, byteorder="big")

                # Check if it could be an RSA modulus
                if self._is_probable_rsa_modulus(n):
                    # Look for exponent nearby
                    exp_candidates = [65537, 3, 17, 257, 65539]
                    for exp in exp_candidates:
                        exp_bytes = exp.to_bytes((exp.bit_length() + 7) // 8, byteorder="big")
                        if exp_bytes in data[max(0, offset - 100) : offset + key_size + 100]:
                            keys.append(
                                ExtractedKey(
                                    key_type=KeyType.RSA_PUBLIC,
                                    key_data=chunk,
                                    modulus=n,
                                    exponent=exp,
                                    address=offset,
                                    confidence=0.7,
                                    context=f"Probable RSA modulus with e={exp}",
                                ),
                            )
                            break

        return keys

    def _is_probable_rsa_modulus(self, n: int) -> bool:
        """Check if a number has properties of an RSA modulus."""
        if n < 2**511 or n > 2**4097:  # Common RSA sizes
            return False

        # RSA moduli are odd
        if n % 2 == 0:
            return False

        # Check bit pattern (should have high bit set)
        bit_length = n.bit_length()
        if not (n >> (bit_length - 1)) & 1:
            return False

        # Additional heuristics
        hex_str = hex(n)
        return hex_str.count("0") <= len(hex_str) * 0.7

    def _extract_from_pe_resources(self, binary_path: str) -> list[ExtractedKey]:
        """Extract keys from PE resources and data sections."""
        keys = []

        try:
            pe = pefile.PE(binary_path)

            # Check resources
            logger.debug("Checking PE resources for embedded keys.")
            if hasattr(pe, "DIRECTORY_ENTRY_RESOURCE"):
                for resource_type in pe.DIRECTORY_ENTRY_RESOURCE.entries:
                    for resource_id in resource_type.directory.entries:
                        for resource_lang in resource_id.directory.entries:
                            data = pe.get_data(
                                resource_lang.data.struct.OffsetToData,
                                resource_lang.data.struct.Size,
                            )

                            # Check for certificate or key data
                            if self._is_key_data(data):
                                if extracted := self._parse_key_data(data):
                                    logger.debug("Found %s key(s) in PE resource.", len(extracted))
                                    keys.extend(extracted)

            # Check data sections
            logger.debug("Checking PE data sections for embedded keys.")
            for section in pe.sections:
                if section.Name.startswith(b".data") or section.Name.startswith(b".rdata"):
                    data = section.get_data()
                    if section_keys := self._scan_section_for_keys(data, section.VirtualAddress):
                        logger.debug("Found %s key(s) in section %s.", len(section_keys), section.Name.decode(errors="ignore"))
                        keys.extend(section_keys)

        except Exception:
            logger.warning("PE resource and section scanning failed", exc_info=True)

        return keys

    def _extract_from_crypto_api_calls(self, binary_path: str) -> list[ExtractedKey]:
        """Extract keys from CryptoAPI usage patterns."""
        keys = []

        try:
            pe = pefile.PE(binary_path)

            # Look for CryptoAPI imports
            logger.debug("Looking for CryptoAPI imports.")
            crypto_imports = []
            if hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
                crypto_apis = [
                    "CryptImportKey",
                    "CryptExportKey",
                    "CryptGenKey",
                    "CryptDeriveKey",
                    "BCryptImportKeyPair",
                    "BCryptGenerateKeyPair",
                ]

                for entry in pe.DIRECTORY_ENTRY_IMPORT:
                    crypto_imports.extend(
                        (imp.address, imp.name)
                        for imp in entry.imports
                        if imp.name and imp.name.decode("utf-8", errors="ignore") in crypto_apis
                    )
            logger.debug("Found %s CryptoAPI imports.", len(crypto_imports))

            # Analyze code around crypto API calls
            if crypto_imports:
                logger.debug("Analyzing code around CryptoAPI calls.")
                if text_section := next(
                    (section for section in pe.sections if section.Name.startswith(b".text")),
                    None,
                ):
                    code = text_section.get_data()
                    keys.extend(self._analyze_crypto_api_usage(code, crypto_imports, text_section.VirtualAddress))
            else:
                logger.debug("No CryptoAPI imports found to analyze.")

        except Exception:
            logger.warning("CryptoAPI analysis failed", exc_info=True)

        return keys

    def _analyze_memory_patterns(self, data: bytes) -> list[ExtractedKey]:
        """Analyze memory patterns for in-memory key structures."""
        keys = []

        # OpenSSL RSA structure
        logger.debug("Analyzing memory for OpenSSL RSA structures.")
        openssl_rsa_magic = b"RSA\x00"
        offset = 0
        while True:
            offset = data.find(openssl_rsa_magic, offset)
            if offset == -1:
                break

            # Parse OpenSSL RSA structure
            try:
                struct_data = data[offset : offset + 1024]
                if key := self._parse_openssl_rsa_struct(struct_data):
                    key.address = offset
                    keys.append(key)
                    logger.debug("Found OpenSSL RSA structure at offset %s.", offset)
            except (ValueError, TypeError):
                logger.warning("Failed to parse OpenSSL RSA structure at offset %s", offset, exc_info=True)

            offset += 1

        # Windows BCRYPT_RSAKEY_BLOB structure
        logger.debug("Analyzing memory for Windows BCRYPT_RSAKEY_BLOB structures.")
        bcrypt_magic = b"RSA1"  # BCRYPT_RSAPUBLIC_MAGIC
        offset = 0
        while True:
            offset = data.find(bcrypt_magic, offset)
            if offset == -1:
                break

            try:
                if key := self._parse_bcrypt_key_blob(data[offset : offset + 2048]):
                    key.address = offset
                    keys.append(key)
                    logger.debug("Found Windows BCRYPT_RSAKEY_BLOB structure at offset %s.", offset)
            except (ValueError, TypeError):
                logger.warning("Failed to parse BCRYPT key blob at offset %s", offset, exc_info=True)

            offset += 1

        return keys

    def _entropy_based_key_detection(self, data: bytes) -> list[ExtractedKey]:
        """Detect keys based on entropy analysis."""
        keys = []
        window_size = 256
        logger.debug("Starting entropy-based key detection with window size: %s", window_size)

        for offset in range(0, len(data) - window_size, 16):
            chunk = data[offset : offset + window_size]
            entropy = self._calculate_entropy(chunk)
            logger.debug("Chunk at offset %s has entropy: %.2f", offset, entropy)

            if entropy > 7.8:  # Very high entropy
                logger.debug("High entropy chunk found at offset %s. Checking for key structure.", offset)
                # Check if it's structured like a key
                if self._has_key_structure(chunk):
                    logger.debug("Chunk at offset %s has key-like structure. Attempting to parse.", offset)
                    # Try to parse as various key formats
                    for parser in [
                        self._try_parse_der,
                        self._try_parse_pem,
                        self._try_parse_raw_modulus,
                    ]:
                        if key := parser(chunk):
                            key.address = offset
                            key.confidence *= 0.8  # Lower confidence for entropy-based
                            keys.append(key)
                            logger.debug("Successfully parsed key from high entropy chunk at offset %s.", offset)
                            break

        return keys

    def _calculate_entropy(self, data: bytes) -> float:
        """Calculate Shannon entropy of data."""
        if not data:
            return 0.0

        entropy = 0.0
        for x in range(256):
            p_x = data.count(bytes([x])) / len(data)
            if p_x > 0:
                entropy -= p_x * np.log2(p_x)

        return entropy

    def _is_key_data(self, data: bytes) -> bool:
        """Check if data likely contains cryptographic keys."""
        if len(data) < 128:
            return False

        # Check entropy
        entropy = self._calculate_entropy(data)
        if entropy < 6.0:
            return False

        # Check for key markers
        markers = [b"RSA", b"DSA", b"EC", b"-----BEGIN", b"\x30\x82", b"\x30\x81"]
        return any(marker in data for marker in markers)

    def _parse_key_data(self, data: bytes) -> list[ExtractedKey]:
        """Parse various key formats from data."""
        keys = []

        # Try different parsers
        parsers = [
            self._try_parse_der,
            self._try_parse_pem,
            self._try_parse_pkcs8,
            self._try_parse_pkcs12,
            self._try_parse_openssh,
            self._try_parse_jwk,
        ]

        for parser in parsers:
            try:
                if key := parser(data):
                    keys.append(key)
            except (ValueError, TypeError):
                continue

        return keys

    def _scan_section_for_keys(self, data: bytes, virtual_address: int) -> list[ExtractedKey]:
        """Scan a PE section for embedded keys."""
        keys = []

        # Look for DER encoded keys
        der_markers = [b"\x30\x82", b"\x30\x81"]
        for marker in der_markers:
            offset = 0
            while True:
                offset = data.find(marker, offset)
                if offset == -1:
                    break

                if key := self._extract_asn1_key(data[offset : offset + 4096]):
                    key.address = virtual_address + offset
                    keys.append(key)

                offset += 1

        # Look for PEM encoded keys
        pem_start = b"-----BEGIN"
        offset = 0
        while True:
            offset = data.find(pem_start, offset)
            if offset == -1:
                break

            end_offset = data.find(b"-----END", offset)
            if end_offset != -1:
                pem_data = data[offset : end_offset + 50]
                if key := self._try_parse_pem(pem_data):
                    key.address = virtual_address + offset
                    keys.append(key)

            offset += 1

        return keys

    def _analyze_crypto_api_usage(self, code: bytes, imports: list[tuple[int, bytes]], text_va: int) -> list[ExtractedKey]:
        """Analyze code around CryptoAPI calls to extract keys."""
        keys = []

        # Disassemble code
        instructions = list(self.cs_x64.disasm(code, text_va))

        for imp_addr, imp_name in imports:
            # Find calls to the import
            for i, insn in enumerate(instructions):
                if insn.mnemonic == "call" and insn.op_str == hex(imp_addr):
                    # Analyze parameters pushed before the call
                    # This would involve complex data flow analysis
                    # For now, simple heuristic

                    # Look for key data being pushed
                    for j in range(max(0, i - 20), i):
                        if instructions[j].mnemonic in ["push", "mov", "lea"] and (
                            "dword ptr" in instructions[j].op_str or "qword ptr" in instructions[j].op_str
                        ):
                            try:
                                if addr_match := re.search(
                                    r"\[.*\+ (0x[0-9a-f]+)\]",
                                    instructions[j].op_str,
                                ):
                                    offset = int(addr_match[1], 16)
                                    if 0 < offset < len(code):
                                        potential_key = code[offset : offset + 1024]
                                        if extracted := self._parse_key_data(potential_key):
                                            for key in extracted:
                                                key.context = f"Found near {imp_name.decode('utf-8', errors='ignore')} call"
                                            keys.extend(extracted)
                            except (UnicodeDecodeError, AttributeError):
                                logger.debug("Failed to process import function", exc_info=True)

        return keys

    def _parse_openssl_rsa_struct(self, data: bytes) -> ExtractedKey | None:
        """Parse OpenSSL RSA structure from memory."""
        # OpenSSL RSA structure detection with version-specific handling
        try:
            if data[:4] != b"RSA\x00":
                return None

            # Detect OpenSSL version from structure patterns
            version = self._detect_openssl_version(data)

            if version == "1.0.x":
                return self._parse_openssl_10x_rsa(data)
            if version == "1.1.x":
                return self._parse_openssl_11x_rsa(data)
            if version == "3.x":
                return self._parse_openssl_3x_rsa(data)
            # Generic parser for unknown versions
            return self._parse_generic_openssl_rsa(data)

        except Exception:
            logger.warning("OpenSSL RSA parsing failed", exc_info=True)

        return None

    def _detect_openssl_version(self, data: bytes) -> str:
        """Detect OpenSSL version from RSA structure patterns."""
        # OpenSSL 1.0.x has different structure alignment
        if len(data) > 32 and data[16:20] == b"\x00\x00\x00\x00" and data[24:28] == b"\x00\x00\x00\x00":
            return "1.0.x"

        # OpenSSL 1.1.x uses different memory layout
        if len(data) > 40 and data[32:36] == b"\x01\x00\x00\x00":
            return "1.1.x"

        # OpenSSL 3.x has additional fields
        if len(data) > 48 and data[40:44] == b"\x03\x00\x00\x00":
            return "3.x"

        return "unknown"

    def _parse_openssl_10x_rsa(self, data: bytes) -> ExtractedKey | None:
        """Parse OpenSSL 1.0.x RSA structure."""
        try:
            # OpenSSL 1.0.x RSA structure layout
            offset = 16  # Skip RSA magic and padding

            # Version field (4 bytes)
            struct.unpack("<I", data[offset : offset + 4])[0]
            offset += 4

            # Method pointer (8 bytes on 64-bit)
            offset += 8

            # Engine pointer
            offset += 8

            # BIGNUM pointers for n, e, d, p, q, dmp1, dmq1, iqmp
            struct.unpack("<Q", data[offset : offset + 8])[0]
            offset += 8
            struct.unpack("<Q", data[offset : offset + 8])[0]
            offset += 8
            d_ptr = struct.unpack("<Q", data[offset : offset + 8])[0]
            offset += 8

            # Read actual BIGNUM values from offsets
            n = self._read_openssl_bignum_10x(data[offset:])
            offset += self._bignum_size(n) if n else 32

            e = self._read_openssl_bignum_10x(data[offset:])
            offset += self._bignum_size(e) if e else 4

            if n and e:
                if d_ptr != 0:
                    # Private key
                    self._read_openssl_bignum_10x(data[offset:])
                    return ExtractedKey(
                        key_type=KeyType.RSA_PRIVATE,
                        key_data=data[:1024],
                        modulus=n,
                        exponent=e,
                        confidence=0.90,
                        context="OpenSSL 1.0.x RSA private key structure",
                    )
                # Public key only
                return ExtractedKey(
                    key_type=KeyType.RSA_PUBLIC,
                    key_data=data[:512],
                    modulus=n,
                    exponent=e,
                    confidence=0.85,
                    context="OpenSSL 1.0.x RSA public key structure",
                )
        except Exception:
            logger.warning("OpenSSL 1.0.x RSA parsing failed", exc_info=True)

        return None

    def _parse_openssl_11x_rsa(self, data: bytes) -> ExtractedKey | None:
        """Parse OpenSSL 1.1.x RSA structure."""
        try:
            offset = 16 + 16
            # Version and flags
            struct.unpack("<I", data[offset : offset + 4])[0]
            offset += 4
            struct.unpack("<I", data[offset : offset + 4])[0]
            offset += 4

            # Read BIGNUM structures inline (not pointers in 1.1.x)
            n = self._read_openssl_bignum_11x(data[offset:])
            if not n:
                return None
            offset += self._bignum_size_11x(n)

            e = self._read_openssl_bignum_11x(data[offset:])
            if not e:
                return None
            offset += self._bignum_size_11x(e)

            # Check if private key components exist
            if offset + 32 < len(data):
                if d := self._read_openssl_bignum_11x(data[offset:]):
                    logger.debug("Found OpenSSL 1.1.x RSA private key with d component size: %s", len(d))
                    return ExtractedKey(
                        key_type=KeyType.RSA_PRIVATE,
                        key_data=data[:2048],
                        modulus=n,
                        exponent=e,
                        private_exponent=d,
                        confidence=0.92,
                        context="OpenSSL 1.1.x RSA private key structure",
                    )

            return ExtractedKey(
                key_type=KeyType.RSA_PUBLIC,
                key_data=data[:512],
                modulus=n,
                exponent=e,
                confidence=0.88,
                context="OpenSSL 1.1.x RSA public key structure",
            )

        except Exception:
            logger.warning("OpenSSL 1.1.x RSA parsing failed", exc_info=True)

        return None

    def _parse_openssl_3x_rsa(self, data: bytes) -> ExtractedKey | None:
        """Parse OpenSSL 3.x RSA structure."""
        try:
            offset = 16 + 8
            # Provider pointer
            offset += 8

            # Reference counting
            struct.unpack("<I", data[offset : offset + 4])[0]
            offset += 4

            # Flags
            flags = struct.unpack("<I", data[offset : offset + 4])[0]
            offset += 4

            # Key data starts here
            n = self._read_openssl_bignum_3x(data[offset:])
            if not n:
                return None
            offset += self._bignum_size_3x(n)

            e = self._read_openssl_bignum_3x(data[offset:])
            if not e:
                return None
            offset += self._bignum_size_3x(e)

            # Check for private key
            if flags & 0x01:  # Private key flag
                if d := self._read_openssl_bignum_3x(data[offset:]):
                    logger.debug("Found OpenSSL 3.x RSA private key with d component size: %s", len(d))
                    return ExtractedKey(
                        key_type=KeyType.RSA_PRIVATE,
                        key_data=data[:2048],
                        modulus=n,
                        exponent=e,
                        private_exponent=d,
                        confidence=0.93,
                        context="OpenSSL 3.x RSA private key structure",
                    )

            return ExtractedKey(
                key_type=KeyType.RSA_PUBLIC,
                key_data=data[:512],
                modulus=n,
                exponent=e,
                confidence=0.89,
                context="OpenSSL 3.x RSA public key structure",
            )

        except Exception:
            logger.warning("OpenSSL 3.x RSA parsing failed", exc_info=True)

        return None

    def _parse_generic_openssl_rsa(self, data: bytes) -> ExtractedKey | None:
        """Parse unknown OpenSSL versions with generic parser."""
        try:
            # Try multiple offsets to find BIGNUM structures
            possible_offsets = [16, 24, 32, 40, 48]

            for start_offset in possible_offsets:
                offset = start_offset

                # Try to read n
                n = self._read_openssl_bignum(data[offset:])
                if not n or n.bit_length() < 512 or n.bit_length() > 8192:
                    continue

                offset += self._bignum_size(n)

                # Try to read e
                e = self._read_openssl_bignum(data[offset:])
                if not e or e < 3 or e > 0x10001:
                    continue

                # Found valid n and e
                return ExtractedKey(
                    key_type=KeyType.RSA_PUBLIC,
                    key_data=data[:1024],
                    modulus=n,
                    exponent=e,
                    confidence=0.75,
                    context="OpenSSL RSA structure (generic parser)",
                )

        except Exception:
            logger.warning("Generic OpenSSL RSA parsing failed", exc_info=True)

        return None

    def _read_openssl_bignum_10x(self, data: bytes) -> int | None:
        """Read OpenSSL 1.0.x BIGNUM format (pointer-based storage).

        OpenSSL 1.0.x uses a BIGNUM structure with pointer to dynamically
        allocated data. The structure layout is:
        - d: BN_ULONG* pointer to number data (8 bytes on x64)
        - top: int number of BN_ULONGs used (4 bytes)
        - dmax: int allocated size (4 bytes)
        - neg: int sign flag (4 bytes)
        - flags: int (4 bytes)

        Args:
            data: Raw bytes containing the BIGNUM structure.

        Returns:
            Integer value of the BIGNUM, or None if parsing fails.

        """
        try:
            if len(data) < 24:
                return None

            d_ptr = struct.unpack("<Q", data[:8])[0]

            top = struct.unpack("<I", data[8:12])[0]
            if top == 0 or top > 256:
                return None

            struct.unpack("<I", data[12:16])[0]

            neg = struct.unpack("<I", data[16:20])[0]

            if d_ptr == 0:
                return 0

            num_offset = 24
            if num_offset + (top * 8) > len(data):
                num_offset = 0
            if num_offset + (top * 8) > len(data):
                return None

            num_bytes = []
            for i in range(top):
                word_offset = num_offset + (i * 8)
                if word_offset + 8 > len(data):
                    break
                word = struct.unpack("<Q", data[word_offset : word_offset + 8])[0]
                num_bytes.extend(word.to_bytes(8, "little"))

            while num_bytes and num_bytes[-1] == 0:
                num_bytes.pop()

            if not num_bytes:
                return 0

            value = int.from_bytes(bytes(num_bytes), "little")
            return value if neg == 0 else -value

        except (struct.error, ValueError, IndexError):
            logger.debug("OpenSSL 1.0.x BIGNUM reading failed", exc_info=True)
            return None

    def _read_openssl_bignum_11x(self, data: bytes) -> int | None:
        """Read OpenSSL 1.1.x BIGNUM format (inline storage)."""
        try:
            if len(data) < 12:
                return None

            # 1.1.x stores BIGNUM inline
            # width (number of BN_ULONG)
            width = struct.unpack("<I", data[:4])[0]
            if width > 256:
                return None

            # dmax
            struct.unpack("<I", data[4:8])[0]

            # neg and flags packed
            neg_flags = struct.unpack("<I", data[8:12])[0]
            neg = neg_flags & 1

            # Read number data immediately following
            offset = 12
            num_bytes = []
            for _i in range(width):
                if offset + 8 > len(data):
                    break
                word = struct.unpack("<Q", data[offset : offset + 8])[0]
                num_bytes.extend(word.to_bytes(8, "little"))
                offset += 8

            if num_bytes:
                value = int.from_bytes(bytes(num_bytes), "little")
                return value if neg == 0 else -value

        except Exception:
            logger.debug("BIGNUM reading failed (1.1.x)", exc_info=True)

        return None

    def _read_openssl_bignum_3x(self, data: bytes) -> int | None:
        """Read OpenSSL 3.x BIGNUM format."""
        try:
            if len(data) < 16:
                return None

            # 3.x format with additional metadata
            # Size field
            size = struct.unpack("<Q", data[:8])[0]
            if size > 2048:
                return None

            # Width
            width = struct.unpack("<I", data[8:12])[0]
            if width > 256:
                return None

            # Flags
            flags = struct.unpack("<I", data[12:16])[0]
            neg = flags & 1

            # Data follows
            offset = 16
            if offset + size > len(data):
                return None

            if num_bytes := data[offset : offset + size]:
                value = int.from_bytes(num_bytes, "little")
                return value if neg == 0 else -value

        except Exception:
            logger.debug("BIGNUM reading failed (3.x)", exc_info=True)

        return None

    def _bignum_size_11x(self, n: int) -> int:
        """Calculate BIGNUM size in OpenSSL 1.1.x format."""
        width = (n.bit_length() + 63) // 64
        return 12 + (width * 8)

    def _bignum_size_3x(self, n: int) -> int:
        """Calculate BIGNUM size in OpenSSL 3.x format."""
        size = (n.bit_length() + 7) // 8
        return 16 + size

    def _read_openssl_bignum(self, data: bytes) -> int | None:
        """Read OpenSSL BIGNUM from memory."""
        try:
            # Simplified BIGNUM reading
            if len(data) < 8:
                return None

            # Read size (simplified)
            size = struct.unpack("<I", data[:4])[0]
            if size > 1024 or size < 1:
                return None

            # Read number bytes
            num_bytes = data[8 : 8 + size]
            return int.from_bytes(num_bytes, byteorder="big")
        except (ValueError, IndexError):
            logger.warning("Failed to read OpenSSL BIGNUM from memory", exc_info=True)
            return None

    def _bignum_size(self, n: int) -> int:
        """Calculate size of BIGNUM in memory."""
        return 8 + ((n.bit_length() + 7) // 8)

    def _parse_bcrypt_key_blob(self, data: bytes) -> ExtractedKey | None:
        """Parse Windows BCRYPT_RSAKEY_BLOB structure."""
        try:
            # BCRYPT_RSAKEY_BLOB structure
            magic = data[:4]
            if magic not in [b"RSA1", b"RSA2", b"RSA3"]:
                return None

            struct.unpack("<I", data[4:8])[0]
            pub_exp_len = struct.unpack("<I", data[8:12])[0]
            mod_len = struct.unpack("<I", data[12:16])[0]

            if mod_len > 1024 or pub_exp_len > 8:
                return None

            offset = 24  # Size of header

            # Read exponent
            exponent = int.from_bytes(data[offset : offset + pub_exp_len], byteorder="little")
            offset += pub_exp_len

            # Read modulus
            modulus = int.from_bytes(data[offset : offset + mod_len], byteorder="little")

            key_type = KeyType.RSA_PUBLIC if magic == b"RSA1" else KeyType.RSA_PRIVATE

            return ExtractedKey(
                key_type=key_type,
                key_data=data[: offset + mod_len],
                modulus=modulus,
                exponent=exponent,
                confidence=0.9,
                context="Windows BCRYPT_RSAKEY_BLOB",
            )
        except (ValueError, TypeError):
            logger.warning("Failed to parse BCRYPT key blob", exc_info=True)
            return None

    def _has_key_structure(self, data: bytes) -> bool:
        """Check if data has structure consistent with a key."""
        # Check for ASN.1 structure
        if data[0] == 0x30 and data[1] in [0x81, 0x82]:
            return True

        # Check for consistent byte patterns
        # Keys often have repeating patterns at specific intervals
        return len(set(data[::32])) >= len(data) // 32 * 0.7

    def _try_parse_der(self, data: bytes) -> ExtractedKey | None:
        """Try to parse DER encoded key."""
        return self._extract_asn1_key(data)

    def _try_parse_pem(self, data: bytes) -> ExtractedKey | None:
        """Try to parse PEM encoded key."""
        try:
            # Find PEM boundaries
            start = data.find(b"-----BEGIN")
            if start == -1:
                return None

            end = data.find(b"-----END", start)
            if end == -1:
                return None

            end = data.find(b"-----", end + 8)
            if end == -1:
                end = len(data)
            else:
                end += 5

            pem_data = data[start:end]

            # Determine key type
            if b"RSA PRIVATE" in pem_data:
                key = serialization.load_pem_private_key(pem_data, password=None, backend=self.backend)
                if isinstance(key, RSAPrivateKey):
                    numbers = key.private_numbers()
                    return ExtractedKey(
                        key_type=KeyType.RSA_PRIVATE,
                        key_data=pem_data,
                        modulus=numbers.public_numbers.n,
                        exponent=numbers.public_numbers.e,
                        confidence=0.95,
                        context="PEM encoded RSA private key",
                        key_object=key,
                    )
            elif b"PUBLIC KEY" in pem_data or b"RSA PUBLIC" in pem_data:
                key = serialization.load_pem_public_key(pem_data, backend=self.backend)
                if isinstance(key, RSAPublicKey):
                    numbers = key.public_numbers()
                    return ExtractedKey(
                        key_type=KeyType.RSA_PUBLIC,
                        key_data=pem_data,
                        modulus=numbers.n,
                        exponent=numbers.e,
                        confidence=0.95,
                        context="PEM encoded RSA public key",
                        key_object=key,
                    )
        except (AttributeError, KeyError, ValueError):
            logger.warning("Failed to parse PEM RSA public key", exc_info=True)

        return None

    def _try_parse_raw_modulus(self, data: bytes) -> ExtractedKey | None:
        """Try to interpret data as raw RSA modulus."""
        # Check if it could be a raw modulus (high entropy, right size)
        if len(data) not in [128, 256, 512]:
            return None

        entropy = self._calculate_entropy(data)
        if entropy < 7.5:
            return None

        n = int.from_bytes(data, byteorder="big")
        if self._is_probable_rsa_modulus(n):
            return ExtractedKey(
                key_type=KeyType.RSA_PUBLIC,
                key_data=data,
                modulus=n,
                exponent=65537,  # Common default
                confidence=0.6,
                context="Probable raw RSA modulus",
            )

        return None

    def _try_parse_pkcs8(self, data: bytes) -> ExtractedKey | None:
        """Try to parse PKCS#8 format key."""
        try:
            # PKCS#8 unencrypted private key
            if data[:4] == b"\x30\x82" and b"\x06\x09\x2a\x86\x48\x86\xf7\x0d\x01\x01\x01" in data[:50]:
                key = serialization.load_der_private_key(data, password=None, backend=self.backend)
                if isinstance(key, RSAPrivateKey):
                    numbers = key.private_numbers()
                    return ExtractedKey(
                        key_type=KeyType.RSA_PRIVATE,
                        key_data=data,
                        modulus=numbers.public_numbers.n,
                        exponent=numbers.public_numbers.e,
                        confidence=0.95,
                        context="PKCS#8 RSA private key",
                        key_object=key,
                    )
        except (AttributeError, KeyError, ValueError):
            logger.warning("Failed to parse PKCS#8 RSA private key", exc_info=True)

        return None

    def _try_parse_pkcs12(self, data: bytes) -> ExtractedKey | None:
        """Try to parse PKCS#12 format (PFX) - would need password."""
        # PKCS#12 is typically password protected
        # This would require password cracking or extraction
        return None

    def _try_parse_openssh(self, data: bytes) -> ExtractedKey | None:
        """Try to parse OpenSSH format key."""
        try:
            import base64

            if data.startswith(b"ssh-rsa "):
                # Public key format
                parts = data.split(b" ")
                if len(parts) >= 2:
                    key_data = parts[1]
                    # Base64 decode
                    decoded = base64.b64decode(key_data)

                    # Parse SSH wire format
                    offset = 0

                    # Read key type length (4 bytes, big-endian)
                    if len(decoded) < offset + 4:
                        return None
                    type_len = struct.unpack(">I", decoded[offset : offset + 4])[0]
                    offset += 4

                    # Read key type
                    if len(decoded) < offset + type_len:
                        return None
                    key_type_str = decoded[offset : offset + type_len]
                    offset += type_len

                    if key_type_str != b"ssh-rsa":
                        return None

                    # Read exponent length
                    if len(decoded) < offset + 4:
                        return None
                    e_len = struct.unpack(">I", decoded[offset : offset + 4])[0]
                    offset += 4

                    # Read exponent
                    if len(decoded) < offset + e_len:
                        return None
                    e_bytes = decoded[offset : offset + e_len]
                    exponent = int.from_bytes(e_bytes, byteorder="big")
                    offset += e_len

                    # Read modulus length
                    if len(decoded) < offset + 4:
                        return None
                    n_len = struct.unpack(">I", decoded[offset : offset + 4])[0]
                    offset += 4

                    # Read modulus
                    if len(decoded) < offset + n_len:
                        return None
                    n_bytes = decoded[offset : offset + n_len]
                    modulus = int.from_bytes(n_bytes, byteorder="big")

                    # Create RSA public key
                    from cryptography.hazmat.primitives.asymmetric import rsa

                    public_numbers = rsa.RSAPublicNumbers(exponent, modulus)
                    public_key = public_numbers.public_key(self.backend)

                    return ExtractedKey(
                        key_type=KeyType.RSA_PUBLIC,
                        key_data=decoded,
                        modulus=modulus,
                        exponent=exponent,
                        confidence=0.95,
                        context="OpenSSH RSA public key",
                        key_object=public_key,
                    )

            elif data.startswith(b"ssh-ed25519 "):
                # ED25519 public key
                parts = data.split(b" ")
                if len(parts) >= 2:
                    key_data = parts[1]
                    decoded = base64.b64decode(key_data)

                    offset = 0
                    # Read key type length
                    if len(decoded) < offset + 4:
                        return None
                    type_len = struct.unpack(">I", decoded[offset : offset + 4])[0]
                    offset += 4

                    # Read key type
                    if len(decoded) < offset + type_len:
                        return None
                    key_type_str = decoded[offset : offset + type_len]
                    offset += type_len

                    if key_type_str != b"ssh-ed25519":
                        return None

                    # Read public key length
                    if len(decoded) < offset + 4:
                        return None
                    key_len = struct.unpack(">I", decoded[offset : offset + 4])[0]
                    offset += 4

                    # Read public key
                    if len(decoded) < offset + key_len:
                        return None
                    decoded[offset : offset + key_len]

                    return ExtractedKey(
                        key_type=KeyType.ECC_PUBLIC,
                        key_data=decoded,
                        curve="ed25519",
                        confidence=0.95,
                        context="OpenSSH ED25519 public key",
                    )

            elif data.startswith(b"-----BEGIN OPENSSH PRIVATE KEY-----"):  # pragma: allowlist secret
                # OpenSSH private key format
                end_marker = b"-----END OPENSSH PRIVATE KEY-----"
                end = data.find(end_marker)
                if end == -1:
                    return None

                key_data = data[: end + len(end_marker)]
                # Extract base64 content
                lines = key_data.split(b"\n")
                b64_data = b""
                for line in lines[1:-1]:
                    if not line.startswith(b"-----"):
                        b64_data += line.strip()

                decoded = base64.b64decode(b64_data)

                # Parse OpenSSH private key format
                magic = b"openssh-key-v1\x00"
                if not decoded.startswith(magic):
                    return None

                offset = len(magic)

                # Read cipher name
                cipher_len = struct.unpack(">I", decoded[offset : offset + 4])[0]
                offset += 4
                cipher = decoded[offset : offset + cipher_len]
                offset += cipher_len

                # Read KDF name
                kdf_len = struct.unpack(">I", decoded[offset : offset + 4])[0]
                offset += 4
                decoded[offset : offset + kdf_len]
                offset += kdf_len

                # Read KDF options
                kdf_opts_len = struct.unpack(">I", decoded[offset : offset + 4])[0]
                offset += 4
                decoded[offset : offset + kdf_opts_len]
                offset += kdf_opts_len

                # Number of keys
                num_keys = struct.unpack(">I", decoded[offset : offset + 4])[0]
                offset += 4

                # Read public keys
                for _i in range(num_keys):
                    pubkey_len = struct.unpack(">I", decoded[offset : offset + 4])[0]
                    offset += 4
                    decoded[offset : offset + pubkey_len]
                    offset += pubkey_len

                # Read private key section
                privkey_len = struct.unpack(">I", decoded[offset : offset + 4])[0]
                offset += 4
                if cipher != b"none":
                    # Encrypted key
                    return ExtractedKey(
                        key_type=KeyType.RSA_PRIVATE,
                        key_data=decoded,
                        confidence=0.5,
                        context=f"OpenSSH private key (encrypted with {cipher.decode('utf-8')})",
                    )

                # Unencrypted key - parse it
                priv_offset = 0

                privkey_data = decoded[offset : offset + privkey_len]

                # Check padding
                check1 = struct.unpack(">I", privkey_data[priv_offset : priv_offset + 4])[0]
                priv_offset += 4
                check2 = struct.unpack(">I", privkey_data[priv_offset : priv_offset + 4])[0]
                priv_offset += 4

                if check1 != check2:
                    return None

                # Read key type
                keytype_len = struct.unpack(">I", privkey_data[priv_offset : priv_offset + 4])[0]
                priv_offset += 4
                keytype = privkey_data[priv_offset : priv_offset + keytype_len]
                priv_offset += keytype_len

                if keytype == b"ssh-rsa":
                    # Parse RSA private key
                    # Read n
                    n_len = struct.unpack(">I", privkey_data[priv_offset : priv_offset + 4])[0]
                    priv_offset += 4
                    n = int.from_bytes(privkey_data[priv_offset : priv_offset + n_len], "big")
                    priv_offset += n_len

                    # Read e
                    e_len = struct.unpack(">I", privkey_data[priv_offset : priv_offset + 4])[0]
                    priv_offset += 4
                    e = int.from_bytes(privkey_data[priv_offset : priv_offset + e_len], "big")
                    priv_offset += e_len

                    # Read d
                    d_len = struct.unpack(">I", privkey_data[priv_offset : priv_offset + 4])[0]
                    priv_offset += 4
                    d = int.from_bytes(privkey_data[priv_offset : priv_offset + d_len], "big")
                    priv_offset += d_len

                    # Read iqmp
                    iqmp_len = struct.unpack(">I", privkey_data[priv_offset : priv_offset + 4])[0]
                    priv_offset += 4
                    iqmp = int.from_bytes(privkey_data[priv_offset : priv_offset + iqmp_len], "big")
                    priv_offset += iqmp_len

                    # Read p
                    p_len = struct.unpack(">I", privkey_data[priv_offset : priv_offset + 4])[0]
                    priv_offset += 4
                    p = int.from_bytes(privkey_data[priv_offset : priv_offset + p_len], "big")
                    priv_offset += p_len

                    # Read q
                    q_len = struct.unpack(">I", privkey_data[priv_offset : priv_offset + 4])[0]
                    priv_offset += 4
                    q = int.from_bytes(privkey_data[priv_offset : priv_offset + q_len], "big")

                    # Calculate dmp1 and dmq1
                    dmp1 = d % (p - 1)
                    dmq1 = d % (q - 1)

                    # Create RSA private key
                    from cryptography.hazmat.primitives.asymmetric import rsa

                    private_numbers = rsa.RSAPrivateNumbers(
                        p=p,
                        q=q,
                        d=d,
                        dmp1=dmp1,
                        dmq1=dmq1,
                        iqmp=iqmp,
                        public_numbers=rsa.RSAPublicNumbers(e, n),
                    )
                    private_key = private_numbers.private_key(self.backend)

                    return ExtractedKey(
                        key_type=KeyType.RSA_PRIVATE,
                        key_data=decoded,
                        modulus=n,
                        exponent=e,
                        confidence=0.98,
                        context="OpenSSH RSA private key (unencrypted)",
                        key_object=private_key,
                    )
        except Exception:
            logger.warning("OpenSSH RSA parsing failed", exc_info=True)

        return None

    def _try_parse_jwk(self, data: bytes) -> ExtractedKey | None:
        """Try to parse JSON Web Key format."""
        try:
            import json

            jwk = json.loads(data)
            if jwk.get("kty") == "RSA":
                import base64

                n = int.from_bytes(base64.urlsafe_b64decode(jwk["n"] + "=="), "big")
                e = int.from_bytes(base64.urlsafe_b64decode(jwk["e"] + "=="), "big")

                return ExtractedKey(
                    key_type=KeyType.RSA_PUBLIC,
                    key_data=data,
                    modulus=n,
                    exponent=e,
                    confidence=0.95,
                    context="JSON Web Key (JWK)",
                )
        except (ValueError, TypeError, json.JSONDecodeError):
            logger.warning("Failed to parse JSON Web Key", exc_info=True)

        return None

    def extract_ecc_keys_from_binary(self, binary_path: str) -> list[ExtractedKey]:
        """Extract ECC keys from binary."""
        keys = []

        with open(binary_path, "rb") as f:
            data = f.read()

        # Pattern matching for ECC structures
        for pattern in self.ecc_patterns:
            for match in pattern.finditer(data):
                offset = match.start()
                if key_candidate := self._extract_ecc_key(data[offset : offset + 512]):
                    key_candidate.address = offset
                    keys.append(key_candidate)

        # Look for named curve OIDs
        curve_oids = {
            b"\x06\x08\x2a\x86\x48\xce\x3d\x03\x01\x07": "P-256",
            b"\x06\x05\x2b\x81\x04\x00\x22": "P-384",
            b"\x06\x05\x2b\x81\x04\x00\x23": "P-521",
            b"\x06\x05\x2b\x81\x04\x00\x0a": "secp256k1",
        }

        for oid, curve_name in curve_oids.items():
            offset = 0
            while True:
                offset = data.find(oid, offset)
                if offset == -1:
                    break

                # Look for EC point nearby
                for point_offset in range(max(0, offset - 100), min(len(data), offset + 100)):
                    if data[point_offset] == 0x04:  # Uncompressed point
                        point_len = {"P-256": 64, "P-384": 96, "P-521": 132}.get(curve_name)
                        if point_len and point_offset + point_len + 1 <= len(data):
                            point_data = data[point_offset : point_offset + point_len + 1]
                            keys.append(
                                ExtractedKey(
                                    key_type=KeyType.ECC_PUBLIC,
                                    key_data=point_data,
                                    curve=curve_name,
                                    address=point_offset,
                                    confidence=0.8,
                                    context=f"EC point for curve {curve_name}",
                                ),
                            )
                            break

                offset += 1
        return keys

    def _extract_ecc_key(self, data: bytes) -> ExtractedKey | None:
        """Extract ECC key from data."""
        try:
            # Try to parse as ECC public key
            key = serialization.load_der_public_key(data, backend=self.backend)
            if isinstance(key, EllipticCurvePublicKey):
                curve_name = key.curve.name
                return ExtractedKey(
                    key_type=KeyType.ECC_PUBLIC,
                    key_data=data[:256],
                    curve=curve_name,
                    confidence=0.95,
                    context="ASN.1 DER encoded ECC public key",
                    key_object=key,
                )

            # Try as private key
            key = serialization.load_der_private_key(data, password=None, backend=self.backend)
            if isinstance(key, EllipticCurvePrivateKey):
                curve_name = key.curve.name
                return ExtractedKey(
                    key_type=KeyType.ECC_PRIVATE,
                    key_data=data[:256],
                    curve=curve_name,
                    confidence=0.98,
                    context="ASN.1 DER encoded ECC private key",
                    key_object=key,
                )
        except (AttributeError, KeyError, ValueError):
            logger.warning("Failed to extract ECC key", exc_info=True)

        return None

    def extract_certificates(self, binary_path: str) -> list[x509.Certificate]:
        """Extract X.509 certificates from binary."""
        certificates = []

        with open(binary_path, "rb") as f:
            data = f.read()

        # Look for certificate markers
        for pattern in self.cert_patterns:
            for match in pattern.finditer(data):
                offset = match.start()
                try:
                    # Try to parse certificate
                    cert_data = data[offset : offset + 8192]
                    cert = x509.load_der_x509_certificate(cert_data, backend=self.backend)
                    certificates.append(cert)
                except (ValueError, TypeError):
                    logger.warning("Failed to parse DER certificate at offset %s", offset, exc_info=True)
                    # Try PEM format
                    try:
                        end = data.find(b"-----END CERTIFICATE-----", offset)
                        if end != -1:
                            cert_data = data[offset : end + 25]
                            cert = x509.load_pem_x509_certificate(cert_data, backend=self.backend)
                            certificates.append(cert)
                    except (ValueError, TypeError):
                        logger.warning("Failed to parse PEM certificate at offset %s", offset, exc_info=True)

        logger.info("Found %s certificates in %s", len(certificates), binary_path)
        return certificates

    def extract_all_keys(self, binary_path: str) -> dict[str, list[ExtractedKey]]:
        """Extract all types of cryptographic keys from binary."""
        results = {
            "ecc": [],
            "symmetric": [],
            "certificates": [],
            "rsa": self.extract_rsa_keys_from_binary(binary_path),
        }

        # Extract ECC keys
        results["ecc"] = self.extract_ecc_keys_from_binary(binary_path)

        # Extract symmetric keys (simplified)
        results["symmetric"] = self._extract_symmetric_keys(binary_path)

        # Extract certificates and get their public keys
        certs = self.extract_certificates(binary_path)
        for cert in certs:
            pub_key = cert.public_key()
            if isinstance(pub_key, RSAPublicKey):
                numbers = pub_key.public_numbers()
                results["rsa"].append(
                    ExtractedKey(
                        key_type=KeyType.RSA_PUBLIC,
                        key_data=cert.public_bytes(serialization.Encoding.DER),
                        modulus=numbers.n,
                        exponent=numbers.e,
                        confidence=1.0,
                        context=f"Certificate: {cert.subject}",
                    ),
                )
            elif isinstance(pub_key, EllipticCurvePublicKey):
                results["ecc"].append(
                    ExtractedKey(
                        key_type=KeyType.ECC_PUBLIC,
                        key_data=cert.public_bytes(serialization.Encoding.DER),
                        curve=pub_key.curve.name,
                        confidence=1.0,
                        context=f"Certificate: {cert.subject}",
                    ),
                )

        total_keys = len(results["rsa"]) + len(results["ecc"]) + len(results["symmetric"])
        logger.info("Extraction complete. Found %s total keys and %s certificates in %s", total_keys, len(certs), binary_path)
        return results

    def _extract_symmetric_keys(self, binary_path: str) -> list[ExtractedKey]:
        """Extract symmetric encryption keys (AES, DES, etc.)."""
        keys = []

        with open(binary_path, "rb") as f:
            data = f.read()

        # Look for high-entropy regions of specific sizes
        key_sizes = [16, 24, 32, 56, 64, 128, 256]  # Common symmetric key sizes

        for size in key_sizes:
            for offset in range(0, len(data) - size, 4):
                chunk = data[offset : offset + size]
                entropy = self._calculate_entropy(chunk)

                if entropy > 7.5 and self._is_likely_symmetric_key(chunk):
                    key_type = self._determine_symmetric_type(chunk)
                    keys.append(
                        ExtractedKey(
                            key_type=key_type,
                            key_data=chunk,
                            address=offset,
                            confidence=0.7,
                            context=f"Probable {key_type.value} key",
                        ),
                    )

        return keys

    def _is_likely_symmetric_key(self, data: bytes) -> bool:
        """Check if data is likely a symmetric key."""
        # No obvious patterns
        if b"\x00" * 4 in data or b"\xff" * 4 in data:
            return False

        # High entropy
        if self._calculate_entropy(data) < 7.0:
            return False

        # No ASCII text
        try:
            data.decode("ascii")
            return False  # Keys shouldn't be ASCII text
        except UnicodeDecodeError:
            pass

        return True

    def _determine_symmetric_type(self, data: bytes) -> KeyType:
        """Determine type of symmetric key based on size."""
        size = len(data)
        if size in {16, 24, 32}:
            return KeyType.AES
        return KeyType.DES if size in {56, 64} else KeyType.CUSTOM

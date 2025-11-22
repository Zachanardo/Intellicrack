"""Radare2 string analysis module for extracting and analyzing string data."""

import binascii
import logging
import re
from typing import Any

from intellicrack.utils.logger import logger

from ...utils.tools.radare2_utils import R2Exception, R2Session, r2_session


"""
Radare2 Advanced String Analysis Engine

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


class R2StringAnalyzer:
    """Advanced string analysis engine using radare2's comprehensive string detection.

    Provides sophisticated string analysis for:
    - License key and validation string detection
    - Crypto constants and algorithm identifiers
    - API and library function names
    - Error messages and user prompts
    - Network endpoints and URLs
    - File paths and registry keys
    """

    def __init__(self, binary_path: str, radare2_path: str | None = None) -> None:
        """Initialize string analyzer.

        Args:
            binary_path: Path to binary file
            radare2_path: Optional path to radare2 executable

        """
        self.binary_path = binary_path
        self.radare2_path = radare2_path
        self.logger = logging.getLogger(__name__)
        self.string_cache = {}

    def analyze_all_strings(self, min_length: int = 4, encoding: str = "auto") -> dict[str, Any]:
        """Perform comprehensive string analysis on the binary.

        Args:
            min_length: Minimum string length to consider
            encoding: String encoding ('auto', 'ascii', 'utf8', 'utf16')

        Returns:
            Complete string analysis results

        """
        result = {
            "binary_path": self.binary_path,
            "total_strings": 0,
            "string_sections": {},
            "license_strings": [],
            "crypto_strings": [],
            "api_strings": [],
            "url_strings": [],
            "file_path_strings": [],
            "registry_strings": [],
            "error_message_strings": [],
            "version_strings": [],
            "compiler_strings": [],
            "debug_strings": [],
            "user_interface_strings": [],
            "network_strings": [],
            "categorized_stats": {},
            "cross_references": {},
            "string_entropy_analysis": {},
            "suspicious_patterns": [],
        }

        try:
            with r2_session(self.binary_path, self.radare2_path) as r2:
                # Get all strings using different radare2 commands
                all_strings = self._get_comprehensive_strings(r2, min_length, encoding)
                result["total_strings"] = len(all_strings)

                # Analyze strings by section
                result["string_sections"] = self._analyze_strings_by_section(r2, all_strings)

                # Categorize strings
                categories = self._categorize_strings(all_strings)
                result |= categories

                # Get cross-references for important strings
                result["cross_references"] = self._get_string_cross_references(r2, all_strings)

                # Perform entropy analysis
                result["string_entropy_analysis"] = self._analyze_string_entropy(all_strings)

                # Detect suspicious patterns
                result["suspicious_patterns"] = self._detect_suspicious_patterns(all_strings)

                # Generate statistics
                result["categorized_stats"] = self._generate_category_statistics(result)

        except R2Exception as e:
            result["error"] = str(e)
            self.logger.error(f"String analysis failed: {e}")

        return result

    def _get_comprehensive_strings(
        self, r2: R2Session, min_length: int, encoding: str
    ) -> list[dict[str, Any]]:
        """Get strings using multiple radare2 commands for comprehensive coverage."""
        all_strings = []

        try:
            # Primary string extraction - all strings in sections
            strings_data = r2._execute_command("izzj", expect_json=True)
            if isinstance(strings_data, list):
                all_strings.extend(strings_data)

            # Get strings from data sections specifically
            data_strings = r2._execute_command("izj", expect_json=True)
            if isinstance(data_strings, list):
                # Merge, avoiding duplicates
                existing_addrs = {s.get("vaddr", 0) for s in all_strings}
                for string_data in data_strings:
                    if string_data.get("vaddr", 0) not in existing_addrs:
                        all_strings.append(string_data)

            # Get strings with minimum length filter
            if min_length > 4:
                filtered_strings = []
                for string_data in all_strings:
                    if string_data.get("length", 0) >= min_length:
                        filtered_strings.append(string_data)
                all_strings = filtered_strings

            # Apply encoding-specific string extraction
            if encoding in {"auto", "utf16"}:
                # Get wide character strings (UTF-16)
                try:
                    wide_strings = r2._execute_command("izwj", expect_json=True)
                    if isinstance(wide_strings, list):
                        # Mark wide strings
                        for ws in wide_strings:
                            ws["encoding"] = "utf-16"
                            ws["is_wide"] = True
                        existing_addrs = {s.get("vaddr", 0) for s in all_strings}
                        for wide_string in wide_strings:
                            if wide_string.get("vaddr", 0) not in existing_addrs:
                                all_strings.append(wide_string)
                except R2Exception as e:
                    logger.error("R2Exception in radare2_strings: %s", e)

            # For specific encodings, filter strings accordingly
            if encoding in ["ascii", "utf8"] and encoding != "auto":
                filtered_strings = []
                for string_data in all_strings:
                    string_content = string_data.get("string", "")
                    try:
                        if encoding == "ascii":
                            string_content.encode("ascii")
                        elif encoding == "utf8":
                            string_content.encode("utf-8")
                        string_data["encoding"] = encoding
                        filtered_strings.append(string_data)
                    except UnicodeEncodeError as e:
                        logger.error("UnicodeEncodeError in radare2_strings: %s", e)
                        continue
                all_strings = filtered_strings

            # Clean and normalize string data
            normalized_strings = []
            for string_data in all_strings:
                if normalized := self._normalize_string_data(string_data):
                    normalized_strings.append(normalized)

            return normalized_strings

        except R2Exception as e:
            self.logger.error(f"Failed to extract strings: {e}")
            return []

    def _normalize_string_data(self, string_data: dict[str, Any]) -> dict[str, Any] | None:
        """Normalize string data from radare2 output."""
        if not isinstance(string_data, dict):
            return None

        # Extract string content
        content = string_data.get("string", "")
        if not content:
            return None

        # Normalize the data structure
        normalized = {
            "content": content,
            "address": string_data.get("vaddr", 0),
            "physical_address": string_data.get("paddr", 0),
            "length": string_data.get("length", len(content)),
            "size": string_data.get("size", len(content)),
            "section": string_data.get("section", ""),
            "type": string_data.get("type", "ascii"),
            "encoding": string_data.get("encoding", "ascii"),
            "is_wide": string_data.get("is_wide", False),
            "entropy": self._calculate_entropy(content),
        }

        normalized["has_null_bytes"] = "\x00" in content
        normalized["is_printable"] = all(c.isprintable() or c.isspace() for c in content)

        return normalized

    def _analyze_strings_by_section(
        self, r2: R2Session, strings: list[dict[str, Any]]
    ) -> dict[str, Any]:
        """Analyze string distribution by binary sections."""
        sections = {}

        # Get section information
        try:
            section_info = r2._execute_command("iSj", expect_json=True)
            if isinstance(section_info, list):
                for section in section_info:
                    sections[section.get("name", "")] = {
                        "address": section.get("vaddr", 0),
                        "size": section.get("vsize", 0),
                        "permissions": section.get("perm", ""),
                        "strings": [],
                    }
        except R2Exception as e:
            self.logger.error("R2Exception in radare2_strings: %s", e)

        # Distribute strings to sections
        for string_data in strings:
            section_name = string_data.get("section", "unknown")
            if section_name not in sections:
                sections[section_name] = {"strings": []}
            sections[section_name]["strings"].append(string_data)

        # Calculate section statistics
        for section_data in sections.values():
            section_strings = section_data["strings"]
            section_data["string_count"] = len(section_strings)
            section_data["total_string_length"] = sum(s.get("length", 0) for s in section_strings)
            section_data["average_string_length"] = section_data["total_string_length"] / max(
                1, section_data["string_count"]
            )

        return sections

    def _categorize_strings(self, strings: list[dict[str, Any]]) -> dict[str, list[dict[str, Any]]]:
        """Categorize strings based on content patterns."""
        categories = {
            "license_strings": [],
            "crypto_strings": [],
            "api_strings": [],
            "url_strings": [],
            "file_path_strings": [],
            "registry_strings": [],
            "error_message_strings": [],
            "version_strings": [],
            "compiler_strings": [],
            "debug_strings": [],
            "user_interface_strings": [],
            "network_strings": [],
        }

        for string_data in strings:
            content = string_data.get("content", "").lower()

            # License-related strings
            if self._is_license_string(content):
                categories["license_strings"].append(string_data)

            # Cryptographic strings
            if self._is_crypto_string(content):
                categories["crypto_strings"].append(string_data)

            # API function names
            if self._is_api_string(content):
                categories["api_strings"].append(string_data)

            # URLs and network endpoints
            if self._is_url_string(content):
                categories["url_strings"].append(string_data)

            # File paths
            if self._is_file_path_string(content):
                categories["file_path_strings"].append(string_data)

            # Registry keys
            if self._is_registry_string(content):
                categories["registry_strings"].append(string_data)

            # Error messages
            if self._is_error_message_string(content):
                categories["error_message_strings"].append(string_data)

            # Version information
            if self._is_version_string(content):
                categories["version_strings"].append(string_data)

            # Compiler artifacts
            if self._is_compiler_string(content):
                categories["compiler_strings"].append(string_data)

            # Debug information
            if self._is_debug_string(content):
                categories["debug_strings"].append(string_data)

            # UI elements
            if self._is_ui_string(content):
                categories["user_interface_strings"].append(string_data)

            # Network-related
            if self._is_network_string(content):
                categories["network_strings"].append(string_data)

        return categories

    def _is_license_string(self, content: str) -> bool:
        """Enhanced license string detection with advanced algorithms."""
        # Basic pattern matching (existing functionality)
        license_patterns = [
            r"\blicens\w*\b",
            r"\bregistr\w*\b",
            r"\bactivat\w*\b",
            r"\bserial\b",
            r"\bkey\b.*\b(valid|check|verify)\b",
            r"\btrial\b",
            r"\bdemo\b.*\b(period|time|expir)\b",
            r"\bexpir\w*\b",
            r"\bauthenti\w*\b",
            r"\bdongle\b",
            r"\bhwid\b",
            r"\bcrack\w*\b",
            r"\bpirat\w*\b",
            r"\billegal\b.*\bcopy\b",
            r"\bgenuine\b.*\bsoftware\b",
        ]

        if any(re.search(pattern, content, re.IGNORECASE) for pattern in license_patterns):
            return True

        # Enhanced license key format detection
        return self._detect_license_key_formats(content)

    def _detect_license_key_formats(self, content: str) -> bool:
        """Advanced license key format detection algorithms."""
        # Remove whitespace and hyphens for analysis
        clean_content = re.sub(r"[\s\-_]", "", content)

        # Common license key patterns
        license_key_patterns = [
            # XXXX-XXXX-XXXX-XXXX format (16 chars in groups of 4)
            r"^[A-Z0-9]{4}-[A-Z0-9]{4}-[A-Z0-9]{4}-[A-Z0-9]{4}$",
            # XXXXX-XXXXX-XXXXX-XXXXX format (20 chars in groups of 5)
            r"^[A-Z0-9]{5}-[A-Z0-9]{5}-[A-Z0-9]{5}-[A-Z0-9]{5}$",
            # Microsoft-style product keys (25 characters)
            r"^[BCDFGHJKMPQRTVWXY2346789]{25}$",
            # UUID format (license keys sometimes use this)
            r"^[0-9A-F]{8}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{12}$",
            # Base32 encoded keys (common in software licensing)
            r"^[A-Z2-7]{16,}$",
        ]

        # Check against known patterns
        for pattern in license_key_patterns:
            if re.match(pattern, content.upper()):
                # Additional check for Base32 pattern to avoid false positives
                if "A-Z2-7" in pattern and self._is_repetitive_pattern(content.upper()):
                    continue
                return True

        # Entropy-based detection for potential license keys
        if self._analyze_license_key_entropy(clean_content):
            return True

        # Character distribution analysis
        if self._analyze_license_key_distribution(clean_content):
            return True

        # Check for common license validation contexts
        return self._check_license_validation_context(content)

    def _analyze_license_key_entropy(self, content: str) -> bool:
        """Analyze entropy to detect potential license keys."""
        if len(content) < 8:
            return False

        # Calculate Shannon entropy
        entropy = self._calculate_entropy(content)

        # License keys typically have moderate to high entropy (2.5-4.5)
        # but not as high as random data (>4.5)
        if 2.5 <= entropy <= 4.5 and len(content) >= 12:
            # Additional checks for license key characteristics
            alphanum_ratio = sum(c.isalnum() for c in content) / len(content)
            # Avoid repetitive patterns that could false positive
            if alphanum_ratio > 0.8 and not self._is_repetitive_pattern(content):
                return True

        return False

    def _analyze_license_key_distribution(self, content: str) -> bool:
        """Analyze character distribution patterns typical of license keys."""
        if len(content) < 12 or len(content) > 50:
            return False

        # Count character types
        digits = sum(c.isdigit() for c in content)
        letters = sum(c.isalpha() for c in content)
        total = len(content)

        if total == 0:
            return False

        digit_ratio = digits / total
        letter_ratio = letters / total

        # License keys typically have balanced alphanumeric distribution
        # Usually 30-70% digits, 30-70% letters
        return bool(0.3 <= digit_ratio <= 0.7 and 0.3 <= letter_ratio <= 0.7 and (self._has_license_key_patterns(content) and not self._is_repetitive_pattern(content)))

    def _has_license_key_patterns(self, content: str) -> bool:
        """Check for patterns common in license keys."""
        # Avoid keys with too many repeated characters
        char_counts = {}
        for char in content:
            char_counts[char] = char_counts.get(char, 0) + 1

        # Check if any character appears more than 40% of the time
        max_char_freq = max(char_counts.values()) / len(content)
        if max_char_freq > 0.4:
            return False

        alternations = sum(bool(content[i].isdigit() != content[i + 1].isdigit())
                       for i in range(len(content) - 1))
        alternation_ratio = alternations / max(1, len(content) - 1)
        return 0.3 <= alternation_ratio <= 0.8  # Moderate alternation suggests structure

    def _is_repetitive_pattern(self, content: str) -> bool:
        """Check if string has repetitive patterns that are unlikely in real license keys."""
        if len(content) < 4:
            return False

        # Check for excessive character repetition
        char_counts = {}
        for char in content:
            char_counts[char] = char_counts.get(char, 0) + 1

        # If any character appears more than 50% of the time, it's too repetitive
        max_char_freq = max(char_counts.values()) / len(content)
        if max_char_freq > 0.5:
            return True

        # Check for simple patterns like "AAAA", "ABAB", etc.
        # Pattern 1: All same character
        if len(set(content)) == 1:
            return True

        # Pattern 2: Simple repetition of 1-3 characters
        for pattern_len in range(1, 4):
            pattern = content[:pattern_len]
            if (
                pattern * (len(content) // pattern_len + 1)
                == content + pattern[: len(content) % pattern_len]
            ):
                return True

        return False

    def _check_license_validation_context(self, content: str) -> bool:
        """Check if string appears in license validation context."""
        # Check if the string format suggests it's used for validation
        # Common patterns in license validation messages

        # This would need context from surrounding strings/code
        # For now, check if the string itself has validation-like structure
        content_lower = content.lower()
        return any(
            pattern in content_lower
            for pattern in ["key", "serial", "code"]
            if len(content) >= 10 and content.isascii()
        )

    def _is_crypto_string(self, content: str) -> bool:
        """Enhanced cryptographic string identification with advanced algorithms."""
        # Basic pattern matching (existing functionality)
        crypto_patterns = [
            r"\b(aes|des|3des|blowfish|twofish|serpent)\b",
            r"\b(rsa|dsa|ecdsa|ecdh|dh)\b",
            r"\b(sha1|sha256|sha512|md5|md4|crc32)\b",
            r"\b(hmac|pbkdf2|scrypt|bcrypt)\b",
            r"\b(cipher|encrypt|decrypt|hash|sign|verify)\b",
            r"\b(ssl|tls|x509|pkcs|asn1)\b",
            r"\b(iv|salt|nonce|padding|key)\b.*\b(size|length)\b",
            r"\bcrypto\w*\b",
            r"\bcipher\w*\b",
        ]

        if any(re.search(pattern, content, re.IGNORECASE) for pattern in crypto_patterns):
            return True

        # Enhanced cryptographic data detection
        return self._detect_cryptographic_data(content)

    def _detect_cryptographic_data(self, content: str) -> bool:
        """Advanced detection of cryptographic data patterns."""
        # Check for Base64 encoded data (common in crypto)
        if self._is_base64_data(content):
            return True

        # Check for hexadecimal data that could be keys/hashes
        if self._is_hex_crypto_data(content):
            return True

        # Check for PEM format data
        if self._is_pem_format(content):
            return True

        # Check for binary data patterns that suggest crypto
        if self._analyze_crypto_entropy(content):
            return True

        # Check for common crypto constants
        return self._has_crypto_constants(content)

    def _is_base64_data(self, content: str) -> bool:
        """Detect Base64 encoded cryptographic data."""
        # Remove whitespace for analysis
        clean_content = re.sub(r"\s+", "", content)

        # Basic Base64 pattern check
        if not re.match(r"^[A-Za-z0-9+/]*={0,2}$", clean_content):
            return False

        # Length should be multiple of 4 (with padding)
        if len(clean_content) % 4 != 0:
            return False

        # Should be reasonably long to be crypto data
        if len(clean_content) < 16:
            return False

        # Try to decode to verify it's valid Base64
        try:
            decoded = binascii.a2b_base64(clean_content)
            # Check if decoded data has crypto-like characteristics
            return self._analyze_binary_crypto_data(decoded)
        except Exception:
            return False

    def _is_hex_crypto_data(self, content: str) -> bool:
        """Detect hexadecimal cryptographic data."""
        # Remove spaces and check if it's valid hex
        clean_hex = re.sub(r"[\s:,]", "", content)

        if not re.match(r"^[0-9A-Fa-f]+$", clean_hex):
            return False

        # Common crypto data lengths (in bytes, so hex length * 2)
        common_crypto_lengths = [
            32,  # 16 bytes - MD5 hash, AES-128 key
            40,  # 20 bytes - SHA1 hash
            48,  # 24 bytes - 3DES key
            64,  # 32 bytes - SHA256 hash, AES-256 key
            96,  # 48 bytes - 3DES key with parity
            128,  # 64 bytes - SHA512 hash
            256,  # 128 bytes - RSA-1024 key component
            512,  # 256 bytes - RSA-2048 key component
        ]

        hex_len = len(clean_hex)

        # Check against common crypto lengths
        if hex_len in common_crypto_lengths:
            return True

        # Check for patterns suggesting structured crypto data
        if hex_len >= 32 and hex_len % 16 == 0:  # Multiple of 16 bytes
            entropy = self._calculate_hex_entropy(clean_hex)
            return entropy > 3.5  # High entropy suggests crypto data

        return False

    def _is_pem_format(self, content: str) -> bool:
        """Detect PEM format cryptographic data."""
        pem_patterns = [
            r"-----BEGIN\s+(CERTIFICATE|PRIVATE KEY|PUBLIC KEY|RSA PRIVATE KEY)-----",
            r"-----END\s+(CERTIFICATE|PRIVATE KEY|PUBLIC KEY|RSA PRIVATE KEY)-----",
        ]

        return any(re.search(pattern, content, re.IGNORECASE) for pattern in pem_patterns)

    def _analyze_crypto_entropy(self, content: str) -> bool:
        """Analyze entropy to detect potential cryptographic data."""
        if len(content) < 20:
            return False

        entropy = self._calculate_entropy(content)

        # Cryptographic data typically has very high entropy (>4.0)
        if entropy > 4.0:
            # Additional checks to avoid false positives
            # Check character distribution
            char_variety = len(set(content))
            length = len(content)

            # Crypto data should have good character variety
            if char_variety / length > 0.3:
                return True

        return False

    def _has_crypto_constants(self, content: str) -> bool:
        """Check for known cryptographic constants."""
        # Common crypto constants (in hex)
        crypto_constants = [
            "67452301",  # MD5 initial value
            "6A09E667",  # SHA-256 initial value
            "76543210",  # Common test pattern
            "DEADBEEF",  # Common debug value
            "01234567",  # Sequential pattern
            "CAFEBABE",  # Java class file magic
        ]

        content_upper = content.upper()
        return any(const in content_upper for const in crypto_constants)

    def _analyze_binary_crypto_data(self, data: bytes) -> bool:
        """Analyze binary data for cryptographic characteristics."""
        if len(data) < 8:
            return False

        # Calculate byte frequency distribution
        byte_counts = [0] * 256
        for byte in data:
            byte_counts[byte] += 1

        # Calculate chi-square test for randomness
        expected = len(data) / 256.0
        chi_square = sum((count - expected) ** 2 / expected for count in byte_counts)

        # Values close to 255 suggest random/crypto data
        # Threshold based on statistical analysis
        return chi_square < 300  # Adjusted threshold for crypto detection

    def _calculate_hex_entropy(self, hex_string: str) -> float:
        """Calculate entropy of hex string."""
        if not hex_string:
            return 0.0

        # Convert to bytes for entropy calculation
        try:
            data = bytes.fromhex(hex_string)
            return self._calculate_entropy(data.decode("latin-1"))
        except ValueError:
            # Fallback to character-based entropy
            return self._calculate_entropy(hex_string)

    def _is_api_string(self, content: str) -> bool:
        """Enhanced API call string analysis with advanced algorithms."""
        if len(content) > 50:
            return False

        # Basic pattern matching (existing functionality)
        api_patterns = [
            r"^(Get|Set|Create|Delete|Open|Close|Read|Write|Load|Save)\w+$",
            r"^(Reg|File|Process|Thread|Memory|Window)\w+$",
            r"^(Socket|Connect|Send|Recv|Http)\w+$",
            r"^(Crypt|Hash|Sign|Verify)\w+$",
            r"^\w+(A|W)$",  # ANSI/Wide API variants
            r"^\w+Ex$",  # Extended API variants
            r"^_\w+$",  # C runtime functions
            r"^__\w+$",  # Compiler intrinsics
        ]

        return (
            True
            if any(re.match(pattern, content) for pattern in api_patterns)
            else self._analyze_api_function_patterns(content)
        )

    def _analyze_api_function_patterns(self, content: str) -> bool:
        """Advanced analysis of API function patterns."""
        # Check against comprehensive Windows API database
        if self._is_windows_api_function(content):
            return True

        # Check against POSIX/Linux API patterns
        if self._is_posix_api_function(content):
            return True

        # Check against common library APIs
        if self._is_library_api_function(content):
            return True

        # Analyze naming conventions typical of APIs
        return self._analyze_api_naming_conventions(content)

    def _is_windows_api_function(self, content: str) -> bool:
        """Detect Windows API functions using comprehensive patterns."""
        # Windows API prefixes and common functions
        windows_api_prefixes = [
            "Nt",
            "Zw",
            "Rtl",
            "Ke",
            "Io",
            "Mm",
            "Ps",
            "Se",
            "Ex",
            "Ob",
            "Hal",
            "Cc",
            "Cm",
            "Fsrtl",
            "Flt",
            "Pci",
            "Wdf",
            "Wdm",
        ]

        # Check for Windows API prefixes
        for prefix in windows_api_prefixes:
            if content.startswith(prefix) and len(content) > len(prefix) + 2:
                # Verify it follows Windows API naming convention
                remaining = content[len(prefix) :]
                if remaining[0].isupper() and any(c.islower() for c in remaining):
                    return True

        # Check for common Windows API patterns
        windows_patterns = [
            r"^(Create|Open|Close|Delete|Query|Set|Enum|Find)\w*(File|Key|Process|Thread|Section)$",
            r"^(Load|Free|Get|Release)\w*(Library|Module|Proc)$",
            r"^(Virtual|Heap|Local|Global)\w*(Alloc|Free|Lock|Unlock)$",
            r"^(Wait|Signal|Create|Open|Close)\w*(Event|Mutex|Semaphore)$",
            r"^(Reg|Registry)\w*(Create|Open|Close|Query|Set|Delete|Enum)$",
        ]

        return any(re.match(pattern, content, re.IGNORECASE) for pattern in windows_patterns)

    def _is_posix_api_function(self, content: str) -> bool:
        """Detect POSIX/Linux API functions."""
        # Common POSIX system calls and library functions
        posix_functions = [
            # File operations
            "open",
            "close",
            "read",
            "write",
            "lseek",
            "stat",
            "fstat",
            "lstat",
            "access",
            "chmod",
            "chown",
            "link",
            "unlink",
            "symlink",
            "readlink",
            "mkdir",
            "rmdir",
            "opendir",
            "readdir",
            "closedir",
            "rewinddir",
            # Process management
            "fork",
            "execve",
            "execl",
            "execlp",
            "execv",
            "execvp",
            "wait",
            "waitpid",
            "kill",
            "getpid",
            "getppid",
            "getuid",
            "geteuid",
            "getgid",
            # Memory management
            "malloc",
            "calloc",
            "realloc",
            "free",
            "mmap",
            "munmap",
            "mprotect",
            # Networking
            "socket",
            "bind",
            "listen",
            "accept",
            "connect",
            "send",
            "recv",
            "sendto",
            "recvfrom",
            "getsockopt",
            "setsockopt",
            # Threading
            "pthread_create",
            "pthread_join",
            "pthread_mutex_init",
            "pthread_mutex_lock",
            "pthread_mutex_unlock",
            "pthread_cond_wait",
        ]

        # Check exact matches (case-sensitive for POSIX)
        if content in posix_functions:
            return True

        # Check for POSIX-style prefixes
        posix_prefixes = ["pthread_", "sem_", "shm_", "msg_", "sig_"]
        return any(content.startswith(prefix) for prefix in posix_prefixes)

    def _is_library_api_function(self, content: str) -> bool:
        """Detect common library API functions."""
        # Common library prefixes
        library_prefixes = [
            # Graphics libraries
            "gl",
            "GL_",
            "d3d",
            "D3D",
            "gdi",
            "GDI",
            # Crypto libraries
            "SSL_",
            "EVP_",
            "RSA_",
            "AES_",
            "SHA_",
            "MD5_",
            # Network libraries
            "curl_",
            "wget_",
            "http_",
            "ftp_",
            # Database libraries
            "sqlite3_",
            "mysql_",
            "pg_",
            "PQexec",
            # Compression libraries
            "zlib_",
            "gzip_",
            "deflate_",
            "inflate_",
        ]

        content_lower = content.lower()
        return any(content_lower.startswith(prefix.lower()) for prefix in library_prefixes)

    def _analyze_api_naming_conventions(self, content: str) -> bool:
        """Analyze naming conventions typical of API functions."""
        # Length check - API functions are usually 4-40 characters
        if len(content) < 4 or len(content) > 40:
            return False

        # Check for valid identifier pattern
        if not re.match(r"^[A-Za-z_][A-Za-z0-9_]*$", content):
            return False

        # API functions typically have:
        # 1. Mixed case (CamelCase or snake_case)
        # 2. Descriptive verbs
        # 3. Reasonable character distribution

        has_upper = any(c.isupper() for c in content)
        has_lower = any(c.islower() for c in content)
        has_underscore = "_" in content

        # CamelCase pattern
        if has_upper and has_lower and not has_underscore:
            # Check for verb-noun pattern typical of APIs
            api_verbs = [
                "get",
                "set",
                "create",
                "delete",
                "open",
                "close",
                "read",
                "write",
                "load",
                "save",
                "init",
                "destroy",
                "start",
                "stop",
                "send",
                "recv",
                "alloc",
                "free",
                "lock",
                "unlock",
                "wait",
                "signal",
                "query",
                "find",
            ]

            content_lower = content.lower()
            if any(content_lower.startswith(verb) for verb in api_verbs):
                return True

        # snake_case pattern
        if has_underscore and not has_upper:
            parts = content.split("_")
            if len(parts) >= 2 and all(part.isalpha() for part in parts if part):
                # Check if first part is a common API verb
                api_verbs = [
                    "get",
                    "set",
                    "create",
                    "delete",
                    "open",
                    "close",
                    "read",
                    "write",
                    "load",
                    "save",
                    "init",
                    "destroy",
                    "start",
                    "stop",
                    "alloc",
                    "free",
                ]
                return parts[0] in api_verbs

        return False

    def _is_url_string(self, content: str) -> bool:
        """Check if string is a URL or network endpoint."""
        url_patterns = [
            r"https?://\S+",
            r"ftp://\S+",
            r"file://\S+",
            r"\b\w+\.\w+\.\w+\b",  # Domain names
            r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b",  # IP addresses
            r":\d{1,5}$",  # Port numbers
            r"\.com|\.org|\.net|\.gov|\.edu|\.mil",
        ]

        return any(re.search(pattern, content, re.IGNORECASE) for pattern in url_patterns)

    def _is_file_path_string(self, content: str) -> bool:
        """Check if string is a file path."""
        path_patterns = [
            r"^[A-Z]:\\",  # Windows absolute path
            r"^\\\\",  # UNC path
            r"^/",  # Unix absolute path
            r"\.\w{1,4}$",  # File extension
            r"\\[^\\]+\\",  # Windows path separators
            r"/[^/]+/",  # Unix path separators
            r"\.(exe|dll|sys|bat|cmd|ini|cfg|log|txt|xml|json)$",
        ]

        return any(re.search(pattern, content, re.IGNORECASE) for pattern in path_patterns)

    def _is_registry_string(self, content: str) -> bool:
        """Check if string is a Windows registry key."""
        registry_patterns = [
            r"^HKEY_",
            r"^HKLM\\",
            r"^HKCU\\",
            r"^HKCR\\",
            r"^HKCC\\",
            r"\\SOFTWARE\\",
            r"\\SYSTEM\\",
            r"\\Microsoft\\",
            r"\\Windows\\",
            r"\\CurrentVersion\\",
        ]

        return any(re.search(pattern, content, re.IGNORECASE) for pattern in registry_patterns)

    def _is_error_message_string(self, content: str) -> bool:
        """Check if string is an error message."""
        error_patterns = [
            r"\berror\b",
            r"\bfail\w*\b",
            r"\bexception\b",
            r"\binvalid\b",
            r"\bcannot\b",
            r"\bunable\b",
            r"\bdenied\b",
            r"\bunauthorized\b",
            r"\bcorrupt\w*\b",
            r"\bmissing\b",
            r"\bnot found\b",
            r"\baccess\b.*\bdenied\b",
        ]

        return any(re.search(pattern, content, re.IGNORECASE) for pattern in error_patterns)

    def _is_version_string(self, content: str) -> bool:
        """Check if string contains version information."""
        version_patterns = [
            r"\bv?\d+\.\d+(\.\d+)*\b",
            r"\bversion\b.*\d+",
            r"\bbuild\b.*\d+",
            r"\bcopyright\b",
            r"\b(c)\b.*\d{4}",
            r"\ball rights reserved\b",
        ]

        return any(re.search(pattern, content, re.IGNORECASE) for pattern in version_patterns)

    def _is_compiler_string(self, content: str) -> bool:
        """Check if string is compiler-related."""
        compiler_patterns = [
            r"\b(gcc|clang|msvc|mingw|borland)\b",
            r"\b(microsoft|visual|studio)\b.*\bc\+\+\b",
            r"\b__\w+__\b",  # Compiler macros
            r"\bcompiled with\b",
            r"\b\.pdb$",
            r"\b\.obj$",
            r"\b\.lib$",
        ]

        return any(re.search(pattern, content, re.IGNORECASE) for pattern in compiler_patterns)

    def _is_debug_string(self, content: str) -> bool:
        """Check if string is debug-related."""
        debug_patterns = [
            r"\bdebug\b",
            r"\btrace\b",
            r"\bverbose\b",
            r"\blog\b.*\b(level|file)\b",
            r"\bassert\b",
            r"^\s*//.*",  # Comments
            r"^\s*\*.*",  # Block comments
            r"\b__FILE__\b",
            r"\b__LINE__\b",
            r"\b__FUNCTION__\b",
        ]

        return any(re.search(pattern, content, re.IGNORECASE) for pattern in debug_patterns)

    def _is_ui_string(self, content: str) -> bool:
        """Check if string is user interface related."""
        ui_patterns = [
            r"\b(ok|cancel|yes|no|apply|close|exit)\b",
            r"\b(button|dialog|window|menu|tab)\b",
            r"\b(click|press|select|choose)\b",
            r"\bmessage\b.*\bbox\b",
            r"\balert\b",
            r"\bwarning\b",
            r"\bconfirm\b",
            r"&\w+",  # Mnemonics
            r"\.\.\.$",  # Ellipsis
        ]

        return any(re.search(pattern, content, re.IGNORECASE) for pattern in ui_patterns)

    def _is_network_string(self, content: str) -> bool:
        """Check if string is network-related."""
        network_patterns = [
            r"\b(tcp|udp|http|https|ftp|smtp|pop3|imap)\b",
            r"\b(socket|connect|bind|listen|accept)\b",
            r"\b(send|recv|get|post|put|delete)\b",
            r"\bport\b.*\d+",
            r"\bhost\b.*\bname\b",
            r"\bproxy\b",
            r"\bgateway\b",
            r"\bfirewall\b",
        ]

        return any(re.search(pattern, content, re.IGNORECASE) for pattern in network_patterns)

    def _get_string_cross_references(
        self, r2: R2Session, strings: list[dict[str, Any]]
    ) -> dict[str, list[dict[str, Any]]]:
        """Get cross-references for important strings."""
        xrefs = {}

        # Focus on license and crypto strings for cross-reference analysis
        important_strings = [
            s
            for s in strings
            if self._is_license_string(s.get("content", ""))
            or self._is_crypto_string(s.get("content", ""))
        ]

        for string_data in important_strings[:20]:  # Limit to avoid performance issues
            if addr := string_data.get("address", 0):
                try:
                    # Get cross-references to this string
                    xref_data = r2._execute_command(f"axtj @ {hex(addr)}", expect_json=True)
                    if isinstance(xref_data, list) and xref_data:
                        xrefs[hex(addr)] = {
                            "string_content": string_data.get("content", ""),
                            "references": xref_data,
                        }
                except R2Exception as e:
                    self.logger.error("R2Exception in radare2_strings: %s", e)
                    continue

        return xrefs

    def _analyze_string_entropy(self, strings: list[dict[str, Any]]) -> dict[str, Any]:
        """Analyze string entropy for encoded/encrypted content detection."""
        entropy_analysis = {
            "high_entropy_strings": [],
            "low_entropy_strings": [],
            "average_entropy": 0,
            "entropy_distribution": {"0-1": 0, "1-2": 0, "2-3": 0, "3-4": 0, "4+": 0},
        }

        total_entropy = 0
        for string_data in strings:
            entropy = string_data.get("entropy", 0)
            total_entropy += entropy

            # Categorize by entropy
            if entropy > 3.5:
                entropy_analysis["high_entropy_strings"].append(string_data)
                entropy_analysis["entropy_distribution"]["4+"] += 1
            elif entropy > 2.5:
                entropy_analysis["entropy_distribution"]["3-4"] += 1
            elif entropy > 1.5:
                entropy_analysis["entropy_distribution"]["2-3"] += 1
            elif entropy > 0.5:
                entropy_analysis["entropy_distribution"]["1-2"] += 1
            else:
                entropy_analysis["low_entropy_strings"].append(string_data)
                entropy_analysis["entropy_distribution"]["0-1"] += 1

        if strings:
            entropy_analysis["average_entropy"] = total_entropy / len(strings)

        return entropy_analysis

    def _detect_suspicious_patterns(self, strings: list[dict[str, Any]]) -> list[dict[str, Any]]:
        """Detect suspicious string patterns."""
        suspicious = []

        for string_data in strings:
            content = string_data.get("content", "")

            # Base64-like patterns
            if re.match(r"^[A-Za-z0-9+/]{20,}={0,2}$", content):
                suspicious.append(
                    {
                        "string": string_data,
                        "pattern_type": "base64_like",
                        "description": "Possible Base64 encoded data",
                    },
                )

            # Hex-like patterns
            if re.match(r"^[0-9A-Fa-f]{32,}$", content):
                suspicious.append(
                    {
                        "string": string_data,
                        "pattern_type": "hex_data",
                        "description": "Long hexadecimal string (possible hash/key)",
                    },
                )

            # High entropy short strings (possible keys)
            if string_data.get("entropy", 0) > 3.8 and len(content) < 50:
                suspicious.append(
                    {
                        "string": string_data,
                        "pattern_type": "high_entropy",
                        "description": "High entropy string (possible encrypted data/key)",
                    },
                )

            # Suspicious license keywords
            if any(
                keyword in content.lower() for keyword in ["crack", "keygen", "serial", "patch"]
            ):
                suspicious.append(
                    {
                        "string": string_data,
                        "pattern_type": "crack_related",
                        "description": "Contains crack/keygen related keywords",
                    },
                )

        return suspicious

    def _calculate_entropy(self, text: str) -> float:
        """Calculate Shannon entropy of a string."""
        if not text:
            return 0

        # Count character frequencies
        freq = {}
        for char in text:
            freq[char] = freq.get(char, 0) + 1

        # Calculate entropy
        entropy = 0
        text_len = len(text)
        for count in freq.values():
            p = count / text_len
            if p > 0:
                entropy -= p * (p.bit_length() - 1)

        return entropy

    def _generate_category_statistics(self, result: dict[str, Any]) -> dict[str, Any]:
        """Generate statistics for categorized strings."""
        stats = {}

        categories = [
            "license_strings",
            "crypto_strings",
            "api_strings",
            "url_strings",
            "file_path_strings",
            "registry_strings",
            "error_message_strings",
            "version_strings",
            "compiler_strings",
            "debug_strings",
            "user_interface_strings",
            "network_strings",
        ]

        for category in categories:
            category_strings = result.get(category, [])
            stats[category] = {
                "count": len(category_strings),
                "percentage": (len(category_strings) / max(1, result.get("total_strings", 1)))
                * 100,
                "average_length": sum(len(s.get("content", "")) for s in category_strings)
                / max(1, len(category_strings)),
            }

        return stats

    def search_license_validation_strings(self) -> dict[str, Any]:
        """Specialized search for license validation related strings."""
        try:
            with r2_session(self.binary_path, self.radare2_path) as r2:
                validation_strings = []

                # Search for specific license validation patterns
                license_search_terms = [
                    "license",
                    "registration",
                    "activation",
                    "serial",
                    "key",
                    "trial",
                    "demo",
                    "expire",
                    "valid",
                    "authentic",
                    "genuine",
                    "pirat",
                    "crack",
                    "illegal",
                    "stolen",
                    "tamper",
                ]

                for term in license_search_terms:
                    try:
                        # Use radare2's search functionality
                        search_results = r2._execute_command(f"/j {term}", expect_json=True)
                        if isinstance(search_results, list):
                            for result in search_results:
                                if addr := result.get("offset", 0):
                                    try:
                                        string_content = r2._execute_command(f"ps @ {hex(addr)}")
                                        if (
                                            string_content
                                            and term.lower() in string_content.lower()
                                        ):
                                            validation_strings.append(
                                                {
                                                    "content": string_content.strip(),
                                                    "address": hex(addr),
                                                    "search_term": term,
                                                    "context": "license_validation",
                                                },
                                            )
                                    except R2Exception as e:
                                        logger.error("R2Exception in radare2_strings: %s", e)
                                        continue
                    except R2Exception as e:
                        logger.error("R2Exception in radare2_strings: %s", e)
                        continue

                return {
                    "validation_strings": validation_strings,
                    "total_found": len(validation_strings),
                    "search_terms_used": license_search_terms,
                }

        except R2Exception as e:
            logger.error("R2Exception in radare2_strings: %s", e)
            return {"error": str(e)}


def analyze_binary_strings(
    binary_path: str, radare2_path: str | None = None, min_length: int = 4
) -> dict[str, Any]:
    """Perform comprehensive string analysis on a binary.

    Args:
        binary_path: Path to binary file
        radare2_path: Optional path to radare2 executable
        min_length: Minimum string length to analyze

    Returns:
        Complete string analysis results

    """
    analyzer = R2StringAnalyzer(binary_path, radare2_path)
    return analyzer.analyze_all_strings(min_length=min_length)


__all__ = ["R2StringAnalyzer", "analyze_binary_strings"]

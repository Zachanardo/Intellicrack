"""Radare2 string analysis module for extracting and analyzing string data."""

import logging
import re
from typing import Any

from intellicrack.logger import logger

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

    def __init__(self, binary_path: str, radare2_path: str | None = None):
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
                result.update(categories)

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
            if encoding == "auto" or encoding == "utf16":
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
                normalized = self._normalize_string_data(string_data)
                if normalized:
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
        }

        # Calculate additional metrics
        normalized["entropy"] = self._calculate_entropy(content)
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
        for section_name, section_data in sections.items():
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
        """Check if string is license-related."""
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

        return any(re.search(pattern, content, re.IGNORECASE) for pattern in license_patterns)

    def _is_crypto_string(self, content: str) -> bool:
        """Check if string is cryptography-related."""
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

        return any(re.search(pattern, content, re.IGNORECASE) for pattern in crypto_patterns)

    def _is_api_string(self, content: str) -> bool:
        """Check if string is an API function name."""
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

        # Check length (API names are typically not too long)
        if len(content) > 50:
            return False

        return any(re.match(pattern, content) for pattern in api_patterns)

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
            addr = string_data.get("address", 0)
            if addr:
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
                    }
                )

            # Hex-like patterns
            if re.match(r"^[0-9A-Fa-f]{32,}$", content):
                suspicious.append(
                    {
                        "string": string_data,
                        "pattern_type": "hex_data",
                        "description": "Long hexadecimal string (possible hash/key)",
                    }
                )

            # High entropy short strings (possible keys)
            if string_data.get("entropy", 0) > 3.8 and len(content) < 50:
                suspicious.append(
                    {
                        "string": string_data,
                        "pattern_type": "high_entropy",
                        "description": "High entropy string (possible encrypted data/key)",
                    }
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
                    }
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
                                # Get string at found address
                                addr = result.get("offset", 0)
                                if addr:
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
                                                }
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

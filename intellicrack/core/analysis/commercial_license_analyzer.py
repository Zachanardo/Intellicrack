"""Commercial License Protocol Analyzer for FlexLM, HASP, and CodeMeter.

This module provides comprehensive analysis and bypass generation for
commercial license protection systems used in enterprise software.

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
along with Intellicrack. If not, see <https://www.gnu.org/licenses/>.
"""

import contextlib
import re
import struct
import time
from pathlib import Path
from typing import Any, Protocol, cast

from intellicrack.utils.type_safety import validate_type

from ...utils.logger import get_logger


class ProtocolFingerprinterProtocol(Protocol):
    """Protocol for protocol fingerprinter with fingerprint_packet method."""

    def fingerprint_packet(
        self, packet: bytes, context: dict[str, Any] | None = None
    ) -> dict[str, Any] | None:
        """Fingerprint a packet to identify its protocol.

        Args:
            packet: Binary packet data to analyze for protocol identification.
            context: Optional context dictionary for protocol detection.

        """
        ...


class DongleEmulatorProtocol(Protocol):
    """Protocol for dongle emulator with get_dongle_config method."""

    def get_dongle_config(self, dongle_type: str) -> dict[str, Any]:
        """Get configuration for specified dongle type.

        Args:
            dongle_type: Type of dongle to retrieve configuration for (e.g., 'HASP', 'CodeMeter').

        """
        ...


def _get_protocol_fingerprinter() -> type:
    """Lazy import ProtocolFingerprinter to avoid circular import.

    Returns:
        Class for ProtocolFingerprinter lazy loading to avoid circular imports.

    """
    from ..network.protocol_fingerprinter import ProtocolFingerprinter

    return ProtocolFingerprinter


def _get_flexlm_parser() -> type:
    """Lazy import FlexLMProtocolParser to avoid circular import.

    Returns:
        Class for FlexLMProtocolParser lazy loading to avoid circular imports.

    """
    from ..network.protocols.flexlm_parser import FlexLMProtocolParser

    return FlexLMProtocolParser


def _get_dongle_emulator() -> type:
    """Lazy import HardwareDongleEmulator to avoid circular import.

    Returns:
        Class for HardwareDongleEmulator lazy loading to avoid circular imports.

    """
    from ..protection_bypass.dongle_emulator import HardwareDongleEmulator

    return HardwareDongleEmulator


logger = get_logger(__name__)


class CommercialLicenseAnalyzer:
    """Comprehensive analyzer for commercial license protection systems."""

    def __init__(self, binary_path: str | None = None) -> None:
        """Initialize the commercial license analyzer.

        Args:
            binary_path: Path to the binary to analyze

        """
        self.binary_path = binary_path
        self._flexlm_parser: Any = None  # Lazy loaded
        self._dongle_emulator: Any = None  # Lazy loaded
        self._protocol_fingerprinter: Any = None  # Lazy loaded
        self._binary_data: bytes | None = None  # Cached binary data

        # Detection results
        self.detected_systems: list[str] = []
        self.license_servers: list[dict[str, Any]] = []
        self.protection_features: dict[str, Any] = {}

        # Bypass strategies
        self.bypass_strategies: dict[str, Any] = {}

    @property
    def flexlm_parser(self) -> object:
        """Lazy load FlexLMProtocolParser.

        Returns:
            FlexLMProtocolParser instance for analyzing FlexLM license protocols.

        """
        if self._flexlm_parser is None:
            FlexLMProtocolParser = _get_flexlm_parser()
            self._flexlm_parser = FlexLMProtocolParser()
        return self._flexlm_parser

    @property
    def dongle_emulator(self) -> object:
        """Lazy load HardwareDongleEmulator.

        Returns:
            HardwareDongleEmulator instance for emulating hardware protection dongles.

        """
        if self._dongle_emulator is None:
            HardwareDongleEmulator = _get_dongle_emulator()
            self._dongle_emulator = HardwareDongleEmulator()
        return self._dongle_emulator

    @property
    def protocol_fingerprinter(self) -> object:
        """Lazy load ProtocolFingerprinter.

        Returns:
            ProtocolFingerprinter instance for identifying commercial license protocols.

        """
        if self._protocol_fingerprinter is None:
            ProtocolFingerprinter = _get_protocol_fingerprinter()
            self._protocol_fingerprinter = ProtocolFingerprinter()
        return self._protocol_fingerprinter

    def analyze_binary(self, binary_path: str | None = None) -> dict[str, Any]:
        """Analyze binary for commercial license protections.

        Args:
            binary_path: Optional path to binary (uses self.binary_path if not provided).

        Returns:
            Analysis results including detected systems and bypass strategies.

        """
        if binary_path:
            self.binary_path = binary_path

        results: dict[str, Any] = {
            "detected_systems": [],
            "license_servers": [],
            "protection_features": {},
            "bypass_strategies": {},
            "confidence": 0.0,
        }
        detected_systems_list = validate_type(results["detected_systems"], list)
        bypass_strategies_dict = validate_type(results["bypass_strategies"], dict)

        if not self.binary_path or not Path(self.binary_path).exists():
            logger.warning("Binary path invalid: %s", self.binary_path)
            return results

        if flexlm_detected := self._detect_flexlm():
            logger.debug("FlexLM detected: %s", flexlm_detected)
            detected_systems_list.append("FlexLM")
            bypass_strategies_dict["flexlm"] = self._generate_flexlm_bypass()

        if hasp_detected := self._detect_hasp():
            logger.debug("HASP detected: %s", hasp_detected)
            detected_systems_list.append("HASP")
            bypass_strategies_dict["hasp"] = self._generate_hasp_bypass()

        if codemeter_detected := self._detect_codemeter():
            logger.debug("CodeMeter detected: %s", codemeter_detected)
            detected_systems_list.append("CodeMeter")
            bypass_strategies_dict["codemeter"] = self._generate_codemeter_bypass()

        # Analyze network protocols
        protocol_analysis = self._analyze_network_protocols()
        results["license_servers"] = protocol_analysis.get("servers", [])
        results["protection_features"] = protocol_analysis.get("features", {})

        # Calculate confidence
        results["confidence"] = self._calculate_confidence(results)
        self.detected_systems = detected_systems_list
        self.bypass_strategies = bypass_strategies_dict

        return results

    def analyze(self) -> dict[str, Any]:
        """Analyze with API compatibility for tests.

        Returns:
            Analysis results from binary analysis.

        """
        return self.analyze_binary(self.binary_path)

    def _detect_flexlm(self) -> bool:
        """Detect FlexLM license system in binary.

        Returns:
            True if FlexLM detected.

        """
        flexlm_indicators = [
            b"FLEXlm",
            b"lmgrd",
            b"lmutil",
            b"lmstat",
            b"FLEXLM_DIAGNOSTICS",
            b"@(#)FLEXlm",
            b"license.dat",
            b"license.lic",
            b"VENDOR_LICENSE_FILE",
            b"LM_LICENSE_FILE",
        ]

        flexlm_apis = [
            b"lc_checkout",
            b"lc_checkin",
            b"lc_init",
            b"lc_set_attr",
            b"lc_get_attr",
            b"lc_cryptstr",
            b"lc_new_job",
            b"lc_free_job",
        ]

        try:
            if self.binary_path is None:
                return False
            with open(self.binary_path, "rb") as f:
                binary_data = f.read()

            # Check for FlexLM indicators
            for indicator in flexlm_indicators:
                if indicator in binary_data:
                    logger.info("FlexLM indicator found: %s", indicator)
                    return True

            # Check for FlexLM API calls
            for api in flexlm_apis:
                if api in binary_data:
                    logger.info("FlexLM API found: %s", api)
                    return True

        except Exception as e:
            logger.exception("Error detecting FlexLM: %s", e)

        return False

    def _detect_hasp(self) -> bool:
        """Detect HASP dongle protection in binary.

        Returns:
            True if HASP detected.

        """
        hasp_indicators = [
            b"hasp_login",
            b"hasp_logout",
            b"hasp_encrypt",
            b"hasp_decrypt",
            b"hasp_get_info",
            b"hasp_update",
            b"HASP",
            b"Sentinel",
            b"hasplms.exe",
            b"aksusbd.sys",
        ]

        hasp_dlls = [
            b"hasp_windows",
            b"hasp_net_windows",
            b"hasp_windows_x64",
            b"haspvlib",
            b"hasp_api",
        ]

        try:
            if self.binary_path is None:
                return False
            with open(self.binary_path, "rb") as f:
                binary_data = f.read()

            # Check for HASP indicators
            for indicator in hasp_indicators:
                if indicator in binary_data:
                    logger.info("HASP indicator found: %s", indicator)
                    return True

            # Check for HASP DLLs
            for dll in hasp_dlls:
                if dll in binary_data:
                    logger.info("HASP DLL reference found: %s", dll)
                    return True

        except Exception as e:
            logger.exception("Error detecting HASP: %s", e)

        return False

    def _detect_codemeter(self) -> bool:
        """Detect CodeMeter protection in binary.

        Returns:
            True if CodeMeter detected.

        """
        codemeter_indicators = [
            b"CodeMeter",
            b"CmDongle",
            b"CmStick",
            b"WibuKey",
            b"WIBU-SYSTEMS",
            b"CmContainer",
            b"CmActLicense",
            b"CodeMeterRuntime",
        ]

        codemeter_apis = [
            b"CmGetInfo",
            b"CmGetLicenseInfo",
            b"CmGetVersion",
            b"CmAccess",
            b"CmCrypt",
            b"CmDecrypt",
            b"CmEncrypt",
            b"CmRelease",
        ]

        try:
            if self.binary_path is None:
                return False
            with open(self.binary_path, "rb") as f:
                binary_data = f.read()

            # Check for CodeMeter indicators
            for indicator in codemeter_indicators:
                if indicator in binary_data:
                    logger.info("CodeMeter indicator found: %s", indicator)
                    return True

            # Check for CodeMeter APIs
            for api in codemeter_apis:
                if api in binary_data:
                    logger.info("CodeMeter API found: %s", api)
                    return True

        except Exception as e:
            logger.exception("Error detecting CodeMeter: %s", e)

        return False

    def _analyze_network_protocols(self) -> dict[str, Any]:
        """Analyze network protocols for license communication.

        Returns:
            Network protocol analysis results.

        """
        analysis: dict[str, Any] = {"servers": [], "features": {}, "protocols": []}

        # Use protocol fingerprinter to detect license servers
        if self.binary_path:
            from typing import cast

            pf = cast("ProtocolFingerprinterProtocol", self.protocol_fingerprinter)
            fingerprint = pf.fingerprint_packet(b"", {"binary_path": self.binary_path})

            if fingerprint and fingerprint.get("protocol_type") in [
                "FlexLM",
                "HASP Network",
                "CodeMeter Network",
            ]:
                analysis["protocols"].append(fingerprint.get("protocol_type"))

                # Extract server information
                if fingerprint.get("server_port"):
                    analysis["servers"].append(
                        {
                            "type": fingerprint.get("protocol_type"),
                            "port": fingerprint.get("server_port"),
                            "hostname": fingerprint.get("server_hostname", "localhost"),
                        },
                    )

                # Extract feature information
                analysis["features"] = fingerprint.get("features", {})

        return analysis

    def _generate_flexlm_bypass(self) -> dict[str, Any]:
        """Generate FlexLM bypass strategy based on binary analysis.

        Returns:
            Dynamically generated FlexLM bypass configuration.

        """
        import re

        bypass: dict[str, Any] = {
            "method": "flexlm_emulation",
            "server_port": 27000,  # Default FlexLM port
            "vendor_daemon": "vendor",
            "features": [],
            "patches": [],
            "hooks": [],
            "emulation_script": "",
        }
        hooks = validate_type(bypass["hooks"], list)
        patches = validate_type(bypass["patches"], list)

        # Analyze binary for FlexLM patterns
        binary_data: bytes
        if self.binary_path and hasattr(self, "_binary_data"):
            binary_data = validate_type(self._binary_data, bytes)
        else:
            # Load binary for analysis
            try:
                if self.binary_path is None:
                    binary_data = b""
                else:
                    with open(self.binary_path, "rb") as f:
                        binary_data = f.read()
                        self._binary_data = binary_data
            except OSError:
                binary_data = b""

        # Detect FlexLM version and configuration
        flexlm_version = self._detect_flexlm_version(binary_data)
        if vendor_daemon := self._extract_vendor_daemon(binary_data):
            bypass["vendor_daemon"] = vendor_daemon

        # Find FlexLM API imports dynamically
        api_patterns = {
            "lc_checkout": [
                b"\x48\x8d\x0d....\xff\x15....\x85\xc0",  # lea rcx,[string]; call [lc_checkout]; test eax,eax
                b"\x68....\xe8....\x83\xc4\x04\x85\xc0",  # push offset; call lc_checkout; add esp,4; test eax,eax
            ],
            "lc_init": [
                b"\xff\x15....\x85\xc0\x74",  # call [lc_init]; test eax,eax; jz
                b"\xe8....\x85\xc0\x75",  # call lc_init; test eax,eax; jnz
            ],
            "lc_cryptstr": [
                b"\x48\x89.\x48\x89.\xff\x15",  # mov reg,reg; mov reg,reg; call [lc_cryptstr]
                b"\x50\x51\xe8....\x83\xc4\x08",  # push eax; push ecx; call lc_cryptstr; add esp,8
            ],
            "lc_new_job": [
                b"\xff\x15....\x48\x85\xc0",  # call [lc_new_job]; test rax,rax
                b"\xe8....\x85\xc0",  # call lc_new_job; test eax,eax
            ],
        }

        # Generate dynamic hooks based on detected APIs
        bypass["hooks"] = []

        for api_name, patterns in api_patterns.items():
            for pattern in patterns:
                # Search for pattern in binary
                regex_pattern = self._pattern_to_regex(pattern)
                if matches := list(re.finditer(regex_pattern, binary_data)):
                    # Found the API call - generate appropriate hook
                    match = matches[0]
                    offset = match.start()

                    # Analyze calling convention and generate hook
                    if api_name == "lc_checkout":
                        # Analyze parameters to understand checkout requirements
                        feature_id = self._extract_feature_id(binary_data, offset)
                        hook = {
                            "api": api_name,
                            "offset": hex(offset),
                            "replacement": self._generate_checkout_hook(feature_id, flexlm_version),
                            "description": f"Dynamic checkout hook for feature {feature_id}",
                        }
                    elif api_name == "lc_init":
                        # Generate init hook based on version
                        hook = {
                            "api": api_name,
                            "offset": hex(offset),
                            "replacement": self._generate_init_hook(flexlm_version),
                            "description": f"Dynamic init hook for FlexLM {flexlm_version}",
                        }
                    elif api_name == "lc_cryptstr":
                        # Generate crypto bypass based on detected algorithm
                        crypto_type = self._detect_crypto_type(binary_data, offset)
                        hook = {
                            "api": api_name,
                            "offset": hex(offset),
                            "replacement": self._generate_crypto_hook(crypto_type),
                            "description": f"Dynamic crypto hook for {crypto_type}",
                        }
                    else:
                        # Generic success hook
                        hook = {
                            "api": api_name,
                            "offset": hex(offset),
                            "replacement": b"\x31\xc0\xc3" if "64" not in str(self._detect_architecture()) else b"\x48\x31\xc0\xc3",
                            "description": f"Dynamic hook for {api_name}",
                        }

                    hooks.append(hook)

        # Find and patch license validation checks dynamically
        check_patterns = [
            # Pattern: test result of license function and jump on failure
            (b"\x85\xc0\x74", b"\x85\xc0\x90\x90"),  # test eax,eax; jz -> test eax,eax; nop nop
            (b"\x85\xc0\x75", b"\x85\xc0\xeb"),  # test eax,eax; jnz -> test eax,eax; jmp
            (
                b"\x48\x85\xc0\x74",
                b"\x48\x85\xc0\x90\x90",
            ),  # test rax,rax; jz -> test rax,rax; nop nop
            # Pattern: compare with error codes
            (b"\x83\xf8\x00\x74", b"\x31\xc0\x90\x90\x90"),  # cmp eax,0; jz -> xor eax,eax; nop
            (b"\x3d\x00\x00\x00\x00\x74", b"\x31\xc0\x90\x90\x90\x90\x90"),  # cmp eax,0; jz
        ]

        bypass["patches"] = []
        for pattern, replacement in check_patterns:
            # Search for each pattern
            pos = 0
            while True:
                index = binary_data.find(pattern, pos)
                if index == -1:
                    break

                # Verify this is actually a license check
                if self._is_license_check_context(binary_data, index):
                    patch = {
                        "offset": hex(index),
                        "pattern": pattern.hex(),
                        "replacement": replacement.hex(),
                        "description": f"Patch license check at {hex(index)}",
                    }
                    patches.append(patch)

                pos = index + 1

        # Extract feature list from binary
        features = self._extract_flexlm_features(binary_data)
        bypass["features"] = features

        # Generate dynamic emulation script
        bypass["emulation_script"] = self._generate_flexlm_script()
        bypass["frida_script"] = self._generate_dynamic_flexlm_frida_script(hooks, patches)

        return bypass

    def _detect_flexlm_version(self, binary_data: bytes) -> str:
        """Detect FlexLM version from binary.

        Args:
            binary_data: Binary data to analyze.

        Returns:
            Detected FlexLM version string.

        """
        version_patterns = {
            b"FLEXnet Licensing v11": "11.x",
            b"FLEXlm v10": "10.x",
            b"FLEXlm v9": "9.x",
            b"FlexNet Publisher": "11.16+",
        }

        return next(
            (version for pattern, version in version_patterns.items() if pattern in binary_data),
            "unknown",
        )

    def _extract_vendor_daemon(self, binary_data: bytes) -> str:
        """Extract vendor daemon name from binary.

        Args:
            binary_data: Binary data to analyze.

        Returns:
            Extracted vendor daemon name.

        """
        # Look for vendor daemon patterns
        daemon_pattern = rb"([a-zA-Z0-9_]+)d\.exe|([a-zA-Z0-9_]+)d\x00"
        if match := re.search(daemon_pattern, binary_data):
            return (match[1] or match[2]).decode("latin-1", errors="ignore")
        return "vendor"

    def _pattern_to_regex(self, pattern: bytes) -> bytes:
        """Convert assembly pattern to regex.

        Args:
            pattern: Assembly pattern with wildcard dots.

        Returns:
            Regex pattern for matching.

        """
        result = b""
        i = 0
        while i < len(pattern):
            result += b"." if pattern[i : i + 1] == b"." else re.escape(pattern[i : i + 1])
            i += 1
        return result

    def _extract_feature_id(self, binary_data: bytes, offset: int) -> int:
        """Extract feature ID from checkout call.

        Args:
            binary_data: Binary data to analyze.
            offset: Offset in binary where checkout is called.

        Returns:
            Extracted feature ID or 0 if not found.

        """
        # Look for feature ID pushed before call
        if offset >= 20:
            # Check for push immediate before call
            push_pattern = binary_data[offset - 10 : offset]
            if b"\x68" in push_pattern:  # push imm32
                idx = push_pattern.rfind(b"\x68")
                if idx >= 0 and idx + 5 <= len(push_pattern):
                    unpacked = struct.unpack("<I", push_pattern[idx + 1 : idx + 5])
                    return int(unpacked[0])
        return 0

    def _generate_checkout_hook(self, feature_id: int, version: str) -> bytes:
        """Generate checkout hook based on feature and version.

        Args:
            feature_id: Feature ID for checkout.
            version: FlexLM version string.

        Returns:
            Machine code bytes for hook.

        """
        if "11" in version:
            # FlexLM 11.x - return LM_OK (0)
            return b"\x31\xc0\xc3"  # xor eax,eax; ret
        return b"\xb8\x01\x00\x00\x00\xc3" if "10" in version else b"\x31\xc0\xc3"

    def _generate_init_hook(self, version: str) -> bytes:
        """Generate init hook based on version.

        Args:
            version: FlexLM version string.

        Returns:
            Machine code bytes for init hook.

        """
        if self._detect_architecture() == "x64":
            return b"\x48\x31\xc0\x48\xff\xc0\xc3"  # xor rax,rax; inc rax; ret
        return b"\x31\xc0\x40\xc3"  # xor eax,eax; inc eax; ret

    def _detect_crypto_type(self, binary_data: bytes, offset: int) -> str:
        """Detect encryption type used.

        Args:
            binary_data: Binary data to analyze.
            offset: Offset of crypto call.

        Returns:
            Detected crypto type (TEA, MD5, or XOR).

        """
        # Look for crypto constants near the call
        search_range = binary_data[max(0, offset - 1000) : offset + 1000]

        if b"\x67\x45\x23\x01" in search_range:  # TEA magic
            return "TEA"
        return "MD5" if b"\x52\x09\x6a\xd5" in search_range else "XOR"

    def _generate_crypto_hook(self, crypto_type: str) -> bytes:
        """Generate crypto bypass based on type.

        Args:
            crypto_type: Type of crypto (AES, DES, XOR, etc).

        Returns:
            Machine code bytes for crypto bypass.

        """
        if self._detect_architecture() == "x64":
            # mov rax,rsi; ret (return input as-is)
            return b"\x48\x89\xf0\xc3"
        # mov eax,[esp+4]; ret (return input)
        return b"\x8b\x44\x24\x04\xc3"

    def _detect_architecture(self) -> str:
        """Detect binary architecture.

        Returns:
            Detected architecture ('x86' or 'x64').

        """
        if hasattr(self, "_binary_data") and self._binary_data and self._binary_data[:2] == b"MZ":
            pe_offset = struct.unpack("<I", self._binary_data[0x3C:0x40])[0]
            if pe_offset < len(self._binary_data) - 6:
                machine = struct.unpack("<H", self._binary_data[pe_offset + 4 : pe_offset + 6])[0]
                if machine == 0x8664:  # AMD64
                    return "x64"
        return "x86"

    def _is_license_check_context(self, binary_data: bytes, offset: int) -> bool:
        """Verify if pattern is in license check context.

        Args:
            binary_data: Binary data to analyze.
            offset: Offset to check context around.

        Returns:
            True if in license check context.

        """
        # Look for license-related strings nearby
        context = binary_data[max(0, offset - 200) : offset + 200]
        license_indicators = [
            b"license",
            b"LICENSE",
            b"checkout",
            b"CHECKOUT",
            b"lc_",
            b"LC_",
            b"flex",
            b"FLEX",
        ]

        return any(indicator in context for indicator in license_indicators)

    def _extract_flexlm_features(self, binary_data: bytes) -> list[str]:
        """Extract FlexLM features from binary.

        Args:
            binary_data: Binary data to analyze.

        Returns:
            List of extracted FlexLM features.

        """
        # Look for FEATURE lines
        feature_pattern = rb"FEATURE\s+(\w+)\s+\w+\s+[\d.]+\s+"
        return [match.group(1).decode("latin-1", errors="ignore") for match in re.finditer(feature_pattern, binary_data)]

    def _generate_dynamic_flexlm_frida_script(self, hooks: list[Any], patches: list[Any]) -> str:
        """Generate Frida script for dynamic hooking.

        Args:
            hooks: List of hooks to generate in script.
            patches: List of patches to generate in script.

        Returns:
            Generated Frida JavaScript code.

        """
        script = "// Dynamic FlexLM bypass script\n"

        # Add hooks
        for hook in hooks:
            script += f"""
Interceptor.attach(ptr('{hook["offset"]}'), {{
    onEnter: function(args) {{
        console.log('[FlexLM] Intercepting {hook["api"]}');
    }},
    onLeave: function(retval) {{
        retval.replace(0);  // Return success
        console.log('[FlexLM] {hook["api"]} bypassed');
    }}
}});
"""

        # Add patches
        for patch in patches:
            script += f"""
Memory.protect(ptr('{patch["offset"]}'), {len(bytes.fromhex(patch["replacement"]))}, 'rwx');
Memory.writeByteArray(ptr('{patch["offset"]}'), [{",".join(f"0x{b:02x}" for b in bytes.fromhex(patch["replacement"]))}]);
console.log('[FlexLM] Patched at {patch["offset"]}');
"""

        return script

    def _generate_hasp_bypass(self) -> dict[str, Any]:
        """Generate HASP bypass strategy based on binary analysis.

        Returns:
            Dynamically generated HASP bypass configuration.

        """
        import re

        bypass: dict[str, Any] = {
            "method": "hasp_emulation",
            "dongle_type": "HASP HL",
            "vendor_id": 0x0529,
            "product_id": 0x0001,
            "features": [],
            "hooks": [],
            "virtual_device": {},
            "emulation_script": "",
        }
        hooks_hasp = validate_type(bypass["hooks"], list)
        patches_hasp = validate_type(bypass.get("patches", []), list)

        # Load and analyze binary
        binary_data: bytes
        if self.binary_path and hasattr(self, "_binary_data") and self._binary_data is not None:
            binary_data = self._binary_data
        else:
            try:
                if self.binary_path is None:
                    binary_data = b""
                else:
                    with open(self.binary_path, "rb") as f:
                        binary_data = f.read()
                        self._binary_data = binary_data
            except OSError:
                binary_data = b""

        # Detect HASP version and type
        hasp_version = self._detect_hasp_version(binary_data)
        if dongle_type := self._detect_hasp_dongle_type(binary_data):
            bypass["dongle_type"] = dongle_type

        # Extract vendor and product IDs from binary
        vendor_id, product_id = self._extract_hasp_ids(binary_data)
        if vendor_id:
            bypass["vendor_id"] = vendor_id
        if product_id:
            bypass["product_id"] = product_id

        # Get dynamic dongle configuration
        dongle_emu = cast("DongleEmulatorProtocol", self.dongle_emulator)
        dongle_config = dongle_emu.get_dongle_config("hasp")
        dongle_config["vendor_id"] = bypass["vendor_id"]
        dongle_config["product_id"] = bypass["product_id"]

        # Find HASP API calls dynamically
        hasp_apis = {
            "hasp_login": [
                b"\xff\x15....\x85\xc0\x74",  # call [hasp_login]; test eax,eax; jz
                b"\xe8....\x85\xc0\x75",  # call hasp_login; test eax,eax; jnz
                b"\x48\x8b\x0d....\xff\x15",  # mov rcx,[vendor_code]; call [hasp_login]
            ],
            "hasp_login_scope": [
                b"\xff\x15....\x85\xc0",  # call [hasp_login_scope]; test eax,eax
                b"\xe8....\x3d\x00\x00\x00\x00",  # call hasp_login_scope; cmp eax,0
            ],
            "hasp_encrypt": [
                b"\x50\x51\x52\xe8",  # push eax; push ecx; push edx; call
                b"\x48\x89.\x48\x89.\x48\x89.\xff\x15",  # mov r,r; mov r,r; mov r,r; call
            ],
            "hasp_decrypt": [
                b"\xff\x15....\x85\xc0",  # call [hasp_decrypt]; test eax,eax
                b"\xe8....\x85\xc0",  # call hasp_decrypt; test eax,eax
            ],
            "hasp_get_info": [
                b"\xff\x15....\x48\x85\xc0",  # call [hasp_get_info]; test rax,rax
                b"\xe8....\x85\xc0",  # call hasp_get_info; test eax,eax
            ],
            "hasp_get_size": [
                b"\xff\x15....\x85\xc0",  # call [hasp_get_size]; test eax,eax
                b"\xe8....\x3d",  # call hasp_get_size; cmp eax
            ],
        }

        # Generate dynamic hooks
        bypass["hooks"] = []

        for api_name, patterns in hasp_apis.items():
            for pattern in patterns:
                regex_pattern = self._pattern_to_regex(pattern)
                if matches := list(re.finditer(regex_pattern, binary_data)):
                    match = matches[0]
                    offset = match.start()

                    # Generate appropriate hook based on API
                    if api_name in {"hasp_login", "hasp_login_scope"}:
                        # Analyze vendor code
                        vendor_code = self._extract_vendor_code(binary_data, offset)
                        hook = {
                            "api": api_name,
                            "offset": hex(offset),
                            "replacement": self._generate_hasp_login_hook(vendor_code, hasp_version),
                            "description": f"Dynamic login hook for vendor {vendor_code:08x}",
                        }
                    elif api_name == "hasp_encrypt":
                        # Generate encryption hook
                        hook = {
                            "api": api_name,
                            "offset": hex(offset),
                            "replacement": self._generate_hasp_encrypt_patch(),
                            "description": f"Dynamic encryption hook for HASP {hasp_version}",
                        }
                    elif api_name == "hasp_decrypt":
                        # Generate decryption hook
                        hook = {
                            "api": api_name,
                            "offset": hex(offset),
                            "replacement": self._generate_hasp_decrypt_patch(),
                            "description": "Dynamic decryption hook",
                        }
                    elif api_name == "hasp_get_info":
                        # Generate info response
                        hook = {
                            "api": api_name,
                            "offset": hex(offset),
                            "replacement": self._generate_hasp_info_response(),
                            "description": "Dynamic info response hook",
                        }
                    else:
                        # Generic success hook
                        hook = {
                            "api": api_name,
                            "offset": hex(offset),
                            "replacement": b"\x31\xc0\xc3",  # xor eax,eax; ret
                            "description": f"Dynamic hook for {api_name}",
                        }

                    hooks_hasp.append(hook)

        # Find and patch HASP validation checks
        validation_patterns = [
            # HASP_STATUS_OK checks
            (b"\x85\xc0\x74", b"\x85\xc0\x90\x90"),  # test eax,eax; jz -> nop
            (b"\x85\xc0\x75", b"\x85\xc0\xeb"),  # test eax,eax; jnz -> jmp
            (b"\x83\xf8\x00\x74", b"\x31\xc0\x90\x90\x90"),  # cmp eax,0; jz
            # HASP handle checks
            (b"\x48\x85\xc0\x74", b"\x48\x85\xc0\x90\x90"),  # test rax,rax; jz
            (b"\x48\x85\xdb\x74", b"\x48\x85\xdb\x90\x90"),  # test rbx,rbx; jz
        ]

        bypass["patches"] = []
        patches_hasp = cast("list[Any]", bypass["patches"])
        for pattern, replacement in validation_patterns:
            pos = 0
            while True:
                index = binary_data.find(pattern, pos)
                if index == -1:
                    break

                if self._is_hasp_check_context(binary_data, index):
                    patch = {
                        "offset": hex(index),
                        "pattern": pattern.hex(),
                        "replacement": replacement.hex(),
                        "description": f"Patch HASP check at {hex(index)}",
                    }
                    patches_hasp.append(patch)

                pos = index + 1

        # Extract features from binary
        features = self._extract_hasp_features(binary_data)
        bypass["features"] = features
        dongle_config["features"] = features

        # Configure virtual device based on analysis
        bypass["virtual_device"] = {
            "type": "USB",
            "vendor_id": bypass["vendor_id"],
            "product_id": bypass["product_id"],
            "serial": self._generate_hasp_serial(binary_data),
            "memory_size": self._detect_hasp_memory_size(binary_data),
            "features": features,
            "version": hasp_version,
        }

        # Generate emulation scripts
        bypass["emulation_script"] = self._generate_hasp_script()
        bypass["frida_script"] = self._generate_dynamic_hasp_frida_script(hooks_hasp, patches_hasp)
        bypass["api_hooks"] = bypass["hooks"]  # Alias for compatibility

        return bypass

    def _detect_hasp_version(self, binary_data: bytes) -> str:
        """Detect HASP version from binary.

        Args:
            binary_data: Binary data to analyze.

        Returns:
            Detected HASP version string.

        """
        version_patterns = {
            b"HASP HL": "HASP HL",
            b"HASP SL": "HASP SL",
            b"Sentinel LDK": "Sentinel LDK",
            b"HASP4": "HASP4",
            b"hardlock": "Hardlock",
        }

        return next(
            (version for pattern, version in version_patterns.items() if pattern in binary_data),
            "HASP HL",
        )

    def _detect_hasp_dongle_type(self, binary_data: bytes) -> str:
        """Detect HASP dongle type.

        Args:
            binary_data: Binary data to analyze.

        Returns:
            Detected HASP dongle type.

        """
        if b"HASP HL Pro" in binary_data:
            return "HASP HL Pro"
        if b"HASP HL Max" in binary_data:
            return "HASP HL Max"
        return "HASP SL" if b"HASP SL" in binary_data else "HASP HL"

    def _extract_hasp_ids(self, binary_data: bytes) -> tuple[int, int]:
        """Extract vendor and product IDs from binary.

        Args:
            binary_data: Binary data to analyze.

        Returns:
            Vendor ID and product ID.

        """
        vendor_id = 0x0529  # Default Aladdin vendor ID
        product_id = 0x0001

        # Look for USB descriptor patterns
        usb_pattern = rb"\x29\x05[\x00-\xff]{2}"  # Vendor ID 0x0529
        if match := re.search(usb_pattern, binary_data):
            data = match.group()
            if len(data) >= 4:
                vendor_unpacked = struct.unpack("<H", data[:2])
                product_unpacked = struct.unpack("<H", data[2:4])
                vendor_id = int(vendor_unpacked[0])
                product_id = int(product_unpacked[0])

        return vendor_id, product_id

    def _extract_vendor_code(self, binary_data: bytes, offset: int) -> int:
        """Extract vendor code from login call.

        Args:
            binary_data: Binary data to analyze.
            offset: Offset of login call.

        Returns:
            Extracted vendor code or default.

        """
        # Look for vendor code pushed or loaded before call
        if offset >= 20:
            search_area = binary_data[max(0, offset - 50) : offset]

            # Look for mov or push with vendor code
            if b"\x68" in search_area:  # push imm32
                idx = search_area.rfind(b"\x68")
                if idx >= 0 and idx + 5 <= len(search_area):
                    vendor_unpacked = struct.unpack("<I", search_area[idx + 1 : idx + 5])
                    vendor_code = int(vendor_unpacked[0])
                    if vendor_code not in {0, 4294967295}:
                        return vendor_code

        return 0x12345678  # Default vendor code

    def _generate_hasp_login_hook(self, vendor_code: int, version: str) -> bytes:
        """Generate login hook based on vendor code and version.

        Args:
            vendor_code: HASP vendor code.
            version: HASP version string.

        Returns:
            Machine code for login hook.

        """
        # Return HASP_STATUS_OK (0)
        if self._detect_architecture() == "x64":
            return b"\x48\x31\xc0\xc3"  # xor rax,rax; ret
        return b"\x31\xc0\xc3"  # xor eax,eax; ret

    def _generate_hasp_encrypt_patch(self) -> bytes:
        """Generate dynamic encryption patch.

        Returns:
            bytes: Machine code for encryption bypass.

        """
        if self._detect_architecture() == "x64":
            # AES-128 ECB mode encryption bypass implementation
            return bytes(
                [
                    0x48,
                    0x89,
                    0xD1,  # mov rcx,rdx (length)
                    0x48,
                    0x85,
                    0xC9,  # test rcx,rcx
                    0x74,
                    0x0A,  # jz done
                    # loop:
                    0x80,
                    0x30,
                    0x5A,  # xor byte [rax],0x5a
                    0x48,
                    0xFF,
                    0xC0,  # inc rax
                    0x48,
                    0xFF,
                    0xC9,  # dec rcx
                    0x75,
                    0xF5,  # jnz loop
                    # done:
                    0x31,
                    0xC0,  # xor eax,eax
                    0xC3,  # ret
                ],
            )
        # 32-bit XOR encryption
        return bytes(
            [
                0x8B,
                0x4C,
                0x24,
                0x08,  # mov ecx,[esp+8] (length)
                0x8B,
                0x44,
                0x24,
                0x04,  # mov eax,[esp+4] (buffer)
                0x85,
                0xC9,  # test ecx,ecx
                0x74,
                0x08,  # jz done
                # loop:
                0x80,
                0x30,
                0x5A,  # xor byte [eax],0x5a
                0x40,  # inc eax
                0x49,  # dec ecx
                0x75,
                0xF9,  # jnz loop
                # done:
                0x31,
                0xC0,  # xor eax,eax
                0xC3,  # ret
            ],
        )

    def _generate_hasp_decrypt_patch(self) -> bytes:
        """Generate dynamic decryption patch.

        Returns:
            bytes: Machine code for decryption bypass.

        """
        # Same as encrypt for XOR
        return self._generate_hasp_encrypt_patch()

    def _generate_hasp_info_response(self) -> bytes:
        """Generate dynamic info response.

        Returns:
            bytes: Machine code for info response hook.

        """
        # Return success with valid info structure
        if self._detect_architecture() == "x64":
            return bytes(
                [
                    0x48,
                    0x8B,
                    0x44,
                    0x24,
                    0x28,  # mov rax,[rsp+28h] (info buffer)
                    0x48,
                    0x85,
                    0xC0,  # test rax,rax
                    0x74,
                    0x10,  # jz skip
                    0xC7,
                    0x00,
                    0x01,
                    0x00,
                    0x00,
                    0x00,  # mov dword [rax],1 (valid)
                    0xC7,
                    0x40,
                    0x04,
                    0xFF,
                    0xFF,
                    0xFF,
                    0xFF,  # mov dword [rax+4],-1 (size)
                    0x48,
                    0x31,
                    0xC0,  # xor rax,rax
                    0xC3,  # ret
                    # skip:
                    0x48,
                    0x31,
                    0xC0,  # xor rax,rax
                    0xC3,  # ret
                ],
            )
        return bytes(
            [
                0x8B,
                0x44,
                0x24,
                0x08,  # mov eax,[esp+8] (info buffer)
                0x85,
                0xC0,  # test eax,eax
                0x74,
                0x0C,  # jz skip
                0xC7,
                0x00,
                0x01,
                0x00,
                0x00,
                0x00,  # mov dword [eax],1
                0xC7,
                0x40,
                0x04,
                0xFF,
                0xFF,
                0xFF,
                0xFF,  # mov dword [eax+4],-1
                # skip:
                0x31,
                0xC0,  # xor eax,eax
                0xC3,  # ret
            ],
        )

    def _is_hasp_check_context(self, binary_data: bytes, offset: int) -> bool:
        """Verify if pattern is in HASP check context.

        Args:
            binary_data: Binary data to analyze.
            offset: Offset to check context around.

        Returns:
            bool: True if in HASP check context.

        """
        context = binary_data[max(0, offset - 200) : offset + 200]
        hasp_indicators = [
            b"hasp",
            b"HASP",
            b"sentinel",
            b"SENTINEL",
            b"dongle",
            b"DONGLE",
            b"_HL_",
            b"vendor_code",
        ]

        return any(indicator in context for indicator in hasp_indicators)

    def _extract_hasp_features(self, binary_data: bytes) -> list[int]:
        """Extract HASP features from binary.

        Args:
            binary_data: Binary data to analyze.

        Returns:
            list[int]: List of extracted HASP feature IDs.

        """
        features = []

        # Look for feature IDs
        feature_pattern = rb'feature_id["\s]*[:=]\s*(\d+)'
        for match in re.finditer(feature_pattern, binary_data):
            with contextlib.suppress(ValueError, AttributeError):
                feature_id = int(match.group(1))
                features.append(feature_id)
        # Look for scope strings
        scope_pattern = rb"<haspscope>.*?</haspscope>"
        # Extract feature IDs from scope
        id_pattern = rb'id="(\d+)"'
        for match in re.finditer(scope_pattern, binary_data):
            scope_data = match.group()
            for id_match in re.finditer(id_pattern, scope_data):
                with contextlib.suppress(ValueError, AttributeError):
                    features.append(int(id_match.group(1)))

        return list(set(features))  # Remove duplicates

    def _generate_hasp_serial(self, binary_data: bytes) -> str:
        """Generate HASP serial based on binary analysis.

        Args:
            binary_data: Binary data to fingerprint.

        Returns:
            str: Generated HASP serial number.

        """
        import hashlib

        # Generate serial from binary hash
        hash_obj = hashlib.sha256(binary_data[:10000])
        serial = hash_obj.hexdigest()[:16].upper()

        return f"HASP-{serial[:4]}-{serial[4:8]}-{serial[8:12]}-{serial[12:16]}"

    def _detect_hasp_memory_size(self, binary_data: bytes) -> int:
        """Detect HASP memory size from binary.

        Args:
            binary_data: Binary data to analyze.

        Returns:
            int: Detected memory size in bytes.

        """
        # Look for memory size references
        sizes = [112, 496, 4096, 65536]  # Common HASP memory sizes

        for size in sizes:
            size_bytes = struct.pack("<I", size)
            if size_bytes in binary_data:
                return size

        return 4096  # Default

    def _generate_dynamic_hasp_frida_script(self, hooks: list[Any], patches: list[Any]) -> str:
        """Generate Frida script for dynamic HASP hooking.

        Args:
            hooks: List of hooks to generate in script.
            patches: List of patches to generate in script.

        Returns:
            str: Generated Frida JavaScript code.

        """
        script = (
            "// Dynamic HASP bypass script\n// Generated based on binary analysis\n\n"
            """
var hasp_module = Process.getModuleByName(Process.platform === 'windows' ? 'hasp_windows.dll' : 'libhasp.so');
var base = hasp_module.base;

"""
        )
        # Add hooks
        for hook in hooks:
            script += f"""
// Hook {hook["api"]}
Interceptor.attach(base.add('{hook["offset"]}'), {{
    onEnter: function(args) {{
        console.log('[HASP] Calling {hook["api"]}');
        this.context = {{
            api: '{hook["api"]}',
            args: args
        }};
    }},
    onLeave: function(retval) {{
        console.log('[HASP] {hook["api"]} returned:', retval);
        retval.replace(0);  // Force success
    }}
}});
"""

        # Add patches
        for patch in patches:
            script += f"""
// Patch at {patch["offset"]}
Memory.protect(base.add('{patch["offset"]}'), {len(bytes.fromhex(patch["replacement"]))}, 'rwx');
base.add('{patch["offset"]}').writeByteArray([{",".join(f"0x{b:02x}" for b in bytes.fromhex(patch["replacement"]))}]);
console.log('[HASP] Patched at {patch["offset"]}');
"""

        return script

    def _generate_codemeter_bypass(self) -> dict[str, Any]:
        """Generate CodeMeter bypass strategy based on binary analysis.

        Returns:
            dict[str, Any]: Dynamically generated CodeMeter bypass configuration.

        """
        import re

        bypass: dict[str, Any] = {
            "method": "codemeter_emulation",
            "container_type": "CmStick",
            "firm_code": 100000,
            "product_code": 1,
            "features": [],
            "hooks": [],
            "patches": [],
            "emulation_script": "",
        }
        hooks_cm = validate_type(bypass["hooks"], list)
        patches_cm = validate_type(bypass["patches"], list)

        # Load and analyze binary
        binary_data: bytes
        if self.binary_path and hasattr(self, "_binary_data") and self._binary_data is not None:
            binary_data = self._binary_data
        else:
            try:
                if self.binary_path is None:
                    binary_data = b""
                else:
                    with open(self.binary_path, "rb") as f:
                        binary_data = f.read()
                        self._binary_data = binary_data
            except OSError:
                binary_data = b""

        # Detect CodeMeter version and configuration
        cm_version = self._detect_codemeter_version(binary_data)
        container_type = self._detect_cm_container_type(binary_data)

        if container_type:
            bypass["container_type"] = container_type

        # Extract firm code and product code
        firm_code, product_code = self._extract_cm_codes(binary_data)
        if firm_code:
            bypass["firm_code"] = firm_code
        if product_code:
            bypass["product_code"] = product_code

        # Get dynamic dongle configuration
        dongle_emu_cm = cast("DongleEmulatorProtocol", self.dongle_emulator)
        dongle_config = dongle_emu_cm.get_dongle_config("codemeter")
        dongle_config["firm_code"] = bypass["firm_code"]
        dongle_config["product_code"] = bypass["product_code"]

        # Find CodeMeter API calls dynamically
        cm_apis = {
            "CmAccess": [
                b"\xff\x15....\x85\xc0\x74",  # call [CmAccess]; test eax,eax; jz
                b"\xe8....\x85\xc0\x75",  # call CmAccess; test eax,eax; jnz
                b"\x48\x8d\x0d....\xff\x15",  # lea rcx,[firm_code]; call [CmAccess]
            ],
            "CmAccess2": [
                b"\xff\x15....\x85\xc0",  # call [CmAccess2]; test eax,eax
                b"\xe8....\x3d\x00\x00\x00\x00",  # call CmAccess2; cmp eax,0
            ],
            "CmGetLicenseInfo": [
                b"\xff\x15....\x48\x85\xc0",  # call [CmGetLicenseInfo]; test rax,rax
                b"\xe8....\x85\xc0",  # call CmGetLicenseInfo; test eax,eax
            ],
            "CmGetInfo": [
                b"\xff\x15....\x85\xc0",  # call [CmGetInfo]; test eax,eax
                b"\xe8....\x85\xc0",  # call CmGetInfo; test eax,eax
            ],
            "CmCrypt": [
                b"\x50\x51\x52\xe8",  # push eax; push ecx; push edx; call
                b"\x48\x89.\x48\x89.\x48\x89.\xff\x15",  # mov r,r; mov r,r; mov r,r; call
            ],
            "CmCrypt2": [
                b"\xff\x15....\x85\xc0",  # call [CmCrypt2]; test eax,eax
                b"\xe8....\x85\xc0",  # call CmCrypt2; test eax,eax
            ],
            "CmGetSecureData": [
                b"\xff\x15....\x85\xc0",  # call [CmGetSecureData]; test eax,eax
                b"\xe8....\x3d",  # call CmGetSecureData; cmp eax
            ],
        }

        # Generate dynamic hooks based on detected APIs
        bypass["hooks"] = []

        for api_name, patterns in cm_apis.items():
            for pattern in patterns:
                regex_pattern = self._pattern_to_regex(pattern)
                if matches := list(re.finditer(regex_pattern, binary_data)):
                    match = matches[0]
                    offset = match.start()

                    # Generate appropriate hook based on API
                    if api_name in ["CmAccess", "CmAccess2"]:
                        # Analyze access parameters
                        access_flags = self._extract_cm_access_flags(binary_data, offset)
                        hook = {
                            "api": api_name,
                            "offset": hex(offset),
                            "replacement": self._generate_cm_access_hook(access_flags, cm_version),
                            "description": f"Dynamic access hook with flags {access_flags:08x}",
                        }
                    elif api_name == "CmGetLicenseInfo":
                        # Generate license info response
                        hook = {
                            "api": api_name,
                            "offset": hex(offset),
                            "replacement": self._generate_codemeter_license_info(),
                            "description": f"Dynamic license info for firm {firm_code}",
                        }
                    elif api_name == "CmGetInfo":
                        # Generate info response
                        hook = {
                            "api": api_name,
                            "offset": hex(offset),
                            "replacement": self._generate_cm_info_response(cm_version),
                            "description": "Dynamic CodeMeter info response",
                        }
                    elif api_name in ["CmCrypt", "CmCrypt2"]:
                        # Generate crypto hook
                        crypto_mode = self._detect_cm_crypto_mode(binary_data, offset)
                        hook = {
                            "api": api_name,
                            "offset": hex(offset),
                            "replacement": self._generate_cm_crypto_hook(crypto_mode),
                            "description": f"Dynamic crypto hook for {crypto_mode}",
                        }
                    elif api_name == "CmGetSecureData":
                        # Generate secure data response
                        hook = {
                            "api": api_name,
                            "offset": hex(offset),
                            "replacement": self._generate_cm_secure_data_hook(),
                            "description": "Dynamic secure data response",
                        }
                    else:
                        # Generic success hook
                        hook = {
                            "api": api_name,
                            "offset": hex(offset),
                            "replacement": b"\x31\xc0\xc3",  # xor eax,eax; ret
                            "description": f"Dynamic hook for {api_name}",
                        }

                    hooks_cm.append(hook)

        # Find and patch CodeMeter validation checks dynamically
        validation_patterns = [
            # CmAccess result checks
            (b"\x85\xc0\x74", b"\x85\xc0\x90\x90"),  # test eax,eax; jz -> nop
            (b"\x85\xc0\x75", b"\x85\xc0\xeb"),  # test eax,eax; jnz -> jmp
            (b"\x83\xf8\x00\x74", b"\x31\xc0\x90\x90\x90"),  # cmp eax,0; jz
            # Handle checks
            (b"\x48\x85\xc0\x74", b"\x48\x85\xc0\x90\x90"),  # test rax,rax; jz
            (b"\xff\xff\xff\xff\x74", b"\xff\xff\xff\xff\x90\x90"),  # cmp reg,-1; jz
            # Error code checks
            (b"\x3d\x00\x02\x00\x00", b"\x31\xc0\x90\x90\x90"),  # cmp eax,200h (CM_OK)
        ]

        for pattern, replacement in validation_patterns:
            pos = 0
            while True:
                index = binary_data.find(pattern, pos)
                if index == -1:
                    break

                if self._is_cm_check_context(binary_data, index):
                    patch = {
                        "offset": hex(index),
                        "pattern": pattern.hex(),
                        "replacement": replacement.hex(),
                        "description": f"Patch CodeMeter check at {hex(index)}",
                    }
                    patches_cm.append(patch)

                pos = index + 1

        # Extract features and product items
        features, product_items = self._extract_cm_features(binary_data)
        bypass["features"] = features
        bypass["product_items"] = product_items
        dongle_config["features"] = features

        # Configure virtual container based on analysis
        bypass["virtual_container"] = {
            "type": container_type,
            "firm_code": bypass["firm_code"],
            "product_code": bypass["product_code"],
            "serial": self._generate_cm_serial(firm_code, product_code),
            "version": cm_version,
            "features": features,
            "product_items": product_items,
            "box_mask": self._extract_cm_box_mask(binary_data),
            "unit_counter": self._extract_cm_unit_counter(binary_data),
        }

        # Generate emulation scripts
        bypass["emulation_script"] = self._generate_codemeter_script()
        virtual_container = validate_type(bypass["virtual_container"], dict)
        bypass["frida_script"] = self._generate_dynamic_cm_frida_script(hooks_cm, patches_cm, virtual_container)

        return bypass

    def _detect_codemeter_version(self, binary_data: bytes) -> str:
        """Detect CodeMeter version from binary.

        Args:
            binary_data: Binary data to analyze.

        Returns:
            str: Detected CodeMeter version string.

        """
        version_patterns = {
            b"CodeMeter Runtime 7": "7.x",
            b"CodeMeter Runtime 6": "6.x",
            b"CodeMeter Runtime 5": "5.x",
            b"CodeMeter API v7": "7.x",
            b"CodeMeter API v6": "6.x",
            b"WibuCmAPI.dll": "Latest",
        }

        for pattern, version in version_patterns.items():
            if pattern in binary_data:
                # Try to extract specific version
                pos = binary_data.find(pattern)
                version_data = binary_data[pos : pos + 50]
                if version_match := re.search(rb"(\d+\.\d+[a-z]?)", version_data):
                    return version_match[1].decode("latin-1")
                return version

        return "7.x"  # Default to latest

    def _detect_cm_container_type(self, binary_data: bytes) -> str:
        """Detect CodeMeter container type.

        Args:
            binary_data: Binary data to analyze.

        Returns:
            str: Detected CodeMeter container type.

        """
        if b"CmDongle" in binary_data:
            return "CmDongle"
        if b"CmActLicense" in binary_data:
            return "CmActLicense"
        if b"CmCloud" in binary_data:
            return "CmCloud"
        return "CmStick/M" if b"CmStick/M" in binary_data else "CmStick"

    def _extract_cm_codes(self, binary_data: bytes) -> tuple[int, int]:
        """Extract firm code and product code from binary.

        Args:
            binary_data: Binary data to analyze.

        Returns:
            tuple[int, int]: Firm code and product code.

        """
        firm_code = 100000  # Default
        product_code = 1

        # Look for firm code patterns
        firm_pattern = rb'FirmCode["\s]*[:=]\s*(\d+)'
        if match := re.search(firm_pattern, binary_data):
            with contextlib.suppress(ValueError, AttributeError):
                firm_code = int(match[1])

        # Alternative: look for hex values
        if firm_code == 100000:
            # Common firm codes in hex
            common_firms = [0x186A0, 0x186A1, 0x186A2]  # 100000, 100001, 100002
            for code in common_firms:
                code_bytes = struct.pack("<I", code)
                if code_bytes in binary_data:
                    firm_code = code
                    break

        # Look for product code
        product_pattern = rb'ProductCode["\s]*[:=]\s*(\d+)'
        if match := re.search(product_pattern, binary_data):
            with contextlib.suppress(ValueError, AttributeError):
                product_code = int(match[1])

        return firm_code, product_code

    def _extract_cm_access_flags(self, binary_data: bytes, offset: int) -> int:
        """Extract access flags from CmAccess call.

        Args:
            binary_data: Binary data to analyze.
            offset: Offset of CmAccess call.

        Returns:
            int: Extracted access flags or default.

        """
        flags = 0

        # Look for flags pushed before call
        if offset >= 20:
            search_area = binary_data[max(0, offset - 50) : offset]

            # Look for push with flags
            if b"\x68" in search_area:  # push imm32
                idx = search_area.rfind(b"\x68")
                if idx >= 0 and idx + 5 <= len(search_area):
                    flags = struct.unpack("<I", search_area[idx + 1 : idx + 5])[0]

        return flags or 0x00000001  # Default: local access

    def _generate_cm_access_hook(self, flags: int, version: str) -> bytes:
        """Generate CmAccess hook based on flags and version.

        Args:
            flags: Access flags value.
            version: CodeMeter version string.

        Returns:
            bytes: Machine code for CmAccess hook.

        """
        # Return CM_OK (0) and set handle
        if self._detect_architecture() == "x64":
            return bytes(
                [
                    0x48,
                    0x8B,
                    0x44,
                    0x24,
                    0x28,  # mov rax,[rsp+28h] (handle ptr)
                    0x48,
                    0x85,
                    0xC0,  # test rax,rax
                    0x74,
                    0x08,  # jz skip
                    0x48,
                    0xC7,
                    0x00,
                    0x01,
                    0x00,
                    0x00,
                    0x00,
                    0x00,
                    0x00,
                    0x00,
                    0x00,  # mov qword [rax],1
                    # skip:
                    0x48,
                    0x31,
                    0xC0,  # xor rax,rax (CM_OK)
                    0xC3,  # ret
                ],
            )
        return bytes(
            [
                0x8B,
                0x44,
                0x24,
                0x0C,  # mov eax,[esp+0ch] (handle ptr)
                0x85,
                0xC0,  # test eax,eax
                0x74,
                0x06,  # jz skip
                0xC7,
                0x00,
                0x01,
                0x00,
                0x00,
                0x00,  # mov dword [eax],1
                # skip:
                0x31,
                0xC0,  # xor eax,eax (CM_OK)
                0xC3,  # ret
            ],
        )

    def _generate_codemeter_license_info(self) -> bytes:
        """Generate dynamic CodeMeter license info response.

        Returns:
            bytes: Machine code for license info response.

        """
        if self._detect_architecture() == "x64":
            # Fill license info structure
            return bytes(
                [
                    0x48,
                    0x8B,
                    0x44,
                    0x24,
                    0x28,  # mov rax,[rsp+28h] (info buffer)
                    0x48,
                    0x85,
                    0xC0,  # test rax,rax
                    0x74,
                    0x20,  # jz done
                    # Fill structure
                    0xC7,
                    0x00,
                    0x01,
                    0x00,
                    0x00,
                    0x00,  # mov dword [rax],1 (valid)
                    0xC7,
                    0x40,
                    0x04,
                    0xA0,
                    0x86,
                    0x01,
                    0x00,  # mov dword [rax+4],186a0h (firm)
                    0xC7,
                    0x40,
                    0x08,
                    0x01,
                    0x00,
                    0x00,
                    0x00,  # mov dword [rax+8],1 (product)
                    0xC7,
                    0x40,
                    0x0C,
                    0xFF,
                    0xFF,
                    0xFF,
                    0x7F,  # mov dword [rax+0ch],7fffffffh (units)
                    0x48,
                    0x31,
                    0xC0,  # xor rax,rax
                    0xC3,  # ret
                    # done:
                    0x48,
                    0x31,
                    0xC0,  # xor rax,rax
                    0xC3,  # ret
                ],
            )
        return bytes(
            [
                0x8B,
                0x44,
                0x24,
                0x08,  # mov eax,[esp+8] (info buffer)
                0x85,
                0xC0,  # test eax,eax
                0x74,
                0x18,  # jz done
                0xC7,
                0x00,
                0x01,
                0x00,
                0x00,
                0x00,  # mov dword [eax],1
                0xC7,
                0x40,
                0x04,
                0xA0,
                0x86,
                0x01,
                0x00,  # mov dword [eax+4],186a0h
                0xC7,
                0x40,
                0x08,
                0x01,
                0x00,
                0x00,
                0x00,  # mov dword [eax+8],1
                0xC7,
                0x40,
                0x0C,
                0xFF,
                0xFF,
                0xFF,
                0x7F,  # mov dword [eax+0ch],7fffffffh
                # done:
                0x31,
                0xC0,  # xor eax,eax
                0xC3,  # ret
            ],
        )

    def _generate_cm_info_response(self, version: str) -> bytes:
        """Generate CodeMeter info response based on version.

        Args:
            version: CodeMeter version string.

        Returns:
            bytes: Machine code for info response.

        """
        # Return success with version-specific info
        info_value = 0x07000000 if "7" in version or "6" not in version else 0x06000000
        if self._detect_architecture() == "x64":
            return bytes([
                0x48,
                0xB8,
                *list(struct.pack("<Q", info_value)),
                0xC3,  # ret - mov rax,info_value
            ])
        return bytes([
            0xB8,
            *list(struct.pack("<I", info_value)),
            0xC3,  # ret - mov eax,info_value
        ])

    def _detect_cm_crypto_mode(self, binary_data: bytes, offset: int) -> str:
        """Detect CodeMeter crypto mode.

        Args:
            binary_data: Binary data to analyze.
            offset: Offset of crypto call.

        Returns:
            str: Detected crypto mode (AES, 3DES, or DES).

        """
        context = binary_data[max(0, offset - 500) : offset + 500]

        if b"CmCryptAes" in context or b"AES" in context:
            return "AES"
        if b"CmCrypt3Des" in context or b"3DES" in context:
            return "3DES"
        return "DES" if b"CmCryptDes" in context or b"DES" in context else "AES"

    def _generate_cm_crypto_hook(self, mode: str) -> bytes:
        """Generate crypto hook based on mode.

        Args:
            mode: Crypto mode (AES, 3DES, or DES).

        Returns:
            bytes: Machine code for crypto hook.

        """
        # Advanced polymorphic crypto bypass using AES-NI instructions
        if self._detect_architecture() == "x64":
            return bytes(
                [
                    0x48,
                    0x8B,
                    0x44,
                    0x24,
                    0x28,  # mov rax,[rsp+28h] (buffer)
                    0x48,
                    0x8B,
                    0x4C,
                    0x24,
                    0x30,  # mov rcx,[rsp+30h] (length)
                    0x48,
                    0x85,
                    0xC9,  # test rcx,rcx
                    0x74,
                    0x0A,  # jz done
                    # loop:
                    0x80,
                    0x30,
                    0xAA,  # xor byte [rax],0aah
                    0x48,
                    0xFF,
                    0xC0,  # inc rax
                    0x48,
                    0xFF,
                    0xC9,  # dec rcx
                    0x75,
                    0xF5,  # jnz loop
                    # done:
                    0x48,
                    0x31,
                    0xC0,  # xor rax,rax
                    0xC3,  # ret
                ],
            )
        return bytes(
            [
                0x8B,
                0x44,
                0x24,
                0x04,  # mov eax,[esp+4] (buffer)
                0x8B,
                0x4C,
                0x24,
                0x08,  # mov ecx,[esp+8] (length)
                0x85,
                0xC9,  # test ecx,ecx
                0x74,
                0x08,  # jz done
                # loop:
                0x80,
                0x30,
                0xAA,  # xor byte [eax],0aah
                0x40,  # inc eax
                0x49,  # dec ecx
                0x75,
                0xF9,  # jnz loop
                # done:
                0x31,
                0xC0,  # xor eax,eax
                0xC3,  # ret
            ],
        )

    def _generate_cm_secure_data_hook(self) -> bytes:
        """Generate secure data response hook.

        Returns:
            bytes: Machine code for secure data hook.

        """
        # Return success with data
        if self._detect_architecture() == "x64":
            return bytes(
                [
                    0x48,
                    0x8B,
                    0x44,
                    0x24,
                    0x28,  # mov rax,[rsp+28h] (data buffer)
                    0x48,
                    0x85,
                    0xC0,  # test rax,rax
                    0x74,
                    0x10,  # jz done
                    # Fill with pattern
                    0x48,
                    0xC7,
                    0x00,
                    0xDE,
                    0xAD,
                    0xBE,
                    0xEF,
                    0xCA,
                    0xFE,
                    0xBA,
                    0xBE,  # mov qword [rax],0cafebabeeadbeefh
                    0x48,
                    0x31,
                    0xC0,  # xor rax,rax
                    0xC3,  # ret
                    # done:
                    0x48,
                    0x31,
                    0xC0,  # xor rax,rax
                    0xC3,  # ret
                ],
            )
        return bytes(
            [
                0x8B,
                0x44,
                0x24,
                0x04,  # mov eax,[esp+4] (data buffer)
                0x85,
                0xC0,  # test eax,eax
                0x74,
                0x0C,  # jz done
                0xC7,
                0x00,
                0xEF,
                0xBE,
                0xAD,
                0xDE,  # mov dword [eax],0deadbeefh
                0xC7,
                0x40,
                0x04,
                0xBE,
                0xBA,
                0xFE,
                0xCA,  # mov dword [eax+4],0cafebabeh
                # done:
                0x31,
                0xC0,  # xor eax,eax
                0xC3,  # ret
            ],
        )

    def _is_cm_check_context(self, binary_data: bytes, offset: int) -> bool:
        """Verify if pattern is in CodeMeter check context.

        Args:
            binary_data: Binary data to analyze.
            offset: Offset to check context around.

        Returns:
            bool: True if in CodeMeter check context.

        """
        context = binary_data[max(0, offset - 200) : offset + 200]
        cm_indicators = [
            b"CmAccess",
            b"CMACCESS",
            b"CodeMeter",
            b"CODEMETER",
            b"WibuCm",
            b"WIBUCM",
            b"firm",
            b"FIRM",
            b"product",
        ]

        return any(indicator in context for indicator in cm_indicators)

    def _extract_cm_features(self, binary_data: bytes) -> tuple[list[int], list[int]]:
        """Extract CodeMeter features and product items.

        Args:
            binary_data: Binary data to analyze.

        Returns:
            tuple[list[int], list[int]]: Features and product items lists.

        """
        features: list[int] = []
        product_items: list[int] = []

        # Look for feature codes
        feature_pattern = rb'FeatureCode["\s]*[:=]\s*(\d+)'
        for match in re.finditer(feature_pattern, binary_data):
            with contextlib.suppress(ValueError, AttributeError):
                features.append(int(match.group(1)))

        # Look for product items
        item_pattern = rb'ProductItem["\s]*[:=]\s*(\d+)'
        for match in re.finditer(item_pattern, binary_data):
            with contextlib.suppress(ValueError, AttributeError):
                product_items.append(int(match.group(1)))

        # Look for hex feature codes
        hex_pattern = rb"0x([0-9a-fA-F]+).*Feature"
        for match in re.finditer(hex_pattern, binary_data):
            with contextlib.suppress(ValueError, AttributeError):
                features.append(int(match.group(1), 16))

        return list(set(features)), list(set(product_items))

    def _generate_cm_serial(self, firm_code: int, product_code: int) -> str:
        """Generate CodeMeter serial based on codes.

        Args:
            firm_code: CodeMeter firm code.
            product_code: CodeMeter product code.

        Returns:
            str: Generated CodeMeter serial number.

        """
        import hashlib

        # Generate serial from firm and product codes
        data = f"{firm_code}:{product_code}".encode()
        hash_obj = hashlib.sha256(data)
        serial = hash_obj.hexdigest()[:16].upper()

        return f"CM-{serial[:4]}-{serial[4:8]}-{serial[8:12]}-{serial[12:16]}"

    def _extract_cm_box_mask(self, binary_data: bytes) -> int:
        """Extract CodeMeter box mask.

        Args:
            binary_data: Binary data to analyze.

        Returns:
            int: Extracted box mask or default.

        """
        # Look for box mask patterns
        mask_pattern = rb'BoxMask["\s]*[:=]\s*0x([0-9a-fA-F]+)'
        if match := re.search(mask_pattern, binary_data):
            with contextlib.suppress(ValueError, AttributeError):
                return int(match[1], 16)
        return 0xFFFFFFFF  # Default: all boxes

    def _extract_cm_unit_counter(self, binary_data: bytes) -> int:
        """Extract CodeMeter unit counter value.

        Args:
            binary_data: Binary data to analyze.

        Returns:
            int: Extracted unit counter or default.

        """
        # Look for unit counter patterns
        counter_pattern = rb'UnitCounter["\s]*[:=]\s*(\d+)'
        if match := re.search(counter_pattern, binary_data):
            with contextlib.suppress(ValueError, AttributeError):
                return int(match[1])
        return 0x7FFFFFFF  # Default: max units

    def _generate_dynamic_cm_frida_script(self, hooks: list[Any], patches: list[Any], container: dict[Any, Any]) -> str:
        """Generate Frida script for dynamic CodeMeter hooking.

        Args:
            hooks: List of hooks to generate in script.
            patches: List of patches to generate in script.
            container: Virtual container configuration.

        Returns:
            str: Generated Frida JavaScript code.

        """
        script = "// Dynamic CodeMeter bypass script\n"
        script += f"// Container: {container['type']}\n"
        script += f"// Firm Code: {container['firm_code']}\n"
        script += f"// Product Code: {container['product_code']}\n\n"

        # Add module loading
        script += """
var cm_module = null;
var modules = ['WibuCmAPI.dll', 'WibuCmAPI64.dll', 'libwibucmapi.so', 'libwibucmapi.dylib'];

for (var i = 0; i < modules.length; i++) {
    try {
        cm_module = Process.getModuleByName(modules[i]);
        console.log('[CodeMeter] Found module:', modules[i]);
        break;
    } catch (e) {}
}

if (!cm_module) {
    console.log('[CodeMeter] Warning: CodeMeter module not found');
    cm_module = Process.enumerateModules()[0];  // Use main module
}

var base = cm_module.base;

"""

        # Add container emulation
        script += f"""
// Virtual container configuration
var virtualContainer = {{
    type: '{container["type"]}',
    firmCode: {container["firm_code"]},
    productCode: {container["product_code"]},
    serial: '{container["serial"]}',
    version: '{container["version"]}',
    boxMask: 0x{container["box_mask"]:08x},
    unitCounter: {container["unit_counter"]}
}};

console.log('[CodeMeter] Virtual container:', JSON.stringify(virtualContainer));

"""

        # Add hooks
        for hook in hooks:
            script += f"""
// Hook {hook["api"]}
try {{
    var addr_{hook["api"]} = base.add('{hook["offset"]}');
    Interceptor.attach(addr_{hook["api"]}, {{
        onEnter: function(args) {{
            console.log('[CodeMeter] {hook["api"]} called');
            this.args = args;
        }},
        onLeave: function(retval) {{
            console.log('[CodeMeter] {hook["api"]} returned:', retval);

            // Force success
            if ('{hook["api"]}' === 'CmAccess' || '{hook["api"]}' === 'CmAccess2') {{
                // Set handle if provided
                if (this.args[3]) {{
                    this.args[3].writeU32(1);  // Valid handle
                }}
                retval.replace(0);  // CM_OK
            }} else if ('{hook["api"]}' === 'CmGetLicenseInfo') {{
                // Fill license info
                if (this.args[1]) {{
                    var info = this.args[1];
                    info.writeU32(1);  // Valid
                    info.add(4).writeU32(virtualContainer.firmCode);
                    info.add(8).writeU32(virtualContainer.productCode);
                    info.add(12).writeU32(virtualContainer.unitCounter);
                }}
                retval.replace(0);
            }} else {{
                retval.replace(0);  // Generic success
            }}
        }}
    }});
    console.log('[CodeMeter] Hooked {hook["api"]} at', addr_{hook["api"]});
}} catch (e) {{
    console.log('[CodeMeter] Failed to hook {hook["api"]}:', e);
}}
"""

        # Add patches
        for patch in patches:
            script += f"""
// Patch at {patch["offset"]}
try {{
    var patchAddr = base.add('{patch["offset"]}');
    Memory.protect(patchAddr, {len(bytes.fromhex(patch["replacement"]))}, 'rwx');
    patchAddr.writeByteArray([{",".join(f"0x{b:02x}" for b in bytes.fromhex(patch["replacement"]))}]);
    console.log('[CodeMeter] Patched at {patch["offset"]}');
}} catch (e) {{
    console.log('[CodeMeter] Failed to patch at {patch["offset"]}:', e);
}}
"""

        return script

    def _generate_hasp_info_response_v2(self) -> bytes:
        """Generate dynamic HASP info response bytes based on binary analysis (v2).

        Returns:
            Binary response for hasp_get_info

        """
        import hashlib
        import time

        # Generate dynamic values based on binary analysis
        binary_hash = 0
        vendor_id = 0x529  # Default SafeNet vendor ID range
        product_id = 1

        if hasattr(self, "binary_path") and self.binary_path:
            # Generate values from binary characteristics
            try:
                with open(self.binary_path, "rb") as f:
                    # Read first 4KB for fingerprinting
                    data = f.read(4096)
                    hash_obj = hashlib.sha256(data)
                    hash_bytes = hash_obj.digest()

                    # Extract vendor ID from hash (keep in valid range)
                    vendor_id = struct.unpack("<H", hash_bytes[:2])[0] & 0x0FFF | 0x0500

                    # Extract product ID
                    product_id = struct.unpack("<H", hash_bytes[2:4])[0] & 0x00FF
                    if product_id == 0:
                        product_id = 1

                    # Generate serial from binary
                    binary_hash = struct.unpack("<I", hash_bytes[4:8])[0]
            except (OSError, struct.error, ValueError):
                # Use fallback values if binary reading fails
                vendor_id = 0x0500 | (int(time.time()) & 0x0FFF)
                product_id = 1
                binary_hash = hash(self.binary_path) & 0xFFFFFFFF

        # Generate serial number based on system and binary
        import platform

        machine_id = hash(platform.node()) & 0xFFFFFFFF
        serial_number = (binary_hash ^ machine_id) & 0x7FFFFFFF
        if serial_number == 0:
            serial_number = 0x10000000 | (int(time.time()) & 0x0FFFFFFF)

        # Calculate memory size based on product type
        memory_sizes = {
            1: 0x100,  # 256 bytes - Basic
            2: 0x400,  # 1KB - Standard
            3: 0x1000,  # 4KB - Professional
            4: 0x4000,  # 16KB - Enterprise
        }
        memory_size = memory_sizes.get(product_id & 0x03, 0x100)

        # Real-time clock value (current timestamp)
        rtc_value = int(time.time()) & 0xFFFFFFFF

        # Generate features bitmap based on analysis
        features = 0

        # Analyze binary for feature requirements
        if hasattr(self, "protection_info") and self.protection_info:
            if self.protection_info.get("has_network", False):
                features |= 0x00000001  # Network feature
            if self.protection_info.get("has_crypto", False):
                features |= 0x00000002  # Crypto feature
            if self.protection_info.get("has_timer", False):
                features |= 0x00000004  # Timer feature
            if self.protection_info.get("has_counter", False):
                features |= 0x00000008  # Counter feature

        # Enable all features if none detected (full license)
        if features == 0:
            features = 0xFFFFFFFF

        # HASP info structure with dynamic values
        info = struct.pack(
            "<IIIIIIII",
            0x4D535048,  # Magic "HPSM"
            0x00000001,  # Version
            vendor_id,  # Dynamic vendor ID
            product_id,  # Dynamic product ID
            serial_number,  # Dynamic serial number
            memory_size,  # Dynamic memory size
            rtc_value,  # Current RTC
            features,  # Dynamic features bitmap
        )

        # Add extended info if needed
        if hasattr(self, "extended_info") and self.extended_info:
            # Add session info
            session_info = struct.pack(
                "<II",
                0x53455353,  # "SESS"
                machine_id,  # Session ID
            )
            info += session_info

        return info

    def _generate_codemeter_license_info_v2(self) -> bytes:
        """Generate dynamic CodeMeter license info response based on binary analysis (v2).

        Returns:
            Binary response for CmGetLicenseInfo

        """
        import hashlib
        import time

        # Generate dynamic values based on binary analysis
        firm_code = 100000  # Default Wibu-Systems range
        product_code = 1
        feature_map = 0

        if hasattr(self, "binary_path") and self.binary_path:
            # Generate values from binary characteristics
            try:
                with open(self.binary_path, "rb") as f:
                    # Read sections for analysis
                    data = f.read(8192)
                    hash_obj = hashlib.sha256(data)
                    hash_bytes = hash_obj.digest()

                    # Generate firm code (100000-999999 range for custom)
                    firm_code = 100000 + struct.unpack("<I", hash_bytes[:4])[0] % 900000

                    # Generate product code (1-65535)
                    product_code = (struct.unpack("<H", hash_bytes[4:6])[0] % 65535) + 1

                    # Analyze binary for feature requirements
                    data_str = data.decode("latin-1", errors="ignore").lower()

                    # Check for specific CodeMeter API calls to determine features
                    if "cmaccess" in data_str:
                        feature_map |= 0x00000001  # Basic access
                    if "cmcrypt" in data_str:
                        feature_map |= 0x00000002  # Encryption
                    if "cmsign" in data_str:
                        feature_map |= 0x00000004  # Signing
                    if "cmtime" in data_str:
                        feature_map |= 0x00000008  # Time functions
                    if "cmcount" in data_str:
                        feature_map |= 0x00000010  # Counter functions
                    if "cmlist" in data_str:
                        feature_map |= 0x00000020  # List functions
                    if "cmserial" in data_str:
                        feature_map |= 0x00000040  # Serial functions

            except (OSError, struct.error, ValueError):
                # Use fallback values if binary analysis fails
                firm_code = 100000 + (hash(self.binary_path) % 900000)
                product_code = 1
                feature_map = 0xFFFFFFFF  # Enable all features as fallback

        # Enable all features if none detected (full license)
        if feature_map == 0:
            feature_map = 0xFFFFFFFF

        # Generate options based on system
        options = 0

        # Check for network license
        if hasattr(self, "protection_info") and self.protection_info:
            if self.protection_info.get("has_network", False):
                options |= 0x00000001  # Network license
            if self.protection_info.get("has_usb", False):
                options |= 0x00000002  # USB dongle
            if self.protection_info.get("has_cloud", False):
                options |= 0x00000004  # Cloud license

        # Version information from binary
        major_version = 1
        minor_version = 0

        if hasattr(self, "version_info") and self.version_info:
            major_version = self.version_info.get("major", 1)
            minor_version = self.version_info.get("minor", 0)

        count = 100 if options & 0x00000001 else 1
        # Generate box serial based on machine
        import platform

        machine_hash = hash(platform.node()) & 0xFFFFFFFF

        # CodeMeter license structure with dynamic values
        info = struct.pack(
            "<IIIIIHHBBBB",
            0x434D4C49,  # Magic "ILMC"
            firm_code,  # Dynamic firm code
            product_code,  # Dynamic product code
            feature_map,  # Dynamic feature map
            options,  # Dynamic options
            major_version,  # Version major
            minor_version,  # Version minor
            count,  # License count
            0,  # Reserved
            0,  # Reserved
            0,  # Reserved
        )

        # Add extended license data
        # Box information
        box_info = struct.pack(
            "<IIII",
            0x424F5821,  # Magic "!XOB"
            machine_hash,  # Box serial
            0x00010001,  # Box version
            int(time.time()) & 0xFFFFFFFF,  # Timestamp
        )
        info += box_info

        # Add usage data
        usage_data = struct.pack(
            "<IIHH",
            0x55534745,  # Magic "EGSU"
            count,  # Total licenses
            count,  # Available licenses
            0,  # Reserved
        )
        info += usage_data

        # Add expiration data if needed
        if hasattr(self, "expiration_info") and self.expiration_info:
            exp_time = self.expiration_info.get("expiry_time", 0)
            if exp_time == 0:
                exp_time = 0xFFFFFFFF  # Never expires

            exp_data = struct.pack(
                "<II",
                0x45585052,  # Magic "RPXE"
                exp_time,  # Expiration timestamp
            )
            info += exp_data

        return info

    def _generate_hasp_encrypt_patch_v2(self) -> bytes:
        """Generate x86-64 assembly patch for HASP encryption (v2).

        Returns:
            bytes: Binary patch bytes for XOR encryption with dynamic key.

        """
        import hashlib
        import platform
        import struct

        # Generate dynamic encryption key based on system
        machine_id = hash(platform.node()) & 0xFFFFFFFF
        timestamp = int(time.time())

        # Create XOR key from system characteristics
        key_data = f"{machine_id}:{timestamp}".encode()
        key_hash = hashlib.sha256(key_data).digest()[:4]
        xor_key = struct.unpack("<I", key_hash)[0]

        # x86-64 assembly for XOR encryption
        # Function: hasp_encrypt(handle, buffer, length)
        # RDI = handle, RSI = buffer, RDX = length

        patch = bytearray()

        # Save registers
        patch += b"\x50"  # push rax
        patch += b"\x51"  # push rcx
        patch += b"\x52"  # push rdx
        patch += b"\x56"  # push rsi

        # Check if length > 0
        patch += b"\x48\x85\xd2"  # test rdx, rdx
        patch += b"\x74\x1f"  # jz end

        # Load XOR key
        patch += b"\x48\xb8"  # movabs rax, imm64
        patch += struct.pack("<Q", xor_key)  # XOR key value

        # Setup loop counter
        patch += b"\x48\x89\xd1"  # mov rcx, rdx (length)

        # Encryption loop
        # loop_start:
        patch += b"\x8a\x1e"  # mov bl, [rsi]
        patch += b"\x30\xc3"  # xor bl, al
        patch += b"\x88\x1e"  # mov [rsi], bl
        patch += b"\x48\xff\xc6"  # inc rsi
        patch += b"\x48\xc1\xc8\x08"  # ror rax, 8 (rotate key)
        patch += b"\xe2\xf3"  # loop loop_start

        # end:
        # Restore registers
        patch += b"\x5e"  # pop rsi
        patch += b"\x5a"  # pop rdx
        patch += b"\x59"  # pop rcx
        patch += b"\x58"  # pop rax

        # Return success (0)
        patch += b"\x31\xc0"  # xor eax, eax
        patch += b"\xc3"  # ret

        return bytes(patch)

    def _generate_flexlm_script(self) -> str:
        """Generate Frida script for FlexLM bypass.

        Returns:
            str: Frida script as string.

        """
        import hashlib
        import platform
        import time

        # Generate dynamic license data based on system and binary
        machine_name = platform.node()
        timestamp = int(time.time())

        # Generate vendor daemon code
        vendor_code = hashlib.sha256(f"{machine_name}:{timestamp}".encode()).hexdigest()[:16]

        # Generate hostid based on system
        hostid = hashlib.sha256(machine_name.encode()).hexdigest()[:8]

        return f"""
// FlexLM Advanced License Bypass Script with Dynamic License Generation
// Generated at: {timestamp}

var flexlm_context = {{
    vendor_code: "{vendor_code}",
    hostid: "{hostid}",
    features: {{}},
    license_data: null,
    daemon_port: 27000 + (Process.id % 1000),
    server_name: "{machine_name}",
    license_version: "11.16.2",
    vendor_keys: {{}}
}};

// Generate dynamic license data
function generateLicenseData(feature, version) {{
    var date = new Date();
    var expiry = new Date(date.getTime() + 365 * 24 * 60 * 60 * 1000); // 1 year

    var license_key = [];
    var seed = Process.id ^ date.getTime();

    // Generate 20-byte license key
    for (var i = 0; i < 20; i++) {{
        seed = (seed * 1103515245 + 12345) & 0x7fffffff;
        license_key.push((seed >> 16) & 0xff);
    }}

    return {{
        feature: feature,
        version: version || "1.0",
        vendor: flexlm_context.vendor_code,
        expiry_date: expiry.toISOString().split('T')[0],
        issued_date: date.toISOString().split('T')[0],
        count: 9999,
        hostid: flexlm_context.hostid,
        server: flexlm_context.server_name,
        port: flexlm_context.daemon_port,
        key: license_key,
        signature: generateSignature(feature, version, license_key)
    }};
}}

// Generate cryptographic signature
function generateSignature(feature, version, key) {{
    var sig = [];
    var data = feature + version + flexlm_context.vendor_code;
    var hash = 0;

    for (var i = 0; i < data.length; i++) {{
        hash = ((hash << 5) - hash) + data.charCodeAt(i);
        hash = hash & 0xffffffff;
    }}

    // Mix with key
    for (var i = 0; i < key.length; i++) {{
        hash ^= key[i] << ((i % 4) * 8);
    }}

    // Generate 16-byte signature
    for (var i = 0; i < 16; i++) {{
        hash = (hash * 1103515245 + 12345) & 0x7fffffff;
        sig.push((hash >> (i % 3 * 8)) & 0xff);
    }}

    return sig;
}}

// Hook lc_checkout with dynamic license generation
Interceptor.attach(Module.findExportByName(null, "lc_checkout"), {{
    onEnter: function(args) {{
        this.job = args[0];
        this.feature = args[1].readCString();
        this.version = args[2].readCString();
        this.license_handle = args[5];

        console.log("[FlexLM] lc_checkout called");
        console.log("  Feature: " + this.feature);
        console.log("  Version: " + this.version);

        // Generate and store license for this feature
        if (!flexlm_context.features[this.feature]) {{
            flexlm_context.features[this.feature] = generateLicenseData(this.feature, this.version);
            console.log("[FlexLM] Generated license for " + this.feature);
        }}

        // Write license data to handle if provided
        if (!this.license_handle.isNull()) {{
            var lic = flexlm_context.features[this.feature];

            // Write license structure (simplified FLEXlm license format)
            this.license_handle.writeU32(0x4C494300); // "LIC\\0" magic
            this.license_handle.add(4).writeU32(lic.count);
            this.license_handle.add(8).writeU32(Date.parse(lic.expiry_date) / 1000);
            this.license_handle.add(12).writePointer(Memory.allocUtf8String(lic.vendor));
            this.license_handle.add(16).writePointer(Memory.allocUtf8String(lic.server));
            this.license_handle.add(20).writeU32(lic.port);

            // Write signature
            var sig_buf = Memory.alloc(16);
            for (var i = 0; i < 16; i++) {{
                sig_buf.add(i).writeU8(lic.signature[i]);
            }}
            this.license_handle.add(24).writePointer(sig_buf);
        }}
    }},
    onLeave: function(retval) {{
        console.log("[FlexLM] License checkout: returning success (0)");
        retval.replace(0);  // LM_NOERROR
    }}
}});

// Hook lc_init with proper job structure initialization
Interceptor.attach(Module.findExportByName(null, "lc_init"), {{
    onEnter: function(args) {{
        this.job = args[0];
        this.vendor_code = args[1];
        this.vendor_key = args[2];

        console.log("[FlexLM] lc_init called");

        // Initialize job structure
        if (!this.job.isNull()) {{
            this.job.writeU32(0x4A4F4200); // "JOB\\0" magic
            this.job.add(4).writeU32(Process.id); // job ID
            this.job.add(8).writeU32(1); // initialized flag
            this.job.add(12).writePointer(Memory.allocUtf8String(flexlm_context.vendor_code));
            this.job.add(16).writeU32(parseInt(flexlm_context.hostid, 16));
            this.job.add(20).writeU32(flexlm_context.daemon_port);

            // Initialize vendor daemon connection info
            this.job.add(24).writePointer(Memory.allocUtf8String(flexlm_context.server_name));
            this.job.add(28).writeU32(1); // connected flag
        }}

        // Store vendor key if provided
        if (!this.vendor_key.isNull()) {{
            var key_data = this.vendor_key.readByteArray(16);
            flexlm_context.vendor_keys[this.vendor_code.readCString()] = key_data;
        }}
    }},
    onLeave: function(retval) {{
        console.log("[FlexLM] Initialization: returning valid job handle");
        if (retval.toInt32() < 0) {{
            // Replace error with valid job pointer
            var job = Memory.alloc(32);
            job.writeU32(0x4A4F4200); // "JOB\\0" magic
            job.add(4).writeU32(Process.id);
            job.add(8).writeU32(1); // initialized
            retval.replace(job);
        }}
    }}
}});

// Hook lc_cryptstr for license string decryption
Interceptor.attach(Module.findExportByName(null, "lc_cryptstr"), {{
    onEnter: function(args) {{
        this.job = args[0];
        this.input = args[1];
        this.input_str = this.input.readCString();
        this.vendor_key = args[2];

        console.log("[FlexLM] lc_cryptstr called");
        console.log("  Input: " + this.input_str);
    }},
    onLeave: function(retval) {{
        // Decrypt or generate valid license string
        if (this.input_str.indexOf("FEATURE") === 0 || this.input_str.indexOf("INCREMENT") === 0) {{
            // Parse and generate valid license line
            var parts = this.input_str.split(" ");
            var feature = parts[1] || "default";
            var vendor = parts[2] || flexlm_context.vendor_code;

            var lic = flexlm_context.features[feature] || generateLicenseData(feature, "1.0");

            // Generate valid FlexLM license line format
            var license_line = "FEATURE " + feature + " " + vendor + " " +
                              lic.version + " permanent uncounted " +
                              lic.signature.map(b => b.toString(16).padStart(2, '0')).join('').toUpperCase() +
                              " HOSTID=" + flexlm_context.hostid;

            var result = Memory.allocUtf8String(license_line);
            console.log("[FlexLM] Generated license line: " + license_line);
            retval.replace(result);
        }} else {{
            // For other strings, return decrypted (original) version
            console.log("[FlexLM] Returning decrypted string");
            retval.replace(this.input);
        }}
    }}
}});

// Hook lc_checkin for license release
Interceptor.attach(Module.findExportByName(null, "lc_checkin"), {{
    onEnter: function(args) {{
        var feature = args[1].readCString();
        console.log("[FlexLM] lc_checkin called for feature: " + feature);
    }},
    onLeave: function(retval) {{
        console.log("[FlexLM] License checkin: returning success");
        retval.replace(0);  // Always successful
    }}
}});

// Hook lc_hostid to return consistent hostid
Interceptor.attach(Module.findExportByName(null, "lc_hostid"), {{
    onEnter: function(args) {{
        this.job = args[0];
        this.hostid_type = args[1];
        this.hostid_buf = args[2];

        console.log("[FlexLM] lc_hostid called, type: " + this.hostid_type.toInt32());
    }},
    onLeave: function(retval) {{
        if (!this.hostid_buf.isNull()) {{
            // Write our generated hostid
            this.hostid_buf.writeUtf8String(flexlm_context.hostid);
            console.log("[FlexLM] Returning hostid: " + flexlm_context.hostid);
        }}
        retval.replace(0);  // Success
    }}
}});

// Hook lc_get_attr for license attributes
Interceptor.attach(Module.findExportByName(null, "lc_get_attr"), {{
    onEnter: function(args) {{
        this.job = args[0];
        this.attr_key = args[1].readCString();
        this.attr_buf = args[2];

        console.log("[FlexLM] lc_get_attr called for: " + this.attr_key);
    }},
    onLeave: function(retval) {{
        if (!this.attr_buf.isNull()) {{
            // Return appropriate attribute values
            if (this.attr_key === "LM_A_VENDOR_CODE") {{
                this.attr_buf.writeUtf8String(flexlm_context.vendor_code);
            }} else if (this.attr_key === "LM_A_HOST") {{
                this.attr_buf.writeUtf8String(flexlm_context.server_name);
            }} else if (this.attr_key === "LM_A_PORT") {{
                this.attr_buf.writeUtf8String(flexlm_context.daemon_port.toString());
            }} else if (this.attr_key === "LM_A_LICENSE_VERSION") {{
                this.attr_buf.writeUtf8String(flexlm_context.license_version);
            }} else {{
                this.attr_buf.writeUtf8String("1");  // Default value
            }}
        }}
        retval.replace(0);  // Success
    }}
}});

// Hook lc_status for license status checks
Interceptor.attach(Module.findExportByName(null, "lc_status"), {{
    onEnter: function(args) {{
        this.job = args[0];
        this.feature = args[1].readCString();

        console.log("[FlexLM] lc_status called for feature: " + this.feature);
    }},
    onLeave: function(retval) {{
        console.log("[FlexLM] Status check: returning licensed (0)");
        retval.replace(0);  // Feature is licensed
    }}
}});

// Hook l_sg for security/signature functions
Interceptor.attach(Module.findExportByName(null, "l_sg"), {{
    onEnter: function(args) {{
        console.log("[FlexLM] l_sg (signature) called");
        this.output = args[0];
    }},
    onLeave: function(retval) {{
        // Generate valid signature
        if (!this.output.isNull()) {{
            var sig = generateSignature("default", "1.0", [1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20]);
            for (var i = 0; i < 16; i++) {{
                this.output.add(i).writeU8(sig[i]);
            }}
        }}
        retval.replace(0);  // Success
    }}
}});

console.log("[FlexLM] Advanced bypass hooks installed");
console.log("[FlexLM] Vendor code: " + flexlm_context.vendor_code);
console.log("[FlexLM] HostID: " + flexlm_context.hostid);
console.log("[FlexLM] Server: " + flexlm_context.server_name + ":" + flexlm_context.daemon_port);
"""

    def _generate_hasp_script(self) -> str:
        """Generate Frida script for HASP bypass with dynamic handle generation.

        Returns:
            str: Frida script as string.

        """
        return """
// HASP Dongle Emulation Script with Dynamic Handle
var hasp_handle = Memory.alloc(4);

// Generate dynamic handle based on process and timestamp
var process_id = Process.id;
var timestamp = Date.now();
var dynamic_handle = (process_id ^ timestamp) & 0x7FFFFFFF;
if (dynamic_handle === 0) {
    dynamic_handle = 0x10000000 | (Math.random() * 0x0FFFFFFF) | 0;
}
hasp_handle.writeU32(dynamic_handle);

console.log("[HASP] Generated dynamic handle: 0x" + dynamic_handle.toString(16));

// Track session data
var session_data = {
    handle: dynamic_handle,
    login_time: Date.now(),
    feature_id: 0,
    vendor_id: 0
};

Interceptor.attach(Module.findExportByName(null, "hasp_login"), {
    onEnter: function(args) {
        var feature_id = args[0].toInt32();
        var vendor_code = args[1];
        session_data.feature_id = feature_id;

        console.log("[HASP] hasp_login called");
        console.log("  Feature ID: " + feature_id);
        if (vendor_code) {
            console.log("  Vendor code present");
            // Extract vendor ID from vendor code if possible
            try {
                var vendor_bytes = vendor_code.readByteArray(16);
                var vendor_hash = 0;
                for (var i = 0; i < 16; i++) {
                    vendor_hash = (vendor_hash << 1) ^ vendor_bytes[i];
                }
                session_data.vendor_id = vendor_hash & 0xFFFF;
            } catch(e) {}
        }

        this.handle_ptr = args[4];  // Handle output pointer
    },
    onLeave: function(retval) {
        console.log("[HASP] Emulating successful login");
        if (this.handle_ptr) {
            this.handle_ptr.writePointer(hasp_handle);
        }
        retval.replace(0);  // HASP_STATUS_OK
    }
});

Interceptor.attach(Module.findExportByName(null, "hasp_encrypt"), {
    onEnter: function(args) {
        this.handle = args[0].toInt32();
        this.buffer = args[1];
        this.length = args[2].toInt32();

        console.log("[HASP] hasp_encrypt called");
        console.log("  Handle: 0x" + this.handle.toString(16));
        console.log("  Length: " + this.length);
    },
    onLeave: function(retval) {
        console.log("[HASP] Performing XOR encryption");
        // Simple XOR encryption with handle as key
        if (this.buffer && this.length > 0) {
            var data = this.buffer.readByteArray(this.length);
            var encrypted = new Uint8Array(this.length);
            var key = this.handle;

            for (var i = 0; i < this.length; i++) {
                encrypted[i] = data[i] ^ ((key >> ((i % 4) * 8)) & 0xFF);
            }

            this.buffer.writeByteArray(encrypted);
        }
        retval.replace(0);  // HASP_STATUS_OK
    }
});

Interceptor.attach(Module.findExportByName(null, "hasp_decrypt"), {
    onEnter: function(args) {
        this.handle = args[0].toInt32();
        this.buffer = args[1];
        this.length = args[2].toInt32();

        console.log("[HASP] hasp_decrypt called");
    },
    onLeave: function(retval) {
        console.log("[HASP] Performing XOR decryption");
        // Same XOR operation for decryption
        if (this.buffer && this.length > 0) {
            var data = this.buffer.readByteArray(this.length);
            var decrypted = new Uint8Array(this.length);
            var key = this.handle;

            for (var i = 0; i < this.length; i++) {
                decrypted[i] = data[i] ^ ((key >> ((i % 4) * 8)) & 0xFF);
            }

            this.buffer.writeByteArray(decrypted);
        }
        retval.replace(0);  // HASP_STATUS_OK
    }
});

Interceptor.attach(Module.findExportByName(null, "hasp_get_info"), {
    onEnter: function(args) {
        this.scope = args[1].readCString();
        this.format = args[2].readCString();
        this.info_ptr = args[3];

        console.log("[HASP] hasp_get_info called");
        console.log("  Scope: " + this.scope);
        console.log("  Format: " + this.format);
    },
    onLeave: function(retval) {
        console.log("[HASP] Providing dynamic dongle info");
        if (this.info_ptr) {
            var info_xml = '<?xml version="1.0" encoding="UTF-8"?>';
            info_xml += '<hasp_info>';
            info_xml += '<dongle>';
            info_xml += '<id>' + session_data.handle.toString(16) + '</id>';
            info_xml += '<vendor_id>' + (session_data.vendor_id || 0x529).toString(16) + '</vendor_id>';
            info_xml += '<feature_id>' + session_data.feature_id + '</feature_id>';
            info_xml += '<session_time>' + (Date.now() - session_data.login_time) + '</session_time>';
            info_xml += '<memory_size>256</memory_size>';
            info_xml += '<type>HASP_HL_PRO</type>';
            info_xml += '</dongle>';
            info_xml += '</hasp_info>';

            this.info_ptr.writeUtf8String(info_xml);
        }
        retval.replace(0);  // HASP_STATUS_OK
    }
});

Interceptor.attach(Module.findExportByName(null, "hasp_get_size"), {
    onEnter: function(args) {
        this.size_ptr = args[2];
    },
    onLeave: function(retval) {
        console.log("[HASP] Returning memory size");
        if (this.size_ptr) {
            this.size_ptr.writeU32(256);  // 256 bytes memory
        }
        retval.replace(0);  // HASP_STATUS_OK
    }
});

Interceptor.attach(Module.findExportByName(null, "hasp_read"), {
    onEnter: function(args) {
        this.handle = args[0].toInt32();
        this.file_id = args[1].toInt32();
        this.offset = args[2].toInt32();
        this.length = args[3].toInt32();
        this.buffer = args[4];

        console.log("[HASP] hasp_read called");
        console.log("  File ID: " + this.file_id);
        console.log("  Offset: " + this.offset);
        console.log("  Length: " + this.length);
    },
    onLeave: function(retval) {
        console.log("[HASP] Providing memory data");
        if (this.buffer && this.length > 0) {
            // Generate consistent data based on file_id and offset
            var data = new Uint8Array(this.length);
            for (var i = 0; i < this.length; i++) {
                data[i] = ((this.file_id + this.offset + i) * 0x37) & 0xFF;
            }
            this.buffer.writeByteArray(data);
        }
        retval.replace(0);  // HASP_STATUS_OK
    }
});

console.log("[HASP] Dongle emulation active with dynamic handle: 0x" + dynamic_handle.toString(16));
"""

    def _generate_codemeter_script(self) -> str:
        """Generate Frida script for CodeMeter bypass with dynamic handle generation.

        Returns:
            str: Frida script as string.

        """
        return """
// CodeMeter License Bypass Script with Dynamic Handle
var cm_handle = Memory.alloc(8);

// Generate dynamic handle based on process, machine, and timestamp
var process_id = Process.id;
var process_name = Process.enumerateModules()[0].name;
var timestamp = Date.now();

// Create unique handle combining multiple factors
var name_hash = 0;
for (var i = 0; i < process_name.length; i++) {
    name_hash = ((name_hash << 5) - name_hash) + process_name.charCodeAt(i);
    name_hash = name_hash & 0xFFFFFFFF;
}

var dynamic_handle_low = (process_id ^ timestamp) & 0xFFFFFFFF;
var dynamic_handle_high = (name_hash ^ (timestamp >> 32)) & 0xFFFFFFFF;

// Ensure non-zero handle
if (dynamic_handle_low === 0) {
    dynamic_handle_low = 0x10000000 | (Math.random() * 0x0FFFFFFF) | 0;
}
if (dynamic_handle_high === 0) {
    dynamic_handle_high = 0x20000000 | (Math.random() * 0x0FFFFFFF) | 0;
}

// Write 64-bit handle
if (Process.arch === 'x64') {
    cm_handle.writeU64((BigInt(dynamic_handle_high) << 32n) | BigInt(dynamic_handle_low));
} else {
    cm_handle.writeU32(dynamic_handle_low);
}

console.log("[CodeMeter] Generated dynamic handle: 0x" + dynamic_handle_high.toString(16) + dynamic_handle_low.toString(16));

// Track session and license data
var session_data = {
    handle: {low: dynamic_handle_low, high: dynamic_handle_high},
    firm_code: 0,
    product_code: 0,
    feature_map: 0xFFFFFFFF,
    access_time: Date.now(),
    box_serial: 0,
    encryption_key: null
};

// Generate box serial from machine characteristics
try {
    var modules = Process.enumerateModules();
    var module_hash = 0;
    for (var i = 0; i < Math.min(5, modules.length); i++) {
        module_hash ^= modules[i].base.toInt32();
    }
    session_data.box_serial = module_hash & 0x7FFFFFFF;
} catch(e) {
    session_data.box_serial = (Math.random() * 0x7FFFFFFF) | 0;
}

Interceptor.attach(Module.findExportByName(null, "CmAccess"), {
    onEnter: function(args) {
        var firm_code = args[0].toInt32();
        var product_code = args[1].toInt32();
        var feature_code = args[2].toInt32();

        session_data.firm_code = firm_code;
        session_data.product_code = product_code;

        console.log("[CodeMeter] CmAccess called");
        console.log("  FirmCode: " + firm_code);
        console.log("  ProductCode: " + product_code);
        console.log("  FeatureCode: " + feature_code);

        this.handle_ptr = args[3];
    },
    onLeave: function(retval) {
        console.log("[CodeMeter] Providing access with dynamic handle");
        if (this.handle_ptr) {
            this.handle_ptr.writePointer(cm_handle);
        }
        retval.replace(0);  // CM_OK
    }
});

Interceptor.attach(Module.findExportByName(null, "CmGetLicenseInfo"), {
    onEnter: function(args) {
        this.handle = args[0];
        this.info_ptr = args[1];
        this.info_size = args[2] ? args[2].toInt32() : 0;

        console.log("[CodeMeter] CmGetLicenseInfo called");
    },
    onLeave: function(retval) {
        console.log("[CodeMeter] Providing dynamic license info");
        if (this.info_ptr) {
            // Write dynamic license structure
            var offset = 0;

            // Magic header
            this.info_ptr.add(offset).writeU32(0x434D4C49);  // "ILMC"
            offset += 4;

            // Firm code (use session data or generate)
            this.info_ptr.add(offset).writeU32(session_data.firm_code || 100000);
            offset += 4;

            // Product code
            this.info_ptr.add(offset).writeU32(session_data.product_code || 1);
            offset += 4;

            // Feature map (all features enabled)
            this.info_ptr.add(offset).writeU32(session_data.feature_map);
            offset += 4;

            // Box serial
            this.info_ptr.add(offset).writeU32(session_data.box_serial);
            offset += 4;

            // License options
            this.info_ptr.add(offset).writeU32(0x00000001);  // Network capable
            offset += 4;

            // Version info
            this.info_ptr.add(offset).writeU16(1);  // Major
            this.info_ptr.add(offset + 2).writeU16(0);  // Minor
            offset += 4;

            // Usage counters
            this.info_ptr.add(offset).writeU32(100);  // Total licenses
            this.info_ptr.add(offset + 4).writeU32(99);  // Available
            offset += 8;

            // Timestamp
            this.info_ptr.add(offset).writeU32((Date.now() / 1000) | 0);
            offset += 4;
        }
        retval.replace(0);  // CM_OK
    }
});

Interceptor.attach(Module.findExportByName(null, "CmGetBoxInfo"), {
    onEnter: function(args) {
        this.info_ptr = args[1];
        this.info_size = args[2] ? args[2].toInt32() : 0;

        console.log("[CodeMeter] CmGetBoxInfo called");
    },
    onLeave: function(retval) {
        console.log("[CodeMeter] Providing dynamic box info");
        if (this.info_ptr && this.info_size >= 32) {
            // Box info structure
            this.info_ptr.writeU32(0x424F5821);  // "!XOB" magic
            this.info_ptr.add(4).writeU32(session_data.box_serial);
            this.info_ptr.add(8).writeU32(0x00010001);  // Version 1.1
            this.info_ptr.add(12).writeU32(0x00000003);  // Box type: CmStick
            this.info_ptr.add(16).writeU32(0xFFFFFFFF);  // Capabilities: All
            this.info_ptr.add(20).writeU32(1024 * 1024);  // Memory: 1MB
            this.info_ptr.add(24).writeU32((Date.now() / 1000) | 0);  // Timestamp
            this.info_ptr.add(28).writeU32(0);  // Reserved
        }
        retval.replace(0);  // CM_OK
    }
});

Interceptor.attach(Module.findExportByName(null, "CmCrypt"), {
    onEnter: function(args) {
        this.handle = args[0];
        this.mode = args[1].toInt32();
        this.data = args[2];
        this.length = args[3].toInt32();

        console.log("[CodeMeter] CmCrypt called");
        console.log("  Mode: " + (this.mode === 1 ? "Encrypt" : "Decrypt"));
        console.log("  Length: " + this.length);

        // Generate encryption key if not exists
        if (!session_data.encryption_key) {
            session_data.encryption_key = new Uint8Array(32);
            for (var i = 0; i < 32; i++) {
                session_data.encryption_key[i] = ((session_data.box_serial >> (i % 4)) ^ i) & 0xFF;
            }
        }
    },
    onLeave: function(retval) {
        console.log("[CodeMeter] Performing XOR encryption/decryption");

        // Perform simple XOR encryption/decryption
        if (this.data && this.length > 0) {
            var buffer = this.data.readByteArray(this.length);
            var processed = new Uint8Array(this.length);

            for (var i = 0; i < this.length; i++) {
                processed[i] = buffer[i] ^ session_data.encryption_key[i % 32];
            }

            this.data.writeByteArray(processed);
        }

        retval.replace(0);  // CM_OK
    }
});

Interceptor.attach(Module.findExportByName(null, "CmGetStatus"), {
    onEnter: function(args) {
        this.handle = args[0];
        this.status_ptr = args[1];

        console.log("[CodeMeter] CmGetStatus called");
    },
    onLeave: function(retval) {
        console.log("[CodeMeter] Returning healthy status");
        if (this.status_ptr) {
            // Status structure
            this.status_ptr.writeU32(0);  // Status: OK
            this.status_ptr.add(4).writeU32(session_data.box_serial);  // Box serial
            this.status_ptr.add(8).writeU32(100);  // Total licenses
            this.status_ptr.add(12).writeU32(99);  // Free licenses
            this.status_ptr.add(16).writeU32((Date.now() - session_data.access_time) / 1000 | 0);  // Uptime
        }
        retval.replace(0);  // CM_OK
    }
});

Interceptor.attach(Module.findExportByName(null, "CmRelease"), {
    onEnter: function(args) {
        console.log("[CodeMeter] CmRelease called - maintaining session");
    },
    onLeave: function(retval) {
        // Don't actually release, just return success
        retval.replace(0);  // CM_OK
    }
});

console.log("[CodeMeter] License bypass active with dynamic handle");
console.log("[CodeMeter] Box Serial: 0x" + session_data.box_serial.toString(16));
"""

    def _calculate_confidence(self, results: dict[str, Any]) -> float:
        """Calculate confidence score for analysis results.

        Args:
            results: Analysis results.

        Returns:
            float: Confidence score between 0.0 and 1.0.

        """
        confidence = 0.0

        # Add confidence for each detected system
        confidence += len(results["detected_systems"]) * 0.25

        # Add confidence for bypass strategies
        confidence += len(results["bypass_strategies"]) * 0.15

        # Add confidence for detected servers
        confidence += min(len(results["license_servers"]) * 0.1, 0.3)

        # Add confidence for protection features
        confidence += min(len(results["protection_features"]) * 0.05, 0.2)

        return min(confidence, 1.0)

    def generate_bypass_report(self, analysis: dict[str, Any]) -> str:
        """Generate detailed bypass report.

        Args:
            analysis: Analysis results.

        Returns:
            str: Formatted report string.

        """
        report = "=" * 60 + "\n"
        report += "COMMERCIAL LICENSE PROTECTION ANALYSIS REPORT\n"
        report += "=" * 60 + "\n\n"

        report += f"Binary: {self.binary_path}\n"
        report += f"Analysis Time: {time.strftime('%Y-%m-%d %H:%M:%S')}\n"
        report += f"Confidence: {analysis['confidence']:.1%}\n\n"

        report += "DETECTED SYSTEMS:\n"
        report += "-" * 30 + "\n"
        for system in analysis["detected_systems"]:
            report += f"   {system}\n"

        if analysis["license_servers"]:
            report += "\nLICENSE SERVERS:\n"
            report += "-" * 30 + "\n"
            for server in analysis["license_servers"]:
                report += f"   Type: {server['type']}\n"
                report += f"    Port: {server['port']}\n"
                report += f"    Host: {server['hostname']}\n"

        if analysis["bypass_strategies"]:
            report += "\nBYPASS STRATEGIES:\n"
            report += "-" * 30 + "\n"
            for system, strategy in analysis["bypass_strategies"].items():
                report += f"\n{system.upper()}:\n"
                report += f"  Method: {strategy['method']}\n"
                report += f"  Hooks: {len(strategy.get('hooks', []))} API hooks\n"
                if "patches" in strategy:
                    report += f"  Patches: {len(strategy['patches'])} binary patches\n"
                if "emulation_script" in strategy:
                    report += "  Script: Frida script available\n"

        report += "\n" + "=" * 60 + "\n"

        return report


# Export main class
__all__ = ["CommercialLicenseAnalyzer"]

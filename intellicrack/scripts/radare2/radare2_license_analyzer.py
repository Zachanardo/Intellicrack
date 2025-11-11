#!/usr/bin/env python3
"""Radare2 license analyzer script for Intellicrack.

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
import struct
import sys
from collections import defaultdict
from dataclasses import dataclass, field
from enum import Enum

# Third-party imports
import networkx as nx
import r2pipe

"""
Radare2 License Analyzer Module

Comprehensive license detection and analysis for Radare2, providing automated
identification of license validation routines with machine learning-enhanced
pattern recognition and behavioral analysis.

Author: Intellicrack Framework
Version: 2.0.0
License: GPL v3
"""


class LicenseType(Enum):
    """Types of license validation mechanisms."""

    SERIAL_KEY = "serial_key"
    ONLINE = "online_validation"
    HARDWARE = "hardware_locked"
    TIME_TRIAL = "time_trial"
    FEATURE_LOCK = "feature_locked"
    CRYPTO_SIGNATURE = "cryptographic"
    CUSTOM = "custom_implementation"


class ProtectionLevel(Enum):
    """License protection complexity levels."""

    BASIC = 1  # Simple checks, easily bypassable
    MODERATE = 2  # Some obfuscation, multiple checks
    ADVANCED = 3  # Strong crypto, anti-debug
    EXTREME = 4  # VM protection, custom crypto


@dataclass
class LicenseFunction:
    """Represents a detected license validation function."""

    address: int
    name: str
    size: int
    type: LicenseType
    confidence: float
    protection_level: ProtectionLevel
    cross_refs: list[int] = field(default_factory=list)
    strings: list[str] = field(default_factory=list)
    constants: list[int] = field(default_factory=list)
    api_calls: list[str] = field(default_factory=list)
    bypass_strategies: list[str] = field(default_factory=list)


class R2LicenseAnalyzer:
    """Advanced license analysis engine for Radare2."""

    # Pattern weights for ML-based detection
    PATTERN_WEIGHTS = {
        # Function name patterns
        "function_names": {
            "license": 0.9,
            "licence": 0.9,
            "activation": 0.85,
            "registration": 0.8,
            "validate": 0.75,
            "verify": 0.75,
            "check": 0.7,
            "authenticate": 0.8,
            "authorize": 0.8,
            "trial": 0.85,
            "demo": 0.8,
            "eval": 0.75,
            "expire": 0.9,
            "serial": 0.8,
            "key": 0.65,
            "unlock": 0.8,
            "crack": -0.9,  # Negative weight for anti-crack
            "patch": -0.8,
        },
        # String patterns
        "strings": {
            "Invalid license": 0.95,
            "License expired": 0.95,
            "Trial period": 0.9,
            "Demo version": 0.9,
            "Please register": 0.9,
            "Activation failed": 0.9,
            "Product key": 0.85,
            "Serial number": 0.85,
            "Thank you for purchasing": 0.9,
            "Unregistered": 0.85,
            "days remaining": 0.85,
            "Hardware ID": 0.8,
            "Machine code": 0.8,
            "License file": 0.85,
            "HKEY_LOCAL_MACHINE": 0.7,
            "Software\\": 0.6,
        },
        # API patterns
        "apis": {
            "RegOpenKeyEx": 0.7,
            "RegQueryValueEx": 0.8,
            "GetVolumeInformation": 0.8,
            "GetComputerName": 0.7,
            "CryptHashData": 0.8,
            "InternetConnect": 0.85,
            "HttpSendRequest": 0.9,
            "GetSystemTime": 0.6,
            "GetLocalTime": 0.6,
            "MessageBox": 0.5,
            "ExitProcess": 0.7,
            "CreateFile": 0.6,
            "ReadFile": 0.6,
            "IsDebuggerPresent": 0.7,
        },
        # Crypto patterns
        "crypto": {
            "MD5": 0.8,
            "SHA": 0.8,
            "RSA": 0.85,
            "AES": 0.85,
            "Base64": 0.7,
            "CRC32": 0.7,
        },
    }

    def __init__(self, r2: r2pipe.open = None, filename: str = None) -> None:
        """Initialize the license analyzer."""
        self.r2 = r2 if r2 else r2pipe.open(filename)
        self.license_functions: list[LicenseFunction] = []
        self.call_graph = nx.DiGraph()
        self.string_refs: dict[int, list[str]] = defaultdict(list)
        self.api_refs: dict[int, list[str]] = defaultdict(list)
        self.crypto_locations: dict[str, list[int]] = defaultdict(list)
        self.logger = logging.getLogger(f"{__name__}.R2LicenseAnalyzer")

        # Initialize analysis
        self._init_analysis()

    def _init_analysis(self) -> None:
        """Initialize r2 analysis."""
        print("[*] Initializing Radare2 analysis...")

        # Analyze all
        self.r2.cmd("aaa")

        # Get binary info
        self.info = self.r2.cmdj("ij")
        self.arch = self.info.get("bin", {}).get("arch", "unknown")
        self.bits = self.info.get("bin", {}).get("bits", 32)

        # Load strings
        self._load_strings()

        # Load imports
        self._load_imports()

        # Build call graph
        self._build_call_graph()

    def _load_strings(self) -> None:
        """Load and categorize strings."""
        print("[*] Loading strings...")

        strings = self.r2.cmdj("izj")
        if not strings:
            return

        for s in strings:
            string_val = s.get("string", "")
            vaddr = s.get("vaddr", 0)

            # Find xrefs to this string
            xrefs = self.r2.cmdj(f"axtj @ {vaddr}")
            for xref in xrefs:
                func_addr = self._get_function_at(xref.get("from", 0))
                if func_addr:
                    self.string_refs[func_addr].append(string_val)

    def _load_imports(self) -> None:
        """Load and categorize imports."""
        print("[*] Loading imports...")

        imports = self.r2.cmdj("iij")
        if not imports:
            return

        for imp in imports:
            name = imp.get("name", "")
            plt_addr = imp.get("plt", 0)

            if plt_addr:
                # Find xrefs to this import
                xrefs = self.r2.cmdj(f"axtj @ {plt_addr}")
                for xref in xrefs:
                    func_addr = self._get_function_at(xref.get("from", 0))
                    if func_addr:
                        self.api_refs[func_addr].append(name)

    def _build_call_graph(self) -> None:
        """Build function call graph."""
        print("[*] Building call graph...")

        functions = self.r2.cmdj("aflj")
        if not functions:
            return

        for func in functions:
            addr = func.get("offset", 0)
            self.call_graph.add_node(addr, **func)

            # Get calls from this function
            calls = self.r2.cmdj(f"afcfj @ {addr}")
            if calls:
                for callee in calls:
                    self.call_graph.add_edge(addr, callee)

    def _get_function_at(self, addr: int) -> int | None:
        """Get function containing address."""
        result = self.r2.cmd(f"afi. @ {addr}")
        if result and result.strip():
            try:
                # Extract function address from output
                lines = result.strip().split("\n")
                for line in lines:
                    if line.startswith("offset:"):
                        return int(line.split()[1], 16)
            except Exception as e:
                self.logger.debug("Error finding license check offset: %s", e)
        return None

    def analyze(self) -> list[LicenseFunction]:
        """Perform comprehensive license analysis."""
        print("\n[*] Starting license function detection...")

        # Phase 1: Function name analysis
        self._analyze_function_names()

        # Phase 2: String reference analysis
        self._analyze_string_references()

        # Phase 3: API call analysis
        self._analyze_api_calls()

        # Phase 4: Control flow analysis
        self._analyze_control_flow()

        # Phase 5: Cryptographic detection
        self._detect_crypto_operations()

        # Phase 6: Pattern matching
        self._pattern_matching()

        # Phase 7: Generate bypass strategies
        self._generate_bypass_strategies()

        # Sort by confidence
        self.license_functions.sort(key=lambda x: x.confidence, reverse=True)

        return self.license_functions

    def _analyze_function_names(self) -> None:
        """Analyze function names for license patterns."""
        print("[*] Analyzing function names...")

        functions = self.r2.cmdj("aflj")
        if not functions:
            return

        for func in functions:
            name = func.get("name", "")
            addr = func.get("offset", 0)
            size = func.get("size", 0)

            # Calculate name score
            score = self._calculate_name_score(name)

            if score > 0.5:
                lic_func = LicenseFunction(
                    address=addr,
                    name=name,
                    size=size,
                    type=LicenseType.CUSTOM,
                    confidence=score,
                    protection_level=ProtectionLevel.BASIC,
                )
                self.license_functions.append(lic_func)

    def _calculate_name_score(self, name: str) -> float:
        """Calculate license probability based on function name."""
        name_lower = name.lower()
        score = 0.0
        matches = 0

        for pattern, weight in self.PATTERN_WEIGHTS["function_names"].items():
            if pattern in name_lower:
                score += weight
                matches += 1

        # Normalize score
        if matches > 0:
            score = score / matches

        return max(0.0, min(1.0, score))

    def _analyze_string_references(self) -> None:
        """Analyze string references in functions."""
        print("[*] Analyzing string references...")

        # Check existing license functions
        for lic_func in self.license_functions:
            strings = self.string_refs.get(lic_func.address, [])
            lic_func.strings = strings

            # Update score based on strings
            string_score = self._calculate_string_score(strings)
            lic_func.confidence = (lic_func.confidence + string_score) / 2

        # Check other functions with high string scores
        for addr, strings in self.string_refs.items():
            if not any(f.address == addr for f in self.license_functions):
                score = self._calculate_string_score(strings)

                if score > 0.6:
                    func_info = self.call_graph.nodes.get(addr, {})

                    lic_func = LicenseFunction(
                        address=addr,
                        name=func_info.get("name", f"sub_{addr:x}"),
                        size=func_info.get("size", 0),
                        type=self._determine_license_type(strings),
                        confidence=score,
                        protection_level=ProtectionLevel.MODERATE,
                        strings=strings,
                    )
                    self.license_functions.append(lic_func)

    def _calculate_string_score(self, strings: list[str]) -> float:
        """Calculate license probability based on strings."""
        if not strings:
            return 0.0

        total_score = 0.0
        matches = 0

        for string in strings:
            for pattern, weight in self.PATTERN_WEIGHTS["strings"].items():
                if pattern.lower() in string.lower():
                    total_score += weight
                    matches += 1

        # Normalize
        if matches > 0:
            return min(1.0, total_score / len(strings))

        return 0.0

    def _determine_license_type(self, indicators: list[str]) -> LicenseType:
        """Determine license type from indicators."""
        indicators_lower = " ".join(indicators).lower()

        if any(x in indicators_lower for x in ["serial", "key", "product key"]):
            return LicenseType.SERIAL_KEY
        if any(x in indicators_lower for x in ["online", "server", "internet", "http"]):
            return LicenseType.ONLINE
        if any(x in indicators_lower for x in ["hardware", "hwid", "machine", "computer"]):
            return LicenseType.HARDWARE
        if any(x in indicators_lower for x in ["trial", "days", "expire", "time"]):
            return LicenseType.TIME_TRIAL
        if any(x in indicators_lower for x in ["feature", "unlock", "enable"]):
            return LicenseType.FEATURE_LOCK
        if any(x in indicators_lower for x in ["rsa", "aes", "signature", "crypt"]):
            return LicenseType.CRYPTO_SIGNATURE
        return LicenseType.CUSTOM

    def _analyze_api_calls(self) -> None:
        """Analyze API calls in functions."""
        print("[*] Analyzing API calls...")

        # Update existing functions
        for lic_func in self.license_functions:
            apis = self.api_refs.get(lic_func.address, [])
            lic_func.api_calls = apis

            # Update score based on APIs
            api_score = self._calculate_api_score(apis)
            lic_func.confidence = (lic_func.confidence * 2 + api_score) / 3

            # Update protection level based on APIs
            if any("IsDebuggerPresent" in api for api in apis):
                lic_func.protection_level = ProtectionLevel.ADVANCED

    def _calculate_api_score(self, apis: list[str]) -> float:
        """Calculate license probability based on API calls."""
        if not apis:
            return 0.0

        total_score = 0.0
        matches = 0

        for api in apis:
            for pattern, weight in self.PATTERN_WEIGHTS["apis"].items():
                if pattern in api:
                    total_score += weight
                    matches += 1

        if matches > 0:
            return min(1.0, total_score / len(apis))

        return 0.0

    def _analyze_control_flow(self) -> None:
        """Analyze control flow complexity."""
        print("[*] Analyzing control flow patterns...")

        for lic_func in self.license_functions:
            # Get function basic blocks
            blocks = self.r2.cmdj(f"afbj @ {lic_func.address}")
            if not blocks:
                continue

            # Calculate cyclomatic complexity
            num_blocks = len(blocks)
            num_edges = sum(len(b.get("jump", [])) + len(b.get("fail", [])) for b in blocks)

            complexity = num_edges - num_blocks + 2

            # License functions typically have moderate complexity
            if 5 <= complexity <= 50:
                lic_func.confidence *= 1.1
            elif complexity > 100:
                # Too complex, might be obfuscated
                lic_func.protection_level = ProtectionLevel.EXTREME

            # Look for specific patterns
            if self._has_license_control_pattern(blocks):
                lic_func.confidence *= 1.2

    def _has_license_control_pattern(self, blocks: list[dict]) -> bool:
        """Check for common license validation patterns."""
        if len(blocks) < 3:
            return False

        # Look for multiple return paths
        return_blocks = [b for b in blocks if b.get("ninstr", 0) > 0 and any("ret" in str(b.get("disasm", "")) for b in blocks)]

        # License functions often have multiple returns (success/failure)
        return len(return_blocks) >= 2

    def _detect_crypto_operations(self) -> None:
        """Detect cryptographic operations."""
        print("[*] Detecting cryptographic operations...")

        # Search for crypto constants
        crypto_constants = {
            "MD5": [0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476],
            "SHA1": [0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0],
            "SHA256": [0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A],
            "AES_SBOX": [0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5],
        }

        for name, constants in crypto_constants.items():
            self._search_crypto_constants(name, constants)

        # Update license functions with crypto info
        for lic_func in self.license_functions:
            for _crypto_type, locations in self.crypto_locations.items():
                if any(lic_func.address <= loc <= lic_func.address + lic_func.size for loc in locations):
                    lic_func.type = LicenseType.CRYPTO_SIGNATURE
                    lic_func.protection_level = ProtectionLevel.ADVANCED
                    lic_func.confidence = min(1.0, lic_func.confidence * 1.3)

    def _search_crypto_constants(self, name: str, constants: list[int]) -> None:
        """Search for cryptographic constants."""
        for const in constants:
            # Search in different formats
            search_patterns = [
                f"{const:08x}",  # Hex
                struct.pack("<I", const).hex(),  # Little endian
                struct.pack(">I", const).hex(),  # Big endian
            ]

            for pattern in search_patterns:
                results = self.r2.cmd(f"/x {pattern}")
                if results:
                    for line in results.strip().split("\n"):
                        if line.startswith("0x"):
                            addr = int(line.split()[0], 16)
                            self.crypto_locations[name].append(addr)

    def _pattern_matching(self) -> None:
        """Advanced pattern matching for license functions."""
        print("[*] Performing pattern matching...")

        # Common license validation patterns
        patterns = [
            # Registry access pattern
            {
                "apis": ["RegOpenKeyEx", "RegQueryValueEx"],
                "strings": ["Software\\", "License"],
                "type": LicenseType.SERIAL_KEY,
            },
            # Network validation pattern
            {
                "apis": ["InternetConnect", "HttpSendRequest"],
                "strings": ["license", "validate", "server"],
                "type": LicenseType.ONLINE,
            },
            # Hardware ID pattern
            {
                "apis": ["GetVolumeInformation", "GetComputerName"],
                "strings": ["hardware", "machine", "id"],
                "type": LicenseType.HARDWARE,
            },
            # Time trial pattern
            {
                "apis": ["GetSystemTime", "GetLocalTime"],
                "strings": ["trial", "expire", "days"],
                "type": LicenseType.TIME_TRIAL,
            },
        ]

        # Check each pattern
        for pattern in patterns:
            self._check_pattern(pattern)

    def _check_pattern(self, pattern: dict) -> None:
        """Check if pattern matches any function."""
        required_apis = set(pattern.get("apis", []))
        required_strings = set(pattern.get("strings", []))
        license_type = pattern.get("type", LicenseType.CUSTOM)

        for addr, apis in self.api_refs.items():
            api_set = set(apis)
            strings = self.string_refs.get(addr, [])
            string_text = " ".join(strings).lower()

            # Check if APIs match
            if required_apis and not required_apis.intersection(api_set):
                continue

            # Check if strings match
            string_match = any(s.lower() in string_text for s in required_strings)

            if string_match or (required_apis and required_apis.issubset(api_set)):
                # Found a match
                existing = next((f for f in self.license_functions if f.address == addr), None)

                if existing:
                    existing.type = license_type
                    existing.confidence = min(1.0, existing.confidence * 1.2)
                else:
                    func_info = self.call_graph.nodes.get(addr, {})

                    lic_func = LicenseFunction(
                        address=addr,
                        name=func_info.get("name", f"sub_{addr:x}"),
                        size=func_info.get("size", 0),
                        type=license_type,
                        confidence=0.8,
                        protection_level=ProtectionLevel.MODERATE,
                        strings=strings,
                        api_calls=list(apis),
                    )
                    self.license_functions.append(lic_func)

    def _generate_bypass_strategies(self) -> None:
        """Generate bypass strategies for each license function."""
        print("[*] Generating bypass strategies...")

        for lic_func in self.license_functions:
            strategies = []

            # Basic patching strategies
            strategies.append(f"Patch at 0x{lic_func.address:x}: Change conditional jump to unconditional")
            strategies.append(f"NOP critical validation code at 0x{lic_func.address:x}")

            # Type-specific strategies
            if lic_func.type == LicenseType.SERIAL_KEY:
                strategies.append("Patch string comparison to always return equal")
                strategies.append("Hook key validation function to return success")

            elif lic_func.type == LicenseType.ONLINE:
                strategies.append("Redirect network calls to local server")
                strategies.append("Patch out network validation entirely")

            elif lic_func.type == LicenseType.HARDWARE:
                strategies.append("Spoof hardware ID generation")
                strategies.append("Patch hardware comparison logic")

            elif lic_func.type == LicenseType.TIME_TRIAL:
                strategies.append("Freeze or extend trial period")
                strategies.append("Patch time comparison to always pass")

            elif lic_func.type == LicenseType.CRYPTO_SIGNATURE:
                strategies.append("Replace public key with known key")
                strategies.append("Patch signature verification to succeed")

            # Protection level specific
            if lic_func.protection_level == ProtectionLevel.ADVANCED:
                strategies.append("May require unpacking/devirtualization first")
                strategies.append("Consider using dynamic patching with Frida")

            lic_func.bypass_strategies = strategies

    def export_report(self, output_file: str = "license_analysis.json") -> None:
        """Export analysis results."""
        report = {
            "binary": self.info.get("bin", {}).get("file", "unknown"),
            "arch": self.arch,
            "bits": self.bits,
            "total_functions_analyzed": len(self.call_graph.nodes),
            "license_functions_found": len(self.license_functions),
            "functions": [],
        }

        for lic_func in self.license_functions:
            func_data = {
                "address": f"0x{lic_func.address:x}",
                "name": lic_func.name,
                "size": lic_func.size,
                "type": lic_func.type.value,
                "confidence": lic_func.confidence,
                "protection_level": lic_func.protection_level.value,
                "strings": lic_func.strings,
                "api_calls": lic_func.api_calls,
                "bypass_strategies": lic_func.bypass_strategies,
            }
            report["functions"].append(func_data)

        with open(output_file, "w") as f:
            json.dump(report, f, indent=2)

        print(f"\n[+] Report exported to {output_file}")

    def generate_r2_script(self, output_file: str = "patch_license.r2") -> None:
        """Generate r2 patching script."""
        with open(output_file, "w") as f:
            f.write("# Radare2 License Patch Script\n")
            f.write("# Generated by Intellicrack License Analyzer\n\n")

            for lic_func in self.license_functions:
                if lic_func.confidence < 0.7:
                    continue

                f.write(f"\n# {lic_func.name} - {lic_func.type.value}\n")
                f.write(f"# Confidence: {lic_func.confidence:.2f}\n")

                # Find first conditional jump
                disasm = self.r2.cmd(f"pd 20 @ {lic_func.address}")

                for line in disasm.split("\n"):
                    if any(jmp in line for jmp in ["je", "jne", "jz", "jnz", "ja", "jb"]):
                        # Extract address
                        parts = line.split()
                        if len(parts) > 0 and parts[0].startswith("0x"):
                            jmp_addr = int(parts[0], 16)

                            # Generate patch
                            f.write(f"# Patch conditional jump at 0x{jmp_addr:x}\n")
                            f.write(f"wa jmp @ 0x{jmp_addr:x}\n")
                            break

        print(f"[+] R2 script generated: {output_file}")

    def interactive_analysis(self) -> None:
        """Interactive analysis mode."""
        print("\n=== Interactive License Analysis ===")

        while True:
            print("\nOptions:")
            print("1. List detected license functions")
            print("2. Analyze specific function")
            print("3. Generate patches")
            print("4. Export report")
            print("5. Exit")

            choice = input("\nChoice: ")

            if choice == "1":
                self._list_functions()
            elif choice == "2":
                self._analyze_specific()
            elif choice == "3":
                self._generate_patches()
            elif choice == "4":
                self.export_report()
            elif choice == "5":
                break

    def _list_functions(self) -> None:
        """List detected license functions."""
        print("\nDetected License Functions:")
        print("-" * 80)

        for i, lic_func in enumerate(self.license_functions):
            print(f"{i + 1}. 0x{lic_func.address:08x} - {lic_func.name}")
            print(f"   Type: {lic_func.type.value}")
            print(f"   Confidence: {lic_func.confidence:.2%}")
            print(f"   Protection: {lic_func.protection_level.name}")

    def _analyze_specific(self) -> None:
        """Analyze specific function in detail."""
        idx = int(input("Function number: ")) - 1

        if 0 <= idx < len(self.license_functions):
            lic_func = self.license_functions[idx]

            print(f"\n=== Detailed Analysis: {lic_func.name} ===")
            print(f"Address: 0x{lic_func.address:08x}")
            print(f"Size: {lic_func.size} bytes")
            print(f"Type: {lic_func.type.value}")
            print(f"Confidence: {lic_func.confidence:.2%}")

            print("\nStrings:")
            for s in lic_func.strings[:10]:
                print(f"  - {s}")

            print("\nAPI Calls:")
            for api in lic_func.api_calls[:10]:
                print(f"  - {api}")

            print("\nBypass Strategies:")
            for strategy in lic_func.bypass_strategies:
                print(f"  - {strategy}")

            # Show disassembly
            print("\nDisassembly (first 20 instructions):")
            print(self.r2.cmd(f"pd 20 @ {lic_func.address}"))

    def _generate_patches(self) -> None:
        """Generate patches interactively."""
        print("\nGenerating patches...")

        self.generate_r2_script()

        # Also generate binary patches
        patches = []

        for lic_func in self.license_functions:
            if lic_func.confidence < 0.7:
                continue

            # Simple patch: change first conditional jump
            patch_addr, patch_bytes = self._find_patch_location(lic_func)

            if patch_addr:
                patches.append(
                    {
                        "address": patch_addr,
                        "original": patch_bytes,
                        "patched": b"\x90" * len(patch_bytes),  # NOP
                        "function": lic_func.name,
                    },
                )

        print(f"\nGenerated {len(patches)} patches")

        # Save patches
        with open("patches.json", "w") as f:
            json.dump(
                [
                    {
                        "address": f"0x{p['address']:x}",
                        "original": p["original"].hex(),
                        "patched": p["patched"].hex(),
                        "function": p["function"],
                    }
                    for p in patches
                ],
                f,
                indent=2,
            )

    def _find_patch_location(self, lic_func: LicenseFunction) -> tuple[int | None, bytes | None]:
        """Find optimal patch location using capstone disassembly."""
        # Get function bytes
        func_bytes = self.r2.cmdj(f"p8j {lic_func.size} @ {lic_func.address}")

        if not func_bytes:
            return None, None

        # Use capstone for proper disassembly and instruction analysis
        try:
            import capstone

            # Determine architecture mode
            if self.arch == "x86":
                if self.bits == 64:
                    md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
                else:
                    md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
            elif self.arch == "arm":
                if self.bits == 64:
                    md = capstone.Cs(capstone.CS_ARCH_ARM64, capstone.CS_MODE_ARM)
                else:
                    md = capstone.Cs(capstone.CS_ARCH_ARM, capstone.CS_MODE_ARM)
            elif self.arch == "mips":
                md = capstone.Cs(capstone.CS_ARCH_MIPS, capstone.CS_MODE_MIPS32)
            else:
                # Fallback to raw byte scanning for unsupported architectures
                return self._find_patch_location_fallback(lic_func, func_bytes)

            md.detail = True

            # Disassemble function and find first conditional jump
            for insn in md.disasm(bytes(func_bytes), lic_func.address):
                # Check for conditional jump instructions
                if insn.group(capstone.CS_GRP_JUMP):
                    # Verify it's a conditional jump (not unconditional)
                    if self.arch == "x86":
                        # x86 conditional jumps
                        if insn.mnemonic in ["je", "jne", "jz", "jnz", "jg", "jl", "jge", "jle", "ja", "jb", "jae", "jbe", "jp", "jnp", "jo", "jno", "js", "jns"]:
                            # Return the instruction address and bytes
                            return insn.address, insn.bytes
                    elif self.arch == "arm":
                        # ARM conditional branches (check condition codes)
                        if insn.mnemonic.startswith("b") and insn.mnemonic not in ["b", "bl", "blx"]:
                            return insn.address, insn.bytes
                    elif self.arch == "mips":
                        # MIPS conditional branches
                        if insn.mnemonic in ["beq", "bne", "bgtz", "blez", "bltz", "bgez"]:
                            return insn.address, insn.bytes

        except ImportError:
            self.logger.debug("Capstone not available, using fallback instruction detection")
            return self._find_patch_location_fallback(lic_func, func_bytes)
        except Exception as e:
            self.logger.error(f"Error in capstone disassembly: {e}")
            return self._find_patch_location_fallback(lic_func, func_bytes)

        return None, None

    def _find_patch_location_fallback(self, lic_func: LicenseFunction, func_bytes: list) -> tuple[int | None, bytes | None]:
        """Fallback instruction detection without capstone using opcode patterns."""
        if self.arch == "x86":
            # x86/x64 conditional jump opcodes
            jump_opcodes = {
                0x74: 2,  # JE/JZ (short)
                0x75: 2,  # JNE/JNZ (short)
                0x76: 2,  # JBE/JNA (short)
                0x77: 2,  # JA/JNBE (short)
                0x78: 2,  # JS (short)
                0x79: 2,  # JNS (short)
                0x7A: 2,  # JP/JPE (short)
                0x7B: 2,  # JNP/JPO (short)
                0x7C: 2,  # JL/JNGE (short)
                0x7D: 2,  # JGE/JNL (short)
                0x7E: 2,  # JLE/JNG (short)
                0x7F: 2,  # JG/JNLE (short)
                0xE0: 2,  # LOOPNE (short)
                0xE1: 2,  # LOOPE (short)
                0xE2: 2,  # LOOP (short)
                0xE3: 2,  # JCXZ/JECXZ (short)
            }

            # Check for 0F prefix (long conditional jumps)
            for i in range(len(func_bytes) - 1):
                if func_bytes[i] == 0x0F:
                    next_byte = func_bytes[i + 1]
                    # Long conditional jumps (0F 8x)
                    if 0x80 <= next_byte <= 0x8F:
                        return lic_func.address + i, bytes(func_bytes[i : i + 6])

            # Check for short conditional jumps
            for i, byte in enumerate(func_bytes):
                if byte in jump_opcodes:
                    size = jump_opcodes[byte]
                    if i + size <= len(func_bytes):
                        return lic_func.address + i, bytes(func_bytes[i : i + size])

        elif self.arch == "arm":
            # ARM conditional branch detection (simplified)
            # ARM instructions are 4 bytes, conditions in top 4 bits
            for i in range(0, len(func_bytes) - 3, 4):
                word = int.from_bytes(bytes(func_bytes[i : i + 4]), "little")
                # Check for branch instruction (bits 27-25 = 101)
                if (word >> 25) & 0x7 == 0x5:
                    # Check condition field (bits 31-28) - not always (0xE)
                    condition = (word >> 28) & 0xF
                    if condition != 0xE:  # Not unconditional
                        return lic_func.address + i, bytes(func_bytes[i : i + 4])

        return None, None


def main() -> None:
    """Run the Radare2 license analyzer."""
    if len(sys.argv) < 2:
        print("Usage: radare2_license_analyzer.py <binary>")
        sys.exit(1)

    binary = sys.argv[1]

    print(f"[*] Analyzing {binary}")

    # Create analyzer
    analyzer = R2LicenseAnalyzer(filename=binary)

    # Run analysis
    results = analyzer.analyze()

    print(f"\n[+] Found {len(results)} potential license functions")

    # Show top results
    print("\nTop License Functions:")
    print("-" * 80)

    for func in results[:10]:
        print(f"0x{func.address:08x} - {func.name}")
        print(f"  Type: {func.type.value}")
        print(f"  Confidence: {func.confidence:.2%}")
        print(f"  Protection: {func.protection_level.name}")

    # Export report
    analyzer.export_report()

    # Generate r2 script
    analyzer.generate_r2_script()

    # Interactive mode
    if input("\nEnter interactive mode? (y/n): ").lower() == "y":
        analyzer.interactive_analysis()

    print("\n[+] Analysis complete!")


if __name__ == "__main__":
    main()

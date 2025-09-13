"""This file is part of Intellicrack.
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

import logging
from typing import Any, Dict, List

from .bypass_base import MitigationBypassBase


class CFIBypass(MitigationBypassBase):
    """Control Flow Integrity bypass techniques."""

    def __init__(self):
        """Initialize CFI bypass with available techniques."""
        super().__init__("CFI")
        self.logger = logging.getLogger(__name__)
        self.rop_gadgets = []
        self.jop_gadgets = []

    def _initialize_techniques(self) -> None:
        """Initialize CFI bypass techniques."""
        self.techniques = [
            "legitimate_targets",
            "jop_gadgets",
            "indirect_branches",
            "vtable_hijacking",
            "return_oriented",
            "backward_edge_bypass",
            "forward_edge_bypass",
        ]

    def get_recommended_technique(self, binary_info: Dict[str, Any]) -> str:
        """Get recommended CFI bypass technique based on binary analysis."""
        security_features = binary_info.get("security_features", [])
        binary_info.get("architecture", "")

        # Check CFI implementation type
        if "intel_cet" in security_features:
            return "legitimate_targets"  # Hardware CFI is harder to bypass
        elif "clang_cfi" in security_features:
            return "jop_gadgets"  # Clang CFI vulnerable to JOP
        elif "gcc_cfi" in security_features:
            return "indirect_branches"  # GCC CFI has weaker branch protection
        else:
            return "vtable_hijacking"  # Default for C++ targets

    def analyze_cfi_protection(self, binary_data: bytes) -> Dict[str, Any]:
        """Analyze CFI protection mechanisms in binary."""
        results = {
            "cfi_enabled": False,
            "cfi_type": None,
            "protection_level": "none",
            "bypass_opportunities": [],
            "analysis": {},
        }

        try:
            self.logger.info("Analyzing CFI protection mechanisms")

            # Check for CFI markers
            cfi_markers = self._check_cfi_markers(binary_data)
            results["analysis"]["markers"] = cfi_markers

            if cfi_markers["found"]:
                results["cfi_enabled"] = True
                results["cfi_type"] = cfi_markers["type"]
                results["protection_level"] = cfi_markers["level"]

            # Analyze indirect calls
            indirect_calls = self._analyze_indirect_calls(binary_data)
            results["analysis"]["indirect_calls"] = indirect_calls

            # Find potential bypass targets
            bypass_targets = self._find_bypass_targets(binary_data)
            results["bypass_opportunities"] = bypass_targets

            # Calculate bypass difficulty
            results["bypass_difficulty"] = self._calculate_bypass_difficulty(results)

            return results

        except Exception as e:
            self.logger.error(f"CFI analysis failed: {e}")
            return results

    def generate_bypass_payload(self, target_binary: bytes, technique: str = "jop_gadgets") -> Dict[str, Any]:
        """Generate CFI bypass payload."""
        payload_info = {
            "payload": b"",
            "technique": technique,
            "success_probability": 0.0,
            "requirements": [],
            "metadata": {},
        }

        try:
            self.logger.info(f"Generating CFI bypass using {technique}")

            if technique not in self.techniques:
                raise ValueError(f"Unknown bypass technique: {technique}")

            # Analyze CFI configuration
            cfi_analysis = self.analyze_cfi_protection(target_binary)

            # Generate technique-specific payload
            if technique == "legitimate_targets":
                payload_data = self._find_legitimate_targets(target_binary, cfi_analysis)
            elif technique == "jop_gadgets":
                payload_data = self._find_jop_gadgets(target_binary, cfi_analysis)
            elif technique == "indirect_branches":
                payload_data = self._analyze_indirect_branches(target_binary, cfi_analysis)
            elif technique == "vtable_hijacking":
                payload_data = self._vtable_hijacking(target_binary, cfi_analysis)
            elif technique == "return_oriented":
                payload_data = self._return_oriented_bypass(target_binary, cfi_analysis)
            else:
                raise ValueError(f"Technique {technique} not implemented")

            payload_info.update(payload_data)

            self.logger.info(f"CFI bypass payload generated: {len(payload_info['payload'])} bytes")
            return payload_info

        except Exception as e:
            self.logger.error(f"CFI bypass generation failed: {e}")
            return payload_info

    def find_rop_gadgets(self, binary_data: bytes, arch: str = "x86_64") -> List[Dict[str, Any]]:
        """Find ROP gadgets for CFI bypass."""
        gadgets = []

        # ROP gadget patterns
        rop_patterns = {
            "x86_64": [
                (b"\x5d\xc3", "pop rbp; ret"),
                (b"\x58\xc3", "pop rax; ret"),
                (b"\x5f\xc3", "pop rdi; ret"),
                (b"\x5e\xc3", "pop rsi; ret"),
                (b"\x5a\xc3", "pop rdx; ret"),
                (b"\x59\xc3", "pop rcx; ret"),
                (b"\x5b\xc3", "pop rbx; ret"),
            ],
            "x86": [
                (b"\x5d\xc3", "pop ebp; ret"),
                (b"\x58\xc3", "pop eax; ret"),
                (b"\x5f\xc3", "pop edi; ret"),
                (b"\x5e\xc3", "pop esi; ret"),
                (b"\x5a\xc3", "pop edx; ret"),
                (b"\x59\xc3", "pop ecx; ret"),
                (b"\x5b\xc3", "pop ebx; ret"),
            ],
        }

        patterns = rop_patterns.get(arch, rop_patterns["x86_64"])

        for pattern_bytes, description in patterns:
            offset = 0
            while offset < len(binary_data) - len(pattern_bytes):
                index = binary_data.find(pattern_bytes, offset)
                if index == -1:
                    break

                gadgets.append({"offset": index, "bytes": pattern_bytes, "description": description, "type": "rop"})
                offset = index + 1

        return gadgets

    def find_jop_gadgets(self, binary_data: bytes, arch: str = "x86_64") -> List[Dict[str, Any]]:
        """Find JOP gadgets for CFI bypass."""
        gadgets = []

        # JOP gadget patterns
        jop_patterns = {
            "x86_64": [
                (b"\xff\xe0", "jmp rax"),
                (b"\xff\xe1", "jmp rcx"),
                (b"\xff\xe2", "jmp rdx"),
                (b"\xff\xe3", "jmp rbx"),
                (b"\xff\xe6", "jmp rsi"),
                (b"\xff\xe7", "jmp rdi"),
            ],
            "x86": [(b"\xff\xe0", "jmp eax"), (b"\xff\xe1", "jmp ecx"), (b"\xff\xe2", "jmp edx"), (b"\xff\xe3", "jmp ebx")],
        }

        patterns = jop_patterns.get(arch, jop_patterns["x86_64"])

        for pattern_bytes, description in patterns:
            offset = 0
            while offset < len(binary_data) - len(pattern_bytes):
                index = binary_data.find(pattern_bytes, offset)
                if index == -1:
                    break

                gadgets.append({"offset": index, "bytes": pattern_bytes, "description": description, "type": "jop"})
                offset = index + 1

        return gadgets

    def _check_cfi_markers(self, binary_data: bytes) -> Dict[str, Any]:
        """Check for CFI protection markers."""
        markers = {
            "found": False,
            "type": None,
            "level": "none",
            "details": [],
        }

        # Check for various CFI markers
        cfi_patterns = [
            (b"__cfi_check", "gcc"),
            (b"__CFI_TYPE", "gcc"),
            (b"__typeid", "llvm"),
            (b".cfi_startproc", "llvm"),
            (b"endbr64", "cet"),
            (b"endbr32", "cet"),
        ]

        for pattern, cfi_type in cfi_patterns:
            if pattern in binary_data:
                markers["found"] = True
                markers["type"] = cfi_type
                markers["details"].append(f"Found: {pattern.decode('ascii', errors='ignore')}")

        # Estimate protection level
        if len(markers["details"]) > 3:
            markers["level"] = "high"
        elif len(markers["details"]) > 1:
            markers["level"] = "medium"
        elif markers["found"]:
            markers["level"] = "low"

        return markers

    def _analyze_indirect_calls(self, binary_data: bytes) -> Dict[str, Any]:
        """Analyze indirect call sites."""
        calls = {
            "count": 0,
            "call_sites": [],
            "protected": 0,
            "unprotected": 0,
        }

        # Look for indirect call patterns
        call_patterns = [
            b"\xff\xd0",  # call eax
            b"\xff\xd1",  # call ecx
            b"\xff\xd2",  # call edx
            b"\xff\x15",  # call [addr]
            b"\xff\x25",  # jmp [addr]
            b"\xff\xe0",  # jmp eax
        ]

        for pattern in call_patterns:
            offset = 0
            while offset < len(binary_data) - len(pattern):
                index = binary_data.find(pattern, offset)
                if index == -1:
                    break

                calls["call_sites"].append(
                    {
                        "offset": index,
                        "pattern": pattern.hex(),
                        "type": "call" if b"\xd0" in pattern or b"\xd1" in pattern or b"\xd2" in pattern else "jump",
                    }
                )
                calls["count"] += 1
                offset = index + 1

        # Simple protection check
        for call_site in calls["call_sites"]:
            start = max(0, call_site["offset"] - 20)
            end = call_site["offset"]
            region = binary_data[start:end]

            if b"cmp" in region or b"test" in region:
                calls["protected"] += 1
            else:
                calls["unprotected"] += 1

        return calls

    def _find_bypass_targets(self, binary_data: bytes) -> List[Dict[str, Any]]:
        """Find potential CFI bypass targets."""
        targets = []

        # Look for function starts (simplified)
        for i in range(0, len(binary_data) - 4, 4):
            # Look for function prologue patterns
            if binary_data[i : i + 3] == b"\x55\x48\x89":  # push rbp; mov rbp, rsp
                targets.append({"type": "function", "address": i, "confidence": 0.8, "usable": True})

        return targets

    def _find_legitimate_targets(self, binary_data: bytes, analysis: Dict[str, Any]) -> Dict[str, Any]:
        """Find legitimate call targets for CFI bypass."""
        return {
            "payload": b"\x90" * 8,  # NOP sled
            "technique": "legitimate_targets",
            "success_probability": 0.8,
            "requirements": ["leaked_address"],
            "metadata": {"targets": [], "strategy": "use_valid_targets"},
        }

    def _find_jop_gadgets(self, binary_data: bytes, analysis: Dict[str, Any]) -> Dict[str, Any]:
        """Find JOP gadgets for CFI bypass."""
        gadgets = self.find_jop_gadgets(binary_data)

        return {
            "payload": b"\x90" * 8 if gadgets else b"",
            "technique": "jop_gadgets",
            "success_probability": 0.6 if gadgets else 0.0,
            "requirements": ["gadget_chain", "memory_leak"],
            "metadata": {"gadgets": gadgets[:10], "chain_length": len(gadgets)},
        }

    def _analyze_indirect_branches(self, binary_data: bytes, analysis: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze indirect branch targets."""
        return {
            "payload": b"\x90" * 4,
            "technique": "indirect_branches",
            "success_probability": 0.7,
            "requirements": ["branch_target_leak"],
            "metadata": {"branches": [], "targets": []},
        }

    def _vtable_hijacking(self, binary_data: bytes, analysis: Dict[str, Any]) -> Dict[str, Any]:
        """Virtual table hijacking for CFI bypass."""
        return {
            "payload": b"\x00" * 32,  # Fake vtable
            "technique": "vtable_hijacking",
            "success_probability": 0.5,
            "requirements": ["vtable_pointer", "object_control"],
            "metadata": {"vtables": [], "methods": []},
        }

    def _return_oriented_bypass(self, binary_data: bytes, analysis: Dict[str, Any]) -> Dict[str, Any]:
        """Return-oriented programming for CFI bypass."""
        gadgets = self.find_rop_gadgets(binary_data)

        return {
            "payload": b"\x90" * 16 if gadgets else b"",
            "technique": "return_oriented",
            "success_probability": 0.4 if gadgets else 0.0,
            "requirements": ["stack_control", "rop_gadgets"],
            "metadata": {"gadgets": gadgets[:10], "chain": []},
        }

    def _calculate_bypass_difficulty(self, analysis: Dict[str, Any]) -> int:
        """Calculate CFI bypass difficulty (1-10)."""
        difficulty = 1

        if analysis["cfi_enabled"]:
            difficulty += 3

            if analysis["protection_level"] == "high":
                difficulty += 3
            elif analysis["protection_level"] == "medium":
                difficulty += 2
            else:
                difficulty += 1

            # Factor in bypass opportunities
            opportunities = len(analysis["bypass_opportunities"])
            if opportunities < 5:
                difficulty += 2
            elif opportunities < 10:
                difficulty += 1

        return min(10, difficulty)


__all__ = ["CFIBypass"]

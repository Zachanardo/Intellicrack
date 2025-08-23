"""Base classes for mitigation bypass techniques.

Copyright (C) 2025 Zachary Flint

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
from abc import ABC, abstractmethod
from typing import Any


class MitigationBypassBase(ABC):
    """Base class for all mitigation bypass techniques."""

    def __init__(self, mitigation_name: str):
        """Initialize the bypass.

        Args:
            mitigation_name: Name of the mitigation being bypassed

        """
        self.mitigation_name = mitigation_name
        self.techniques = []
        self.logger = logging.getLogger(__name__ + ".MitigationBypassBase")
        self._initialize_techniques()

    @abstractmethod
    def _initialize_techniques(self) -> None:
        """Initialize the list of available techniques for this bypass."""

    @abstractmethod
    def get_recommended_technique(self, binary_info: dict[str, Any]) -> str:
        """Get the recommended technique based on binary analysis.

        Args:
            binary_info: Information about the target binary

        Returns:
            Name of recommended technique

        """

    def analyze_bypass_opportunities(self, binary_info: dict[str, Any]) -> dict[str, Any]:
        """Analyze bypass opportunities for this mitigation.

        Args:
            binary_info: Information about the target binary

        Returns:
            Analysis results dictionary

        """
        try:
            recommended = self.get_recommended_technique(binary_info)

            return {
                "success": True,
                "mitigation": self.mitigation_name,
                "techniques_available": self.techniques,
                "recommended": recommended,
                "analysis": self._perform_detailed_analysis(binary_info),
            }
        except Exception as e:
            self.logger.error("Exception in bypass_base: %s", e)
            return {
                "success": False,
                "mitigation": self.mitigation_name,
                "error": str(e),
                "techniques_available": self.techniques,
            }

    def _perform_detailed_analysis(self, binary_info: dict[str, Any]) -> dict[str, Any]:
        """Perform detailed analysis for this bypass type.

        Args:
            binary_info: Information about the target binary

        Returns:
            Detailed analysis results

        """
        # Default implementation - subclasses can override
        return {
            "binary_architecture": binary_info.get("architecture", "unknown"),
            "has_symbols": binary_info.get("has_symbols", False),
            "is_stripped": binary_info.get("is_stripped", True),
            "security_features": binary_info.get("security_features", []),
        }

    def get_technique_info(self, technique_name: str) -> dict[str, Any] | None:
        """Get information about a specific technique.

        Args:
            technique_name: Name of the technique

        Returns:
            Technique information or None if not found

        """
        if technique_name not in self.techniques:
            return None

        # Default info - subclasses can override
        return {
            "name": technique_name,
            "difficulty": "medium",
            "reliability": "medium",
            "requirements": [],
        }

    def is_technique_applicable(self, technique_name: str, binary_info: dict[str, Any]) -> bool:
        """Check if a technique is applicable to the given binary.

        Args:
            technique_name: Name of the technique
            binary_info: Information about the target binary

        Returns:
            True if technique is applicable

        """
        # First check if technique exists
        if technique_name not in self.techniques:
            return False

        # Check architecture compatibility
        tech_info = self.get_technique_info(technique_name)
        if tech_info and "supported_architectures" in tech_info:
            binary_arch = binary_info.get("architecture", "unknown").lower()
            supported_archs = [arch.lower() for arch in tech_info["supported_architectures"]]
            if binary_arch not in supported_archs and "all" not in supported_archs:
                return False

        # Check OS compatibility
        if tech_info and "supported_os" in tech_info:
            binary_os = binary_info.get("os", "unknown").lower()
            supported_os = [os.lower() for os in tech_info["supported_os"]]
            if binary_os not in supported_os and "all" not in supported_os:
                return False

        # Check security feature requirements
        security_features = binary_info.get("security_features", [])

        # ROP-based techniques require executable memory regions
        if technique_name in ["rop_chain", "jop_chain", "ret2libc"]:
            if not binary_info.get("has_executable_sections", True):
                return False
            # ROP is less effective with CFG/CET
            if "cfg" in security_features or "cet" in security_features:
                return False

        # Stack-based techniques require writable stack
        if technique_name in ["stack_pivot", "stack_spray"]:
            if not binary_info.get("has_writable_stack", True):
                return False
            if "stack_guard" in security_features:
                return False

        # Heap-based techniques require heap execution
        if technique_name in ["heap_spray", "heap_feng_shui"]:
            if not binary_info.get("has_heap", True):
                return False
            if "heap_protection" in security_features:
                return False

        # Code injection techniques require writable+executable memory
        if technique_name in ["code_injection", "dll_injection"]:
            if "dep" in security_features or "nx" in security_features:
                if not binary_info.get("has_rwx_sections", False):
                    return False

        # Process hollowing requires specific OS features
        if technique_name == "process_hollowing":
            if binary_info.get("os", "").lower() not in ["windows", "win32", "win64"]:
                return False

        # Shared library techniques require dynamic linking
        if technique_name in ["got_overwrite", "plt_redirect"]:
            if binary_info.get("is_static", False):
                return False
            if not binary_info.get("has_dynamic_symbols", True):
                return False

        # Check minimum binary size requirements
        if tech_info and "min_binary_size" in tech_info:
            binary_size = binary_info.get("size", 0)
            if binary_size < tech_info["min_binary_size"]:
                return False

        # Check for required binary features
        if tech_info and "required_features" in tech_info:
            for feature in tech_info["required_features"]:
                if not binary_info.get(feature, False):
                    return False

        # Check for incompatible features
        if tech_info and "incompatible_features" in tech_info:
            for feature in tech_info["incompatible_features"]:
                if binary_info.get(feature, False):
                    return False

        # Additional checks based on binary type
        binary_type = binary_info.get("type", "").lower()

        # Kernel exploits only work on kernel binaries
        if technique_name in ["kernel_exploit", "driver_exploit"]:
            if binary_type not in ["kernel", "driver", "kext"]:
                return False

        # Service exploits require service binaries
        if technique_name in ["service_exploit", "privilege_escalation"]:
            if binary_type not in ["service", "daemon", "suid"]:
                return False

        # All checks passed
        return True

    def get_all_techniques(self) -> list[str]:
        """Get list of all available techniques.

        Returns:
            List of technique names

        """
        return self.techniques.copy()

    def get_technique_difficulty(self, technique_name: str) -> str:
        """Get the difficulty level of a technique.

        Args:
            technique_name: Name of the technique

        Returns:
            Difficulty level (easy, medium, hard)

        """
        info = self.get_technique_info(technique_name)
        return info.get("difficulty", "medium") if info else "unknown"


class ROPBasedBypass(MitigationBypassBase):
    """Base class for bypasses that can use ROP techniques."""

    def __init__(self, mitigation_name: str):
        """Initialize the ROP-based bypass with mitigation name and ROP technique list.

        Args:
            mitigation_name: Name of the mitigation being bypassed.

        """
        super().__init__(mitigation_name)
        self.rop_techniques = ["rop_chain", "jop_chain", "ret2libc"]

    def find_rop_gadgets(self, binary_info: dict[str, Any]) -> list[dict[str, Any]]:
        """Find ROP gadgets in the binary.

        Args:
            binary_info: Information about the target binary

        Returns:
            List of found gadgets

        """
        gadgets = []

        # Get binary data and architecture
        binary_data = binary_info.get("data", b"")
        arch = binary_info.get("architecture", "x64")
        sections = binary_info.get("sections", [])

        if not binary_data:
            return gadgets

        # Common ROP instruction patterns for x86/x64
        gadget_patterns = {
            "x86": [
                # ret instructions
                (b"\xc3", "ret"),
                (b"\xc2[\x00-\xff][\x00-\xff]", "ret imm16"),
                # pop register + ret
                (b"\x58\xc3", "pop eax; ret"),
                (b"\x59\xc3", "pop ecx; ret"),
                (b"\x5a\xc3", "pop edx; ret"),
                (b"\x5b\xc3", "pop ebx; ret"),
                (b"\x5c\xc3", "pop esp; ret"),
                (b"\x5d\xc3", "pop ebp; ret"),
                (b"\x5e\xc3", "pop esi; ret"),
                (b"\x5f\xc3", "pop edi; ret"),
                # xchg + ret
                (b"\x94\xc3", "xchg eax, esp; ret"),
                (b"\x87[\xe0-\xe7]\xc3", "xchg esp, reg; ret"),
                # leave + ret
                (b"\xc9\xc3", "leave; ret"),
                # add/sub esp + ret
                (b"\x83\xc4[\x00-\xff]\xc3", "add esp, imm8; ret"),
                (b"\x83\xec[\x00-\xff]\xc3", "sub esp, imm8; ret"),
                # jmp/call register
                (b"\xff[\xe0-\xe7]", "jmp reg"),
                (b"\xff[\xd0-\xd7]", "call reg"),
            ],
            "x64": [
                # ret instructions
                (b"\xc3", "ret"),
                (b"\xc2[\x00-\xff][\x00-\xff]", "ret imm16"),
                # pop register + ret (with REX prefix)
                (b"\x58\xc3", "pop rax; ret"),
                (b"\x59\xc3", "pop rcx; ret"),
                (b"\x5a\xc3", "pop rdx; ret"),
                (b"\x5b\xc3", "pop rbx; ret"),
                (b"\x5c\xc3", "pop rsp; ret"),
                (b"\x5d\xc3", "pop rbp; ret"),
                (b"\x5e\xc3", "pop rsi; ret"),
                (b"\x5f\xc3", "pop rdi; ret"),
                (b"\x41[\x58-\x5f]\xc3", "pop r8-r15; ret"),
                # xchg + ret
                (b"\x48\x94\xc3", "xchg rax, rsp; ret"),
                (b"\x48\x87[\xe0-\xe7]\xc3", "xchg rsp, reg; ret"),
                # leave + ret
                (b"\xc9\xc3", "leave; ret"),
                # add/sub rsp + ret
                (b"\x48\x83\xc4[\x00-\xff]\xc3", "add rsp, imm8; ret"),
                (b"\x48\x83\xec[\x00-\xff]\xc3", "sub rsp, imm8; ret"),
                # syscall + ret
                (b"\x0f\x05\xc3", "syscall; ret"),
                # jmp/call register
                (b"\xff[\xe0-\xe7]", "jmp reg"),
                (b"\xff[\xd0-\xd7]", "call reg"),
            ]
        }

        patterns = gadget_patterns.get(arch, gadget_patterns["x64"])

        # Search for gadgets in executable sections
        for section in sections:
            if not section.get("executable", False):
                continue

            section_start = section.get("virtual_address", 0)
            section_data = section.get("data", b"")

            if not section_data:
                continue

            # Search for each gadget pattern
            for pattern_bytes, description in patterns:
                # Simple pattern matching (would use regex in production)
                if isinstance(pattern_bytes, bytes):
                    # Find all occurrences of the pattern
                    offset = 0
                    while offset < len(section_data) - len(pattern_bytes):
                        index = section_data.find(pattern_bytes, offset)
                        if index == -1:
                            break

                        # Verify this is a valid gadget location
                        # Check for preceding instructions that form a valid gadget
                        gadget_addr = section_start + index

                        # Look back up to 15 bytes for valid instruction sequences
                        lookback = min(index, 15)
                        if lookback > 0:
                            gadget_bytes = section_data[index-lookback:index+len(pattern_bytes)]

                            # Disassemble to verify (simplified)
                            if self._is_valid_gadget_sequence(gadget_bytes, arch):
                                gadgets.append({
                                    "address": hex(gadget_addr),
                                    "instruction": description,
                                    "type": self._classify_gadget(description),
                                    "bytes": gadget_bytes.hex(),
                                    "section": section.get("name", ".text")
                                })

                        offset = index + 1

                        # Limit gadgets per pattern
                        if len(gadgets) >= 100:
                            break

        # Sort gadgets by address
        gadgets.sort(key=lambda x: int(x["address"], 16))

        # Remove duplicates
        seen = set()
        unique_gadgets = []
        for gadget in gadgets:
            key = (gadget["address"], gadget["instruction"])
            if key not in seen:
                seen.add(key)
                unique_gadgets.append(gadget)

        return unique_gadgets

    def _is_valid_gadget_sequence(self, gadget_bytes: bytes, arch: str) -> bool:
        """Check if bytes form a valid gadget sequence."""
        # Simplified validation - check for common invalid patterns
        invalid_patterns = [
            b"\x00\x00\x00\x00",  # Null bytes
            b"\xff\xff\xff\xff",  # All 0xFF
            b"\xcc",  # INT3 breakpoint
            b"\xcd\x80",  # INT 0x80 (old syscall)
        ]

        for pattern in invalid_patterns:
            if pattern in gadget_bytes:
                return False

        # Must end with ret or jmp/call
        valid_endings = [b"\xc3", b"\xc2", b"\xff\xe4", b"\xff\xd4"]
        for ending in valid_endings:
            if any(gadget_bytes.endswith(ending + bytes([b])) or gadget_bytes.endswith(ending)
                   for b in range(256)):
                return True

        return gadget_bytes.endswith(b"\xc3")  # At least must end with ret

    def _classify_gadget(self, instruction: str) -> str:
        """Classify gadget type based on instruction."""
        instruction_lower = instruction.lower()

        if "pop" in instruction_lower:
            return "pop_register"
        elif "xchg" in instruction_lower:
            return "stack_pivot"
        elif "leave" in instruction_lower:
            return "leave_ret"
        elif "add" in instruction_lower or "sub" in instruction_lower:
            return "stack_adjust"
        elif "syscall" in instruction_lower:
            return "syscall"
        elif "jmp" in instruction_lower:
            return "jmp_register"
        elif "call" in instruction_lower:
            return "call_register"
        elif "ret" in instruction_lower:
            return "ret"
        else:
            return "other"

    def assess_rop_viability(self, binary_info: dict[str, Any]) -> dict[str, Any]:
        """Assess the viability of ROP-based attacks.

        Args:
            binary_info: Information about the target binary

        Returns:
            ROP viability assessment

        """
        gadgets = self.find_rop_gadgets(binary_info)

        return {
            "viable": len(gadgets) > 0,
            "gadget_count": len(gadgets),
            "quality": "good" if len(gadgets) > 10 else "limited",
            "gadgets": gadgets[:5],  # Return first 5 for preview
        }

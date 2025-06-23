"""
Base classes for mitigation bypass techniques.

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
along with this program.  If not, see <https://www.gnu.org/licenses/>.
"""

from abc import ABC, abstractmethod
from typing import Any, Dict, List, Optional


class MitigationBypassBase(ABC):
    """Base class for all mitigation bypass techniques."""

    def __init__(self, mitigation_name: str):
        """
        Initialize the bypass.

        Args:
            mitigation_name: Name of the mitigation being bypassed
        """
        self.mitigation_name = mitigation_name
        self.techniques = []
        self._initialize_techniques()

    @abstractmethod
    def _initialize_techniques(self) -> None:
        """Initialize the list of available techniques for this bypass."""
        pass

    @abstractmethod
    def get_recommended_technique(self, binary_info: Dict[str, Any]) -> str:
        """
        Get the recommended technique based on binary analysis.

        Args:
            binary_info: Information about the target binary

        Returns:
            Name of recommended technique
        """
        pass

    def analyze_bypass_opportunities(self, binary_info: Dict[str, Any]) -> Dict[str, Any]:
        """
        Analyze bypass opportunities for this mitigation.

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
            return {
                "success": False,
                "mitigation": self.mitigation_name,
                "error": str(e),
                "techniques_available": self.techniques,
            }

    def _perform_detailed_analysis(self, binary_info: Dict[str, Any]) -> Dict[str, Any]:
        """
        Perform detailed analysis for this bypass type.

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

    def get_technique_info(self, technique_name: str) -> Optional[Dict[str, Any]]:
        """
        Get information about a specific technique.

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

    def is_technique_applicable(self, technique_name: str, binary_info: Dict[str, Any]) -> bool:
        """
        Check if a technique is applicable to the given binary.

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
        if tech_info and 'supported_architectures' in tech_info:
            binary_arch = binary_info.get('architecture', 'unknown').lower()
            supported_archs = [arch.lower() for arch in tech_info['supported_architectures']]
            if binary_arch not in supported_archs and 'all' not in supported_archs:
                return False

        # Check OS compatibility
        if tech_info and 'supported_os' in tech_info:
            binary_os = binary_info.get('os', 'unknown').lower()
            supported_os = [os.lower() for os in tech_info['supported_os']]
            if binary_os not in supported_os and 'all' not in supported_os:
                return False

        # Check security feature requirements
        security_features = binary_info.get('security_features', [])

        # ROP-based techniques require executable memory regions
        if technique_name in ['rop_chain', 'jop_chain', 'ret2libc']:
            if not binary_info.get('has_executable_sections', True):
                return False
            # ROP is less effective with CFG/CET
            if 'cfg' in security_features or 'cet' in security_features:
                return False

        # Stack-based techniques require writable stack
        if technique_name in ['stack_pivot', 'stack_spray']:
            if not binary_info.get('has_writable_stack', True):
                return False
            if 'stack_guard' in security_features:
                return False

        # Heap-based techniques require heap execution
        if technique_name in ['heap_spray', 'heap_feng_shui']:
            if not binary_info.get('has_heap', True):
                return False
            if 'heap_protection' in security_features:
                return False

        # Code injection techniques require writable+executable memory
        if technique_name in ['code_injection', 'dll_injection']:
            if 'dep' in security_features or 'nx' in security_features:
                if not binary_info.get('has_rwx_sections', False):
                    return False

        # Process hollowing requires specific OS features
        if technique_name == 'process_hollowing':
            if binary_info.get('os', '').lower() not in ['windows', 'win32', 'win64']:
                return False

        # Shared library techniques require dynamic linking
        if technique_name in ['got_overwrite', 'plt_redirect']:
            if binary_info.get('is_static', False):
                return False
            if not binary_info.get('has_dynamic_symbols', True):
                return False

        # Check minimum binary size requirements
        if tech_info and 'min_binary_size' in tech_info:
            binary_size = binary_info.get('size', 0)
            if binary_size < tech_info['min_binary_size']:
                return False

        # Check for required binary features
        if tech_info and 'required_features' in tech_info:
            for feature in tech_info['required_features']:
                if not binary_info.get(feature, False):
                    return False

        # Check for incompatible features
        if tech_info and 'incompatible_features' in tech_info:
            for feature in tech_info['incompatible_features']:
                if binary_info.get(feature, False):
                    return False

        # Additional checks based on binary type
        binary_type = binary_info.get('type', '').lower()

        # Kernel exploits only work on kernel binaries
        if technique_name in ['kernel_exploit', 'driver_exploit']:
            if binary_type not in ['kernel', 'driver', 'kext']:
                return False

        # Service exploits require service binaries
        if technique_name in ['service_exploit', 'privilege_escalation']:
            if binary_type not in ['service', 'daemon', 'suid']:
                return False

        # All checks passed
        return True

    def get_all_techniques(self) -> List[str]:
        """
        Get list of all available techniques.

        Returns:
            List of technique names
        """
        return self.techniques.copy()

    def get_technique_difficulty(self, technique_name: str) -> str:
        """
        Get the difficulty level of a technique.

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
        super().__init__(mitigation_name)
        self.rop_techniques = ["rop_chain", "jop_chain", "ret2libc"]

    def find_rop_gadgets(self, binary_info: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Find ROP gadgets in the binary.

        Args:
            binary_info: Information about the target binary

        Returns:
            List of found gadgets
        """
        # Placeholder implementation
        gadgets = []

        # In a real implementation, this would analyze the binary for gadgets
        if binary_info.get("has_executable_sections", True):
            gadgets.append(
                {"address": "0x401000", "instruction": "pop rdi; ret", "type": "pop_register"}
            )
            gadgets.append(
                {"address": "0x401005", "instruction": "pop rsi; ret", "type": "pop_register"}
            )

        return gadgets

    def assess_rop_viability(self, binary_info: Dict[str, Any]) -> Dict[str, Any]:
        """
        Assess the viability of ROP-based attacks.

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

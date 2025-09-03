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

from typing import Any

"""
Shared Bypass Configuration

Common bypass definitions and helper functions used across mitigation bypass modules.
"""


class BypassConfig:
    """Centralized configuration for exploit mitigation bypasses."""

    # Standard bypass types with their descriptions
    BYPASS_TYPES = {
        "aslr_bypass": {
            "description": "Address Space Layout Randomization bypass",
            "target_protection": "aslr_enabled",
            "difficulty": "medium",
            "reliability": 7,
        },
        "dep_bypass": {
            "description": "Data Execution Prevention bypass",
            "target_protection": "dep_enabled",
            "difficulty": "high",
            "reliability": 8,
        },
        "cfi_bypass": {
            "description": "Control Flow Integrity bypass",
            "target_protection": "cfi_enabled",
            "difficulty": "high",
            "reliability": 6,
        },
        "cfg_bypass": {
            "description": "Control Flow Guard bypass",
            "target_protection": "cfg_enabled",
            "difficulty": "medium",
            "reliability": 7,
        },
        "cet_bypass": {
            "description": "Control-flow Enforcement Technology bypass",
            "target_protection": "cet_enabled",
            "difficulty": "very_high",
            "reliability": 5,
        },
    }

    @staticmethod
    def get_available_bypasses() -> list[str]:
        """Get list of available bypass types."""
        return list(BypassConfig.BYPASS_TYPES.keys())

    @staticmethod
    def analyze_bypass_capabilities(target_info: dict[str, Any]) -> dict[str, Any]:
        """Analyze available bypass capabilities for a target."""
        bypasses = []

        for bypass_type, config in BypassConfig.BYPASS_TYPES.items():
            protection_key = config["target_protection"]
            if target_info.get(protection_key, False):
                bypasses.append(bypass_type)

        return {
            "bypasses_available": bypasses,
            "target_info": target_info,
            "bypass_count": len(bypasses),
        }

    @staticmethod
    def get_bypass_info(bypass_type: str) -> dict[str, Any]:
        """Get detailed information about a specific bypass type."""
        return BypassConfig.BYPASS_TYPES.get(
            bypass_type,
            {
                "description": "Unknown bypass type",
                "target_protection": "unknown",
                "difficulty": "unknown",
                "reliability": 0,
            },
        )

    @staticmethod
    def get_bypasses_by_difficulty(difficulty: str) -> list[str]:
        """Get bypasses filtered by difficulty level."""
        return [bypass_type for bypass_type, config in BypassConfig.BYPASS_TYPES.items() if config["difficulty"] == difficulty]

    @staticmethod
    def get_recommended_bypasses(target_info: dict[str, Any], min_reliability: int = 6) -> list[str]:
        """Get recommended bypasses based on target and reliability threshold."""
        analysis = BypassConfig.analyze_bypass_capabilities(target_info)
        available_bypasses = analysis["bypasses_available"]

        return [
            bypass_type for bypass_type in available_bypasses if BypassConfig.BYPASS_TYPES[bypass_type]["reliability"] >= min_reliability
        ]


__all__ = ["BypassConfig"]

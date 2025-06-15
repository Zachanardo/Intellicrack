"""
Shared Bypass Configuration

Common bypass definitions and helper functions used across mitigation bypass modules.
"""

from typing import Dict, List, Any


class BypassConfig:
    """Centralized configuration for exploit mitigation bypasses."""

    # Standard bypass types with their descriptions
    BYPASS_TYPES = {
        'aslr_bypass': {
            'description': 'Address Space Layout Randomization bypass',
            'target_protection': 'aslr_enabled',
            'difficulty': 'medium',
            'reliability': 7
        },
        'dep_bypass': {
            'description': 'Data Execution Prevention bypass',
            'target_protection': 'dep_enabled',
            'difficulty': 'high',
            'reliability': 8
        },
        'cfi_bypass': {
            'description': 'Control Flow Integrity bypass',
            'target_protection': 'cfi_enabled',
            'difficulty': 'high',
            'reliability': 6
        },
        'cfg_bypass': {
            'description': 'Control Flow Guard bypass',
            'target_protection': 'cfg_enabled',
            'difficulty': 'medium',
            'reliability': 7
        },
        'cet_bypass': {
            'description': 'Control-flow Enforcement Technology bypass',
            'target_protection': 'cet_enabled',
            'difficulty': 'very_high',
            'reliability': 5
        }
    }

    @staticmethod
    def get_available_bypasses() -> List[str]:
        """Get list of available bypass types."""
        return list(BypassConfig.BYPASS_TYPES.keys())

    @staticmethod
    def analyze_bypass_capabilities(target_info: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze available bypass capabilities for a target."""
        bypasses = []
        
        for bypass_type, config in BypassConfig.BYPASS_TYPES.items():
            protection_key = config['target_protection']
            if target_info.get(protection_key, False):
                bypasses.append(bypass_type)
        
        return {
            'bypasses_available': bypasses,
            'target_info': target_info,
            'bypass_count': len(bypasses)
        }

    @staticmethod
    def get_bypass_info(bypass_type: str) -> Dict[str, Any]:
        """Get detailed information about a specific bypass type."""
        return BypassConfig.BYPASS_TYPES.get(bypass_type, {
            'description': 'Unknown bypass type',
            'target_protection': 'unknown',
            'difficulty': 'unknown',
            'reliability': 0
        })

    @staticmethod
    def get_bypasses_by_difficulty(difficulty: str) -> List[str]:
        """Get bypasses filtered by difficulty level."""
        return [
            bypass_type for bypass_type, config in BypassConfig.BYPASS_TYPES.items()
            if config['difficulty'] == difficulty
        ]

    @staticmethod
    def get_recommended_bypasses(target_info: Dict[str, Any], 
                                min_reliability: int = 6) -> List[str]:
        """Get recommended bypasses based on target and reliability threshold."""
        analysis = BypassConfig.analyze_bypass_capabilities(target_info)
        available_bypasses = analysis['bypasses_available']
        
        return [
            bypass_type for bypass_type in available_bypasses
            if BypassConfig.BYPASS_TYPES[bypass_type]['reliability'] >= min_reliability
        ]


__all__ = ['BypassConfig']
"""
Common PE file analysis utilities.

This module consolidates PE parsing patterns to reduce code duplication.
"""

import logging
from typing import Dict, List

logger = logging.getLogger(__name__)

def analyze_pe_imports(pe, target_apis: Dict[str, List[str]]) -> Dict[str, List[str]]:
    """
    Analyze PE imports for specific API categories.
    
    Args:
        pe: PE file object
        target_apis: Dictionary mapping categories to API lists
        
    Returns:
        Dictionary mapping categories to detected APIs
    """
    detected_apis = {category: [] for category in target_apis.keys()}

    if not hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
        return detected_apis

    for entry in pe.DIRECTORY_ENTRY_IMPORT:
        for imp in entry.imports:
            if not imp.name:
                continue

            func_name = imp.name.decode('utf-8', errors='ignore')

            # Check each category of APIs
            for category, apis in target_apis.items():
                if any(api.lower() in func_name.lower() for api in apis):
                    detected_apis[category].append(func_name)

    return detected_apis

def get_pe_sections_info(pe) -> List[Dict]:
    """
    Extract PE section information.
    
    Args:
        pe: PE file object
        
    Returns:
        List of section information dictionaries
    """
    sections = []

    for section in pe.sections:
        section_info = {
            'name': section.Name.decode('utf-8', errors='ignore').rstrip('\x00'),
            'virtual_address': section.VirtualAddress,
            'virtual_size': section.Misc_VirtualSize,
            'raw_size': section.SizeOfRawData,
            'characteristics': section.Characteristics
        }
        sections.append(section_info)

    return sections

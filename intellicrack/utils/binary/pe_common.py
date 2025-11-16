"""PE common utilities for Intellicrack.

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

Common PE file analysis utilities.

This module provides common functions for PE file import parsing.
"""

import logging
from typing import Callable

logger = logging.getLogger(__name__)


def extract_pe_imports(pe_obj: object) -> list[str]:
    """Extract import function names from a PE object.

    Args:
        pe_obj: A pefile PE object

    Returns:
        List of import function names

    """
    imports = []

    try:
        if hasattr(pe_obj, "DIRECTORY_ENTRY_IMPORT"):
            for entry in pe_obj.DIRECTORY_ENTRY_IMPORT:
                for imp in entry.imports:
                    if imp.name:
                        func_name = imp.name.decode("utf-8", errors="ignore")
                        imports.append(func_name)
    except (AttributeError, ValueError) as e:
        logger.debug("Error extracting PE imports: %s", e)

    return imports


def iterate_pe_imports_with_dll(
    pe_obj: object, callback: Callable[..., object], include_import_obj: bool = False,
) -> object:
    """Iterate through PE imports with DLL names, calling callback for each.

    Args:
        pe_obj: A pefile PE object
        callback: Function to call for each import
                 (dll_name, func_name[, imp_obj]) -> Any
        include_import_obj: Whether to pass the import object as 3rd parameter

    Yields:
        Results from callback function

    """
    try:
        if hasattr(pe_obj, "DIRECTORY_ENTRY_IMPORT"):
            for entry in pe_obj.DIRECTORY_ENTRY_IMPORT:
                dll_name = entry.dll.decode("utf-8", errors="ignore")
                for imp in entry.imports:
                    if imp.name:
                        func_name = imp.name.decode("utf-8", errors="ignore")
                        if include_import_obj:
                            result = callback(dll_name, func_name, imp)
                        else:
                            result = callback(dll_name, func_name)
                        if result is not None:
                            yield result
    except (AttributeError, ValueError) as e:
        logger.debug("Error iterating PE imports: %s", e)


def analyze_pe_import_security(pe_obj: object) -> dict[str, list[str]]:
    """Analyze PE imports for security-related functions.

    Args:
        pe_obj: A pefile PE object

    Returns:
        Dictionary with security analysis results

    """
    security_apis = {
        "crypto": ["CryptAcquireContext", "CryptCreateHash", "CryptDecrypt", "CryptEncrypt"],
        "network": ["socket", "connect", "send", "recv", "WSAStartup", "InternetOpen"],
        "process": ["CreateProcess", "OpenProcess", "TerminateProcess", "ReadProcessMemory"],
        "registry": ["RegOpenKey", "RegQueryValue", "RegSetValue", "RegCreateKey"],
        "file": ["CreateFile", "ReadFile", "WriteFile", "DeleteFile"],
    }

    results = {category: [] for category in security_apis}
    imports = extract_pe_imports(pe_obj)

    for func_name in imports:
        for category, apis in security_apis.items():
            if any(api.lower() in func_name.lower() for api in apis):
                results[category].append(func_name)

    return results

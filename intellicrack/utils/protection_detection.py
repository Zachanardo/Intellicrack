"""Protection detection utilities - wrapper to redirect to protection/protection_detection.py.

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
along with Intellicrack.  If not, see https://www.gnu.org/licenses/.
"""

# Import all functions from the protection/protection_detection module
from .protection.protection_detection import (
    detect_all_protections,
    detect_anti_debug,
    detect_anti_debugging,
    detect_anti_debugging_techniques,
    detect_checksum_verification,
    detect_commercial_protections,
    detect_commercial_protectors,
    detect_obfuscation,
    detect_packing_methods,
    detect_protection_mechanisms,
    detect_self_healing,
    detect_self_healing_code,
    detect_tpm_protection,
    detect_virtualization_protection,
    detect_vm_detection,
    run_comprehensive_protection_scan,
    scan_for_bytecode_protectors,
)

__all__ = [
    "detect_all_protections",
    "detect_anti_debug",
    "detect_anti_debugging",
    "detect_anti_debugging_techniques",
    "detect_checksum_verification",
    "detect_commercial_protections",
    "detect_commercial_protectors",
    "detect_obfuscation",
    "detect_packing_methods",
    "detect_protection_mechanisms",
    "detect_self_healing",
    "detect_self_healing_code",
    "detect_tpm_protection",
    "detect_virtualization_protection",
    "detect_vm_detection",
    "run_comprehensive_protection_scan",
    "scan_for_bytecode_protectors",
]

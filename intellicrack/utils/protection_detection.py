"""
Protection detection utilities - wrapper to redirect to protection/protection_detection.py

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
along with Intellicrack.  If not, see <https://www.gnu.org/licenses/>.
"""

# Import all functions from the protection/protection_detection module
from .protection.protection_detection import (
    detect_virtualization_protection,
    detect_commercial_protections,
    run_comprehensive_protection_scan,
    generate_checksum,
    detect_checksum_verification,
    detect_self_healing_code,
    detect_obfuscation,
    detect_anti_debugging_techniques,
    scan_for_bytecode_protectors,
    detect_protection_mechanisms,
    detect_packing_methods,
    detect_all_protections,
    detect_anti_debug,
    detect_commercial_protectors,
    detect_tpm_protection,
    detect_anti_debugging,
    detect_vm_detection
)

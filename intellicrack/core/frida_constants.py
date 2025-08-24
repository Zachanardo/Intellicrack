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

from enum import Enum

"""
Frida Constants Module

This module contains enums and constants used by Frida components
to avoid cyclic imports between core and UI modules.
"""


class ProtectionType(Enum):
    """Classification of protection techniques.

    Enumerates common software protection mechanisms that can be
    detected and bypassed using Frida. Each protection type has
    specific bypass strategies and detection methods.

    The enum values are human-readable descriptions used in UI
    and reporting. The enum names are used programmatically.

    Categories:
    - Debugging: ANTI_DEBUG, ANTI_ATTACH
    - Environment: ANTI_VM, ROOT_DETECTION
    - Validation: LICENSE, HARDWARE, CLOUD, TIME
    - Security: SSL_PINNING, INTEGRITY, INTEGRITY_CHECK
    - Obfuscation: PACKING, MEMORY, MEMORY_PROTECTION
    - Advanced: KERNEL, BEHAVIOR
    """

    ANTI_DEBUG = "Anti-Debugging"  # Detects debuggers like GDB, IDA, x64dbg
    ANTI_VM = "Anti-VM/Sandbox"  # Detects VMs/sandboxes (VMware, VirtualBox)
    ANTI_ATTACH = "Anti-Attach"  # Prevents process attachment/injection
    SSL_PINNING = "SSL Pinning"  # Certificate pinning for HTTPS
    PACKING = "Packing/Obfuscation"  # Code packing/encryption (UPX, Themida)
    LICENSE = "License Verification"  # License key/serial validation
    INTEGRITY = "Code Integrity"  # Checksum/hash verification
    HARDWARE = "Hardware Binding"  # HWID/machine fingerprinting
    CLOUD = "Cloud Verification"  # Online license/integrity checks
    TIME = "Time-based Protection"  # Trial periods, expiration
    MEMORY = "Memory Protection"  # Memory access restrictions
    MEMORY_PROTECTION = "Memory Protection"  # Duplicate for compatibility
    KERNEL = "Kernel-mode Protection"  # Driver-based protections
    BEHAVIOR = "Behavioral Analysis"  # Runtime behavior monitoring
    ROOT_DETECTION = "Root Detection"  # Mobile root/jailbreak detection
    INTEGRITY_CHECK = "Integrity Check"  # File/memory integrity validation
    UNKNOWN = "Unknown Protection"  # Unidentified protection mechanism


class HookCategory(Enum):
    """Categories for hook batching.

    Defines priority levels for Frida hooks to optimize performance
    and minimize detection. Higher priority hooks are applied
    immediately while lower priority ones can be batched.

    Batching Strategy:
    - CRITICAL: Applied immediately, no batching
    - HIGH: Applied within 100ms
    - MEDIUM: Batched up to 500ms
    - LOW: Batched up to 2000ms
    - MONITORING: Passive hooks, lowest priority

    Use Cases:
    - CRITICAL: Anti-debug bypass, time-sensitive hooks
    - HIGH: License checks, integrity validation
    - MEDIUM: General API hooks, data collection
    - LOW: Logging, statistics gathering
    - MONITORING: Performance monitoring, analytics
    """

    CRITICAL = "critical"  # Must hook immediately (no delay)
    HIGH = "high"  # Hook soon (max 100ms delay)
    MEDIUM = "medium"  # Can batch (max 500ms delay)
    LOW = "low"  # Batch aggressively (max 2s delay)
    MONITORING = "monitoring"  # Passive monitoring hooks (lowest priority)


__all__ = ["HookCategory", "ProtectionType"]

"""
Frida Constants Module

This module contains enums and constants used by Frida components
to avoid cyclic imports between core and UI modules.
"""

from enum import Enum


class ProtectionType(Enum):
    """Classification of protection techniques"""
    ANTI_DEBUG = "Anti-Debugging"
    ANTI_VM = "Anti-VM/Sandbox"
    ANTI_ATTACH = "Anti-Attach"
    SSL_PINNING = "SSL Pinning"
    PACKING = "Packing/Obfuscation"
    LICENSE = "License Verification"
    INTEGRITY = "Code Integrity"
    HARDWARE = "Hardware Binding"
    CLOUD = "Cloud Verification"
    TIME = "Time-based Protection"
    MEMORY = "Memory Protection"
    MEMORY_PROTECTION = "Memory Protection"
    KERNEL = "Kernel-mode Protection"
    BEHAVIOR = "Behavioral Analysis"
    ROOT_DETECTION = "Root Detection"
    INTEGRITY_CHECK = "Integrity Check"
    UNKNOWN = "Unknown Protection"


class HookCategory(Enum):
    """Categories for hook batching"""
    CRITICAL = "critical"      # Must hook immediately
    HIGH = "high"             # Hook soon
    MEDIUM = "medium"         # Can batch
    LOW = "low"              # Batch aggressively
    MONITORING = "monitoring" # Passive monitoring hooks


__all__ = ['ProtectionType', 'HookCategory']

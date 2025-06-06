"""
Intellicrack Core Patching Package

This package provides binary patching and modification capabilities for the Intellicrack framework.
It includes tools for generating patches, applying binary modifications, and creating custom payloads.

Modules:
    - payload_generator: Generate custom payloads for binary patching
    - adobe_injector: Adobe Creative Suite license bypass functionality  
    - windows_activator: Windows activation and license management
    - memory_patcher: Memory patching and launcher generation for protected binaries

Key Features:
    - Binary patch generation
    - Payload creation and injection
    - Pattern-based patching
    - Multi-architecture support
    - Adobe license bypass with Frida injection
    - Windows activation using MAS scripts
    - Memory patching for heavily protected binaries
    - Launcher script generation for runtime patching
"""

import logging

# Set up package logger
logger = logging.getLogger(__name__)

# Import patching modules with error handling
try:
    from .payload_generator import (
        PayloadGenerator,
        apply_patch,
        create_nop_sled,
        inject_shellcode,
        generate_complete_api_hooking_script,
    )
except ImportError as e:
    logger.warning(f"Failed to import payload_generator: {e}")

try:
    from .adobe_injector import (
        AdobeInjector,
        create_adobe_injector,
        inject_running_adobe_processes,
        start_adobe_monitoring,
    )
except ImportError as e:
    logger.warning(f"Failed to import adobe_injector: {e}")

try:
    from .windows_activator import (
        ActivationMethod,
        ActivationStatus,
        WindowsActivator,
        activate_windows_hwid,
        activate_windows_kms,
        check_windows_activation,
        create_windows_activator,
    )
except ImportError as e:
    logger.warning(f"Failed to import windows_activator: {e}")

try:
    from .memory_patcher import generate_launcher_script, setup_memory_patching
except ImportError as e:
    logger.warning(f"Failed to import memory_patcher: {e}")

# Define package exports
__all__ = [
    # From payload_generator
    'PayloadGenerator',
    'apply_patch',
    'create_nop_sled',
    'inject_shellcode',
    'generate_complete_api_hooking_script',

    # From adobe_injector
    'AdobeInjector',
    'create_adobe_injector',
    'inject_running_adobe_processes',
    'start_adobe_monitoring',

    # From windows_activator
    'WindowsActivator',
    'ActivationMethod',
    'ActivationStatus',
    'create_windows_activator',
    'check_windows_activation',
    'activate_windows_hwid',
    'activate_windows_kms',

    # From memory_patcher
    'generate_launcher_script',
    'setup_memory_patching',
]

# Package metadata
__version__ = "0.1.0"
__author__ = "Intellicrack Development Team"

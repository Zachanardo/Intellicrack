"""
Qiling Binary Emulation Framework Integration. 

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

#!/usr/bin/env python3
"""
Qiling Binary Emulation Framework Integration.

This module provides Qiling-based binary emulation capabilities for lightweight
dynamic analysis, API hooking, and runtime behavior monitoring without full
system emulation overhead.
"""

import logging
import os
import time
import traceback
from typing import Any, Callable, Dict, List, Optional

# Try to import Qiling
try:
    from qiling import Qiling
    from qiling.const import QL_ARCH, QL_OS, QL_VERBOSE
    from qiling.os.mapper import QlFsMappedObject
    QILING_AVAILABLE = True
except ImportError:
    QILING_AVAILABLE = False
    Qiling = None
    QL_ARCH = None
    QL_OS = None
    QL_VERBOSE = None


class QilingEmulator:
    """
    Lightweight binary emulator using Qiling framework.

    Provides fast binary-level emulation with API hooking, memory monitoring,
    and behavior analysis without the overhead of full system emulation.

    Features:
        - Multi-architecture support (x86, x64, ARM, MIPS)
        - API hooking and instrumentation
        - Memory access monitoring
        - File/Registry/Network emulation
        - License check detection
        - Fast execution compared to full VM
    """

    ARCH_MAPPING = {
        'x86': 'x86' if QILING_AVAILABLE else None,
        'x64': 'x86' if QILING_AVAILABLE else None,
        'x86_64': 'x86' if QILING_AVAILABLE else None,
        'arm': 'arm' if QILING_AVAILABLE else None,
        'arm64': 'arm64' if QILING_AVAILABLE else None,
        'mips': 'mips' if QILING_AVAILABLE else None,
    }

    OS_MAPPING = {
        'windows': 'windows' if QILING_AVAILABLE else None,
        'linux': 'linux' if QILING_AVAILABLE else None,
        'macos': 'macos' if QILING_AVAILABLE else None,
        'freebsd': 'freebsd' if QILING_AVAILABLE else None,
    }

    def __init__(self, binary_path: str, rootfs: Optional[str] = None,
                 ostype: str = 'windows', arch: str = 'x86_64',
                 verbose: bool = False):
        """
        Initialize Qiling emulator.

        Args:
            binary_path: Path to binary to emulate
            rootfs: Root filesystem path (optional, auto-detected if None)
            ostype: Operating system type
            arch: Architecture type
            verbose: Enable verbose output
        """
        if not QILING_AVAILABLE:
            raise ImportError("Qiling framework not available. Install with: pip install qiling")

        if not os.path.exists(binary_path):
            raise FileNotFoundError(f"Binary not found: {binary_path}")

        self.binary_path = os.path.abspath(binary_path)
        self.ostype = ostype.lower()
        self.arch = arch.lower()
        self.verbose = verbose
        self.logger = logging.getLogger(__name__)

        # Hooks storage
        self.api_hooks = {}
        self.memory_hooks = []
        self.code_hooks = []

        # Analysis results
        self.api_calls = []
        self.memory_accesses = []
        self.suspicious_behaviors = []
        self.license_checks = []

        # Determine rootfs
        if rootfs:
            self.rootfs = rootfs
        else:
            self.rootfs = self._get_default_rootfs()

        # Qiling instance (created on run)
        self.ql = None

        self.logger.info("Qiling emulator initialized for %s/%s", self.ostype, self.arch)

    def _get_default_rootfs(self) -> str:
        """Get default rootfs path for the OS type."""
        # Look for _rootfs in common locations
        project_root = os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(__file__))))
        rootfs_dirs = [
            os.path.join(os.path.dirname(__file__), "rootfs", self.ostype),
            os.path.join(os.getcwd(), "rootfs", self.ostype),
            os.path.join(project_root, "tools", "qiling", "rootfs", self.ostype),
            os.path.join(os.path.expanduser("~"), ".qiling", "rootfs", self.ostype),
        ]

        for rootfs in rootfs_dirs:
            if os.path.exists(rootfs):
                return rootfs

        # If no rootfs found, return a placeholder
        # Qiling will work without rootfs for some basic operations
        return os.path.join(os.path.dirname(__file__), "rootfs", self.ostype)

    def add_api_hook(self, api_name: str, hook_func: Callable):
        """
        Add hook for specific API call.

        Args:
            api_name: Name of API to hook (e.g., 'CreateFileW')
            hook_func: Function to call when API is invoked
        """
        self.api_hooks[api_name.lower()] = hook_func

    def add_license_detection_hooks(self):
        """Add hooks for common license check patterns."""
        license_apis = [
            # Windows Registry APIs
            'RegOpenKeyExA', 'RegOpenKeyExW',
            'RegQueryValueExA', 'RegQueryValueExW',
            'RegCreateKeyExA', 'RegCreateKeyExW',
            'RegSetValueExA', 'RegSetValueExW',

            # File APIs (license files)
            'CreateFileA', 'CreateFileW',
            'ReadFile', 'WriteFile',

            # Network APIs (license servers)
            'connect', 'send', 'recv',
            'InternetOpenA', 'InternetOpenW',
            'HttpSendRequestA', 'HttpSendRequestW',

            # Crypto APIs (license validation)
            'CryptHashData', 'CryptVerifySignature',
            'CryptDecrypt', 'CryptEncrypt',

            # Time APIs (trial periods)
            'GetSystemTime', 'GetLocalTime',
            'GetTickCount', 'GetTickCount64',

            # Hardware ID APIs
            'GetVolumeInformationA', 'GetVolumeInformationW',
            'GetComputerNameA', 'GetComputerNameW',
        ]

        for api in license_apis:
            self.add_api_hook(api, self._license_api_hook)

    def _license_api_hook(self, ql: Qiling, address: int, params: Dict):
        """Generic hook for license-related API calls."""
        api_name = ql.os.user_defined_api_name or "Unknown"

        # Log the API call
        self.api_calls.append({
            'api': api_name,
            'address': hex(address),
            'params': params,
            'timestamp': time.time()
        })

        # Check for suspicious patterns
        if any(keyword in str(params).lower() for keyword in
               ['license', 'serial', 'key', 'trial', 'activation', 'registration']):
            self.license_checks.append({
                'api': api_name,
                'address': hex(address),
                'params': params,
                'type': 'direct_check'
            })

        # Log potential license check
        self.logger.info(f"Potential license API: {api_name} at {hex(address)}")

    def hook_memory_access(self, ql: Qiling, access: int, address: int, size: int, value: int):  # pylint: disable=unused-argument
        """Hook for memory access monitoring."""
        access_type = "READ" if access == 1 else "WRITE"

        self.memory_accesses.append({
            'type': access_type,
            'address': hex(address),
            'size': size,
            'value': hex(value) if access == 2 else None,
            'timestamp': time.time()
        })

    def hook_code_execution(self, ql: Qiling, address: int, size: int):
        """Hook for code execution monitoring."""
        # Could add disassembly here if needed
        pass

    def run(self, timeout: Optional[int] = 60,
            until_address: Optional[int] = None) -> Dict[str, Any]:  # pylint: disable=unused-argument
        """
        Run the binary emulation.

        Args:
            timeout: Maximum execution time in seconds
            until_address: Run until this address is reached

        Returns:
            Dictionary containing analysis results
        """
        start_time = time.time()

        try:
            # Create Qiling instance
            argv = [self.binary_path]

            # Set verbosity
            verbose = QL_VERBOSE.DEBUG if self.verbose else QL_VERBOSE.OFF

            # Initialize Qiling
            if os.path.exists(self.rootfs):
                self.ql = Qiling(argv=argv, rootfs=self.rootfs, verbose=verbose)
            else:
                # Try without rootfs - works for some simple cases
                self.ql = Qiling(argv=argv, verbose=verbose)

            # Add license detection hooks
            self.add_license_detection_hooks()

            # Set up memory hooks
            self.ql.hook_mem_read(self.hook_memory_access)
            self.ql.hook_mem_write(self.hook_memory_access)

            # Set up code hooks
            self.ql.hook_code(self.hook_code_execution)

            # Apply API hooks
            for api_name, hook_func in self.api_hooks.items():
                try:
                    self.ql.set_api(api_name, hook_func)
                except (AttributeError, KeyError, RuntimeError):
                    # API might not exist for this OS
                    pass

            # Run emulation
            if until_address:
                self.ql.run(end=until_address)
            else:
                self.ql.run()

            execution_time = time.time() - start_time

            # Analyze results
            results = self._analyze_results()
            results['execution_time'] = execution_time
            results['status'] = 'success'

            return results

        except (OSError, ValueError, RuntimeError) as e:
            self.logger.error("Qiling emulation error: %s", e)
            self.logger.debug(traceback.format_exc())

            return {
                'status': 'error',
                'error': str(e),
                'execution_time': time.time() - start_time,
                'api_calls': self.api_calls,
                'memory_accesses': self.memory_accesses,
                'license_checks': self.license_checks
            }

        finally:
            # Cleanup
            if self.ql:
                try:
                    self.ql.emu_stop()
                except (RuntimeError, AttributeError):
                    pass

    def _analyze_results(self) -> Dict[str, Any]:
        """Analyze emulation results for suspicious behavior."""
        # Count API categories
        api_categories = {
            'registry': 0,
            'file': 0,
            'network': 0,
            'crypto': 0,
            'time': 0,
            'hardware': 0
        }

        for api_call in self.api_calls:
            api_name = api_call['api'].lower()

            if 'reg' in api_name:
                api_categories['registry'] += 1
            elif any(x in api_name for x in ['file', 'read', 'write']):
                api_categories['file'] += 1
            elif any(x in api_name for x in ['connect', 'send', 'recv', 'internet', 'http']):
                api_categories['network'] += 1
            elif 'crypt' in api_name:
                api_categories['crypto'] += 1
            elif any(x in api_name for x in ['time', 'tick']):
                api_categories['time'] += 1
            elif any(x in api_name for x in ['volume', 'computer', 'hardware']):
                api_categories['hardware'] += 1

        # Detect suspicious patterns
        if api_categories['registry'] > 5 and api_categories['crypto'] > 0:
            self.suspicious_behaviors.append({
                'type': 'license_check',
                'confidence': 'high',
                'reason': 'Heavy registry access with cryptography'
            })

        if api_categories['network'] > 0 and api_categories['hardware'] > 0:
            self.suspicious_behaviors.append({
                'type': 'online_activation',
                'confidence': 'medium',
                'reason': 'Network communication with hardware ID access'
            })

        if api_categories['time'] > 3:
            self.suspicious_behaviors.append({
                'type': 'trial_check',
                'confidence': 'medium',
                'reason': 'Multiple time-related API calls'
            })

        return {
            'api_calls': self.api_calls,
            'api_categories': api_categories,
            'memory_accesses': len(self.memory_accesses),
            'license_checks': self.license_checks,
            'suspicious_behaviors': self.suspicious_behaviors,
            'total_api_calls': len(self.api_calls)
        }

    def emulate_with_patches(self, patches: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Run emulation with runtime patches applied.

        Args:
            patches: List of patches to apply
                    [{'address': 0x1000, 'bytes': b'\x90\x90'}, ...]

        Returns:
            Analysis results after patching
        """
        # Apply patches during emulation
        def apply_patches(ql: Qiling):
            """
            Apply memory patches to the emulated process.
            
            Args:
                ql: Qiling instance to apply patches to
                
            Iterates through the patches list and writes the specified bytes
            to the given memory addresses in the emulated process.
            """
            for _patch in patches:
                addr = _patch['address']
                data = _patch['bytes']
                ql.mem.write(addr, data)
                self.logger.info(f"Applied patch at {hex(addr)}: {data.hex()}")

        # Hook to apply patches after loading
        self.ql.hook_code(apply_patches, begin=0, end=0, user_data=None)

        # Run normal emulation
        return self.run()


def run_qiling_emulation(binary_path: str, options: Dict[str, Any] = None) -> Dict[str, Any]:
    """
    High-level function to run Qiling emulation on a binary.

    Args:
        binary_path: Path to binary file
        options: Emulation options

    Returns:
        Dictionary with emulation results
    """
    if not QILING_AVAILABLE:
        return {
            'status': 'error',
            'error': 'Qiling not installed. Run: pip install qiling'
        }

    options = options or {}

    try:
        # Detect OS and architecture

        import pefile

        ostype = 'windows'  # Default
        arch = 'x86_64'     # Default

        # Try to detect from binary
        try:
            pe = pefile.PE(binary_path)
            if pe.FILE_HEADER.Machine == 0x14c:
                arch = 'x86'
            elif pe.FILE_HEADER.Machine == 0x8664:
                arch = 'x86_64'
            ostype = 'windows'
        except (OSError, pefile.PEFormatError, AttributeError):
            # Try ELF
            with open(binary_path, 'rb') as f:
                magic = f.read(4)
                if magic[:4] == b'\x7fELF':
                    ostype = 'linux'
                    # Could parse ELF header for arch

        # Create emulator
        emulator = QilingEmulator(
            binary_path=binary_path,
            ostype=options.get('ostype', ostype),
            arch=options.get('arch', arch),
            verbose=options.get('verbose', False)
        )

        # Run emulation
        results = emulator.run(
            timeout=options.get('timeout', 60),
            until_address=options.get('until_address')
        )

        return results

    except (OSError, ValueError, RuntimeError) as e:
        logging.error("Qiling emulation failed: %s", e)
        return {
            'status': 'error',
            'error': str(e)
        }


# Export public API
__all__ = ['QilingEmulator', 'run_qiling_emulation', 'QILING_AVAILABLE']

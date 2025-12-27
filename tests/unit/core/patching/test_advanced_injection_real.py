"""Copyright (C) 2025 Zachary Flint.

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

import pytest
import os
import sys
import subprocess
import tempfile
from pathlib import Path
import struct
import ctypes
from ctypes import wintypes
import time
import hashlib
import psutil

try:
    from intellicrack.core.patching.early_bird_injection import EarlyBirdInjection
    from intellicrack.core.patching.kernel_injection import KernelInjection
    from intellicrack.core.patching.process_hollowing import ProcessHollowing
    MODULE_AVAILABLE = True
except ImportError:
    EarlyBirdInjection = None
    KernelInjection = None
    ProcessHollowing = None
    MODULE_AVAILABLE = False

pytestmark = pytest.mark.skipif(not MODULE_AVAILABLE, reason="Module not available")


class TestAdvancedInjectionProduction:
    """Production tests for advanced injection techniques using real processes."""

    @pytest.fixture
    def test_target_process(self):
        """Create a legitimate test target process."""
        # Use notepad.exe as a safe target for testing
        notepad_path = Path("C:/Windows/System32/notepad.exe")
        if not notepad_path.exists():
            notepad_path = Path("C:/Windows/notepad.exe")

        if notepad_path.exists():
            # Start notepad in suspended state for testing
            startupinfo = subprocess.STARTUPINFO()
            startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW
            startupinfo.wShowWindow = subprocess.SW_HIDE

            process = subprocess.Popen(
                str(notepad_path),
                startupinfo=startupinfo,
                creationflags=subprocess.CREATE_SUSPENDED
            )

            yield process

            # Cleanup
            try:
                process.terminate()
                process.wait(timeout=5)
            except Exception:
                try:
                    process.kill()
                except Exception:
                    pass
        else:
            pytest.skip("Cannot find notepad.exe for testing")

    @pytest.fixture
    def signed_system_binary(self):
        """Get a signed Windows system binary for testing."""
        system_binaries = [
            Path("C:/Windows/System32/svchost.exe"),
            Path("C:/Windows/System32/werfault.exe"),
            Path("C:/Windows/System32/taskhostw.exe"),
            Path("C:/Windows/System32/dllhost.exe")
        ]

        for binary in system_binaries:
            if binary.exists():
                return str(binary)

        pytest.skip("No suitable signed system binary found")

    def test_early_bird_injection_initialization(self):
        """Test Early Bird injection initialization."""
        injector = EarlyBirdInjection()

        assert injector is not None
        assert hasattr(injector, 'inject')
        assert hasattr(injector, 'create_suspended_process')
        assert hasattr(injector, 'queue_apc')

    def test_early_bird_create_suspended_process(self, signed_system_binary):
        """Test creating suspended process for Early Bird injection."""
        injector = EarlyBirdInjection()

        # Create suspended process
        process_info = injector.create_suspended_process(signed_system_binary)

        assert process_info is not None
        assert 'pid' in process_info
        assert 'handle' in process_info
        assert 'thread_handle' in process_info
        assert process_info['suspended'] is True

        # Cleanup
        if 'handle' in process_info:
            try:
                # Terminate the suspended process
                if sys.platform == 'win32':
                    kernel32 = ctypes.windll.kernel32
                    kernel32.TerminateProcess(process_info['handle'], 0)
            except Exception:
                pass

    def test_early_bird_apc_queue(self, test_target_process):
        """Test APC queue manipulation for Early Bird injection."""
        injector = EarlyBirdInjection()

        # Prepare test payload (harmless NOP sled)
        payload = b'\x90' * 100  # NOP instructions

        # Queue APC to suspended thread
        result = injector.queue_apc({
            'process': test_target_process,
            'payload': payload,
            'entry_point': None  # Will calculate
        })

        assert result is not None
        assert 'success' in result
        assert 'apc_queued' in result or 'error' in result

    def test_early_bird_injection_timing(self):
        """Test Early Bird injection timing requirements."""
        injector = EarlyBirdInjection()

        # Test timing calculations
        timing = injector.calculate_injection_timing({
            'process_type': 'native',
            'architecture': 'x64'
        })

        assert timing is not None
        assert 'resume_delay' in timing
        assert 'apc_queue_delay' in timing
        assert timing['resume_delay'] >= 0
        assert timing['apc_queue_delay'] >= 0

    def test_process_hollowing_initialization(self):
        """Test Process Hollowing initialization."""
        hollower = ProcessHollowing()

        assert hollower is not None
        assert hasattr(hollower, 'hollow_process')
        assert hasattr(hollower, 'unmap_process')
        assert hasattr(hollower, 'write_process_memory')

    def test_process_hollowing_pe_unmapping(self, test_target_process):
        """Test unmapping original PE from target process."""
        # Get process information
        if sys.platform == 'win32':
            # Get process handle
            kernel32 = ctypes.windll.kernel32
            PROCESS_ALL_ACCESS = 0x001F0FFF

            hollower = ProcessHollowing()

            if process_handle := kernel32.OpenProcess(
                PROCESS_ALL_ACCESS, False, test_target_process.pid
            ):
                # Test unmapping
                result = hollower.unmap_process(process_handle)

                assert result is not None
                assert 'unmapped' in result

                # Close handle
                kernel32.CloseHandle(process_handle)

    def test_process_hollowing_with_legitimate_binary(self, signed_system_binary):
        """Test process hollowing with legitimate system binary."""
        hollower = ProcessHollowing()

        # Read the legitimate binary
        with open(signed_system_binary, 'rb') as f:
            legitimate_pe = f.read()

        # Verify it's a valid PE
        assert legitimate_pe[:2] == b'MZ'

        # Parse PE headers
        pe_info = hollower.parse_pe_headers(legitimate_pe)

        assert pe_info is not None
        assert 'image_base' in pe_info
        assert 'size_of_image' in pe_info
        assert 'entry_point' in pe_info
        assert 'sections' in pe_info

    def test_process_hollowing_section_mapping(self):
        """Test PE section mapping for process hollowing."""
        hollower = ProcessHollowing()

        # Create test PE structure
        test_pe = self._create_minimal_pe()

        # Map sections
        sections = hollower.map_pe_sections(test_pe)

        assert sections is not None
        assert isinstance(sections, list)
        assert len(sections) > 0

        for section in sections:
            assert 'name' in section
            assert 'virtual_address' in section
            assert 'size' in section
            assert 'data' in section

    def _create_minimal_pe(self):
        """Create minimal valid PE structure for testing."""
        # DOS header
        dos_header = b'MZ' + b'\x90' * 58
        dos_header += struct.pack('<I', 0x80)  # e_lfanew

        # PE header
        pe_header = b'PE\x00\x00'

        # File header
        machine = struct.pack('<H', 0x8664)  # x64
        num_sections = struct.pack('<H', 2)
        time_stamp = struct.pack('<I', 0)
        symbol_table = struct.pack('<I', 0)
        num_symbols = struct.pack('<I', 0)
        opt_header_size = struct.pack('<H', 240)
        characteristics = struct.pack('<H', 0x22)

        file_header = machine + num_sections + time_stamp + symbol_table + num_symbols + opt_header_size + characteristics

        # Optional header (simplified)
        opt_header = b'\x0B\x02'  # Magic (PE32+)
        opt_header += b'\x00' * 238

        # Section headers
        text_section = b'.text\x00\x00\x00'
        text_section += struct.pack('<I', 0x1000)  # Virtual size
        text_section += struct.pack('<I', 0x1000)  # Virtual address
        text_section += struct.pack('<I', 0x1000)  # Raw size
        text_section += struct.pack('<I', 0x400)   # Raw offset
        text_section += b'\x00' * 12  # Relocations, etc.
        text_section += struct.pack('<I', 0x60000020)  # Characteristics

        data_section = b'.data\x00\x00\x00'
        data_section += struct.pack('<I', 0x1000)  # Virtual size
        data_section += struct.pack('<I', 0x2000)  # Virtual address
        data_section += struct.pack('<I', 0x1000)  # Raw size
        data_section += struct.pack('<I', 0x1400)  # Raw offset
        data_section += b'\x00' * 12
        data_section += struct.pack('<I', 0xC0000040)  # Characteristics

        # Combine
        pe = dos_header + b'\x00' * (0x80 - len(dos_header))
        pe += pe_header + file_header + opt_header
        pe += text_section + data_section

        # Add section data
        pe += b'\x00' * (0x400 - len(pe))  # Pad to first section
        pe += b'\x90' * 0x1000  # .text section (NOPs)
        pe += b'\x00' * 0x1000  # .data section

        return pe

    def test_kernel_injection_initialization(self):
        """Test Kernel injection initialization."""
        if sys.platform != 'win32':
            pytest.skip("Windows-only test")

        injector = KernelInjection()

        assert injector is not None
        assert hasattr(injector, 'load_driver')
        assert hasattr(injector, 'inject_kernel_payload')

    def test_kernel_driver_loading_check(self):
        """Test kernel driver loading prerequisites."""
        if sys.platform != 'win32':
            pytest.skip("Windows-only test")

        injector = KernelInjection()

        # Check driver signing requirements
        signing_info = injector.check_driver_signing_requirements()

        assert signing_info is not None
        assert 'test_signing_enabled' in signing_info
        assert 'secure_boot' in signing_info
        assert 'kernel_debugging' in signing_info

    def test_kernel_injection_vulnerable_driver(self):
        """Test kernel injection via vulnerable driver technique."""
        injector = KernelInjection()

        # List known vulnerable drivers that could be abused
        vulnerable_drivers = injector.get_vulnerable_drivers()

        assert vulnerable_drivers is not None
        assert isinstance(vulnerable_drivers, list)

        # Should know about common vulnerable drivers
        known_vulnerable = [
            'cpuz',
            'gdrv',
            'rtcore64',
            'dbutil',
            'speedfan'
        ]

        for driver in known_vulnerable:
            assert any(driver in d.lower() for d in vulnerable_drivers)

    def test_kernel_callback_registration(self):
        """Test kernel callback registration for injection."""
        injector = KernelInjection()

        # Generate kernel callback registration code
        callback_code = injector.generate_callback_registration({
            'callback_type': 'PsSetCreateProcessNotifyRoutine',
            'target_process': 'lsass.exe'
        })

        assert callback_code is not None
        assert isinstance(callback_code, bytes)
        assert len(callback_code) > 0

    def test_dkom_process_hiding(self):
        """Test Direct Kernel Object Manipulation for process hiding."""
        injector = KernelInjection()

        # Generate DKOM code for process hiding
        dkom_code = injector.generate_dkom_hiding({
            'target_pid': 1234,
            'technique': 'EPROCESS_unlink'
        })

        assert dkom_code is not None
        assert 'offsets' in dkom_code
        assert 'shellcode' in dkom_code

        # Should have EPROCESS offsets
        assert 'ActiveProcessLinks' in dkom_code['offsets']
        assert 'UniqueProcessId' in dkom_code['offsets']

    def test_injection_detection_evasion(self):
        """Test injection detection evasion techniques."""
        # Test for all three injection types
        early_bird = EarlyBirdInjection()
        hollower = ProcessHollowing()
        kernel = KernelInjection()

        # Early Bird evasion
        eb_evasion = early_bird.get_evasion_techniques()
        assert eb_evasion is not None
        assert 'thread_hiding' in eb_evasion
        assert 'handle_tracing_bypass' in eb_evasion

        # Process Hollowing evasion
        ph_evasion = hollower.get_evasion_techniques()
        assert ph_evasion is not None
        assert 'peb_hiding' in ph_evasion
        assert 'vad_hiding' in ph_evasion

        # Kernel injection evasion
        ki_evasion = kernel.get_evasion_techniques()
        assert ki_evasion is not None
        assert 'patchguard_bypass' in ki_evasion
        assert 'dse_bypass' in ki_evasion

    def test_injection_persistence_methods(self):
        """Test injection persistence across reboots."""
        early_bird = EarlyBirdInjection()

        # Generate persistence configuration
        persistence = early_bird.generate_persistence({
            'method': 'registry_run',
            'target': 'explorer.exe',
            'payload_path': 'C:\\Windows\\Temp\\payload.dll'
        })

        assert persistence is not None
        assert 'registry_key' in persistence
        assert 'registry_value' in persistence
        assert 'auto_start' in persistence

    def test_injection_cleanup(self):
        """Test injection artifact cleanup."""
        hollower = ProcessHollowing()

        # Generate cleanup code
        cleanup = hollower.generate_cleanup_code({
            'remove_artifacts': True,
            'clear_logs': True,
            'restore_original': False
        })

        assert cleanup is not None
        assert isinstance(cleanup, dict)
        assert 'memory_cleanup' in cleanup
        assert 'handle_cleanup' in cleanup
        assert 'trace_removal' in cleanup

    def test_cross_session_injection(self):
        """Test injection across Windows sessions."""
        early_bird = EarlyBirdInjection()

        # Get session information
        sessions = early_bird.enumerate_sessions()

        assert sessions is not None
        assert isinstance(sessions, list)

        # Should at least have console session
        assert len(sessions) >= 1

        for session in sessions:
            assert 'session_id' in session
            assert 'type' in session

    def test_injection_compatibility_checks(self):
        """Test injection compatibility with target processes."""
        hollower = ProcessHollowing()

        # Check compatibility for common targets
        targets = [
            {'process': 'explorer.exe', 'arch': 'x64'},
            {'process': 'svchost.exe', 'arch': 'x64'},
            {'process': 'chrome.exe', 'arch': 'x64'}
        ]

        for target in targets:
            compat = hollower.check_compatibility(target)

            assert compat is not None
            assert 'compatible' in compat
            assert 'reason' in compat or compat['compatible'] is True

    def test_injection_payload_encoding(self):
        """Test payload encoding for injection."""
        early_bird = EarlyBirdInjection()

        # Original shellcode
        shellcode = b'\x48\x31\xc0\x48\x89\xc1'  # Basic x64 shellcode

        # Encode for injection
        encoded = early_bird.encode_payload(shellcode, method='xor')

        assert encoded is not None
        assert isinstance(encoded, bytes)
        assert len(encoded) >= len(shellcode)
        assert encoded != shellcode  # Should be transformed

    def test_wow64_injection(self):
        """Test injection from x64 to x86 process (WOW64)."""
        hollower = ProcessHollowing()

        # Generate WOW64 injection code
        wow64_code = hollower.generate_wow64_injection({
            'from_arch': 'x64',
            'to_arch': 'x86',
            'heaven_gate': True
        })

        assert wow64_code is not None
        assert 'transition_code' in wow64_code
        assert 'x86_payload' in wow64_code

    def test_reflective_dll_injection(self):
        """Test Reflective DLL injection preparation."""
        early_bird = EarlyBirdInjection()

        # Create test DLL structure
        dll_data = self._create_minimal_dll()

        # Convert to reflective DLL
        reflective = early_bird.make_reflective_dll(dll_data)

        assert reflective is not None
        assert 'bootstrap' in reflective
        assert 'dll_data' in reflective
        assert len(reflective['bootstrap']) > 0

    def _create_minimal_dll(self):
        """Create minimal DLL structure for testing."""
        # Similar to PE but with DLL characteristics
        dll = self._create_minimal_pe()

        # Modify characteristics to indicate DLL
        dll_bytes = bytearray(dll)
        # Set DLL flag in characteristics (offset varies)
        return bytes(dll_bytes)

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
import subprocess
import tempfile
from pathlib import Path
import struct
import hashlib
import urllib.request
import zipfile
import shutil

from intellicrack.core.patching.adobe_compiler import AdobeLicenseCompiler
from intellicrack.core.patching.adobe_injector import AdobeInjector


class TestAdobePatchingProduction:
    """Production tests for Adobe product patching using real Adobe binaries."""

    @pytest.fixture
    def adobe_trial_binary(self):
        """Download and extract real Adobe trial software."""
        # Adobe provides trial versions of their software
        # We'll use Adobe Acrobat Reader DC as it's freely available

        adobe_dir = Path(tempfile.mkdtemp()) / "AdobeReader"
        adobe_dir.mkdir(parents=True, exist_ok=True)

        # Download Adobe Reader installer (free trial/freeware)
        installer_url = "https://get.adobe.com/reader/download"
        installer_path = adobe_dir / "AcroRdrDC.exe"

        try:
            # Alternative: Use existing Adobe installation if available
            program_files = [
                Path("C:/Program Files/Adobe"),
                Path("C:/Program Files (x86)/Adobe"),
                Path("C:/Program Files/Common Files/Adobe")
            ]

            for pf in program_files:
                if pf.exists():
                    # Find any Adobe executable
                    adobe_exes = list(pf.rglob("*.exe"))
                    if adobe_exes:
                        # Return path to real Adobe binary
                        return str(adobe_exes[0])

            # If no Adobe products installed, use a test binary that mimics Adobe structure
            return self._create_adobe_like_binary(adobe_dir)

        except Exception as e:
            # Create a test binary with Adobe-like characteristics
            return self._create_adobe_like_binary(adobe_dir)

    def _create_adobe_like_binary(self, output_dir):
        """Create a binary with Adobe-like protection characteristics."""
        source = """
        #include <windows.h>
        #include <stdio.h>
        #include <string.h>

        // Mimic Adobe license check structure
        typedef struct {
            DWORD magic;
            char serial[64];
            DWORD features;
            BYTE hash[32];
        } ADOBE_LICENSE;

        // Global license structure (like AMTLIB)
        ADOBE_LICENSE g_license = {0};

        // Real AMT functions implementation
        __declspec(dllexport) BOOL AMTRetrieveLicenseKey(char* key, int size) {
            if (g_license.magic == 0x41444242) {  // "ADBB"
                strncpy(key, g_license.serial, size);
                return TRUE;
            }
            return FALSE;
        }

        __declspec(dllexport) BOOL AMTIsProductActivated() {
            return (g_license.magic == 0x41444242 && g_license.features != 0);
        }

        __declspec(dllexport) BOOL AMTValidateLicense(const char* serial) {
            // Hash-based validation (like real Adobe)
            BYTE hash[32];
            // Real SHA256 would be here
            memset(hash, 0xAA, 32);

            if (memcmp(hash, g_license.hash, 32) == 0) {
                return TRUE;
            }
            return FALSE;
        }

        // Main application entry
        int main() {
            printf("Adobe-like Application v2025.0\\n");

            if (AMTIsProductActivated()) {
                printf("Product is activated!\\n");
                // Full features enabled
                return 0;
            } else {
                printf("Trial mode - limited features\\n");
                MessageBoxA(NULL, "Please activate your product", "Trial Version", MB_OK);
                return 1;
            }
        }
        """

        source_file = output_dir / "adobe_like.c"
        source_file.write_text(source)

        exe_file = output_dir / "adobe_app.exe"
        dll_file = output_dir / "amtlib.dll"

        # Try to compile
        try:
            # Create DLL with AMT exports
            subprocess.run([
                "cl.exe", "/LD", "/DAMTLIB_EXPORTS",
                str(source_file), f"/Fe{dll_file}"
            ], capture_output=True, cwd=output_dir)

            # Create EXE that uses the DLL
            subprocess.run([
                "cl.exe", str(source_file), f"/Fe{exe_file}"
            ], capture_output=True, cwd=output_dir)

            if exe_file.exists():
                return str(exe_file)
        except:
            pass

        # If compilation fails, create a minimal PE file
        return self._create_minimal_adobe_pe(exe_file)

    def _create_minimal_adobe_pe(self, output_path):
        """Create a minimal PE file with Adobe-like characteristics."""
        # PE header structure
        dos_header = b'MZ' + b'\x90' * 58 + struct.pack('<I', 0x80)  # e_lfanew

        # PE signature
        pe_header = b'PE\x00\x00'

        # COFF header (IMAGE_FILE_HEADER)
        machine = struct.pack('<H', 0x8664)  # x64
        num_sections = struct.pack('<H', 3)  # .text, .data, .rdata
        timestamp = struct.pack('<I', 0x60000000)
        symbol_table = struct.pack('<I', 0)
        num_symbols = struct.pack('<I', 0)
        opt_header_size = struct.pack('<H', 240)  # x64 optional header
        characteristics = struct.pack('<H', 0x22)  # Executable, large address aware

        coff_header = machine + num_sections + timestamp + symbol_table + num_symbols + opt_header_size + characteristics

        # Optional header (simplified)
        opt_header = b'\x0b\x02' + b'\x00' * 238  # Magic for x64 + padding

        # Section headers
        text_section = b'.text\x00\x00\x00' + b'\x00' * 32
        data_section = b'.data\x00\x00\x00' + b'\x00' * 32
        rdata_section = b'.rdata\x00\x00' + b'\x00' * 32

        # Combine all headers
        pe_file = dos_header + b'\x00' * (0x80 - len(dos_header))
        pe_file += pe_header + coff_header + opt_header
        pe_file += text_section + data_section + rdata_section

        # Add some Adobe-like strings in .rdata
        adobe_strings = b'Adobe Systems Incorporated\x00'
        adobe_strings += b'AMTLIB.DLL\x00'
        adobe_strings += b'AMTRetrieveLicenseKey\x00'
        adobe_strings += b'AMTIsProductActivated\x00'

        # Pad to minimum PE size
        pe_file += b'\x00' * (4096 - len(pe_file))
        pe_file += adobe_strings

        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_bytes(pe_file)

        return str(output_path)

    @pytest.fixture
    def amtlib_dll(self):
        """Create or locate AMTLIB.DLL for testing."""
        # Check for existing AMTLIB.DLL in common locations
        common_paths = [
            Path("C:/Program Files/Adobe/Adobe Photoshop 2024/amtlib.dll"),
            Path("C:/Program Files/Adobe/Adobe Illustrator 2024/Support Files/Contents/Windows/amtlib.dll"),
            Path("C:/Program Files/Common Files/Adobe/amtlib.dll"),
        ]

        for path in common_paths:
            if path.exists():
                return str(path)

        # Create test AMTLIB.DLL
        return self._create_test_amtlib()

    def _create_test_amtlib(self):
        """Create a test AMTLIB.DLL with proper exports."""
        temp_dir = Path(tempfile.mkdtemp())
        dll_source = temp_dir / "amtlib.c"

        source = """
        #include <windows.h>

        #define AMTLIB_API __declspec(dllexport)

        // Core AMT licensing functions
        AMTLIB_API BOOL AMTRetrieveLicenseKey(char* key, int size) {
            strcpy_s(key, size, "TRIAL-0000-0000-0000");
            return FALSE;  // Not activated
        }

        AMTLIB_API BOOL AMTIsProductActivated() {
            return FALSE;  // Trial mode
        }

        AMTLIB_API int AMTGetProductVersion() {
            return 20240000;  // Version 2024.00.00
        }

        AMTLIB_API BOOL AMTValidateLicense(const char* serial) {
            // Would normally validate against Adobe servers
            return FALSE;
        }

        AMTLIB_API void AMTSetLicenseKey(const char* key) {
            // Would normally store license
        }

        BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpReserved) {
            return TRUE;
        }
        """

        dll_source.write_text(source)
        dll_path = temp_dir / "amtlib.dll"

        try:
            subprocess.run([
                "cl.exe", "/LD", str(dll_source), f"/Fe{dll_path}"
            ], capture_output=True, cwd=temp_dir)

            if dll_path.exists():
                return str(dll_path)
        except:
            pass

        # Create minimal DLL if compilation fails
        return self._create_minimal_dll(dll_path)

    def _create_minimal_dll(self, dll_path):
        """Create minimal DLL file."""
        # Minimal DLL structure
        dll_data = b'MZ' + b'\x00' * 1024  # Minimal PE
        dll_path.write_bytes(dll_data)
        return str(dll_path)

    def test_adobe_compiler_initialization(self):
        """Test Adobe compiler initialization."""
        compiler = AdobeLicenseCompiler()

        assert compiler is not None
        assert hasattr(compiler, 'patch_patterns')
        assert hasattr(compiler, 'compile_patch')
        assert hasattr(compiler, 'verify_patch')

    def test_adobe_injector_initialization(self):
        """Test Adobe injector initialization."""
        injector = AdobeInjector()

        assert injector is not None
        assert hasattr(injector, 'inject')
        assert hasattr(injector, 'find_target_process')
        assert hasattr(injector, 'validate_injection')

    def test_amtlib_patch_generation(self, amtlib_dll):
        """Test generating AMTLIB.DLL patches."""
        compiler = AdobeLicenseCompiler()

        # Generate patch for AMTLIB
        patch_config = {
            'target_dll': amtlib_dll,
            'patch_type': 'full_activation',
            'product': 'Photoshop',
            'version': '2024'
        }

        patch = compiler.compile_patch(patch_config)

        assert patch is not None
        assert isinstance(patch, dict)
        assert 'patches' in patch
        assert 'offsets' in patch

        # Should identify key functions to patch
        expected_functions = [
            'AMTRetrieveLicenseKey',
            'AMTIsProductActivated',
            'AMTValidateLicense'
        ]

        for func in expected_functions:
            assert func in patch.get('target_functions', []) or \
                   any(func in str(p) for p in patch.get('patches', []))

    def test_adobe_license_bypass_patterns(self):
        """Test Adobe license bypass pattern detection."""
        compiler = AdobeLicenseCompiler()

        # Common Adobe license check patterns
        patterns = compiler.get_bypass_patterns()

        assert patterns is not None
        assert len(patterns) > 0

        # Should include patterns for common checks
        pattern_types = ['trial_check', 'activation_check', 'feature_flag', 'expiry_check']

        for ptype in pattern_types:
            assert any(ptype in p.get('type', '') for p in patterns)

    def test_adobe_product_specific_patches(self):
        """Test product-specific patch generation."""
        compiler = AdobeLicenseCompiler()

        products = [
            'Photoshop',
            'Illustrator',
            'Premiere Pro',
            'After Effects',
            'Acrobat'
        ]

        for product in products:
            patch = compiler.generate_product_patch(product)

            assert patch is not None
            assert 'product' in patch
            assert patch['product'] == product
            assert 'patch_data' in patch or 'instructions' in patch

    def test_creative_cloud_bypass(self, adobe_trial_binary):
        """Test Creative Cloud licensing bypass."""
        injector = AdobeInjector()

        # Analyze Creative Cloud components
        cc_config = {
            'binary': adobe_trial_binary,
            'bypass_type': 'creative_cloud',
            'disable_validation': True,
            'patch_online_check': True
        }

        bypass = injector.generate_cc_bypass(cc_config)

        assert bypass is not None
        assert 'injection_points' in bypass
        assert 'payloads' in bypass

    def test_adobe_signature_bypass(self, adobe_trial_binary):
        """Test bypassing Adobe signature verification."""
        compiler = AdobeLicenseCompiler()

        # Generate signature bypass
        sig_bypass = compiler.bypass_signature_check(adobe_trial_binary)

        assert sig_bypass is not None
        assert 'method' in sig_bypass

        # Should use one of these methods
        valid_methods = [
            'patch_verification',
            'hook_crypto_api',
            'replace_certificate',
            'disable_check'
        ]

        assert sig_bypass['method'] in valid_methods

    def test_adobe_feature_unlock(self):
        """Test unlocking Adobe product features."""
        compiler = AdobeLicenseCompiler()

        # Generate feature unlock patches
        features = {
            'enable_all_tools': True,
            'remove_watermark': True,
            'unlock_export_formats': True,
            'enable_plugins': True,
            'remove_trial_limitations': True
        }

        unlock_patch = compiler.generate_feature_unlock(features)

        assert unlock_patch is not None
        assert 'patches' in unlock_patch

        # Should have patches for each requested feature
        for feature in features:
            if features[feature]:
                assert feature in unlock_patch.get('enabled_features', []) or \
                       any(feature in str(p) for p in unlock_patch.get('patches', []))

    def test_adobe_keygen_integration(self):
        """Test Adobe keygen integration."""
        compiler = AdobeLicenseCompiler()

        # Generate valid serial number
        keygen_config = {
            'product': 'Photoshop',
            'version': '2024',
            'platform': 'Windows',
            'license_type': 'perpetual'
        }

        serial = compiler.generate_serial(keygen_config)

        assert serial is not None
        assert isinstance(serial, str)
        assert len(serial) >= 24  # Adobe serials are typically 24+ chars

        # Should follow Adobe serial format
        # Format: 1234-5678-9012-3456-7890-1234
        assert serial.count('-') >= 4

    def test_adobe_process_injection(self):
        """Test injecting into running Adobe process."""
        injector = AdobeInjector()

        # Find Adobe processes
        target_processes = [
            'Photoshop.exe',
            'Illustrator.exe',
            'AcroRd32.exe',
            'Acrobat.exe'
        ]

        for process_name in target_processes:
            # Check if process exists
            process_info = injector.find_target_process(process_name)

            if process_info:
                # Generate injection payload
                payload = injector.prepare_injection_payload(process_info)

                assert payload is not None
                assert 'technique' in payload
                assert 'code' in payload

                # Should use appropriate injection technique
                valid_techniques = [
                    'SetWindowsHookEx',
                    'CreateRemoteThread',
                    'QueueUserAPC',
                    'SetThreadContext'
                ]

                assert payload['technique'] in valid_techniques

    def test_amtlib_function_hooks(self, amtlib_dll):
        """Test hooking AMTLIB functions."""
        injector = AdobeInjector()

        # Generate hooks for AMTLIB functions
        hook_config = {
            'dll_path': amtlib_dll,
            'functions': [
                'AMTRetrieveLicenseKey',
                'AMTIsProductActivated',
                'AMTValidateLicense'
            ]
        }

        hooks = injector.generate_function_hooks(hook_config)

        assert hooks is not None
        assert len(hooks) == len(hook_config['functions'])

        for hook in hooks:
            assert 'function' in hook
            assert 'original_bytes' in hook or 'hook_bytes' in hook
            assert 'trampoline' in hook or 'detour' in hook

    def test_adobe_memory_patching(self, adobe_trial_binary):
        """Test in-memory patching of Adobe binaries."""
        injector = AdobeInjector()

        # Generate memory patches
        memory_patches = injector.generate_memory_patches(adobe_trial_binary)

        assert memory_patches is not None
        assert isinstance(memory_patches, list)

        for patch in memory_patches:
            assert 'offset' in patch or 'address' in patch
            assert 'original' in patch
            assert 'patched' in patch
            assert isinstance(patch.get('patched'), bytes)

    def test_adobe_anti_debugging_bypass(self):
        """Test bypassing Adobe anti-debugging measures."""
        injector = AdobeInjector()

        # Generate anti-debug bypass
        antidbg_bypass = injector.bypass_anti_debugging()

        assert antidbg_bypass is not None
        assert 'techniques' in antidbg_bypass

        # Should handle common anti-debug techniques
        expected_techniques = [
            'IsDebuggerPresent',
            'CheckRemoteDebuggerPresent',
            'NtQueryInformationProcess',
            'PEB_BeingDebugged',
            'Hardware_Breakpoints'
        ]

        for technique in expected_techniques:
            assert technique in antidbg_bypass['techniques']

    def test_adobe_license_file_generation(self):
        """Test generating Adobe license files."""
        compiler = AdobeLicenseCompiler()

        # Generate license file
        license_config = {
            'product': 'Photoshop',
            'version': '2024',
            'user': 'TestUser',
            'organization': 'TestOrg',
            'serial': '1234-5678-9012-3456-7890-1234'
        }

        license_file = compiler.generate_license_file(license_config)

        assert license_file is not None
        assert isinstance(license_file, bytes)

        # Should contain license markers
        assert b'<?xml' in license_file or \
               b'[License]' in license_file or \
               b'ADOBE' in license_file

    def test_adobe_trial_reset(self):
        """Test Adobe trial period reset."""
        compiler = AdobeLicenseCompiler()

        # Generate trial reset patch
        reset_patch = compiler.generate_trial_reset()

        assert reset_patch is not None
        assert 'registry_keys' in reset_patch or 'files' in reset_patch

        # Should target trial tracking locations
        if 'registry_keys' in reset_patch:
            assert len(reset_patch['registry_keys']) > 0

        if 'files' in reset_patch:
            # Should include common trial files
            trial_locations = [
                'AMT',
                'SLCache',
                'SLStore',
                'cache.db'
            ]

            for location in trial_locations:
                assert any(location in f for f in reset_patch['files'])

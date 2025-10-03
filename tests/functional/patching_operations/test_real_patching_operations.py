import pytest
import tempfile
import os
import struct
import hashlib
import time
from pathlib import Path

from intellicrack.core.patching.memory_patcher import MemoryPatcher
from intellicrack.core.patching.payload_generator import PayloadGenerator
from intellicrack.core.patching.adobe_injector import AdobeInjector
from intellicrack.utils.patching.patch_generator import PatchGenerator
from intellicrack.utils.patching.patch_verification import PatchVerification, verify_patch
from intellicrack.core.app_context import AppContext


class TestRealPatchingOperations:
    """Functional tests for REAL patching operations."""

    @pytest.fixture
    def test_binary(self):
        """Create REAL binary for patching tests."""
        with tempfile.NamedTemporaryFile(suffix='.exe', delete=False) as temp_file:
            # DOS Header
            dos_header = b'MZ\x90\x00\x03\x00\x00\x00\x04\x00\x00\x00\xff\xff\x00\x00'
            dos_header += b'\xb8\x00\x00\x00\x00\x00\x00\x00\x40\x00\x00\x00\x00\x00\x00\x00'
            dos_header += b'\x00' * 40
            dos_header += b'\x80\x00\x00\x00'
            dos_header += b'\x00' * 60

            # PE Signature
            pe_signature = b'PE\x00\x00'

            # COFF Header
            coff_header = struct.pack('<H', 0x014c)  # Machine (x86)
            coff_header += struct.pack('<H', 3)      # NumberOfSections
            coff_header += struct.pack('<I', int(time.time()))  # TimeDateStamp
            coff_header += struct.pack('<I', 0)      # PointerToSymbolTable
            coff_header += struct.pack('<I', 0)      # NumberOfSymbols
            coff_header += struct.pack('<H', 224)    # SizeOfOptionalHeader
            coff_header += struct.pack('<H', 0x0102) # Characteristics

            # Optional Header
            optional_header = struct.pack('<H', 0x010b)  # Magic (PE32)
            optional_header += b'\x0e\x00'  # Linker version
            optional_header += struct.pack('<I', 0x1000)  # SizeOfCode
            optional_header += struct.pack('<I', 0x1000)  # SizeOfInitializedData
            optional_header += struct.pack('<I', 0)       # SizeOfUninitializedData
            optional_header += struct.pack('<I', 0x1000)  # AddressOfEntryPoint
            optional_header += struct.pack('<I', 0x1000)  # BaseOfCode
            optional_header += struct.pack('<I', 0x2000)  # BaseOfData
            optional_header += struct.pack('<I', 0x400000)  # ImageBase
            optional_header += struct.pack('<I', 0x1000)    # SectionAlignment
            optional_header += struct.pack('<I', 0x200)     # FileAlignment
            optional_header += b'\x00' * (224 - len(optional_header))

            # Section Headers
            text_section = b'.text\x00\x00\x00'
            text_section += struct.pack('<I', 0x1000)  # VirtualSize
            text_section += struct.pack('<I', 0x1000)  # VirtualAddress
            text_section += struct.pack('<I', 0x1000)  # SizeOfRawData
            text_section += struct.pack('<I', 0x400)   # PointerToRawData
            text_section += b'\x00' * 12
            text_section += struct.pack('<I', 0x60000020)  # Characteristics

            data_section = b'.data\x00\x00\x00'
            data_section += struct.pack('<I', 0x1000)
            data_section += struct.pack('<I', 0x2000)
            data_section += struct.pack('<I', 0x1000)
            data_section += struct.pack('<I', 0x1400)
            data_section += b'\x00' * 12
            data_section += struct.pack('<I', 0xC0000040)

            rdata_section = b'.rdata\x00\x00'
            rdata_section += struct.pack('<I', 0x1000)
            rdata_section += struct.pack('<I', 0x3000)
            rdata_section += struct.pack('<I', 0x1000)
            rdata_section += struct.pack('<I', 0x2400)
            rdata_section += b'\x00' * 12
            rdata_section += struct.pack('<I', 0x40000040)

            # Pad to code section
            padding1 = b'\x00' * (0x400 - temp_file.tell())

            # Code section with license check
            code_section = b''

            # License check function
            code_section += b'\x55'  # push ebp
            code_section += b'\x8b\xec'  # mov ebp, esp
            code_section += b'\x83\xec\x10'  # sub esp, 16

            # Call GetLicenseStatus
            code_section += b'\xe8\x50\x00\x00\x00'  # call GetLicenseStatus
            code_section += b'\x85\xc0'  # test eax, eax
            code_section += b'\x75\x0a'  # jnz valid_license

            # Invalid license path
            code_section += b'\x6a\x00'  # push 0
            code_section += b'\xe8\x60\x00\x00\x00'  # call ShowErrorMessage
            code_section += b'\xeb\x08'  # jmp exit

            # Valid license path
            code_section += b'\x6a\x01'  # push 1
            code_section += b'\xe8\x70\x00\x00\x00'  # call RunMainProgram

            # Exit
            code_section += b'\x8b\xe5'  # mov esp, ebp
            code_section += b'\x5d'  # pop ebp
            code_section += b'\xc3'  # ret

            # Trial check function
            code_section += b'\x90' * 16  # NOP padding
            code_section += b'\x55'  # push ebp
            code_section += b'\x8b\xec'  # mov ebp, esp

            # Get current date
            code_section += b'\xe8\x80\x00\x00\x00'  # call GetCurrentDate

            # Compare with trial expiry (hardcoded date)
            code_section += b'\x3d\x00\x00\x00\x00'  # cmp eax, TRIAL_DATE
            code_section += b'\x7e\x06'  # jle not_expired

            # Expired
            code_section += b'\x33\xc0'  # xor eax, eax (return 0)
            code_section += b'\xeb\x05'  # jmp return

            # Not expired
            code_section += b'\xb8\x01\x00\x00\x00'  # mov eax, 1

            # Return
            code_section += b'\x8b\xe5'  # mov esp, ebp
            code_section += b'\x5d'  # pop ebp
            code_section += b'\xc3'  # ret

            # Hardware ID check
            code_section += b'\x90' * 16
            code_section += b'\x55'  # push ebp
            code_section += b'\x8b\xec'  # mov ebp, esp

            # Get hardware ID
            code_section += b'\xe8\x90\x00\x00\x00'  # call GetHardwareID
            code_section += b'\x89\x45\xfc'  # mov [ebp-4], eax

            # Compare with stored ID
            code_section += b'\x8b\x45\x08'  # mov eax, [ebp+8] (stored ID parameter)
            code_section += b'\x39\x45\xfc'  # cmp [ebp-4], eax
            code_section += b'\x74\x06'  # je valid_hardware

            # Invalid hardware
            code_section += b'\x33\xc0'  # xor eax, eax
            code_section += b'\xeb\x05'  # jmp return

            # Valid hardware
            code_section += b'\xb8\x01\x00\x00\x00'  # mov eax, 1

            code_section += b'\x8b\xe5'  # mov esp, ebp
            code_section += b'\x5d'  # pop ebp
            code_section += b'\xc3'  # ret

            # Pad code section
            code_section += b'\x90' * (0x1000 - len(code_section))

            # Data section
            data_content = b'License Invalid!\x00'
            data_content += b'Trial Expired!\x00'
            data_content += b'Hardware Mismatch!\x00'
            data_content += b'Welcome to Application!\x00'
            data_content += b'\x00' * (0x1000 - len(data_content))

            # Rdata section (imports)
            rdata_content = b'KERNEL32.dll\x00'
            rdata_content += b'USER32.dll\x00'
            rdata_content += b'GetTickCount\x00'
            rdata_content += b'MessageBoxA\x00'
            rdata_content += b'\x00' * (0x1000 - len(rdata_content))

            # Write file
            temp_file.write(dos_header + pe_signature + coff_header + optional_header +
                          text_section + data_section + rdata_section + padding1 +
                          code_section + data_content + rdata_content)
            temp_file.flush()
            yield temp_file.name

        try:
            os.unlink(temp_file.name)
        except:
            pass

    @pytest.fixture
    def app_context(self):
        """Create REAL application context."""
        context = AppContext()
        context.initialize()
        return context

    def test_real_memory_patching(self, test_binary, app_context):
        """Test REAL memory patching operations."""
        patcher = MemoryPatcher()

        # Load binary into memory
        with open(test_binary, 'rb') as f:
            binary_data = bytearray(f.read())

        # Find license check patterns
        patterns = {
            'license_check': b'\xe8\x50\x00\x00\x00\x85\xc0\x75',  # call GetLicenseStatus; test eax, eax; jnz
            'trial_check': b'\x3d\x00\x00\x00\x00\x7e',  # cmp eax, TRIAL_DATE; jle
            'hardware_check': b'\x39\x45\xfc\x74'  # cmp [ebp-4], eax; je
        }

        patches_to_apply = []

        for name, pattern in patterns.items():
            offset = binary_data.find(pattern)
            if offset != -1:
                if name == 'license_check':
                    # Patch to always return valid license
                    # Change jnz to jmp (always take valid path)
                    patch = {
                        'offset': offset + 7,
                        'original': b'\x75',
                        'patched': b'\xeb',
                        'description': 'Bypass license check'
                    }
                elif name == 'trial_check':
                    # Patch to never expire
                    # Change jle to jmp (always take not expired path)
                    patch = {
                        'offset': offset + 5,
                        'original': b'\x7e',
                        'patched': b'\xeb',
                        'description': 'Bypass trial expiration'
                    }
                elif name == 'hardware_check':
                    # Patch to accept any hardware
                    # Change je to jmp (always valid)
                    patch = {
                        'offset': offset + 3,
                        'original': b'\x74',
                        'patched': b'\xeb',
                        'description': 'Bypass hardware check'
                    }

                patches_to_apply.append(patch)

        assert len(patches_to_apply) > 0, "Must find patterns to patch"

        # Apply patches
        for patch in patches_to_apply:
            result = patcher.apply_patch(binary_data, patch)
            assert result['success'], f"Patch {patch['description']} must succeed"
            assert binary_data[patch['offset']] == patch['patched'][0], "Patch must be applied"

        # Verify patches
        verification = PatchVerification()
        for patch in patches_to_apply:
            verify_result = verification.verify_patch(binary_data, patch)
            assert verify_result['verified'], f"Patch {patch['description']} must be verified"
            assert verify_result['integrity_maintained'], "Binary integrity must be maintained"

        # Test patch rollback
        for patch in patches_to_apply:
            rollback_result = patcher.rollback_patch(binary_data, patch)
            assert rollback_result['success'], "Rollback must succeed"
            assert binary_data[patch['offset']] == patch['original'][0], "Original byte must be restored"

    def test_real_payload_generation(self, app_context):
        """Test REAL payload generation for patching."""
        generator = PayloadGenerator()

        # Test various payload types
        payload_configs = [
            {
                'type': 'nop_sled',
                'size': 100,
                'purpose': 'Fill removed checks'
            },
            {
                'type': 'jmp_patch',
                'offset_from': 0x1000,
                'offset_to': 0x2000,
                'arch': 'x86'
            },
            {
                'type': 'function_hook',
                'target_function': 'CheckLicense',
                'hook_function': 'AlwaysReturnTrue',
                'arch': 'x86'
            },
            {
                'type': 'inline_patch',
                'code': [
                    'xor eax, eax',  # Clear return value
                    'inc eax',       # Set to 1 (true)
                    'ret'            # Return
                ]
            }
        ]

        for config in payload_configs:
            payload = generator.generate_payload(config)
            assert payload is not None, f"Must generate {config['type']} payload"
            assert len(payload) > 0, "Payload must not be empty"

            if config['type'] == 'nop_sled':
                assert len(payload) == config['size'], "NOP sled must be correct size"
                assert all(b == 0x90 for b in payload), "NOP sled must contain only NOPs"

            elif config['type'] == 'jmp_patch':
                # Verify it's a valid JMP instruction
                assert payload[0] == 0xe9, "Must be JMP instruction"
                # Calculate and verify offset
                jmp_offset = struct.unpack('<I', payload[1:5])[0]
                calculated_offset = config['offset_to'] - config['offset_from'] - 5
                assert jmp_offset == calculated_offset & 0xffffffff, "JMP offset must be correct"

            elif config['type'] == 'function_hook':
                # Verify hook structure
                assert payload[:5][0] == 0xe9, "Hook must start with JMP"
                assert len(payload) >= 5, "Hook must be at least 5 bytes"

            elif config['type'] == 'inline_patch':
                # Verify assembled code
                expected_bytes = b'\x31\xc0'  # xor eax, eax
                expected_bytes += b'\x40'      # inc eax
                expected_bytes += b'\xc3'      # ret
                assert payload == expected_bytes, "Inline patch must assemble correctly"

        # Test advanced payloads
        advanced_configs = [
            {
                'type': 'detour_hook',
                'target_address': 0x401000,
                'detour_address': 0x402000,
                'preserve_registers': True,
                'call_original': True
            },
            {
                'type': 'iat_hook',
                'dll_name': 'kernel32.dll',
                'function_name': 'GetTickCount',
                'hook_address': 0x403000
            },
            {
                'type': 'polymorphic_nop',
                'size': 50,
                'variation': 'random'
            }
        ]

        for config in advanced_configs:
            payload = generator.generate_advanced_payload(config)
            assert payload is not None, f"Must generate advanced {config['type']} payload"

            if config['type'] == 'detour_hook':
                # Should preserve registers if requested
                if config['preserve_registers']:
                    assert payload[:1] == b'\x60', "Should start with PUSHAD"
                    assert b'\x61' in payload, "Should contain POPAD"

            elif config['type'] == 'polymorphic_nop':
                assert len(payload) == config['size'], "Polymorphic NOP must be correct size"
                # Should not be all 0x90
                assert not all(b == 0x90 for b in payload), "Polymorphic NOP should vary"

    def test_real_adobe_license_injection(self, test_binary, app_context):
        """Test REAL Adobe license injection and patching."""
        injector = AdobeInjector()

        # Simulate Adobe application structure
        adobe_patterns = {
            'license_manager': b'AdobeLicenseManager',
            'activation_check': b'CheckActivationStatus',
            'feature_flags': b'EnabledFeatures',
            'trial_counter': b'TrialDaysRemaining'
        }

        # Create test Adobe binary
        with tempfile.NamedTemporaryFile(suffix='.exe', delete=False) as adobe_file:
            with open(test_binary, 'rb') as f:
                adobe_data = bytearray(f.read())

            # Add Adobe-specific markers
            for pattern in adobe_patterns.values():
                adobe_data.extend(pattern + b'\x00')

            adobe_file.write(adobe_data)
            adobe_file.flush()
            adobe_path = adobe_file.name

        try:
            # Analyze Adobe binary
            analysis = injector.analyze_adobe_binary(adobe_path)
            assert analysis is not None, "Adobe analysis must succeed"
            assert 'license_checks' in analysis, "Must identify license checks"
            assert 'protection_version' in analysis, "Must identify protection version"

            # Generate Adobe-specific patches
            adobe_patches = injector.generate_adobe_patches(analysis)
            assert len(adobe_patches) > 0, "Must generate Adobe patches"

            for patch in adobe_patches:
                assert 'type' in patch, "Patch must have type"
                assert 'offset' in patch, "Patch must have offset"
                assert 'payload' in patch, "Patch must have payload"

                if patch['type'] == 'activation_bypass':
                    # Should patch activation check to always succeed
                    assert len(patch['payload']) > 0, "Activation bypass must have payload"

                elif patch['type'] == 'feature_unlock':
                    # Should enable all features
                    assert patch['payload'] == b'\xff' * len(patch['payload']), \
                           "Feature unlock should set all bits"

                elif patch['type'] == 'trial_removal':
                    # Should remove trial limitations
                    assert patch['payload'] in [b'\x00\x00\x00\x00', b'\xff\xff\xff\xff'], \
                           "Trial removal should set to 0 or max"

            # Test license data injection
            license_data = {
                'product_id': 'PHSP2024',
                'serial_number': 'XXXX-XXXX-XXXX-XXXX',
                'activation_key': 'AAAA-BBBB-CCCC-DDDD',
                'features': ['all'],
                'expiry': 'never'
            }

            injection_result = injector.inject_license_data(adobe_path, license_data)
            assert injection_result['success'], "License injection must succeed"
            assert 'injection_points' in injection_result, "Must report injection points"
            assert len(injection_result['injection_points']) > 0, "Must inject at multiple points"

            # Verify Adobe-specific protections are bypassed
            protection_bypass = injector.bypass_adobe_protections(adobe_path)
            assert protection_bypass['success'], "Protection bypass must succeed"

            bypassed_protections = protection_bypass.get('bypassed', [])
            expected_bypasses = ['license_check', 'activation_check', 'feature_validation']

            for expected in expected_bypasses:
                assert any(expected in bp for bp in bypassed_protections), \
                       f"Must bypass {expected}"

        finally:
            try:
                os.unlink(adobe_path)
            except:
                pass

    def test_real_patch_generation_workflow(self, test_binary, app_context):
        """Test REAL end-to-end patch generation workflow."""
        patch_gen = PatchGenerator()

        # Analyze binary for patchable locations
        analysis_result = patch_gen.analyze_binary(test_binary)
        assert analysis_result is not None, "Binary analysis must succeed"
        assert 'patchable_locations' in analysis_result, "Must find patchable locations"
        assert 'protection_mechanisms' in analysis_result, "Must identify protections"

        patchable = analysis_result['patchable_locations']
        assert len(patchable) > 0, "Must find locations to patch"

        # Generate patch strategies
        strategies = patch_gen.generate_patch_strategies(patchable)
        assert len(strategies) > 0, "Must generate patch strategies"

        for strategy in strategies:
            assert 'name' in strategy, "Strategy must have name"
            assert 'patches' in strategy, "Strategy must have patches"
            assert 'risk_level' in strategy, "Strategy must assess risk"
            assert 'success_probability' in strategy, "Strategy must estimate success"

        # Select optimal strategy
        optimal = patch_gen.select_optimal_strategy(strategies)
        assert optimal is not None, "Must select optimal strategy"
        assert optimal['risk_level'] in ['low', 'medium', 'high'], "Risk must be categorized"

        # Generate patch file
        patch_file_data = patch_gen.generate_patch_file(test_binary, optimal)
        assert patch_file_data is not None, "Must generate patch file"
        assert 'header' in patch_file_data, "Patch file must have header"
        assert 'patches' in patch_file_data, "Patch file must have patches"
        assert 'checksum' in patch_file_data, "Patch file must have checksum"

        # Verify patch file integrity
        calculated_checksum = hashlib.sha256(
            str(patch_file_data['patches']).encode()
        ).hexdigest()
        assert patch_file_data['checksum'] == calculated_checksum, "Checksum must match"

        # Test patch application
        with tempfile.NamedTemporaryFile(suffix='.exe', delete=False) as patched_file:
            # Copy original
            with open(test_binary, 'rb') as f:
                patched_data = bytearray(f.read())

            # Apply patches
            apply_result = patch_gen.apply_patch_file(patched_data, patch_file_data)
            assert apply_result['success'], "Patch application must succeed"
            assert apply_result['patches_applied'] == len(patch_file_data['patches']), \
                   "All patches must be applied"

            # Write patched file
            patched_file.write(patched_data)
            patched_file.flush()
            patched_path = patched_file.name

        try:
            # Verify patched binary
            verification = verify_patch(test_binary, patched_path)
            assert verification['patches_verified'], "Patches must be verified"
            assert verification['integrity_maintained'], "Binary integrity must be maintained"
            assert not verification.get('corruption_detected', False), "No corruption allowed"

        finally:
            try:
                os.unlink(patched_path)
            except:
                pass

    def test_real_anti_tampering_bypass(self, test_binary, app_context):
        """Test REAL anti-tampering protection bypass."""
        patcher = MemoryPatcher()

        # Add anti-tampering protection to binary
        with open(test_binary, 'rb') as f:
            protected_data = bytearray(f.read())

        # Simple checksum protection
        checksum = sum(protected_data) & 0xffffffff
        checksum_check = b'\x81\x3d' + struct.pack('<I', 0x404000) + struct.pack('<I', checksum)
        checksum_check += b'\x74\x06'  # je continue
        checksum_check += b'\x6a\x00'  # push 0
        checksum_check += b'\xe8\x00\x00\x00\x00'  # call exit

        # Insert at beginning of code
        code_offset = 0x400
        protected_data[code_offset:code_offset] = checksum_check

        # Analyze anti-tampering
        anti_tamper_analysis = patcher.analyze_anti_tampering(protected_data)
        assert anti_tamper_analysis is not None, "Must analyze anti-tampering"
        assert 'methods_found' in anti_tamper_analysis, "Must identify methods"
        assert len(anti_tamper_analysis['methods_found']) > 0, "Must find anti-tampering"

        # Generate bypass
        for method in anti_tamper_analysis['methods_found']:
            bypass = patcher.generate_anti_tamper_bypass(method)
            assert bypass is not None, f"Must generate bypass for {method['type']}"

            if method['type'] == 'checksum':
                # Should either patch the check or update the checksum
                assert 'patch_check' in bypass or 'update_checksum' in bypass, \
                       "Must have bypass method"

            elif method['type'] == 'hash_verification':
                assert 'patch_verification' in bypass, "Must patch hash verification"

            elif method['type'] == 'self_modification_detection':
                assert 'disable_detection' in bypass, "Must disable detection"

        # Apply bypasses
        for method, bypass in zip(anti_tamper_analysis['methods_found'],
                                  [patcher.generate_anti_tamper_bypass(m) for m in anti_tamper_analysis['methods_found']]):

            if 'patch_check' in bypass:
                # Patch the checksum check to always pass
                patch_offset = method['offset']
                protected_data[patch_offset + 8] = 0xeb  # Change je to jmp

            elif 'update_checksum' in bypass:
                # Recalculate and update stored checksum
                new_checksum = sum(protected_data) & 0xffffffff
                checksum_offset = method.get('checksum_offset', 0x404000)
                # In real scenario, would update at checksum_offset

        # Verify bypass effectiveness
        bypass_verification = patcher.verify_anti_tamper_bypass(protected_data)
        assert bypass_verification['bypassed'], "Anti-tampering must be bypassed"
        assert bypass_verification['can_modify'], "Should be able to modify after bypass"

    def test_real_code_caves_utilization(self, test_binary, app_context):
        """Test REAL code caves finding and utilization."""
        patcher = MemoryPatcher()

        with open(test_binary, 'rb') as f:
            binary_data = bytearray(f.read())

        # Find code caves
        caves = patcher.find_code_caves(binary_data, min_size=20)
        assert caves is not None, "Must find code caves"
        assert len(caves) > 0, "Must find at least one code cave"

        for cave in caves:
            assert 'offset' in cave, "Cave must have offset"
            assert 'size' in cave, "Cave must have size"
            assert 'section' in cave, "Cave must identify section"
            assert cave['size'] >= 20, "Cave must meet minimum size"

        # Test cave utilization
        if caves:
            largest_cave = max(caves, key=lambda c: c['size'])

            # Generate code to place in cave
            cave_code = PayloadGenerator().generate_payload({
                'type': 'custom_function',
                'code': [
                    'push ebp',
                    'mov ebp, esp',
                    'mov eax, 1',  # Return true
                    'pop ebp',
                    'ret'
                ]
            })

            # Place code in cave
            place_result = patcher.place_code_in_cave(
                binary_data,
                largest_cave,
                cave_code
            )
            assert place_result['success'], "Code placement must succeed"
            assert place_result['bytes_used'] <= largest_cave['size'], \
                   "Must not exceed cave size"

            # Verify code was placed
            placed_offset = largest_cave['offset']
            placed_code = binary_data[placed_offset:placed_offset + len(cave_code)]
            assert placed_code == cave_code, "Code must be placed correctly"

            # Create jump to cave
            jump_from = 0x1000  # Example offset
            jump_patch = patcher.create_jump_to_cave(jump_from, placed_offset)
            assert jump_patch is not None, "Must create jump patch"
            assert len(jump_patch) == 5, "Jump must be 5 bytes"
            assert jump_patch[0] == 0xe9, "Must be JMP instruction"

    def test_real_relocation_handling(self, test_binary, app_context):
        """Test REAL relocation table handling during patching."""
        patcher = MemoryPatcher()
        patch_gen = PatchGenerator()

        # Analyze relocations
        reloc_analysis = patch_gen.analyze_relocations(test_binary)
        assert reloc_analysis is not None, "Relocation analysis must succeed"

        if reloc_analysis.get('has_relocations', False):
            relocations = reloc_analysis['relocations']
            assert isinstance(relocations, list), "Relocations must be a list"

            for reloc in relocations:
                assert 'type' in reloc, "Relocation must have type"
                assert 'offset' in reloc, "Relocation must have offset"
                assert 'value' in reloc, "Relocation must have value"

            # Test relocation-aware patching
            with open(test_binary, 'rb') as f:
                binary_data = bytearray(f.read())

            # Generate patch that affects relocated addresses
            test_patch = {
                'offset': 0x1000,
                'original': binary_data[0x1000:0x1004],
                'patched': b'\x90\x90\x90\x90',
                'affects_relocations': True
            }

            # Apply with relocation handling
            reloc_aware_result = patcher.apply_patch_with_relocations(
                binary_data,
                test_patch,
                relocations
            )
            assert reloc_aware_result['success'], "Relocation-aware patch must succeed"

            if reloc_aware_result.get('relocations_updated', 0) > 0:
                assert 'updated_relocations' in reloc_aware_result, \
                       "Must provide updated relocations"

                # Verify relocations still valid
                for updated_reloc in reloc_aware_result['updated_relocations']:
                    assert updated_reloc['adjusted'], "Relocation must be adjusted"
                    assert 'new_value' in updated_reloc, "Must have new value"

    def test_real_section_permission_modification(self, test_binary, app_context):
        """Test REAL PE section permission modification."""
        patcher = MemoryPatcher()

        # Load PE headers
        with open(test_binary, 'rb') as f:
            pe_data = bytearray(f.read())

        # Parse PE sections
        dos_header = pe_data[:64]
        pe_offset = struct.unpack('<I', dos_header[60:64])[0]

        # Get section headers offset
        coff_header_size = 24
        optional_header_size = struct.unpack('<H', pe_data[pe_offset + 20:pe_offset + 22])[0]
        section_headers_offset = pe_offset + 24 + optional_header_size

        # Modify section permissions
        section_size = 40  # Size of IMAGE_SECTION_HEADER
        num_sections = struct.unpack('<H', pe_data[pe_offset + 6:pe_offset + 8])[0]

        modified_sections = []
        for i in range(num_sections):
            section_offset = section_headers_offset + (i * section_size)
            section_name = pe_data[section_offset:section_offset + 8].rstrip(b'\x00')
            characteristics_offset = section_offset + 36
            characteristics = struct.unpack('<I', pe_data[characteristics_offset:characteristics_offset + 4])[0]

            # Make .text section writable for patching
            if section_name == b'.text':
                original_chars = characteristics
                # Add IMAGE_SCN_MEM_WRITE (0x80000000)
                new_characteristics = characteristics | 0x80000000
                pe_data[characteristics_offset:characteristics_offset + 4] = struct.pack('<I', new_characteristics)

                modified_sections.append({
                    'name': section_name.decode('ascii', errors='ignore'),
                    'original': original_chars,
                    'modified': new_characteristics,
                    'offset': characteristics_offset
                })

        assert len(modified_sections) > 0, "Must modify at least one section"

        # Verify modifications
        for section in modified_sections:
            stored_chars = struct.unpack('<I', pe_data[section['offset']:section['offset'] + 4])[0]
            assert stored_chars == section['modified'], "Section characteristics must be updated"
            assert stored_chars & 0x80000000, "Section must be writable"

        # Test permission restoration
        for section in modified_sections:
            pe_data[section['offset']:section['offset'] + 4] = struct.pack('<I', section['original'])
            restored_chars = struct.unpack('<I', pe_data[section['offset']:section['offset'] + 4])[0]
            assert restored_chars == section['original'], "Original permissions must be restored"

    def test_real_incremental_patching(self, test_binary, app_context):
        """Test REAL incremental and reversible patching."""
        patcher = MemoryPatcher()
        patch_gen = PatchGenerator()

        with open(test_binary, 'rb') as f:
            original_data = f.read()
            working_data = bytearray(original_data)

        # Create patch history
        patch_history = []

        # Apply multiple incremental patches
        incremental_patches = [
            {
                'id': 'patch_1',
                'offset': 0x1000,
                'original': working_data[0x1000:0x1002],
                'patched': b'\x90\x90',
                'description': 'NOP first check'
            },
            {
                'id': 'patch_2',
                'offset': 0x1010,
                'original': working_data[0x1010:0x1012],
                'patched': b'\xeb\x10',
                'description': 'Jump over second check'
            },
            {
                'id': 'patch_3',
                'offset': 0x1020,
                'original': working_data[0x1020:0x1025],
                'patched': b'\xb8\x01\x00\x00\x00',  # mov eax, 1
                'description': 'Force success return'
            }
        ]

        # Apply patches incrementally
        for patch in incremental_patches:
            # Take snapshot before patch
            snapshot = patcher.create_snapshot(working_data, patch['offset'], len(patch['original']))
            patch_history.append({
                'patch': patch,
                'snapshot': snapshot,
                'timestamp': time.time()
            })

            # Apply patch
            result = patcher.apply_patch(working_data, patch)
            assert result['success'], f"Patch {patch['id']} must succeed"

            # Verify patch applied
            patched_bytes = working_data[patch['offset']:patch['offset'] + len(patch['patched'])]
            assert patched_bytes == patch['patched'], f"Patch {patch['id']} must be applied"

        # Test selective rollback
        # Rollback patch_2 only
        rollback_result = patcher.rollback_specific_patch(
            working_data,
            patch_history[1]['patch'],
            patch_history[1]['snapshot']
        )
        assert rollback_result['success'], "Selective rollback must succeed"

        # Verify patch_2 rolled back but others remain
        assert working_data[0x1000:0x1002] == b'\x90\x90', "Patch 1 must remain"
        assert working_data[0x1010:0x1012] == incremental_patches[1]['original'], "Patch 2 must be rolled back"
        assert working_data[0x1020:0x1025] == b'\xb8\x01\x00\x00\x00', "Patch 3 must remain"

        # Test full rollback to original
        for entry in reversed(patch_history):
            if working_data[entry['patch']['offset']:entry['patch']['offset'] + len(entry['patch']['patched'])] == entry['patch']['patched']:
                patcher.rollback_specific_patch(
                    working_data,
                    entry['patch'],
                    entry['snapshot']
                )

        # Verify complete restoration
        assert working_data == bytearray(original_data), "Must restore to original state"

        # Test patch dependency management
        dependent_patches = [
            {
                'id': 'base_patch',
                'offset': 0x2000,
                'dependencies': [],
                'patched': b'\xe9\x00\x10\x00\x00'  # jmp to cave
            },
            {
                'id': 'cave_code',
                'offset': 0x3000,
                'dependencies': ['base_patch'],
                'patched': b'\x90' * 100  # Code in cave
            }
        ]

        # Verify dependency enforcement
        dep_result = patch_gen.validate_patch_dependencies(dependent_patches)
        assert dep_result['valid'], "Dependencies must be valid"
        assert dep_result['order'] == ['base_patch', 'cave_code'], "Must respect dependency order"

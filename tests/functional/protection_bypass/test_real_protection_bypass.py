"""
Functional tests for Intellicrack's protection bypass capabilities.

This module contains comprehensive tests for protection bypass techniques in Intellicrack,
including VMProtect bypass techniques, Themida bypass techniques, Frida dynamic bypass
generation, memory patching techniques, TPM bypass methods, code integrity bypass,
advanced unpacking techniques, multi-layer protection bypass, license emulation bypass,
and real-world protection combinations. These tests verify the effectiveness of bypass
techniques on real protection schemes like VMProtect and Themida.
"""

import pytest
import tempfile
import os
import struct
import time
from pathlib import Path

from intellicrack.core.protection_bypass.vm_bypass import VMBypass
from intellicrack.core.protection_bypass.tpm_bypass import TPMBypass
from intellicrack.core.mitigation_bypass.bypass_base import BypassBase
from intellicrack.core.anti_analysis.api_obfuscation import APIObfuscation
from intellicrack.core.anti_analysis.timing_attacks import TimingAttacks
from intellicrack.protection.protection_detector import ProtectionDetector
from intellicrack.core.frida_bypass_wizard import FridaBypassWizard
from intellicrack.core.patching.memory_patcher import MemoryPatcher
from intellicrack.core.app_context import AppContext


class TestRealProtectionBypass:
    """Functional tests for REAL protection bypass techniques."""

    @pytest.fixture
    def vmprotect_protected_binary(self):
        """Create REAL VMProtect-like protected binary for testing."""
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
            coff_header = b'\x4c\x01'  # Machine
            coff_header += b'\x04\x00'  # Number of sections
            coff_header += b'\x00\x00\x00\x00' * 3
            coff_header += b'\xe0\x00'  # SizeOfOptionalHeader
            coff_header += b'\x02\x01'  # Characteristics

            # Optional Header
            optional_header = b'\x0b\x01\x0e\x00' + b'\x00' * 220

            # VMProtect sections
            vmp0_section = b'.vmp0\x00\x00\x00'
            vmp0_section += b'\x00\x10\x00\x00'  # VirtualSize
            vmp0_section += b'\x00\x10\x00\x00'  # VirtualAddress
            vmp0_section += b'\x00\x10\x00\x00'  # SizeOfRawData
            vmp0_section += b'\x00\x04\x00\x00'  # PointerToRawData
            vmp0_section += b'\x00' * 12
            vmp0_section += b'\x60\x00\x00\xe0'  # Characteristics

            vmp1_section = b'.vmp1\x00\x00\x00'
            vmp1_section += b'\x00\x10\x00\x00'
            vmp1_section += b'\x00\x20\x00\x00'
            vmp1_section += b'\x00\x10\x00\x00'
            vmp1_section += b'\x00\x14\x00\x00'
            vmp1_section += b'\x00' * 12
            vmp1_section += b'\x60\x00\x00\xe0'

            vmp2_section = b'.vmp2\x00\x00\x00'
            vmp2_section += b'\x00\x10\x00\x00'
            vmp2_section += b'\x00\x30\x00\x00'
            vmp2_section += b'\x00\x10\x00\x00'
            vmp2_section += b'\x00\x24\x00\x00'
            vmp2_section += b'\x00' * 12
            vmp2_section += b'\x60\x00\x00\xe0'

            text_section = b'.text\x00\x00\x00'
            text_section += b'\x00\x10\x00\x00'
            text_section += b'\x00\x40\x00\x00'
            text_section += b'\x00\x10\x00\x00'
            text_section += b'\x00\x34\x00\x00'
            text_section += b'\x00' * 12
            text_section += b'\x20\x00\x00\x60'

            # VMProtect virtualized code patterns
            vmp_handler_table = b'\x68\x00\x00\x00\x00'  # push handler
            vmp_handler_table += b'\xc3'  # ret
            vmp_handler_table += b'\x55'  # push ebp
            vmp_handler_table += b'\x8b\xec'  # mov ebp, esp
            vmp_handler_table += b'\x60'  # pushad
            vmp_handler_table += b'\x9c'  # pushfd
            vmp_handler_table += b'\x8b\x45\x08'  # mov eax, [ebp+8]
            vmp_handler_table += b'\x8b\x00'  # mov eax, [eax]
            vmp_handler_table += b'\xff\xe0'  # jmp eax
            vmp_handler_table += b'\x90' * (4096 - len(vmp_handler_table))

            # Obfuscated VM handlers
            vm_handlers = b''
            # ADD handler
            vm_handlers += b'\x58'  # pop eax
            vm_handlers += b'\x5b'  # pop ebx
            vm_handlers += b'\x01\xd8'  # add eax, ebx
            vm_handlers += b'\x50'  # push eax
            vm_handlers += b'\xc3'  # ret
            # SUB handler
            vm_handlers += b'\x58'  # pop eax
            vm_handlers += b'\x5b'  # pop ebx
            vm_handlers += b'\x29\xd8'  # sub eax, ebx
            vm_handlers += b'\x50'  # push eax
            vm_handlers += b'\xc3'  # ret
            # XOR handler
            vm_handlers += b'\x58'  # pop eax
            vm_handlers += b'\x5b'  # pop ebx
            vm_handlers += b'\x31\xd8'  # xor eax, ebx
            vm_handlers += b'\x50'  # push eax
            vm_handlers += b'\xc3'  # ret
            vm_handlers += b'\x90' * (4096 - len(vm_handlers))

            # VM bytecode (virtualized instructions)
            vm_bytecode = b'\x01\x00\x00\x00'  # PUSH immediate
            vm_bytecode += b'\x10\x00\x00\x00'  # value: 16
            vm_bytecode += b'\x01\x00\x00\x00'  # PUSH immediate
            vm_bytecode += b'\x20\x00\x00\x00'  # value: 32
            vm_bytecode += b'\x02\x00\x00\x00'  # ADD
            vm_bytecode += b'\x03\x00\x00\x00'  # POP to register
            vm_bytecode += b'\x00\x00\x00\x00'  # register: EAX
            vm_bytecode += b'\xff\x00\x00\x00'  # VM_EXIT
            vm_bytecode += b'\x00' * (4096 - len(vm_bytecode))

            # Protected original code
            protected_code = b'\xeb\x10'  # jmp to VM entry
            protected_code += b'\x90' * 14  # nops (original code space)
            protected_code += b'\xe9\x00\x10\x00\x00'  # jmp to VM handler
            protected_code += b'\x90' * (4096 - len(protected_code))

            temp_file.write(dos_header + pe_signature + coff_header + optional_header +
                          vmp0_section + vmp1_section + vmp2_section + text_section +
                          vmp_handler_table + vm_handlers + vm_bytecode + protected_code)
            temp_file.flush()
            yield temp_file.name

        try:
            os.unlink(temp_file.name)
        except:
            pass

    @pytest.fixture
    def themida_protected_binary(self):
        """Create REAL Themida-like protected binary for testing."""
        with tempfile.NamedTemporaryFile(suffix='.exe', delete=False) as temp_file:
            # DOS Header
            dos_header = b'MZ\x90\x00\x03\x00\x00\x00\x04\x00\x00\x00\xff\xff\x00\x00'
            dos_header += b'\xb8\x00\x00\x00\x00\x00\x00\x00\x40\x00\x00\x00\x00\x00\x00\x00'
            dos_header += b'\x00' * 40
            dos_header += b'\x80\x00\x00\x00'
            dos_header += b'\x00' * 60

            pe_signature = b'PE\x00\x00'
            coff_header = b'\x4c\x01\x03\x00' + b'\x00' * 16
            optional_header = b'\x0b\x01\x0e\x00' + b'\x00' * 220

            # Themida sections
            themida_section = b'.themida\x00'
            themida_section += b'\x00\x20\x00\x00'
            themida_section += b'\x00\x10\x00\x00'
            themida_section += b'\x00\x20\x00\x00'
            themida_section += b'\x00\x04\x00\x00'
            themida_section += b'\x00' * 12
            themida_section += b'\x60\x00\x00\xe0'

            rsrc_section = b'.rsrc\x00\x00\x00'
            rsrc_section += b'\x00\x10\x00\x00'
            rsrc_section += b'\x00\x30\x00\x00'
            rsrc_section += b'\x00\x10\x00\x00'
            rsrc_section += b'\x00\x24\x00\x00'
            rsrc_section += b'\x00' * 12
            rsrc_section += b'\x40\x00\x00\x40'

            # Themida protection features
            themida_code = b'\x60'  # pushad
            themida_code += b'\x0f\x31'  # rdtsc (anti-debug)
            themida_code += b'\x89\x45\xfc'  # mov [ebp-4], eax
            themida_code += b'\x9c'  # pushfd
            themida_code += b'\x58'  # pop eax
            themida_code += b'\x25\x00\x01\x00\x00'  # and eax, 0x100 (check trap flag)
            themida_code += b'\x74\x05'  # jz no_debugger
            themida_code += b'\xb8\x00\x00\x00\x00'  # mov eax, 0
            themida_code += b'\xc3'  # ret (exit if debugger)
            # Anti-VM checks
            themida_code += b'\x0f\xa2'  # cpuid
            themida_code += b'\x81\xfb\x56\x4d\x77\x61'  # cmp ebx, 'VMwa'
            themida_code += b'\x74\x10'  # je detected_vm
            themida_code += b'\x81\xfb\x56\x69\x72\x74'  # cmp ebx, 'Virt'
            themida_code += b'\x74\x08'  # je detected_vm
            # Code encryption layer
            themida_code += b'\x8b\x35\x00\x40\x00\x00'  # mov esi, code_start
            themida_code += b'\x8b\x3d\x00\x50\x00\x00'  # mov edi, code_end
            themida_code += b'\x8b\x0e'  # mov ecx, [esi]
            themida_code += b'\x81\xf1\xaa\xaa\xaa\xaa'  # xor ecx, 0xaaaaaaaa
            themida_code += b'\x89\x0e'  # mov [esi], ecx
            themida_code += b'\x83\xc6\x04'  # add esi, 4
            themida_code += b'\x39\xfe'  # cmp esi, edi
            themida_code += b'\x75\xf0'  # jne decrypt_loop
            themida_code += b'\x61'  # popad
            themida_code += b'\x90' * (8192 - len(themida_code))

            # Resource section with Themida markers
            resource_data = b'Themida - (c) Oreans Technologies\x00'
            resource_data += b'\x00\x00\x00\x01'  # Version
            resource_data += b'\x00\x00\x00\x00' * 16  # Protection data
            resource_data += b'\x00' * (4096 - len(resource_data))

            temp_file.write(dos_header + pe_signature + coff_header + optional_header +
                          themida_section + rsrc_section + themida_code + resource_data)
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

    def test_vmprotect_bypass_techniques(self, vmprotect_protected_binary, app_context):
        """Test REAL VMProtect bypass techniques."""
        vm_bypass = VMBypass()
        detector = ProtectionDetector()

        # Detect VMProtect
        protection_result = detector.analyze_file(vmprotect_protected_binary)
        assert protection_result is not None, "Must detect protection"

        protections = protection_result['protections']
        vmp_detected = any('VMProtect' in p.get('name', '') or 'vmp' in p.get('name', '').lower()
                          for p in protections)
        assert vmp_detected, "Must detect VMProtect protection"

        # Analyze VM structure
        vm_analysis = vm_bypass.analyze_vm_structure(vmprotect_protected_binary)
        assert vm_analysis is not None, "VM structure analysis must succeed"
        assert 'vm_handlers' in vm_analysis, "Must identify VM handlers"
        assert 'vm_dispatcher' in vm_analysis, "Must identify VM dispatcher"
        assert 'vm_context' in vm_analysis, "Must identify VM context"

        # Devirtualize handlers
        devirt_result = vm_bypass.devirtualize_handlers(vm_analysis)
        assert devirt_result is not None, "Handler devirtualization must succeed"
        assert 'recovered_handlers' in devirt_result, "Must recover some handlers"
        assert len(devirt_result['recovered_handlers']) > 0, "Must recover at least one handler"

        for handler in devirt_result['recovered_handlers']:
            assert 'opcode' in handler, "Each handler must have opcode"
            assert 'semantics' in handler, "Each handler must have semantics"
            assert 'native_code' in handler, "Each handler must have native code"

        # Generate VM trace
        trace_config = {
            'entry_point': 0x401000,
            'max_instructions': 10000,
            'trace_branches': True
        }

        vm_trace = vm_bypass.generate_vm_trace(vmprotect_protected_binary, trace_config)
        assert vm_trace is not None, "VM trace generation must succeed"
        assert 'trace_data' in vm_trace, "Trace must contain data"
        assert 'vm_exits' in vm_trace, "Trace must identify VM exits"

    def test_themida_bypass_techniques(self, themida_protected_binary, app_context):
        """Test REAL Themida bypass techniques."""
        vm_bypass = VMBypass()
        api_obfuscation = APIObfuscation()
        timing_attacks = TimingAttacks()

        # Bypass anti-debug
        antidebug_patches = vm_bypass.bypass_anti_debug(themida_protected_binary)
        assert antidebug_patches is not None, "Anti-debug bypass must succeed"
        assert len(antidebug_patches) > 0, "Must identify anti-debug locations"

        for patch in antidebug_patches:
            assert 'address' in patch, "Each patch must have address"
            assert 'original_bytes' in patch, "Each patch must have original bytes"
            assert 'patch_bytes' in patch, "Each patch must have patch bytes"
            assert patch['patch_bytes'] == b'\x90' * len(patch['original_bytes']) or \
                   patch['patch_bytes'] == b'\xeb', "Patches must be NOPs or JMP"

        # Bypass anti-VM
        antivm_patches = vm_bypass.bypass_anti_vm(themida_protected_binary)
        assert antivm_patches is not None, "Anti-VM bypass must succeed"
        assert len(antivm_patches) > 0, "Must identify anti-VM checks"

        # Recover obfuscated APIs
        api_recovery = api_obfuscation.recover_obfuscated_apis(themida_protected_binary)
        assert api_recovery is not None, "API recovery must succeed"
        assert 'recovered_apis' in api_recovery, "Must contain recovered APIs"

        if len(api_recovery['recovered_apis']) > 0:
            for api in api_recovery['recovered_apis']:
                assert 'name' in api, "Each API must have name"
                assert 'address' in api, "Each API must have address"
                assert 'obfuscation_type' in api, "Each API must identify obfuscation"

        # Bypass timing checks
        timing_patches = timing_attacks.bypass_timing_checks(themida_protected_binary)
        assert timing_patches is not None, "Timing bypass must succeed"

    def test_frida_dynamic_bypass_generation(self, vmprotect_protected_binary, app_context):
        """Test REAL Frida script generation for bypassing protections."""
        frida_wizard = FridaBypassWizard()

        # Generate comprehensive bypass script
        bypass_config = {
            'target': vmprotect_protected_binary,
            'protections': ['anti_debug', 'anti_vm', 'integrity_checks', 'timing_checks'],
            'hook_depth': 'comprehensive'
        }

        frida_script = frida_wizard.generate_bypass_script(bypass_config)
        assert frida_script is not None, "Frida script generation must succeed"
        assert len(frida_script) > 0, "Frida script must not be empty"
        assert 'Interceptor.attach' in frida_script, "Script must use Interceptor API"
        assert 'Module.findExportByName' in frida_script or 'Module.getExportByName' in frida_script, \
            "Script must hook APIs"

        # Verify script contains bypass patterns
        assert 'IsDebuggerPresent' in frida_script, "Must hook IsDebuggerPresent"
        assert 'CheckRemoteDebuggerPresent' in frida_script, "Must hook CheckRemoteDebuggerPresent"
        assert any(vm_check in frida_script for vm_check in ['VMwareService', 'VBoxService', 'cpuid']), \
            "Must include VM detection bypass"

        # Generate targeted hooks
        targeted_config = {
            'target_functions': ['check_license', 'validate_key', 'is_trial_expired'],
            'return_values': {'check_license': 1, 'validate_key': 1, 'is_trial_expired': 0}
        }

        targeted_script = frida_wizard.generate_targeted_hooks(vmprotect_protected_binary, targeted_config)
        assert targeted_script is not None, "Targeted hook generation must succeed"

        for func_name in targeted_config['target_functions']:
            assert func_name in targeted_script, f"Script must hook {func_name}"
            assert 'retval.replace' in targeted_script, "Script must modify return values"

    def test_memory_patching_techniques(self, vmprotect_protected_binary, app_context):
        """Test REAL memory patching techniques."""
        memory_patcher = MemoryPatcher()

        # Generate memory patches
        patch_targets = [
            {
                'name': 'license_check',
                'pattern': b'\x85\xc0\x74',  # test eax, eax; jz
                'patch': b'\x90\x90\xeb',  # nop nop jmp
                'description': 'Always jump past license check'
            },
            {
                'name': 'trial_check',
                'pattern': b'\x3d\x00\x00\x00\x00\x7f',  # cmp eax, 0; jg
                'patch': b'\x90\x90\x90\x90\x90\xeb',  # nops + jmp
                'description': 'Bypass trial expiration'
            }
        ]

        patches = memory_patcher.generate_patches(vmprotect_protected_binary, patch_targets)
        assert patches is not None, "Patch generation must succeed"
        assert len(patches) > 0, "Must generate at least one patch"

        for patch in patches:
            assert 'address' in patch, "Each patch must have address"
            assert 'original' in patch, "Each patch must store original bytes"
            assert 'patched' in patch, "Each patch must have patch bytes"
            assert len(patch['original']) == len(patch['patched']), "Patch size must match"

        # Generate inline hooks
        hook_config = {
            'target_function': 'check_protection',
            'hook_type': 'detour',
            'return_value': 0
        }

        inline_hook = memory_patcher.generate_inline_hook(vmprotect_protected_binary, hook_config)
        assert inline_hook is not None, "Inline hook generation must succeed"
        assert 'trampoline' in inline_hook, "Hook must include trampoline"
        assert 'hook_bytes' in inline_hook, "Hook must include hook bytes"
        assert len(inline_hook['hook_bytes']) >= 5, "Hook must be at least 5 bytes (JMP)"

    def test_tpm_bypass_techniques(self, app_context):
        """Test REAL TPM bypass techniques."""
        tpm_bypass = TPMBypass()

        # Generate TPM emulation
        tpm_emulation = tpm_bypass.generate_tpm_emulator()
        assert tpm_emulation is not None, "TPM emulation must be generated"
        assert 'tpm_commands' in tpm_emulation, "Emulation must handle TPM commands"
        assert 'pcr_values' in tpm_emulation, "Emulation must maintain PCR values"

        # Test TPM command responses
        test_commands = [
            {'command': 'TPM2_GetRandom', 'size': 32},
            {'command': 'TPM2_PCR_Read', 'pcr_index': 0},
            {'command': 'TPM2_Quote', 'pcr_selection': [0, 1, 2]}
        ]

        for cmd in test_commands:
            response = tpm_bypass.handle_tpm_command(cmd)
            assert response is not None, f"TPM command {cmd['command']} must be handled"
            assert 'status' in response, "Response must include status"
            assert response['status'] == 0, "Command must succeed"
            assert 'data' in response, "Response must include data"

    def test_code_integrity_bypass(self, vmprotect_protected_binary, app_context):
        """Test REAL code integrity bypass techniques."""
        bypass_base = BypassBase()

        # Analyze integrity checks
        integrity_analysis = bypass_base.analyze_integrity_checks(vmprotect_protected_binary)
        assert integrity_analysis is not None, "Integrity analysis must succeed"
        assert 'check_locations' in integrity_analysis, "Must identify check locations"
        assert 'checksum_algorithms' in integrity_analysis, "Must identify algorithms"

        # Generate integrity bypass
        integrity_bypass = bypass_base.generate_integrity_bypass(integrity_analysis)
        assert integrity_bypass is not None, "Integrity bypass must be generated"
        assert 'hook_points' in integrity_bypass, "Bypass must identify hook points"
        assert 'fake_checksums' in integrity_bypass, "Bypass must provide fake checksums"

        for algo in integrity_analysis['checksum_algorithms']:
            assert algo in integrity_bypass['fake_checksums'], f"Must provide checksum for {algo}"

    def test_advanced_unpacking_techniques(self, vmprotect_protected_binary, app_context):
        """Test REAL advanced unpacking techniques."""
        vm_bypass = VMBypass()

        # Dump process memory
        dump_config = {
            'dump_type': 'full',
            'fix_imports': True,
            'rebuild_pe': True
        }

        memory_dump = vm_bypass.dump_protected_process(vmprotect_protected_binary, dump_config)
        assert memory_dump is not None, "Memory dump must succeed"
        assert 'dump_data' in memory_dump, "Must contain dump data"
        assert 'import_table' in memory_dump, "Must rebuild import table"
        assert 'entry_point' in memory_dump, "Must identify real entry point"

        # Reconstruct original code
        reconstruction = vm_bypass.reconstruct_original_code(memory_dump)
        assert reconstruction is not None, "Code reconstruction must succeed"
        assert 'recovered_functions' in reconstruction, "Must recover functions"
        assert len(reconstruction['recovered_functions']) > 0, "Must recover at least one function"

    def test_multi_layer_protection_bypass(self, vmprotect_protected_binary, themida_protected_binary, app_context):
        """Test REAL multi-layer protection bypass."""
        vm_bypass = VMBypass()
        detector = ProtectionDetector()

        # Create multi-protected binary simulation
        protections_detected = []

        for binary in [vmprotect_protected_binary, themida_protected_binary]:
            result = detector.analyze_file(binary)
            if result and 'protections' in result:
                protections_detected.extend(result['protections'])

        # Generate comprehensive bypass strategy
        bypass_strategy = vm_bypass.generate_bypass_strategy(protections_detected)
        assert bypass_strategy is not None, "Bypass strategy must be generated"
        assert 'bypass_order' in bypass_strategy, "Strategy must define order"
        assert 'techniques' in bypass_strategy, "Strategy must list techniques"

        # Verify bypass order makes sense
        bypass_order = bypass_strategy['bypass_order']
        anti_debug_index = next((i for i, b in enumerate(bypass_order) if 'debug' in b.lower()), -1)
        unpacking_index = next((i for i, b in enumerate(bypass_order) if 'unpack' in b.lower()), -1)

        if anti_debug_index >= 0 and unpacking_index >= 0:
            assert anti_debug_index < unpacking_index, "Anti-debug must come before unpacking"

    def test_license_emulation_bypass(self, app_context):
        """Test REAL license check emulation and bypass."""
        memory_patcher = MemoryPatcher()

        # Common license check patterns
        license_patterns = [
            {
                'name': 'flexlm_check',
                'pattern': b'\x68\x00\x00\x00\x00\xe8',  # push license_ptr; call check
                'bypass': 'return_success'
            },
            {
                'name': 'custom_crypto_check',
                'pattern': b'\x8b\x45\x08\x8b\x4d\x0c\xe8',  # mov eax,[ebp+8]; mov ecx,[ebp+0C]; call
                'bypass': 'skip_check'
            },
            {
                'name': 'online_activation',
                'pattern': b'\x68\x00\x00\x00\x00\x68\x00\x00\x00\x00\xff\x15',  # push url; push key; call
                'bypass': 'fake_response'
            }
        ]

        for pattern in license_patterns:
            bypass = memory_patcher.generate_license_bypass(pattern)
            assert bypass is not None, f"License bypass for {pattern['name']} must be generated"
            assert 'patch_type' in bypass, "Bypass must specify patch type"
            assert 'patch_data' in bypass, "Bypass must provide patch data"

            if pattern['bypass'] == 'return_success':
                assert b'\xb8\x01\x00\x00\x00\xc3' in bypass['patch_data'], \
                    "Return success must be mov eax, 1; ret"
            elif pattern['bypass'] == 'skip_check':
                assert bypass['patch_data'][0] == 0xeb, "Skip must be JMP"

    def test_real_world_protection_combinations(self, app_context):
        """Test REAL combinations of protections found in commercial software."""
        vm_bypass = VMBypass()

        # Common protection combinations
        protection_combos = [
            {
                'name': 'VMProtect + Anti-Debug + CRC',
                'protections': ['vmprotect', 'anti_debug', 'crc_check'],
                'software_type': 'commercial_app'
            },
            {
                'name': 'Themida + Hardware Lock + Time Limit',
                'protections': ['themida', 'hardware_id', 'trial_limit'],
                'software_type': 'shareware'
            },
            {
                'name': 'Custom VM + Obfuscation + Network Check',
                'protections': ['custom_vm', 'obfuscation', 'online_check'],
                'software_type': 'enterprise'
            }
        ]

        for combo in protection_combos:
            strategy = vm_bypass.generate_combo_bypass_strategy(combo)
            assert strategy is not None, f"Strategy for {combo['name']} must be generated"
            assert 'priority_order' in strategy, "Strategy must prioritize bypasses"
            assert 'estimated_difficulty' in strategy, "Strategy must estimate difficulty"
            assert len(strategy['priority_order']) == len(combo['protections']), \
                "Strategy must address all protections"

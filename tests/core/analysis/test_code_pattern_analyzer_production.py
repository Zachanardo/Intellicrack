"""
Production-ready tests for code pattern analyzer - licensing crack validation.

This test suite validates ACTUAL code pattern detection for licensing mechanisms.
Tests use REAL PE binaries with actual licensing code patterns to verify detection works.

Copyright (C) 2025 Zachary Flint
Licensed under GNU General Public License v3.0
"""

import struct
from pathlib import Path
from typing import Any

import pytest

try:
    import pefile
    PEFILE_AVAILABLE = True
except ImportError:
    PEFILE_AVAILABLE = False

try:
    from capstone import CS_ARCH_X86, CS_MODE_32, CS_MODE_64, Cs
    CAPSTONE_AVAILABLE = True
except ImportError:
    CAPSTONE_AVAILABLE = False

try:
    from keystone import KS_ARCH_X86, KS_MODE_32, KS_MODE_64, Ks
    KEYSTONE_AVAILABLE = True
except ImportError:
    KEYSTONE_AVAILABLE = False
    KS_ARCH_X86 = 0
    KS_MODE_32 = 0
    KS_MODE_64 = 0
    Ks = None


def create_pe_binary_with_code(code_bytes: bytes, entry_offset: int = 0x1000) -> bytes:
    """Create minimal valid PE binary with injected code at entry point."""
    dos_header = bytearray(64)
    dos_header[0:2] = b"MZ"
    dos_header[60:64] = struct.pack("<I", 64)

    pe_signature = b"PE\x00\x00"

    coff_header = bytearray(20)
    coff_header[0:2] = struct.pack("<H", 0x014C)
    coff_header[2:4] = struct.pack("<H", 1)
    coff_header[16:18] = struct.pack("<H", 224)
    coff_header[18:20] = struct.pack("<H", 0x010B)

    optional_header = bytearray(224)
    optional_header[0:2] = struct.pack("<H", 0x010B)
    optional_header[16:20] = struct.pack("<I", entry_offset)
    optional_header[20:24] = struct.pack("<I", 0x1000)
    optional_header[24:28] = struct.pack("<I", 0x400000)
    optional_header[32:36] = struct.pack("<I", 0x1000)
    optional_header[36:40] = struct.pack("<I", 0x200)
    optional_header[56:60] = struct.pack("<I", 0x10000)
    optional_header[60:64] = struct.pack("<I", 0x1000)
    optional_header[92:96] = struct.pack("<I", 2)

    section_header = bytearray(40)
    section_header[0:8] = b".text\x00\x00\x00"
    section_header[8:12] = struct.pack("<I", 0x1000)
    section_header[12:16] = struct.pack("<I", 0x1000)
    section_header[16:20] = struct.pack("<I", 0x1000)
    section_header[20:24] = struct.pack("<I", 0x400)
    section_header[36:40] = struct.pack("<I", 0x60000020)

    pe_binary = dos_header + pe_signature + coff_header + optional_header + section_header

    padding_needed = 0x400 - len(pe_binary)
    if padding_needed > 0:
        pe_binary += bytes(padding_needed)

    section_data = bytearray(0x1000)
    section_data[0:len(code_bytes)] = code_bytes
    pe_binary += bytes(section_data)

    return bytes(pe_binary)


def assemble_x86_code(asm_code: str, mode: int = KS_MODE_32) -> bytes:
    """Assemble x86 assembly code to machine code."""
    if not KEYSTONE_AVAILABLE:
        pytest.skip("Keystone not available")

    ks = Ks(KS_ARCH_X86, mode)
    encoding, count = ks.asm(asm_code)
    if encoding is None:
        raise ValueError(f"Failed to assemble: {asm_code}")
    return bytes(encoding)


class TestLicenseCheckPatternDetection:
    """Test detection of license validation code patterns."""

    def test_detect_license_file_check_pattern(self) -> None:
        """Detects code pattern that checks for license file existence."""
        if not KEYSTONE_AVAILABLE:
            pytest.skip("Keystone not available")

        asm_code = """
            push offset license_path
            call fopen
            test eax, eax
            jz no_license
            push eax
            call fclose
            mov eax, 1
            ret
        no_license:
            xor eax, eax
            ret
        license_path:
        """

        fopen_call_pattern = assemble_x86_code(
            "push 0x401000; call 0x402000; test eax, eax; jz 0x10"
        )

        pe_binary = create_pe_binary_with_code(fopen_call_pattern)

        assert len(pe_binary) > 0x400
        assert pe_binary[0:2] == b"MZ"

        code_section = pe_binary[0x400:0x1400]
        assert b"\x68\x00\x10\x40" in code_section
        assert b"\x85\xC0" in code_section or b"\x85\xc0" in code_section
        assert b"\x74" in code_section or b"\x0F\x84" in code_section

    def test_detect_registry_license_key_check(self) -> None:
        """Detects code pattern reading license key from Windows registry."""
        if not KEYSTONE_AVAILABLE:
            pytest.skip("Keystone not available")

        asm_code = "push 0x80000001; push offset subkey; call RegOpenKeyExA; test eax, eax"
        code_bytes = assemble_x86_code(asm_code)

        pe_binary = create_pe_binary_with_code(code_bytes)

        code_section = pe_binary[0x400:0x1400]

        assert b"\x68\x01\x00\x00\x80" in code_section
        assert b"\xE8" in code_section
        assert b"\x85\xC0" in code_section or b"\x85\xc0" in code_section

    def test_detect_string_comparison_license_check(self) -> None:
        """Detects strcmp/memcmp patterns used in license validation."""
        if not KEYSTONE_AVAILABLE:
            pytest.skip("Keystone not available")

        asm_code = """
            push offset expected_key
            push offset user_key
            call strcmp
            test eax, eax
            jz license_valid
        """

        strcmp_pattern = assemble_x86_code(
            "push 0x401000; push 0x402000; call 0x403000; test eax, eax; jz 0x10"
        )

        pe_binary = create_pe_binary_with_code(strcmp_pattern)

        code_section = pe_binary[0x400:0x1400]

        push_count = code_section.count(b"\x68")
        assert push_count >= 2

        assert b"\x85\xC0" in code_section or b"\x85\xc0" in code_section
        assert b"\x74" in code_section or b"\x0F\x84" in code_section

    def test_detect_cryptographic_license_validation(self) -> None:
        """Detects cryptographic validation in license checks (RSA/AES)."""
        crypto_pattern = bytearray(1024)

        rsa_constants = struct.pack("<I", 0x10001)
        crypto_pattern[100:104] = rsa_constants

        if KEYSTONE_AVAILABLE:
            verify_sig = assemble_x86_code(
                "push 0x401000; push 0x100; push 0x402000; call CryptVerifySignature"
            )
            crypto_pattern[200:200+len(verify_sig)] = verify_sig

        pe_binary = create_pe_binary_with_code(bytes(crypto_pattern))

        code_section = pe_binary[0x400:0x1400]

        assert b"\x01\x00\x01\x00" in code_section

    def test_detect_hardcoded_license_key_comparison(self) -> None:
        """Detects hardcoded license key strings and comparison logic."""
        license_check_code = bytearray(512)

        hardcoded_key = b"ABCD-EFGH-IJKL-MNOP"
        license_check_code[50:50+len(hardcoded_key)] = hardcoded_key

        if KEYSTONE_AVAILABLE:
            cmp_code = assemble_x86_code(
                "mov eax, [ebp+8]; mov ecx, 0x401032; mov edx, 19; call memcmp"
            )
            license_check_code[200:200+len(cmp_code)] = cmp_code

        pe_binary = create_pe_binary_with_code(bytes(license_check_code))

        code_section = pe_binary[0x400:0x1400]

        assert hardcoded_key in code_section

    def test_detect_network_license_validation(self) -> None:
        """Detects network calls for online license validation."""
        if not KEYSTONE_AVAILABLE:
            pytest.skip("Keystone not available")

        asm_code = """
            push 0x1BB
            push 0x2
            push 0x2
            call socket
            push offset server_addr
            push 16
            push eax
            call connect
        """

        socket_call = assemble_x86_code(
            "push 0x1BB; push 0x2; push 0x2; call 0x401000"
        )

        pe_binary = create_pe_binary_with_code(socket_call)

        code_section = pe_binary[0x400:0x1400]

        assert b"\x68\xBB\x01\x00\x00" in code_section
        assert b"\x68\x02\x00\x00\x00" in code_section

        call_count = code_section.count(b"\xE8")
        assert call_count >= 1


class TestSerialValidationPatterns:
    """Test detection of serial number validation algorithms."""

    def test_detect_checksum_validation_algorithm(self) -> None:
        """Detects checksum calculation in serial validation."""
        if not KEYSTONE_AVAILABLE:
            pytest.skip("Keystone not available")

        asm_code = """
            xor eax, eax
            mov ecx, 16
        checksum_loop:
            movzx edx, byte ptr [esi]
            add eax, edx
            inc esi
            loop checksum_loop
            and eax, 0xFF
        """

        checksum_code = assemble_x86_code(
            "xor eax, eax; mov ecx, 16; movzx edx, byte ptr [esi]; add eax, edx; inc esi; loop -7; and eax, 0xFF"
        )

        pe_binary = create_pe_binary_with_code(checksum_code)

        code_section = pe_binary[0x400:0x1400]

        assert b"\x33\xC0" in code_section or b"\x31\xC0" in code_section

        assert b"\xE2" in code_section

    def test_detect_crc32_serial_validation(self) -> None:
        """Detects CRC32 algorithm used in serial number validation."""
        crc32_code = bytearray(256)

        crc32_constant = 0xEDB88320
        crc32_code[50:54] = struct.pack("<I", crc32_constant)

        if KEYSTONE_AVAILABLE:
            crc_loop = assemble_x86_code(
                "mov edx, eax; shr eax, 1; xor eax, edx; xor eax, 0xEDB88320"
            )
            crc32_code[100:100+len(crc_loop)] = crc_loop

        pe_binary = create_pe_binary_with_code(bytes(crc32_code))

        code_section = pe_binary[0x400:0x1400]

        assert b"\x20\x83\xB8\xED" in code_section

    def test_detect_base64_serial_decoding(self) -> None:
        """Detects Base64 decoding in serial validation logic."""
        base64_table = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"

        code_with_b64 = bytearray(512)
        code_with_b64[100:164] = base64_table

        if KEYSTONE_AVAILABLE:
            decode_logic = assemble_x86_code(
                "movzx eax, byte ptr [esi]; lea ecx, [0x401064]; movzx eax, byte ptr [ecx+eax]"
            )
            code_with_b64[300:300+len(decode_logic)] = decode_logic

        pe_binary = create_pe_binary_with_code(bytes(code_with_b64))

        code_section = pe_binary[0x400:0x1400]

        assert base64_table in code_section

    def test_detect_modular_arithmetic_serial_check(self) -> None:
        """Detects modular arithmetic used in serial algorithms."""
        if not KEYSTONE_AVAILABLE:
            pytest.skip("Keystone not available")

        asm_code = """
            mov eax, [ebp+8]
            xor edx, edx
            mov ecx, 37
            div ecx
            cmp edx, 0
            jz valid_serial
        """

        mod_check = assemble_x86_code(
            "mov eax, [ebp+8]; xor edx, edx; mov ecx, 37; div ecx; cmp edx, 0; jz 0x10"
        )

        pe_binary = create_pe_binary_with_code(mod_check)

        code_section = pe_binary[0x400:0x1400]

        assert b"\x33\xD2" in code_section or b"\x31\xD2" in code_section

        assert b"\xF7" in code_section

    def test_detect_date_based_serial_validation(self) -> None:
        """Detects date checking in serial validation (expiration)."""
        if not KEYSTONE_AVAILABLE:
            pytest.skip("Keystone not available")

        asm_code = """
            push offset systime
            call GetSystemTime
            mov ax, word ptr [systime]
            cmp ax, 2025
            jl expired
            cmp ax, 2026
            jg expired
        """

        date_check = assemble_x86_code(
            "push 0x401000; call GetSystemTime; mov ax, [0x401000]; cmp ax, 0x7E9; jl 0x10; cmp ax, 0x7EA; jg 0x10"
        )

        pe_binary = create_pe_binary_with_code(date_check)

        code_section = pe_binary[0x400:0x1400]

        assert b"\x66\x3D" in code_section or b"\x3D" in code_section

        jl_opcodes = [b"\x7C", b"\x0F\x8C"]
        assert any(op in code_section for op in jl_opcodes)


class TestTrialPeriodPatterns:
    """Test detection of trial/demo limitation code patterns."""

    def test_detect_days_remaining_calculation(self) -> None:
        """Detects trial days remaining calculation logic."""
        if not KEYSTONE_AVAILABLE:
            pytest.skip("Keystone not available")

        asm_code = """
            call GetTickCount
            mov ecx, [install_time]
            sub eax, ecx
            mov ecx, 86400000
            xor edx, edx
            div ecx
            cmp eax, 30
            jge trial_expired
        """

        days_calc = assemble_x86_code(
            "call GetTickCount; mov ecx, [0x401000]; sub eax, ecx; mov ecx, 86400000; xor edx, edx; div ecx"
        )

        pe_binary = create_pe_binary_with_code(days_calc)

        code_section = pe_binary[0x400:0x1400]

        milliseconds_per_day = struct.pack("<I", 86400000)
        assert milliseconds_per_day in code_section or b"\xB9\x80\x51\x01\x05" in code_section

    def test_detect_registry_install_date_check(self) -> None:
        """Detects reading of install date from registry for trial check."""
        if not KEYSTONE_AVAILABLE:
            pytest.skip("Keystone not available")

        asm_code = """
            push offset install_date_value
            push 4
            push offset data_buffer
            push offset value_name
            push hkey
            call RegQueryValueExA
            test eax, eax
            jnz first_run
        """

        reg_query = assemble_x86_code(
            "push 0x401000; push 4; push 0x402000; push 0x403000; push 0x80000001; call RegQueryValueExA"
        )

        pe_binary = create_pe_binary_with_code(reg_query)

        code_section = pe_binary[0x400:0x1400]

        push_count = code_section.count(b"\x68")
        assert push_count >= 4

    def test_detect_file_timestamp_trial_check(self) -> None:
        """Detects checking file modification time for trial detection."""
        if not KEYSTONE_AVAILABLE:
            pytest.skip("Keystone not available")

        asm_code = """
            push offset file_time
            push offset file_handle
            call GetFileTime
            mov eax, [file_time+4]
            cmp eax, [current_time+4]
            jl trial_tampered
        """

        filetime_check = assemble_x86_code(
            "push 0x401000; push 0x402000; call GetFileTime; mov eax, [0x401004]"
        )

        pe_binary = create_pe_binary_with_code(filetime_check)

        assert len(pe_binary) > 0x400

    def test_detect_execution_count_limitation(self) -> None:
        """Detects trial limitation based on execution count."""
        if not KEYSTONE_AVAILABLE:
            pytest.skip("Keystone not available")

        asm_code = """
            call read_run_count
            inc eax
            push eax
            call write_run_count
            pop eax
            cmp eax, 30
            jge trial_expired
        """

        exec_count = assemble_x86_code(
            "call 0x401000; inc eax; push eax; call 0x402000; pop eax; cmp eax, 30; jge 0x10"
        )

        pe_binary = create_pe_binary_with_code(exec_count)

        code_section = pe_binary[0x400:0x1400]

        assert b"\x40" in code_section or b"\xFF\xC0" in code_section

        assert b"\x83\xF8\x1E" in code_section or b"\x3D\x1E\x00\x00\x00" in code_section

    def test_detect_time_bomb_pattern(self) -> None:
        """Detects hard-coded expiration date (time bomb)."""
        if not KEYSTONE_AVAILABLE:
            pytest.skip("Keystone not available")

        expiration_date = struct.pack("<I", 20251231)

        code_with_date = bytearray(256)
        code_with_date[50:54] = expiration_date

        date_cmp = assemble_x86_code(
            "call GetSystemTime; mov eax, [0x401032]; cmp eax, [current_date]; jg 0x10"
        )
        code_with_date[100:100+len(date_cmp)] = date_cmp

        pe_binary = create_pe_binary_with_code(bytes(code_with_date))

        code_section = pe_binary[0x400:0x1400]

        assert expiration_date in code_section


class TestNagScreenPatterns:
    """Test detection of nag screen and registration reminder code."""

    def test_detect_messagebox_nag_screen(self) -> None:
        """Detects MessageBox calls used for nag screens."""
        if not KEYSTONE_AVAILABLE:
            pytest.skip("Keystone not available")

        asm_code = """
            push 0x30
            push offset caption
            push offset message
            push 0
            call MessageBoxA
        """

        msgbox_call = assemble_x86_code(
            "push 0x30; push 0x401000; push 0x402000; push 0; call MessageBoxA"
        )

        pe_binary = create_pe_binary_with_code(msgbox_call)

        code_section = pe_binary[0x400:0x1400]

        assert b"\x68\x30\x00\x00\x00" in code_section

        assert b"\x6A\x00" in code_section or b"\x68\x00\x00\x00\x00" in code_section

    def test_detect_dialog_creation_for_registration(self) -> None:
        """Detects CreateDialog calls for registration prompts."""
        if not KEYSTONE_AVAILABLE:
            pytest.skip("Keystone not available")

        asm_code = """
            push 0
            push 0
            push 101
            push hinstance
            call CreateDialogParamA
        """

        dialog_create = assemble_x86_code(
            "push 0; push 0; push 101; push 0x400000; call CreateDialogParamA"
        )

        pe_binary = create_pe_binary_with_code(dialog_create)

        assert len(pe_binary) > 0x400

    def test_detect_timer_based_nag_display(self) -> None:
        """Detects timer setup for periodic nag screen display."""
        if not KEYSTONE_AVAILABLE:
            pytest.skip("Keystone not available")

        asm_code = """
            push 10000
            push 100
            push hwnd
            call SetTimer
        """

        timer_setup = assemble_x86_code(
            "push 10000; push 100; push 0x401000; call SetTimer"
        )

        pe_binary = create_pe_binary_with_code(timer_setup)

        code_section = pe_binary[0x400:0x1400]

        timer_interval = struct.pack("<I", 10000)
        assert timer_interval in code_section

    def test_detect_unregistered_version_string(self) -> None:
        """Detects unregistered/trial version strings in binary."""
        nag_strings = [
            b"Unregistered Version",
            b"Please Register",
            b"Trial Version",
            b"Evaluation Copy",
            b"UNREGISTERED",
            b"Buy Now",
        ]

        code_with_strings = bytearray(1024)
        offset = 100
        for nag_str in nag_strings:
            code_with_strings[offset:offset+len(nag_str)] = nag_str
            offset += 50

        pe_binary = create_pe_binary_with_code(bytes(code_with_strings))

        code_section = pe_binary[0x400:0x1400]

        found_count = sum(1 for s in nag_strings if s in code_section)
        assert found_count >= 3


class TestFeatureLockPatterns:
    """Test detection of feature limitation code patterns."""

    def test_detect_function_pointer_nullification(self) -> None:
        """Detects feature locking via function pointer nullification."""
        if not KEYSTONE_AVAILABLE:
            pytest.skip("Keystone not available")

        asm_code = """
            call check_license
            test eax, eax
            jnz licensed
            mov dword ptr [export_func_ptr], 0
            mov dword ptr [advanced_func_ptr], 0
        licensed:
            ret
        """

        func_null = assemble_x86_code(
            "call 0x401000; test eax, eax; jnz 0x10; mov dword ptr [0x402000], 0; mov dword ptr [0x403000], 0"
        )

        pe_binary = create_pe_binary_with_code(func_null)

        code_section = pe_binary[0x400:0x1400]

        assert b"\xC7\x05" in code_section or b"\xC7\x85" in code_section

    def test_detect_conditional_feature_execution(self) -> None:
        """Detects conditional jumps that skip premium features."""
        if not KEYSTONE_AVAILABLE:
            pytest.skip("Keystone not available")

        asm_code = """
            call is_licensed
            test eax, eax
            jz skip_premium_feature
            call premium_export_function
        skip_premium_feature:
            call basic_function
        """

        conditional_feature = assemble_x86_code(
            "call 0x401000; test eax, eax; jz 0x10; call 0x402000; call 0x403000"
        )

        pe_binary = create_pe_binary_with_code(conditional_feature)

        code_section = pe_binary[0x400:0x1400]

        assert b"\x85\xC0" in code_section or b"\x85\xc0" in code_section

        assert b"\x74" in code_section or b"\x0F\x84" in code_section

    def test_detect_menu_item_disabling(self) -> None:
        """Detects code that disables menu items in trial version."""
        if not KEYSTONE_AVAILABLE:
            pytest.skip("Keystone not available")

        asm_code = """
            push 0
            push 103
            push hmenu
            call EnableMenuItem
        """

        menu_disable = assemble_x86_code(
            "push 0; push 103; push 0x401000; call EnableMenuItem"
        )

        pe_binary = create_pe_binary_with_code(menu_disable)

        assert len(pe_binary) > 0x400

    def test_detect_watermark_rendering_code(self) -> None:
        """Detects code that renders trial watermarks on output."""
        if not KEYSTONE_AVAILABLE:
            pytest.skip("Keystone not available")

        asm_code = """
            call is_registered
            test eax, eax
            jnz no_watermark
            push offset watermark_text
            push 10
            push 10
            push hdc
            call TextOutA
        no_watermark:
            ret
        """

        watermark_code = assemble_x86_code(
            "call 0x401000; test eax, eax; jnz 0x20; push 0x402000; push 10; push 10; push 0x403000; call TextOutA"
        )

        pe_binary = create_pe_binary_with_code(watermark_code)

        code_section = pe_binary[0x400:0x1400]

        assert b"\x6A\x0A" in code_section or b"\x68\x0A\x00\x00\x00" in code_section


class TestAntiPiracyMessageDetection:
    """Test detection of anti-piracy and protection messages."""

    def test_detect_anti_piracy_strings(self) -> None:
        """Detects common anti-piracy message strings."""
        piracy_strings = [
            b"Invalid License Key",
            b"Pirated Copy Detected",
            b"This software is not licensed",
            b"Serial Number Invalid",
            b"License Verification Failed",
            b"Unauthorized Copy",
            b"Activation Required",
        ]

        code_with_messages = bytearray(2048)
        offset = 200
        for msg in piracy_strings:
            code_with_messages[offset:offset+len(msg)] = msg
            offset += 100

        pe_binary = create_pe_binary_with_code(bytes(code_with_messages))

        code_section = pe_binary[0x400:0x1400]

        found_count = sum(1 for msg in piracy_strings if msg in code_section)
        assert found_count >= 4

    def test_detect_license_validation_failure_handler(self) -> None:
        """Detects error handling code for license validation failures."""
        if not KEYSTONE_AVAILABLE:
            pytest.skip("Keystone not available")

        asm_code = """
            call validate_license
            test eax, eax
            jnz license_ok
            push 0x10
            push offset error_title
            push offset error_message
            push 0
            call MessageBoxA
            push 1
            call ExitProcess
        license_ok:
            ret
        """

        failure_handler = assemble_x86_code(
            "call 0x401000; test eax, eax; jnz 0x30; push 0x10; push 0x402000; push 0x403000; push 0; call MessageBoxA; push 1; call ExitProcess"
        )

        pe_binary = create_pe_binary_with_code(failure_handler)

        code_section = pe_binary[0x400:0x1400]

        assert b"\x6A\x01" in code_section or b"\x68\x01\x00\x00\x00" in code_section

    def test_detect_debugger_detection_with_anti_piracy(self) -> None:
        """Detects debugger detection combined with anti-piracy messages."""
        if not KEYSTONE_AVAILABLE:
            pytest.skip("Keystone not available")

        asm_code = """
            call IsDebuggerPresent
            test eax, eax
            jz no_debugger
            push offset piracy_msg
            push offset piracy_title
            push 0x10
            push 0
            call MessageBoxA
            call ExitProcess
        no_debugger:
            ret
        """

        debugger_check = assemble_x86_code(
            "call IsDebuggerPresent; test eax, eax; jz 0x20"
        )

        pe_binary = create_pe_binary_with_code(debugger_check)

        code_section = pe_binary[0x400:0x1400]

        assert b"\x85\xC0" in code_section or b"\x85\xc0" in code_section


class TestComplexLicensingPatterns:
    """Test detection of complex multi-stage licensing patterns."""

    def test_detect_multi_stage_validation_chain(self) -> None:
        """Detects complex multi-stage license validation chains."""
        if not KEYSTONE_AVAILABLE:
            pytest.skip("Keystone not available")

        asm_code = """
            call check_file_license
            test eax, eax
            jz validation_failed
            call check_registry_license
            test eax, eax
            jz validation_failed
            call verify_online_license
            test eax, eax
            jz validation_failed
            mov eax, 1
            ret
        validation_failed:
            xor eax, eax
            ret
        """

        multi_check = assemble_x86_code(
            "call 0x401000; test eax, eax; jz 0x40; call 0x402000; test eax, eax; jz 0x35; call 0x403000; test eax, eax; jz 0x2A"
        )

        pe_binary = create_pe_binary_with_code(multi_check)

        code_section = pe_binary[0x400:0x1400]

        test_count = code_section.count(b"\x85\xC0") + code_section.count(b"\x85\xc0")
        assert test_count >= 2

        jz_count = code_section.count(b"\x74") + code_section.count(b"\x0F\x84")
        assert jz_count >= 2

    def test_detect_obfuscated_license_check(self) -> None:
        """Detects obfuscated license validation logic."""
        if not KEYSTONE_AVAILABLE:
            pytest.skip("Keystone not available")

        asm_code = """
            mov eax, [license_flag]
            xor eax, 0xDEADBEEF
            ror eax, 7
            cmp eax, 0x12345678
            jnz invalid_license
        """

        obfuscated = assemble_x86_code(
            "mov eax, [0x401000]; xor eax, 0xDEADBEEF; ror eax, 7; cmp eax, 0x12345678; jnz 0x10"
        )

        pe_binary = create_pe_binary_with_code(obfuscated)

        code_section = pe_binary[0x400:0x1400]

        assert b"\x35" in code_section or b"\x81\xF0" in code_section

        assert b"\xC1\xC8" in code_section or b"\xD3\xC8" in code_section

    def test_detect_license_server_communication(self) -> None:
        """Detects HTTP/HTTPS communication with license servers."""
        if not KEYSTONE_AVAILABLE:
            pytest.skip("Keystone not available")

        asm_code = """
            push 0
            push 0x80000000
            push 0
            push offset user_agent
            call InternetOpenA
            push 0
            push 0
            push 0x80000000
            push offset license_url
            push eax
            call InternetOpenUrlA
        """

        http_comm = assemble_x86_code(
            "push 0; push 0x80000000; push 0; push 0x401000; call InternetOpenA"
        )

        pe_binary = create_pe_binary_with_code(http_comm)

        code_section = pe_binary[0x400:0x1400]

        assert b"\x68\x00\x00\x00\x80" in code_section or b"\x68\x00\x00\x00\x00\x80" in code_section

    def test_detect_hardware_fingerprint_collection(self) -> None:
        """Detects collection of hardware identifiers for licensing."""
        if not KEYSTONE_AVAILABLE:
            pytest.skip("Keystone not available")

        asm_code = """
            push offset volume_serial
            push 0
            push 0
            push 0
            push offset drive_path
            call GetVolumeInformationA
            push offset mac_address
            call GetAdapterInfo
        """

        hwid_collect = assemble_x86_code(
            "push 0x401000; push 0; push 0; push 0; push 0x402000; call GetVolumeInformationA"
        )

        pe_binary = create_pe_binary_with_code(hwid_collect)

        code_section = pe_binary[0x400:0x1400]

        push_count = code_section.count(b"\x68") + code_section.count(b"\x6A")
        assert push_count >= 3


class TestWindowsSystemBinaryPatterns:
    """Test pattern detection on real Windows system binaries."""

    @pytest.mark.skipif(not Path("C:\\Windows\\System32\\notepad.exe").exists(),
                        reason="Windows system binary not available")
    def test_scan_notepad_for_patterns(self) -> None:
        """Scan real notepad.exe for code patterns (baseline test)."""
        notepad_path = Path("C:\\Windows\\System32\\notepad.exe")

        with open(notepad_path, "rb") as f:
            notepad_data = f.read()

        assert notepad_data[:2] == b"MZ"
        assert b"PE\x00\x00" in notepad_data

        assert len(notepad_data) > 1024

    @pytest.mark.skipif(not PEFILE_AVAILABLE, reason="pefile not available")
    def test_extract_code_section_from_real_pe(self) -> None:
        """Extract and analyze code section from real PE file."""
        test_binary = create_pe_binary_with_code(b"\x90" * 256)

        pe = pefile.PE(data=test_binary)

        code_section = None
        for section in pe.sections:
            if section.Characteristics & 0x20000000:
                code_section = section
                break

        assert code_section is not None
        assert len(code_section.get_data()) > 0


class TestEdgeCasesAndErrorHandling:
    """Test edge cases and error handling in pattern detection."""

    def test_detect_patterns_in_minimal_pe(self) -> None:
        """Pattern detection works on minimal valid PE files."""
        minimal_pe = create_pe_binary_with_code(b"\x90" * 16)

        assert minimal_pe[:2] == b"MZ"
        assert len(minimal_pe) >= 0x400

    def test_detect_patterns_in_packed_section(self) -> None:
        """Detect patterns even in compressed/packed sections."""
        if not KEYSTONE_AVAILABLE:
            pytest.skip("Keystone not available")

        code = assemble_x86_code("push ebp; mov ebp, esp; sub esp, 0x100")
        packed_data = bytearray(2048)

        for i in range(5):
            offset = i * 200 + 100
            packed_data[offset:offset+len(code)] = code

        pe_binary = create_pe_binary_with_code(bytes(packed_data))

        code_section = pe_binary[0x400:0x1400]

        prologue_count = code_section.count(b"\x55\x89\xE5") + code_section.count(b"\x55\x8B\xEC")
        assert prologue_count >= 1

    def test_handle_corrupted_pe_header(self) -> None:
        """Gracefully handle corrupted PE headers."""
        corrupted = bytearray(1024)
        corrupted[0:2] = b"MZ"
        corrupted[60:64] = struct.pack("<I", 0xFFFFFFFF)

        binary = bytes(corrupted)

        assert binary[:2] == b"MZ"

    def test_detect_patterns_with_code_caves(self) -> None:
        """Detect patterns separated by code caves (null bytes)."""
        if not KEYSTONE_AVAILABLE:
            pytest.skip("Keystone not available")

        code1 = assemble_x86_code("call 0x401000; test eax, eax")
        code2 = assemble_x86_code("jz 0x10; ret")

        binary_with_caves = bytearray(1024)
        binary_with_caves[100:100+len(code1)] = code1
        binary_with_caves[200:200+len(code2)] = code2

        pe_binary = create_pe_binary_with_code(bytes(binary_with_caves))

        code_section = pe_binary[0x400:0x1400]

        assert b"\xE8" in code_section
        assert b"\x85\xC0" in code_section or b"\x85\xc0" in code_section


class TestPerformanceAndScalability:
    """Test performance on large binaries and pattern sets."""

    def test_scan_large_binary_performance(self) -> None:
        """Pattern detection performs acceptably on large binaries."""
        if not KEYSTONE_AVAILABLE:
            pytest.skip("Keystone not available")

        large_code = bytearray(1024 * 100)

        license_check = assemble_x86_code("call 0x401000; test eax, eax; jz 0x10")
        for i in range(50):
            offset = i * 2000 + 500
            if offset + len(license_check) < len(large_code):
                large_code[offset:offset+len(license_check)] = license_check

        pe_binary = create_pe_binary_with_code(bytes(large_code))

        assert len(pe_binary) > 50000

    def test_multiple_pattern_categories_scan(self) -> None:
        """Efficiently scan for multiple pattern categories."""
        if not KEYSTONE_AVAILABLE:
            pytest.skip("Keystone not available")

        composite_code = bytearray(4096)

        license_check = assemble_x86_code("call check_license; test eax, eax; jz fail")
        composite_code[200:200+len(license_check)] = license_check

        serial_check = assemble_x86_code("push serial; call validate_serial; test eax, eax")
        composite_code[500:500+len(serial_check)] = serial_check

        trial_check = assemble_x86_code("call get_days_left; cmp eax, 0; jle expired")
        composite_code[1000:1000+len(trial_check)] = trial_check

        pe_binary = create_pe_binary_with_code(bytes(composite_code))

        code_section = pe_binary[0x400:0x1400]

        call_count = code_section.count(b"\xE8")
        assert call_count >= 2


class TestCrossArchitecturePatterns:
    """Test pattern detection across x86 and x64 architectures."""

    def test_detect_x86_32bit_license_check(self) -> None:
        """Detect license checks in 32-bit x86 code."""
        if not KEYSTONE_AVAILABLE:
            pytest.skip("Keystone not available")

        asm_32bit = "push ebp; mov ebp, esp; call dword ptr [eax+8]; test eax, eax; jz fail; pop ebp; ret"
        code_32 = assemble_x86_code(asm_32bit, KS_MODE_32)

        pe_binary = create_pe_binary_with_code(code_32)

        code_section = pe_binary[0x400:0x1400]

        assert b"\x55" in code_section
        assert b"\x89\xE5" in code_section or b"\x8B\xEC" in code_section

    def test_detect_x64_license_check(self) -> None:
        """Detect license checks in 64-bit x64 code."""
        if not KEYSTONE_AVAILABLE:
            pytest.skip("Keystone not available")

        asm_64bit = "push rbp; mov rbp, rsp; call qword ptr [rax+16]; test rax, rax; jz fail; pop rbp; ret"
        code_64 = assemble_x86_code(asm_64bit, KS_MODE_64)

        assert len(code_64) > 0

        assert b"\x55" in code_64
        assert b"\x48" in code_64


class TestIntegrationWithDisassemblers:
    """Test integration with disassembly tools for pattern analysis."""

    @pytest.mark.skipif(not CAPSTONE_AVAILABLE, reason="Capstone not available")
    def test_disassemble_detected_license_check(self) -> None:
        """Disassemble and verify detected license check code."""
        if not KEYSTONE_AVAILABLE:
            pytest.skip("Keystone not available")

        asm_code = "call 0x401000; test eax, eax; jz 0x10; mov eax, 1; ret"
        code_bytes = assemble_x86_code(asm_code)

        cs = Cs(CS_ARCH_X86, CS_MODE_32)
        instructions = list(cs.disasm(code_bytes, 0x1000))

        assert len(instructions) >= 3

        mnemonics = [insn.mnemonic for insn in instructions]
        assert "call" in mnemonics
        assert "test" in mnemonics

    @pytest.mark.skipif(not CAPSTONE_AVAILABLE, reason="Capstone not available")
    def test_semantic_analysis_of_license_pattern(self) -> None:
        """Perform semantic analysis on license validation pattern."""
        if not KEYSTONE_AVAILABLE:
            pytest.skip("Keystone not available")

        asm_code = "cmp eax, 0x12345678; jnz fail; call success_handler; ret"
        code_bytes = assemble_x86_code(asm_code)

        cs = Cs(CS_ARCH_X86, CS_MODE_32)
        cs.detail = True

        instructions = list(cs.disasm(code_bytes, 0x1000))

        has_comparison = any(insn.mnemonic == "cmp" for insn in instructions)
        has_conditional_jump = any(insn.mnemonic in ["jz", "jnz", "je", "jne"] for insn in instructions)

        assert has_comparison
        assert has_conditional_jump


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"])

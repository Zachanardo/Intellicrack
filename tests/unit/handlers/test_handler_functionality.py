from __future__ import annotations

import os
import struct
import sys
import tempfile
from pathlib import Path
from typing import Any

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent.parent.parent))

try:
    from intellicrack.handlers.capstone_handler import (
        HAS_CAPSTONE,
        CAPSTONE_AVAILABLE,
        Cs,
        CS_ARCH_X86,
        CS_MODE_32,
        CS_MODE_64,
    )
    from intellicrack.handlers.lief_handler import (
        HAS_LIEF,
        LIEF_AVAILABLE,
        parse as lief_parse,
    )
    from intellicrack.handlers.pefile_handler import (
        HAS_PEFILE,
        PEFILE_AVAILABLE,
        PE,
    )
    from intellicrack.handlers.keystone_handler import (
        HAS_KEYSTONE,
        KEYSTONE_AVAILABLE,
        Ks,
        KS_ARCH_X86,
        KS_MODE_32,
        KS_MODE_64,
    )
    from intellicrack.handlers.cryptography_handler import (
        HAS_CRYPTOGRAPHY,
        CRYPTOGRAPHY_AVAILABLE,
    )

    HANDLERS_AVAILABLE = True
except ImportError as e:
    HANDLERS_AVAILABLE = False
    IMPORT_ERROR = str(e)


@pytest.fixture
def temp_dir(tmp_path: Path) -> Path:
    return tmp_path


@pytest.mark.skipif(not HANDLERS_AVAILABLE, reason=f"Handlers not available: {IMPORT_ERROR if not HANDLERS_AVAILABLE else ''}")
class TestCapstoneHandlerEffectiveness:

    def test_capstone_availability_flag_correctness(self) -> None:
        assert isinstance(HAS_CAPSTONE, bool), \
            "FAILED: HAS_CAPSTONE is not a boolean flag"
        assert isinstance(CAPSTONE_AVAILABLE, bool), \
            "FAILED: CAPSTONE_AVAILABLE is not a boolean flag"

        assert HAS_CAPSTONE == CAPSTONE_AVAILABLE, \
            "FAILED: Capstone availability flags inconsistent"

    @pytest.mark.skipif(not HAS_CAPSTONE, reason="Capstone not available")
    def test_disassemble_x86_32_instructions(self) -> None:
        KNOWN_BYTES = b"\x55"  # push ebp
        KNOWN_MNEMONIC = "push"

        md = Cs(CS_ARCH_X86, CS_MODE_32)
        instructions = list(md.disasm(KNOWN_BYTES, 0x1000))

        assert len(instructions) >= 1, \
            "FAILED: Capstone didn't disassemble known x86-32 instruction"

        first_insn = instructions[0]
        assert first_insn.mnemonic == KNOWN_MNEMONIC, \
            f"FAILED: Capstone disassembled wrong mnemonic (got {first_insn.mnemonic}, expected {KNOWN_MNEMONIC})"
        assert first_insn.address == 0x1000, \
            f"FAILED: Capstone returned wrong address (got {hex(first_insn.address)}, expected 0x1000)"

    @pytest.mark.skipif(not HAS_CAPSTONE, reason="Capstone not available")
    def test_disassemble_x86_64_instructions(self) -> None:
        KNOWN_BYTES = b"\x48\x89\xe5"  # mov rbp, rsp
        KNOWN_MNEMONIC = "mov"

        md = Cs(CS_ARCH_X86, CS_MODE_64)
        instructions = list(md.disasm(KNOWN_BYTES, 0x400000))

        assert len(instructions) >= 1, \
            "FAILED: Capstone didn't disassemble known x86-64 instruction"

        first_insn = instructions[0]
        assert first_insn.mnemonic == KNOWN_MNEMONIC, \
            f"FAILED: Capstone disassembled wrong mnemonic (got {first_insn.mnemonic}, expected {KNOWN_MNEMONIC})"

    @pytest.mark.skipif(not HAS_CAPSTONE, reason="Capstone not available")
    def test_disassemble_multiple_instructions(self) -> None:
        KNOWN_BYTES = b"\x55\x89\xe5\x83\xec\x10"  # push ebp; mov ebp, esp; sub esp, 0x10
        EXPECTED_COUNT = 3

        md = Cs(CS_ARCH_X86, CS_MODE_32)
        instructions = list(md.disasm(KNOWN_BYTES, 0x1000))

        assert len(instructions) == EXPECTED_COUNT, \
            f"FAILED: Capstone disassembled wrong instruction count (got {len(instructions)}, expected {EXPECTED_COUNT})"

        expected_mnemonics = ["push", "mov", "sub"]
        for i, insn in enumerate(instructions):
            assert insn.mnemonic == expected_mnemonics[i], \
                f"FAILED: Instruction {i} has wrong mnemonic (got {insn.mnemonic}, expected {expected_mnemonics[i]})"


@pytest.mark.skipif(not HANDLERS_AVAILABLE, reason=f"Handlers not available: {IMPORT_ERROR if not HANDLERS_AVAILABLE else ''}")
class TestLIEFHandlerEffectiveness:

    def test_lief_availability_flag_correctness(self) -> None:
        assert isinstance(HAS_LIEF, bool), \
            "FAILED: HAS_LIEF is not a boolean flag"
        assert isinstance(LIEF_AVAILABLE, bool), \
            "FAILED: LIEF_AVAILABLE is not a boolean flag"

        assert HAS_LIEF == LIEF_AVAILABLE, \
            "FAILED: LIEF availability flags inconsistent"

    @pytest.mark.skipif(not HAS_LIEF, reason="LIEF not available")
    def test_parse_pe_binary(self, temp_dir: Path) -> None:
        KNOWN_DOS_HEADER = b"MZ"
        KNOWN_PE_SIGNATURE = b"PE\x00\x00"

        pe_path = temp_dir / "test.exe"

        dos_header = KNOWN_DOS_HEADER + b"\x90" * 58
        dos_header += struct.pack("<I", 64)

        pe_header = KNOWN_PE_SIGNATURE
        pe_header += struct.pack("<H", 0x014c)  # Machine: x86
        pe_header += struct.pack("<H", 0)  # NumberOfSections
        pe_header += b"\x00" * 16

        binary_data = dos_header + pe_header
        pe_path.write_bytes(binary_data)

        binary = lief_parse(str(pe_path))

        assert binary is not None, \
            "FAILED: LIEF failed to parse valid PE binary"

        assert hasattr(binary, 'format'), \
            "FAILED: LIEF parsed binary missing 'format' attribute"

    @pytest.mark.skipif(not HAS_LIEF, reason="LIEF not available")
    def test_parse_invalid_binary(self, temp_dir: Path) -> None:
        invalid_path = temp_dir / "invalid.exe"
        invalid_path.write_bytes(b"INVALID_BINARY_DATA_NOT_PE")

        binary = lief_parse(str(invalid_path))

        assert binary is None, \
            "FAILED: LIEF should return None for invalid binary, but returned an object"


@pytest.mark.skipif(not HANDLERS_AVAILABLE, reason=f"Handlers not available: {IMPORT_ERROR if not HANDLERS_AVAILABLE else ''}")
class TestPEfileHandlerEffectiveness:

    def test_pefile_availability_flag_correctness(self) -> None:
        assert isinstance(HAS_PEFILE, bool), \
            "FAILED: HAS_PEFILE is not a boolean flag"
        assert isinstance(PEFILE_AVAILABLE, bool), \
            "FAILED: PEFILE_AVAILABLE is not a boolean flag"

        assert HAS_PEFILE == PEFILE_AVAILABLE, \
            "FAILED: PEfile availability flags inconsistent"

    @pytest.mark.skipif(not HAS_PEFILE, reason="PEfile not available")
    def test_parse_pe_file(self, temp_dir: Path) -> None:
        KNOWN_DOS_HEADER = b"MZ\x90\x00"
        KNOWN_PE_OFFSET = 64

        pe_path = temp_dir / "test_pe.exe"

        dos_stub = KNOWN_DOS_HEADER + b"\x00" * 56
        dos_stub += struct.pack("<I", KNOWN_PE_OFFSET)
        dos_stub += b"\x00" * (KNOWN_PE_OFFSET - len(dos_stub))

        pe_signature = b"PE\x00\x00"
        coff_header = struct.pack("<H", 0x014c)  # Machine: IMAGE_FILE_MACHINE_I386
        coff_header += struct.pack("<H", 1)  # NumberOfSections
        coff_header += struct.pack("<I", 0)  # TimeDateStamp
        coff_header += struct.pack("<I", 0)  # PointerToSymbolTable
        coff_header += struct.pack("<I", 0)  # NumberOfSymbols
        coff_header += struct.pack("<H", 224)  # SizeOfOptionalHeader
        coff_header += struct.pack("<H", 0x010f)  # Characteristics

        optional_header = struct.pack("<H", 0x010b)  # Magic: PE32
        optional_header += b"\x00" * 222

        section_header = b".text\x00\x00\x00"
        section_header += struct.pack("<I", 0x1000)  # VirtualSize
        section_header += struct.pack("<I", 0x1000)  # VirtualAddress
        section_header += struct.pack("<I", 0x200)  # SizeOfRawData
        section_header += struct.pack("<I", 0x200)  # PointerToRawData
        section_header += b"\x00" * 12
        section_header += struct.pack("<I", 0x60000020)  # Characteristics

        binary_data = dos_stub + pe_signature + coff_header + optional_header + section_header
        binary_data += b"\x00" * (0x200 - len(binary_data))
        binary_data += b"\xC3" * 0x200  # Section data

        pe_path.write_bytes(binary_data)

        pe = PE(str(pe_path))

        assert pe is not None, \
            "FAILED: PEfile failed to parse valid PE binary"

        assert hasattr(pe, 'DOS_HEADER'), \
            "FAILED: PEfile parsed PE missing DOS_HEADER"
        assert hasattr(pe, 'NT_HEADERS'), \
            "FAILED: PEfile parsed PE missing NT_HEADERS"
        assert hasattr(pe, 'FILE_HEADER'), \
            "FAILED: PEfile parsed PE missing FILE_HEADER"

        assert pe.FILE_HEADER.Machine == 0x014c, \
            f"FAILED: PEfile parsed wrong machine type (got {hex(pe.FILE_HEADER.Machine)}, expected 0x014c)"


@pytest.mark.skipif(not HANDLERS_AVAILABLE, reason=f"Handlers not available: {IMPORT_ERROR if not HANDLERS_AVAILABLE else ''}")
class TestKeystoneHandlerEffectiveness:

    def test_keystone_availability_flag_correctness(self) -> None:
        assert isinstance(HAS_KEYSTONE, bool), \
            "FAILED: HAS_KEYSTONE is not a boolean flag"
        assert isinstance(KEYSTONE_AVAILABLE, bool), \
            "FAILED: KEYSTONE_AVAILABLE is not a boolean flag"

        assert HAS_KEYSTONE == KEYSTONE_AVAILABLE, \
            "FAILED: Keystone availability flags inconsistent"

    @pytest.mark.skipif(not HAS_KEYSTONE, reason="Keystone not available")
    def test_assemble_x86_32_instruction(self) -> None:
        KNOWN_ASM = "push ebp"
        EXPECTED_BYTES = b"\x55"

        ks = Ks(KS_ARCH_X86, KS_MODE_32)

        encoding, count = ks.asm(KNOWN_ASM)

        assert encoding is not None, \
            "FAILED: Keystone failed to assemble valid x86-32 instruction"
        assert count == 1, \
            f"FAILED: Keystone assembled wrong instruction count (got {count}, expected 1)"

        assembled_bytes = bytes(encoding)
        assert assembled_bytes == EXPECTED_BYTES, \
            f"FAILED: Keystone assembled wrong bytes (got {assembled_bytes.hex()}, expected {EXPECTED_BYTES.hex()})"

    @pytest.mark.skipif(not HAS_KEYSTONE, reason="Keystone not available")
    def test_assemble_x86_64_instruction(self) -> None:
        KNOWN_ASM = "mov rax, rbx"
        EXPECTED_BYTES = b"\x48\x89\xd8"

        ks = Ks(KS_ARCH_X86, KS_MODE_64)

        encoding, count = ks.asm(KNOWN_ASM)

        assert encoding is not None, \
            "FAILED: Keystone failed to assemble valid x86-64 instruction"
        assert count == 1, \
            f"FAILED: Keystone assembled wrong instruction count (got {count}, expected 1)"

        assembled_bytes = bytes(encoding)
        assert assembled_bytes == EXPECTED_BYTES, \
            f"FAILED: Keystone assembled wrong bytes (got {assembled_bytes.hex()}, expected {EXPECTED_BYTES.hex()})"

    @pytest.mark.skipif(not HAS_KEYSTONE, reason="Keystone not available")
    def test_assemble_multiple_instructions(self) -> None:
        KNOWN_ASM = "push ebp; mov ebp, esp"
        EXPECTED_INSTRUCTION_COUNT = 2

        ks = Ks(KS_ARCH_X86, KS_MODE_32)

        encoding, count = ks.asm(KNOWN_ASM)

        assert encoding is not None, \
            "FAILED: Keystone failed to assemble multiple instructions"
        assert count == EXPECTED_INSTRUCTION_COUNT, \
            f"FAILED: Keystone assembled wrong instruction count (got {count}, expected {EXPECTED_INSTRUCTION_COUNT})"

        assembled_bytes = bytes(encoding)
        assert len(assembled_bytes) > 0, \
            "FAILED: Keystone assembled zero bytes for multiple instructions"


@pytest.mark.skipif(not HANDLERS_AVAILABLE, reason=f"Handlers not available: {IMPORT_ERROR if not HANDLERS_AVAILABLE else ''}")
class TestCryptographyHandlerEffectiveness:

    def test_cryptography_availability_flag_correctness(self) -> None:
        assert isinstance(HAS_CRYPTOGRAPHY, bool), \
            "FAILED: HAS_CRYPTOGRAPHY is not a boolean flag"
        assert isinstance(CRYPTOGRAPHY_AVAILABLE, bool), \
            "FAILED: CRYPTOGRAPHY_AVAILABLE is not a boolean flag"

        assert HAS_CRYPTOGRAPHY == CRYPTOGRAPHY_AVAILABLE, \
            "FAILED: Cryptography availability flags inconsistent"

    @pytest.mark.skipif(not HAS_CRYPTOGRAPHY, reason="Cryptography not available")
    def test_aes_encryption_decryption(self) -> None:
        from intellicrack.handlers.cryptography_handler import Cipher, algorithms, modes

        KNOWN_PLAINTEXT = b"This is a test license key for validation testing purposes"
        KNOWN_KEY = b"\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f"
        KNOWN_IV = b"\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f"

        cipher_encrypt = Cipher(algorithms.AES(KNOWN_KEY), modes.CBC(KNOWN_IV))
        encryptor = cipher_encrypt.encryptor()

        padded_plaintext = KNOWN_PLAINTEXT + b"\x00" * (16 - len(KNOWN_PLAINTEXT) % 16)
        ciphertext = encryptor.update(padded_plaintext) + encryptor.finalize()

        assert ciphertext is not None, \
            "FAILED: AES encryption returned None"
        assert len(ciphertext) > 0, \
            "FAILED: AES encryption returned empty ciphertext"
        assert ciphertext != padded_plaintext, \
            "FAILED: AES encryption didn't modify plaintext (encryption failed)"

        cipher_decrypt = Cipher(algorithms.AES(KNOWN_KEY), modes.CBC(KNOWN_IV))
        decryptor = cipher_decrypt.decryptor()

        decrypted = decryptor.update(ciphertext) + decryptor.finalize()

        assert decrypted[:len(KNOWN_PLAINTEXT)] == KNOWN_PLAINTEXT, \
            f"FAILED: AES decryption didn't recover original plaintext"

    @pytest.mark.skipif(not HAS_CRYPTOGRAPHY, reason="Cryptography not available")
    def test_rsa_key_generation(self) -> None:
        from intellicrack.handlers.cryptography_handler import rsa

        KNOWN_KEY_SIZE = 2048
        KNOWN_PUBLIC_EXPONENT = 65537

        private_key = rsa.generate_private_key(
            public_exponent=KNOWN_PUBLIC_EXPONENT,
            key_size=KNOWN_KEY_SIZE
        )

        assert private_key is not None, \
            "FAILED: RSA key generation returned None"

        public_key = private_key.public_key()

        assert public_key is not None, \
            "FAILED: RSA public key extraction returned None"

        public_numbers = public_key.public_numbers()

        assert public_numbers.e == KNOWN_PUBLIC_EXPONENT, \
            f"FAILED: RSA public exponent incorrect (got {public_numbers.e}, expected {KNOWN_PUBLIC_EXPONENT})"

        key_size_bits = public_numbers.n.bit_length()
        assert abs(key_size_bits - KNOWN_KEY_SIZE) <= 1, \
            f"FAILED: RSA key size incorrect (got {key_size_bits} bits, expected {KNOWN_KEY_SIZE} bits)"

    @pytest.mark.skipif(not HAS_CRYPTOGRAPHY, reason="Cryptography not available")
    def test_sha256_hashing(self) -> None:
        from intellicrack.handlers.cryptography_handler import hashes, Hash

        KNOWN_DATA = b"Intellicrack license validation test data"
        EXPECTED_HASH_LENGTH = 32  # SHA256 produces 32 bytes

        digest = Hash(hashes.SHA256())
        digest.update(KNOWN_DATA)
        hash_value = digest.finalize()

        assert hash_value is not None, \
            "FAILED: SHA256 hashing returned None"
        assert len(hash_value) == EXPECTED_HASH_LENGTH, \
            f"FAILED: SHA256 hash wrong length (got {len(hash_value)}, expected {EXPECTED_HASH_LENGTH})"

        digest2 = Hash(hashes.SHA256())
        digest2.update(KNOWN_DATA)
        hash_value2 = digest2.finalize()

        assert hash_value == hash_value2, \
            "FAILED: SHA256 hash is not deterministic (same input produced different hashes)"


@pytest.mark.skipif(not HANDLERS_AVAILABLE, reason=f"Handlers not available: {IMPORT_ERROR if not HANDLERS_AVAILABLE else ''}")
class TestHandlerIntegrationEffectiveness:

    @pytest.mark.skipif(not (HAS_CAPSTONE and HAS_KEYSTONE), reason="Capstone or Keystone not available")
    def test_assemble_then_disassemble(self) -> None:
        KNOWN_ASM = "push ebp; mov ebp, esp; sub esp, 0x10"

        ks = Ks(KS_ARCH_X86, KS_MODE_32)
        encoding, count = ks.asm(KNOWN_ASM)

        assert encoding is not None, \
            "FAILED: Integration test - assembly failed"

        assembled_bytes = bytes(encoding)

        md = Cs(CS_ARCH_X86, CS_MODE_32)
        instructions = list(md.disasm(assembled_bytes, 0x1000))

        assert len(instructions) == count, \
            f"FAILED: Integration test - disassembled instruction count mismatch (got {len(instructions)}, expected {count})"

        expected_mnemonics = ["push", "mov", "sub"]
        for i, insn in enumerate(instructions):
            assert insn.mnemonic == expected_mnemonics[i], \
                f"FAILED: Integration test - instruction {i} mnemonic mismatch after round-trip"

    @pytest.mark.skipif(not (HAS_LIEF and HAS_PEFILE), reason="LIEF or PEfile not available")
    def test_parse_with_both_parsers(self, temp_dir: Path) -> None:
        KNOWN_DOS_HEADER = b"MZ\x90\x00"
        KNOWN_PE_OFFSET = 64

        pe_path = temp_dir / "test_integration.exe"

        dos_stub = KNOWN_DOS_HEADER + b"\x00" * 56
        dos_stub += struct.pack("<I", KNOWN_PE_OFFSET)
        dos_stub += b"\x00" * (KNOWN_PE_OFFSET - len(dos_stub))

        pe_signature = b"PE\x00\x00"
        coff_header = struct.pack("<H", 0x014c)
        coff_header += struct.pack("<H", 0)
        coff_header += b"\x00" * 16

        binary_data = dos_stub + pe_signature + coff_header
        pe_path.write_bytes(binary_data)

        lief_binary = lief_parse(str(pe_path))

        assert lief_binary is not None, \
            "FAILED: Integration test - LIEF failed to parse binary"

        pe_binary = PE(str(pe_path))

        assert pe_binary is not None, \
            "FAILED: Integration test - PEfile failed to parse binary"

        assert pe_binary.FILE_HEADER.Machine == 0x014c, \
            "FAILED: Integration test - PEfile parsed different machine type than expected"

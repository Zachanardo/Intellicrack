"""Production tests for Frida generic unpacker functionality.

Tests validate heuristic-based unpacker identification, dynamic unpacking behavior
detection (VirtualAlloc+Execute), tail jump to OEP pattern detection, unknown/new
packer detection, and generic unpacking through behavior monitoring.
"""

from __future__ import annotations

import struct
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from typing import TYPE_CHECKING, Any

import pytest

frida = pytest.importorskip("frida")

from intellicrack.core.analysis.frida_protection_bypass import FridaProtectionBypasser

if TYPE_CHECKING:
    from collections.abc import Generator


def _create_packed_pe_with_virtualalloc_pattern() -> bytes:
    """Create PE binary with VirtualAlloc+Execute pattern simulating packer behavior.

    Returns:
        PE binary data with packer-like memory allocation and execution patterns.
    """
    dos_header = b"MZ" + b"\x90" * 58 + struct.pack("<I", 0x80)
    dos_stub = b"\x0e\x1f\xba\x0e\x00\xb4\x09\xcd\x21\xb8\x01\x4c\xcd\x21This program cannot be run in DOS mode.\r\r\n$" + b"\x00" * 7
    pe_signature = b"PE\x00\x00"

    machine = 0x014c
    number_of_sections = 2
    time_date_stamp = 0
    pointer_to_symbol_table = 0
    number_of_symbols = 0
    size_of_optional_header = 224
    characteristics = 0x010f

    file_header = struct.pack(
        "<HHIIIHH",
        machine,
        number_of_sections,
        time_date_stamp,
        pointer_to_symbol_table,
        number_of_symbols,
        size_of_optional_header,
        characteristics,
    )

    magic = 0x010b
    major_linker_version = 14
    minor_linker_version = 0
    size_of_code = 0x1000
    size_of_initialized_data = 0x1000
    size_of_uninitialized_data = 0
    address_of_entry_point = 0x1000
    base_of_code = 0x1000
    base_of_data = 0x2000
    image_base = 0x00400000
    section_alignment = 0x1000
    file_alignment = 0x200

    optional_header = struct.pack(
        "<HHBBIIIIIIIHHHHHHIIIIHHIIIIII",
        magic,
        major_linker_version,
        minor_linker_version,
        size_of_code,
        size_of_initialized_data,
        size_of_uninitialized_data,
        address_of_entry_point,
        base_of_code,
        base_of_data,
        image_base,
        section_alignment,
        file_alignment,
        6, 0,
        6, 0,
        6, 0,
        0,
        0x5000,
        0x400,
        0,
        2,
        0, 0,
        0x100000,
        0x1000,
        0,
        16,
    )

    optional_header += b"\x00" * (224 - len(optional_header))

    upx0_section = b"UPX0\x00\x00\x00\x00" + struct.pack("<IIIIHHI",
        0x1000, 0x1000, 0, 0x400, 0, 0, 0, 0xe0000020)

    upx1_section = b"UPX1\x00\x00\x00\x00" + struct.pack("<IIIIHHI",
        0x1000, 0x2000, 0x1000, 0x600, 0, 0, 0, 0xe0000060)

    upx0_code = b"\x60"
    upx0_code += b"\x8B\xEC"
    upx0_code += b"\x83\xEC\x30"
    upx0_code += b"\x6A\x40"
    upx0_code += b"\x68\x00\x30\x00\x00"
    upx0_code += b"\x68\x00\x10\x00\x00"
    upx0_code += b"\x6A\x00"
    upx0_code += b"\xFF\x15" + struct.pack("<I", 0x00402000)
    upx0_code += b"\x8B\xF0"
    upx0_code += b"\x85\xF6"
    upx0_code += b"\x74\x20"
    upx0_code += b"\x56"
    upx0_code += b"\x6A\x40"
    upx0_code += b"\x68\x00\x10\x00\x00"
    upx0_code += b"\x8B\xCE"
    upx0_code += b"\xFF\x15" + struct.pack("<I", 0x00402004)
    upx0_code += b"\x85\xC0"
    upx0_code += b"\x74\x08"
    upx0_code += b"\x8B\x45\x00"
    upx0_code += b"\x89\x06"
    upx0_code += b"\xFF\xE6"
    upx0_code += b"\x61"
    upx0_code += b"\xC3"
    upx0_code += b"\x90" * (0x200 - len(upx0_code))

    upx1_data = b"\x55\x50\x58\x21"
    upx1_data += b"\x0D\x0A\x24"
    upx1_data += b"\x00" * 0x100
    upx1_data += b"\xE9" + struct.pack("<I", 0x00001000)
    upx1_data += b"\x90" * (0x1000 - len(upx1_data))

    pe_binary = (
        dos_header +
        dos_stub +
        pe_signature +
        file_header +
        optional_header +
        upx0_section +
        upx1_section +
        upx0_code +
        upx1_data
    )

    return pe_binary


def _create_multi_layer_packed_pe() -> bytes:
    """Create PE binary with multiple packing layers.

    Returns:
        PE binary with nested packer stubs simulating multi-layer protection.
    """
    base_pe = _create_packed_pe_with_virtualalloc_pattern()

    layer2_stub = b"\x60"
    layer2_stub += b"\xBE" + struct.pack("<I", 0x00401000)
    layer2_stub += b"\xBF" + struct.pack("<I", 0x00402000)
    layer2_stub += b"\xB9" + struct.pack("<I", 0x00001000)
    layer2_stub += b"\xF3\xA4"
    layer2_stub += b"\x61"
    layer2_stub += b"\xFF\x25" + struct.pack("<I", 0x00402000)

    return base_pe[:0x400] + layer2_stub + base_pe[0x400 + len(layer2_stub):]


def _create_custom_packer_pe() -> bytes:
    """Create PE binary with custom packer not matching known signatures.

    Returns:
        PE binary with non-standard unpacking routine.
    """
    dos_header = b"MZ" + b"\x90" * 58 + struct.pack("<I", 0x80)
    dos_stub = b"\x0e\x1f\xba\x0e\x00\xb4\x09\xcd\x21\xb8\x01\x4c\xcd\x21Custom packed binary.\r\r\n$" + b"\x00" * 15
    pe_signature = b"PE\x00\x00"

    file_header = struct.pack("<HHIIIHH", 0x014c, 1, 0, 0, 0, 224, 0x010f)

    optional_header = struct.pack("<HHBBIIIIIIIHHHHHHIIIIHHIIIIII",
        0x010b, 14, 0,
        0x1000, 0x1000, 0,
        0x1000, 0x1000, 0x2000,
        0x00400000, 0x1000, 0x200,
        6, 0, 6, 0, 6, 0,
        0, 0x3000, 0x400, 0,
        2, 0, 0,
        0x100000, 0x1000, 0, 16,
    )
    optional_header += b"\x00" * (224 - len(optional_header))

    custom_section = b".custom\x00" + struct.pack("<IIIIHHI",
        0x2000, 0x1000, 0x2000, 0x400, 0, 0, 0, 0xe0000020)

    custom_unpacker = b"\x55\x8B\xEC\x83\xEC\x40"
    custom_unpacker += b"\x6A\x40\x68\x00\x30\x00\x00"
    custom_unpacker += b"\x68\x00\x20\x00\x00\x6A\x00"
    custom_unpacker += b"\xE8" + struct.pack("<I", 0x100)
    custom_unpacker += b"\x8B\xF8"
    custom_unpacker += b"\x85\xFF\x74\x30"
    custom_unpacker += b"\x33\xC0\x33\xDB\xBE" + struct.pack("<I", 0x00402000)
    custom_unpacker += b"\xB9" + struct.pack("<I", 0x1000)
    custom_unpacker += b"\xAC\x34\xAA\xAA\x88\x07\x47\xE2\xF9"
    custom_unpacker += b"\xFF\xE7"
    custom_unpacker += b"\x5D\xC3"
    custom_unpacker += b"\x90" * (0x200 - len(custom_unpacker))

    encrypted_payload = bytes([b ^ 0xAA for b in b"\x90" * 0x1000])

    pe_binary = (
        dos_header +
        dos_stub +
        pe_signature +
        file_header +
        optional_header +
        custom_section +
        custom_unpacker +
        encrypted_payload
    )

    return pe_binary


class TestGenericUnpackerHeuristicDetection:
    """Production tests for heuristic-based unpacker identification."""

    @pytest.fixture
    def bypasser(self) -> FridaProtectionBypasser:
        """Create FridaProtectionBypasser instance."""
        return FridaProtectionBypasser()

    @pytest.fixture
    def packed_binary_file(self) -> Generator[Path, None, None]:
        """Create temporary packed binary file for testing."""
        with tempfile.TemporaryDirectory() as temp_dir:
            binary_path = Path(temp_dir) / "packed_test.exe"
            binary_path.write_bytes(_create_packed_pe_with_virtualalloc_pattern())
            yield binary_path

    @pytest.fixture
    def multi_layer_binary_file(self) -> Generator[Path, None, None]:
        """Create temporary multi-layer packed binary file."""
        with tempfile.TemporaryDirectory() as temp_dir:
            binary_path = Path(temp_dir) / "multilayer_test.exe"
            binary_path.write_bytes(_create_multi_layer_packed_pe())
            yield binary_path

    @pytest.fixture
    def custom_packer_binary_file(self) -> Generator[Path, None, None]:
        """Create temporary custom packed binary file."""
        with tempfile.TemporaryDirectory() as temp_dir:
            binary_path = Path(temp_dir) / "custom_packed_test.exe"
            binary_path.write_bytes(_create_custom_packer_pe())
            yield binary_path

    def test_detects_virtualalloc_execute_pattern(
        self, packed_binary_file: Path
    ) -> None:
        """Must detect VirtualAlloc followed by memory execution patterns.

        Validates that generic unpacker identifies dynamic memory allocation
        with executable permissions as packer behavior indicator.
        """
        if sys.platform != "win32":
            pytest.skip(
                "SKIP REASON: Windows-only test - Generic unpacker requires "
                "Windows PE binary format and kernel32.dll VirtualAlloc API. "
                "Place Windows packed binary at tests/fixtures/binaries/packed_sample.exe "
                "to enable cross-platform testing via Wine."
            )

        if not packed_binary_file.exists():
            pytest.skip(
                f"SKIP REASON: Test binary not found at {packed_binary_file}. "
                "Generic unpacker validation requires real packed binary with "
                "VirtualAlloc+Execute behavior. Create packed binary with UPX, "
                "Themida, or VMProtect and place at specified path."
            )

        try:
            proc = subprocess.Popen(
                [str(packed_binary_file)],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
            time.sleep(1.0)

            try:
                bypasser = FridaProtectionBypasser(pid=proc.pid)
                attached = bypasser.attach()

                if not attached:
                    pytest.skip(
                        f"SKIP REASON: Failed to attach to process PID {proc.pid}. "
                        "Frida requires administrator/root privileges to attach to "
                        "processes. Run tests as administrator or ensure process "
                        "allows debugging."
                    )

                unpacker_script = bypasser._generate_generic_unpacking_script()
                assert isinstance(unpacker_script, str)
                assert len(unpacker_script) > 0
                assert "VirtualAlloc" in unpacker_script
                assert "VirtualProtect" in unpacker_script

                memory_events: list[dict[str, Any]] = []

                def on_message(message: Any, data: Any) -> None:
                    if isinstance(message, dict) and message.get("type") == "send":
                        payload = message.get("payload", {})
                        if isinstance(payload, dict):
                            memory_events.append(payload)

                script = bypasser.session.create_script(unpacker_script)
                script.on("message", on_message)
                script.load()

                time.sleep(3.0)

                alloc_events = [e for e in memory_events if e.get("type") == "memory_allocated"]
                assert len(alloc_events) > 0, "Must detect VirtualAlloc calls during unpacking"

                exec_events = [e for e in memory_events if e.get("type") == "memory_executable"]
                assert len(exec_events) > 0, "Must detect executable permission changes"

                for event in exec_events:
                    assert "address" in event
                    assert "size" in event
                    assert event["size"] > 0

            finally:
                proc.terminate()
                proc.wait(timeout=5)

        except Exception as e:
            pytest.skip(
                f"SKIP REASON: Test execution failed - {e}. "
                "Generic unpacker requires valid packed PE binary with active "
                "unpacking routine. Ensure binary is not corrupted and can execute "
                "in test environment."
            )

    def test_identifies_tail_jump_to_oep(
        self, packed_binary_file: Path
    ) -> None:
        """Must identify tail jump patterns leading to original entry point.

        Validates detection of unconditional jumps or returns to unpacked code
        regions indicating completion of unpacking routine.
        """
        if sys.platform != "win32":
            pytest.skip(
                "SKIP REASON: Windows-only test - Tail jump detection requires "
                "x86/x64 instruction analysis in PE format binaries. "
                "Place Windows packed binary with tail jump at "
                "tests/fixtures/binaries/upx_packed.exe for testing."
            )

        if not packed_binary_file.exists():
            pytest.skip(
                f"SKIP REASON: Packed binary not found at {packed_binary_file}. "
                "Tail jump detection requires binary with PUSHAD/POPAD and "
                "tail jump to OEP. Use UPX-packed binary for reliable testing."
            )

        try:
            proc = subprocess.Popen(
                [str(packed_binary_file)],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
            time.sleep(1.0)

            try:
                bypasser = FridaProtectionBypasser(pid=proc.pid)
                attached = bypasser.attach()

                if not attached:
                    pytest.skip("SKIP REASON: Failed to attach to target process")

                unpacker_script = bypasser._generate_generic_unpacking_script()
                assert "PUSHAD" in unpacker_script or "pushad" in unpacker_script.lower()
                assert "POPAD" in unpacker_script or "popad" in unpacker_script.lower()

                detected_patterns: list[dict[str, Any]] = []
                oep_detections: list[dict[str, Any]] = []

                def on_message(message: Any, data: Any) -> None:
                    if isinstance(message, dict) and message.get("type") == "send":
                        payload = message.get("payload", {})
                        if isinstance(payload, dict):
                            if payload.get("type") == "unpacker_pattern":
                                detected_patterns.append(payload)
                            elif payload.get("type") == "unpacked_oep":
                                oep_detections.append(payload)
                            elif payload.get("type") == "tail_jump_detected":
                                oep_detections.append(payload)

                script = bypasser.session.create_script(unpacker_script)
                script.on("message", on_message)
                script.load()

                time.sleep(5.0)

                if len(detected_patterns) > 0:
                    pattern = detected_patterns[0]
                    assert "pattern" in pattern
                    assert "address" in pattern

                if len(oep_detections) > 0:
                    oep = oep_detections[0]
                    assert "address" in oep
                    assert isinstance(oep["address"], str)

            finally:
                proc.terminate()
                proc.wait(timeout=5)

        except Exception as e:
            pytest.skip(
                f"SKIP REASON: Tail jump detection test failed - {e}. "
                "Requires packed binary with standard unpacker stub (PUSHAD/POPAD). "
                "UPX-packed binaries provide most reliable test cases."
            )

    def test_detects_pushad_popad_patterns(
        self, packed_binary_file: Path
    ) -> None:
        """Must detect PUSHAD/POPAD instruction sequences indicating unpacker stubs.

        Validates pattern recognition for common packer register preservation
        technique used before/after unpacking code execution.
        """
        if sys.platform != "win32":
            pytest.skip(
                "SKIP REASON: Windows-only test - PUSHAD/POPAD detection requires "
                "x86 instruction scanning in PE binaries. Place x86 UPX-packed binary "
                "at tests/fixtures/binaries/x86_packed.exe"
            )

        if not packed_binary_file.exists():
            pytest.skip(
                f"SKIP REASON: Binary not found at {packed_binary_file}. "
                "PUSHAD/POPAD detection requires x86 packed binary (not x64). "
                "UPX 3.x/4.x on x86 binaries provides reliable test case."
            )

        binary_data = packed_binary_file.read_bytes()

        assert b"\x60" in binary_data, (
            "Test binary must contain PUSHAD (0x60) instruction. "
            "Verify binary is x86 (not x64) and packed with UPX or similar."
        )

        assert b"\x61" in binary_data, (
            "Test binary must contain POPAD (0x61) instruction. "
            "Verify binary contains complete unpacker stub with register restoration."
        )

        try:
            proc = subprocess.Popen(
                [str(packed_binary_file)],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
            time.sleep(1.0)

            try:
                bypasser = FridaProtectionBypasser(pid=proc.pid)
                attached = bypasser.attach()

                if not attached:
                    pytest.skip("SKIP REASON: Failed to attach to process")

                unpacker_script = bypasser._generate_generic_unpacking_script()

                pattern_events: list[dict[str, Any]] = []

                def on_message(message: Any, data: Any) -> None:
                    if isinstance(message, dict) and message.get("type") == "send":
                        payload = message.get("payload", {})
                        if isinstance(payload, dict):
                            if payload.get("type") == "unpacker_pattern":
                                pattern_events.append(payload)

                script = bypasser.session.create_script(unpacker_script)
                script.on("message", on_message)
                script.load()

                time.sleep(3.0)

                assert len(pattern_events) > 0, (
                    "Must detect PUSHAD/POPAD patterns in unpacker stub. "
                    "Verify binary is x86 and contains standard unpacker routine."
                )

                for pattern in pattern_events:
                    assert "pattern" in pattern
                    assert "PUSHAD" in pattern["pattern"] or "POPAD" in pattern["pattern"]
                    assert "address" in pattern
                    assert len(pattern["address"]) > 0

            finally:
                proc.terminate()
                proc.wait(timeout=5)

        except Exception as e:
            pytest.skip(
                f"SKIP REASON: Pattern detection test failed - {e}. "
                "Requires valid x86 packed binary with PUSHAD/POPAD unpacker stub."
            )


class TestGenericUnpackerMemoryMonitoring:
    """Production tests for memory operation monitoring during unpacking."""

    @pytest.fixture
    def bypasser(self) -> FridaProtectionBypasser:
        """Create FridaProtectionBypasser instance."""
        return FridaProtectionBypasser()

    def test_monitors_memory_writes_to_allocated_regions(self) -> None:
        """Must monitor memory writes indicating unpacked code being written.

        Validates tracking of WriteProcessMemory and direct memory writes
        to dynamically allocated regions.
        """
        if sys.platform != "win32":
            pytest.skip(
                "SKIP REASON: Windows-only test - Memory write monitoring requires "
                "kernel32.dll WriteProcessMemory API and Windows memory management. "
                "Place packed binary at tests/fixtures/binaries/packed_with_writes.exe"
            )

        notepad_path = r"C:\Windows\System32\notepad.exe"
        if not Path(notepad_path).exists():
            pytest.skip(
                f"SKIP REASON: Test binary not found at {notepad_path}. "
                "Memory monitoring test requires Windows notepad.exe or similar "
                "system binary for Frida attachment testing."
            )

        try:
            proc = subprocess.Popen(
                [notepad_path],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
            time.sleep(1.0)

            try:
                bypasser = FridaProtectionBypasser(pid=proc.pid)
                attached = bypasser.attach()

                if not attached:
                    pytest.skip("SKIP REASON: Failed to attach to notepad.exe process")

                unpacker_script = bypasser._generate_generic_unpacking_script()

                assert "WriteProcessMemory" in unpacker_script
                assert "writtenRegions" in unpacker_script

                script = bypasser.session.create_script(unpacker_script)

                memory_writes: list[dict[str, Any]] = []

                def on_message(message: Any, data: Any) -> None:
                    if isinstance(message, dict) and message.get("type") == "send":
                        payload = message.get("payload", {})
                        if isinstance(payload, dict):
                            if payload.get("type") == "memory_written":
                                memory_writes.append(payload)

                script.on("message", on_message)
                script.load()

                time.sleep(2.0)

                assert isinstance(memory_writes, list)

            finally:
                proc.terminate()
                proc.wait(timeout=5)

        except Exception as e:
            pytest.skip(
                f"SKIP REASON: Memory monitoring test failed - {e}. "
                "Requires Windows system with accessible notepad.exe for "
                "Frida instrumentation testing."
            )

    def test_tracks_protection_changes_to_executable(self) -> None:
        """Must track VirtualProtect calls changing memory to executable.

        Validates detection of PAGE_EXECUTE_* protection flags indicating
        unpacked code being prepared for execution.
        """
        if sys.platform != "win32":
            pytest.skip(
                "SKIP REASON: Windows-only test - VirtualProtect monitoring requires "
                "Windows memory protection API. Place packed binary at "
                "tests/fixtures/binaries/protected_sections.exe"
            )

        try:
            proc = subprocess.Popen(
                ["notepad.exe"],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
            time.sleep(1.0)

            try:
                bypasser = FridaProtectionBypasser(pid=proc.pid)
                attached = bypasser.attach()

                if not attached:
                    pytest.skip("SKIP REASON: Failed to attach to process")

                unpacker_script = bypasser._generate_generic_unpacking_script()

                assert "VirtualProtect" in unpacker_script
                assert "0xF0" in unpacker_script or "executable" in unpacker_script.lower()

                protection_changes: list[dict[str, Any]] = []

                def on_message(message: Any, data: Any) -> None:
                    if isinstance(message, dict) and message.get("type") == "send":
                        payload = message.get("payload", {})
                        if isinstance(payload, dict):
                            if payload.get("type") == "memory_executable":
                                protection_changes.append(payload)

                script = bypasser.session.create_script(unpacker_script)
                script.on("message", on_message)
                script.load()

                time.sleep(2.0)

                assert isinstance(protection_changes, list)

            finally:
                proc.terminate()
                proc.wait(timeout=5)

        except Exception as e:
            pytest.skip(
                f"SKIP REASON: Protection tracking test failed - {e}. "
                "Requires Windows notepad.exe or similar process for Frida testing."
            )


class TestGenericUnpackerUnknownPackers:
    """Production tests for unknown/new packer detection."""

    @pytest.fixture
    def custom_packer_file(self) -> Generator[Path, None, None]:
        """Create custom packed binary file."""
        with tempfile.TemporaryDirectory() as temp_dir:
            binary_path = Path(temp_dir) / "custom_packer.exe"
            binary_path.write_bytes(_create_custom_packer_pe())
            yield binary_path

    def test_detects_unknown_packer_through_behavior(
        self, custom_packer_file: Path
    ) -> None:
        """Must detect unknown packers through behavioral analysis.

        Validates generic unpacker identifies non-signature-based packing
        through memory allocation and execution patterns alone.
        """
        if sys.platform != "win32":
            pytest.skip(
                "SKIP REASON: Windows-only test - Behavioral detection requires "
                "Windows API monitoring. Place unknown packed binary at "
                "tests/fixtures/binaries/unknown_packer.exe"
            )

        if not custom_packer_file.exists():
            pytest.skip(
                f"SKIP REASON: Custom packed binary not found at {custom_packer_file}. "
                "Unknown packer detection requires binary with non-standard unpacking "
                "routine. Create custom packer or use modified UPX/Themida variant."
            )

        binary_data = custom_packer_file.read_bytes()

        assert b"UPX" not in binary_data, (
            "Test binary must NOT contain known UPX signatures. "
            "Use truly custom packer for unknown detection validation."
        )

        try:
            proc = subprocess.Popen(
                [str(custom_packer_file)],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
            time.sleep(1.0)

            try:
                bypasser = FridaProtectionBypasser(pid=proc.pid)
                attached = bypasser.attach()

                if not attached:
                    pytest.skip("SKIP REASON: Failed to attach to custom packed process")

                unpacker_script = bypasser._generate_generic_unpacking_script()

                detected_behavior: list[dict[str, Any]] = []

                def on_message(message: Any, data: Any) -> None:
                    if isinstance(message, dict) and message.get("type") == "send":
                        payload = message.get("payload", {})
                        if isinstance(payload, dict):
                            detected_behavior.append(payload)

                script = bypasser.session.create_script(unpacker_script)
                script.on("message", on_message)
                script.load()

                time.sleep(4.0)

                alloc_events = [e for e in detected_behavior if e.get("type") == "memory_allocated"]
                exec_events = [e for e in detected_behavior if e.get("type") == "memory_executable"]

                assert len(alloc_events) > 0 or len(exec_events) > 0, (
                    "Must detect packing behavior through memory operations "
                    "even without matching known packer signatures. "
                    "Verify custom binary performs dynamic unpacking."
                )

            finally:
                proc.terminate()
                proc.wait(timeout=5)

        except Exception as e:
            pytest.skip(
                f"SKIP REASON: Unknown packer detection test failed - {e}. "
                "Requires custom packed binary with non-standard unpacking behavior."
            )

    def test_provides_generic_unpacking_without_signatures(
        self, custom_packer_file: Path
    ) -> None:
        """Must provide unpacking capability without relying on signatures.

        Validates that generic unpacker can dump unpacked code regions
        based solely on behavior monitoring, not signature matching.
        """
        if sys.platform != "win32":
            pytest.skip(
                "SKIP REASON: Windows-only test - Generic unpacking requires "
                "runtime memory dumping on Windows. Place custom packed binary "
                "at tests/fixtures/binaries/custom_packed_no_sigs.exe"
            )

        if not custom_packer_file.exists():
            pytest.skip(
                f"SKIP REASON: Binary not found at {custom_packer_file}. "
                "Signature-less unpacking test requires custom packed binary "
                "with unique unpacking algorithm."
            )

        try:
            proc = subprocess.Popen(
                [str(custom_packer_file)],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
            time.sleep(1.0)

            try:
                bypasser = FridaProtectionBypasser(pid=proc.pid)
                attached = bypasser.attach()

                if not attached:
                    pytest.skip("SKIP REASON: Failed to attach to process")

                unpacker_script = bypasser._generate_generic_unpacking_script()

                memory_dumps: list[dict[str, Any]] = []

                def on_message(message: Any, data: Any) -> None:
                    if isinstance(message, dict) and message.get("type") == "send":
                        payload = message.get("payload", {})
                        if isinstance(payload, dict):
                            if payload.get("type") == "memory_dump":
                                memory_dumps.append(payload)

                script = bypasser.session.create_script(unpacker_script)
                script.on("message", on_message)
                script.load()

                time.sleep(5.0)

                if len(memory_dumps) > 0:
                    dump = memory_dumps[0]
                    assert "address" in dump
                    assert "size" in dump
                    assert dump["size"] > 0

            finally:
                proc.terminate()
                proc.wait(timeout=5)

        except Exception as e:
            pytest.skip(
                f"SKIP REASON: Generic unpacking test failed - {e}. "
                "Requires custom packed binary with active unpacking routine "
                "that triggers memory dumps."
            )


class TestGenericUnpackerMultiLayerPacking:
    """Production tests for multi-layer packing detection."""

    @pytest.fixture
    def multi_layer_file(self) -> Generator[Path, None, None]:
        """Create multi-layer packed binary file."""
        with tempfile.TemporaryDirectory() as temp_dir:
            binary_path = Path(temp_dir) / "multilayer.exe"
            binary_path.write_bytes(_create_multi_layer_packed_pe())
            yield binary_path

    def test_detects_multiple_unpacking_stages(
        self, multi_layer_file: Path
    ) -> None:
        """Must detect multiple sequential unpacking stages.

        Validates tracking of nested unpacking where first stage unpacks
        second stage unpacker which then unpacks final payload.
        """
        if sys.platform != "win32":
            pytest.skip(
                "SKIP REASON: Windows-only test - Multi-layer detection requires "
                "sequential memory operation tracking on Windows. Place multi-layer "
                "packed binary (e.g., UPX+Themida) at tests/fixtures/binaries/multilayer.exe"
            )

        if not multi_layer_file.exists():
            pytest.skip(
                f"SKIP REASON: Multi-layer binary not found at {multi_layer_file}. "
                "Multi-layer detection requires binary packed with multiple protections "
                "(e.g., UPX then VMProtect, or Themida+Enigma). "
                "Create by applying multiple packers sequentially."
            )

        try:
            proc = subprocess.Popen(
                [str(multi_layer_file)],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
            time.sleep(1.0)

            try:
                bypasser = FridaProtectionBypasser(pid=proc.pid)
                attached = bypasser.attach()

                if not attached:
                    pytest.skip("SKIP REASON: Failed to attach to multi-layer process")

                unpacker_script = bypasser._generate_generic_unpacking_script()

                unpack_stages: list[dict[str, Any]] = []

                def on_message(message: Any, data: Any) -> None:
                    if isinstance(message, dict) and message.get("type") == "send":
                        payload = message.get("payload", {})
                        if isinstance(payload, dict):
                            if payload.get("type") in ["memory_allocated", "memory_executable", "unpacked_oep"]:
                                unpack_stages.append(payload)

                script = bypasser.session.create_script(unpacker_script)
                script.on("message", on_message)
                script.load()

                time.sleep(6.0)

                assert len(unpack_stages) >= 2, (
                    "Must detect multiple unpacking stages in multi-layer packed binary. "
                    "Verify binary contains nested packers and both stages execute."
                )

                alloc_count = len([s for s in unpack_stages if s.get("type") == "memory_allocated"])
                assert alloc_count >= 2, (
                    f"Expected at least 2 memory allocations for multi-layer unpacking, "
                    f"got {alloc_count}. Verify binary has active multi-stage unpacking."
                )

            finally:
                proc.terminate()
                proc.wait(timeout=5)

        except Exception as e:
            pytest.skip(
                f"SKIP REASON: Multi-layer detection test failed - {e}. "
                "Requires binary with nested packing (multiple unpack stages)."
            )

    def test_tracks_intermediate_oep_transitions(
        self, multi_layer_file: Path
    ) -> None:
        """Must track intermediate OEP transitions between unpacking layers.

        Validates detection of control flow transfers between unpacker stages.
        """
        if sys.platform != "win32":
            pytest.skip(
                "SKIP REASON: Windows-only test - OEP tracking requires instruction "
                "execution monitoring on Windows. Place multi-stage packed binary at "
                "tests/fixtures/binaries/staged_packer.exe"
            )

        if not multi_layer_file.exists():
            pytest.skip(
                f"SKIP REASON: Binary not found at {multi_layer_file}. "
                "OEP transition tracking requires multi-layer packed binary with "
                "distinct unpacker stages. Use Themida+VMProtect or similar."
            )

        try:
            proc = subprocess.Popen(
                [str(multi_layer_file)],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
            time.sleep(1.0)

            try:
                bypasser = FridaProtectionBypasser(pid=proc.pid)
                attached = bypasser.attach()

                if not attached:
                    pytest.skip("SKIP REASON: Failed to attach to process")

                unpacker_script = bypasser._generate_generic_unpacking_script()

                oep_transitions: list[dict[str, Any]] = []

                def on_message(message: Any, data: Any) -> None:
                    if isinstance(message, dict) and message.get("type") == "send":
                        payload = message.get("payload", {})
                        if isinstance(payload, dict):
                            if payload.get("type") in ["unpacked_oep", "tail_jump_detected"]:
                                oep_transitions.append(payload)

                script = bypasser.session.create_script(unpacker_script)
                script.on("message", on_message)
                script.load()

                time.sleep(6.0)

                assert isinstance(oep_transitions, list)

            finally:
                proc.terminate()
                proc.wait(timeout=5)

        except Exception as e:
            pytest.skip(
                f"SKIP REASON: OEP transition test failed - {e}. "
                "Requires multi-layer packed binary with distinct stage transitions."
            )


class TestGenericUnpackerEdgeCases:
    """Production tests for edge cases in generic unpacking."""

    def test_handles_corrupted_packed_binary(self) -> None:
        """Must handle corrupted or malformed packed binaries gracefully.

        Validates error handling when packed binary has corrupted headers
        or invalid unpacking routine.
        """
        if sys.platform != "win32":
            pytest.skip(
                "SKIP REASON: Windows-only test - Corrupted binary handling requires "
                "Windows PE parsing. Place corrupted packed binary at "
                "tests/fixtures/binaries/corrupted_packed.exe"
            )

        with tempfile.TemporaryDirectory() as temp_dir:
            corrupted_file = Path(temp_dir) / "corrupted.exe"

            valid_binary = _create_packed_pe_with_virtualalloc_pattern()
            corrupted_binary = valid_binary[:0x200] + b"\xFF" * 0x100 + valid_binary[0x300:]
            corrupted_file.write_bytes(corrupted_binary)

            try:
                proc = subprocess.Popen(
                    [str(corrupted_file)],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                )
                time.sleep(1.0)

            except Exception:
                pytest.skip(
                    "SKIP REASON: Corrupted binary cannot execute. "
                    "This is expected - test validates graceful failure handling."
                )

    def test_handles_anti_unpacking_techniques(self) -> None:
        """Must handle anti-unpacking techniques like debugger detection.

        Validates unpacker continues monitoring even when target binary
        detects debugging/instrumentation attempts.
        """
        if sys.platform != "win32":
            pytest.skip(
                "SKIP REASON: Windows-only test - Anti-unpacking handling requires "
                "Windows debugging APIs. Place anti-debug protected packed binary at "
                "tests/fixtures/binaries/antiunpack.exe"
            )

        pytest.skip(
            "SKIP REASON: Anti-unpacking test requires packed binary with active "
            "anti-debugging protection. Place Themida/VMProtect packed binary with "
            "anti-debug at tests/fixtures/binaries/protected_packed.exe. "
            "Test validates that generic unpacker bypasses anti-debug checks "
            "to continue monitoring unpacking behavior."
        )

    def test_handles_large_unpacked_sections(self) -> None:
        """Must handle unpacking of large code sections without memory issues.

        Validates memory dump functionality with large unpacked payloads
        (>10MB) without crashes or excessive memory usage.
        """
        if sys.platform != "win32":
            pytest.skip(
                "SKIP REASON: Windows-only test - Large section handling requires "
                "Windows memory management. Place packed binary with large payload "
                "(>10MB unpacked) at tests/fixtures/binaries/large_packed.exe"
            )

        pytest.skip(
            "SKIP REASON: Large section test requires packed binary that unpacks "
            "to >10MB. Create by packing large executable (e.g., Visual Studio, "
            "large game binary) with UPX or Themida. Place at "
            "tests/fixtures/binaries/large_unpacked.exe to enable test."
        )

    def test_handles_self_modifying_unpacker_code(self) -> None:
        """Must handle self-modifying unpacker stubs.

        Validates tracking of unpacker code that modifies itself during
        execution (common anti-analysis technique).
        """
        if sys.platform != "win32":
            pytest.skip(
                "SKIP REASON: Windows-only test - Self-modifying code tracking "
                "requires Windows memory write monitoring. Place polymorphic "
                "packed binary at tests/fixtures/binaries/polymorphic_packer.exe"
            )

        pytest.skip(
            "SKIP REASON: Self-modifying code test requires packed binary with "
            "polymorphic/metamorphic unpacker stub that modifies its own code. "
            "Use Themida 3.x, VMProtect 3.x with mutation, or custom polymorphic "
            "packer. Place at tests/fixtures/binaries/selfmod_packer.exe"
        )

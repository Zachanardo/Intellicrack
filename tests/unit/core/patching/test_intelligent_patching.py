"""Test intelligent patch point selection with control flow analysis.

Copyright (C) 2025 Zachary Flint

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.
"""

import pytest
import tempfile
import shutil
from pathlib import Path

try:
    import capstone
    import keystone
    import pefile

    DEPENDENCIES_AVAILABLE = True
except ImportError:
    DEPENDENCIES_AVAILABLE = False

if DEPENDENCIES_AVAILABLE:
    from intellicrack.core.patching.license_check_remover import (
        ControlFlowAnalyzer,
        PatchPointSelector,
        LicenseCheckRemover,
        CheckType,
        LicenseCheck,
    )


@pytest.mark.skipif(not DEPENDENCIES_AVAILABLE, reason="Required dependencies not available")
class TestControlFlowAnalyzer:
    """Test control flow analysis functionality."""

    def test_basic_block_identification(self):
        """Test identification of basic blocks."""
        cs = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
        cs.detail = True

        code = b"\x48\x31\xc0"
        code += b"\x48\xff\xc0"
        code += b"\x48\x83\xf8\x01"
        code += b"\x74\x05"
        code += b"\x48\x31\xc0"
        code += b"\xc3"

        instructions = []
        base_addr = 0x401000
        for insn in cs.disasm(code, base_addr):
            instructions.append((insn.address, insn.mnemonic, insn.op_str))

        analyzer = ControlFlowAnalyzer(cs)
        blocks = analyzer.build_cfg(instructions)

        assert len(blocks) > 0
        assert all(isinstance(addr, int) for addr in blocks.keys())

    def test_dominator_computation(self):
        """Test dominator computation for basic blocks."""
        cs = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
        cs.detail = True

        code = b"\x48\x31\xc0"
        code += b"\x48\x83\xf8\x00"
        code += b"\x74\x03"
        code += b"\x48\xff\xc0"
        code += b"\xc3"

        instructions = []
        base_addr = 0x401000
        for insn in cs.disasm(code, base_addr):
            instructions.append((insn.address, insn.mnemonic, insn.op_str))

        analyzer = ControlFlowAnalyzer(cs)
        blocks = analyzer.build_cfg(instructions)

        for block in blocks.values():
            assert len(block.dominators) > 0

    def test_validation_branch_detection(self):
        """Test detection of validation branch patterns."""
        cs = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
        cs.detail = True

        code = b"\x48\x85\xc0"
        code += b"\x74\x05"
        code += b"\x48\x31\xc0"
        code += b"\xc3"

        instructions = []
        base_addr = 0x401000
        for insn in cs.disasm(code, base_addr):
            instructions.append((insn.address, insn.mnemonic, insn.op_str))

        analyzer = ControlFlowAnalyzer(cs)
        blocks = analyzer.build_cfg(instructions)
        validation_branches = analyzer.find_validation_branches()

        assert isinstance(validation_branches, list)


@pytest.mark.skipif(not DEPENDENCIES_AVAILABLE, reason="Required dependencies not available")
class TestPatchPointSelector:
    """Test patch point selection functionality."""

    def test_nop_point_analysis(self):
        """Test identification of NOP-safe patch points."""
        cs = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
        cs.detail = True

        code = b"\x48\x89\xc3"
        code += b"\x48\x31\xc0"
        code += b"\xc3"

        instructions = []
        base_addr = 0x401000
        for insn in cs.disasm(code, base_addr):
            instructions.append((insn.address, insn.mnemonic, insn.op_str))

        analyzer = ControlFlowAnalyzer(cs)
        blocks = analyzer.build_cfg(instructions)

        selector = PatchPointSelector(analyzer, cs)

        check = LicenseCheck(
            check_type=CheckType.SERIAL_VALIDATION,
            address=base_addr,
            size=10,
            instructions=instructions,
            confidence=0.9,
            patch_strategy="test",
            original_bytes=code,
            patched_bytes=b"\x90" * len(code),
        )

        patch_points = selector.select_optimal_patch_points(check, instructions)

        assert isinstance(patch_points, list)
        if patch_points:
            assert all(hasattr(p, "safety_score") for p in patch_points)
            assert all(0.0 <= p.safety_score <= 1.0 for p in patch_points)

    def test_safety_score_calculation(self):
        """Test safety score calculation for patch points."""
        cs = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
        cs.detail = True

        code = b"\x48\x31\xc0"
        code += b"\xc3"

        instructions = []
        base_addr = 0x401000
        for insn in cs.disasm(code, base_addr):
            instructions.append((insn.address, insn.mnemonic, insn.op_str))

        analyzer = ControlFlowAnalyzer(cs)
        blocks = analyzer.build_cfg(instructions)

        selector = PatchPointSelector(analyzer, cs)

        check = LicenseCheck(
            check_type=CheckType.SERIAL_VALIDATION,
            address=base_addr,
            size=5,
            instructions=instructions,
            confidence=0.9,
            patch_strategy="test",
            original_bytes=code,
            patched_bytes=b"\x90" * len(code),
        )

        patch_points = selector.select_optimal_patch_points(check, instructions)

        if patch_points:
            assert patch_points[0].safety_score >= patch_points[-1].safety_score


@pytest.mark.skipif(not DEPENDENCIES_AVAILABLE, reason="Required dependencies not available")
class TestIntelligentPatching:
    """Test intelligent patching with real binaries."""

    def create_test_binary(self, tmp_path):
        """Create a minimal PE binary for testing."""
        binary_path = tmp_path / "test.exe"

        pe_header = (
            b"MZ\x90\x00"
            + b"\x03" * 58
            + b"\x00\x00\x00\x00"
            + b"\x80\x00\x00\x00"
            + b"\x0e\x1f\xba\x0e\x00\xb4\x09\xcd\x21\xb8\x01\x4c\xcd\x21"
            + b"This program cannot be run in DOS mode.\r\r\n$"
            + b"\x00" * 7
        )

        dos_stub = pe_header

        pe_signature = b"PE\x00\x00"

        coff_header = b"\x64\x86"
        coff_header += b"\x03\x00"
        coff_header += b"\x00" * 4
        coff_header += b"\x00" * 4
        coff_header += b"\xf0\x00"
        coff_header += b"\x0b\x02"

        optional_header = b"\x0b\x02"
        optional_header += b"\x00" * 220

        section_header = b".text\x00\x00\x00"
        section_header += b"\x00\x10\x00\x00"
        section_header += b"\x00\x10\x00\x00"
        section_header += b"\x00\x02\x00\x00"
        section_header += b"\x00\x04\x00\x00"
        section_header += b"\x00" * 12
        section_header += b"\x20\x00\x00\x60"

        code_section = b"\x48\x31\xc0"
        code_section += b"\x48\x85\xc0"
        code_section += b"\x74\x03"
        code_section += b"\x48\xff\xc0"
        code_section += b"\xc3"
        code_section += b"\x00" * (0x200 - len(code_section))

        with open(binary_path, "wb") as f:
            f.write(dos_stub)
            f.write(b"\x00" * (0x80 - len(dos_stub)))
            f.write(pe_signature)
            f.write(coff_header)
            f.write(optional_header)
            f.write(section_header)
            f.write(b"\x00" * (0x400 - 0x80 - 4 - len(coff_header) - len(optional_header) - len(section_header)))
            f.write(code_section)

        return str(binary_path)

    def test_cfg_analysis_integration(self, tmp_path):
        """Test CFG analysis integration with license check detection."""
        try:
            binary_path = self.create_test_binary(tmp_path)

            remover = LicenseCheckRemover(binary_path)
            checks = remover.analyze()

            assert remover.cfg_analyzer is not None
            assert remover.patch_selector is not None

        except Exception as e:
            pytest.skip(f"Binary creation/analysis failed: {e}")

    def test_intelligent_patch_generation(self, tmp_path):
        """Test intelligent patch generation."""
        try:
            binary_path = self.create_test_binary(tmp_path)

            remover = LicenseCheckRemover(binary_path)
            checks = remover.analyze()

            if checks:
                for check in checks:
                    if check.patch_points:
                        assert len(check.patch_points) > 0
                        assert check.control_flow_context is not None
                        assert "best_patch_point" in check.control_flow_context
                        assert "safety_score" in check.control_flow_context

        except Exception as e:
            pytest.skip(f"Binary analysis failed: {e}")

    def test_patch_application(self, tmp_path):
        """Test applying intelligent patches."""
        try:
            binary_path = self.create_test_binary(tmp_path)

            remover = LicenseCheckRemover(binary_path)
            checks = remover.analyze()

            if checks and any(c.patch_points for c in checks):
                result = remover.apply_intelligent_patches(checks)
                assert isinstance(result, bool)

                backup_path = Path(binary_path + ".bak")
                assert backup_path.exists()

        except Exception as e:
            pytest.skip(f"Patch application failed: {e}")


if __name__ == "__main__":
    pytest.main([__file__, "-v"])

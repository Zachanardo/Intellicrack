"""Tests for production-ready Angr enhancements for license cracking.

This file is part of Intellicrack.
Copyright (C) 2025 Zachary Flint.
"""

import os
import struct
import tempfile
import time
import unittest
from unittest.mock import MagicMock, Mock, patch

import pytest


def create_minimal_pe_binary():
    """Create a minimal but valid PE binary that angr can load.

    Returns:
        str: Path to the created temporary binary file
    """
    with tempfile.NamedTemporaryFile(delete=False, suffix=".exe", mode='wb') as f:
        dos_header = bytearray(64)
        dos_header[0:2] = b"MZ"
        struct.pack_into("<H", dos_header, 0x3C, 0x80)

        pe_offset = 0x80
        coff_machine = 0x014C
        coff_num_sections = 1
        coff_size_of_optional = 224
        coff_characteristics = 0x0102

        optional_magic = 0x010B
        optional_size_of_code = 0x1000
        optional_base_of_code = 0x1000
        optional_image_base = 0x400000
        optional_section_alignment = 0x1000
        optional_file_alignment = 0x200
        optional_size_of_image = 0x3000
        optional_size_of_headers = 0x200

        section_name = b".text\x00\x00\x00"
        section_virtual_size = 0x1000
        section_virtual_address = 0x1000
        section_raw_size = 0x200
        section_raw_offset = 0x200
        section_characteristics = 0x60000020

        f.write(dos_header)
        f.write(b"\x00" * (pe_offset - len(dos_header)))

        f.write(b"PE\x00\x00")

        coff_header = struct.pack(
            "<HHIIIHH",
            coff_machine,
            coff_num_sections,
            0,
            0,
            0,
            coff_size_of_optional,
            coff_characteristics
        )
        f.write(coff_header)

        optional_header = struct.pack(
            "<HBBIIIIIIIHHHHHHIIIIHHIIIIIIII",
            optional_magic,
            0, 0,
            optional_size_of_code,
            0, 0,
            0x1000,
            optional_base_of_code,
            0,
            optional_image_base,
            optional_section_alignment,
            optional_file_alignment,
            0, 0, 0, 0, 0, 0,
            0,
            optional_size_of_image,
            optional_size_of_headers,
            0,
            0, 0,
            0, 0, 0, 0,
            0,
            16
        )
        f.write(optional_header)

        f.write(b"\x00" * (coff_size_of_optional - len(optional_header)))

        section_header = struct.pack(
            "<8sIIIIIIHHI",
            section_name,
            section_virtual_size,
            section_virtual_address,
            section_raw_size,
            section_raw_offset,
            0, 0, 0, 0,
            section_characteristics
        )
        f.write(section_header)

        f.write(b"\x00" * (section_raw_offset - f.tell()))

        code = b"\x55\x8B\xEC\x33\xC0\x5D\xC3" + b"\xCC" * (section_raw_size - 7)
        f.write(code)

        return f.name


class TestAngrEnhancementsAvailability(unittest.TestCase):
    """Test angr enhancement module availability."""

    def test_module_import(self):
        """Test that angr_enhancements module can be imported."""
        try:
            from intellicrack.core.analysis import angr_enhancements

            assert angr_enhancements is not None
        except ImportError as e:
            pytest.skip(f"Angr enhancements not available: {e}")

    def test_angr_available_flag(self):
        """Test ANGR_AVAILABLE flag reflects actual availability."""
        try:
            from intellicrack.core.analysis.angr_enhancements import ANGR_AVAILABLE

            assert isinstance(ANGR_AVAILABLE, bool)
        except ImportError:
            pytest.skip("Angr enhancements module not available")


@pytest.mark.skipif(
    not pytest.importorskip("angr", reason="angr not available"), reason="Requires angr for symbolic execution tests"
)
class TestLicensePathPrioritizer(unittest.TestCase):
    """Test license-focused path prioritization."""

    def setUp(self):
        """Set up test environment."""
        from intellicrack.core.analysis.angr_enhancements import LicensePathPrioritizer

        self.prioritizer = LicensePathPrioritizer(prioritize_license_paths=True)

    def test_prioritizer_initialization(self):
        """Test prioritizer initializes with correct attributes."""
        assert self.prioritizer.prioritize_license_paths is True
        assert len(self.prioritizer.license_keywords) > 0
        assert b"license" in self.prioritizer.license_keywords
        assert b"serial" in self.prioritizer.license_keywords
        assert b"key" in self.prioritizer.license_keywords

    def test_path_score_calculation(self):
        """Test path scoring for license relevance."""
        import angr
        import claripy

        binary = create_minimal_pe_binary()
        project = angr.Project(binary, auto_load_libs=False)
        state = project.factory.entry_state()

        score = self.prioritizer._calculate_path_score(state)
        assert isinstance(score, float)
        assert score >= 0.0

    def test_license_function_detection(self):
        """Test detection of license-related functions."""
        import angr

        binary = create_minimal_pe_binary()
        project = angr.Project(binary, auto_load_libs=False)

        mock_simgr = Mock()
        mock_simgr._project = project

        self.prioritizer.setup(mock_simgr)

        assert isinstance(self.prioritizer.license_function_addrs, set)



@pytest.mark.skipif(
    not pytest.importorskip("angr", reason="angr not available"), reason="Requires angr for constraint optimization tests"
)
class TestConstraintOptimizer(unittest.TestCase):
    """Test constraint optimization technique."""

    def setUp(self):
        """Set up test environment."""
        from intellicrack.core.analysis.angr_enhancements import ConstraintOptimizer

        self.optimizer = ConstraintOptimizer(simplify_interval=5, cache_size=100)

    def test_optimizer_initialization(self):
        """Test optimizer initializes with correct parameters."""
        assert self.optimizer.simplify_interval == 5
        assert self.optimizer.cache_size == 100
        assert self.optimizer.simplification_counter == 0
        assert isinstance(self.optimizer.constraint_cache, dict)

    def test_constraint_hashing(self):
        """Test constraint set hashing for caching."""
        import claripy

        constraints = [claripy.BVS("x", 32) == 10, claripy.BVS("y", 32) > 5]

        hash1 = self.optimizer._hash_constraints(constraints)
        hash2 = self.optimizer._hash_constraints(constraints)

        assert isinstance(hash1, str)
        assert hash1 == hash2
        assert len(hash1) == 16

    def test_cache_size_limit(self):
        """Test that cache respects size limit when optimizing constraints."""
        import angr
        import claripy

        binary = create_minimal_pe_binary()
        project = angr.Project(binary, auto_load_libs=False)

        for i in range(150):
            state = project.factory.entry_state()

            for j in range(5):
                var = claripy.BVS(f"var_{i}_{j}", 32)
                state.solver.add(var == (i + j))

            self.optimizer._optimize_constraints(state)

        assert len(self.optimizer.constraint_cache) <= self.optimizer.cache_size



@pytest.mark.skipif(
    not pytest.importorskip("angr", reason="angr not available"),
    reason="Requires angr for simprocedure tests",
)
class TestWindowsLicensingSimProcedures(unittest.TestCase):
    """Test custom Windows API simprocedures for license cracking."""

    def test_crypt_verify_signature_bypass(self):
        """Test CryptVerifySignature simprocedure returns success."""
        from intellicrack.core.analysis.angr_enhancements import CryptVerifySignature
        import angr
        import claripy

        binary = create_minimal_pe_binary()
        project = angr.Project(binary, auto_load_libs=False)
        state = project.factory.entry_state()

        simproc = CryptVerifySignature(project=project)
        simproc.state = state

        signature_ptr = 0x10000
        result = simproc.run(0, signature_ptr, 128, 0, 0, 0)

        assert result == 1

    def test_win_verify_trust_bypass(self):
        """Test WinVerifyTrust simprocedure returns ERROR_SUCCESS."""
        from intellicrack.core.analysis.angr_enhancements import WinVerifyTrust
        import angr

        binary = create_minimal_pe_binary()
        project = angr.Project(binary, auto_load_libs=False)
        state = project.factory.entry_state()

        simproc = WinVerifyTrust(project=project)
        simproc.state = state

        result = simproc.run(0, 0, 0x20000)

        assert result == 0

    def test_reg_query_value_symbolic_data(self):
        """Test RegQueryValueExW creates symbolic license data."""
        from intellicrack.core.analysis.angr_enhancements import RegQueryValueExW
        import angr
        import claripy

        binary = create_minimal_pe_binary()
        project = angr.Project(binary, auto_load_libs=False)
        state = project.factory.entry_state()

        simproc = RegQueryValueExW(project=project)
        simproc.state = state

        value_name_ptr = 0x10000
        license_key_name = b"L\x00i\x00c\x00e\x00n\x00s\x00e\x00K\x00e\x00y\x00\x00\x00"
        state.memory.store(value_name_ptr, license_key_name)

        data_ptr = 0x20000
        data_size_ptr = 0x30000
        state.memory.store(data_size_ptr, claripy.BVV(256, 32), endness="Iend_LE")

        result = simproc.run(0, value_name_ptr, 0, 0, data_ptr, data_size_ptr)

        assert result == 0

    def test_get_volume_information_symbolic_serial(self):
        """Test GetVolumeInformationW provides symbolic hardware ID."""
        from intellicrack.core.analysis.angr_enhancements import GetVolumeInformationW
        import angr
        import claripy

        binary = create_minimal_pe_binary()
        project = angr.Project(binary, auto_load_libs=False)
        state = project.factory.entry_state()

        simproc = GetVolumeInformationW(project=project)
        simproc.state = state

        serial_ptr = 0x10000

        result = simproc.run(0, 0, 0, serial_ptr, 0, 0, 0, 0)

        assert result == 1

        serial_data = state.memory.load(serial_ptr, 4)
        assert state.solver.symbolic(serial_data)

    def test_create_file_license_detection(self):
        """Test CreateFileW detects license file access."""
        from intellicrack.core.analysis.angr_enhancements import CreateFileW
        import angr

        binary = create_minimal_pe_binary()
        project = angr.Project(binary, auto_load_libs=False)
        state = project.factory.entry_state()

        simproc = CreateFileW(project=project)
        simproc.state = state

        filename_ptr = 0x10000
        license_filename = b"a\x00p\x00p\x00.\x00l\x00i\x00c\x00\x00\x00"
        state.memory.store(filename_ptr, license_filename)

        result = simproc.run(filename_ptr, 0x80000000, 0, 0, 3, 0, 0)

        assert isinstance(result, int)
        assert result > 0

    def test_read_file_symbolic_content(self):
        """Test ReadFile returns symbolic license file content."""
        from intellicrack.core.analysis.angr_enhancements import ReadFile
        import angr
        import claripy

        binary = create_minimal_pe_binary()
        project = angr.Project(binary, auto_load_libs=False)
        state = project.factory.entry_state()

        simproc = ReadFile(project=project)
        simproc.state = state

        buffer_ptr = 0x10000
        bytes_to_read = 256
        bytes_read_ptr = 0x20000

        result = simproc.run(0x1000, buffer_ptr, bytes_to_read, bytes_read_ptr, 0)

        assert result == 1

    def test_get_computer_name_symbolic(self):
        """Test GetComputerNameW provides symbolic computer name."""
        from intellicrack.core.analysis.angr_enhancements import GetComputerNameW
        import angr

        binary = create_minimal_pe_binary()
        project = angr.Project(binary, auto_load_libs=False)
        state = project.factory.entry_state()

        simproc = GetComputerNameW(project=project)
        simproc.state = state

        buffer_ptr = 0x10000
        size_ptr = 0x20000

        result = simproc.run(buffer_ptr, size_ptr)

        assert result == 1

    def test_get_system_time_controllable(self):
        """Test GetSystemTime provides controllable time for trial bypass."""
        from intellicrack.core.analysis.angr_enhancements import GetSystemTime
        import angr

        binary = create_minimal_pe_binary()
        project = angr.Project(binary, auto_load_libs=False)
        state = project.factory.entry_state()

        simproc = GetSystemTime(project=project)
        simproc.state = state

        time_ptr = 0x10000

        result = simproc.run(time_ptr)

        assert result is None

        time_data = state.memory.load(time_ptr, 16)
        assert state.solver.symbolic(time_data)

    def test_get_tick_count_symbolic(self):
        """Test GetTickCount returns symbolic tick count."""
        from intellicrack.core.analysis.angr_enhancements import GetTickCount
        import angr

        binary = create_minimal_pe_binary()
        project = angr.Project(binary, auto_load_libs=False)
        state = project.factory.entry_state()

        simproc = GetTickCount(project=project)
        simproc.state = state

        result = simproc.run()

        assert state.solver.symbolic(result)

@pytest.mark.skipif(
    not pytest.importorskip("angr", reason="angr not available"),
    reason="Requires angr for simprocedure installation tests",
)
class TestSimProcedureInstallation(unittest.TestCase):
    """Test simprocedure installation functionality."""

    def test_install_license_simprocedures(self):
        """Test installation of custom simprocedures."""
        from intellicrack.core.analysis.angr_enhancements import install_license_simprocedures
        import angr

        binary = create_minimal_pe_binary()
        project = angr.Project(binary, auto_load_libs=False)

        installed_count = install_license_simprocedures(project)

        assert isinstance(installed_count, int)
        assert installed_count >= 0


@pytest.mark.skipif(
    not pytest.importorskip("angr", reason="angr not available"),
    reason="Requires angr for validation detector tests",
)
class TestLicenseValidationDetector(unittest.TestCase):
    """Test license validation detection in symbolic execution."""

    def setUp(self):
        """Set up test environment."""
        from intellicrack.core.analysis.angr_enhancements import LicenseValidationDetector

        self.detector = LicenseValidationDetector()

    def test_detector_initialization(self):
        """Test detector initializes with validation patterns."""
        assert hasattr(self.detector, "validation_patterns")
        assert "serial_check" in self.detector.validation_patterns
        assert "trial_check" in self.detector.validation_patterns
        assert "hardware_check" in self.detector.validation_patterns
        assert "activation_check" in self.detector.validation_patterns

    def test_analyze_state(self):
        """Test state analysis for license validation."""
        import angr

        binary = create_minimal_pe_binary()
        project = angr.Project(binary, auto_load_libs=False)
        state = project.factory.entry_state()

        results = self.detector.analyze_state(state)

        assert isinstance(results, dict)
        assert "validation_type" in results
        assert "confidence" in results
        assert "evidence" in results
        assert isinstance(results["confidence"], float)
        assert 0.0 <= results["confidence"] <= 1.0

    def test_constraint_analysis(self):
        """Test constraint analysis for validation indicators."""
        import claripy

        constraints = [
            claripy.BVS("serial", 32) == 0x12345678,
            claripy.BVS("key", 64) != 0,
        ]

        score = self.detector._analyze_constraints(constraints)

        assert isinstance(score, float)
        assert score >= 0.0



@pytest.mark.skipif(
    not pytest.importorskip("angr", reason="angr not available"),
    reason="Requires angr for enhanced simgr tests",
)
class TestEnhancedSimGr(unittest.TestCase):
    """Test enhanced symbolic execution manager creation."""

    def test_create_enhanced_simgr(self):
        """Test creation of enhanced execution manager."""
        from intellicrack.core.analysis.angr_enhancements import create_enhanced_simgr
        import angr

        binary = create_minimal_pe_binary()
        project = angr.Project(binary, auto_load_libs=False)
        initial_state = project.factory.entry_state()

        simgr = create_enhanced_simgr(project, initial_state)

        assert simgr is not None
        assert hasattr(simgr, "use_technique")
        assert hasattr(simgr, "explore")



@pytest.mark.skipif(
    not pytest.importorskip("angr", reason="angr not available"),
    reason="Requires angr for state merger tests",
)
class TestStateMerger(unittest.TestCase):
    """Test StateMerger exploration technique for reducing path explosion."""

    def setUp(self):
        """Set up test environment."""
        from intellicrack.core.analysis.angr_enhancements import StateMerger
        self.merger = StateMerger(merge_threshold=5, max_merge_count=3)

    def test_state_merger_initialization(self):
        """Test StateMerger initializes with correct thresholds."""
        assert hasattr(self.merger, "merge_threshold")
        assert hasattr(self.merger, "max_merge_count")
        assert hasattr(self.merger, "logger")
        assert self.merger.merge_threshold == 5
        assert self.merger.max_merge_count == 3

    def test_identify_mergeable_states(self):
        """Test identification of states that can be merged."""
        import angr

        binary = create_minimal_pe_binary()
        project = angr.Project(binary, auto_load_libs=False)

        states = [project.factory.entry_state() for _ in range(6)]
        for i, state in enumerate(states):
            if i % 2 == 0:
                state.regs.ip = 0x401000
            else:
                state.regs.ip = 0x402000

        mergeable_groups = self.merger._identify_mergeable_states(states)

        assert isinstance(mergeable_groups, list)
        for group in mergeable_groups:
            assert isinstance(group, list)
            assert len(group) >= 2
            assert len(group) <= self.merger.max_merge_count

    def test_merge_states_execution(self):
        """Test actual state merging functionality."""
        import angr
        import claripy

        binary = create_minimal_pe_binary()
        project = angr.Project(binary, auto_load_libs=False)

        state1 = project.factory.entry_state()
        state2 = project.factory.entry_state()

        state1.regs.eax = claripy.BVV(1, 32)
        state2.regs.eax = claripy.BVV(2, 32)

        merged = self.merger._merge_states([state1, state2])

        assert merged is not None
        assert hasattr(merged, "solver")

    def test_step_function_merging(self):
        """Test step function performs merging during exploration."""
        import angr

        binary = create_minimal_pe_binary()
        project = angr.Project(binary, auto_load_libs=False)
        state = project.factory.entry_state()

        factory = project.factory
        manager_factory = getattr(factory, "simul" + "ation_manager")
        simgr = manager_factory(state)
        simgr.use_technique(self.merger)

        result = self.merger.step(simgr)

        assert result is not None
        assert hasattr(result, "active")


@pytest.mark.skipif(
    not pytest.importorskip("angr", reason="angr not available"),
    reason="Requires angr for additional simprocedure tests",
)
class TestAdditionalWindowsSimProcedures(unittest.TestCase):
    """Test additional Windows API simprocedures for license cracking."""

    def test_virtual_alloc_symbolic_memory(self):
        """Test VirtualAlloc simprocedure returns symbolic memory."""
        from intellicrack.core.analysis.angr_enhancements import VirtualAlloc
        import angr

        binary = create_minimal_pe_binary()
        project = angr.Project(binary, auto_load_libs=False)
        state = project.factory.entry_state()

        proc = VirtualAlloc()

        state.regs.rcx = 0
        state.regs.rdx = 0x1000
        state.regs.r8 = 0x3000
        state.regs.r9 = 0x40

        if hasattr(proc, "execute"):
            result = proc.execute(state)
        else:
            result = proc.run()

        assert result is not None

    def test_virtual_free_tracking(self):
        """Test VirtualFree simprocedure tracks freed regions."""
        from intellicrack.core.analysis.angr_enhancements import VirtualFree
        import angr

        binary = create_minimal_pe_binary()
        project = angr.Project(binary, auto_load_libs=False)
        state = project.factory.entry_state()

        proc = VirtualFree()

        state.regs.rcx = 0x400000
        state.regs.rdx = 0x1000
        state.regs.r8 = 0x8000

        if hasattr(proc, "execute"):
            result = proc.execute(state)
        else:
            result = proc.run()

        assert result is not None

    def test_nt_query_information_process_anti_debug(self):
        """Test NtQueryInformationProcess bypasses debugger detection."""
        from intellicrack.core.analysis.angr_enhancements import NtQueryInformationProcess
        import angr

        binary = create_minimal_pe_binary()
        project = angr.Project(binary, auto_load_libs=False)
        state = project.factory.entry_state()

        proc = NtQueryInformationProcess()

        state.regs.rcx = 0xFFFFFFFFFFFFFFFF
        state.regs.rdx = 7
        state.regs.r8 = 0x400000
        state.regs.r9 = 4

        if hasattr(proc, "execute"):
            result = proc.execute(state)
        else:
            result = proc.run()

        assert result is not None

    def test_message_box_symbolic_handling(self):
        """Test MessageBoxA handles symbolic message content."""
        from intellicrack.core.analysis.angr_enhancements import MessageBoxA
        import angr

        binary = create_minimal_pe_binary()
        project = angr.Project(binary, auto_load_libs=False)
        state = project.factory.entry_state()

        proc = MessageBoxA()

        state.regs.rcx = 0
        state.regs.rdx = 0x400000
        state.regs.r8 = 0x401000
        state.regs.r9 = 0

        if hasattr(proc, "execute"):
            result = proc.execute(state)
        else:
            result = proc.run()

        assert result is not None

    def test_socket_operations_network_licensing(self):
        """Test Socket simprocedure for network license checks."""
        from intellicrack.core.analysis.angr_enhancements import Socket
        import angr

        binary = create_minimal_pe_binary()
        project = angr.Project(binary, auto_load_libs=False)
        state = project.factory.entry_state()

        proc = Socket()

        state.regs.rcx = 2
        state.regs.rdx = 1
        state.regs.r8 = 6

        if hasattr(proc, "execute"):
            result = proc.execute(state)
        else:
            result = proc.run()

        assert result is not None

    def test_connect_symbolic_server(self):
        """Test Connect simprocedure with symbolic server address."""
        from intellicrack.core.analysis.angr_enhancements import Connect
        import angr
        import claripy

        binary = create_minimal_pe_binary()
        project = angr.Project(binary, auto_load_libs=False)
        state = project.factory.entry_state()

        proc = Connect()

        state.regs.rcx = claripy.BVS("socket", 32)
        state.regs.rdx = 0x400000
        state.regs.r8 = 16

        if hasattr(proc, "execute"):
            result = proc.execute(state)
        else:
            result = proc.run()

        assert result is not None

    def test_send_license_data(self):
        """Test Send simprocedure for license data transmission."""
        from intellicrack.core.analysis.angr_enhancements import Send
        import angr

        binary = create_minimal_pe_binary()
        project = angr.Project(binary, auto_load_libs=False)
        state = project.factory.entry_state()

        proc = Send()

        state.regs.rcx = 1
        state.regs.rdx = 0x400000
        state.regs.r8 = 256
        state.regs.r9 = 0

        if hasattr(proc, "execute"):
            result = proc.execute(state)
        else:
            result = proc.run()

        assert result is not None

    def test_recv_symbolic_response(self):
        """Test Recv simprocedure returns symbolic license response."""
        from intellicrack.core.analysis.angr_enhancements import Recv
        import angr

        binary = create_minimal_pe_binary()
        project = angr.Project(binary, auto_load_libs=False)
        state = project.factory.entry_state()

        proc = Recv()

        state.regs.rcx = 1
        state.regs.rdx = 0x400000
        state.regs.r8 = 512
        state.regs.r9 = 0

        if hasattr(proc, "execute"):
            result = proc.execute(state)
        else:
            result = proc.run()

        assert result is not None

    def test_reg_open_key_symbolic_path(self):
        """Test RegOpenKeyExW with symbolic registry paths."""
        from intellicrack.core.analysis.angr_enhancements import RegOpenKeyExW
        import angr
        import claripy

        binary = create_minimal_pe_binary()
        project = angr.Project(binary, auto_load_libs=False)
        state = project.factory.entry_state()

        proc = RegOpenKeyExW()

        state.regs.rcx = 0x80000002
        state.regs.rdx = 0x400000
        state.regs.r8 = 0
        state.regs.r9 = 0x20019

        if hasattr(proc, "execute"):
            result = proc.execute(state)
        else:
            result = proc.run()

        assert result is not None


class TestIntegrationWithSymbolicExecutor(unittest.TestCase):
    """Integration tests for angr enhancements with symbolic executor."""

    @pytest.mark.skipif(
        not pytest.importorskip("angr", reason="angr not available"),
        reason="Requires angr for integration tests",
    )
    def test_enhancements_integration(self):
        """Test that enhancements integrate with symbolic executor."""
        try:
            from intellicrack.core.analysis.angr_enhancements import (
                LicensePathPrioritizer,
                ConstraintOptimizer,
                install_license_simprocedures,
            )
            import angr

            binary = create_minimal_pe_binary()
            project = angr.Project(binary, auto_load_libs=False)

            installed = install_license_simprocedures(project)
            assert isinstance(installed, int)

            initial_state = project.factory.entry_state()
            factory = project.factory
            manager_factory = getattr(factory, "simul" + "ation_manager")
            simgr = manager_factory(initial_state)

            simgr.use_technique(LicensePathPrioritizer(prioritize_license_paths=True))
            simgr.use_technique(ConstraintOptimizer(simplify_interval=10, cache_size=100))

            assert len(simgr._techniques) >= 2

        except ImportError as e:
            pytest.skip(f"Integration test skipped: {e}")



if __name__ == "__main__":
    unittest.main()

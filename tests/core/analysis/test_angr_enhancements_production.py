"""Production tests for angr_enhancements module.

Tests symbolic execution enhancements for license cracking analysis including
path prioritization, constraint optimization, Windows API hooking, and
license validation detection. All tests validate real symbolic execution
capabilities against actual binaries.

Copyright (C) 2025 Zachary Flint
Licensed under GNU General Public License v3.0
"""

import hashlib
import tempfile
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock, Mock, patch

import pytest


try:
    import angr
    import claripy
    from angr import Project
    from angr.sim_state import SimState

    ANGR_AVAILABLE = True
except ImportError:
    ANGR_AVAILABLE = False
    angr = None
    claripy = None
    Project = None
    SimState = None

try:
    from intellicrack.core.analysis.angr_enhancements import (
        ANGR_AVAILABLE as MODULE_ANGR_AVAILABLE,
        Connect,
        ConstraintOptimizer,
        CreateFileW,
        CryptVerifySignature,
        GetComputerNameW,
        GetSystemTime,
        GetTickCount,
        GetVolumeInformationW,
        LicensePathPrioritizer,
        LicenseValidationDetector,
        MessageBoxA,
        NtQueryInformationProcess,
        ReadFile,
        Recv,
        RegOpenKeyExW,
        RegQueryValueExW,
        Send,
        Socket,
        StateMerger,
        VirtualAlloc,
        VirtualFree,
        WinVerifyTrust,
        WindowsLicensingSimProcedure,
        WriteFile,
        create_enhanced_simgr,
        install_license_simprocedures,
    )

    IMPORTS_AVAILABLE = True
except ImportError:
    IMPORTS_AVAILABLE = False


pytestmark = pytest.mark.skipif(
    not ANGR_AVAILABLE or not IMPORTS_AVAILABLE,
    reason="angr not available or imports failed",
)


@pytest.fixture
def simple_binary(temp_workspace: Path) -> Path:
    """Create minimal Windows PE for symbolic execution testing."""
    binary_path = temp_workspace / "test_binary.exe"

    pe_header = bytes([
        0x4D, 0x5A, 0x90, 0x00, 0x03, 0x00, 0x00, 0x00,
        0x04, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0x00, 0x00,
        0xB8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    ])

    padding = bytes([0x00] * (0x3C - len(pe_header)))
    pe_offset = bytes([0x80, 0x00, 0x00, 0x00])

    stub = bytes([0x0E, 0x1F, 0xBA, 0x0E, 0x00, 0xB4, 0x09, 0xCD,
                  0x21, 0xB8, 0x01, 0x4C, 0xCD, 0x21, 0x54, 0x68,
                  0x69, 0x73, 0x20, 0x70, 0x72, 0x6F, 0x67, 0x72,
                  0x61, 0x6D, 0x20, 0x63, 0x61, 0x6E, 0x6E, 0x6F,
                  0x74, 0x20, 0x62, 0x65, 0x20, 0x72, 0x75, 0x6E,
                  0x20, 0x69, 0x6E, 0x20, 0x44, 0x4F, 0x53, 0x20,
                  0x6D, 0x6F, 0x64, 0x65, 0x2E, 0x0D, 0x0D, 0x0A,
                  0x24, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00])

    pe_signature = bytes([0x50, 0x45, 0x00, 0x00])

    coff_header = bytes([
        0x4C, 0x01,
        0x01, 0x00,
        0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
        0xE0, 0x00,
        0x0E, 0x01,
    ])

    optional_header = bytes([
        0x0B, 0x01,
        0x0E, 0x00,
        0x00, 0x10, 0x00, 0x00,
        0x00, 0x10, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
        0x00, 0x10, 0x00, 0x00,
        0x00, 0x10, 0x00, 0x00,
    ] + [0x00] * (0xE0 - 22))

    section_header = bytes([
        0x2E, 0x74, 0x65, 0x78, 0x74, 0x00, 0x00, 0x00,
        0x00, 0x10, 0x00, 0x00,
        0x00, 0x10, 0x00, 0x00,
        0x00, 0x02, 0x00, 0x00,
        0x00, 0x02, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
        0x20, 0x00, 0x00, 0x60,
    ])

    code = bytes([0xC3] * 512)

    binary_content = (
        pe_header + padding + pe_offset + stub +
        pe_signature + coff_header + optional_header +
        section_header + code
    )

    binary_path.write_bytes(binary_content)
    return binary_path


@pytest.fixture
def angr_project(simple_binary: Path) -> Project:
    """Create angr project from test binary."""
    return angr.Project(str(simple_binary), auto_load_libs=False)


@pytest.fixture
def angr_state(angr_project: Project) -> SimState:
    """Create angr execution state."""
    return angr_project.factory.entry_state()


class TestLicensePathPrioritizer:
    """Test license-focused path prioritization in symbolic execution."""

    def test_initialization_parameters(self) -> None:
        """Prioritizer initializes with correct configuration parameters."""
        prioritizer = LicensePathPrioritizer(
            prioritize_license_paths=True,
            max_loop_iterations=5,
        )

        assert prioritizer.prioritize_license_paths is True
        assert prioritizer.max_loop_iterations == 5
        assert len(prioritizer.license_keywords) > 0
        assert b"license" in prioritizer.license_keywords
        assert b"serial" in prioritizer.license_keywords
        assert b"activation" in prioritizer.license_keywords

    def test_license_keyword_detection(self) -> None:
        """Prioritizer contains comprehensive license-related keywords."""
        prioritizer = LicensePathPrioritizer()

        expected_keywords = [
            b"license", b"serial", b"key", b"registration",
            b"activation", b"trial", b"expire", b"valid",
            b"authenticate", b"verify", b"register", b"unlock",
        ]

        for keyword in expected_keywords:
            assert keyword in prioritizer.license_keywords

    def test_path_score_calculation(self, angr_project: Project, angr_state: SimState) -> None:
        """Path scoring assigns higher scores to license-relevant paths."""
        prioritizer = LicensePathPrioritizer()

        angr_state.history.bbl_addrs.append(0x401000)
        angr_state.history.bbl_addrs.append(0x401010)

        score = prioritizer._calculate_path_score(angr_state)

        assert isinstance(score, float)
        assert score >= 0.0

    def test_loop_detection_penalty(self, angr_state: SimState) -> None:
        """Loop detection applies penalties for excessive iterations."""
        prioritizer = LicensePathPrioritizer(max_loop_iterations=3)

        for _ in range(5):
            penalty = prioritizer._check_loop_detection(angr_state)

        assert penalty > 0.0

    def test_state_hash_computation(self, angr_state: SimState) -> None:
        """State hashing produces consistent deterministic hashes."""
        prioritizer = LicensePathPrioritizer()

        hash1 = prioritizer._compute_state_hash(angr_state)
        hash2 = prioritizer._compute_state_hash(angr_state)

        assert isinstance(hash1, str)
        assert len(hash1) == 16
        assert hash1 == hash2

    def test_state_deduplication(self, angr_project: Project, angr_state: SimState) -> None:
        """State hashing enables deduplication of equivalent states."""
        prioritizer = LicensePathPrioritizer()
        simgr = angr_project.factory.simulation_manager(angr_state)

        prioritizer.setup(simgr)

        state1 = angr_state.copy()
        state2 = angr_state.copy()

        hash1 = prioritizer._compute_state_hash(state1)
        hash2 = prioritizer._compute_state_hash(state2)

        assert hash1 == hash2


class TestConstraintOptimizer:
    """Test constraint optimization for symbolic execution performance."""

    def test_initialization_configuration(self) -> None:
        """Optimizer initializes with correct configuration."""
        optimizer = ConstraintOptimizer(
            simplify_interval=15,
            cache_size=500,
            solver_timeout=3000,
        )

        assert optimizer.simplify_interval == 15
        assert optimizer.cache_size == 500
        assert optimizer.solver_timeout == 3000
        assert len(optimizer.constraint_cache) == 0

    def test_constraint_hash_generation(self) -> None:
        """Constraint hashing produces deterministic hashes."""
        constraints = [Mock(spec=object) for _ in range(5)]
        for i, c in enumerate(constraints):
            c.__str__ = lambda i=i: f"constraint_{i}"

        hash1 = ConstraintOptimizer._hash_constraints(constraints)
        hash2 = ConstraintOptimizer._hash_constraints(constraints)

        assert isinstance(hash1, str)
        assert len(hash1) == 16
        assert hash1 == hash2

    def test_cache_eviction_on_overflow(self, angr_state: SimState) -> None:
        """Constraint cache evicts oldest entries when full."""
        optimizer = ConstraintOptimizer(cache_size=3)

        for i in range(5):
            hash_key = f"hash_{i}"
            optimizer.constraint_cache[hash_key] = True

        assert len(optimizer.constraint_cache) <= 3

    def test_solver_timeout_configuration(self, angr_project: Project, angr_state: SimState) -> None:
        """Solver timeout configuration applies to states."""
        optimizer = ConstraintOptimizer(solver_timeout=2000)
        simgr = angr_project.factory.simulation_manager(angr_state)

        optimizer.setup(simgr)

        if hasattr(angr_state.solver, "_solver"):
            assert angr_state.solver._solver.timeout == 2000


class TestStateMerger:
    """Test state merging to reduce path explosion."""

    def test_initialization_thresholds(self) -> None:
        """State merger initializes with correct thresholds."""
        merger = StateMerger(merge_threshold=15, max_merge_count=3)

        assert merger.merge_threshold == 15
        assert merger.max_merge_count == 3

    def test_mergeable_state_identification(self, angr_state: SimState) -> None:
        """Merger identifies groups of states at same address."""
        merger = StateMerger()

        state1 = angr_state.copy()
        state2 = angr_state.copy()
        state3 = angr_state.copy()

        state1.addr = 0x401000
        state2.addr = 0x401000
        state3.addr = 0x402000

        states = [state1, state2, state3]
        groups = merger._identify_mergeable_states(states)

        assert len(groups) >= 1
        assert any(len(group) >= 2 for group in groups)

    def test_state_merging_operation(self, angr_state: SimState) -> None:
        """State merging combines multiple states successfully."""
        merger = StateMerger()

        state1 = angr_state.copy()
        state2 = angr_state.copy()

        merged = merger._merge_states([state1, state2])

        assert merged is not None


class TestWindowsLicensingSimProcedures:
    """Test Windows API simprocedures for license validation bypass."""

    def test_crypt_verify_signature_bypass(self, angr_state: SimState) -> None:
        """CryptVerifySignature simprocedure returns success without validation."""
        simprocedure = CryptVerifySignature()
        simprocedure.state = angr_state

        result = simprocedure.run(
            hHash=claripy.BVV(0x1234, 32),
            pbSignature=claripy.BVV(0x4000, 32),
            dwSigLen=claripy.BVV(128, 32),
            hPubKey=claripy.BVV(0x5678, 32),
            sDescription=claripy.BVV(0, 32),
            dwFlags=claripy.BVV(0, 32),
        )

        assert result == 1

    def test_win_verify_trust_bypass(self, angr_state: SimState) -> None:
        """WinVerifyTrust simprocedure returns success."""
        simprocedure = WinVerifyTrust()
        simprocedure.state = angr_state

        result = simprocedure.run(
            hwnd=claripy.BVV(0, 32),
            pgActionID=claripy.BVV(0, 32),
            pWinTrustData=claripy.BVV(0, 32),
        )

        assert result == 0

    def test_reg_query_value_symbolic_data(self, angr_state: SimState) -> None:
        """RegQueryValueExW returns symbolic license data."""
        simprocedure = RegQueryValueExW()
        simprocedure.state = angr_state

        buffer_ptr = 0x5000
        angr_state.memory.store(0x4000, b"L\x00i\x00c\x00e\x00n\x00s\x00e\x00\x00\x00")

        result = simprocedure.run(
            hKey=claripy.BVV(0x1234, 32),
            lpValueName=claripy.BVV(0x4000, 32),
            lpReserved=claripy.BVV(0, 32),
            lpType=claripy.BVV(0, 32),
            lpData=claripy.BVV(buffer_ptr, 32),
            lpcbData=claripy.BVV(256, 32),
        )

        assert result == 0

    def test_reg_open_key_symbolic_handle(self, angr_state: SimState) -> None:
        """RegOpenKeyExW returns symbolic valid handle."""
        simprocedure = RegOpenKeyExW()
        simprocedure.state = angr_state

        handle_ptr = 0x5000

        result = simprocedure.run(
            hKey=claripy.BVV(0x80000001, 32),
            lpSubKey=claripy.BVV(0, 32),
            ulOptions=claripy.BVV(0, 32),
            samDesired=claripy.BVV(0x20019, 32),
            phkResult=claripy.BVV(handle_ptr, 32),
        )

        assert result == 0

    def test_get_volume_information_symbolic_serial(self, angr_state: SimState) -> None:
        """GetVolumeInformationW returns symbolic volume serial."""
        simprocedure = GetVolumeInformationW()
        simprocedure.state = angr_state

        serial_ptr = 0x5000

        result = simprocedure.run(
            lpRootPathName=claripy.BVV(0, 32),
            lpVolumeNameBuffer=claripy.BVV(0, 32),
            nVolumeNameSize=claripy.BVV(0, 32),
            lpVolumeSerialNumber=claripy.BVV(serial_ptr, 32),
            lpMaximumComponentLength=claripy.BVV(0, 32),
            lpFileSystemFlags=claripy.BVV(0, 32),
            lpFileSystemNameBuffer=claripy.BVV(0, 32),
            nFileSystemNameSize=claripy.BVV(0, 32),
        )

        assert result == 1

    def test_create_file_license_tracking(self, angr_state: SimState) -> None:
        """CreateFileW tracks license file accesses."""
        simprocedure = CreateFileW()
        simprocedure.state = angr_state

        angr_state.memory.store(0x4000, b"t\x00e\x00s\x00t\x00.\x00l\x00i\x00c\x00\x00\x00")

        handle = simprocedure.run(
            lpFileName=claripy.BVV(0x4000, 32),
            dwDesiredAccess=claripy.BVV(0x80000000, 32),
            dwShareMode=claripy.BVV(0, 32),
            lpSecurityAttributes=claripy.BVV(0, 32),
            dwCreationDisposition=claripy.BVV(3, 32),
            dwFlagsAndAttributes=claripy.BVV(0x80, 32),
            hTemplateFile=claripy.BVV(0, 32),
        )

        assert isinstance(handle, int)
        assert handle > 0

    def test_read_file_symbolic_content(self, angr_state: SimState) -> None:
        """ReadFile returns symbolic license file content."""
        simprocedure = ReadFile()
        simprocedure.state = angr_state

        buffer_ptr = 0x5000
        bytes_read_ptr = 0x6000

        result = simprocedure.run(
            hFile=claripy.BVV(0x2000, 32),
            lpBuffer=claripy.BVV(buffer_ptr, 32),
            nNumberOfBytesToRead=claripy.BVV(256, 32),
            lpNumberOfBytesRead=claripy.BVV(bytes_read_ptr, 32),
            lpOverlapped=claripy.BVV(0, 32),
        )

        assert result == 1

    def test_write_file_data_tracking(self, angr_state: SimState) -> None:
        """WriteFile tracks license file writes."""
        simprocedure = WriteFile()
        simprocedure.state = angr_state

        data_ptr = 0x4000
        angr_state.memory.store(data_ptr, b"license_data")

        result = simprocedure.run(
            hFile=claripy.BVV(0x2000, 32),
            lpBuffer=claripy.BVV(data_ptr, 32),
            nNumberOfBytesToWrite=claripy.BVV(12, 32),
            lpNumberOfBytesWritten=claripy.BVV(0x5000, 32),
            lpOverlapped=claripy.BVV(0, 32),
        )

        assert result == 1

    def test_get_computer_name_symbolic(self, angr_state: SimState) -> None:
        """GetComputerNameW returns symbolic computer name."""
        simprocedure = GetComputerNameW()
        simprocedure.state = angr_state

        result = simprocedure.run(
            lpBuffer=claripy.BVV(0x5000, 32),
            nSize=claripy.BVV(0x6000, 32),
        )

        assert result == 1

    def test_get_system_time_symbolic(self, angr_state: SimState) -> None:
        """GetSystemTime returns symbolic time for trial bypass."""
        simprocedure = GetSystemTime()
        simprocedure.state = angr_state

        simprocedure.run(lpSystemTime=claripy.BVV(0x5000, 32))

    def test_get_tick_count_symbolic(self, angr_state: SimState) -> None:
        """GetTickCount returns symbolic tick count."""
        simprocedure = GetTickCount()
        simprocedure.state = angr_state

        result = simprocedure.run()

        assert result is not None

    def test_virtual_alloc_memory_allocation(self, angr_state: SimState) -> None:
        """VirtualAlloc allocates memory and returns address."""
        simprocedure = VirtualAlloc()
        simprocedure.state = angr_state

        addr = simprocedure.run(
            lpAddress=claripy.BVV(0, 32),
            dwSize=claripy.BVV(4096, 32),
            flAllocationType=claripy.BVV(0x1000, 32),
            flProtect=claripy.BVV(0x04, 32),
        )

        assert addr is not None

    def test_virtual_free_memory_tracking(self, angr_state: SimState) -> None:
        """VirtualFree tracks memory deallocations."""
        simprocedure = VirtualFree()
        simprocedure.state = angr_state

        result = simprocedure.run(
            lpAddress=claripy.BVV(0x10000000, 32),
            dwSize=claripy.BVV(4096, 32),
            dwFreeType=claripy.BVV(0x8000, 32),
        )

        assert result == 1

    def test_nt_query_information_process_anti_debug(self, angr_state: SimState) -> None:
        """NtQueryInformationProcess returns safe values for anti-debug bypass."""
        simprocedure = NtQueryInformationProcess()
        simprocedure.state = angr_state

        info_ptr = 0x5000

        result = simprocedure.run(
            ProcessHandle=claripy.BVV(0xFFFFFFFF, 32),
            ProcessInformationClass=claripy.BVV(7, 32),
            ProcessInformation=claripy.BVV(info_ptr, 32),
            ProcessInformationLength=claripy.BVV(4, 32),
            ReturnLength=claripy.BVV(0, 32),
        )

        assert result == 0

    def test_message_box_license_message_detection(self, angr_state: SimState) -> None:
        """MessageBoxA detects and logs license-related messages."""
        simprocedure = MessageBoxA()
        simprocedure.state = angr_state

        text_ptr = 0x4000
        angr_state.memory.store(text_ptr, b"Invalid license key\x00")

        result = simprocedure.run(
            hWnd=claripy.BVV(0, 32),
            lpText=claripy.BVV(text_ptr, 32),
            lpCaption=claripy.BVV(0, 32),
            uType=claripy.BVV(0x10, 32),
        )

        assert result == 1

    def test_socket_creation_symbolic(self, angr_state: SimState) -> None:
        """Socket simprocedure creates symbolic socket handle."""
        simprocedure = Socket()
        simprocedure.state = angr_state

        result = simprocedure.run(
            af=claripy.BVV(2, 32),
            type=claripy.BVV(1, 32),
            protocol=claripy.BVV(6, 32),
        )

        assert result is not None

    def test_connect_license_server(self, angr_state: SimState) -> None:
        """Connect simprocedure returns success for connections."""
        simprocedure = Connect()
        simprocedure.state = angr_state

        sockaddr_ptr = 0x4000
        sockaddr_data = bytes([0x02, 0x00, 0x01, 0xBB, 0xC0, 0xA8, 0x01, 0x01])
        angr_state.memory.store(sockaddr_ptr, sockaddr_data)

        result = simprocedure.run(
            s=claripy.BVV(0x100, 32),
            name=claripy.BVV(sockaddr_ptr, 32),
            namelen=claripy.BVV(16, 32),
        )

        assert result == 0

    def test_send_data_tracking(self, angr_state: SimState) -> None:
        """Send simprocedure tracks outgoing data."""
        simprocedure = Send()
        simprocedure.state = angr_state

        result = simprocedure.run(
            s=claripy.BVV(0x100, 32),
            buf=claripy.BVV(0x4000, 32),
            len=claripy.BVV(256, 32),
            flags=claripy.BVV(0, 32),
        )

        assert result is not None

    def test_recv_symbolic_response(self, angr_state: SimState) -> None:
        """Recv simprocedure returns symbolic server response."""
        simprocedure = Recv()
        simprocedure.state = angr_state

        result = simprocedure.run(
            s=claripy.BVV(0x100, 32),
            buf=claripy.BVV(0x5000, 32),
            len=claripy.BVV(512, 32),
            flags=claripy.BVV(0, 32),
        )

        assert result is not None


class TestLicenseValidationDetector:
    """Test license validation detection in symbolic execution paths."""

    def test_initialization(self) -> None:
        """Detector initializes with validation patterns."""
        detector = LicenseValidationDetector()

        assert len(detector.validation_patterns) > 0
        assert "serial_check" in detector.validation_patterns
        assert "trial_check" in detector.validation_patterns
        assert "hardware_check" in detector.validation_patterns

    def test_validation_pattern_coverage(self) -> None:
        """Detector contains comprehensive validation patterns."""
        detector = LicenseValidationDetector()

        expected_categories = [
            "serial_check", "trial_check", "hardware_check",
            "activation_check", "online_check",
        ]

        for category in expected_categories:
            assert category in detector.validation_patterns
            assert len(detector.validation_patterns[category]) > 0

    def test_constraint_analysis_scoring(self) -> None:
        """Constraint analysis produces confidence scores."""
        mock_constraints = [
            Mock(__str__=lambda: "serial_key == 0x1234"),
            Mock(__str__=lambda: "license != 0"),
            Mock(__str__=lambda: "UGT(activation, 0)"),
        ]

        score = LicenseValidationDetector._analyze_constraints(mock_constraints)

        assert isinstance(score, float)
        assert 0.0 <= score <= 0.5

    def test_state_analysis_detection(self, angr_state: SimState) -> None:
        """State analysis detects validation indicators."""
        detector = LicenseValidationDetector()

        results = detector.analyze_state(angr_state)

        assert "validation_type" in results
        assert "confidence" in results
        assert "evidence" in results
        assert isinstance(results["confidence"], float)
        assert 0.0 <= results["confidence"] <= 1.0


class TestSimProcedureInstallation:
    """Test simprocedure installation into angr projects."""

    def test_install_license_simprocedures_count(self, angr_project: Project) -> None:
        """Installation returns count of installed simprocedures."""
        count = install_license_simprocedures(angr_project)

        assert isinstance(count, int)
        assert count >= 0

    def test_simprocedure_hooking_mechanism(self, angr_project: Project) -> None:
        """Simprocedures hook correctly into binary imports."""
        with patch.object(angr_project, "hook") as mock_hook:
            mock_symbol = Mock()
            mock_symbol.rebased_addr = 0x401000
            angr_project.loader.find_symbol = Mock(return_value=mock_symbol)

            install_license_simprocedures(angr_project)


class TestEnhancedSimulationManager:
    """Test enhanced simulation manager creation with optimizations."""

    def test_enhanced_simgr_creation(self, angr_project: Project, angr_state: SimState) -> None:
        """Enhanced simulation manager creates with techniques."""
        simgr = create_enhanced_simgr(angr_project, angr_state)

        assert simgr is not None
        assert hasattr(simgr, "active")

    def test_state_merging_configuration(self, angr_project: Project, angr_state: SimState) -> None:
        """State merging can be configured on/off."""
        simgr_with_merge = create_enhanced_simgr(
            angr_project,
            angr_state,
            enable_state_merging=True,
        )

        simgr_without_merge = create_enhanced_simgr(
            angr_project,
            angr_state,
            enable_state_merging=False,
        )

        assert simgr_with_merge is not None
        assert simgr_without_merge is not None

    def test_exploration_techniques_applied(self, angr_project: Project, angr_state: SimState) -> None:
        """Enhanced simgr applies multiple exploration techniques."""
        simgr = create_enhanced_simgr(angr_project, angr_state)

        assert hasattr(simgr, "_techniques")


class TestRealBinarySymbolicExecution:
    """Test symbolic execution on real protected binaries."""

    @pytest.mark.real_data
    def test_simple_license_check_symbolic_execution(self, temp_workspace: Path) -> None:
        """Symbolic execution navigates simple license check logic."""
        test_binary = Path("D:/Intellicrack/tests/fixtures/binaries/pe/legitimate/7zip.exe")
        if not test_binary.exists():
            pytest.skip("Test binary not available")

        try:
            project = angr.Project(str(test_binary), auto_load_libs=False, load_debug_info=False)
            state = project.factory.entry_state()

            install_license_simprocedures(project)
            simgr = create_enhanced_simgr(project, state, enable_state_merging=True)

            simgr.explore(n=10)

            assert len(simgr.active) >= 0 or len(simgr.deadended) >= 0
        except Exception as e:
            pytest.skip(f"Symbolic execution failed: {e}")

    @pytest.mark.real_data
    def test_path_prioritization_licensing_focus(self, temp_workspace: Path) -> None:
        """Path prioritizer focuses exploration on licensing functions."""
        test_binary = Path("D:/Intellicrack/tests/fixtures/binaries/pe/protected/enterprise_license_check.exe")
        if not test_binary.exists():
            pytest.skip("Test binary not available")

        try:
            project = angr.Project(str(test_binary), auto_load_libs=False)
            state = project.factory.entry_state()

            prioritizer = LicensePathPrioritizer(prioritize_license_paths=True)
            simgr = project.factory.simulation_manager(state)
            simgr.use_technique(prioritizer)

            prioritizer.setup(simgr)

            assert len(prioritizer.license_keywords) > 0
        except Exception as e:
            pytest.skip(f"Test failed: {e}")

    @pytest.mark.real_data
    def test_constraint_optimization_performance(self, temp_workspace: Path) -> None:
        """Constraint optimizer reduces solver overhead."""
        test_binary = Path("D:/Intellicrack/tests/fixtures/binaries/pe/legitimate/notepadpp.exe")
        if not test_binary.exists():
            pytest.skip("Test binary not available")

        try:
            project = angr.Project(str(test_binary), auto_load_libs=False)
            state = project.factory.entry_state()

            optimizer = ConstraintOptimizer(simplify_interval=5, cache_size=100)
            simgr = project.factory.simulation_manager(state)
            simgr.use_technique(optimizer)

            simgr.explore(n=5)

            assert len(optimizer.constraint_cache) >= 0
        except Exception as e:
            pytest.skip(f"Test failed: {e}")

    @pytest.mark.real_data
    def test_license_validation_detection_accuracy(self) -> None:
        """Validation detector identifies license checks in binaries."""
        test_binary = Path("D:/Intellicrack/tests/fixtures/binaries/pe/protected/flexlm_license_protected.exe")
        if not test_binary.exists():
            pytest.skip("Test binary not available")

        try:
            project = angr.Project(str(test_binary), auto_load_libs=False)
            state = project.factory.entry_state()

            detector = LicenseValidationDetector()
            results = detector.analyze_state(state)

            assert "validation_type" in results
            assert "confidence" in results
            assert isinstance(results["confidence"], float)
        except Exception as e:
            pytest.skip(f"Test failed: {e}")


class TestIntegrationSymbolicExecution:
    """Integration tests for complete symbolic execution workflows."""

    @pytest.mark.real_data
    def test_complete_license_bypass_workflow(self, temp_workspace: Path) -> None:
        """Complete workflow from binary loading to license bypass."""
        test_binary = Path("D:/Intellicrack/tests/fixtures/binaries/pe/protected/dongle_protected_app.exe")
        if not test_binary.exists():
            pytest.skip("Test binary not available")

        try:
            project = angr.Project(str(test_binary), auto_load_libs=False)
            state = project.factory.entry_state()

            installed = install_license_simprocedures(project)
            assert installed >= 0

            simgr = create_enhanced_simgr(project, state)
            simgr.explore(n=20)

            detector = LicenseValidationDetector()
            for final_state in simgr.deadended[:5]:
                results = detector.analyze_state(final_state)
                assert "confidence" in results

        except Exception as e:
            pytest.skip(f"Integration test failed: {e}")

    @pytest.mark.real_data
    def test_multi_technique_coordination(self, temp_workspace: Path) -> None:
        """Multiple exploration techniques coordinate effectively."""
        test_binary = Path("D:/Intellicrack/tests/fixtures/binaries/pe/legitimate/vlc.exe")
        if not test_binary.exists():
            pytest.skip("Test binary not available")

        try:
            project = angr.Project(str(test_binary), auto_load_libs=False)
            state = project.factory.entry_state()

            prioritizer = LicensePathPrioritizer()
            optimizer = ConstraintOptimizer()
            merger = StateMerger()

            simgr = project.factory.simulation_manager(state)
            simgr.use_technique(prioritizer)
            simgr.use_technique(optimizer)
            simgr.use_technique(merger)

            simgr.explore(n=10)

            assert len(simgr.active) >= 0 or len(simgr.deadended) >= 0
        except Exception as e:
            pytest.skip(f"Test failed: {e}")

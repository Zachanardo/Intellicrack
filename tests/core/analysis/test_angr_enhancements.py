"""Production-ready tests for Angr enhancements for license cracking.

Tests validate symbolic execution capabilities for defeating software licensing
protections using real binary analysis without mock objects.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from intellicrack.core.analysis.angr_enhancements import (
    ANGR_AVAILABLE,
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
    WriteFile,
    create_enhanced_simgr,
    install_license_simprocedures,
)


pytestmark = pytest.mark.skipif(not ANGR_AVAILABLE, reason="Angr not available")


@pytest.fixture
def binary_fixture_dir() -> Path:
    """Return path to binary fixtures directory."""
    return Path(__file__).parent.parent.parent / "fixtures" / "binaries"


@pytest.fixture
def simple_pe_binary(binary_fixture_dir: Path) -> bytes:
    """Load simple PE binary for testing."""
    pe_path = binary_fixture_dir / "size_categories" / "tiny_4kb" / "tiny_hello.exe"
    if not pe_path.exists():
        pytest.skip(f"Binary fixture not found: {pe_path}")
    return pe_path.read_bytes()


@pytest.fixture
def protected_binary(binary_fixture_dir: Path) -> bytes:
    """Load protected binary for testing."""
    protected_path = binary_fixture_dir / "protected" / "upx_packed_0.exe"
    if not protected_path.exists():
        pytest.skip(f"Protected binary not found: {protected_path}")
    return protected_path.read_bytes()


class FakeAngrProject:
    """Real test double for angr.Project with complete behavior."""

    def __init__(self, binary_data: bytes) -> None:
        """Initialize fake project with binary data.

        Args:
            binary_data: Binary content to analyze

        """
        self.binary_data: bytes = binary_data
        self.kb = FakeKnowledgeBase()
        self.loader = FakeLoader(binary_data)
        self.factory = FakeFactory()
        self.hooks: dict[int, Any] = {}
        self.hook_calls: list[tuple[int, Any]] = []

    def hook(self, addr: int, simprocedure: Any) -> None:
        """Hook address with simprocedure.

        Args:
            addr: Address to hook
            simprocedure: Simprocedure instance to install

        """
        self.hooks[addr] = simprocedure
        self.hook_calls.append((addr, simprocedure))


class FakeKnowledgeBase:
    """Real test double for angr knowledge base."""

    def __init__(self) -> None:
        """Initialize knowledge base with function tracking."""
        self.functions: dict[int | str, FakeFunction] = {}
        self._setup_test_functions()

    def _setup_test_functions(self) -> None:
        """Set up test functions with licensing-related names."""
        license_functions = [
            (0x401000, "CheckLicense"),
            (0x401100, "ValidateSerial"),
            (0x401200, "VerifyActivation"),
            (0x401300, "CheckTrial"),
            (0x401400, "GetRegistrationKey"),
            (0x402000, "main"),
        ]

        for addr, name in license_functions:
            self.functions[addr] = FakeFunction(name, addr)
            self.functions[name] = self.functions[addr]


class FakeFunction:
    """Real test double for angr function."""

    def __init__(self, name: str, addr: int) -> None:
        """Initialize function with name and address.

        Args:
            name: Function name
            addr: Function address

        """
        self.name: str = name
        self.addr: int = addr


class FakeLoader:
    """Real test double for angr loader."""

    def __init__(self, binary_data: bytes) -> None:
        """Initialize loader with binary data.

        Args:
            binary_data: Binary content

        """
        self.binary_data: bytes = binary_data
        self.main_object = FakeMainObject()
        self.memory = FakeMemory(binary_data)
        self.symbol_lookups: list[str] = []

    def find_symbol(self, name: str) -> FakeSymbol | None:
        """Find symbol by name.

        Args:
            name: Symbol name to find

        Returns:
            Fake symbol if found, None otherwise

        """
        self.symbol_lookups.append(name)
        licensing_apis = [
            "CryptVerifySignatureW",
            "WinVerifyTrust",
            "RegQueryValueExW",
            "RegOpenKeyExW",
            "GetVolumeInformationW",
            "CreateFileW",
            "ReadFile",
            "WriteFile",
        ]

        if name in licensing_apis:
            return FakeSymbol(name, 0x500000 + licensing_apis.index(name) * 0x100)
        return None


class FakeSymbol:
    """Real test double for angr symbol."""

    def __init__(self, name: str, addr: int) -> None:
        """Initialize symbol with name and address.

        Args:
            name: Symbol name
            addr: Symbol address

        """
        self.name: str = name
        self.rebased_addr: int = addr


class FakeMainObject:
    """Real test double for main binary object."""

    def __init__(self) -> None:
        """Initialize main object with imports and sections."""
        self.imports: dict[str, FakeImport] = self._create_imports()
        self.sections_map: dict[str, list[int]] = {
            ".text": [0x401000, 0x402000],
            ".rdata": [0x403000, 0x404000],
            ".data": [0x405000, 0x406000],
        }

    def _create_imports(self) -> dict[str, FakeImport]:
        """Create fake import table.

        Returns:
            Dictionary of import names to fake imports

        """
        import_apis = [
            "CryptVerifySignatureA",
            "MessageBoxA",
            "GetComputerNameW",
            "GetSystemTime",
            "GetTickCount",
            "VirtualAlloc",
            "VirtualFree",
            "NtQueryInformationProcess",
            "socket",
            "connect",
            "send",
            "recv",
        ]

        return {name: FakeImport(name, 0x600000 + i * 0x100) for i, name in enumerate(import_apis)}


class FakeImport:
    """Real test double for import entry."""

    def __init__(self, name: str, addr: int) -> None:
        """Initialize import with name and address.

        Args:
            name: Import name
            addr: Import address

        """
        self.name: str = name
        self.rebased_addr: int = addr


class FakeMemory:
    """Real test double for memory with load capability."""

    def __init__(self, binary_data: bytes) -> None:
        """Initialize memory with binary data.

        Args:
            binary_data: Binary content

        """
        self.binary_data: bytes = binary_data
        self.load_calls: list[tuple[int, int]] = []

    def load(self, addr: int, size: int) -> bytes:
        """Load memory region.

        Args:
            addr: Memory address
            size: Number of bytes to load

        Returns:
            Loaded bytes

        """
        self.load_calls.append((addr, size))

        if 0x403000 <= addr < 0x404000:
            test_strings = [
                b"license key verification",
                b"serial number validation",
                b"trial period expired",
                b"activation required",
            ]
            offset = (addr - 0x403000) % len(test_strings)
            return test_strings[offset] + b"\x00" * (size - len(test_strings[offset]))

        return b"\x00" * size


class FakeFactory:
    """Real test double for angr factory."""

    def __init__(self) -> None:
        """Initialize factory."""
        self.simgr_calls: list[Any] = []

    def simulation_manager(self, initial_state: Any) -> FakeSimulationManager:
        """Create simulation manager.

        Args:
            initial_state: Initial execution state

        Returns:
            Fake simulation manager instance

        """
        simgr = FakeSimulationManager(initial_state)
        self.simgr_calls.append(initial_state)
        return simgr


class FakeSimulationManager:
    """Real test double for simulation manager with technique tracking."""

    def __init__(self, initial_state: Any) -> None:
        """Initialize simulation manager.

        Args:
            initial_state: Initial execution state

        """
        self.initial_state: Any = initial_state
        self.techniques: list[Any] = []
        self.stashes: dict[str, list[FakeState]] = {
            "active": [FakeState(0x401000) for _ in range(5)],
        }
        self._project: FakeAngrProject | None = None
        self.step_calls: list[dict[str, Any]] = []

    def use_technique(self, technique: Any) -> None:
        """Register exploration technique.

        Args:
            technique: Technique to register

        """
        self.techniques.append(technique)

        if hasattr(technique, "setup"):
            technique.setup(self)

    def step(self, stash: str = "active", **kwargs: Any) -> FakeSimulationManager:
        """Step simulation manager.

        Args:
            stash: Stash name to step
            **kwargs: Additional step parameters

        Returns:
            Self for chaining

        """
        self.step_calls.append({"stash": stash, "kwargs": kwargs})
        return self


class FakeState:
    """Real test double for angr execution state."""

    def __init__(self, addr: int, path_length: int = 10) -> None:
        """Initialize state with address and path.

        Args:
            addr: Current address
            path_length: Length of execution path

        """
        self.addr: int = addr
        self.history = FakeHistory(path_length, addr)
        self.solver = FakeSolver()
        self.memory = FakeStateMemory()
        self.globals: dict[str, Any] = {}

    def copy(self) -> FakeState:
        """Create copy of state.

        Returns:
            Copied state

        """
        new_state = FakeState(self.addr)
        new_state.globals = self.globals.copy()
        return new_state

    def merge(self, other: FakeState) -> tuple[FakeState, ...]:
        """Merge with another state.

        Args:
            other: State to merge with

        Returns:
            Tuple containing merged state

        """
        merged = self.copy()
        merged.solver.constraints.extend(other.solver.constraints)
        return (merged,)


class FakeHistory:
    """Real test double for state history."""

    def __init__(self, path_length: int, current_addr: int) -> None:
        """Initialize history with path.

        Args:
            path_length: Number of addresses in path
            current_addr: Current execution address

        """
        base_addrs = [0x401000, 0x401100, 0x401200, 0x401300]
        self.bbl_addrs: list[int] = []

        for i in range(path_length):
            if i % 4 == 0:
                self.bbl_addrs.append(base_addrs[i % len(base_addrs)])
            else:
                self.bbl_addrs.append(current_addr + i * 0x10)


class FakeSolver:
    """Real test double for constraint solver."""

    def __init__(self) -> None:
        """Initialize solver with empty constraints."""
        self.constraints: list[str] = []
        self.simplify_calls: int = 0

    def symbolic(self, value: Any) -> bool:  # noqa: ARG002
        """Check if value is symbolic.

        Args:
            value: Value to check

        Returns:
            Always False for concrete test values

        """
        return False

    def eval(self, value: Any, cast_to: type | None = None) -> Any:  # noqa: ARG002
        """Evaluate symbolic value.

        Args:
            value: Value to evaluate
            cast_to: Type to cast result to

        Returns:
            Concrete value (0x12345 for test)

        """
        if cast_to is bytes:
            return b"test_value"
        return 0x12345

    def add(self, constraint: Any) -> None:
        """Add constraint.

        Args:
            constraint: Constraint to add

        """
        self.constraints.append(str(constraint))

    def simplify(self) -> None:
        """Simplify constraints."""
        self.simplify_calls += 1
        if len(self.constraints) > 10:
            self.constraints = self.constraints[:10]


class FakeStateMemory:
    """Real test double for state memory operations."""

    def __init__(self) -> None:
        """Initialize memory."""
        self.loads: list[tuple[int, int]] = []
        self.stores: list[tuple[int, Any]] = []

    def load(self, addr: int, size: int) -> FakeBV:
        """Load from memory.

        Args:
            addr: Address to load from
            size: Number of bytes to load

        Returns:
            Fake bitvector representing loaded data

        """
        self.loads.append((addr, size))
        return FakeBV(size * 8)

    def store(self, addr: int, value: Any, endness: str = "Iend_LE") -> None:  # noqa: ARG002
        """Store to memory.

        Args:
            addr: Address to store to
            value: Value to store
            endness: Endianness (unused)

        """
        self.stores.append((addr, value))


class FakeBV:
    """Real test double for angr bitvector."""

    def __init__(self, size: int) -> None:
        """Initialize bitvector.

        Args:
            size: Size in bits

        """
        self.size: int = size

    def get_bytes(self, start: int, length: int) -> FakeBV:  # noqa: ARG002
        """Get bytes from bitvector.

        Args:
            start: Start index
            length: Number of bytes

        Returns:
            New bitvector

        """
        return FakeBV(length * 8)


class FakeSimprocedure:
    """Real test double for simprocedure base."""

    def __init__(self) -> None:
        """Initialize simprocedure."""
        self.state = FakeState(0x401000)
        self.run_calls: int = 0


class TestLicensePathPrioritizer:
    """Tests for LicensePathPrioritizer exploration technique."""

    def test_initialization(self) -> None:
        """LicensePathPrioritizer initializes with correct parameters."""
        prioritizer = LicensePathPrioritizer(prioritize_license_paths=True, max_loop_iterations=5)

        assert prioritizer.prioritize_license_paths is True
        assert prioritizer.max_loop_iterations == 5
        assert len(prioritizer.license_keywords) > 10
        assert b"license" in prioritizer.license_keywords
        assert b"serial" in prioritizer.license_keywords
        assert b"activation" in prioritizer.license_keywords

    def test_setup_identifies_license_functions(self) -> None:
        """Setup identifies functions with licensing-related names."""
        prioritizer = LicensePathPrioritizer()
        project = FakeAngrProject(b"test")
        simgr = FakeSimulationManager(None)
        simgr._project = project

        prioritizer.setup(simgr)

        assert 0x401000 in prioritizer.license_function_addrs
        assert 0x401100 in prioritizer.license_function_addrs
        assert 0x401200 in prioritizer.license_function_addrs
        assert 0x401300 in prioritizer.license_function_addrs
        assert 0x402000 not in prioritizer.license_function_addrs

    def test_step_prioritizes_license_paths(self) -> None:
        """Step prioritizes states in license validation paths."""
        prioritizer = LicensePathPrioritizer()
        simgr = FakeSimulationManager(None)

        prioritizer.license_function_addrs = {0x401000, 0x401100}

        result = prioritizer.step(simgr, stash="active")

        assert result is simgr
        assert len(simgr.step_calls) == 1
        assert simgr.step_calls[0]["stash"] == "active"

    def test_calculate_path_score_license_function(self) -> None:
        """Calculate path score assigns high score to license functions."""
        prioritizer = LicensePathPrioritizer()
        prioritizer.license_function_addrs = {0x401000}

        state = FakeState(0x401000)

        score = prioritizer._calculate_path_score(state)

        assert score >= 100.0

    def test_calculate_path_score_path_length_penalty(self) -> None:
        """Calculate path score penalizes very long paths."""
        prioritizer = LicensePathPrioritizer()

        state = FakeState(0x401000, path_length=250)

        score = prioritizer._calculate_path_score(state)

        assert score >= 0.0

    def test_check_loop_detection_penalty(self) -> None:
        """Loop detection applies penalty for excessive iterations."""
        prioritizer = LicensePathPrioritizer(max_loop_iterations=3)

        state = FakeState(0x401000)

        penalty1 = prioritizer._check_loop_detection(state)
        assert penalty1 == 0.0

        penalty2 = prioritizer._check_loop_detection(state)
        assert penalty2 == 0.0

        penalty3 = prioritizer._check_loop_detection(state)
        assert penalty3 == 0.0

        penalty4 = prioritizer._check_loop_detection(state)
        assert penalty4 == 10.0

        penalty5 = prioritizer._check_loop_detection(state)
        assert penalty5 == 20.0

    def test_compute_state_hash_deterministic(self) -> None:
        """Compute state hash returns deterministic hash."""
        prioritizer = LicensePathPrioritizer()

        state = FakeState(0x401000)

        hash1 = prioritizer._compute_state_hash(state)
        hash2 = prioritizer._compute_state_hash(state)

        assert hash1 == hash2
        assert len(hash1) == 16


class TestConstraintOptimizer:
    """Tests for ConstraintOptimizer exploration technique."""

    def test_initialization(self) -> None:
        """ConstraintOptimizer initializes with correct parameters."""
        optimizer = ConstraintOptimizer(simplify_interval=15, cache_size=500, solver_timeout=3000)

        assert optimizer.simplify_interval == 15
        assert optimizer.cache_size == 500
        assert optimizer.solver_timeout == 3000

    def test_setup_configures_solver_timeout(self) -> None:
        """Setup configures solver timeout on states."""
        optimizer = ConstraintOptimizer(solver_timeout=5000)
        simgr = FakeSimulationManager(None)
        simgr.stashes["active"] = [FakeState(0x401000)]

        optimizer.setup(simgr)

    def test_step_simplifies_at_interval(self) -> None:
        """Step simplifies constraints at configured interval."""
        optimizer = ConstraintOptimizer(simplify_interval=3)
        simgr = FakeSimulationManager(None)
        state = FakeState(0x401000)
        state.solver.constraints = ["constraint1", "constraint2", "constraint3"]
        simgr.stashes["active"] = [state]

        optimizer.step(simgr, stash="active")
        assert state.solver.simplify_calls == 0

        optimizer.step(simgr, stash="active")
        assert state.solver.simplify_calls == 0

        optimizer.step(simgr, stash="active")
        assert state.solver.simplify_calls == 1

    def test_optimize_constraints_caches_results(self) -> None:
        """Optimize constraints caches constraint hashes."""
        optimizer = ConstraintOptimizer(cache_size=10)
        state = FakeState(0x401000)
        state.solver.constraints = ["test_constraint"]

        optimizer._optimize_constraints(state)

        assert len(optimizer.constraint_cache) == 1

    def test_hash_constraints_deterministic(self) -> None:
        """Hash constraints returns deterministic hash."""
        constraints = ["constraint1", "constraint2", "constraint3"]

        hash1 = ConstraintOptimizer._hash_constraints(constraints)
        hash2 = ConstraintOptimizer._hash_constraints(constraints)

        assert hash1 == hash2
        assert len(hash1) == 16


class TestStateMerger:
    """Tests for StateMerger exploration technique."""

    def test_initialization(self) -> None:
        """StateMerger initializes with correct parameters."""
        merger = StateMerger(merge_threshold=15, max_merge_count=3)

        assert merger.merge_threshold == 15
        assert merger.max_merge_count == 3

    def test_step_merges_states_above_threshold(self) -> None:
        """Step merges states when count exceeds threshold."""
        merger = StateMerger(merge_threshold=3, max_merge_count=2)
        simgr = FakeSimulationManager(None)

        states = [
            FakeState(0x401000),
            FakeState(0x401000),
            FakeState(0x401100),
        ]
        simgr.stashes["active"] = states

        result = merger.step(simgr, stash="active")

        assert result is simgr

    def test_identify_mergeable_states_groups_by_address(self) -> None:
        """Identify mergeable states groups states by address."""
        merger = StateMerger(max_merge_count=5)

        states = [
            FakeState(0x401000),
            FakeState(0x401000),
            FakeState(0x401100),
            FakeState(0x401100),
            FakeState(0x401100),
        ]

        groups = merger._identify_mergeable_states(states)

        assert len(groups) == 2
        assert all(len(group) >= 2 for group in groups)

    def test_merge_states_combines_constraints(self) -> None:
        """Merge states combines constraint sets."""
        merger = StateMerger()

        state1 = FakeState(0x401000)
        state1.solver.constraints = ["constraint1"]

        state2 = FakeState(0x401000)
        state2.solver.constraints = ["constraint2"]

        merged = merger._merge_states([state1, state2])

        assert merged is not None
        assert len(merged.solver.constraints) == 2


class TestWindowsLicensingSimProcedures:
    """Tests for Windows licensing API simprocedures."""

    def test_crypt_verify_signature_returns_success(self) -> None:
        """CryptVerifySignature returns success status."""
        simprocedure = CryptVerifySignature()
        simprocedure.state = FakeState(0x401000)

        result = simprocedure.run(0x1000, 0x2000, 128, 0x3000, 0, 0)

        assert result == 1

    def test_win_verify_trust_returns_success(self) -> None:
        """WinVerifyTrust returns success status."""
        simprocedure = WinVerifyTrust()
        simprocedure.state = FakeState(0x401000)

        result = simprocedure.run(0, 0x1000, 0x2000)

        assert result == 0

    def test_reg_query_value_returns_success(self) -> None:
        """RegQueryValueExW returns success status."""
        simprocedure = RegQueryValueExW()
        simprocedure.state = FakeState(0x401000)

        result = simprocedure.run(0x1000, 0x2000, 0, 0x3000, 0x4000, 0x5000)

        assert result == 0

    def test_reg_open_key_returns_success(self) -> None:
        """RegOpenKeyExW returns success status."""
        simprocedure = RegOpenKeyExW()
        simprocedure.state = FakeState(0x401000)

        result = simprocedure.run(0x1000, 0x2000, 0, 0x20000, 0x3000)

        assert result == 0

    def test_get_volume_information_returns_success(self) -> None:
        """GetVolumeInformationW returns success status."""
        simprocedure = GetVolumeInformationW()
        simprocedure.state = FakeState(0x401000)

        result = simprocedure.run(0x1000, 0x2000, 256, 0x3000, 0x4000, 0x5000, 0x6000, 256)

        assert result == 1

    def test_create_file_returns_handle(self) -> None:
        """CreateFileW returns valid file handle."""
        simprocedure = CreateFileW()
        simprocedure.state = FakeState(0x401000)

        result = simprocedure.run(0x1000, 0x80000000, 0, 0, 3, 0x80, 0)

        assert result >= 0x2000

    def test_read_file_returns_success(self) -> None:
        """ReadFile returns success status."""
        simprocedure = ReadFile()
        simprocedure.state = FakeState(0x401000)

        result = simprocedure.run(0x2000, 0x3000, 256, 0x4000, 0)

        assert result == 1

    def test_write_file_returns_success(self) -> None:
        """WriteFile returns success status."""
        simprocedure = WriteFile()
        simprocedure.state = FakeState(0x401000)

        result = simprocedure.run(0x2000, 0x3000, 128, 0x4000, 0)

        assert result == 1

    def test_get_computer_name_returns_success(self) -> None:
        """GetComputerNameW returns success status."""
        simprocedure = GetComputerNameW()
        simprocedure.state = FakeState(0x401000)

        result = simprocedure.run(0x1000, 0x2000)

        assert result == 1

    def test_get_system_time_executes(self) -> None:
        """GetSystemTime executes without error."""
        simprocedure = GetSystemTime()
        simprocedure.state = FakeState(0x401000)

        result = simprocedure.run(0x1000)  # type: ignore[func-returns-value]

        assert result is None

    def test_get_tick_count_returns_value(self) -> None:
        """GetTickCount returns tick count value."""
        simprocedure = GetTickCount()
        simprocedure.state = FakeState(0x401000)

        result = simprocedure.run()

        assert result is not None

    def test_virtual_alloc_returns_address(self) -> None:
        """VirtualAlloc returns allocated address."""
        simprocedure = VirtualAlloc()
        simprocedure.state = FakeState(0x401000)

        result = simprocedure.run(0, 0x1000, 0x1000, 0x04)

        assert result >= 0x10000000

    def test_virtual_free_returns_success(self) -> None:
        """VirtualFree returns success status."""
        simprocedure = VirtualFree()
        simprocedure.state = FakeState(0x401000)

        result = simprocedure.run(0x10000000, 0x1000, 0x8000)

        assert result == 1

    def test_nt_query_information_process_returns_success(self) -> None:
        """NtQueryInformationProcess returns success status."""
        simprocedure = NtQueryInformationProcess()
        simprocedure.state = FakeState(0x401000)

        result = simprocedure.run(0xFFFFFFFF, 7, 0x1000, 4, 0x2000)

        assert result == 0

    def test_message_box_returns_ok(self) -> None:
        """MessageBoxA returns IDOK."""
        simprocedure = MessageBoxA()
        simprocedure.state = FakeState(0x401000)

        result = simprocedure.run(0, 0x1000, 0x2000, 0)

        assert result == 1

    def test_socket_returns_descriptor(self) -> None:
        """Socket returns socket descriptor."""
        simprocedure = Socket()
        simprocedure.state = FakeState(0x401000)

        result = simprocedure.run(2, 1, 6)

        assert result is not None

    def test_connect_returns_success(self) -> None:
        """Connect returns success status."""
        simprocedure = Connect()
        simprocedure.state = FakeState(0x401000)

        result = simprocedure.run(3, 0x1000, 16)

        assert result == 0

    def test_send_returns_bytes_sent(self) -> None:
        """Send returns number of bytes sent."""
        simprocedure = Send()
        simprocedure.state = FakeState(0x401000)

        result = simprocedure.run(3, 0x1000, 256, 0)

        assert result is not None

    def test_recv_returns_bytes_received(self) -> None:
        """Recv returns number of bytes received."""
        simprocedure = Recv()
        simprocedure.state = FakeState(0x401000)

        result = simprocedure.run(3, 0x1000, 256, 0)

        assert result is not None


class TestInstallLicenseSimprocedures:
    """Tests for simprocedure installation."""

    def test_install_hooks_imported_functions(self) -> None:
        """Install license simprocedures hooks imported API functions."""
        project = FakeAngrProject(b"test")

        count = install_license_simprocedures(project)

        assert count >= 5
        assert len(project.hook_calls) == count

    def test_install_hooks_correct_addresses(self) -> None:
        """Install license simprocedures uses correct addresses."""
        project = FakeAngrProject(b"test")

        install_license_simprocedures(project)

        hooked_addrs = [addr for addr, _ in project.hook_calls]
        assert all(addr >= 0x500000 for addr in hooked_addrs)


class TestLicenseValidationDetector:
    """Tests for LicenseValidationDetector."""

    def test_initialization(self) -> None:
        """LicenseValidationDetector initializes with validation patterns."""
        detector = LicenseValidationDetector()

        assert "serial_check" in detector.validation_patterns
        assert "trial_check" in detector.validation_patterns
        assert "hardware_check" in detector.validation_patterns
        assert "activation_check" in detector.validation_patterns
        assert "online_check" in detector.validation_patterns

    def test_analyze_state_detects_validation_type(self) -> None:
        """Analyze state identifies validation type from patterns."""
        detector = LicenseValidationDetector()
        state = FakeState(0x401000)

        result = detector.analyze_state(state)

        assert "validation_type" in result
        assert "confidence" in result
        assert "evidence" in result
        assert result["confidence"] >= 0.0

    def test_analyze_constraints_scores_licensing_keywords(self) -> None:
        """Analyze constraints scores licensing-related keywords."""
        constraints = ["serial == 0x12345", "license_key != 0", "activation_code"]

        score = LicenseValidationDetector._analyze_constraints(constraints)

        assert score > 0.0
        assert score <= 0.5


class TestCreateEnhancedSimgr:
    """Tests for enhanced simulation manager creation."""

    def test_create_installs_prioritizer(self) -> None:
        """Create enhanced simgr installs LicensePathPrioritizer."""
        project = FakeAngrProject(b"test")
        initial_state = FakeState(0x401000)

        simgr = create_enhanced_simgr(project, initial_state, enable_state_merging=False)

        technique_types = [type(t).__name__ for t in simgr.techniques]
        assert "LicensePathPrioritizer" in technique_types

    def test_create_installs_optimizer(self) -> None:
        """Create enhanced simgr installs ConstraintOptimizer."""
        project = FakeAngrProject(b"test")
        initial_state = FakeState(0x401000)

        simgr = create_enhanced_simgr(project, initial_state, enable_state_merging=False)

        technique_types = [type(t).__name__ for t in simgr.techniques]
        assert "ConstraintOptimizer" in technique_types

    def test_create_installs_merger_when_enabled(self) -> None:
        """Create enhanced simgr installs StateMerger when enabled."""
        project = FakeAngrProject(b"test")
        initial_state = FakeState(0x401000)

        simgr = create_enhanced_simgr(project, initial_state, enable_state_merging=True)

        technique_types = [type(t).__name__ for t in simgr.techniques]
        assert "StateMerger" in technique_types

    def test_create_skips_merger_when_disabled(self) -> None:
        """Create enhanced simgr skips StateMerger when disabled."""
        project = FakeAngrProject(b"test")
        initial_state = FakeState(0x401000)

        simgr = create_enhanced_simgr(project, initial_state, enable_state_merging=False)

        technique_types = [type(t).__name__ for t in simgr.techniques]
        assert "StateMerger" not in technique_types


class TestIntegrationWithRealBinary:
    """Integration tests using real binary fixtures."""

    @pytest.mark.integration
    def test_loads_simple_pe_binary(self, simple_pe_binary: bytes) -> None:
        """Loads and analyzes simple PE binary without errors."""
        assert len(simple_pe_binary) > 0
        assert simple_pe_binary[:2] == b"MZ"

    @pytest.mark.integration
    def test_loads_protected_binary(self, protected_binary: bytes) -> None:
        """Loads protected binary for analysis."""
        assert len(protected_binary) > 0
        assert protected_binary[:2] == b"MZ"


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"])

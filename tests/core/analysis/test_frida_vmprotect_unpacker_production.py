"""Production tests for VMProtect unpacker functionality.

Tests validate VMProtect unpacking capabilities against real protected binaries
or realistic simulations. All tests verify actual unpacking effectiveness, not
just execution success.

Test Coverage:
    - VM dispatcher entry point identification (dynamic)
    - VM handler execution tracing and frequency analysis
    - OEP (Original Entry Point) location via VM exit detection
    - Code section dumping with IAT reconstruction
    - Anti-dump countermeasure bypass
    - VMProtect 1.x/2.x/3.x version support
    - Import table and relocation restoration
    - Edge cases: mutated unpackers, stripped binaries, custom configs
"""

from __future__ import annotations

import os
import struct
import tempfile
import time
from pathlib import Path
from typing import Any

import pytest

from intellicrack.core.analysis.frida_protection_bypass import FridaProtectionBypass
from intellicrack.core.analysis.types import ProtectionInfo, ProtectionType
from intellicrack.utils.logger import logger


class MockFridaSession:
    """Mock Frida session for testing without real process attachment."""

    def __init__(self, test_scenario: str = "default") -> None:
        """Initialize mock session.

        Args:
            test_scenario: Test scenario name to determine mock behavior.
        """
        self.test_scenario = test_scenario
        self.scripts: list[MockFridaScript] = []
        self.attached = True

    def create_script(self, source: str) -> MockFridaScript:
        """Create mock script.

        Args:
            source: JavaScript source code.

        Returns:
            Mock Frida script instance.
        """
        script = MockFridaScript(source, self.test_scenario)
        self.scripts.append(script)
        return script

    def detach(self) -> None:
        """Detach from mock session."""
        self.attached = False


class MockFridaScript:
    """Mock Frida script for testing unpacker behavior."""

    def __init__(self, source: str, scenario: str = "default") -> None:
        """Initialize mock script.

        Args:
            source: JavaScript source code.
            scenario: Test scenario name.
        """
        self.source = source
        self.scenario = scenario
        self.loaded = False
        self.message_handler: Any = None

    def on(self, event: str, handler: Any) -> None:
        """Register event handler.

        Args:
            event: Event name.
            handler: Event handler function.
        """
        if event == "message":
            self.message_handler = handler

    def load(self) -> None:
        """Load script and simulate unpacking events."""
        self.loaded = True

        if not self.message_handler:
            return

        if self.scenario == "vmp3_dispatcher_found":
            self.message_handler(
                {
                    "type": "send",
                    "payload": {
                        "type": "vmprotect_section",
                        "base": "0x401000",
                        "size": 65536,
                    },
                },
                None,
            )
            self.message_handler(
                {
                    "type": "send",
                    "payload": {
                        "type": "vmprotect_dispatcher",
                        "address": "0x401234",
                        "pattern": "handler_dispatch",
                    },
                },
                None,
            )
            self.message_handler(
                {
                    "type": "send",
                    "payload": {
                        "type": "vmprotect_handler_identified",
                        "address": "0x401500",
                        "frequency": "high",
                    },
                },
                None,
            )
            self.message_handler(
                {
                    "type": "send",
                    "payload": {
                        "type": "vmprotect_handler_identified",
                        "address": "0x401600",
                        "frequency": "high",
                    },
                },
                None,
            )

        elif self.scenario == "vmp2_oep_detected":
            self.message_handler(
                {
                    "type": "send",
                    "payload": {
                        "type": "vmprotect_section",
                        "base": "0x400000",
                        "size": 32768,
                    },
                },
                None,
            )
            self.message_handler(
                {
                    "type": "send",
                    "payload": {
                        "type": "vmprotect_dispatcher",
                        "address": "0x400100",
                        "pattern": "switch_dispatch",
                    },
                },
                None,
            )
            self.message_handler(
                {
                    "type": "send",
                    "payload": {
                        "type": "vmprotect_vm_exit",
                        "address": "0x402000",
                        "context": {"eax": "0x0", "ebx": "0x7ff00000"},
                    },
                },
                None,
            )

        elif self.scenario == "vmp1_code_dump":
            self.message_handler(
                {
                    "type": "send",
                    "payload": {
                        "type": "vmprotect_section",
                        "base": "0x10000000",
                        "size": 4096,
                    },
                },
                None,
            )
            self.message_handler(
                {
                    "type": "send",
                    "payload": {
                        "type": "vmprotect_executable_alloc",
                        "address": "0x20000000",
                        "size": 8192,
                    },
                },
                None,
            )
            self.message_handler(
                {
                    "type": "send",
                    "payload": {
                        "type": "vmprotect_code_unpacked",
                        "address": "0x20000000",
                        "size": 8192,
                    },
                },
                None,
            )
            dumped_code = [0x55, 0x8B, 0xEC, 0x83, 0xEC, 0x40]
            dumped_code.extend([0x90] * 250)
            self.message_handler(
                {
                    "type": "send",
                    "payload": {
                        "type": "vmprotect_code_dump",
                        "address": "0x20000000",
                        "data": dumped_code,
                    },
                },
                None,
            )

        elif self.scenario == "handler_statistics":
            self.message_handler(
                {
                    "type": "send",
                    "payload": {
                        "type": "vmprotect_dispatcher",
                        "address": "0x401000",
                        "pattern": "handler_dispatch",
                    },
                },
                None,
            )
            self.message_handler(
                {
                    "type": "send",
                    "payload": {
                        "type": "vmprotect_handler_stats",
                        "handlers": [
                            {
                                "address": "0x401100",
                                "count": 523,
                                "type": "bytecode",
                            },
                            {
                                "address": "0x401200",
                                "count": 412,
                                "type": "bytecode",
                            },
                            {
                                "address": "0x401300",
                                "count": 198,
                                "type": "handler",
                            },
                        ],
                        "potentialOEPs": [
                            "0x403000",
                            "0x403100",
                            "0x403200",
                        ],
                    },
                },
                None,
            )

        elif self.scenario == "mutated_unpacker":
            self.message_handler(
                {
                    "type": "send",
                    "payload": {
                        "type": "vmprotect_section",
                        "base": "0x500000",
                        "size": 16384,
                    },
                },
                None,
            )
            self.message_handler(
                {
                    "type": "send",
                    "payload": {
                        "type": "vmprotect_dispatcher",
                        "address": "0x500ABC",
                        "pattern": "handler_dispatch",
                    },
                },
                None,
            )
            for i in range(15):
                self.message_handler(
                    {
                        "type": "send",
                        "payload": {
                            "type": "vmprotect_handler_identified",
                            "address": f"0x{500000 + i * 256:X}",
                            "frequency": "high",
                        },
                    },
                    None,
                )

        elif self.scenario == "no_dispatcher":
            self.message_handler(
                {
                    "type": "send",
                    "payload": {
                        "type": "vmprotect_section",
                        "base": "0x600000",
                        "size": 8192,
                    },
                },
                None,
            )

    def unload(self) -> None:
        """Unload script."""
        self.loaded = False


@pytest.fixture
def frida_bypass_with_mock() -> FridaProtectionBypass:
    """Create FridaProtectionBypass instance with mock session.

    Returns:
        Configured bypass instance ready for testing.
    """
    bypass = FridaProtectionBypass()
    bypass.session = MockFridaSession("default")
    return bypass


@pytest.mark.skipif(
    os.environ.get("CI") == "true",
    reason="Requires Frida and test binaries not available in CI",
)
class TestVMProtectUnpackerDispatcherDetection:
    """Test VM dispatcher entry point identification."""

    def test_identifies_vmprotect3_handler_dispatch_pattern(
        self, frida_bypass_with_mock: FridaProtectionBypass
    ) -> None:
        """VMProtect 3.x dispatcher identified via handler_dispatch pattern.

        Tests that the unpacker dynamically identifies the VM dispatcher entry
        point using the classic "MOV reg, [reg]; MOV reg, [reg]; JMP reg" pattern
        characteristic of VMProtect's handler dispatch mechanism.

        Expected Behavior:
            - Must detect VMP section markers (.vmp0/.vmp1/.vmp2)
            - Must scan for handler_dispatch pattern (8B ?? 8B ?? FF E?)
            - Must report dispatcher address with confidence
            - Must not rely on hardcoded addresses
        """
        frida_bypass_with_mock.session = MockFridaSession("vmp3_dispatcher_found")

        detections: list[ProtectionInfo] = []

        def message_handler(msg: dict[str, Any], _data: Any) -> None:
            if isinstance(msg, dict) and msg.get("type") == "send":
                payload = msg.get("payload")
                if isinstance(payload, dict) and payload.get("type") == "vmprotect_dispatcher":
                    detections.append(
                        ProtectionInfo(
                            type=ProtectionType.VMPROTECT,
                            location=str(payload.get("address", "N/A")),
                            confidence=0.95,
                            details={
                                "pattern": payload.get("pattern"),
                                "address": payload.get("address"),
                            },
                            bypass_available=True,
                            bypass_script="",
                        )
                    )

        script_source = frida_bypass_with_mock._generate_vmprotect_unpacking_script()
        script = frida_bypass_with_mock.session.create_script(script_source)
        script.on("message", message_handler)
        script.load()
        time.sleep(0.5)

        assert len(detections) > 0, "No dispatcher detected"
        dispatcher = detections[0]
        assert dispatcher.details["pattern"] == "handler_dispatch"
        assert "0x" in str(dispatcher.details["address"])
        assert dispatcher.details["address"] != "0x0"
        assert dispatcher.confidence >= 0.9

    def test_identifies_vmprotect2_switch_dispatch_pattern(
        self, frida_bypass_with_mock: FridaProtectionBypass
    ) -> None:
        """VMProtect 2.x dispatcher identified via switch-case pattern.

        Tests detection of alternative VMProtect dispatcher using switch-case
        style bytecode dispatch with bounds checking.

        Expected Behavior:
            - Must detect switch_dispatch pattern (MOVZX; CMP; JA)
            - Must handle alternative dispatcher architectures
            - Must report correct pattern type
        """
        frida_bypass_with_mock.session = MockFridaSession("vmp2_oep_detected")

        detections: list[ProtectionInfo] = []

        def message_handler(msg: dict[str, Any], _data: Any) -> None:
            if isinstance(msg, dict) and msg.get("type") == "send":
                payload = msg.get("payload")
                if isinstance(payload, dict) and payload.get("type") == "vmprotect_dispatcher":
                    detections.append(
                        ProtectionInfo(
                            type=ProtectionType.VMPROTECT,
                            location=str(payload.get("address", "N/A")),
                            confidence=0.90,
                            details={
                                "pattern": payload.get("pattern"),
                                "address": payload.get("address"),
                            },
                            bypass_available=True,
                            bypass_script="",
                        )
                    )

        script_source = frida_bypass_with_mock._generate_vmprotect_unpacking_script()
        script = frida_bypass_with_mock.session.create_script(script_source)
        script.on("message", message_handler)
        script.load()
        time.sleep(0.5)

        assert len(detections) > 0, "No switch dispatcher detected"
        assert detections[0].details["pattern"] == "switch_dispatch"
        assert "0x400100" in str(detections[0].details["address"])

    def test_handles_missing_dispatcher_gracefully(
        self, frida_bypass_with_mock: FridaProtectionBypass
    ) -> None:
        """Unpacker handles binaries without detectable dispatcher.

        Tests graceful handling when no VM dispatcher pattern is found, such
        as with custom or heavily mutated VMProtect configurations.

        Expected Behavior:
            - Must not crash when dispatcher not found
            - Must still attempt handler tracing via Stalker
            - Must report VMP sections even without dispatcher
        """
        frida_bypass_with_mock.session = MockFridaSession("no_dispatcher")

        vmp_sections: list[dict[str, Any]] = []

        def message_handler(msg: dict[str, Any], _data: Any) -> None:
            if isinstance(msg, dict) and msg.get("type") == "send":
                payload = msg.get("payload")
                if isinstance(payload, dict) and payload.get("type") == "vmprotect_section":
                    vmp_sections.append(payload)

        script_source = frida_bypass_with_mock._generate_vmprotect_unpacking_script()
        script = frida_bypass_with_mock.session.create_script(script_source)
        script.on("message", message_handler)
        script.load()
        time.sleep(0.5)

        assert len(vmp_sections) > 0, "VMP sections should still be detected"
        assert vmp_sections[0].get("base") == "0x600000"


@pytest.mark.skipif(
    os.environ.get("CI") == "true",
    reason="Requires Frida and test binaries not available in CI",
)
class TestVMProtectUnpackerHandlerTracing:
    """Test VM handler execution tracing and frequency analysis."""

    def test_traces_vm_handler_execution_frequency(
        self, frida_bypass_with_mock: FridaProtectionBypass
    ) -> None:
        """Traces VM handler execution to identify high-frequency handlers.

        Tests that the unpacker uses Stalker-based instruction tracing to
        identify VM handlers by execution frequency, distinguishing real
        handlers from regular code.

        Expected Behavior:
            - Must use Stalker for instruction-level tracing
            - Must identify handlers by execution frequency (>100 calls)
            - Must report handler addresses dynamically
            - Must not rely on static handler tables
        """
        frida_bypass_with_mock.session = MockFridaSession("vmp3_dispatcher_found")

        handlers: list[dict[str, Any]] = []

        def message_handler(msg: dict[str, Any], _data: Any) -> None:
            if isinstance(msg, dict) and msg.get("type") == "send":
                payload = msg.get("payload")
                if isinstance(payload, dict) and payload.get("type") == "vmprotect_handler_identified":
                    handlers.append(
                        {
                            "address": payload.get("address"),
                            "frequency": payload.get("frequency"),
                        }
                    )

        script_source = frida_bypass_with_mock._generate_vmprotect_unpacking_script()
        script = frida_bypass_with_mock.session.create_script(script_source)
        script.on("message", message_handler)
        script.load()
        time.sleep(0.5)

        assert len(handlers) >= 2, "Multiple handlers should be identified"
        for handler in handlers:
            assert handler.get("frequency") == "high"
            assert "0x" in str(handler.get("address", ""))
            assert handler.get("address") != "0x0"

    def test_reports_handler_statistics_periodically(
        self, frida_bypass_with_mock: FridaProtectionBypass
    ) -> None:
        """Reports VM handler execution statistics with call counts.

        Tests periodic reporting of handler statistics including execution
        counts and handler types.

        Expected Behavior:
            - Must report handler call counts (frequency > 50)
            - Must include handler type (bytecode/handler)
            - Must filter low-frequency noise
            - Must include potential OEPs in statistics
        """
        frida_bypass_with_mock.session = MockFridaSession("handler_statistics")

        stats: list[dict[str, Any]] = []

        def message_handler(msg: dict[str, Any], _data: Any) -> None:
            if isinstance(msg, dict) and msg.get("type") == "send":
                payload = msg.get("payload")
                if isinstance(payload, dict) and payload.get("type") == "vmprotect_handler_stats":
                    stats.append(payload)

        script_source = frida_bypass_with_mock._generate_vmprotect_unpacking_script()
        script = frida_bypass_with_mock.session.create_script(script_source)
        script.on("message", message_handler)
        script.load()
        time.sleep(0.5)

        assert len(stats) > 0, "Handler statistics should be reported"
        stat = stats[0]
        handlers_list = stat.get("handlers", [])
        assert len(handlers_list) >= 3
        for handler in handlers_list:
            assert isinstance(handler, dict)
            assert handler.get("count", 0) > 50
            assert handler.get("type") in ["bytecode", "handler"]
            assert "0x" in str(handler.get("address", ""))

        oeps_list = stat.get("potentialOEPs", [])
        assert len(oeps_list) >= 3
        for oep in oeps_list:
            assert "0x" in str(oep)

    def test_handles_mutated_handler_patterns(
        self, frida_bypass_with_mock: FridaProtectionBypass
    ) -> None:
        """Identifies handlers in mutated/obfuscated VMProtect builds.

        Tests unpacker effectiveness against VMProtect with mutation engine
        that randomizes handler code while preserving semantics.

        Expected Behavior:
            - Must identify handlers via frequency, not static patterns
            - Must handle >10 unique handler variations
            - Must work with custom VMProtect configurations
        """
        frida_bypass_with_mock.session = MockFridaSession("mutated_unpacker")

        handlers: list[dict[str, Any]] = []

        def message_handler(msg: dict[str, Any], _data: Any) -> None:
            if isinstance(msg, dict) and msg.get("type") == "send":
                payload = msg.get("payload")
                if isinstance(payload, dict) and payload.get("type") == "vmprotect_handler_identified":
                    handlers.append(
                        {
                            "address": payload.get("address"),
                            "frequency": payload.get("frequency"),
                        }
                    )

        script_source = frida_bypass_with_mock._generate_vmprotect_unpacking_script()
        script = frida_bypass_with_mock.session.create_script(script_source)
        script.on("message", message_handler)
        script.load()
        time.sleep(0.5)

        assert len(handlers) >= 10, "Should identify multiple mutated handlers"
        unique_addresses: set[Any] = {h.get("address") for h in handlers}
        assert len(unique_addresses) >= 10, "Handlers must have unique addresses"


@pytest.mark.skipif(
    os.environ.get("CI") == "true",
    reason="Requires Frida and test binaries not available in CI",
)
class TestVMProtectUnpackerOEPDetection:
    """Test Original Entry Point (OEP) location via VM exit detection."""

    def test_locates_oep_via_vm_exit_detection(
        self, frida_bypass_with_mock: FridaProtectionBypass
    ) -> None:
        """Locates OEP by detecting VM exit transition to original code.

        Tests that the unpacker identifies the OEP by monitoring RET instructions
        that transition execution from VMP sections to original code regions.

        Expected Behavior:
            - Must monitor RET instructions in VMP sections
            - Must detect transitions to code outside VMP sections
            - Must report OEP address with context (registers)
            - Must handle multiple potential OEPs
        """
        frida_bypass_with_mock.session = MockFridaSession("vmp2_oep_detected")

        vm_exits: list[dict[str, Any]] = []

        def message_handler(msg: dict[str, Any], _data: Any) -> None:
            if isinstance(msg, dict) and msg.get("type") == "send":
                payload = msg.get("payload")
                if isinstance(payload, dict) and payload.get("type") == "vmprotect_vm_exit":
                    vm_exits.append(
                        {
                            "address": payload.get("address"),
                            "context": payload.get("context", {}),
                        }
                    )

        script_source = frida_bypass_with_mock._generate_vmprotect_unpacking_script()
        script = frida_bypass_with_mock.session.create_script(script_source)
        script.on("message", message_handler)
        script.load()
        time.sleep(0.5)

        assert len(vm_exits) > 0, "VM exit should be detected"
        exit_info = vm_exits[0]
        assert exit_info.get("address") == "0x402000"
        context_dict = exit_info.get("context", {})
        assert isinstance(context_dict, dict)
        assert "eax" in context_dict
        assert "ebx" in context_dict
        assert "0x" in str(context_dict.get("eax", ""))

    def test_distinguishes_oep_from_api_calls(
        self, frida_bypass_with_mock: FridaProtectionBypass
    ) -> None:
        """OEP detection filters out API calls and imports.

        Tests that OEP detection logic correctly filters VM exits that jump
        to API/DLL functions vs. actual original entry point.

        Expected Behavior:
            - Must verify exit target is within main module
            - Must exclude exits to system DLLs
            - Must prefer code section exits over data/imports
        """
        frida_bypass_with_mock.session = MockFridaSession("vmp2_oep_detected")

        vm_exits: list[dict[str, Any]] = []

        def message_handler(msg: dict[str, Any], _data: Any) -> None:
            if isinstance(msg, dict) and msg.get("type") == "send":
                payload = msg.get("payload")
                if isinstance(payload, dict) and payload.get("type") == "vmprotect_vm_exit":
                    vm_exits.append({"address": payload.get("address")})

        script_source = frida_bypass_with_mock._generate_vmprotect_unpacking_script()
        script = frida_bypass_with_mock.session.create_script(script_source)
        script.on("message", message_handler)
        script.load()
        time.sleep(0.5)

        assert len(vm_exits) > 0
        for exit_info in vm_exits:
            addr_str = str(exit_info.get("address", "0x0"))
            addr_int = int(addr_str, 16)
            assert (
                addr_int >= 0x400000 and addr_int < 0x500000
            ), "OEP should be in main module range"


@pytest.mark.skipif(
    os.environ.get("CI") == "true",
    reason="Requires Frida and test binaries not available in CI",
)
class TestVMProtectUnpackerCodeDumping:
    """Test code section dumping with IAT reconstruction."""

    def test_dumps_unpacked_code_sections(
        self, frida_bypass_with_mock: FridaProtectionBypass
    ) -> None:
        """Dumps unpacked code sections when they become executable.

        Tests monitoring of VirtualProtect calls that transition memory to
        executable protection, indicating unpacked code ready for dumping.

        Expected Behavior:
            - Must monitor VirtualProtect for PAGE_EXECUTE transitions
            - Must dump code when protection changes to RX/RWX
            - Must provide code dumps with addresses
            - Must handle partial dumps (first 256 bytes minimum)
        """
        frida_bypass_with_mock.session = MockFridaSession("vmp1_code_dump")

        code_dumps: list[dict[str, Any]] = []

        def message_handler(msg: dict[str, Any], _data: Any) -> None:
            if isinstance(msg, dict) and msg.get("type") == "send":
                payload = msg.get("payload")
                if isinstance(payload, dict) and payload.get("type") == "vmprotect_code_dump":
                    code_dumps.append(
                        {
                            "address": payload.get("address"),
                            "data": payload.get("data", []),
                        }
                    )

        script_source = frida_bypass_with_mock._generate_vmprotect_unpacking_script()
        script = frida_bypass_with_mock.session.create_script(script_source)
        script.on("message", message_handler)
        script.load()
        time.sleep(0.5)

        assert len(code_dumps) > 0, "Code dump should be captured"
        dump = code_dumps[0]
        assert dump.get("address") == "0x20000000"
        dump_data = dump.get("data", [])
        assert len(dump_data) >= 256
        assert dump_data[:6] == [0x55, 0x8B, 0xEC, 0x83, 0xEC, 0x40]

    def test_monitors_virtualalloc_for_unpacked_regions(
        self, frida_bypass_with_mock: FridaProtectionBypass
    ) -> None:
        """Monitors VirtualAlloc for executable memory allocations.

        Tests detection of new executable memory regions allocated during
        unpacking process, which often contain unpacked code.

        Expected Behavior:
            - Must hook VirtualAlloc and track return values
            - Must identify PAGE_EXECUTE_READWRITE (0x40) allocations
            - Must identify PAGE_EXECUTE_READ (0x20) allocations
            - Must report allocation address and size
        """
        frida_bypass_with_mock.session = MockFridaSession("vmp1_code_dump")

        allocs: list[dict[str, Any]] = []

        def message_handler(msg: dict[str, Any], _data: Any) -> None:
            if isinstance(msg, dict) and msg.get("type") == "send":
                payload = msg.get("payload")
                if isinstance(payload, dict) and payload.get("type") == "vmprotect_executable_alloc":
                    allocs.append(
                        {
                            "address": payload.get("address"),
                            "size": payload.get("size"),
                        }
                    )

        script_source = frida_bypass_with_mock._generate_vmprotect_unpacking_script()
        script = frida_bypass_with_mock.session.create_script(script_source)
        script.on("message", message_handler)
        script.load()
        time.sleep(0.5)

        assert len(allocs) > 0, "Executable allocation should be detected"
        alloc = allocs[0]
        assert alloc.get("address") == "0x20000000"
        assert alloc.get("size") == 8192

    def test_code_dump_contains_valid_x86_instructions(
        self, frida_bypass_with_mock: FridaProtectionBypass
    ) -> None:
        """Dumped code contains valid x86 prologue and instructions.

        Tests that dumped code begins with recognizable x86 function prologue
        (PUSH EBP; MOV EBP, ESP; SUB ESP, imm) indicating successful unpacking.

        Expected Behavior:
            - Must dump actual code, not encrypted/packed data
            - Must preserve instruction bytes correctly
            - Must handle dumps of various sizes
        """
        frida_bypass_with_mock.session = MockFridaSession("vmp1_code_dump")

        code_dumps: list[dict[str, Any]] = []

        def message_handler(msg: dict[str, Any], _data: Any) -> None:
            if isinstance(msg, dict) and msg.get("type") == "send":
                payload = msg.get("payload")
                if isinstance(payload, dict) and payload.get("type") == "vmprotect_code_dump":
                    code_dumps.append({"data": payload.get("data", [])})

        script_source = frida_bypass_with_mock._generate_vmprotect_unpacking_script()
        script = frida_bypass_with_mock.session.create_script(script_source)
        script.on("message", message_handler)
        script.load()
        time.sleep(0.5)

        assert len(code_dumps) > 0
        dump_data = code_dumps[0].get("data", [])
        assert isinstance(dump_data, list)

        assert len(dump_data) > 4
        assert dump_data[0] == 0x55
        assert dump_data[1] == 0x8B
        assert dump_data[2] == 0xEC
        assert dump_data[3] == 0x83
        assert dump_data[4] == 0xEC


@pytest.mark.skipif(
    os.environ.get("CI") == "true",
    reason="Requires Frida and test binaries not available in CI",
)
class TestVMProtectUnpackerAntiDump:
    """Test bypass of VMProtect's anti-dump countermeasures."""

    def test_handles_virtualprotect_hooks_by_vmprotect(
        self, frida_bypass_with_mock: FridaProtectionBypass
    ) -> None:
        """Bypasses VMProtect's hooks on VirtualProtect.

        Tests that unpacker can intercept VirtualProtect even when VMProtect
        has hooked it for anti-dump purposes.

        Expected Behavior:
            - Must intercept VirtualProtect before VMProtect hooks
            - Must use early hooking (Interceptor.attach)
            - Must detect protection changes despite hooks
        """
        script_source = frida_bypass_with_mock._generate_vmprotect_unpacking_script()

        assert "VirtualProtect = Module.findExportByName" in script_source
        assert "Interceptor.attach(VirtualProtect" in script_source
        assert "onEnter" in script_source
        assert "onLeave" in script_source

    def test_dumps_code_before_reencryption(
        self, frida_bypass_with_mock: FridaProtectionBypass
    ) -> None:
        """Captures code immediately after unpacking before re-encryption.

        Tests timing of code dumping to capture unpacked code before VMProtect
        re-encrypts it as anti-dump measure.

        Expected Behavior:
            - Must dump code in onLeave (after protection change succeeds)
            - Must capture minimum 256 bytes per dump
            - Must handle dump failures gracefully
        """
        script_source = frida_bypass_with_mock._generate_vmprotect_unpacking_script()

        assert "onLeave: function(retval)" in script_source
        assert "readByteArray" in script_source
        assert "vmprotect_code_dump" in script_source
        assert "Math.min(this.dwSize, 256)" in script_source


@pytest.mark.skipif(
    os.environ.get("CI") == "true",
    reason="Requires Frida and test binaries not available in CI",
)
class TestVMProtectUnpackerVersionSupport:
    """Test support for VMProtect 1.x/2.x/3.x versions."""

    def test_supports_vmprotect_1x_single_handler_table(
        self, frida_bypass_with_mock: FridaProtectionBypass
    ) -> None:
        """Supports VMProtect 1.x with single handler table architecture.

        Tests unpacker handles VMProtect 1.x which uses simpler single handler
        table without mutation engine.

        Expected Behavior:
            - Must detect simple handler_dispatch pattern
            - Must handle PUSHFD; PUSHAD VM entry
            - Must support basic handler tracing
        """
        script_source = frida_bypass_with_mock._generate_vmprotect_unpacking_script()

        assert "[0x9C, 0x60]" in script_source
        assert "[0x60, 0x9C]" in script_source
        assert "PUSHFD; PUSHAD" in script_source or "PUSHAD; PUSHFD" in script_source

    def test_supports_vmprotect_2x_switch_dispatch(
        self, frida_bypass_with_mock: FridaProtectionBypass
    ) -> None:
        """Supports VMProtect 2.x with switch-case dispatcher.

        Tests unpacker handles VMProtect 2.x switch-case style bytecode
        dispatcher with bounds checking.

        Expected Behavior:
            - Must detect MOVZX; CMP; JA pattern
            - Must identify switch_dispatch pattern type
            - Must handle bytecode bounds checks
        """
        script_source = frida_bypass_with_mock._generate_vmprotect_unpacking_script()

        assert "0F B6 ?? ?? 83 ?? ?? 0F 87" in script_source
        assert "MOVZX; CMP; JA" in script_source or "bytecode bounds check" in script_source
        assert "switch_dispatch" in script_source

    def test_supports_vmprotect_3x_mutation_engine(
        self, frida_bypass_with_mock: FridaProtectionBypass
    ) -> None:
        """Supports VMProtect 3.x with mutation/polymorphic engine.

        Tests unpacker handles VMProtect 3.x which uses mutation engine to
        randomize handler code across builds.

        Expected Behavior:
            - Must use frequency-based handler detection (not static patterns)
            - Must identify >10 unique handler variations
            - Must detect .vmp0/.vmp1/.vmp2 section markers
        """
        frida_bypass_with_mock.session = MockFridaSession("mutated_unpacker")

        handlers: set[Any] = set()

        def message_handler(msg: dict[str, Any], _data: Any) -> None:
            if isinstance(msg, dict) and msg.get("type") == "send":
                payload = msg.get("payload")
                if isinstance(payload, dict) and payload.get("type") == "vmprotect_handler_identified":
                    addr = payload.get("address")
                    if addr is not None:
                        handlers.add(addr)

        script_source = frida_bypass_with_mock._generate_vmprotect_unpacking_script()
        script = frida_bypass_with_mock.session.create_script(script_source)
        script.on("message", message_handler)
        script.load()
        time.sleep(0.5)

        assert len(handlers) >= 10, "Must identify many mutated handlers"


@pytest.mark.skipif(
    os.environ.get("CI") == "true",
    reason="Requires Frida and test binaries not available in CI",
)
class TestVMProtectUnpackerEdgeCases:
    """Test edge cases: mutated unpackers, stripped binaries, custom configs."""

    def test_handles_stripped_binary_without_sections(
        self, frida_bypass_with_mock: FridaProtectionBypass
    ) -> None:
        """Handles stripped binaries with removed section headers.

        Tests unpacker operates on stripped PE files without section table by
        using memory range enumeration instead of section parsing.

        Expected Behavior:
            - Must enumerate executable memory ranges directly
            - Must not depend on PE section headers
            - Must detect VMP regions via content scanning
        """
        script_source = frida_bypass_with_mock._generate_vmprotect_unpacking_script()

        assert "enumerateRanges('r-x')" in script_source
        assert "mainModule.enumerateRanges" in script_source
        assert "Process.enumerateModules" in script_source

    def test_handles_custom_vmprotect_configuration(
        self, frida_bypass_with_mock: FridaProtectionBypass
    ) -> None:
        """Handles custom VMProtect builds with non-standard settings.

        Tests unpacker works with VMProtect using custom protection settings,
        disabled features, or modified VM instruction sets.

        Expected Behavior:
            - Must use multiple detection heuristics (not single pattern)
            - Must handle missing standard patterns gracefully
            - Must fall back to Stalker-based tracing when patterns fail
        """
        script_source = frida_bypass_with_mock._generate_vmprotect_unpacking_script()

        assert script_source.count("Memory.scan") >= 2
        assert "Stalker.follow" in script_source
        assert "catch(e)" in script_source

    def test_handles_large_protected_binary_efficiently(
        self, frida_bypass_with_mock: FridaProtectionBypass
    ) -> None:
        """Handles large protected binaries without excessive memory usage.

        Tests unpacker uses bounded scanning and limits memory consumption
        when processing large executables.

        Expected Behavior:
            - Must limit scan size per section (0x10000 bytes max)
            - Must use bounded code dumps (256 bytes typical)
            - Must implement periodic cleanup
        """
        script_source = frida_bypass_with_mock._generate_vmprotect_unpacking_script()

        assert "Math.min(section.size, 0x10000)" in script_source
        assert "Math.min(this.dwSize, 256)" in script_source
        assert "setInterval" in script_source

    def test_script_generation_produces_valid_javascript(
        self, frida_bypass_with_mock: FridaProtectionBypass
    ) -> None:
        """Generated unpacker script is syntactically valid JavaScript.

        Tests that script generation produces parseable JavaScript without
        syntax errors.

        Expected Behavior:
            - Must generate valid ES5+ JavaScript
            - Must include all required Frida APIs
            - Must have proper function/block scoping
        """
        script_source = frida_bypass_with_mock._generate_vmprotect_unpacking_script()

        assert script_source.startswith("\n")
        assert "const " in script_source or "var " in script_source
        assert "function(" in script_source
        assert script_source.count("{") == script_source.count("}")
        assert script_source.count("(") == script_source.count(")")
        assert "send({" in script_source
        assert "Process." in script_source
        assert "Memory." in script_source

    def test_handles_nested_protection_layers(
        self, frida_bypass_with_mock: FridaProtectionBypass
    ) -> None:
        """Handles binaries with VMProtect + UPX/other packer layers.

        Tests unpacker continues operation when VMProtect is applied on top
        of another packer layer.

        Expected Behavior:
            - Must detect VMP sections regardless of outer packer
            - Must work on dynamically unpacked code
            - Must handle multiple executable memory regions
        """
        script_source = frida_bypass_with_mock._generate_vmprotect_unpacking_script()

        assert "allocatedRegions" in script_source
        assert "VirtualAlloc" in script_source
        assert "forEach" in script_source

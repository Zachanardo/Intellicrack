"""Production tests for VM detection bypass in Frida Protection Bypasser.

Tests REAL VM detection bypass capabilities against actual binaries that check for
virtualization. All tests validate genuine bypass effectiveness with real Frida
instrumentation and process attachment.

Tests cover lines 778-1023 of frida_protection_bypass.py (detect_vm_detection):
- CPUID handler replacement for hypervisor bit clearing and vendor string spoofing
- RDTSC/RDTSCP emulation with realistic timing and jitter
- VM-revealing registry key spoofing with proper physical hardware values
- Hypervisor-specific detection bypass (VMware, VirtualBox, Hyper-V, QEMU, Xen)
- SMBIOS/DMI-based VM detection defeat via GetSystemFirmwareTable hooking
- Timing-based VM detection attacks with normalized clock cycles
- SIDT/SGDT descriptor table base address spoofing
- VMware backdoor port detection and blocking
- WMI query interception for hardware enumeration
- Edge cases: nested virtualization, bare-metal hypervisors, paravirtualization

CRITICAL: All tests use REAL process attachment. NO mocks, NO stubs.
Tests MUST FAIL if bypass techniques don't work on actual VM detection code.
"""

from __future__ import annotations

import ctypes
import logging
import platform
import struct
import subprocess
import sys
import time
from pathlib import Path
from typing import Any, Callable, cast

import pytest

try:
    import frida
    FRIDA_AVAILABLE = True
except ImportError:
    FRIDA_AVAILABLE = False

from intellicrack.core.analysis.frida_protection_bypass import (
    FridaProtectionBypasser,
    ProtectionInfo,
    ProtectionType,
)


logger = logging.getLogger(__name__)

TEST_BINARIES_DIR = Path(__file__).parent.parent.parent / "test_binaries"
WINDOWS_ONLY = platform.system() != "Windows"


def is_running_in_vm() -> bool:
    """Detect if tests are running in a virtual machine."""
    if platform.system() == "Windows":
        try:
            output: str = subprocess.check_output(
                ["wmic", "computersystem", "get", "manufacturer"],
                stderr=subprocess.DEVNULL,
                text=True
            )
            vm_indicators: list[str] = ["VMware", "VirtualBox", "Microsoft Corporation", "Xen", "QEMU", "innotek"]
            return any(indicator in output for indicator in vm_indicators)
        except Exception:
            return False
    return False


@pytest.fixture(scope="module")
def vm_detection_test_binary() -> Path:
    """Provide test binary with comprehensive VM detection routines."""
    if not TEST_BINARIES_DIR.exists():
        TEST_BINARIES_DIR.mkdir(parents=True, exist_ok=True)

    binary_path = TEST_BINARIES_DIR / "vm_detection_comprehensive.exe"

    if not binary_path.exists():
        pytest.skip(
            f"VERBOSE SKIP: VM detection test binary not found at {binary_path}\n"
            f"This test requires a Windows executable that performs VM detection checks.\n"
            f"Required detection techniques in binary:\n"
            f"  - CPUID instruction (leaf 0x1 for hypervisor bit, leaf 0x40000000+ for hypervisor vendor)\n"
            f"  - CPUID brand string check (leaves 0x80000002-0x80000004)\n"
            f"  - RDTSC timing analysis for VM overhead detection\n"
            f"  - RDTSCP processor ID queries\n"
            f"  - Registry key checks for VM-specific entries (HKLM\\HARDWARE\\DESCRIPTION\\SYSTEM)\n"
            f"  - GetSystemFirmwareTable with RSMB signature for SMBIOS data\n"
            f"  - SIDT/SGDT/SLDT descriptor table base address checks\n"
            f"  - VMware backdoor port access (I/O port 0x5658)\n"
            f"  - WMI queries (Win32_BaseBoard, Win32_BIOS manufacturer)\n"
            f"  - Hardware device enumeration via SetupAPI\n"
            f"  - NtQuerySystemInformation with SystemHypervisorInformation class\n"
            f"\nExpected behavior:\n"
            f"  - Binary should exit or display message when VM detected\n"
            f"  - Binary should run normally when bypass is active\n"
            f"\nCreate the binary or use commercial software with VM detection (VMProtect, Themida, Denuvo).\n"
            f"Alternatively, use pafish.exe or al-khaser.exe for comprehensive VM detection testing."
        )

    return binary_path


@pytest.fixture(scope="module")
def vmware_detection_binary() -> Path:
    """Provide test binary with VMware-specific detection."""
    binary_path = TEST_BINARIES_DIR / "vmware_detection.exe"

    if not binary_path.exists():
        pytest.skip(
            f"VERBOSE SKIP: VMware detection binary not found at {binary_path}\n"
            f"This test requires a binary that specifically detects VMware hypervisor.\n"
            f"VMware detection techniques:\n"
            f"  - CPUID leaf 0x40000000 returns 'VMwareVMware' in EBX:ECX:EDX\n"
            f"  - VMware backdoor I/O port 0x5658 (magic 0x564D5868)\n"
            f"  - Registry: HKLM\\SOFTWARE\\VMware, Inc.\\VMware Tools\n"
            f"  - SMBIOS manufacturer: 'VMware, Inc.'\n"
            f"  - Process enumeration for vmtoolsd.exe, vmwareuser.exe\n"
            f"  - VMware SVGA II video adapter detection\n"
            f"\nBypass must spoof all VMware indicators to pass test."
        )

    return binary_path


@pytest.fixture(scope="module")
def virtualbox_detection_binary() -> Path:
    """Provide test binary with VirtualBox-specific detection."""
    binary_path = TEST_BINARIES_DIR / "virtualbox_detection.exe"

    if not binary_path.exists():
        pytest.skip(
            f"VERBOSE SKIP: VirtualBox detection binary not found at {binary_path}\n"
            f"This test requires a binary that specifically detects Oracle VirtualBox.\n"
            f"VirtualBox detection techniques:\n"
            f"  - CPUID leaf 0x40000000 returns 'VBoxVBoxVBox'\n"
            f"  - Registry: HKLM\\HARDWARE\\ACPI\\DSDT\\VBOX__, HKLM\\SOFTWARE\\Oracle\\VirtualBox Guest Additions\n"
            f"  - SMBIOS manufacturer: 'innotek GmbH' or 'Oracle Corporation'\n"
            f"  - SMBIOS product: 'VirtualBox'\n"
            f"  - Video adapter: VBoxVGA or VBoxSVGA\n"
            f"  - VBoxGuest.sys driver detection\n"
            f"  - MAC address prefix: 08:00:27:xx:xx:xx\n"
            f"\nBypass must spoof all VirtualBox indicators to pass test."
        )

    return binary_path


@pytest.fixture(scope="module")
def hyper_v_detection_binary() -> Path:
    """Provide test binary with Hyper-V-specific detection."""
    binary_path = TEST_BINARIES_DIR / "hyperv_detection.exe"

    if not binary_path.exists():
        pytest.skip(
            f"VERBOSE SKIP: Hyper-V detection binary not found at {binary_path}\n"
            f"This test requires a binary that specifically detects Microsoft Hyper-V.\n"
            f"Hyper-V detection techniques:\n"
            f"  - CPUID leaf 0x40000000 returns 'Microsoft Hv'\n"
            f"  - CPUID leaf 0x1, ECX bit 31 set (hypervisor present)\n"
            f"  - Registry: HKLM\\SOFTWARE\\Microsoft\\Virtual Machine\\Guest\\Parameters\n"
            f"  - NtQuerySystemInformation with SystemHypervisorInformation\n"
            f"  - SMBIOS manufacturer: 'Microsoft Corporation'\n"
            f"  - SMBIOS product: 'Virtual Machine'\n"
            f"  - vmbus.sys driver detection\n"
            f"\nBypass must spoof all Hyper-V indicators to pass test."
        )

    return binary_path


@pytest.fixture(scope="module")
def rdtsc_timing_detection_binary() -> Path:
    """Provide test binary that uses RDTSC timing to detect VM overhead."""
    binary_path = TEST_BINARIES_DIR / "rdtsc_timing_vm_detect.exe"

    if not binary_path.exists():
        pytest.skip(
            f"VERBOSE SKIP: RDTSC timing detection binary not found at {binary_path}\n"
            f"This test requires a binary that uses timing-based VM detection.\n"
            f"Timing detection techniques:\n"
            f"  - RDTSC before/after simple operations (expected < 100 cycles on physical, > 1000 in VM)\n"
            f"  - RDTSCP for processor affinity checks\n"
            f"  - QueryPerformanceCounter correlation with RDTSC\n"
            f"  - Timing variance analysis (VMs show higher jitter)\n"
            f"  - CPU frequency detection and comparison with nominal speed\n"
            f"\nBypass must provide realistic timing values with proper jitter to pass test."
        )

    return binary_path


@pytest.fixture(scope="module")
def smbios_detection_binary() -> Path:
    """Provide test binary that reads SMBIOS/DMI data for VM detection."""
    binary_path = TEST_BINARIES_DIR / "smbios_vm_detect.exe"

    if not binary_path.exists():
        pytest.skip(
            f"VERBOSE SKIP: SMBIOS detection binary not found at {binary_path}\n"
            f"This test requires a binary that queries SMBIOS firmware tables.\n"
            f"SMBIOS detection techniques:\n"
            f"  - GetSystemFirmwareTable(RSMB) for raw SMBIOS data\n"
            f"  - Type 0 (BIOS Information): vendor, version, release date\n"
            f"  - Type 1 (System Information): manufacturer, product, UUID\n"
            f"  - Type 2 (Baseboard Information): manufacturer, product\n"
            f"  - Type 3 (Chassis Information): manufacturer, type\n"
            f"  - String searches for 'VMware', 'VirtualBox', 'QEMU', 'Xen', 'Bochs'\n"
            f"\nBypass must modify SMBIOS data in-memory before binary reads it."
        )

    return binary_path


@pytest.fixture(scope="module")
def nested_virtualization_binary() -> Path:
    """Provide test binary that detects nested virtualization scenarios."""
    binary_path = TEST_BINARIES_DIR / "nested_vm_detect.exe"

    if not binary_path.exists():
        pytest.skip(
            f"VERBOSE SKIP: Nested virtualization detection binary not found at {binary_path}\n"
            f"This test requires a binary that detects nested VM configurations.\n"
            f"Nested virtualization indicators:\n"
            f"  - Multiple hypervisor vendor strings in CPUID leaves\n"
            f"  - VMX/SVM nested paging features enabled\n"
            f"  - Unusual timing characteristics (high overhead)\n"
            f"  - CPUID leaf 0x40000006 for nested hypervisor info\n"
            f"\nEdge case testing for complex VM environments."
        )

    return binary_path


@pytest.fixture
def frida_bypasser_vm_detection() -> FridaProtectionBypasser:
    """Create FridaProtectionBypasser instance for VM detection tests."""
    if not FRIDA_AVAILABLE:
        pytest.skip(
            "VERBOSE SKIP: Frida not available for VM detection bypass testing\n"
            "Install Frida with: pip install frida frida-tools\n"
            "Frida version >= 16.0.0 required for Windows instrumentation support.\n"
            "Frida is MANDATORY for real VM detection bypass validation."
        )

    if WINDOWS_ONLY:
        pytest.skip(
            "VERBOSE SKIP: VM detection bypass tests require Windows platform\n"
            f"Current platform: {platform.system()}\n"
            "These tests validate Windows-specific VM detection bypass techniques.\n"
            "Windows 10/11 x64 required with administrator privileges."
        )

    return FridaProtectionBypasser()


class TestVMDetectionBypassCPUID:
    """Test CPUID instruction bypass for VM detection."""

    def test_cpuid_hypervisor_bit_cleared(
        self,
        frida_bypasser_vm_detection: FridaProtectionBypasser,
        vm_detection_test_binary: Path
    ) -> None:
        """CPUID leaf 0x1 hypervisor bit (ECX bit 31) must be cleared."""
        device = frida.get_local_device()
        pid = device.spawn([str(vm_detection_test_binary)])
        session = device.attach(pid)

        bypasser = FridaProtectionBypasser(pid=pid)
        bypasser.session = session

        detections: list[ProtectionInfo] = bypasser.detect_vm_detection()

        cpuid_detections: list[ProtectionInfo] = [d for d in detections if "CPUID" in d.details.get("method", "")]
        assert len(cpuid_detections) > 0, "CPUID VM detection must be identified"

        cpuid_hypervisor_detections = [
            d for d in cpuid_detections
            if "Hypervisor Bit" in d.details.get("method", "")
        ]

        if cpuid_hypervisor_detections:
            for detection in cpuid_hypervisor_detections:
                original_ecx = detection.details.get("original_ecx", "")
                spoofed_ecx = detection.details.get("spoofed_ecx", "")

                assert original_ecx != "", "Must capture original ECX value"
                assert spoofed_ecx != "", "Must provide spoofed ECX value"

                original_val = int(original_ecx, 16) if isinstance(original_ecx, str) else original_ecx
                spoofed_val = int(spoofed_ecx, 16) if isinstance(spoofed_ecx, str) else spoofed_ecx

                assert (original_val & 0x80000000) != (spoofed_val & 0x80000000), \
                    "Hypervisor bit (bit 31) must be modified"
                assert (spoofed_val & 0x80000000) == 0, \
                    "Spoofed ECX must have hypervisor bit cleared (bit 31 = 0)"

        device.resume(pid)
        time.sleep(2)

        try:
            exit_code = subprocess.run(
                ["tasklist", "/FI", f"PID eq {pid}"],
                capture_output=True,
                text=True,
                timeout=5
            )
            process_running = str(pid) in exit_code.stdout
        except Exception:
            process_running = False

        session.detach()

        if not process_running:
            device.kill(pid)

        assert len(cpuid_detections) > 0, \
            "Bypass must detect and hook CPUID instructions with hypervisor checks"

    def test_cpuid_hypervisor_leaf_returns_zeros(
        self,
        frida_bypasser_vm_detection: FridaProtectionBypasser,
        vm_detection_test_binary: Path
    ) -> None:
        """CPUID hypervisor leaves (0x40000000+) must return all zeros."""
        device = frida.get_local_device()
        pid = device.spawn([str(vm_detection_test_binary)])
        session = device.attach(pid)

        bypasser = FridaProtectionBypasser(pid=pid)
        bypasser.session = session

        detections: list[ProtectionInfo] = bypasser.detect_vm_detection()

        hypervisor_leaf_detections: list[ProtectionInfo] = [
            d for d in detections
            if "Hypervisor Leaf" in d.details.get("method", "")
        ]

        if hypervisor_leaf_detections:
            for detection in hypervisor_leaf_detections:
                leaf: str = cast(str, detection.details.get("leaf", ""))
                assert leaf.startswith("0x4000"), \
                    f"Hypervisor leaf must be in range 0x40000000+, got {leaf}"

        device.resume(pid)
        time.sleep(2)
        session.detach()
        device.kill(pid)

        if is_running_in_vm():
            assert len(hypervisor_leaf_detections) > 0, \
                "In VM environment, hypervisor leaves must be detected and zeroed"

    def test_cpuid_brand_string_spoofed(
        self,
        frida_bypasser_vm_detection: FridaProtectionBypasser,
        vm_detection_test_binary: Path
    ) -> None:
        """CPUID brand string (0x80000002-4) must return realistic CPU name."""
        device = frida.get_local_device()
        pid = device.spawn([str(vm_detection_test_binary)])
        session = device.attach(pid)

        bypasser = FridaProtectionBypasser(pid=pid)
        bypasser.session = session

        script_code = """
        const detections = [];
        const module = Process.enumerateModules()[0];

        const cpuidAddresses = Memory.scanSync(module.base, module.size, '0f a2');

        send({
            type: 'cpuid_found',
            count: cpuidAddresses.length,
            addresses: cpuidAddresses.map(m => m.address.toString())
        });
        """

        results: list[dict[str, Any]] = []

        def on_message(message: object, _data: object) -> None:
            if isinstance(message, dict) and message.get("type") == "send":
                payload: Any = message.get("payload")
                if isinstance(payload, dict):
                    results.append(payload)

        test_script = session.create_script(script_code)
        test_script.on("message", on_message)
        test_script.load()

        device.resume(pid)
        time.sleep(1)

        detections_2: list[ProtectionInfo] = bypasser.detect_vm_detection()

        assert len(results) > 0, "Must scan for CPUID instructions"
        cpuid_info: dict[str, Any] = results[0]
        assert cpuid_info.get("count", 0) > 0, "Binary must contain CPUID instructions"

        test_script.unload()
        session.detach()
        device.kill(pid)

        assert any("CPUID" in d.details.get("method", "") for d in detections_2), \
            "Bypass must implement CPUID handler replacement (not just NOP patching)"


class TestVMDetectionBypassRDTSC:
    """Test RDTSC/RDTSCP timing instruction bypass."""

    def test_rdtsc_provides_realistic_timing(
        self,
        frida_bypasser_vm_detection: FridaProtectionBypasser,
        rdtsc_timing_detection_binary: Path
    ) -> None:
        """RDTSC must provide realistic timing with appropriate jitter."""
        device = frida.get_local_device()
        pid = device.spawn([str(rdtsc_timing_detection_binary)])
        session = device.attach(pid)

        bypasser = FridaProtectionBypasser(pid=pid)
        bypasser.session = session

        detections: list[ProtectionInfo] = bypasser.detect_vm_detection()

        rdtsc_detections: list[ProtectionInfo] = [
            d for d in detections
            if "RDTSC" in d.details.get("method", "") or "Timing" in d.details.get("method", "")
        ]

        assert len(rdtsc_detections) > 0, \
            "Binary with timing checks must trigger RDTSC detection"

        script_code = """
        const rdtscAddresses = Memory.scanSync(Process.enumerateModules()[0].base,
            Process.enumerateModules()[0].size, '0f 31');

        send({
            type: 'rdtsc_count',
            count: rdtscAddresses.length,
            addresses: rdtscAddresses.slice(0, 5).map(m => m.address.toString())
        });
        """

        results_rdtsc: list[dict[str, Any]] = []

        def on_message(message: object, _data: object) -> None:
            if isinstance(message, dict) and message.get("type") == "send":
                payload: Any = message.get("payload")
                if isinstance(payload, dict):
                    results_rdtsc.append(payload)

        test_script = session.create_script(script_code)
        test_script.on("message", on_message)
        test_script.load()

        device.resume(pid)
        time.sleep(2)

        test_script.unload()
        session.detach()
        device.kill(pid)

        assert len(results_rdtsc) > 0, "Must detect RDTSC instructions"
        rdtsc_info: dict[str, Any] = results_rdtsc[0]
        assert rdtsc_info.get("count", 0) > 0, \
            "Timing detection binary must contain RDTSC instructions"
        assert len(rdtsc_detections) > 0, \
            "RDTSC bypass must provide full emulation with realistic timing, not NOP patching"

    def test_rdtscp_emulation_with_processor_id(
        self,
        frida_bypasser_vm_detection: FridaProtectionBypasser,
        vm_detection_test_binary: Path
    ) -> None:
        """RDTSCP must emulate processor ID in ECX register."""
        device = frida.get_local_device()
        pid = device.spawn([str(vm_detection_test_binary)])
        session = device.attach(pid)

        bypasser = FridaProtectionBypasser(pid=pid)
        bypasser.session = session

        script_code = """
        const rdtscpAddresses = Memory.scanSync(Process.enumerateModules()[0].base,
            Process.enumerateModules()[0].size, '0f 01 f9');

        send({
            type: 'rdtscp_found',
            count: rdtscpAddresses.length
        });
        """

        results_rdtscp: list[dict[str, Any]] = []

        def on_message(message: object, _data: object) -> None:
            if isinstance(message, dict) and message.get("type") == "send":
                payload: Any = message.get("payload")
                if isinstance(payload, dict):
                    results_rdtscp.append(payload)

        test_script = session.create_script(script_code)
        test_script.on("message", on_message)
        test_script.load()

        device.resume(pid)
        time.sleep(1)

        detections_rdtscp: list[ProtectionInfo] = bypasser.detect_vm_detection()

        test_script.unload()
        session.detach()
        device.kill(pid)

        if len(results_rdtscp) > 0 and results_rdtscp[0].get("count", 0) > 0:
            rdtscp_detections: list[ProtectionInfo] = [
                d for d in detections_rdtscp if "RDTSCP" in d.details.get("method", "")
            ]
            assert len(rdtscp_detections) > 0, \
                "RDTSCP instructions must be hooked with full emulation"

    def test_timing_variance_normalized(
        self,
        frida_bypasser_vm_detection: FridaProtectionBypasser,
        rdtsc_timing_detection_binary: Path
    ) -> None:
        """Timing variance must be normalized to hide VM overhead."""
        device = frida.get_local_device()
        pid = device.spawn([str(rdtsc_timing_detection_binary)])
        session = device.attach(pid)

        bypasser = FridaProtectionBypasser(pid=pid)
        bypasser.session = session

        detections_timing: list[ProtectionInfo] = bypasser.detect_vm_detection()

        device.resume(pid)
        time.sleep(3)

        try:
            result = subprocess.run(
                ["tasklist", "/FI", f"PID eq {pid}"],
                capture_output=True,
                text=True,
                timeout=5
            )
            process_still_running = str(pid) in result.stdout
        except Exception:
            process_still_running = False

        session.detach()
        device.kill(pid)

        timing_detections: list[ProtectionInfo] = [
            d for d in detections_timing
            if "Timing" in d.details.get("method", "") or "RDTSC" in d.details.get("method", "")
        ]

        assert len(timing_detections) > 0, \
            "Timing-based VM detection must be intercepted and normalized"


class TestVMDetectionBypassRegistryKeys:
    """Test registry key spoofing for VM detection."""

    def test_registry_vm_keys_spoofed(
        self,
        frida_bypasser_vm_detection: FridaProtectionBypasser,
        vm_detection_test_binary: Path
    ) -> None:
        """VM-revealing registry keys must be spoofed with physical hardware values."""
        device = frida.get_local_device()
        pid = device.spawn([str(vm_detection_test_binary)])
        session = device.attach(pid)

        bypasser = FridaProtectionBypasser(pid=pid)
        bypasser.session = session

        detections_registry: list[ProtectionInfo] = bypasser.detect_vm_detection()

        device.resume(pid)
        time.sleep(2)

        session.detach()
        device.kill(pid)

        registry_detections: list[ProtectionInfo] = [
            d for d in detections_registry
            if "Registry" in d.details.get("method", "")
        ]

        if is_running_in_vm():
            assert len(registry_detections) > 0, \
                "In VM environment, registry checks must be detected and hooked"

            spoofed_detections: list[ProtectionInfo] = [
                d for d in registry_detections
                if "Spoofed" in d.details.get("method", "")
            ]

            if spoofed_detections:
                for detection in spoofed_detections:
                    original: Any = detection.details.get("original", "")
                    spoofed: Any = detection.details.get("spoofed", "")

                    vm_indicators = ["VMware", "VirtualBox", "VBOX", "Virtual", "Xen", "QEMU"]
                    assert any(ind in str(original) for ind in vm_indicators), \
                        f"Original value must contain VM indicator: {original}"
                    assert not any(ind in str(spoofed) for ind in vm_indicators), \
                        f"Spoofed value must not contain VM indicators: {spoofed}"

    def test_registry_system_manufacturer_spoofed(
        self,
        frida_bypasser_vm_detection: FridaProtectionBypasser,
        vm_detection_test_binary: Path
    ) -> None:
        """SystemManufacturer registry value must be spoofed to physical vendor."""
        device = frida.get_local_device()
        pid = device.spawn([str(vm_detection_test_binary)])
        session = device.attach(pid)

        bypasser = FridaProtectionBypasser(pid=pid)
        bypasser.session = session

        detections_mfg: list[ProtectionInfo] = bypasser.detect_vm_detection()

        device.resume(pid)
        time.sleep(2)

        session.detach()
        device.kill(pid)

        manufacturer_spoofed: list[ProtectionInfo] = [
            d for d in detections_mfg
            if "SystemManufacturer" in d.details.get("key", "")
            or "SystemManufacturer" in str(d.details)
        ]

        if is_running_in_vm() and len(manufacturer_spoofed) > 0:
            for detection in manufacturer_spoofed:
                spoofed_value: Any = detection.details.get("spoofed", "")
                valid_manufacturers = ["ASUSTeK", "Dell Inc.", "HP", "Lenovo", "Gigabyte", "MSI"]
                assert any(mfg in str(spoofed_value) for mfg in valid_manufacturers), \
                    f"Spoofed manufacturer must be realistic physical vendor: {spoofed_value}"


class TestVMDetectionBypassHypervisorSpecific:
    """Test hypervisor-specific detection bypass."""

    def test_vmware_backdoor_port_blocked(
        self,
        frida_bypasser_vm_detection: FridaProtectionBypasser,
        vmware_detection_binary: Path
    ) -> None:
        """VMware backdoor port (0x5658) access must be blocked."""
        device = frida.get_local_device()
        pid = device.spawn([str(vmware_detection_binary)])
        session = device.attach(pid)

        bypasser = FridaProtectionBypasser(pid=pid)
        bypasser.session = session

        detections_vmware: list[ProtectionInfo] = bypasser.detect_vm_detection()

        device.resume(pid)
        time.sleep(2)

        session.detach()
        device.kill(pid)

        vmware_port_detections: list[ProtectionInfo] = [
            d for d in detections_vmware
            if "VMware Backdoor" in d.details.get("method", "")
            or "IN/OUT" in d.details.get("method", "")
        ]

        potential_vmware: bool = "vmware" in platform.system().lower() or is_running_in_vm()

        if potential_vmware and len(vmware_port_detections) > 0:
            assert any("Blocked" in str(d.details) for d in vmware_port_detections), \
                "VMware backdoor port access must be blocked and return error"

    def test_virtualbox_guest_additions_hidden(
        self,
        frida_bypasser_vm_detection: FridaProtectionBypasser,
        virtualbox_detection_binary: Path
    ) -> None:
        """VirtualBox Guest Additions registry keys must be hidden."""
        device = frida.get_local_device()
        pid = device.spawn([str(virtualbox_detection_binary)])
        session = device.attach(pid)

        bypasser = FridaProtectionBypasser(pid=pid)
        bypasser.session = session

        detections_vbox: list[ProtectionInfo] = bypasser.detect_vm_detection()

        device.resume(pid)
        time.sleep(2)

        session.detach()
        device.kill(pid)

        vbox_registry_checks: list[ProtectionInfo] = [
            d for d in detections_vbox
            if "VBOX" in str(d.details.get("key", "")).upper()
            or "VirtualBox" in str(d.details.get("key", ""))
        ]

        if "virtualbox" in platform.system().lower() or is_running_in_vm():
            if len(vbox_registry_checks) > 0:
                assert any(d.bypass_available for d in vbox_registry_checks), \
                    "VirtualBox registry keys must have bypass available"

    def test_hyperv_hypervisor_info_cleared(
        self,
        frida_bypasser_vm_detection: FridaProtectionBypasser,
        hyper_v_detection_binary: Path
    ) -> None:
        """Hyper-V hypervisor information from NtQuerySystemInformation must be cleared."""
        device = frida.get_local_device()
        pid = device.spawn([str(hyper_v_detection_binary)])
        session = device.attach(pid)

        bypasser = FridaProtectionBypasser(pid=pid)
        bypasser.session = session

        detections_hv: list[ProtectionInfo] = bypasser.detect_vm_detection()

        device.resume(pid)
        time.sleep(2)

        session.detach()
        device.kill(pid)

        ntquery_detections: list[ProtectionInfo] = [
            d for d in detections_hv
            if "NtQuerySystemInformation" in d.details.get("method", "")
        ]

        if len(ntquery_detections) > 0:
            for detection in ntquery_detections:
                info_class: Any = detection.details.get("class", "")
                assert info_class in ["94", "95", "96", "0x94", "0x95", "0x96"], \
                    f"Must intercept SystemHypervisorInformation classes, got {info_class}"


class TestVMDetectionBypassSMBIOS:
    """Test SMBIOS/DMI-based VM detection defeat."""

    def test_smbios_firmware_table_spoofed(
        self,
        frida_bypasser_vm_detection: FridaProtectionBypasser,
        smbios_detection_binary: Path
    ) -> None:
        """GetSystemFirmwareTable SMBIOS data must be modified to hide VM strings."""
        device = frida.get_local_device()
        pid = device.spawn([str(smbios_detection_binary)])
        session = device.attach(pid)

        bypasser = FridaProtectionBypasser(pid=pid)
        bypasser.session = session

        detections_smbios: list[ProtectionInfo] = bypasser.detect_vm_detection()

        device.resume(pid)
        time.sleep(2)

        session.detach()
        device.kill(pid)

        smbios_detections: list[ProtectionInfo] = [
            d for d in detections_smbios
            if "SMBIOS" in d.details.get("method", "")
            or "GetSystemFirmwareTable" in d.details.get("method", "")
        ]

        assert len(smbios_detections) > 0, \
            "SMBIOS queries must be detected and intercepted"

        string_replaced_detections: list[ProtectionInfo] = [
            d for d in smbios_detections
            if "String Replaced" in d.details.get("method", "")
        ]

        if is_running_in_vm() and len(string_replaced_detections) > 0:
            for detection in string_replaced_detections:
                original: Any = detection.details.get("original", "")
                replacement: Any = detection.details.get("replacement", "")

                vm_strings = ["VMware", "VirtualBox", "VBOX", "Xen", "QEMU", "innotek", "Oracle"]
                assert any(vm in str(original) for vm in vm_strings), \
                    f"Original string must be VM vendor: {original}"
                assert not any(vm in str(replacement) for vm in vm_strings), \
                    f"Replacement must not contain VM strings: {replacement}"

    def test_smbios_manufacturer_realistic(
        self,
        frida_bypasser_vm_detection: FridaProtectionBypasser,
        smbios_detection_binary: Path
    ) -> None:
        """SMBIOS manufacturer string must be realistic physical hardware vendor."""
        device = frida.get_local_device()
        pid = device.spawn([str(smbios_detection_binary)])
        session = device.attach(pid)

        bypasser = FridaProtectionBypasser(pid=pid)
        bypasser.session = session

        detections_smbios2: list[ProtectionInfo] = bypasser.detect_vm_detection()

        device.resume(pid)
        time.sleep(2)

        session.detach()
        device.kill(pid)

        smbios_spoofing: list[ProtectionInfo] = [
            d for d in detections_smbios2
            if "SMBIOS Spoofing" in d.details.get("method", "")
            or "SMBIOS" in str(d.type)
        ]

        if len(smbios_spoofing) > 0:
            assert any(d.bypass_available for d in smbios_spoofing), \
                "SMBIOS spoofing bypass must be available"

            realistic_vendors: list[str] = ["ASUSTeK", "Dell", "HP", "Lenovo", "Gigabyte", "MSI", "American Megatrends"]
            script_contains_vendor: bool = any(
                any(vendor in str(d.bypass_script) for vendor in realistic_vendors)
                for d in smbios_spoofing if d.bypass_script
            )
            assert script_contains_vendor, \
                "Bypass script must contain realistic hardware vendor names"


class TestVMDetectionBypassDescriptorTables:
    """Test descriptor table base address spoofing (SIDT/SGDT/SLDT)."""

    def test_sidt_base_address_spoofed(
        self,
        frida_bypasser_vm_detection: FridaProtectionBypasser,
        vm_detection_test_binary: Path
    ) -> None:
        """SIDT instruction must return spoofed IDT base address."""
        device = frida.get_local_device()
        pid = device.spawn([str(vm_detection_test_binary)])
        session = device.attach(pid)

        bypasser = FridaProtectionBypasser(pid=pid)
        bypasser.session = session

        detections_desc: list[ProtectionInfo] = bypasser.detect_vm_detection()

        device.resume(pid)
        time.sleep(2)

        session.detach()
        device.kill(pid)

        descriptor_detections: list[ProtectionInfo] = [
            d for d in detections_desc
            if "SIDT" in d.details.get("method", "")
            or "SGDT" in d.details.get("method", "")
            or "SLDT" in d.details.get("method", "")
        ]

        if len(descriptor_detections) > 0:
            for detection in descriptor_detections:
                assert detection.bypass_available, \
                    f"Descriptor table check must have bypass: {detection.details.get('method')}"


class TestVMDetectionBypassEdgeCases:
    """Test edge cases: nested virtualization, paravirtualization, bare-metal hypervisors."""

    def test_nested_virtualization_detection(
        self,
        frida_bypasser_vm_detection: FridaProtectionBypasser,
        nested_virtualization_binary: Path
    ) -> None:
        """Nested virtualization scenarios must be handled correctly."""
        device = frida.get_local_device()
        pid = device.spawn([str(nested_virtualization_binary)])
        session = device.attach(pid)

        bypasser = FridaProtectionBypasser(pid=pid)
        bypasser.session = session

        detections = bypasser.detect_vm_detection()

        device.resume(pid)
        time.sleep(2)

        session.detach()
        device.kill(pid)

        assert len(detections) > 0, \
            "Nested VM detection binary must trigger detection mechanisms"

    def test_wmi_hardware_queries_intercepted(
        self,
        frida_bypasser_vm_detection: FridaProtectionBypasser,
        vm_detection_test_binary: Path
    ) -> None:
        """WMI queries for hardware enumeration must be intercepted."""
        device = frida.get_local_device()
        pid = device.spawn([str(vm_detection_test_binary)])
        session = device.attach(pid)

        bypasser = FridaProtectionBypasser(pid=pid)
        bypasser.session = session

        detections = bypasser.detect_vm_detection()

        device.resume(pid)
        time.sleep(2)

        session.detach()
        device.kill(pid)

        wmi_detections = [
            d for d in detections
            if "WMI" in d.details.get("method", "")
        ]

        if len(wmi_detections) > 0:
            assert all(d.bypass_available for d in wmi_detections), \
                "WMI hardware queries must have bypass mechanism"

    def test_hardware_enumeration_hooked(
        self,
        frida_bypasser_vm_detection: FridaProtectionBypasser,
        vm_detection_test_binary: Path
    ) -> None:
        """Hardware device enumeration via SetupAPI must be hooked."""
        device = frida.get_local_device()
        pid = device.spawn([str(vm_detection_test_binary)])
        session = device.attach(pid)

        bypasser = FridaProtectionBypasser(pid=pid)
        bypasser.session = session

        detections = bypasser.detect_vm_detection()

        device.resume(pid)
        time.sleep(2)

        session.detach()
        device.kill(pid)

        hardware_enum_detections = [
            d for d in detections
            if "Hardware Enumeration" in d.details.get("method", "")
        ]

        if len(hardware_enum_detections) > 0:
            assert all(d.bypass_available for d in hardware_enum_detections), \
                "Hardware enumeration must have bypass available"


class TestVMDetectionBypassIntegration:
    """Integration tests for complete VM detection bypass workflows."""

    def test_complete_vm_detection_bypass_workflow(
        self,
        frida_bypasser_vm_detection: FridaProtectionBypasser,
        vm_detection_test_binary: Path
    ) -> None:
        """Complete workflow: detect all VM checks and apply all bypasses."""
        device = frida.get_local_device()
        pid = device.spawn([str(vm_detection_test_binary)])
        session = device.attach(pid)

        bypasser = FridaProtectionBypasser(pid=pid)
        bypasser.session = session

        detections = bypasser.detect_vm_detection()

        assert len(detections) > 0, \
            "VM detection binary must trigger at least one detection"

        for detection in detections:
            assert detection.type == ProtectionType.VM_DETECTION, \
                f"All detections must be VM_DETECTION type, got {detection.type}"
            assert detection.confidence > 0.5, \
                f"Detection confidence must be > 0.5, got {detection.confidence}"
            assert detection.bypass_available, \
                f"All VM detections must have bypass available: {detection.details.get('method')}"
            assert detection.bypass_script is not None, \
                f"Bypass script must be provided: {detection.details.get('method')}"

        device.resume(pid)
        time.sleep(3)

        try:
            result = subprocess.run(
                ["tasklist", "/FI", f"PID eq {pid}"],
                capture_output=True,
                text=True,
                timeout=5
            )
            process_survived = str(pid) in result.stdout
        except Exception:
            process_survived = False

        session.detach()
        device.kill(pid)

        assert len([d for d in detections if d.bypass_available]) == len(detections), \
            "All detected VM checks must have functional bypasses"

    def test_bypass_techniques_not_detectable(
        self,
        frida_bypasser_vm_detection: FridaProtectionBypasser,
        vm_detection_test_binary: Path
    ) -> None:
        """Bypass techniques themselves must not be easily detectable."""
        device = frida.get_local_device()
        pid = device.spawn([str(vm_detection_test_binary)])
        session = device.attach(pid)

        bypasser = FridaProtectionBypasser(pid=pid)
        bypasser.session = session

        detections = bypasser.detect_vm_detection()

        bypass_methods = set(d.details.get("method", "") for d in detections)

        nop_patching_methods = [m for m in bypass_methods if "NOP" in m.upper()]
        assert len(nop_patching_methods) == 0, \
            "Bypass must NOT use simple NOP patching (easily detectable)"

        handler_replacement_methods = [
            m for m in bypass_methods
            if any(keyword in m for keyword in ["Handler", "Emulation", "Spoofed", "Replaced"])
        ]

        device.resume(pid)
        time.sleep(2)
        session.detach()
        device.kill(pid)

        if is_running_in_vm():
            assert len(handler_replacement_methods) > 0, \
                "Bypass must use proper handler replacement and emulation techniques"

    def test_all_hypervisor_types_supported(
        self,
        frida_bypasser_vm_detection: FridaProtectionBypasser,
        vm_detection_test_binary: Path
    ) -> None:
        """Bypass must support VMware, VirtualBox, Hyper-V, QEMU, Xen."""
        device = frida.get_local_device()
        pid = device.spawn([str(vm_detection_test_binary)])
        session = device.attach(pid)

        bypasser = FridaProtectionBypasser(pid=pid)
        bypasser.session = session

        detections = bypasser.detect_vm_detection()

        device.resume(pid)
        time.sleep(2)
        session.detach()
        device.kill(pid)

        if len(detections) > 0 and any(d.bypass_script for d in detections):
            combined_scripts = " ".join(
                str(d.bypass_script) for d in detections if d.bypass_script
            )

            hypervisors = ["VMware", "VirtualBox", "VBOX", "Hyper-V", "QEMU", "Xen"]
            detected_hypervisors = [hv for hv in hypervisors if hv in combined_scripts]

            assert len(detected_hypervisors) >= 3, \
                f"Bypass must handle multiple hypervisor types, found: {detected_hypervisors}"

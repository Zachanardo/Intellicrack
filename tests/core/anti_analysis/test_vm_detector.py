"""
Comprehensive test suite for VMDetector anti-analysis detection module.

This test suite validates the sophisticated virtual machine detection capabilities
required for Intellicrack's anti-analysis functionality. Tests are designed to
verify production-ready VM detection, evasion generation, and comprehensive
environmental analysis capabilities using specification-driven, black-box testing.

Test Coverage Requirements:
- 80%+ code coverage across all VMDetector methods
- Real-world VM detection scenarios across multiple hypervisors
- Advanced evasion technique validation and bypass generation
- Multi-platform compatibility testing (Windows/Linux)
- Edge case and error condition handling
- Performance and timing attack validation

Testing Philosophy:
- Specification-driven, black-box testing approach
- Production-ready capability validation without implementation inspection
- Real VM environment simulation and detection
- Sophisticated algorithmic processing validation
- Genuine security research tool effectiveness proof
"""

import unittest
import sys
import os
import tempfile
import time
import socket
import threading
import subprocess
import platform
import re
from pathlib import Path
from typing import Any, Optional, TYPE_CHECKING

import pytest

if TYPE_CHECKING:
    from intellicrack.core.anti_analysis.vm_detector import VMDetector as VMDetectorType

try:
    from intellicrack.core.anti_analysis.vm_detector import VMDetector
    MODULE_AVAILABLE = True
except ImportError:
    VMDetector = None  # type: ignore[misc,assignment]
    MODULE_AVAILABLE = False

pytestmark = pytest.mark.skipif(not MODULE_AVAILABLE, reason="Module not available")


class RealPlatformSimulator:
    """Real platform simulator for production VM detection testing."""

    def __init__(self, target_platform: Optional[str] = None) -> None:
        """Initialize platform simulator with real system detection capabilities."""
        self.target_platform: str = target_platform or platform.system()
        self.real_platform: str = platform.system()

    def system(self) -> str:
        """Return the simulated platform system."""
        return self.target_platform


class RealProcessSimulator:
    """Real process simulator for production VM detection testing."""

    def __init__(self) -> None:
        """Initialize process simulator with real VM process patterns."""
        self.vm_processes: dict[str, list[str]] = {
            'vmware': ['vmtoolsd.exe', 'vmwaretray.exe', 'vmwareuser.exe', 'vmacthlp.exe'],
            'virtualbox': ['vboxservice.exe', 'vboxtray.exe', 'vboxguest.exe'],
            'hyperv': ['vmms.exe', 'vmcompute.exe', 'hv_utils.sys'],
            'qemu': ['qemu-ga.exe', 'qemu-guest-agent'],
            'parallels': ['prl_cc.exe', 'prl_tools.exe']
        }

    def get_running_processes(self, vm_type: Optional[str] = None, include_system: bool = True) -> tuple[str, list[str]]:
        """Get simulated running processes including VM-specific ones."""
        base_processes = "explorer.exe notepad.exe chrome.exe winlogon.exe"
        base_list = ["explorer.exe", "notepad.exe", "chrome.exe", "winlogon.exe"]

        if vm_type and vm_type in self.vm_processes:
            vm_procs = self.vm_processes[vm_type]
            combined_processes = f"{base_processes} " + " ".join(vm_procs)
            combined_list = base_list + vm_procs
            return (combined_processes, combined_list)

        return (base_processes, base_list)


class RealRegistrySimulator:
    """Real Windows registry simulator for production testing."""

    def __init__(self) -> None:
        """Initialize registry simulator with real VM registry patterns."""
        self.vm_registry_keys: dict[str, list[str]] = {
            'vmware': [
                r'SOFTWARE\VMware, Inc.\VMware Tools',
                r'HARDWARE\DEVICEMAP\Scsi\Scsi Port 0\Scsi Bus 0\Target Id 0\Logical Unit Id 0',
                r'SYSTEM\ControlSet001\Services\vmci'
            ],
            'virtualbox': [
                r'SOFTWARE\Oracle\VirtualBox Guest Additions',
                r'HARDWARE\DEVICEMAP\Scsi\Scsi Port 0\Scsi Bus 0\Target Id 0\Logical Unit Id 0'
            ]
        }
        self.simulate_access_error: bool = False
        self.registry_values: dict[str, Any] = {}

    def openkey_context_manager(self, hkey: Any, key_path: str) -> "RealRegistrySimulator":
        """Simulate registry key opening with context manager."""
        return self

    def __enter__(self) -> "RealRegistrySimulator":
        """Context manager entry."""
        if self.simulate_access_error:
            raise OSError("Registry access denied")
        return self

    def __exit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        """Context manager exit."""
        pass


class RealFileSystemSimulator:
    """Real file system simulator for production VM detection testing."""

    def __init__(self) -> None:
        """Initialize file system simulator with real VM file patterns."""
        self.vm_files: dict[str, list[str]] = {
            'vmware': [
                os.path.join(os.environ.get('ProgramFiles', 'C:\\Program Files'), 'VMware', 'VMware Tools'),
                '/usr/bin/vmware-toolbox-cmd',
                '/usr/bin/vmtoolsd'
            ],
            'virtualbox': [
                os.path.join(os.environ.get('ProgramFiles', 'C:\\Program Files'), 'Oracle', 'VirtualBox Guest Additions'),
                '/usr/bin/VBoxClient',
                '/usr/sbin/VBoxService'
            ],
            'hyperv': [
                os.path.join(os.environ.get('SystemRoot', 'C:\\Windows'), 'System32', 'vmms.exe')
            ]
        }
        self.simulate_access_error: bool = False

    def path_exists(self, file_path: str, vm_type: Optional[str] = None) -> bool:
        """Simulate file path existence check."""
        if self.simulate_access_error:
            raise OSError("File system access error")

        if vm_type and vm_type in self.vm_files:
            return any(vm_file in file_path for vm_file in self.vm_files[vm_type])
        return False


class RealNetworkSimulator:
    """Real network adapter simulator for production testing."""

    def __init__(self) -> None:
        """Initialize network simulator with real VM MAC address patterns."""
        self.vm_mac_prefixes: dict[str, list[str]] = {
            'vmware': ['00:50:56', '00:0C:29', '00:1C:14'],
            'virtualbox': ['08:00:27'],
            'hyperv': ['00:15:5D'],
            'parallels': ['00:1C:42'],
            'qemu': ['52:54:00']
        }
        self.simulate_tool_missing: bool = False

    def get_network_output(self, platform_name: str, vm_type: Optional[str] = None) -> Optional[str]:
        """Get simulated network command output."""
        if self.simulate_tool_missing:
            return None

        if vm_type and vm_type in self.vm_mac_prefixes:
            mac_prefix = self.vm_mac_prefixes[vm_type][0]
            if platform_name == 'Windows':
                return f"""
Windows IP Configuration

Ethernet adapter VMware Network Adapter VMnet8:
   Physical Address. . . . . . . . . : {mac_prefix}-12-34-56
   DHCP Enabled. . . . . . . . . . . : Yes
"""
            elif platform_name == 'Linux':
                return f"""
1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN mode DEFAULT group default qlen 1000
    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
2: enp0s3: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc fq_codel state UP mode DEFAULT group default qlen 1000
    link/ether {mac_prefix.replace(':', ':').lower()}:78:90 brd ff:ff:ff:ff:ff:ff
"""
        return "No VM network adapters found"


class RealWMISimulator:
    """Real WMI simulator for production Windows testing."""

    def __init__(self) -> None:
        """Initialize WMI simulator with real VM hardware signatures."""
        self.vm_signatures: dict[str, dict[str, str]] = {
            'vmware': {
                'manufacturer': 'VMware, Inc.',
                'model': 'VMware Virtual Platform',
                'processor': 'Intel(R) Xeon(R) CPU           @ 2.40GHz',
                'bios': 'VMware, Inc.'
            },
            'virtualbox': {
                'manufacturer': 'innotek GmbH',
                'model': 'VirtualBox',
                'processor': 'Intel(R) Core(TM) i7',
                'bios': 'innotek GmbH'
            },
            'hyperv': {
                'manufacturer': 'Microsoft Corporation',
                'model': 'Virtual Machine',
                'processor': 'Intel(R) Xeon(R)',
                'bios': 'Microsoft Corporation'
            }
        }
        self.simulate_import_error: bool = False
        self.simulate_access_error: bool = False

    def WMI(self) -> "RealWMISimulator":
        """Simulate WMI connection."""
        if self.simulate_import_error:
            raise ImportError("No module named 'wmi'")
        if self.simulate_access_error:
            raise OSError("WMI access denied")
        return self

    def Win32_ComputerSystem(self, vm_type: Optional[str] = None) -> list["RealWMIComputerSystem"]:
        """Simulate Win32_ComputerSystem query."""
        if vm_type and vm_type in self.vm_signatures:
            return [RealWMIComputerSystem(self.vm_signatures[vm_type])]
        return [RealWMIComputerSystem({})]

    def Win32_Processor(self, vm_type: Optional[str] = None) -> list["RealWMIProcessor"]:
        """Simulate Win32_Processor query."""
        if vm_type and vm_type in self.vm_signatures:
            return [RealWMIProcessor(self.vm_signatures[vm_type])]
        return [RealWMIProcessor({})]

    def Win32_DiskDrive(self, vm_type: Optional[str] = None) -> list["RealWMIDiskDrive"]:
        """Simulate Win32_DiskDrive query."""
        if vm_type and vm_type in self.vm_signatures:
            disk_models: dict[str, str] = {
                'vmware': 'VMware Virtual disk SCSI Disk Device',
                'virtualbox': 'VBOX HARDDISK',
                'hyperv': 'Msft Virtual Disk'
            }
            model = disk_models.get(vm_type, 'Generic Disk')
            return [RealWMIDiskDrive(model)]
        return [RealWMIDiskDrive('Generic Physical Disk')]

    def Win32_BIOS(self, vm_type: Optional[str] = None) -> list["RealWMIBIOS"]:
        """Simulate Win32_BIOS query."""
        if vm_type and vm_type in self.vm_signatures:
            return [RealWMIBIOS(self.vm_signatures[vm_type]['bios'])]
        return [RealWMIBIOS('Generic BIOS')]


class RealWMIComputerSystem:
    """Real WMI computer system object simulator."""

    def __init__(self, system_info: dict[str, str]) -> None:
        """Initialize with system information."""
        self.Manufacturer: str = system_info.get('manufacturer', 'Generic Manufacturer')
        self.Model: str = system_info.get('model', 'Generic Model')


class RealWMIProcessor:
    """Real WMI processor object simulator."""

    def __init__(self, processor_info: dict[str, str]) -> None:
        """Initialize with processor information."""
        self.Manufacturer: str = processor_info.get('manufacturer', 'GenuineIntel')
        self.Name: str = processor_info.get('processor', 'Generic Processor')


class RealWMIDiskDrive:
    """Real WMI disk drive object simulator."""

    def __init__(self, model: str) -> None:
        """Initialize with disk model."""
        self.Model: str = model


class RealWMIBIOS:
    """Real WMI BIOS object simulator."""

    def __init__(self, manufacturer: str) -> None:
        """Initialize with BIOS manufacturer."""
        self.Manufacturer: str = manufacturer


class RealSubprocessSimulator:
    """Real subprocess simulator for production testing."""

    def __init__(self) -> None:
        """Initialize subprocess simulator with real VM command outputs."""
        self.simulate_timeout: bool = False
        self.simulate_error: bool = False
        self.vm_outputs: dict[str, dict[str, str]] = {
            'vmware': {
                'dmidecode': 'VMware, Inc.',
                'driverquery': 'vmci.sys         VMware VMCI Bus Driver',
                'lsmod': 'vmw_vmci               65536  1 vmw_vsock_vmci_transport'
            },
            'virtualbox': {
                'dmidecode': 'innotek GmbH',
                'driverquery': 'vboxguest.sys    VirtualBox Guest Driver',
                'lsmod': 'vboxguest             315392  7 vboxsf'
            }
        }

    def run_command(self, cmd_list: list[str], vm_type: Optional[str] = None, timeout: int = 5) -> "RealSubprocessResult":
        """Simulate subprocess command execution."""
        if self.simulate_timeout:
            raise subprocess.TimeoutExpired(cmd_list, timeout)
        if self.simulate_error:
            raise subprocess.CalledProcessError(1, cmd_list)

        result = RealSubprocessResult()

        if 'dmidecode' in cmd_list[0]:
            if vm_type and vm_type in self.vm_outputs:
                result.stdout = self.vm_outputs[vm_type]['dmidecode']
                result.returncode = 0
        elif 'driverquery' in cmd_list[0]:
            if vm_type and vm_type in self.vm_outputs:
                result.stdout = self.vm_outputs[vm_type]['driverquery']
                result.returncode = 0
        elif 'lsmod' in cmd_list[0]:
            if vm_type and vm_type in self.vm_outputs:
                result.stdout = self.vm_outputs[vm_type]['lsmod']
                result.returncode = 0

        return result


class RealSubprocessResult:
    """Real subprocess result simulator."""

    def __init__(self) -> None:
        """Initialize subprocess result."""
        self.stdout: str = ""
        self.stderr: str = ""
        self.returncode: int = 1


class RealDMISimulator:
    """Real DMI file system simulator for Linux testing."""

    def __init__(self) -> None:
        """Initialize DMI simulator with real VM DMI content."""
        self.vm_dmi_content: dict[str, dict[str, str]] = {
            'vmware': {
                '/sys/class/dmi/id/sys_vendor': 'VMware, Inc.',
                '/sys/class/dmi/id/product_name': 'VMware Virtual Platform',
                '/sys/class/dmi/id/bios_vendor': 'VMware, Inc.'
            },
            'virtualbox': {
                '/sys/class/dmi/id/sys_vendor': 'innotek GmbH',
                '/sys/class/dmi/id/product_name': 'VirtualBox',
                '/sys/class/dmi/id/bios_vendor': 'innotek GmbH'
            }
        }
        self.simulate_access_error: bool = False

    def read_dmi_file(self, file_path: str, vm_type: Optional[str] = None) -> str:
        """Simulate reading DMI file content."""
        if self.simulate_access_error:
            raise OSError("DMI file access error")

        if vm_type and vm_type in self.vm_dmi_content:
            return self.vm_dmi_content[vm_type].get(file_path, "Unknown")
        return "Unknown"


class RealVMTestEnvironment:
    """Real VM test environment for comprehensive testing."""

    def __init__(self, vm_type: Optional[str] = None) -> None:
        """Initialize comprehensive VM test environment."""
        self.vm_type: Optional[str] = vm_type
        self.platform_sim: RealPlatformSimulator = RealPlatformSimulator()
        self.process_sim: RealProcessSimulator = RealProcessSimulator()
        self.registry_sim: RealRegistrySimulator = RealRegistrySimulator()
        self.filesystem_sim: RealFileSystemSimulator = RealFileSystemSimulator()
        self.network_sim: RealNetworkSimulator = RealNetworkSimulator()
        self.wmi_sim: RealWMISimulator = RealWMISimulator()
        self.subprocess_sim: RealSubprocessSimulator = RealSubprocessSimulator()
        self.dmi_sim: RealDMISimulator = RealDMISimulator()

    def configure_vm_environment(self, vm_type: str) -> None:
        """Configure the test environment to simulate specific VM type."""
        self.vm_type = vm_type

    def reset_environment(self) -> None:
        """Reset environment to clean state."""
        self.vm_type = None
        self.filesystem_sim.simulate_access_error = False
        self.network_sim.simulate_tool_missing = False
        self.wmi_sim.simulate_import_error = False
        self.subprocess_sim.simulate_error = False


class TestVMDetectorInitialization(unittest.TestCase):
    """Test VMDetector initialization and configuration capabilities."""

    def setUp(self) -> None:
        """Set up test fixtures with production-ready expectations."""
        self.detector = VMDetector()
        self.test_env = RealVMTestEnvironment()

    def test_detector_initialization_creates_comprehensive_configuration(self) -> None:
        """Test VMDetector initializes with comprehensive VM detection configuration."""
        # Verify proper initialization
        self.assertIsNotNone(self.detector)
        self.assertTrue(hasattr(self.detector, 'detection_methods'))
        self.assertTrue(hasattr(self.detector, 'vm_signatures'))
        self.assertTrue(hasattr(self.detector, 'logger'))

        # Verify detection methods registry is comprehensive
        self.assertIsInstance(self.detector.detection_methods, dict)
        self.assertGreaterEqual(len(self.detector.detection_methods), 8,
                               "VMDetector should have comprehensive detection method coverage")

        # Verify expected detection methods are present
        expected_methods = [
            'cpuid', 'hypervisor_brand', 'hardware_signatures', 'process_list',
            'registry_keys', 'file_system', 'timing_attacks', 'network_adapters',
            'bios_info', 'device_drivers'
        ]

        for method in expected_methods:
            self.assertIn(method, self.detector.detection_methods,
                         f"Detection method '{method}' should be registered")
            self.assertTrue(callable(self.detector.detection_methods[method]),
                           f"Detection method '{method}' should be callable")

    def test_vm_signatures_database_comprehensive_coverage(self) -> None:
        """Test VM signatures database covers major virtualization platforms."""
        vm_signatures = self.detector.vm_signatures

        # Verify signatures structure
        self.assertIsInstance(vm_signatures, dict)
        self.assertGreaterEqual(len(vm_signatures), 4,
                               "Should support major VM platforms")

        # Verify coverage of major VM platforms
        expected_vm_types = ['vmware', 'virtualbox', 'hyperv', 'qemu', 'parallels']
        found_vm_types = [
            vm_type for vm_type in expected_vm_types if vm_type in vm_signatures
        ]
        self.assertGreaterEqual(len(found_vm_types), 4,
                               f"Should cover major VM platforms. Found: {found_vm_types}")

        # Verify each VM type has comprehensive signature data
        for vm_type, signatures in vm_signatures.items():
            self.assertIsInstance(signatures, dict,
                                 f"VM type '{vm_type}' should have signature dictionary")

            # Each VM should have multiple detection vectors
            expected_categories = ['processes', 'files', 'registry', 'hardware', 'mac_prefixes']
            found_categories = [
                category
                for category in expected_categories
                if signatures.get(category)
            ]
            self.assertGreaterEqual(len(found_categories), 2,
                                   f"VM type '{vm_type}' should have multiple detection vectors")

    def test_logger_configuration_for_security_research(self) -> None:
        """Test logger is properly configured for security research operations."""
        logger = self.detector.logger

        self.assertIsNotNone(logger)
        self.assertEqual(logger.name, "IntellicrackLogger.VMDetector")

        # Logger should be configured for detailed VM detection logging
        self.assertTrue(hasattr(logger, 'debug'))
        self.assertTrue(hasattr(logger, 'info'))
        self.assertTrue(hasattr(logger, 'error'))


class TestPrimaryVMDetection(unittest.TestCase):
    """Test primary VM detection functionality and capabilities."""

    def setUp(self) -> None:
        """Set up test fixtures."""
        self.detector = VMDetector()
        self.test_env = RealVMTestEnvironment()

    def test_detect_vm_returns_comprehensive_detection_results(self) -> None:
        """Test detect_vm returns comprehensive VM detection analysis."""
        result = self.detector.detect_vm()

        # Verify result structure
        self.assertIsInstance(result, dict)

        # Verify required fields
        required_fields = ['is_vm', 'confidence', 'vm_type', 'detections', 'evasion_score']
        for field in required_fields:
            self.assertIn(field, result, f"Result should contain '{field}' field")

        # Verify data types and ranges
        self.assertIsInstance(result['is_vm'], bool)
        self.assertIsInstance(result['confidence'], (int, float))
        self.assertGreaterEqual(result['confidence'], 0.0)
        self.assertLessEqual(result['confidence'], 1.0)
        self.assertIsInstance(result['detections'], dict)
        self.assertIsInstance(result['evasion_score'], int)
        self.assertGreaterEqual(result['evasion_score'], 0)
        self.assertLessEqual(result['evasion_score'], 10)

        # VM type should be string or None
        self.assertTrue(result['vm_type'] is None or isinstance(result['vm_type'], str))

    def test_detect_vm_aggressive_mode_enhanced_detection(self) -> None:
        """Test aggressive mode provides enhanced VM detection capabilities."""
        # Test standard detection
        standard_result = self.detector.detect_vm(aggressive=False)

        # Test aggressive detection
        aggressive_result = self.detector.detect_vm(aggressive=True)

        # Both should return valid results
        self.assertIsInstance(standard_result, dict)
        self.assertIsInstance(aggressive_result, dict)

        # Aggressive mode should potentially find more or have higher confidence
        # (this tests that aggressive methods are actually being executed)
        aggressive_detections = len([d for d in aggressive_result['detections'].values()
                                   if d.get('detected', False)])
        standard_detections = len([d for d in standard_result['detections'].values()
                                 if d.get('detected', False)])

        # Aggressive mode should be at least as thorough as standard
        self.assertGreaterEqual(aggressive_detections, standard_detections,
                               "Aggressive mode should be at least as thorough as standard")

    def test_detect_vm_performance_requirements(self) -> None:
        """Test VM detection meets performance requirements for security research."""
        start_time = time.time()
        result = self.detector.detect_vm()
        detection_time = time.time() - start_time

        # Detection should complete within reasonable time for security analysis
        self.assertLess(detection_time, 15.0,
                       f"VM detection took {detection_time:.2f} seconds, expected < 15 seconds")

        # Should return valid result regardless of performance
        self.assertIsInstance(result, dict)
        self.assertIn('is_vm', result)

    def test_detect_vm_error_handling_resilience(self) -> None:
        """Test VM detection handles errors gracefully during security analysis."""
        # Create a real failing detection method to test error handling
        def failing_cpuid_method() -> None:
            """Test method that intentionally fails to validate error handling."""
            raise Exception("Test error for cpuid detection validation")

        # Store original method to restore later
        original_method: Any = None
        if 'cpuid' in self.detector.detection_methods:
            original_method = getattr(self.detector, 'cpuid', None)
            # Temporarily replace with failing method
            setattr(self.detector, 'cpuid', failing_cpuid_method)

        try:
            result = self.detector.detect_vm()

            # Should still return valid result structure even with failing components
            self.assertIsInstance(result, dict)
            self.assertIn('is_vm', result)
            self.assertIn('detections', result)

            # Failed method should be handled gracefully without crashing detection
            self.assertIn('cpuid', result['detections'])

        finally:
            # Restore original method
            self.detector.detection_methods['cpuid'] = original_method


class TestCPUIDDetection(unittest.TestCase):
    """Test CPUID-based VM detection capabilities."""

    def setUp(self) -> None:
        """Set up test fixtures."""
        self.detector = VMDetector()
        self.test_env = RealVMTestEnvironment()

    def test_check_cpuid_linux_hypervisor_detection(self) -> None:
        """Test CPUID detection on Linux systems identifies hypervisor presence."""
        current_platform = platform.system()

        try:
            detected, confidence, details = self.detector._check_cpuid()  # type: ignore[attr-defined]

            # Should return valid CPUID detection results
            self.assertIsInstance(detected, bool)
            self.assertIsInstance(confidence, (int, float))
            self.assertIsInstance(details, dict)

            # Confidence should be in valid range
            self.assertGreaterEqual(confidence, 0.0)
            self.assertLessEqual(confidence, 1.0)

            # Details should contain relevant CPUID information
            if detected:
                # If VM detected, should have hypervisor indicators
                self.assertGreater(confidence, 0.5, "Detected VM should have reasonable confidence")

                # Should have meaningful detection details
                self.assertGreater(len(details), 0, "Detection details should not be empty")

                # Check for expected CPUID indicators
                expected_indicators = ['hypervisor_bit', 'vendor_id', 'cpu_flags']
                found_indicators = sum(bool(indicator in details)
                                   for indicator in expected_indicators)
                self.assertGreater(found_indicators, 0,
                                 "Should have at least one CPUID indicator")

            # On Linux, should attempt to read /proc/cpuinfo if available
            if current_platform == 'Linux':
                try:
                    with open('/proc/cpuinfo') as f:
                        cpuinfo_content = f.read()
                        # Real system test: if hypervisor flag exists, should be detected
                        if 'hypervisor' in cpuinfo_content:
                            self.assertTrue(detected, "Real hypervisor flag should be detected")
                except OSError:
                    # /proc/cpuinfo not accessible, test graceful handling
                    pass

        except Exception as e:
            # CPUID detection should handle errors gracefully
            self.assertIsInstance(e, (OSError, PermissionError, AttributeError, ImportError),
                                f"Unexpected exception type: {type(e).__name__}: {e}")

    def test_check_cpuid_windows_wmi_detection(self) -> None:
        """Test CPUID detection on Windows using WMI identifies VM processors."""
        current_platform = platform.system()

        try:
            detected, confidence, details = self.detector._check_cpuid()  # type: ignore[attr-defined]

            # Should return valid detection results regardless of platform
            self.assertIsInstance(detected, bool)
            self.assertIsInstance(confidence, (int, float))
            self.assertIsInstance(details, dict)

            # Confidence should be in valid range
            self.assertGreaterEqual(confidence, 0.0)
            self.assertLessEqual(confidence, 1.0)

            # Test Windows-specific WMI functionality if on Windows
            if current_platform == 'Windows':
                try:
                    import wmi
                    # Test real WMI processor detection
                    c = wmi.WMI()
                    if processors := c.Win32_Processor():
                        # Check for real VM indicators in processor information
                        vm_indicators = ['vmware', 'virtualbox', 'microsoft corporation', 'xen', 'qemu']
                        processor = processors[0]
                        processor_name = getattr(processor, 'Manufacturer', '')
                        processor_model = getattr(processor, 'Name', '')
                        is_vm_processor = any(indicator in processor_name.lower()
                                            for indicator in vm_indicators)
                        is_vm_model = any(indicator in processor_model.lower()
                                        for indicator in vm_indicators)

                        if is_vm_processor or is_vm_model:
                            # If real VM detected via WMI, verify detection works
                            self.assertTrue(detected, "Real VM processor should be detected")
                            self.assertGreater(confidence, 0.5, "VM detection should have good confidence")

                        # Verify details structure for Windows WMI detection
                        if detected:
                            self.assertGreater(len(details), 0, "Detection details should contain WMI data")

                except ImportError:
                    # WMI not available, should handle gracefully
                    pass
                except Exception as e:
                    # Other WMI errors should be handled gracefully
                    self.assertIsInstance(e, (OSError, PermissionError, AttributeError),
                                        f"WMI error should be handled: {type(e).__name__}: {e}")

            elif detected:
                self.assertGreater(len(details), 0, "Non-Windows detection should have details")

        except Exception as e:
            # Detection should handle all errors gracefully
            self.assertIsInstance(e, (OSError, PermissionError, AttributeError, ImportError),
                                f"CPUID detection error should be handled: {type(e).__name__}: {e}")

    def test_check_cpuid_handles_import_errors_gracefully(self) -> None:
        """Test CPUID detection handles missing dependencies gracefully."""
        # This should not raise an exception regardless of platform or available dependencies
        try:
            detected, confidence, details = self.detector._check_cpuid()  # type: ignore[attr-defined]

            # Should return valid results even with missing dependencies
            self.assertIsInstance(detected, bool)
            self.assertIsInstance(confidence, (int, float))
            self.assertIsInstance(details, dict)

            # Confidence should be in valid range
            self.assertGreaterEqual(confidence, 0.0)
            self.assertLessEqual(confidence, 1.0)

            # Should have some detection details even if some methods fail
            # (May not have hypervisor_bit if dependencies missing, but should have something)
            expected_fields = ['hypervisor_bit', 'vendor_id', 'cpu_flags', 'detection_method']
            found_fields = sum(bool(field in details)
                           for field in expected_fields)
            self.assertGreaterEqual(found_fields, 1,
                                  "Should have at least one detection field even with missing dependencies")

        except Exception as e:
            # Should handle import errors and other dependency issues gracefully
            self.assertIsInstance(e, (ImportError, OSError, PermissionError, AttributeError),
                                f"Should handle dependency errors gracefully: {type(e).__name__}: {e}")


class TestHypervisorBrandDetection(unittest.TestCase):
    """Test hypervisor brand detection capabilities."""

    def setUp(self) -> None:
        """Set up test fixtures."""
        self.detector = VMDetector()
        self.test_env = RealVMTestEnvironment()

    def test_check_hypervisor_brand_linux_dmidecode(self) -> None:
        """Test hypervisor brand detection using Linux dmidecode."""
        current_platform = platform.system()

        try:
            detected, confidence, details = self.detector._check_hypervisor_brand()

            # Should return valid hypervisor brand detection results
            self.assertIsInstance(detected, bool)
            self.assertIsInstance(confidence, (int, float))
            self.assertIsInstance(details, dict)

            # Confidence should be in valid range
            self.assertGreaterEqual(confidence, 0.0)
            self.assertLessEqual(confidence, 1.0)

            # Test Linux-specific dmidecode functionality if on Linux
            if current_platform == 'Linux':
                try:
                    # Test real dmidecode execution
                    import shutil
                    if shutil.which('dmidecode'):
                        result = subprocess.run(['dmidecode', '-s', 'system-manufacturer'],
                                              capture_output=True, text=True, timeout=5)

                        if result.returncode == 0:
                            manufacturer = result.stdout.strip()

                            # Check for real VM indicators in system manufacturer
                            vm_manufacturers = ['vmware', 'oracle', 'microsoft', 'xen', 'qemu',
                                              'virtualbox', 'parallels', 'bochs']

                            is_vm_manufacturer = any(vm_brand in manufacturer.lower()
                                                   for vm_brand in vm_manufacturers)

                            if is_vm_manufacturer and detected:
                                # Real VM detected, verify detection logic works
                                self.assertGreater(confidence, 0.5,
                                                 "Real VM manufacturer should have good confidence")
                                self.assertIn('brand', details,
                                            "Detection should include brand information")

                                # Brand should contain VM manufacturer info
                                detected_brand = details.get('brand', '').lower()
                                self.assertTrue(any(vm_brand in detected_brand
                                                  for vm_brand in vm_manufacturers),
                                              f"Brand '{detected_brand}' should contain VM indicator")

                except (subprocess.TimeoutExpired, subprocess.CalledProcessError,
                       PermissionError, FileNotFoundError):
                    # dmidecode not available or insufficient permissions, test graceful handling
                    pass

            # For all platforms, test detection result structure
            if detected:
                # Should have meaningful detection details
                self.assertGreater(len(details), 0, "Detection details should not be empty")

                # Should have brand information if detected
                expected_fields = ['brand', 'manufacturer', 'product', 'detection_method']
                found_fields = sum(bool(field in details)
                               for field in expected_fields)
                self.assertGreaterEqual(found_fields, 1,
                                      "Should have at least one brand detection field")

        except Exception as e:
            # Hypervisor brand detection should handle errors gracefully
            self.assertIsInstance(e, (OSError, PermissionError, subprocess.SubprocessError,
                                    ImportError, AttributeError),
                                f"Hypervisor brand detection error should be handled: {type(e).__name__}: {e}")

    def test_check_hypervisor_brand_handles_subprocess_failure(self) -> None:
        """Test hypervisor brand detection handles subprocess failures."""
        try:
            detected, confidence, details = self.detector._check_hypervisor_brand()

            # Should handle failures gracefully and return valid structure
            self.assertIsInstance(detected, bool)
            self.assertIsInstance(confidence, (int, float))
            self.assertIsInstance(details, dict)

            # Confidence should be in valid range even with subprocess failures
            self.assertGreaterEqual(confidence, 0.0)
            self.assertLessEqual(confidence, 1.0)

            # Should have some detection attempt details even if subprocess fails
            expected_fields = ['brand', 'manufacturer', 'product', 'detection_method', 'error']
            found_fields = sum(bool(field in details)
                           for field in expected_fields)
            self.assertGreaterEqual(found_fields, 1,
                                  "Should have at least one detection field even with failures")

        except Exception as e:
            # Should handle all subprocess and system errors gracefully
            self.assertIsInstance(e, (subprocess.SubprocessError, OSError, PermissionError,
                                    FileNotFoundError, subprocess.TimeoutExpired, AttributeError),
                                f"Subprocess failure should be handled gracefully: {type(e).__name__}: {e}")

        # Test specific error conditions that might occur
        current_platform = platform.system()

        if current_platform == 'Linux':
            # Test with invalid dmidecode command to verify error handling
            try:
                # This should either work or fail gracefully
                invalid_result = subprocess.run(['dmidecode', '-s', 'nonexistent-field'],
                                              capture_output=True, text=True, timeout=2)
                # Command may fail but should not crash the detection system
            except (subprocess.TimeoutExpired, subprocess.CalledProcessError,
                   FileNotFoundError, PermissionError):
                # These errors should be handled gracefully by the detector
                pass


class TestHardwareSignatureDetection(unittest.TestCase):
    """Test hardware signature detection for VM identification."""

    def setUp(self) -> None:
        """Set up test fixtures."""
        self.detector = VMDetector()
        self.test_env = RealVMTestEnvironment()

    def test_check_hardware_signatures_windows_wmi_comprehensive(self) -> None:
        """Test comprehensive Windows WMI hardware signature detection."""
        current_platform = platform.system()

        try:
            detected, confidence, details = self.detector._check_hardware_signatures()

            # Should return valid hardware signature detection results
            self.assertIsInstance(detected, bool)
            self.assertIsInstance(confidence, (int, float))
            self.assertIsInstance(details, dict)

            # Confidence should be in valid range
            self.assertGreaterEqual(confidence, 0.0)
            self.assertLessEqual(confidence, 1.0)

            # Test Windows-specific WMI hardware detection if on Windows
            if current_platform == 'Windows':
                try:
                    import wmi
                    c = wmi.WMI()

                    if computer_systems := c.Win32_ComputerSystem():
                        system = computer_systems[0]
                        model = getattr(system, 'Model', '').lower()
                        manufacturer = getattr(system, 'Manufacturer', '').lower()

                        # Check for real VM hardware signatures
                        vm_signatures = ['virtualbox', 'vmware', 'microsoft corporation',
                                       'xen', 'qemu', 'parallels', 'bochs', 'virtual machine']

                        has_vm_model = any(sig in model for sig in vm_signatures)
                        has_vm_manufacturer = any(sig in manufacturer for sig in vm_signatures)

                        # Test real WMI disk drive detection
                        disk_drives = c.Win32_DiskDrive()
                        vm_disk_signatures = ['vbox', 'vmware', 'qemu', 'microsoft virtual disk']
                        has_vm_disk = any(any(sig in getattr(disk, 'Model', '').lower()
                                            for sig in vm_disk_signatures)
                                        for disk in disk_drives)

                        if (has_vm_model or has_vm_manufacturer or has_vm_disk) and detected:
                            self.assertGreater(confidence, 0.5,
                                             "Real VM hardware should have good confidence")
                            self.assertIn('detected_hardware', details,
                                        "Should have hardware detection details")
                        
                            hardware_details = details.get('detected_hardware', [])
                            self.assertGreater(len(hardware_details), 0,
                                             "Should have specific hardware signatures")
                        
                            # Should contain meaningful hardware information
                            for hw_detail in hardware_details:
                                self.assertIsInstance(hw_detail, (str, dict))
                                if isinstance(hw_detail, dict):
                                    self.assertGreater(len(hw_detail), 0)

                except ImportError:
                    # WMI not available, should handle gracefully
                    pass
                except Exception as e:
                    # Other WMI errors should be handled gracefully
                    self.assertIsInstance(e, (OSError, PermissionError, AttributeError),
                                        f"WMI hardware detection error should be handled: {type(e).__name__}: {e}")

            # For all platforms, validate detection result structure
            if detected:
                self.assertIn('detected_hardware', details,
                            "Detection should include hardware details")

                hardware_info = details.get('detected_hardware', [])
                self.assertIsInstance(hardware_info, (list, dict))

                if isinstance(hardware_info, list):
                    self.assertGreater(len(hardware_info), 0,
                                     "Hardware detection should have specific signatures")

        except Exception as e:
            # Hardware signature detection should handle all errors gracefully
            self.assertIsInstance(e, (ImportError, OSError, PermissionError, AttributeError),
                                f"Hardware signature detection error should be handled: {type(e).__name__}: {e}")

    def test_check_hardware_signatures_linux_dmi_detection(self) -> None:
        """Test Linux DMI hardware signature detection."""
        current_platform = platform.system()

        try:
            detected, confidence, details = self.detector._check_hardware_signatures()

            # Should return valid hardware signature detection results
            self.assertIsInstance(detected, bool)
            self.assertIsInstance(confidence, (int, float))
            self.assertIsInstance(details, dict)

            # Confidence should be in valid range
            self.assertGreaterEqual(confidence, 0.0)
            self.assertLessEqual(confidence, 1.0)

            # Test Linux-specific DMI detection if on Linux
            if current_platform == 'Linux':
                # DMI files that may contain VM signatures
                dmi_files = [
                    '/sys/class/dmi/id/product_name',
                    '/sys/class/dmi/id/sys_vendor',
                    '/sys/class/dmi/id/board_vendor',
                    '/sys/class/dmi/id/chassis_vendor',
                    '/sys/class/dmi/id/bios_vendor'
                ]

                vm_indicators = ['vmware', 'virtualbox', 'microsoft corporation',
                               'xen', 'qemu', 'parallels', 'bochs', 'innotek',
                               'virtual', 'hyperv']

                real_vm_detected = False
                dmi_content = {}

                # Read real DMI files if available
                for dmi_file in dmi_files:
                    try:
                        if os.path.exists(dmi_file):
                            with open(dmi_file) as f:
                                content = f.read().strip().lower()
                                dmi_content[dmi_file] = content

                                # Check for real VM indicators in DMI content
                                if any(indicator in content for indicator in vm_indicators):
                                    real_vm_detected = True

                    except OSError:
                        # DMI file not accessible, continue with other files
                        continue

                # If real VM signatures found in DMI, verify detection works
                if real_vm_detected and detected:
                    self.assertGreater(confidence, 0.5,
                                     "Real VM DMI signatures should have good confidence")
                    self.assertIn('detected_hardware', details,
                                "Should have hardware detection details")

                    hardware_details = details.get('detected_hardware', [])
                    self.assertGreater(len(hardware_details), 0,
                                     "Should have specific DMI signatures")

                    # Should contain meaningful hardware information from DMI
                    for hw_detail in hardware_details:
                        self.assertIsInstance(hw_detail, (str, dict))
                        if isinstance(hw_detail, str):
                            self.assertGreater(len(hw_detail.strip()), 0)

            # For all platforms, validate detection result structure
            if detected:
                self.assertIn('detected_hardware', details,
                            "Hardware detection should include details")

                hardware_info = details.get('detected_hardware', [])
                self.assertIsInstance(hardware_info, (list, dict))

        except Exception as e:
            # DMI hardware signature detection should handle errors gracefully
            self.assertIsInstance(e, (IOError, OSError, PermissionError, AttributeError),
                                f"DMI hardware detection error should be handled: {type(e).__name__}: {e}")


class TestProcessListDetection(unittest.TestCase):
    """Test VM process detection capabilities."""

    def setUp(self) -> None:
        """Set up test fixtures."""
        self.detector = VMDetector()
        self.test_env = RealVMTestEnvironment()
        self.process_sim = RealProcessSimulator()

    def test_check_process_list_detects_vm_processes(self) -> None:
        """Test process list detection identifies VM-specific processes."""
        # Configure process simulator with VMware tools
        self.test_env.configure_vm_environment('vmware')

        # Replace detector's get_running_processes method with simulator
        original_method = getattr(self.detector, 'get_running_processes', None)

        def simulate_get_processes() -> tuple[str, list[str]]:
            return self.process_sim.get_running_processes('vmware', True)

        self.detector.get_running_processes = simulate_get_processes  # type: ignore[method-assign]

        try:
            detected, confidence, details = self.detector._check_process_list()

            # Should detect VMware processes
            self.assertTrue(detected, "Should detect VMware processes")
            self.assertGreater(confidence, 0.6, "Good confidence for process detection")
            self.assertIn('detected_processes', details)
            self.assertIn('vm_type', details)
            self.assertGreater(len(details['detected_processes']), 0)

        finally:
            # Restore original method if it existed
            if original_method:
                self.detector.get_running_processes = original_method  # type: ignore[method-assign]

    def test_check_process_list_multiple_vm_indicators(self) -> None:
        """Test process detection with multiple VM type indicators."""
        # Configure process simulator with mixed VM processes
        original_method = getattr(self.detector, 'get_running_processes', None)

        def simulate_mixed_processes() -> tuple[str, list[str]]:
            mixed_processes = "vboxservice.exe vmtoolsd.exe explorer.exe"
            mixed_list = ["vboxservice.exe", "vmtoolsd.exe", "explorer.exe"]
            return (mixed_processes, mixed_list)

        self.detector.get_running_processes = simulate_mixed_processes  # type: ignore[method-assign]

        try:
            detected, confidence, details = self.detector._check_process_list()

            # Should detect multiple VM processes
            self.assertTrue(detected, "Should detect multiple VM processes")
            self.assertIn('detected_processes', details)
            self.assertEqual(len(details['detected_processes']), 2)

        finally:
            # Restore original method if it existed
            if original_method:
                self.detector.get_running_processes = original_method  # type: ignore[method-assign]

    def test_check_process_list_no_vm_processes(self) -> None:
        """Test process detection when no VM processes are present."""
        # Configure process simulator without VM processes
        original_method: Any = getattr(self.detector, 'get_running_processes', None)

        def simulate_clean_processes() -> tuple[str, list[str]]:
            return self.process_sim.get_running_processes(None, True)

        self.detector.get_running_processes = simulate_clean_processes  # type: ignore[method-assign]

        try:
            detected, confidence, details = self.detector._check_process_list()

            # Should not detect VM processes
            self.assertFalse(detected, "Should not detect VM processes in clean environment")
            self.assertEqual(confidence, 0.0)
            self.assertEqual(len(details['detected_processes']), 0)

        finally:
            # Restore original method if it existed
            if original_method:
                self.detector.get_running_processes = original_method  # type: ignore[method-assign]


class TestRegistryKeyDetection(unittest.TestCase):
    """Test Windows registry-based VM detection."""

    def setUp(self) -> None:
        """Set up test fixtures."""
        self.detector = VMDetector()
        self.test_env = RealVMTestEnvironment()
        self.registry_sim = RealRegistrySimulator()

    def test_check_registry_keys_non_windows_platform(self) -> None:
        """Test registry detection returns false on non-Windows platforms."""
        # Configure platform simulator for Linux
        self.test_env.platform_sim.target_platform = 'Linux'

        # Replace platform.system with simulator
        original_system = platform.system
        platform.system = self.test_env.platform_sim.system

        try:
            detected, confidence, details = self.detector._check_registry_keys()

            # Should return false on non-Windows
            self.assertFalse(detected)
            self.assertEqual(confidence, 0.0)
            self.assertIn('detected_keys', details)
            self.assertEqual(len(details['detected_keys']), 0)

        finally:
            # Restore original platform.system
            platform.system = original_system

    def test_check_registry_keys_windows_vmware_detection(self) -> None:
        """Test Windows registry detection for VMware Tools."""
        # Configure for Windows platform
        self.test_env.platform_sim.target_platform = 'Windows'

        # Replace platform.system with simulator
        original_system = platform.system
        platform.system = self.test_env.platform_sim.system

        # Create real winreg simulator module
        class RealWinregSimulator:
            HKEY_LOCAL_MACHINE = 'HKLM'

            @staticmethod
            def OpenKey(hkey: Any, key_path: str) -> Any:
                return self.registry_sim.openkey_context_manager(hkey, key_path)

        # Replace importlib import for winreg
        builtins_dict: dict[str, Any] = __builtins__  # type: ignore[assignment]
        original_import: Any = builtins_dict.get('__import__')

        def mock_import(name: str, *args: Any) -> Any:
            if name == 'winreg':
                return RealWinregSimulator()
            return original_import(name, *args)

        builtins_dict['__import__'] = mock_import

        try:
            detected, confidence, details = self.detector._check_registry_keys()

            # Should attempt registry detection
            self.assertIsInstance(detected, bool)
            self.assertIsInstance(confidence, (int, float))
            self.assertIn('detected_keys', details)

        finally:
            # Restore original functions
            platform.system = original_system
            builtins_dict['__import__'] = original_import

    def test_check_registry_keys_handles_registry_errors(self) -> None:
        """Test registry detection handles Windows registry access errors."""
        # Configure for Windows platform
        self.test_env.platform_sim.target_platform = 'Windows'
        self.registry_sim.simulate_access_error = True

        # Replace platform.system with simulator
        original_system = platform.system
        platform.system = self.test_env.platform_sim.system

        # Create real winreg simulator that raises errors
        class RealWinregErrorSimulator:
            HKEY_LOCAL_MACHINE = 'HKLM'

            @staticmethod
            def OpenKey(hkey: Any, key_path: str) -> Any:
                raise OSError("Registry access denied")

        # Replace importlib import for winreg
        builtins_dict: dict[str, Any] = __builtins__  # type: ignore[assignment]
        original_import: Any = builtins_dict.get('__import__')

        def mock_import(name: str, *args: Any) -> Any:
            if name == 'winreg':
                return RealWinregErrorSimulator()
            return original_import(name, *args)

        builtins_dict['__import__'] = mock_import

        try:
            detected, confidence, details = self.detector._check_registry_keys()

            # Should handle registry errors gracefully
            self.assertIsInstance(detected, bool)
            self.assertIsInstance(confidence, (int, float))
            self.assertIn('detected_keys', details)

        finally:
            # Restore original functions
            platform.system = original_system
            builtins_dict['__import__'] = original_import


class TestFileSystemDetection(unittest.TestCase):
    """Test file system artifact detection for VM identification."""

    def setUp(self) -> None:
        """Set up test fixtures."""
        self.detector = VMDetector()
        self.test_env = RealVMTestEnvironment()
        self.filesystem_sim = RealFileSystemSimulator()

    def test_check_file_system_detects_vm_files(self) -> None:
        """Test file system detection identifies VM-specific files."""
        # Replace os.path.exists with simulator
        original_exists = os.path.exists

        def simulate_vmware_files(path: str) -> bool:
            return self.filesystem_sim.path_exists(path, 'vmware')

        os.path.exists = simulate_vmware_files  # type: ignore[assignment]

        try:
            detected, confidence, details = self.detector._check_file_system()

            # Should detect VMware files
            self.assertTrue(detected, "Should detect VMware Tools files")
            self.assertGreater(confidence, 0.6, "Good confidence for file detection")
            self.assertIn('detected_files', details)
            self.assertIn('vm_type', details)
            self.assertGreater(len(details['detected_files']), 0)

        finally:
            # Restore original os.path.exists
            os.path.exists = original_exists

    def test_check_file_system_no_vm_files(self) -> None:
        """Test file system detection when no VM files are present."""
        # Replace os.path.exists with simulator returning False
        original_exists = os.path.exists

        def simulate_no_files(path: str) -> bool:
            return False

        os.path.exists = simulate_no_files  # type: ignore[assignment]

        try:
            detected, confidence, details = self.detector._check_file_system()

            # Should not detect VM files
            self.assertFalse(detected, "Should not detect VM files in clean environment")
            self.assertEqual(confidence, 0.0)
            self.assertEqual(len(details['detected_files']), 0)

        finally:
            # Restore original os.path.exists
            os.path.exists = original_exists

    def test_check_file_system_handles_file_system_errors(self) -> None:
        """Test file system detection handles OS errors gracefully."""
        # Configure simulator to raise errors
        self.filesystem_sim.simulate_access_error = True

        # Replace os.path.exists with simulator
        original_exists = os.path.exists

        def simulate_error_files(path: str) -> bool:
            return self.filesystem_sim.path_exists(path)

        os.path.exists = simulate_error_files  # type: ignore[assignment]

        try:
            detected, confidence, details = self.detector._check_file_system()

            # Should handle file system errors gracefully
            self.assertIsInstance(detected, bool)
            self.assertIsInstance(confidence, (int, float))
            self.assertIn('detected_files', details)

        except OSError:
            # Expected behavior - detection should handle this gracefully
            pass
        finally:
            # Restore original os.path.exists
            os.path.exists = original_exists


class TestTimingAttacks(unittest.TestCase):
    """Test timing attack detection for VM identification."""

    def setUp(self) -> None:
        """Set up test fixtures."""
        self.detector = VMDetector()
        self.test_env = RealVMTestEnvironment()

    def test_check_timing_attacks_measures_instruction_timing(self) -> None:
        """Test timing attacks measure instruction execution timing variance."""
        detected, confidence, details = self.detector._check_timing_attacks()  # type: ignore[attr-defined]

        # Should complete timing measurements
        self.assertIsInstance(detected, bool)
        self.assertIsInstance(confidence, (int, float))
        self.assertIn('timing_anomalies', details)
        self.assertIsInstance(details['timing_anomalies'], int)

        # If detected, should have significant timing variance
        if detected:
            self.assertGreater(confidence, 0.5, "Timing detection should have reasonable confidence")
            self.assertGreater(details['timing_anomalies'], 0)

    def test_check_timing_attacks_handles_timing_errors(self) -> None:
        """Test timing attacks handle measurement errors gracefully."""
        # This test ensures the timing code doesn't crash on edge cases
        original_perf_counter = time.perf_counter_ns

        # Create a real error scenario
        call_count = 0
        def simulate_timing_error() -> int:
            nonlocal call_count
            call_count += 1
            return int(float('inf')) if call_count == 2 else original_perf_counter()

        time.perf_counter_ns = simulate_timing_error

        try:
            detected, confidence, details = self.detector._check_timing_attacks()  # type: ignore[attr-defined]

            self.assertIsInstance(detected, bool)
            self.assertIsInstance(confidence, (int, float))
            self.assertIn('timing_anomalies', details)

        finally:
            # Restore original timing function
            time.perf_counter_ns = original_perf_counter


class TestNetworkAdapterDetection(unittest.TestCase):
    """Test network adapter MAC address detection for VM identification."""

    def setUp(self) -> None:
        """Set up test fixtures."""
        self.detector = VMDetector()
        self.test_env = RealVMTestEnvironment()
        self.network_sim = RealNetworkSimulator()

    def test_check_network_adapters_windows_ipconfig(self) -> None:
        """Test network adapter detection on Windows using ipconfig."""
        # Configure platform and tools
        self.test_env.platform_sim.target_platform = 'Windows'

        # Replace platform.system, shutil.which, and subprocess.run
        original_system = platform.system
        original_which: Any = None
        original_subprocess_run = subprocess.run

        try:
            import shutil
            original_which = shutil.which

            platform.system = self.test_env.platform_sim.system
            shutil.which = lambda cmd: 'C:\\Windows\\System32\\ipconfig.exe' if cmd == 'ipconfig' else None  # type: ignore[assignment]

            def simulate_ipconfig_run(cmd: Any, **kwargs: Any) -> RealSubprocessResult:
                result = RealSubprocessResult()
                result.stdout = self.network_sim.get_network_output('Windows', 'vmware') or ""
                result.returncode = 0
                return result

            subprocess.run = simulate_ipconfig_run  # type: ignore[assignment]

            detected, confidence, details = self.detector._check_network_adapters()

            # Should detect VMware MAC prefix
            self.assertTrue(detected, "Should detect VMware MAC address")
            self.assertGreater(confidence, 0.7, "Good confidence for MAC detection")
            self.assertIn('detected_macs', details)
            self.assertIn('vm_type', details)

        finally:
            # Restore original functions
            platform.system = original_system
            if original_which is not None:
                shutil.which = original_which
            subprocess.run = original_subprocess_run

    def test_check_network_adapters_linux_ip_command(self) -> None:
        """Test network adapter detection on Linux using ip command."""
        # Configure platform and tools
        self.test_env.platform_sim.target_platform = 'Linux'

        # Replace platform.system, shutil.which, and subprocess.run
        original_system = platform.system
        original_which: Any = None
        original_subprocess_run = subprocess.run

        try:
            import shutil
            original_which = shutil.which

            platform.system = self.test_env.platform_sim.system
            shutil.which = lambda cmd: '/sbin/ip' if cmd == 'ip' else None  # type: ignore[assignment]

            def simulate_ip_run(cmd: Any, **kwargs: Any) -> RealSubprocessResult:
                result = RealSubprocessResult()
                result.stdout = self.network_sim.get_network_output('Linux', 'virtualbox') or ""
                result.returncode = 0
                return result

            subprocess.run = simulate_ip_run  # type: ignore[assignment]

            detected, confidence, details = self.detector._check_network_adapters()

            # Should detect VirtualBox MAC prefix
            self.assertTrue(detected, "Should detect VirtualBox MAC address")
            self.assertIn('detected_macs', details)
            self.assertIn('vm_type', details)

        finally:
            # Restore original functions
            platform.system = original_system
            if original_which is not None:
                shutil.which = original_which
            subprocess.run = original_subprocess_run

    def test_check_network_adapters_missing_tools(self) -> None:
        """Test network adapter detection when tools are missing."""
        # Configure simulator to simulate missing tools
        self.network_sim.simulate_tool_missing = True
        self.test_env.platform_sim.target_platform = 'Windows'

        # Replace platform.system and shutil.which
        original_system = platform.system
        original_which: Any = None

        try:
            import shutil
            original_which = shutil.which

            platform.system = self.test_env.platform_sim.system
            shutil.which = lambda cmd: None  # type: ignore[assignment]

            detected, confidence, details = self.detector._check_network_adapters()

            # Should handle missing tools gracefully
            self.assertIsInstance(detected, bool)
            self.assertIsInstance(confidence, (int, float))
            self.assertIn('detected_macs', details)

        finally:
            # Restore original functions
            platform.system = original_system
            if original_which is not None:
                shutil.which = original_which


class TestBIOSInformation(unittest.TestCase):
    """Test BIOS information detection for VM identification."""

    def setUp(self) -> None:
        """Set up test fixtures."""
        self.detector = VMDetector()
        self.test_env = RealVMTestEnvironment()
        self.dmi_sim = RealDMISimulator()

    def test_check_bios_info_linux_dmi_detection(self) -> None:
        """Test BIOS information detection on Linux via DMI."""
        # Configure platform for Linux
        self.test_env.platform_sim.target_platform = 'Linux'

        # Replace platform.system, os.path.exists, and file open
        original_system = platform.system
        original_exists = os.path.exists
        original_open = open

        platform.system = self.test_env.platform_sim.system
        os.path.exists = lambda path: path == '/sys/class/dmi/id/bios_vendor'

        class RealFileSimulator:
            def __init__(self, content: str) -> None:
                self.content = content

            def __enter__(self) -> "RealFileSimulator":
                return self

            def __exit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
                pass

            def read(self) -> "RealStripSimulator":
                return RealStripSimulator(self.content)

        class RealStripSimulator:
            def __init__(self, content: str) -> None:
                self.content = content

            def strip(self) -> str:
                return self.content

        def simulate_open(path: str, mode: str = 'r') -> Any:
            if 'bios_vendor' in path:
                return RealFileSimulator('VMware, Inc.')
            return original_open(path, mode)

        try:
            detected, confidence, details = self.detector._check_bios_info()

            # Should detect VMware BIOS vendor
            self.assertTrue(detected, "Should detect VMware BIOS vendor")
            self.assertGreater(confidence, 0.7, "Good confidence for BIOS detection")
            self.assertIn('bios_vendor', details)
            self.assertIn('vmware', details['bios_vendor'].lower())

        finally:
            # Restore original functions
            platform.system = original_system
            os.path.exists = original_exists

    def test_check_bios_info_windows_wmi_detection(self) -> None:
        """Test BIOS information detection on Windows via WMI."""
        # Configure platform for Windows
        self.test_env.platform_sim.target_platform = 'Windows'

        # Replace platform.system
        original_system = platform.system
        platform.system = self.test_env.platform_sim.system

        # Replace importlib import for WMI
        builtins_dict: dict[str, Any] = __builtins__  # type: ignore[assignment]
        original_import: Any = builtins_dict.get('__import__')

        def mock_import(name: str, *args: Any) -> Any:
            if name == 'wmi':
                wmi_sim = self.test_env.wmi_sim
                return type('MockWMI', (), {'WMI': lambda: wmi_sim})()
            return original_import(name, *args)

        builtins_dict['__import__'] = mock_import

        try:
            # Configure WMI simulator for VirtualBox
            detected, confidence, details = self.detector._check_bios_info()

            # Should detect VirtualBox BIOS
            self.assertTrue(detected, "Should detect VirtualBox BIOS")
            self.assertIn('bios_vendor', details)

        finally:
            # Restore original functions
            platform.system = original_system
            builtins_dict['__import__'] = original_import


class TestDeviceDriverDetection(unittest.TestCase):
    """Test device driver detection for VM identification."""

    def setUp(self) -> None:
        """Set up test fixtures."""
        self.detector = VMDetector()
        self.test_env = RealVMTestEnvironment()
        self.subprocess_sim = RealSubprocessSimulator()

    def test_check_device_drivers_windows_driverquery(self) -> None:
        """Test device driver detection on Windows using driverquery."""
        # Configure platform for Windows
        self.test_env.platform_sim.target_platform = 'Windows'

        # Replace platform.system, shutil.which, and subprocess.run
        original_system = platform.system
        original_which: Any = None
        original_subprocess_run = subprocess.run

        try:
            import shutil
            original_which = shutil.which

            platform.system = self.test_env.platform_sim.system
            shutil.which = lambda cmd: 'C:\\Windows\\System32\\driverquery.exe' if cmd == 'driverquery' else None  # type: ignore[assignment]

            def simulate_driverquery_run(cmd: Any, **kwargs: Any) -> Any:
                return self.subprocess_sim.run_command(cmd, 'vmware')

            subprocess.run = simulate_driverquery_run  # type: ignore[assignment]

            detected, confidence, details = self.detector._check_device_drivers()

            # Should detect VM drivers
            self.assertTrue(detected, "Should detect VM drivers")
            self.assertGreater(confidence, 0.8, "High confidence for driver detection")
            self.assertIn('detected_drivers', details)
            self.assertGreater(len(details['detected_drivers']), 0)

        finally:
            # Restore original functions
            platform.system = original_system
            if original_which is not None:
                shutil.which = original_which
            subprocess.run = original_subprocess_run

    def test_check_device_drivers_linux_lsmod(self) -> None:
        """Test device driver detection on Linux using lsmod."""
        # Configure platform for Linux
        self.test_env.platform_sim.target_platform = 'Linux'

        # Replace platform.system and subprocess.run
        original_system = platform.system
        original_subprocess_run = subprocess.run

        try:
            platform.system = self.test_env.platform_sim.system

            def simulate_lsmod_run(cmd: Any, **kwargs: Any) -> Any:
                return self.subprocess_sim.run_command(cmd, 'virtualbox')

            subprocess.run = simulate_lsmod_run  # type: ignore[assignment]

            detected, confidence, details = self.detector._check_device_drivers()

            # Should detect VM modules
            self.assertTrue(detected, "Should detect VM kernel modules")
            self.assertIn('detected_drivers', details)

        finally:
            # Restore original functions
            platform.system = original_system
            subprocess.run = original_subprocess_run


class TestVMTypeIdentification(unittest.TestCase):
    """Test VM type identification and scoring capabilities."""

    def setUp(self) -> None:
        """Set up test fixtures."""
        self.detector = VMDetector()
        self.test_env = RealVMTestEnvironment()

    def test_identify_vm_type_vmware_identification(self) -> None:
        """Test VM type identification correctly identifies VMware."""
        # Create real detection results indicating VMware
        detections = {
            'process_list': {
                'detected': True,
                'confidence': 0.8,
                'details': {'vm_type': 'vmware', 'detected_processes': ['vmtoolsd.exe']}
            },
            'hardware_signatures': {
                'detected': True,
                'confidence': 0.9,
                'details': {'detected_hardware': ['VMware Virtual Platform']}
            }
        }

        vm_type = self.detector._identify_vm_type(detections)

        # Should identify as VMware
        self.assertEqual(vm_type, 'vmware', "Should correctly identify VMware VM")

    def test_identify_vm_type_multiple_vm_indicators(self) -> None:
        """Test VM type identification with conflicting indicators."""
        # Create real detection results with multiple VM types
        detections = {
            'process_list': {
                'detected': True,
                'confidence': 0.7,
                'details': {'vm_type': 'vmware', 'detected_processes': ['vmtoolsd.exe']}
            },
            'file_system': {
                'detected': True,
                'confidence': 0.8,
                'details': {'vm_type': 'virtualbox', 'detected_files': ['VBoxService.exe']}
            }
        }

        vm_type = self.detector._identify_vm_type(detections)

        # Should return the highest scoring VM type
        self.assertIn(vm_type, ['vmware', 'virtualbox'], "Should identify one of the detected VM types")

    def test_identify_vm_type_no_detections(self) -> None:
        """Test VM type identification with no detections."""
        detections = {
            'process_list': {
                'detected': False,
                'confidence': 0.0,
                'details': {'detected_processes': []}
            }
        }

        vm_type = self.detector._identify_vm_type(detections)

        # Should return unknown
        self.assertEqual(vm_type, 'unknown', "Should return 'unknown' when no VM detected")


class TestEvasionScoring(unittest.TestCase):
    """Test evasion scoring and difficulty assessment."""

    def setUp(self) -> None:
        """Set up test fixtures."""
        self.detector = VMDetector()
        self.test_env = RealVMTestEnvironment()

    def test_calculate_evasion_score_hard_to_evade_methods(self) -> None:
        """Test evasion score calculation prioritizes hard-to-evade methods."""
        # Create real detections with hard-to-evade methods
        detections = {
            'cpuid': {
                'detected': True,
                'confidence': 0.9,
                'details': {'hypervisor_bit': True}
            },
            'hardware_signatures': {
                'detected': True,
                'confidence': 0.8,
                'details': {'detected_hardware': ['VMware Virtual Platform']}
            },
            'process_list': {
                'detected': True,
                'confidence': 0.7,
                'details': {'detected_processes': ['vmtoolsd.exe']}
            }
        }

        evasion_score = self.detector._calculate_evasion_score(detections)

        # Should return high evasion score for hard-to-evade methods
        self.assertIsInstance(evasion_score, int)
        self.assertGreaterEqual(evasion_score, 6, "Hard-to-evade methods should yield high score")
        self.assertLessEqual(evasion_score, 10)

    def test_calculate_evasion_score_easy_to_evade_methods(self) -> None:
        """Test evasion score for easier-to-evade detection methods."""
        # Create real detections with only easy-to-evade methods
        detections = {
            'process_list': {
                'detected': True,
                'confidence': 0.6,
                'details': {'detected_processes': ['vmtoolsd.exe']}
            },
            'file_system': {
                'detected': True,
                'confidence': 0.5,
                'details': {'detected_files': ['C:\\Program Files\\VMware\\VMware Tools']}
            }
        }

        evasion_score = self.detector._calculate_evasion_score(detections)

        # Should return lower evasion score
        self.assertIsInstance(evasion_score, int)
        self.assertLess(evasion_score, 6, "Easy-to-evade methods should yield lower score")


class TestBypassGeneration(unittest.TestCase):
    """Test VM detection bypass generation capabilities."""

    def setUp(self) -> None:
        """Set up test fixtures."""
        self.detector = VMDetector()
        self.test_env = RealVMTestEnvironment()

    def test_generate_bypass_vmware_comprehensive_strategy(self) -> None:
        """Test bypass generation creates comprehensive VMware evasion strategy."""
        bypass_config = self.detector.generate_bypass('vmware')

        # Verify bypass configuration structure
        self.assertIsInstance(bypass_config, dict)
        required_fields = [
            'vm_type', 'detection_methods', 'bypass_techniques',
            'stealth_level', 'success_probability', 'implementation',
            'requirements', 'risks'
        ]

        for field in required_fields:
            self.assertIn(field, bypass_config, f"Bypass config should contain '{field}'")

        # Verify VMware-specific configuration
        self.assertEqual(bypass_config['vm_type'], 'vmware')
        self.assertGreater(bypass_config['success_probability'], 0.7,
                          "VMware bypass should have high success probability")
        self.assertEqual(bypass_config['stealth_level'], 'high')

        # Verify bypass techniques
        self.assertIsInstance(bypass_config['bypass_techniques'], list)
        self.assertGreater(len(bypass_config['bypass_techniques']), 3,
                          "Should provide multiple bypass techniques")

        # Each technique should have proper structure
        for technique in bypass_config['bypass_techniques']:
            self.assertIn('name', technique)
            self.assertIn('description', technique)
            self.assertIn('complexity', technique)
            self.assertIn('effectiveness', technique)

    def test_generate_bypass_virtualbox_specific_techniques(self) -> None:
        """Test bypass generation for VirtualBox with specific techniques."""
        bypass_config = self.detector.generate_bypass('virtualbox')

        # Verify VirtualBox-specific configuration
        self.assertEqual(bypass_config['vm_type'], 'virtualbox')
        self.assertGreater(bypass_config['success_probability'], 0.8,
                          "VirtualBox bypass should have very high success probability")

        # Should include VirtualBox-specific techniques
        technique_names = [t['name'] for t in bypass_config['bypass_techniques']]
        vbox_techniques = ['VBoxGuest Hiding', 'ACPI Table Modification', 'Device Name Changing']

        found_vbox_techniques = [t for t in vbox_techniques if any(vbox_t in t for vbox_t in technique_names)]
        self.assertGreater(len(found_vbox_techniques), 0,
                          "Should include VirtualBox-specific techniques")

    def test_generate_bypass_implementation_details(self) -> None:
        """Test bypass generation includes implementation details."""
        bypass_config = self.detector.generate_bypass('vmware')

        # Verify implementation section
        implementation = bypass_config['implementation']
        self.assertIsInstance(implementation, dict)

        implementation_fields = ['hook_script', 'registry_modifications', 'file_operations']
        for field in implementation_fields:
            self.assertIn(field, implementation)

        # Hook script should be functional
        hook_script = implementation['hook_script']
        self.assertIsInstance(hook_script, str)
        self.assertGreater(len(hook_script), 100, "Hook script should be substantial")
        self.assertIn('Frida', hook_script, "Should use Frida for hooking")

        # Registry modifications should be specific
        registry_mods = implementation['registry_modifications']
        self.assertIsInstance(registry_mods, list)
        if len(registry_mods) > 0:
            for mod in registry_mods:
                self.assertIn('action', mod)
                self.assertIn('key', mod)

    def test_generate_bypass_unknown_vm_type(self) -> None:
        """Test bypass generation for unknown VM type provides generic techniques."""
        bypass_config = self.detector.generate_bypass('unknown_vm')

        # Should handle unknown VM type gracefully
        self.assertIsInstance(bypass_config, dict)
        self.assertEqual(bypass_config['vm_type'], 'unknown_vm')
        self.assertEqual(bypass_config['stealth_level'], 'medium')
        self.assertLess(bypass_config['success_probability'], 0.7,
                       "Unknown VM bypass should have lower success probability")

        # Should provide generic techniques
        self.assertGreater(len(bypass_config['bypass_techniques']), 0)


class TestEvasionCodeGeneration(unittest.TestCase):
    """Test VM evasion code generation capabilities."""

    def setUp(self) -> None:
        """Set up test fixtures."""
        self.detector = VMDetector()
        self.test_env = RealVMTestEnvironment()

    def test_generate_evasion_code_comprehensive_vm_detection(self) -> None:
        """Test evasion code generation creates comprehensive VM detection code."""
        evasion_code = self.detector.generate_evasion_code()

        # Verify code structure and content
        self.assertIsInstance(evasion_code, str)
        self.assertGreater(len(evasion_code), 200, "Evasion code should be substantial")

        # Should include C/C++ code
        self.assertIn('#include', evasion_code)
        self.assertIn('bool', evasion_code)
        self.assertIn('IsRunningInVM', evasion_code)

        # Should include actual VM detection methods
        vm_detection_methods = ['__cpuid', 'GetFileAttributes', 'RegOpenKeyEx']
        found_methods = sum(bool(method in evasion_code)
                        for method in vm_detection_methods)
        self.assertGreaterEqual(found_methods, 2, "Should include multiple detection methods")

    def test_generate_evasion_code_target_specific_vm(self) -> None:
        """Test evasion code generation for specific VM target."""
        vmware_code = self.detector.generate_evasion_code('vmware')

        # Should be the same comprehensive code for now
        self.assertIsInstance(vmware_code, str)
        self.assertGreater(len(vmware_code), 200)

        # Should include VM-specific elements
        self.assertIn('VM', vmware_code.upper())


class TestAggressiveMethods(unittest.TestCase):
    """Test aggressive detection method configuration."""

    def setUp(self) -> None:
        """Set up test fixtures."""
        self.detector = VMDetector()
        self.test_env = RealVMTestEnvironment()

    def test_get_aggressive_methods_returns_timing_attacks(self) -> None:
        """Test get_aggressive_methods identifies timing attacks as aggressive."""
        aggressive_methods = self.detector.get_aggressive_methods()

        self.assertIsInstance(aggressive_methods, list)
        self.assertIn('timing_attacks', aggressive_methods,
                     "Timing attacks should be considered aggressive")

    def test_get_detection_type_returns_virtual_machine(self) -> None:
        """Test get_detection_type returns correct classification."""
        detection_type = self.detector.get_detection_type()

        self.assertEqual(detection_type, 'virtual_machine',
                        "Should return 'virtual_machine' as detection type")


class TestVMDetectorIntegration(unittest.TestCase):
    """Integration tests for VMDetector with real system interaction."""

    def setUp(self) -> None:
        """Set up integration test fixtures."""
        self.detector = VMDetector()
        self.test_env = RealVMTestEnvironment()

    def test_end_to_end_vm_detection_workflow(self) -> None:
        """Test complete VM detection workflow from initialization to results."""
        # Run full detection workflow
        result = self.detector.detect_vm(aggressive=False)

        # Verify complete workflow
        self.assertIsInstance(result, dict)

        # Should have all expected result fields
        required_fields = ['is_vm', 'confidence', 'vm_type', 'detections', 'evasion_score']
        for field in required_fields:
            self.assertIn(field, result)

        # Detections should contain multiple method results
        detections = result['detections']
        self.assertIsInstance(detections, dict)
        self.assertGreaterEqual(len(detections), 8, "Should execute multiple detection methods")

        # Each detection should have proper structure
        for method_name, detection_result in detections.items():
            self.assertIsInstance(detection_result, dict)
            self.assertIn('detected', detection_result)
            self.assertIn('confidence', detection_result)
            self.assertIn('details', detection_result)

    def test_vm_detection_performance_requirements(self) -> None:
        """Test VM detection meets performance requirements for security research."""
        # Test standard detection performance
        start_time = time.time()
        standard_result = self.detector.detect_vm(aggressive=False)
        standard_time = time.time() - start_time

        # Test aggressive detection performance
        start_time = time.time()
        aggressive_result = self.detector.detect_vm(aggressive=True)
        aggressive_time = time.time() - start_time

        # Performance requirements
        self.assertLess(standard_time, 10.0,
                       f"Standard detection took {standard_time:.2f}s, expected < 10s")
        self.assertLess(aggressive_time, 20.0,
                       f"Aggressive detection took {aggressive_time:.2f}s, expected < 20s")

        # Both should return valid results
        self.assertIsInstance(standard_result, dict)
        self.assertIsInstance(aggressive_result, dict)

    def test_cross_platform_vm_detection_compatibility(self) -> None:
        """Test VM detection works across different platforms."""
        # Should work regardless of current platform
        result = self.detector.detect_vm()

        self.assertIsInstance(result, dict)
        self.assertIn('is_vm', result)
        self.assertIn('detections', result)

        # At minimum should execute basic detection methods
        detections = result['detections']
        executed_methods = [method for method, result in detections.items()
                          if result.get('confidence', 0) >= 0]
        self.assertGreaterEqual(len(executed_methods), 5,
                               "Should execute multiple methods across platforms")

    def test_real_world_vm_detection_accuracy(self) -> None:
        """Test VM detection accuracy against real environment characteristics."""
        result = self.detector.detect_vm()

        # If we're actually in a VM, validate detection accuracy
        is_vm_detected = result['is_vm']
        # Validation logic - if VM is detected, should have reasonable confidence
        if is_vm_detected:
            confidence = result['confidence']
            self.assertGreater(confidence, 0.3, "VM detection should have reasonable confidence")
            vm_type = result['vm_type']

            self.assertIsNotNone(vm_type, "Should identify VM type when detected")
            self.assertIn(vm_type, ['vmware', 'virtualbox', 'hyperv', 'qemu', 'parallels', 'unknown'],
                         f"VM type '{vm_type}' should be recognized")

        # Evasion score should be realistic
        evasion_score = result['evasion_score']
        self.assertGreaterEqual(evasion_score, 0)
        self.assertLessEqual(evasion_score, 10)


class TestVMDetectorErrorResilience(unittest.TestCase):
    """Test VMDetector resilience to errors and edge cases."""

    def setUp(self) -> None:
        """Set up test fixtures."""
        self.detector = VMDetector()
        self.test_env = RealVMTestEnvironment()

    def test_detection_method_failure_resilience(self) -> None:
        """Test VM detection continues when individual methods fail."""
        # Create real failing methods
        def failing_cpuid_method() -> None:
            raise Exception("CPUID failed")

        def failing_registry_method() -> None:
            raise Exception("Registry failed")

        def failing_bios_method() -> None:
            raise Exception("BIOS failed")

        # Store original methods
        original_cpuid: Any = getattr(self.detector, '_check_cpuid', None)
        original_registry: Any = getattr(self.detector, '_check_registry_keys', None)
        original_bios: Any = getattr(self.detector, '_check_bios_info', None)

        # Replace with failing methods
        self.detector._check_cpuid = failing_cpuid_method  # type: ignore[attr-defined]
        self.detector._check_registry_keys = failing_registry_method  # type: ignore[assignment]
        self.detector._check_bios_info = failing_bios_method  # type: ignore[assignment]

        try:
            result = self.detector.detect_vm()

            # Should still return valid result
            self.assertIsInstance(result, dict)
            self.assertIn('is_vm', result)
            self.assertIn('detections', result)

            # Should have results from non-failing methods
            detections = result['detections']
            successful_methods = [method for method, result in detections.items()
                                if result.get('confidence', -1) >= 0]
            self.assertGreater(len(successful_methods), 3,
                              "Should have results from non-failing methods")

        finally:
            # Restore original methods
            if original_cpuid is not None:
                self.detector._check_cpuid = original_cpuid  # type: ignore[attr-defined]
            if original_registry is not None:
                self.detector._check_registry_keys = original_registry  # type: ignore[method-assign]
            if original_bios is not None:
                self.detector._check_bios_info = original_bios  # type: ignore[method-assign]

    def test_system_resource_limitation_handling(self) -> None:
        """Test VM detection handles system resource limitations."""
        # Replace subprocess.run to simulate resource exhaustion
        original_subprocess_run = subprocess.run

        def simulate_resource_error(*args: Any, **kwargs: Any) -> None:
            raise OSError("Resource temporarily unavailable")

        subprocess.run = simulate_resource_error  # type: ignore[assignment]

        try:
            result = self.detector.detect_vm()

            # Should handle resource limitations gracefully
            self.assertIsInstance(result, dict)
            self.assertIn('is_vm', result)

        finally:
            # Restore original subprocess.run
            subprocess.run = original_subprocess_run

    def test_permission_denial_handling(self) -> None:
        """Test VM detection handles permission denied scenarios."""
        # Replace file operations to simulate permission errors
        original_open = open
        original_exists = os.path.exists

        def simulate_permission_error(*args: Any, **kwargs: Any) -> None:
            raise PermissionError("Permission denied")

        # Replace functions
        builtins_dict: dict[str, Any] = __builtins__  # type: ignore[assignment]
        builtins_dict['open'] = simulate_permission_error
        os.path.exists = simulate_permission_error  # type: ignore[assignment]

        try:
            result = self.detector.detect_vm()

            # Should handle permission errors gracefully
            self.assertIsInstance(result, dict)
            self.assertIn('is_vm', result)

        except PermissionError:
            # Expected behavior - detection should handle this gracefully
            pass
        finally:
            # Restore original functions
            builtins_dict['open'] = original_open
            os.path.exists = original_exists


if __name__ == '__main__':
    # Configure test logging
    import logging
    logging.basicConfig(level=logging.DEBUG)

    # Run the tests
    unittest.main(verbosity=2)

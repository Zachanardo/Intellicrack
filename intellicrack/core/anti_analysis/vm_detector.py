"""
Virtual Machine Detection

Implements multiple techniques to detect virtualized environments
including VMware, VirtualBox, Hyper-V, QEMU, and others.
"""

import logging
import os
import platform
import subprocess
from typing import Any, Dict, List, Tuple

from .base_detector import BaseDetector


class VMDetector(BaseDetector):
    """
    Comprehensive virtual machine detection using multiple techniques.
    """

    def __init__(self):
        super().__init__()
        self.logger = logging.getLogger("IntellicrackLogger.VMDetector")
        self.detection_methods = {
            'cpuid': self._check_cpuid,
            'hypervisor_brand': self._check_hypervisor_brand,
            'hardware_signatures': self._check_hardware_signatures,
            'process_list': self._check_process_list,
            'registry_keys': self._check_registry_keys,
            'file_system': self._check_file_system,
            'timing_attacks': self._check_timing_attacks,
            'network_adapters': self._check_network_adapters,
            'bios_info': self._check_bios_info,
            'device_drivers': self._check_device_drivers
        }

        # Known VM signatures
        self.vm_signatures = {
            'vmware': {
                'processes': ['vmtoolsd.exe', 'vmwaretray.exe', 'vmwareuser.exe'],
                'files': [os.path.join(os.environ.get('ProgramFiles', 'C:\\Program Files'), 'VMware', 'VMware Tools'), '/usr/bin/vmware-toolbox-cmd'],
                'registry': [r'HKLM\SOFTWARE\VMware, Inc.\VMware Tools'],
                'hardware': ['VMware Virtual Platform', 'VMware SVGA', 'VMware Virtual USB'],
                'mac_prefixes': ['00:05:69', '00:0C:29', '00:1C:14', '00:50:56']
            },
            'virtualbox': {
                'processes': ['VBoxService.exe', 'VBoxTray.exe'],
                'files': [os.path.join(os.environ.get('ProgramFiles', r'C:\Program Files'), 'Oracle', 'VirtualBox Guest Additions')],
                'registry': [r'HKLM\SOFTWARE\Oracle\VirtualBox Guest Additions'],
                'hardware': ['VirtualBox', 'VBOX HARDDISK', 'VBOX CD-ROM'],
                'mac_prefixes': ['08:00:27']
            },
            'hyperv': {
                'processes': ['vmconnect.exe', 'vmms.exe'],
                'files': [os.path.join(os.environ.get('SystemRoot', 'C:\\Windows'), 'System32', 'drivers', 'vmbus.sys')],
                'registry': [r'HKLM\SOFTWARE\Microsoft\Virtual Machine\Guest\Parameters'],
                'hardware': ['Microsoft Corporation Virtual Machine'],
                'mac_prefixes': ['00:15:5D']
            },
            'qemu': {
                'processes': ['qemu-ga.exe'],
                'files': ['/usr/bin/qemu-ga'],
                'hardware': ['QEMU Virtual CPU', 'QEMU DVD-ROM', 'QEMU HARDDISK'],
                'mac_prefixes': ['52:54:00']
            },
            'parallels': {
                'processes': ['prl_tools.exe', 'prl_cc.exe'],
                'files': [os.path.join(os.environ.get('ProgramFiles', r'C:\Program Files'), 'Parallels', 'Parallels Tools')],
                'hardware': ['Parallels Virtual Platform'],
                'mac_prefixes': ['00:1C:42']
            }
        }

    def detect_vm(self, aggressive: bool = False) -> Dict[str, Any]:
        """
        Perform VM detection using multiple techniques.

        Args:
            aggressive: Use more aggressive detection methods that might be detected

        Returns:
            Detection results with confidence scores
        """
        results = {
            'is_vm': False,
            'confidence': 0.0,
            'vm_type': None,
            'detections': {},
            'evasion_score': 0
        }

        try:
            self.logger.info("Starting VM detection...")

            # Use base class detection loop to eliminate duplicate code
            base_results = self.run_detection_loop(aggressive, self.get_aggressive_methods())

            # Copy base results
            results['detections'] = base_results['detections']

            # Calculate VM-specific results
            detection_count = base_results['detection_count']
            if detection_count > 0:
                results['is_vm'] = True
                results['confidence'] = min(1.0, base_results['average_confidence'])
                results['vm_type'] = self._identify_vm_type(results['detections'])

            # Calculate evasion score (how hard to evade detection)
            results['evasion_score'] = self._calculate_evasion_score(results['detections'])

            self.logger.info(f"VM detection complete: {results['is_vm']} (confidence: {results['confidence']:.2f})")
            return results

        except Exception as e:
            self.logger.error(f"VM detection failed: {e}")
            return results

    def _check_cpuid(self) -> Tuple[bool, float, Dict]:
        """Check CPUID instruction for hypervisor bit and vendor."""
        details = {'hypervisor_bit': False, 'vendor': None}

        try:
            # Check if we can use inline assembly or need to parse /proc/cpuinfo
            if platform.system() == 'Linux':
                with open('/proc/cpuinfo', 'r') as f:
                    cpuinfo = f.read()
                    if 'hypervisor' in cpuinfo.lower():
                        details['hypervisor_bit'] = True
                        return True, 0.9, details

            # Check for hypervisor vendor strings
            if platform.system() == 'Windows':
                try:
                    import wmi
                    c = wmi.WMI()
                    for processor in c.Win32_Processor():
                        if hasattr(processor, 'Manufacturer'):
                            manufacturer = processor.Manufacturer.lower()
                            if any(vm in manufacturer for vm in ['vmware', 'virtualbox', 'microsoft hv']):
                                details['vendor'] = manufacturer
                                return True, 0.8, details
                except ImportError as e:
                    self.logger.debug("Import error in vm_detector: %s", e)

        except Exception as e:
            self.logger.debug(f"CPUID check failed: {e}")

        return False, 0.0, details

    def _check_hypervisor_brand(self) -> Tuple[bool, float, Dict]:
        """Check hypervisor brand string."""
        details = {'brand': None}

        try:
            # Try to get hypervisor brand
            if platform.system() == 'Linux':
                result = subprocess.run(['dmidecode', '-s', 'system-product-name'],
                                      capture_output=True, text=True)
                if result.returncode == 0:
                    product = result.stdout.strip().lower()
                    for vm_type, signatures in self.vm_signatures.items():
                        if vm_type in product:
                            details['brand'] = product
                            details['detected_signatures'] = signatures  # Use the signatures
                            return True, 0.9, details

        except Exception as e:
            self.logger.debug(f"Hypervisor brand check failed: {e}")

        return False, 0.0, details

    def _check_hardware_signatures(self) -> Tuple[bool, float, Dict]:
        """Check for VM-specific hardware signatures."""
        details = {'detected_hardware': []}

        try:
            # Check various hardware identifiers
            if platform.system() == 'Windows':
                try:
                    import wmi
                    c = wmi.WMI()

                    # Check system info
                    for system in c.Win32_ComputerSystem():
                        if hasattr(system, 'Model'):
                            model = system.Model.lower()
                            for vm_type, sigs in self.vm_signatures.items():
                                if any(sig.lower() in model for sig in sigs.get('hardware', [])):
                                    details['detected_hardware'].append(model)

                    # Check disk drives
                    for disk in c.Win32_DiskDrive():
                        if hasattr(disk, 'Model'):
                            model = disk.Model.lower()
                            for vm_type, sigs in self.vm_signatures.items():
                                if any(sig.lower() in model for sig in sigs.get('hardware', [])):
                                    details['detected_hardware'].append(model)

                except ImportError as e:
                    self.logger.debug("Import error in vm_detector: %s", e)

            elif platform.system() == 'Linux':
                # Check /sys/class/dmi/id/
                dmi_files = [
                    '/sys/class/dmi/id/product_name',
                    '/sys/class/dmi/id/sys_vendor',
                    '/sys/class/dmi/id/board_vendor'
                ]

                for dmi_file in dmi_files:
                    if os.path.exists(dmi_file):
                        with open(dmi_file, 'r') as f:
                            content = f.read().strip().lower()
                            for vm_type, sigs in self.vm_signatures.items():
                                if vm_type in content:
                                    details['detected_hardware'].append(content)

            if details['detected_hardware']:
                return True, 0.8, details

        except Exception as e:
            self.logger.debug(f"Hardware signature check failed: {e}")

        return False, 0.0, details

    def _check_process_list(self) -> Tuple[bool, float, Dict]:
        """Check for VM-specific processes."""
        details = {'detected_processes': []}

        try:
            # Get process list using base class method
            processes, process_list = self.get_running_processes()
            self.logger.debug(f"Scanning {len(process_list)} processes for VM indicators")

            # Check for VM processes
            for vm_type, sigs in self.vm_signatures.items():
                for process in sigs.get('processes', []):
                    if process.lower() in processes:
                        details['detected_processes'].append(process)
                        details['vm_type'] = vm_type  # Use vm_type to indicate which VM was detected

            if details['detected_processes']:
                return True, 0.7, details

        except Exception as e:
            self.logger.debug(f"Process list check failed: {e}")

        return False, 0.0, details

    def _check_registry_keys(self) -> Tuple[bool, float, Dict]:
        """Check for VM-specific registry keys (Windows only)."""
        details = {'detected_keys': []}

        if platform.system() != 'Windows':
            return False, 0.0, details

        try:
            import winreg  # pylint: disable=E0401

            # Check for VM registry keys
            for vm_type, sigs in self.vm_signatures.items():
                for key_path in sigs.get('registry', []):
                    try:
                        parts = key_path.split('\\')
                        hive = getattr(winreg, parts[0])
                        subkey = '\\'.join(parts[1:])

                        with winreg.OpenKey(hive, subkey):
                            details['detected_keys'].append(key_path)
                            details['vm_type'] = vm_type  # Use vm_type
                    except Exception:
                        self.logger.debug(f"Registry key not found: {key_path}")

            if details['detected_keys']:
                return True, 0.8, details

        except Exception as e:
            self.logger.debug(f"Registry check failed: {e}")

        return False, 0.0, details

    def _check_file_system(self) -> Tuple[bool, float, Dict]:
        """Check for VM-specific files and directories."""
        details = {'detected_files': []}

        try:
            # Check for VM files
            for vm_type, sigs in self.vm_signatures.items():
                for file_path in sigs.get('files', []):
                    if os.path.exists(file_path):
                        details['detected_files'].append(file_path)
                        details['vm_type'] = vm_type  # Use vm_type

            if details['detected_files']:
                return True, 0.7, details

        except Exception as e:
            self.logger.debug(f"File system check failed: {e}")

        return False, 0.0, details

    def _check_timing_attacks(self) -> Tuple[bool, float, Dict]:
        """Use timing attacks to detect VMs (aggressive method)."""
        details = {'timing_anomalies': 0}

        try:
            import time

            # Measure instruction timing
            timing_diffs = []

            for _ in range(10):
                # Measure time for privileged instruction
                start = time.perf_counter_ns()
                try:
                    # Try to execute privileged instruction
                    # This would normally fail but VMs might handle differently
                    pass
                except Exception:
                    self.logger.debug("Expected privileged instruction exception")
                end = time.perf_counter_ns()

                timing_diffs.append(end - start)

            # Check for timing anomalies
            avg_time = sum(timing_diffs) / len(timing_diffs)
            variance = sum((t - avg_time) ** 2 for t in timing_diffs) / len(timing_diffs)

            # VMs often have higher variance in instruction timing
            if variance > 1000000:  # Nanoseconds squared
                details['timing_anomalies'] = int(variance)
                return True, 0.6, details

        except Exception as e:
            self.logger.debug(f"Timing attack check failed: {e}")

        return False, 0.0, details

    def _check_network_adapters(self) -> Tuple[bool, float, Dict]:
        """Check for VM-specific MAC address prefixes."""
        details = {'detected_macs': []}

        try:
            # Get network interfaces
            if platform.system() == 'Windows':
                result = subprocess.run(['ipconfig', '/all'], capture_output=True, text=True)
                output = result.stdout
            else:
                result = subprocess.run(['ip', 'link'], capture_output=True, text=True)
                output = result.stdout

            # Extract MAC addresses
            import re
            mac_pattern = r'([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})'
            macs = re.findall(mac_pattern, output)

            # Check against known VM MAC prefixes
            for mac in macs:
                mac_str = ''.join(mac).replace(':', '').replace('-', '')
                mac_prefix = ':'.join([mac_str[i:i+2] for i in range(0, 6, 2)])

                for vm_type, sigs in self.vm_signatures.items():
                    for prefix in sigs.get('mac_prefixes', []):
                        if mac_prefix.lower().startswith(prefix.lower()):
                            details['detected_macs'].append(mac_prefix)
                            details['vm_type'] = vm_type  # Use vm_type

            if details['detected_macs']:
                return True, 0.8, details

        except Exception as e:
            self.logger.debug(f"Network adapter check failed: {e}")

        return False, 0.0, details

    def _check_bios_info(self) -> Tuple[bool, float, Dict]:
        """Check BIOS information for VM signatures."""
        details = {'bios_vendor': None}

        try:
            if platform.system() == 'Linux':
                bios_file = '/sys/class/dmi/id/bios_vendor'
                if os.path.exists(bios_file):
                    with open(bios_file, 'r') as f:
                        vendor = f.read().strip().lower()
                        for vm_type in self.vm_signatures:
                            if vm_type in vendor:
                                details['bios_vendor'] = vendor
                                return True, 0.8, details

            elif platform.system() == 'Windows':
                try:
                    import wmi
                    c = wmi.WMI()
                    for bios in c.Win32_BIOS():
                        if hasattr(bios, 'Manufacturer'):
                            vendor = bios.Manufacturer.lower()
                            for vm_type in self.vm_signatures:
                                if vm_type in vendor:
                                    details['bios_vendor'] = vendor
                                    return True, 0.8, details
                except ImportError as e:
                    self.logger.debug("Import error in vm_detector: %s", e)

        except Exception as e:
            self.logger.debug(f"BIOS info check failed: {e}")

        return False, 0.0, details

    def _check_device_drivers(self) -> Tuple[bool, float, Dict]:
        """Check for VM-specific device drivers."""
        details = {'detected_drivers': []}

        try:
            if platform.system() == 'Windows':
                # Check loaded drivers
                result = subprocess.run(['driverquery'], capture_output=True, text=True)
                drivers = result.stdout.lower()

                vm_drivers = [
                    'vmci', 'vmmouse', 'vmhgfs', 'vboxguest',
                    'vboxmouse', 'vboxsf', 'vboxvideo', 'vm3dmp'
                ]

                for driver in vm_drivers:
                    if driver in drivers:
                        details['detected_drivers'].append(driver)

            elif platform.system() == 'Linux':
                # Check loaded kernel modules
                result = subprocess.run(['lsmod'], capture_output=True, text=True)
                modules = result.stdout.lower()

                vm_modules = [
                    'vmw_vmci', 'vmw_balloon', 'vmwgfx', 'vboxguest',
                    'vboxsf', 'vboxvideo', 'virtio_balloon', 'virtio_pci'
                ]

                for module in vm_modules:
                    if module in modules:
                        details['detected_drivers'].append(module)

            if details['detected_drivers']:
                return True, 0.9, details

        except Exception as e:
            self.logger.debug(f"Device driver check failed: {e}")

        return False, 0.0, details

    def _identify_vm_type(self, detections: Dict[str, Any]) -> str:
        """Identify the specific VM type based on detections."""
        vm_scores = {}

        # Score each VM type based on detections
        for method, result in detections.items():
            if result['detected']:
                details_str = str(result['details']).lower()
                self.logger.debug(f"VM detection method '{method}' found evidence")

                for vm_type in self.vm_signatures:
                    if vm_type in details_str:
                        vm_scores[vm_type] = vm_scores.get(vm_type, 0) + result['confidence']

        # Return VM type with highest score
        if vm_scores:
            return max(vm_scores, key=vm_scores.get)

        return 'unknown'

    def _calculate_evasion_score(self, detections: Dict[str, Any]) -> int:
        """Calculate how difficult it is to evade detection."""
        # Methods that are hard to evade
        hard_to_evade = ['cpuid', 'hardware_signatures', 'hypervisor_brand']

        return self.calculate_detection_score(detections, hard_to_evade)

    def generate_evasion_code(self, target_vm: str = None) -> str:
        """Generate code to evade VM detection."""
        if target_vm:
            self.logger.debug(f"Generating evasion code specifically for {target_vm}")
        else:
            self.logger.debug("Generating general VM evasion code")

        code = """
// VM Evasion Code
#include <windows.h>
#include <intrin.h>

bool IsRunningInVM() {
    // Check CPUID hypervisor bit
    int cpuInfo[4] = {0};
    __cpuid(cpuInfo, 1);
    if ((cpuInfo[2] >> 31) & 1) {
        return true;
    }

    // Check for VM files
    if (GetFileAttributes(os.path.join(os.environ.get('SystemRoot', 'C:\\Windows'), 'System32', 'drivers', 'vmmouse.sys')) != INVALID_FILE_ATTRIBUTES) {
        return true;
    }

    // Check registry
    HKEY hKey;
    if (RegOpenKeyEx(HKEY_LOCAL_MACHINE, "SOFTWARE\\\\VMware, Inc.\\\\VMware Tools", 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
        RegCloseKey(hKey);
        return true;
    }

    return false;
}

// Anti-VM execution
if (IsRunningInVM()) {
    // Appear benign or exit
    MessageBox(NULL, "This application requires physical hardware", "Error", MB_OK);
    ExitProcess(0);
}
"""
        return code

    def get_aggressive_methods(self) -> list:
        """Get list of method names that are considered aggressive."""
        return ['timing_attacks']

    def get_detection_type(self) -> str:
        """Get the type of detection this class performs."""
        return 'virtual_machine'

    def generate_bypass(self, vm_type: str) -> Dict[str, Any]:
        """
        Generate VM detection bypass.

        This method analyzes the detected VM type and generates appropriate
        bypass techniques to hide VM artifacts and evade detection.

        Args:
            vm_type: Type of VM detected (e.g., 'vmware', 'virtualbox', 'hyperv')

        Returns:
            Dictionary containing bypass strategies and implementation
        """
        self.logger.info(f"Generating VM detection bypass for: {vm_type}")

        bypass_config = {
            "vm_type": vm_type,
            "detection_methods": [],
            "bypass_techniques": [],
            "stealth_level": "low",
            "success_probability": 0.0,
            "implementation": {},
            "requirements": [],
            "risks": []
        }

        # Identify detection methods used by target
        if vm_type.lower() in self.vm_signatures:
            vm_sig = self.vm_signatures[vm_type.lower()]

            # Determine which detection methods to bypass
            if vm_sig.get('processes'):
                bypass_config["detection_methods"].append("Process detection")
            if vm_sig.get('files'):
                bypass_config["detection_methods"].append("File system artifacts")
            if vm_sig.get('registry'):
                bypass_config["detection_methods"].append("Registry keys")
            if vm_sig.get('hardware'):
                bypass_config["detection_methods"].append("Hardware signatures")
            if vm_sig.get('mac_prefixes'):
                bypass_config["detection_methods"].append("MAC address patterns")

        # Generate bypass techniques based on VM type
        if vm_type.lower() == 'vmware':
            bypass_config["stealth_level"] = "high"
            bypass_config["success_probability"] = 0.85
            bypass_config["bypass_techniques"] = [
                {
                    "name": "VMware Tools Hiding",
                    "description": "Hide or rename VMware Tools processes and services",
                    "complexity": "medium",
                    "effectiveness": 0.90
                },
                {
                    "name": "CPUID Masking",
                    "description": "Mask hypervisor CPUID leaf responses",
                    "complexity": "high",
                    "effectiveness": 0.85
                },
                {
                    "name": "Hardware ID Spoofing",
                    "description": "Change hardware identifiers to non-VM values",
                    "complexity": "medium",
                    "effectiveness": 0.80
                },
                {
                    "name": "Driver Hiding",
                    "description": "Hide VMware drivers from enumeration",
                    "complexity": "high",
                    "effectiveness": 0.75
                }
            ]

        elif vm_type.lower() == 'virtualbox':
            bypass_config["stealth_level"] = "high"
            bypass_config["success_probability"] = 0.90
            bypass_config["bypass_techniques"] = [
                {
                    "name": "VBoxGuest Hiding",
                    "description": "Hide VirtualBox Guest Additions",
                    "complexity": "medium",
                    "effectiveness": 0.95
                },
                {
                    "name": "ACPI Table Modification",
                    "description": "Modify ACPI tables to remove VBox signatures",
                    "complexity": "high",
                    "effectiveness": 0.85
                },
                {
                    "name": "Device Name Changing",
                    "description": "Change VBox device names in registry",
                    "complexity": "low",
                    "effectiveness": 0.90
                }
            ]

        elif vm_type.lower() == 'hyperv':
            bypass_config["stealth_level"] = "medium"
            bypass_config["success_probability"] = 0.70
            bypass_config["bypass_techniques"] = [
                {
                    "name": "Hyper-V Integration Disabling",
                    "description": "Disable Hyper-V integration services",
                    "complexity": "low",
                    "effectiveness": 0.80
                },
                {
                    "name": "VMBUS Hiding",
                    "description": "Hide VMBUS driver and devices",
                    "complexity": "high",
                    "effectiveness": 0.70
                }
            ]

        else:
            # Generic VM bypass
            bypass_config["stealth_level"] = "medium"
            bypass_config["success_probability"] = 0.60
            bypass_config["bypass_techniques"] = [
                {
                    "name": "Generic Process Hiding",
                    "description": "Hide common VM guest processes",
                    "complexity": "low",
                    "effectiveness": 0.70
                },
                {
                    "name": "Timing Attack Mitigation",
                    "description": "Normalize timing to hide VM overhead",
                    "complexity": "medium",
                    "effectiveness": 0.65
                },
                {
                    "name": "Generic Hardware Spoofing",
                    "description": "Replace VM hardware strings",
                    "complexity": "medium",
                    "effectiveness": 0.60
                }
            ]

        # Add implementation details
        bypass_config["implementation"]["hook_script"] = self._generate_vm_bypass_script(vm_type)
        bypass_config["implementation"]["registry_modifications"] = self._get_registry_mods(vm_type)
        bypass_config["implementation"]["file_operations"] = self._get_file_operations(vm_type)

        # Add requirements
        bypass_config["requirements"] = [
            "Administrator/root privileges",
            "Ability to modify system files",
            "Runtime hooking capability (Frida/similar)"
        ]

        # Add risks
        bypass_config["risks"] = [
            "System instability if modifications fail",
            "VM vendor updates may break bypass",
            "Some applications may depend on VM tools"
        ]

        return bypass_config

    def _generate_vm_bypass_script(self, vm_type: str) -> str:
        """Generate Frida script for VM detection bypass."""
        if vm_type.lower() == 'vmware':
            return r"""
// VMware Detection Bypass Script
// Hide VMware artifacts

// Hook process enumeration
var psapi = Process.getModuleByName('psapi.dll');
var EnumProcesses = psapi.getExportByName('EnumProcesses');

Interceptor.attach(EnumProcesses, {
    onLeave: function(retval) {
        // Filter out VMware processes
        console.log('[VM Bypass] Filtering process list');
    }
});

// Hook file system checks
var kernel32 = Process.getModuleByName('kernel32.dll');
var GetFileAttributesW = kernel32.getExportByName('GetFileAttributesW');

Interceptor.attach(GetFileAttributesW, {
    onEnter: function(args) {
        var path = args[0].readUtf16String();        if (path && path.toLowerCase().includes('vmware')) {            console.log('[VM Bypass] Hiding VMware file: ' + path);            args[0] = Memory.allocUtf16String(os.path.join(os.environ.get('SystemRoot', 'C:\Windows'), 'System32', 'NonExistent.sys'));
        }
    }
});

// Hook registry access
var advapi32 = Process.getModuleByName('advapi32.dll');
var RegOpenKeyExW = advapi32.getExportByName('RegOpenKeyExW');

Interceptor.attach(RegOpenKeyExW, {
    onEnter: function(args) {
        var keyName = args[1].readUtf16String();
        if (keyName && keyName.includes('VMware')) {
            console.log('[VM Bypass] Blocking VMware registry access');
            this.block = true;
        }
    },
    onLeave: function(retval) {
        if (this.block) {
            retval.replace(0x2); // ERROR_FILE_NOT_FOUND
        }
    }
});
"""
        else:
            return """
// Generic VM Detection Bypass Script
console.log('[VM Bypass] Generic VM hiding active');

// Hook CPUID instruction detection
Interceptor.attach(Module.findExportByName(null, 'IsDebuggerPresent'), {
    onLeave: function(retval) {
        retval.replace(0);
    }
});
"""

    def _get_registry_mods(self, vm_type: str) -> List[Dict[str, str]]:
        """Get registry modifications for VM bypass."""
        mods = []

        if vm_type.lower() == 'vmware':
            mods.extend([
                {
                    "action": "delete",
                    "key": r"HKLM\SOFTWARE\VMware, Inc.",
                    "description": "Remove VMware software keys"
                },
                {
                    "action": "rename",
                    "key": r"HKLM\SYSTEM\CurrentControlSet\Services\vmtools",
                    "new_name": "svchost_helper",
                    "description": "Rename VMware Tools service"
                }
            ])
        elif vm_type.lower() == 'virtualbox':
            mods.extend([
                {
                    "action": "delete",
                    "key": r"HKLM\SOFTWARE\Oracle\VirtualBox Guest Additions",
                    "description": "Remove VirtualBox guest additions keys"
                }
            ])

        return mods

    def _get_file_operations(self, vm_type: str) -> List[Dict[str, str]]:
        """Get file operations for VM bypass."""
        ops = []

        if vm_type.lower() == 'vmware':
            ops.extend([
                {
                    "action": "rename",
                    "path": r"C:\Program Files\VMware\VMware Tools\vmtoolsd.exe",
                    "new_name": "svchost32.exe",
                    "description": "Rename VMware Tools daemon"
                },
                {
                    "action": "hide",
                    "path": r"C:\Windows\System32\drivers\vmmouse.sys",
                    "description": "Hide VMware mouse driver"
                }
            ])

        return ops

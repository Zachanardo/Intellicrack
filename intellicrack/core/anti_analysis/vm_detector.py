"""Virtual machine detection utilities for Intellicrack anti-analysis.

This file is part of Intellicrack.
Copyright (C) 2025 Zachary Flint.

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see https://www.gnu.org/licenses/.
"""

import ctypes
import hashlib
import logging
import os
import platform
import shutil
import struct
import subprocess
import sys
import threading
import time
from dataclasses import dataclass, field
from typing import Any

from .base_detector import BaseDetector

"""
Virtual Machine Detection

Implements advanced techniques to detect virtualized environments with:
- CPUID instruction analysis (hypervisor bit, vendor strings, feature flags)
- Timing-based VM detection (RDTSC analysis, instruction timing variations)
- Hardware fingerprinting (MAC addresses, disk serial numbers, BIOS info)
- VM artifact detection (registry keys, files, processes, services)
- Paravirtualization detection (VMCALL, VMMCALL, CPUID leaves)
- Memory artifact scanning (hypervisor signatures in memory)
- Device detection (VM-specific devices, controllers)
- Performance counter analysis
- Multi-layer detection with confidence scoring
"""


@dataclass
class CPUIDResult:
    """CPUID instruction result storage."""

    leaf: int
    subleaf: int
    eax: int
    ebx: int
    ecx: int
    edx: int
    vendor_string: str = ""
    brand_string: str = ""
    timestamp: float = field(default_factory=time.time)

@dataclass
class TimingMeasurement:
    """Timing measurement data."""

    operation: str
    samples: list[int] = field(default_factory=list)
    mean: float = 0.0
    variance: float = 0.0
    std_dev: float = 0.0
    min_val: int = 0
    max_val: int = 0
    anomaly_detected: bool = False
    confidence: float = 0.0

@dataclass
class HardwareFingerprint:
    """Hardware fingerprint data."""

    cpu_vendor: str = ""
    cpu_model: str = ""
    cpu_cores: int = 0
    total_ram_mb: int = 0
    disk_count: int = 0
    disk_serials: list[str] = field(default_factory=list)
    mac_addresses: list[str] = field(default_factory=list)
    bios_vendor: str = ""
    bios_version: str = ""
    system_manufacturer: str = ""
    system_model: str = ""
    motherboard_manufacturer: str = ""
    fingerprint_hash: str = ""


class VMDetector(BaseDetector):
    """Comprehensive virtual machine detection using multiple techniques."""

    def __init__(self):
        """Initialize the virtual machine detector with detection methods and signatures."""
        super().__init__()
        self.logger = logging.getLogger("IntellicrackLogger.VMDetector")
        self.detection_methods = {
            "cpuid_hypervisor_bit": self._check_cpuid_hypervisor_bit,
            "cpuid_vendor_strings": self._check_cpuid_vendor_strings,
            "cpuid_feature_flags": self._check_cpuid_feature_flags,
            "cpuid_extended_leaves": self._check_cpuid_extended_leaves,
            "cpuid_timing": self._check_cpuid_timing,
            "cpuid_brand_string": self._check_cpuid_brand_string,
            "rdtsc_timing": self._check_rdtsc_timing,
            "rdtsc_vmexit_detection": self._check_rdtsc_vmexit_detection,
            "sleep_timing": self._check_sleep_timing,
            "instruction_timing": self._check_instruction_timing,
            "paravirt_instructions": self._check_paravirt_instructions,
            "cpu_model_detection": self._check_cpu_model_detection,
            "hardware_fingerprint": self._check_hardware_fingerprint,
            "disk_serial_numbers": self._check_disk_serial_numbers,
            "mac_address_patterns": self._check_mac_address_patterns,
            "hypervisor_brand": self._check_hypervisor_brand,
            "hardware_signatures": self._check_hardware_signatures,
            "process_list": self._check_process_list,
            "registry_keys": self._check_registry_keys,
            "file_system": self._check_file_system,
            "network_adapters": self._check_network_adapters,
            "bios_info": self._check_bios_info,
            "device_drivers": self._check_device_drivers,
            "acpi_tables": self._check_acpi_tables,
            "pci_devices": self._check_pci_devices,
            "memory_artifacts": self._check_memory_artifacts,
            "performance_counters": self._check_performance_counters,
            "tsc_frequency_analysis": self._check_tsc_frequency_analysis,
            "cache_timing": self._check_cache_timing,
        }

        self.vm_signatures = {
            "vmware": {
                "processes": ["vmtoolsd.exe", "vmwaretray.exe", "vmwareuser.exe"],
                "files": [
                    os.path.join(
                        os.environ.get("ProgramFiles", "C:\\\\Program Files"),
                        "VMware",
                        "VMware Tools",
                    ),
                    "/usr/bin/vmware-toolbox-cmd",
                ],
                "registry": [r"HKLM\\SOFTWARE\\VMware, Inc.\\VMware Tools"],
                "hardware": ["VMware Virtual Platform", "VMware SVGA", "VMware Virtual USB"],
                "mac_prefixes": ["00:05:69", "00:0C:29", "00:1C:14", "00:50:56"],
                "cpuid_vendor": "VMwareVMware",
                "hypervisor_leaf": 0x40000000,
            },
            "virtualbox": {
                "processes": ["VBoxService.exe", "VBoxTray.exe"],
                "files": [
                    os.path.join(
                        os.environ.get("ProgramFiles", r"C:\\Program Files"),
                        "Oracle",
                        "VirtualBox Guest Additions",
                    )
                ],
                "registry": [r"HKLM\\SOFTWARE\\Oracle\\VirtualBox Guest Additions"],
                "hardware": ["VirtualBox", "VBOX HARDDISK", "VBOX CD-ROM"],
                "mac_prefixes": ["08:00:27"],
                "cpuid_vendor": "VBoxVBoxVBox",
                "hypervisor_leaf": 0x40000000,
            },
            "hyperv": {
                "processes": ["vmconnect.exe", "vmms.exe"],
                "files": [
                    os.path.join(
                        os.environ.get("SystemRoot", "C:\\\\Windows"),
                        "System32",
                        "drivers",
                        "vmbus.sys",
                    )
                ],
                "registry": [r"HKLM\\SOFTWARE\\Microsoft\\Virtual Machine\\Guest\\Parameters"],
                "hardware": ["Microsoft Corporation Virtual Machine"],
                "mac_prefixes": ["00:15:5D"],
                "cpuid_vendor": "Microsoft Hv",
                "hypervisor_leaf": 0x40000000,
            },
            "qemu": {
                "processes": ["qemu-ga.exe"],
                "files": ["/usr/bin/qemu-ga"],
                "hardware": ["QEMU Virtual CPU", "QEMU DVD-ROM", "QEMU HARDDISK"],
                "mac_prefixes": ["52:54:00"],
                "cpuid_vendor": "TCGTCGTCGTCG",
                "hypervisor_leaf": 0x40000000,
            },
            "kvm": {
                "processes": ["qemu-ga"],
                "files": ["/dev/kvm"],
                "hardware": ["QEMU Virtual CPU", "KVM"],
                "mac_prefixes": ["52:54:00"],
                "cpuid_vendor": "KVMKVMKVM\0\0\0",
                "hypervisor_leaf": 0x40000000,
            },
            "xen": {
                "processes": ["xenstore-read"],
                "files": ["/proc/xen"],
                "hardware": ["Xen Virtual"],
                "mac_prefixes": ["00:16:3E"],
                "cpuid_vendor": "XenVMMXenVMM",
                "hypervisor_leaf": 0x40000000,
            },
            "parallels": {
                "processes": ["prl_tools.exe", "prl_cc.exe"],
                "files": [
                    os.path.join(
                        os.environ.get("ProgramFiles", r"C:\\Program Files"),
                        "Parallels",
                        "Parallels Tools",
                    )
                ],
                "hardware": ["Parallels Virtual Platform"],
                "mac_prefixes": ["00:1C:42"],
                "cpuid_vendor": "Parallels\0\0\0\0",
                "hypervisor_leaf": 0x40000000,
            },
        }

        self._cpuid_cache = {}
        self._cpuid_results = {}
        self._timing_baseline = None
        self._timing_measurements = {}
        self._hardware_fingerprint = None
        self._memory_scan_cache = {}
        self._perf_counter_baseline = None
        self._detection_lock = threading.Lock()

    def detect_vm(self, aggressive: bool = False) -> dict[str, Any]:
        """Perform VM detection using multiple techniques.

        Args:
            aggressive: Use more aggressive detection methods that might be detected

        Returns:
            Detection results with confidence scores

        """
        results = {
            "is_vm": False,
            "confidence": 0.0,
            "vm_type": None,
            "detections": {},
            "evasion_score": 0,
        }

        try:
            self.logger.info("Starting VM detection...")

            # Use base class detection loop to eliminate duplicate code
            base_results = self.run_detection_loop(aggressive, self.get_aggressive_methods())

            # Copy base results
            results["detections"] = base_results["detections"]

            # Calculate VM-specific results
            detection_count = base_results["detection_count"]
            if detection_count > 0:
                results["is_vm"] = True
                results["confidence"] = min(1.0, base_results["average_confidence"])
                results["vm_type"] = self._identify_vm_type(results["detections"])

            # Calculate evasion score (how hard to evade detection)
            results["evasion_score"] = self._calculate_evasion_score(results["detections"])

            self.logger.info(f"VM detection complete: {results['is_vm']} (confidence: {results['confidence']:.2f})")
            return results

        except Exception as e:
            self.logger.error(f"VM detection failed: {e}")
            return results

    def _execute_cpuid(self, leaf: int, subleaf: int = 0) -> tuple[int, int, int, int] | None:
        """Execute CPUID instruction and return EAX, EBX, ECX, EDX registers."""
        cache_key = (leaf, subleaf)
        if cache_key in self._cpuid_cache:
            return self._cpuid_cache[cache_key]

        try:
            if platform.system() == "Windows":
                if platform.machine().endswith("64"):
                    code = bytes([
                        0x53,
                        0x89, 0xC8,
                        0x89, 0xD1,
                        0x0F, 0xA2,
                        0x41, 0x89, 0x00,
                        0x41, 0x89, 0x58, 0x04,
                        0x41, 0x89, 0x48, 0x08,
                        0x41, 0x89, 0x50, 0x0C,
                        0x5B,
                        0xC3,
                    ])
                else:
                    code = bytes([
                        0x53,
                        0x89, 0xC0,
                        0x89, 0xD1,
                        0x0F, 0xA2,
                        0x89, 0x07,
                        0x89, 0x5F, 0x04,
                        0x89, 0x4F, 0x08,
                        0x89, 0x57, 0x0C,
                        0x5B,
                        0xC3,
                    ])

                buf = ctypes.create_string_buffer(code)
                VirtualAlloc = ctypes.windll.kernel32.VirtualAlloc
                VirtualProtect = ctypes.windll.kernel32.VirtualProtect
                VirtualFree = ctypes.windll.kernel32.VirtualFree

                exec_mem = VirtualAlloc(None, len(code), 0x1000 | 0x2000, 0x04)
                if not exec_mem:
                    return None

                ctypes.memmove(exec_mem, buf, len(code))

                old_protect = ctypes.c_ulong()
                if not VirtualProtect(exec_mem, len(code), 0x20, ctypes.byref(old_protect)):
                    VirtualFree(exec_mem, 0, 0x8000)
                    return None

                result = (ctypes.c_uint32 * 4)()
                func_type = ctypes.CFUNCTYPE(None, ctypes.c_uint32, ctypes.c_uint32, ctypes.POINTER(ctypes.c_uint32))
                func = func_type(exec_mem)
                func(leaf, subleaf, result)

                VirtualFree(exec_mem, 0, 0x8000)

                registers = (result[0], result[1], result[2], result[3])
                self._cpuid_cache[cache_key] = registers
                return registers

            elif platform.system() == "Linux":
                import mmap

                if platform.machine() in ("x86_64", "AMD64"):
                    code = bytes([
                        0x53,
                        0x89, 0xF8,
                        0x89, 0xF1,
                        0x0F, 0xA2,
                        0x41, 0x89, 0x00,
                        0x41, 0x89, 0x58, 0x04,
                        0x41, 0x89, 0x48, 0x08,
                        0x41, 0x89, 0x50, 0x0C,
                        0x5B,
                        0xC3,
                    ])
                elif platform.machine() in ("i386", "i686"):
                    code = bytes([
                        0x53,
                        0x89, 0xC0,
                        0x89, 0xD1,
                        0x0F, 0xA2,
                        0x89, 0x07,
                        0x89, 0x5F, 0x04,
                        0x89, 0x4F, 0x08,
                        0x89, 0x57, 0x0C,
                        0x5B,
                        0xC3,
                    ])
                else:
                    return None

                try:
                    exec_mem = mmap.mmap(
                        -1,
                        len(code),
                        mmap.MAP_PRIVATE | mmap.MAP_ANONYMOUS,
                        mmap.PROT_READ | mmap.PROT_WRITE | mmap.PROT_EXEC,
                    )
                    exec_mem.write(code)

                    result = (ctypes.c_uint32 * 4)()
                    func_type = ctypes.CFUNCTYPE(
                        None,
                        ctypes.c_uint32,
                        ctypes.c_uint32,
                        ctypes.POINTER(ctypes.c_uint32),
                    )

                    exec_addr = ctypes.c_void_p.from_buffer(exec_mem).value
                    func = func_type(exec_addr)
                    func(leaf, subleaf, result)

                    exec_mem.close()

                    registers = (result[0], result[1], result[2], result[3])
                    self._cpuid_cache[cache_key] = registers
                    return registers

                except Exception as e:
                    self.logger.debug(f"Linux CPUID execution failed: {e}")
                    return None

        except Exception as e:
            self.logger.debug(f"CPUID execution failed for leaf 0x{leaf:X}: {e}")
            return None

    def _check_cpuid_hypervisor_bit(self) -> tuple[bool, float, dict]:
        """Check CPUID leaf 0x1 for hypervisor bit (ECX bit 31)."""
        details = {"hypervisor_bit": False, "leaf": 0x1, "ecx_value": None}

        try:
            result = self._execute_cpuid(0x1)
            if result:
                eax, ebx, ecx, edx = result
                details["ecx_value"] = ecx
                hypervisor_bit = (ecx >> 31) & 1
                details["hypervisor_bit"] = bool(hypervisor_bit)

                if hypervisor_bit:
                    self.logger.info(f"Hypervisor bit detected in CPUID leaf 0x1: ECX=0x{ecx:08X}")
                    return True, 0.95, details

        except Exception as e:
            self.logger.debug(f"CPUID hypervisor bit check failed: {e}")

        return False, 0.0, details

    def _check_cpuid_vendor_strings(self) -> tuple[bool, float, dict]:
        """Check CPUID hypervisor vendor strings (leaves 0x40000000-0x400000FF)."""
        details = {"vendor_string": None, "vm_type": None, "hypervisor_leaves": []}

        try:
            result = self._execute_cpuid(0x40000000)
            if result:
                eax, ebx, ecx, edx = result
                vendor_bytes = struct.pack("<III", ebx, ecx, edx)
                vendor_string = vendor_bytes.decode("ascii", errors="ignore").rstrip("\x00")
                details["vendor_string"] = vendor_string
                details["hypervisor_leaves"].append({
                    "leaf": 0x40000000,
                    "eax": eax,
                    "vendor": vendor_string,
                })

                for vm_type, signatures in self.vm_signatures.items():
                    cpuid_vendor = signatures.get("cpuid_vendor", "")
                    if cpuid_vendor and cpuid_vendor in vendor_string:
                        details["vm_type"] = vm_type
                        self.logger.info(f"Detected {vm_type} via CPUID vendor string: {vendor_string}")
                        return True, 0.98, details

                if vendor_string and len(vendor_string) > 3:
                    self.logger.info(f"Unknown hypervisor vendor detected: {vendor_string}")
                    details["vm_type"] = "unknown"
                    return True, 0.85, details

        except Exception as e:
            self.logger.debug(f"CPUID vendor string check failed: {e}")

        return False, 0.0, details

    def _check_cpuid_timing(self) -> tuple[bool, float, dict]:
        """Check CPUID instruction execution timing for VM overhead."""
        details = {"avg_time_ns": 0, "variance": 0, "samples": 0, "anomaly_detected": False}

        try:
            samples = 1000
            timings = []

            for _ in range(samples):
                start = time.perf_counter_ns()
                self._execute_cpuid(0x1)
                end = time.perf_counter_ns()
                timings.append(end - start)

            if timings:
                avg_time = sum(timings) / len(timings)
                variance = sum((t - avg_time) ** 2 for t in timings) / len(timings)
                std_dev = variance ** 0.5

                details["avg_time_ns"] = int(avg_time)
                details["variance"] = int(variance)
                details["std_dev"] = int(std_dev)
                details["samples"] = len(timings)

                if avg_time > 500 or std_dev > 200:
                    details["anomaly_detected"] = True
                    confidence = min(0.75, (avg_time / 1000) * 0.5 + (std_dev / 500) * 0.25)
                    self.logger.info(f"CPUID timing anomaly: avg={avg_time:.0f}ns, std={std_dev:.0f}ns")
                    return True, confidence, details

        except Exception as e:
            self.logger.debug(f"CPUID timing check failed: {e}")

        return False, 0.0, details

    def _check_hypervisor_brand(self) -> tuple[bool, float, dict]:
        """Check hypervisor brand string."""
        details = {"brand": None}

        try:
            # Try to get hypervisor brand
            if platform.system() == "Linux":
                result = subprocess.run(
                    ["dmidecode", "-s", "system-product-name"],  # noqa: S607
                    check=False,
                    capture_output=True,
                    text=True,
                )
                if result.returncode == 0:
                    product = result.stdout.strip().lower()
                    for vm_type, signatures in self.vm_signatures.items():
                        if vm_type in product:
                            details["brand"] = product
                            details["detected_signatures"] = signatures  # Use the signatures
                            return True, 0.9, details

        except Exception as e:
            self.logger.debug(f"Hypervisor brand check failed: {e}")

        return False, 0.0, details

    def _check_hardware_signatures(self) -> tuple[bool, float, dict]:
        """Check for VM-specific hardware signatures."""
        details = {"detected_hardware": []}

        try:
            # Check various hardware identifiers
            if platform.system() == "Windows":
                try:
                    import wmi

                    c = wmi.WMI()

                    # Check system info
                    for system in c.Win32_ComputerSystem():
                        if hasattr(system, "Model"):
                            model = system.Model.lower()
                            for _vm_type, sigs in self.vm_signatures.items():
                                if any(sig.lower() in model for sig in sigs.get("hardware", [])):
                                    details["detected_hardware"].append(model)

                    # Check disk drives
                    for disk in c.Win32_DiskDrive():
                        if hasattr(disk, "Model"):
                            model = disk.Model.lower()
                            for _vm_type, sigs in self.vm_signatures.items():
                                if any(sig.lower() in model for sig in sigs.get("hardware", [])):
                                    details["detected_hardware"].append(model)

                except ImportError as e:
                    self.logger.debug("Import error in vm_detector: %s", e)

            elif platform.system() == "Linux":
                # Check /sys/class/dmi/id/
                dmi_files = [
                    "/sys/class/dmi/id/product_name",
                    "/sys/class/dmi/id/sys_vendor",
                    "/sys/class/dmi/id/board_vendor",
                ]

                for dmi_file in dmi_files:
                    if os.path.exists(dmi_file):
                        with open(dmi_file) as f:
                            content = f.read().strip().lower()
                            for vm_type, _sigs in self.vm_signatures.items():
                                if vm_type in content:
                                    details["detected_hardware"].append(content)

            if details["detected_hardware"]:
                return True, 0.8, details

        except Exception as e:
            self.logger.debug(f"Hardware signature check failed: {e}")

        return False, 0.0, details

    def _check_process_list(self) -> tuple[bool, float, dict]:
        """Check for VM-specific processes."""
        details = {"detected_processes": []}

        try:
            # Get process list using base class method
            processes, process_list = self.get_running_processes()
            self.logger.debug(f"Scanning {len(process_list)} processes for VM indicators")

            # Check for VM processes
            for vm_type, sigs in self.vm_signatures.items():
                for process in sigs.get("processes", []):
                    if process.lower() in processes:
                        details["detected_processes"].append(process)
                        details["vm_type"] = vm_type  # Use vm_type to indicate which VM was detected

            if details["detected_processes"]:
                return True, 0.7, details

        except Exception as e:
            self.logger.debug(f"Process list check failed: {e}")

        return False, 0.0, details

    def _check_registry_keys(self) -> tuple[bool, float, dict]:
        """Check for VM-specific registry keys (Windows only)."""
        details = {"detected_keys": []}

        if platform.system() != "Windows":
            return False, 0.0, details

        try:
            import winreg  # pylint: disable=E0401

            # Check for VM registry keys
            for vm_type, sigs in self.vm_signatures.items():
                for key_path in sigs.get("registry", []):
                    try:
                        parts = key_path.split("\\")
                        hive = getattr(winreg, parts[0])
                        subkey = "\\".join(parts[1:])

                        with winreg.OpenKey(hive, subkey):
                            details["detected_keys"].append(key_path)
                            details["vm_type"] = vm_type  # Use vm_type
                    except Exception:
                        self.logger.debug(f"Registry key not found: {key_path}")

            if details["detected_keys"]:
                return True, 0.8, details

        except Exception as e:
            self.logger.debug(f"Registry check failed: {e}")

        return False, 0.0, details

    def _check_file_system(self) -> tuple[bool, float, dict]:
        """Check for VM-specific files and directories."""
        details = {"detected_files": []}

        try:
            # Check for VM files
            for vm_type, sigs in self.vm_signatures.items():
                for file_path in sigs.get("files", []):
                    if os.path.exists(file_path):
                        details["detected_files"].append(file_path)
                        details["vm_type"] = vm_type  # Use vm_type

            if details["detected_files"]:
                return True, 0.7, details

        except Exception as e:
            self.logger.debug(f"File system check failed: {e}")

        return False, 0.0, details

    def _check_rdtsc_timing(self) -> tuple[bool, float, dict]:
        """Check RDTSC instruction timing for VM detection."""
        details = {"avg_delta": 0, "variance": 0, "anomaly_detected": False, "min_delta": 0, "max_delta": 0}

        try:
            if platform.system() != "Windows":
                return False, 0.0, details

            if platform.machine().endswith("64"):
                code = bytes([
                    0x0F, 0x31,
                    0x48, 0xC1, 0xE2, 0x20,
                    0x48, 0x09, 0xD0,
                    0x48, 0x89, 0x01,
                    0x90,
                    0x90,
                    0x90,
                    0x90,
                    0x90,
                    0x0F, 0x31,
                    0x48, 0xC1, 0xE2, 0x20,
                    0x48, 0x09, 0xD0,
                    0x48, 0x2B, 0x01,
                    0xC3,
                ])
            else:
                code = bytes([
                    0x0F, 0x31,
                    0x89, 0x01,
                    0x89, 0x51, 0x04,
                    0x90,
                    0x90,
                    0x90,
                    0x90,
                    0x90,
                    0x0F, 0x31,
                    0x2B, 0x01,
                    0x1B, 0x51, 0x04,
                    0xC3,
                ])

            buf = ctypes.create_string_buffer(code)
            VirtualAlloc = ctypes.windll.kernel32.VirtualAlloc
            VirtualProtect = ctypes.windll.kernel32.VirtualProtect
            VirtualFree = ctypes.windll.kernel32.VirtualFree

            exec_mem = VirtualAlloc(None, len(code), 0x1000 | 0x2000, 0x04)
            if not exec_mem:
                return False, 0.0, details

            ctypes.memmove(exec_mem, buf, len(code))

            old_protect = ctypes.c_ulong()
            if not VirtualProtect(exec_mem, len(code), 0x20, ctypes.byref(old_protect)):
                VirtualFree(exec_mem, 0, 0x8000)
                return False, 0.0, details

            if platform.machine().endswith("64"):
                tsc_storage = ctypes.c_uint64()
                func_type = ctypes.CFUNCTYPE(ctypes.c_uint64, ctypes.POINTER(ctypes.c_uint64))
                func = func_type(exec_mem)

                samples = 1000
                deltas = []

                for _ in range(samples):
                    delta = func(ctypes.byref(tsc_storage))
                    if delta > 0 and delta < 100000:
                        deltas.append(delta)
            else:
                tsc_storage = (ctypes.c_uint32 * 2)()
                func_type = ctypes.CFUNCTYPE(ctypes.c_uint32, ctypes.POINTER(ctypes.c_uint32))
                func = func_type(exec_mem)

                samples = 1000
                deltas = []

                for _ in range(samples):
                    delta = func(tsc_storage)
                    if delta > 0 and delta < 100000:
                        deltas.append(delta)

            VirtualFree(exec_mem, 0, 0x8000)

            if deltas and len(deltas) > 100:
                avg_delta = sum(deltas) / len(deltas)
                variance = sum((d - avg_delta) ** 2 for d in deltas) / len(deltas)
                std_dev = variance ** 0.5
                min_delta = min(deltas)
                max_delta = max(deltas)

                details["avg_delta"] = int(avg_delta)
                details["variance"] = int(variance)
                details["std_dev"] = int(std_dev)
                details["min_delta"] = int(min_delta)
                details["max_delta"] = int(max_delta)
                details["samples"] = len(deltas)

                if avg_delta > 500 or std_dev > 300 or max_delta > 5000:
                    details["anomaly_detected"] = True
                    confidence = min(0.85, (avg_delta / 1000) * 0.4 + (std_dev / 500) * 0.3 + 0.15)
                    self.logger.info(
                        f"RDTSC timing anomaly detected: avg={avg_delta:.0f} cycles, "
                        f"std={std_dev:.0f}, min={min_delta}, max={max_delta}"
                    )
                    return True, confidence, details

        except Exception as e:
            self.logger.debug(f"RDTSC timing check failed: {e}")

        return False, 0.0, details

    def _check_sleep_timing(self) -> tuple[bool, float, dict]:
        """Check sleep timing discrepancies for VM detection."""
        details = {"expected_ms": 0, "actual_ms": 0, "discrepancy": 0}

        try:
            sleep_duration = 0.01
            samples = 50
            discrepancies = []

            for _ in range(samples):
                start = time.perf_counter()
                time.sleep(sleep_duration)
                end = time.perf_counter()
                actual = (end - start) * 1000
                expected = sleep_duration * 1000
                discrepancy = abs(actual - expected)
                discrepancies.append(discrepancy)

            if discrepancies:
                avg_discrepancy = sum(discrepancies) / len(discrepancies)
                details["expected_ms"] = sleep_duration * 1000
                details["actual_ms"] = avg_discrepancy + details["expected_ms"]
                details["discrepancy"] = avg_discrepancy

                if avg_discrepancy > 2.0:
                    confidence = min(0.65, avg_discrepancy / 10.0)
                    self.logger.info(f"Sleep timing discrepancy: {avg_discrepancy:.2f}ms")
                    return True, confidence, details

        except Exception as e:
            self.logger.debug(f"Sleep timing check failed: {e}")

        return False, 0.0, details

    def _check_instruction_timing(self) -> tuple[bool, float, dict]:
        """Check instruction execution timing for VM overhead."""
        details = {"baseline_ns": 0, "test_ns": 0, "overhead_pct": 0}

        try:
            iterations = 100000
            baseline_timings = []
            test_timings = []

            for _ in range(10):
                start = time.perf_counter_ns()
                for i in range(iterations):
                    _ = i * 2
                end = time.perf_counter_ns()
                baseline_timings.append(end - start)

            for _ in range(10):
                start = time.perf_counter_ns()
                for i in range(iterations):
                    _ = i * 2
                    _ = i % 3
                end = time.perf_counter_ns()
                test_timings.append(end - start)

            baseline_avg = sum(baseline_timings) / len(baseline_timings)
            test_avg = sum(test_timings) / len(test_timings)
            overhead_pct = ((test_avg - baseline_avg) / baseline_avg) * 100

            details["baseline_ns"] = int(baseline_avg)
            details["test_ns"] = int(test_avg)
            details["overhead_pct"] = round(overhead_pct, 2)

            if overhead_pct > 150:
                confidence = min(0.60, overhead_pct / 500)
                self.logger.info(f"Instruction timing overhead: {overhead_pct:.1f}%")
                return True, confidence, details

        except Exception as e:
            self.logger.debug(f"Instruction timing check failed: {e}")

        return False, 0.0, details

    def _check_network_adapters(self) -> tuple[bool, float, dict]:
        """Check for VM-specific MAC address prefixes."""
        details = {"detected_macs": []}

        try:
            # Get network interfaces
            if platform.system() == "Windows":
                ipconfig_path = shutil.which("ipconfig")
                if ipconfig_path:
                    result = subprocess.run(  # nosec S603 - Legitimate subprocess usage for security research and binary analysis  # noqa: S603
                        [ipconfig_path, "/all"],
                        check=False,
                        capture_output=True,
                        text=True,
                        shell=False,  # Explicitly secure - using list format prevents shell injection
                    )
                    output = result.stdout if result else ""
                else:
                    output = ""
            else:
                ip_path = shutil.which("ip")
                if ip_path:
                    result = subprocess.run(  # nosec S603 - Legitimate subprocess usage for security research and binary analysis  # noqa: S603
                        [ip_path, "link"],
                        check=False,
                        capture_output=True,
                        text=True,
                        shell=False,  # Explicitly secure - using list format prevents shell injection
                    )
                    output = result.stdout if result else ""
                else:
                    output = ""

            # Extract MAC addresses
            import re

            mac_pattern = r"([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})"
            macs = re.findall(mac_pattern, output)

            # Check against known VM MAC prefixes
            for mac in macs:
                mac_str = "".join(mac).replace(":", "").replace("-", "")
                mac_prefix = ":".join([mac_str[i : i + 2] for i in range(0, 6, 2)])

                for vm_type, sigs in self.vm_signatures.items():
                    for prefix in sigs.get("mac_prefixes", []):
                        if mac_prefix.lower().startswith(prefix.lower()):
                            details["detected_macs"].append(mac_prefix)
                            details["vm_type"] = vm_type  # Use vm_type

            if details["detected_macs"]:
                return True, 0.8, details

        except Exception as e:
            self.logger.debug(f"Network adapter check failed: {e}")

        return False, 0.0, details

    def _check_bios_info(self) -> tuple[bool, float, dict]:
        """Check BIOS information for VM signatures."""
        details = {"bios_vendor": None}

        try:
            if platform.system() == "Linux":
                bios_file = "/sys/class/dmi/id/bios_vendor"
                if os.path.exists(bios_file):
                    with open(bios_file) as f:
                        vendor = f.read().strip().lower()
                        for vm_type in self.vm_signatures:
                            if vm_type in vendor:
                                details["bios_vendor"] = vendor
                                return True, 0.8, details

            elif platform.system() == "Windows":
                try:
                    import wmi

                    c = wmi.WMI()
                    for bios in c.Win32_BIOS():
                        if hasattr(bios, "Manufacturer"):
                            vendor = bios.Manufacturer.lower()
                            for vm_type in self.vm_signatures:
                                if vm_type in vendor:
                                    details["bios_vendor"] = vendor
                                    return True, 0.8, details
                except ImportError as e:
                    self.logger.debug("Import error in vm_detector: %s", e)

        except Exception as e:
            self.logger.debug(f"BIOS info check failed: {e}")

        return False, 0.0, details

    def _check_device_drivers(self) -> tuple[bool, float, dict]:
        """Check for VM-specific device drivers."""
        details = {"detected_drivers": []}

        try:
            if platform.system() == "Windows":
                driverquery_path = shutil.which("driverquery")
                if driverquery_path:
                    result = subprocess.run(
                        [driverquery_path],
                        check=False,
                        capture_output=True,
                        text=True,
                        shell=False,
                    )
                    drivers = result.stdout.lower() if result and result.stdout else ""
                else:
                    drivers = ""

                vm_drivers = [
                    "vmci",
                    "vmmouse",
                    "vmhgfs",
                    "vboxguest",
                    "vboxmouse",
                    "vboxsf",
                    "vboxvideo",
                    "vm3dmp",
                ]

                for driver in vm_drivers:
                    if driver in drivers:
                        details["detected_drivers"].append(driver)

            elif platform.system() == "Linux":
                result = subprocess.run(["lsmod"], check=False, capture_output=True, text=True)
                modules = result.stdout.lower()

                vm_modules = [
                    "vmw_vmci",
                    "vmw_balloon",
                    "vmwgfx",
                    "vboxguest",
                    "vboxsf",
                    "vboxvideo",
                    "virtio_balloon",
                    "virtio_pci",
                ]

                for module in vm_modules:
                    if module in modules:
                        details["detected_drivers"].append(module)

            if details["detected_drivers"]:
                return True, 0.9, details

        except Exception as e:
            self.logger.debug(f"Device driver check failed: {e}")

        return False, 0.0, details

    def _check_cpu_model_detection(self) -> tuple[bool, float, dict]:
        """Check CPU model for VM-specific identifiers."""
        details = {"cpu_model": None, "vm_indicators": []}

        try:
            if platform.system() == "Windows":
                try:
                    import wmi

                    c = wmi.WMI()
                    for processor in c.Win32_Processor():
                        if hasattr(processor, "Name"):
                            cpu_name = processor.Name.lower()
                            details["cpu_model"] = cpu_name

                            vm_cpu_patterns = [
                                "qemu",
                                "virtual",
                                "kvm",
                                "xen",
                                "vmware",
                                "virtualbox",
                                "hypervisor",
                            ]

                            for pattern in vm_cpu_patterns:
                                if pattern in cpu_name:
                                    details["vm_indicators"].append(pattern)

                except ImportError:
                    pass

            elif platform.system() == "Linux":
                with open("/proc/cpuinfo") as f:
                    cpuinfo = f.read()
                    for line in cpuinfo.split("\n"):
                        if line.startswith("model name"):
                            cpu_name = line.split(":")[1].strip().lower()
                            details["cpu_model"] = cpu_name

                            vm_cpu_patterns = [
                                "qemu",
                                "virtual",
                                "kvm",
                                "xen",
                                "vmware",
                                "virtualbox",
                            ]

                            for pattern in vm_cpu_patterns:
                                if pattern in cpu_name:
                                    details["vm_indicators"].append(pattern)
                            break

            if details["vm_indicators"]:
                confidence = min(0.90, len(details["vm_indicators"]) * 0.3 + 0.6)
                self.logger.info(f"VM CPU detected: {details['cpu_model']}")
                return True, confidence, details

        except Exception as e:
            self.logger.debug(f"CPU model detection failed: {e}")

        return False, 0.0, details

    def _check_hardware_fingerprint(self) -> tuple[bool, float, dict]:
        """Check hardware fingerprint for VM characteristics."""
        details = {
            "total_ram_mb": 0,
            "cpu_cores": 0,
            "disk_count": 0,
            "suspicious_values": [],
        }

        try:
            if platform.system() == "Windows":
                try:
                    import wmi

                    c = wmi.WMI()

                    for cs in c.Win32_ComputerSystem():
                        if hasattr(cs, "TotalPhysicalMemory"):
                            total_ram = int(cs.TotalPhysicalMemory) // (1024 * 1024)
                            details["total_ram_mb"] = total_ram

                            if total_ram in [512, 1024, 2048, 4096, 8192]:
                                details["suspicious_values"].append(f"ram={total_ram}MB (power of 2)")

                        if hasattr(cs, "NumberOfLogicalProcessors"):
                            cpu_cores = int(cs.NumberOfLogicalProcessors)
                            details["cpu_cores"] = cpu_cores

                            if cpu_cores in [1, 2, 4, 8]:
                                details["suspicious_values"].append(f"cores={cpu_cores} (power of 2)")

                    disk_count = len(list(c.Win32_DiskDrive()))
                    details["disk_count"] = disk_count

                    if disk_count == 1:
                        details["suspicious_values"].append("single_disk (common in VMs)")

                except ImportError:
                    pass

            if details["suspicious_values"]:
                confidence = min(0.55, len(details["suspicious_values"]) * 0.20)
                self.logger.info(f"Suspicious hardware fingerprint: {details['suspicious_values']}")
                return True, confidence, details

        except Exception as e:
            self.logger.debug(f"Hardware fingerprint check failed: {e}")

        return False, 0.0, details

    def _check_disk_serial_numbers(self) -> tuple[bool, float, dict]:
        """Check disk serial numbers for VM patterns."""
        details = {"disk_serials": [], "vm_patterns_found": []}

        try:
            if platform.system() == "Windows":
                try:
                    import wmi

                    c = wmi.WMI()
                    for disk in c.Win32_DiskDrive():
                        if hasattr(disk, "SerialNumber"):
                            serial = disk.SerialNumber.strip()
                            if serial:
                                details["disk_serials"].append(serial)

                                vm_serial_patterns = [
                                    "vmware",
                                    "vbox",
                                    "qemu",
                                    "virtual",
                                    "0000000000",
                                    "1111111111",
                                ]

                                for pattern in vm_serial_patterns:
                                    if pattern.lower() in serial.lower():
                                        details["vm_patterns_found"].append(
                                            f"{serial} contains '{pattern}'"
                                        )

                except ImportError:
                    pass

            elif platform.system() == "Linux":
                try:
                    result = subprocess.run(
                        ["lsblk", "-o", "SERIAL", "-n"],
                        check=False,
                        capture_output=True,
                        text=True,
                    )
                    if result.stdout:
                        for line in result.stdout.split("\n"):
                            serial = line.strip()
                            if serial:
                                details["disk_serials"].append(serial)

                                vm_serial_patterns = [
                                    "vmware",
                                    "vbox",
                                    "qemu",
                                    "virtual",
                                ]

                                for pattern in vm_serial_patterns:
                                    if pattern.lower() in serial.lower():
                                        details["vm_patterns_found"].append(
                                            f"{serial} contains '{pattern}'"
                                        )
                except FileNotFoundError:
                    pass

            if details["vm_patterns_found"]:
                confidence = min(0.85, len(details["vm_patterns_found"]) * 0.30 + 0.55)
                self.logger.info(f"VM disk serial patterns detected: {details['vm_patterns_found']}")
                return True, confidence, details

        except Exception as e:
            self.logger.debug(f"Disk serial number check failed: {e}")

        return False, 0.0, details

    def _check_mac_address_patterns(self) -> tuple[bool, float, dict]:
        """Check MAC address patterns for VM vendors."""
        details = {"mac_addresses": [], "vm_macs": []}

        try:
            import re

            if platform.system() == "Windows":
                ipconfig_path = shutil.which("ipconfig")
                if ipconfig_path:
                    result = subprocess.run(
                        [ipconfig_path, "/all"],
                        check=False,
                        capture_output=True,
                        text=True,
                        shell=False,
                    )
                    output = result.stdout if result else ""
                else:
                    output = ""
            else:
                ip_path = shutil.which("ip")
                if ip_path:
                    result = subprocess.run(
                        [ip_path, "link"],
                        check=False,
                        capture_output=True,
                        text=True,
                        shell=False,
                    )
                    output = result.stdout if result else ""
                else:
                    output = ""

            mac_pattern = r"([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})"
            macs = re.findall(mac_pattern, output)

            for mac in macs:
                mac_str = "".join(mac).replace(":", "").replace("-", "")
                mac_formatted = ":".join([mac_str[i : i + 2] for i in range(0, 12, 2)])
                details["mac_addresses"].append(mac_formatted)

                for vm_type, sigs in self.vm_signatures.items():
                    for prefix in sigs.get("mac_prefixes", []):
                        if mac_formatted.upper().startswith(prefix.upper()):
                            details["vm_macs"].append(
                                {
                                    "mac": mac_formatted,
                                    "vendor": vm_type,
                                    "prefix": prefix,
                                }
                            )

            if details["vm_macs"]:
                confidence = min(0.88, len(details["vm_macs"]) * 0.30 + 0.58)
                self.logger.info(f"VM MAC addresses detected: {details['vm_macs']}")
                return True, confidence, details

        except Exception as e:
            self.logger.debug(f"MAC address pattern check failed: {e}")

        return False, 0.0, details

    def _check_cpuid_feature_flags(self) -> tuple[bool, float, dict]:
        """Analyze CPUID feature flags for VM-specific indicators."""
        details = {
            "hypervisor_present": False,
            "feature_flags": {},
            "vm_indicators": [],
            "ecx_features": [],
            "edx_features": []
        }

        try:
            result = self._execute_cpuid(0x1)
            if result:
                eax, ebx, ecx, edx = result

                details["hypervisor_present"] = bool((ecx >> 31) & 1)

                ecx_features = {
                    "SSE3": bool(ecx & 1),
                    "PCLMULQDQ": bool((ecx >> 1) & 1),
                    "MONITOR": bool((ecx >> 3) & 1),
                    "SSSE3": bool((ecx >> 9) & 1),
                    "FMA": bool((ecx >> 12) & 1),
                    "CMPXCHG16B": bool((ecx >> 13) & 1),
                    "PCID": bool((ecx >> 17) & 1),
                    "SSE4_1": bool((ecx >> 19) & 1),
                    "SSE4_2": bool((ecx >> 20) & 1),
                    "x2APIC": bool((ecx >> 21) & 1),
                    "MOVBE": bool((ecx >> 22) & 1),
                    "POPCNT": bool((ecx >> 23) & 1),
                    "AES": bool((ecx >> 25) & 1),
                    "XSAVE": bool((ecx >> 26) & 1),
                    "OSXSAVE": bool((ecx >> 27) & 1),
                    "AVX": bool((ecx >> 28) & 1),
                    "F16C": bool((ecx >> 29) & 1),
                    "RDRAND": bool((ecx >> 30) & 1),
                }

                details["feature_flags"]["ecx"] = ecx_features
                details["ecx_features"] = [k for k, v in ecx_features.items() if v]

                if not ecx_features.get("RDRAND"):
                    details["vm_indicators"].append("Missing RDRAND (common in older VMs)")

                if ecx_features.get("x2APIC") and details["hypervisor_present"]:
                    details["vm_indicators"].append("x2APIC with hypervisor bit (VM configuration)")

                if details["vm_indicators"] or details["hypervisor_present"]:
                    confidence = 0.70 if details["hypervisor_present"] else 0.40
                    confidence += len(details["vm_indicators"]) * 0.10
                    return True, min(confidence, 0.85), details

        except Exception as e:
            self.logger.debug(f"CPUID feature flag analysis failed: {e}")

        return False, 0.0, details

    def _check_cpuid_extended_leaves(self) -> tuple[bool, float, dict]:
        """Check CPUID extended leaves for hypervisor information."""
        details = {"leaves": [], "hypervisor_info": {}, "vm_detected": False}

        try:
            base_leaf = self._execute_cpuid(0x40000000)
            if base_leaf:
                eax, ebx, ecx, edx = base_leaf
                max_leaf = eax
                vendor = struct.pack("<III", ebx, ecx, edx).decode("ascii", errors="ignore").rstrip("\x00")

                details["hypervisor_info"]["base_leaf"] = {
                    "max_leaf": hex(max_leaf),
                    "vendor": vendor
                }

                if vendor:
                    details["vm_detected"] = True
                    details["hypervisor_info"]["vendor_string"] = vendor

                    for i in range(1, min(16, (max_leaf - 0x40000000) + 1)):
                        leaf_num = 0x40000000 + i
                        leaf_result = self._execute_cpuid(leaf_num)
                        if leaf_result:
                            leaf_eax, leaf_ebx, leaf_ecx, leaf_edx = leaf_result
                            details["leaves"].append({
                                "leaf": hex(leaf_num),
                                "eax": hex(leaf_eax),
                                "ebx": hex(leaf_ebx),
                                "ecx": hex(leaf_ecx),
                                "edx": hex(leaf_edx)
                            })

                    if "VMware" in vendor or "VBox" in vendor or "Microsoft Hv" in vendor or "KVM" in vendor:
                        return True, 0.95, details

                    return True, 0.80, details

        except Exception as e:
            self.logger.debug(f"Extended CPUID leaf check failed: {e}")

        return False, 0.0, details

    def _check_cpuid_brand_string(self) -> tuple[bool, float, dict]:
        """Extract and analyze CPU brand string for VM indicators."""
        details = {"brand_string": "", "vm_indicators": []}

        try:
            brand_parts = []
            for leaf in [0x80000002, 0x80000003, 0x80000004]:
                result = self._execute_cpuid(leaf)
                if result:
                    eax, ebx, ecx, edx = result
                    brand_parts.append(struct.pack("<IIII", eax, ebx, ecx, edx))

            if brand_parts:
                brand_string = b"".join(brand_parts).decode("ascii", errors="ignore").strip("\x00").strip()
                details["brand_string"] = brand_string

                vm_patterns = ["QEMU", "Virtual", "KVM", "Xen", "Bochs", "VMware", "VirtualBox"]

                for pattern in vm_patterns:
                    if pattern.lower() in brand_string.lower():
                        details["vm_indicators"].append(f"Brand contains '{pattern}'")

                if details["vm_indicators"]:
                    confidence = min(0.90, len(details["vm_indicators"]) * 0.35 + 0.55)
                    self.logger.info(f"VM detected in CPU brand: {brand_string}")
                    return True, confidence, details

        except Exception as e:
            self.logger.debug(f"CPU brand string check failed: {e}")

        return False, 0.0, details

    def _check_rdtsc_vmexit_detection(self) -> tuple[bool, float, dict]:
        """Detect VM exits by measuring RDTSC instruction pairs for large deltas."""
        details = {
            "vmexit_candidates": [],
            "max_delta": 0,
            "avg_delta": 0,
            "vmexit_threshold": 1000,
            "samples": 0
        }

        try:
            if platform.system() != "Windows":
                return False, 0.0, details

            if platform.machine().endswith("64"):
                code = bytes([
                    0x48, 0x31, 0xC0,
                    0x48, 0x31, 0xD2,
                    0x0F, 0x31,
                    0x48, 0xC1, 0xE2, 0x20,
                    0x48, 0x09, 0xD0,
                    0x48, 0x89, 0xC1,
                    0x0F, 0x31,
                    0x48, 0xC1, 0xE2, 0x20,
                    0x48, 0x09, 0xD0,
                    0x48, 0x29, 0xC8,
                    0xC3
                ])
            else:
                code = bytes([
                    0x31, 0xC0,
                    0x31, 0xD2,
                    0x0F, 0x31,
                    0x89, 0xC1,
                    0x89, 0xD3,
                    0x0F, 0x31,
                    0x29, 0xC8,
                    0x19, 0xDA,
                    0xC3
                ])

            VirtualAlloc = ctypes.windll.kernel32.VirtualAlloc
            VirtualProtect = ctypes.windll.kernel32.VirtualProtect
            VirtualFree = ctypes.windll.kernel32.VirtualFree

            exec_mem = VirtualAlloc(None, len(code), 0x3000, 0x04)
            if not exec_mem:
                return False, 0.0, details

            ctypes.memmove(exec_mem, code, len(code))

            old_protect = ctypes.c_ulong()
            if not VirtualProtect(exec_mem, len(code), 0x20, ctypes.byref(old_protect)):
                VirtualFree(exec_mem, 0, 0x8000)
                return False, 0.0, details

            func_type = ctypes.CFUNCTYPE(ctypes.c_uint64 if platform.machine().endswith("64") else ctypes.c_uint32)
            func = func_type(exec_mem)

            samples = 2000
            deltas = []
            vmexit_count = 0

            for _ in range(samples):
                delta = func()
                if delta > 0:
                    deltas.append(delta)
                    if delta > details["vmexit_threshold"]:
                        vmexit_count += 1
                        if len(details["vmexit_candidates"]) < 20:
                            details["vmexit_candidates"].append(int(delta))

            VirtualFree(exec_mem, 0, 0x8000)

            if deltas:
                details["avg_delta"] = int(sum(deltas) / len(deltas))
                details["max_delta"] = int(max(deltas))
                details["samples"] = len(deltas)
                details["vmexit_count"] = vmexit_count
                details["vmexit_percentage"] = (vmexit_count / len(deltas)) * 100

                if vmexit_count > (samples * 0.05):
                    confidence = min(0.92, (vmexit_count / samples) * 2.0 + 0.60)
                    self.logger.info(f"VM exit patterns detected: {vmexit_count}/{samples} samples ({details['vmexit_percentage']:.1f}%)")
                    return True, confidence, details

        except Exception as e:
            self.logger.debug(f"RDTSC VM exit detection failed: {e}")

        return False, 0.0, details

    def _check_paravirt_instructions(self) -> tuple[bool, float, dict]:
        """Test for paravirtualization instructions (VMCALL, VMMCALL, VMFUNC)."""
        details = {"instructions_tested": [], "exceptions_caught": [], "paravirt_detected": False}

        try:
            if platform.system() != "Windows":
                return False, 0.0, details

            test_instructions = {
                "VMCALL": bytes([0x0F, 0x01, 0xC1, 0xC3]),
                "VMMCALL": bytes([0x0F, 0x01, 0xD9, 0xC3]),
            }

            VirtualAlloc = ctypes.windll.kernel32.VirtualAlloc
            VirtualProtect = ctypes.windll.kernel32.VirtualProtect
            VirtualFree = ctypes.windll.kernel32.VirtualFree

            for instr_name, code in test_instructions.items():
                try:
                    exec_mem = VirtualAlloc(None, len(code), 0x3000, 0x04)
                    if not exec_mem:
                        continue

                    ctypes.memmove(exec_mem, code, len(code))

                    old_protect = ctypes.c_ulong()
                    if not VirtualProtect(exec_mem, len(code), 0x20, ctypes.byref(old_protect)):
                        VirtualFree(exec_mem, 0, 0x8000)
                        continue

                    func_type = ctypes.CFUNCTYPE(None)
                    func = func_type(exec_mem)

                    details["instructions_tested"].append(instr_name)

                    try:
                        func()
                        details["paravirt_detected"] = True
                        details["working_instruction"] = instr_name
                        VirtualFree(exec_mem, 0, 0x8000)
                        self.logger.info(f"Paravirtualization instruction {instr_name} executed successfully (VM detected)")
                        return True, 0.99, details

                    except Exception as exec_err:
                        details["exceptions_caught"].append(f"{instr_name}: {type(exec_err).__name__}")

                    VirtualFree(exec_mem, 0, 0x8000)

                except Exception as e:
                    self.logger.debug(f"Testing {instr_name} failed: {e}")
                    continue

        except Exception as e:
            self.logger.debug(f"Paravirt instruction testing failed: {e}")

        return False, 0.0, details

    def _check_acpi_tables(self) -> tuple[bool, float, dict]:
        """Check ACPI tables for VM signatures."""
        details = {"acpi_tables": [], "vm_signatures_found": []}

        try:
            if platform.system() == "Windows":
                try:
                    import wmi
                    c = wmi.WMI()

                    for table in c.MSAcpi_RawSMBiosTables():
                        if hasattr(table, "SMBiosData"):
                            data = bytes(table.SMBiosData)
                            data_str = data.decode("ascii", errors="ignore").lower()

                            vm_patterns = ["vmware", "vbox", "virtualbox", "qemu", "xen", "kvm", "hyper-v", "parallels"]
                            for pattern in vm_patterns:
                                if pattern in data_str:
                                    details["vm_signatures_found"].append(f"ACPI contains '{pattern}'")

                except ImportError:
                    pass

            elif platform.system() == "Linux":
                acpi_paths = [
                    "/sys/firmware/acpi/tables/DSDT",
                    "/sys/firmware/acpi/tables/SSDT",
                ]

                for acpi_path in acpi_paths:
                    if os.path.exists(acpi_path):
                        try:
                            with open(acpi_path, "rb") as f:
                                data = f.read(4096)
                                data_str = data.decode("ascii", errors="ignore").lower()

                                vm_patterns = ["vmware", "vbox", "qemu", "xen", "kvm", "bochs"]
                                for pattern in vm_patterns:
                                    if pattern in data_str:
                                        details["vm_signatures_found"].append(f"{acpi_path} contains '{pattern}'")
                        except Exception as e:
                            self.logger.debug(f"Failed to read {acpi_path}: {e}")

            if details["vm_signatures_found"]:
                confidence = min(0.90, len(details["vm_signatures_found"]) * 0.30 + 0.60)
                return True, confidence, details

        except Exception as e:
            self.logger.debug(f"ACPI table check failed: {e}")

        return False, 0.0, details

    def _check_pci_devices(self) -> tuple[bool, float, dict]:
        """Check PCI devices for VM-specific controllers."""
        details = {"pci_devices": [], "vm_devices": []}

        try:
            if platform.system() == "Linux":
                result = subprocess.run(
                    ["lspci"],
                    check=False,
                    capture_output=True,
                    text=True,
                    shell=False
                )

                if result.returncode == 0:
                    pci_output = result.stdout.lower()
                    details["pci_devices"] = result.stdout.split("\n")[:20]

                    vm_device_patterns = [
                        "vmware", "virtualbox", "qemu", "virtio",
                        "red hat", "xen", "hyper-v", "parallels"
                    ]

                    for pattern in vm_device_patterns:
                        if pattern in pci_output:
                            details["vm_devices"].append(f"PCI device contains '{pattern}'")

            elif platform.system() == "Windows":
                try:
                    import wmi
                    c = wmi.WMI()

                    for controller in c.Win32_PnPEntity():
                        if hasattr(controller, "Name"):
                            device_name = controller.Name.lower()

                            vm_patterns = ["vmware", "vbox", "qemu", "virtio", "red hat", "hyper-v"]
                            for pattern in vm_patterns:
                                if pattern in device_name:
                                    details["vm_devices"].append(device_name)

                except ImportError:
                    pass

            if details["vm_devices"]:
                confidence = min(0.88, len(details["vm_devices"]) * 0.25 + 0.63)
                return True, confidence, details

        except Exception as e:
            self.logger.debug(f"PCI device check failed: {e}")

        return False, 0.0, details

    def _check_memory_artifacts(self) -> tuple[bool, float, dict]:
        """Scan process memory for hypervisor signatures."""
        details = {"signatures_found": [], "memory_regions_scanned": 0}

        try:
            if platform.system() != "Windows":
                return False, 0.0, details

            hypervisor_signatures = [
                b"VMware",
                b"VirtualBox",
                b"QEMU",
                b"KVM",
                b"Xen",
                b"Microsoft Hv",
                b"Hyper-V",
                b"Parallels"
            ]

            kernel32 = ctypes.windll.kernel32
            process_handle = kernel32.GetCurrentProcess()

            mbi = ctypes.c_buffer(48)
            address = 0
            max_regions = 100
            regions_scanned = 0

            while regions_scanned < max_regions:
                result = kernel32.VirtualQueryEx(
                    process_handle,
                    ctypes.c_void_p(address),
                    ctypes.byref(mbi),
                    ctypes.sizeof(mbi)
                )

                if result == 0:
                    break

                base_address = int.from_bytes(mbi[0:8] if sys.maxsize > 2**32 else mbi[0:4], "little")
                region_size = int.from_bytes(mbi[16:24] if sys.maxsize > 2**32 else mbi[12:16], "little")
                protect = int.from_bytes(mbi[32:36], "little")

                if protect in [0x04, 0x20, 0x40]:
                    scan_size = min(region_size, 4096)
                    try:
                        buffer = ctypes.create_string_buffer(scan_size)
                        bytes_read = ctypes.c_size_t()

                        if kernel32.ReadProcessMemory(
                            process_handle,
                            ctypes.c_void_p(base_address),
                            buffer,
                            scan_size,
                            ctypes.byref(bytes_read)
                        ):
                            memory_data = buffer.raw[:bytes_read.value]

                            for signature in hypervisor_signatures:
                                if signature in memory_data:
                                    sig_str = signature.decode("ascii", errors="ignore")
                                    if sig_str not in details["signatures_found"]:
                                        details["signatures_found"].append(sig_str)
                                        self.logger.info(f"Found hypervisor signature in memory: {sig_str}")
                    except Exception as e:
                        self.logger.debug(f"Memory region scan error: {e}")

                regions_scanned += 1
                address = base_address + region_size

                if address >= 0x7FFFFFFF:
                    break

            details["memory_regions_scanned"] = regions_scanned

            if details["signatures_found"]:
                confidence = min(0.85, len(details["signatures_found"]) * 0.30 + 0.55)
                return True, confidence, details

        except Exception as e:
            self.logger.debug(f"Memory artifact scan failed: {e}")

        return False, 0.0, details

    def _check_performance_counters(self) -> tuple[bool, float, dict]:
        """Analyze performance counters for VM overhead patterns."""
        details = {"counter_anomalies": [], "baseline": {}, "current": {}}

        try:
            if platform.system() == "Windows":
                try:
                    import wmi
                    c = wmi.WMI()

                    for proc in c.Win32_PerfFormattedData_PerfOS_Processor(Name="_Total"):
                        if hasattr(proc, "PercentProcessorTime"):
                            details["current"]["processor_time"] = int(proc.PercentProcessorTime)
                        if hasattr(proc, "PercentIdleTime"):
                            details["current"]["idle_time"] = int(proc.PercentIdleTime)
                        if hasattr(proc, "PercentInterruptTime"):
                            interrupt_time = int(proc.PercentInterruptTime)
                            details["current"]["interrupt_time"] = interrupt_time

                            if interrupt_time > 15:
                                details["counter_anomalies"].append(
                                    f"High interrupt time: {interrupt_time}% (VM overhead indicator)"
                                )

                except ImportError:
                    pass

            if details["counter_anomalies"]:
                confidence = min(0.60, len(details["counter_anomalies"]) * 0.25 + 0.35)
                return True, confidence, details

        except Exception as e:
            self.logger.debug(f"Performance counter check failed: {e}")

        return False, 0.0, details

    def _check_tsc_frequency_analysis(self) -> tuple[bool, float, dict]:
        """Analyze TSC frequency for VM timing artifacts."""
        details = {
            "tsc_frequency_hz": 0,
            "measurement_variance": 0,
            "anomaly_detected": False
        }

        try:
            if platform.system() != "Windows":
                return False, 0.0, details

            if platform.machine().endswith("64"):
                code = bytes([
                    0x0F, 0x31,
                    0x48, 0xC1, 0xE2, 0x20,
                    0x48, 0x09, 0xD0,
                    0xC3
                ])
            else:
                code = bytes([
                    0x0F, 0x31,
                    0xC3
                ])

            VirtualAlloc = ctypes.windll.kernel32.VirtualAlloc
            VirtualProtect = ctypes.windll.kernel32.VirtualProtect
            VirtualFree = ctypes.windll.kernel32.VirtualFree

            exec_mem = VirtualAlloc(None, len(code), 0x3000, 0x04)
            if not exec_mem:
                return False, 0.0, details

            ctypes.memmove(exec_mem, code, len(code))

            old_protect = ctypes.c_ulong()
            if not VirtualProtect(exec_mem, len(code), 0x20, ctypes.byref(old_protect)):
                VirtualFree(exec_mem, 0, 0x8000)
                return False, 0.0, details

            func_type = ctypes.CFUNCTYPE(ctypes.c_uint64 if platform.machine().endswith("64") else ctypes.c_uint32)
            func = func_type(exec_mem)

            measurements = []
            for _ in range(5):
                tsc_start = func()
                time.sleep(0.1)
                tsc_end = func()

                tsc_diff = tsc_end - tsc_start
                frequency = tsc_diff * 10
                measurements.append(frequency)

            VirtualFree(exec_mem, 0, 0x8000)

            if measurements:
                avg_freq = sum(measurements) / len(measurements)
                variance = sum((m - avg_freq) ** 2 for m in measurements) / len(measurements)
                std_dev = variance ** 0.5

                details["tsc_frequency_hz"] = int(avg_freq)
                details["measurement_variance"] = int(variance)
                details["std_dev"] = int(std_dev)

                variance_pct = (std_dev / avg_freq) * 100

                if variance_pct > 5.0:
                    details["anomaly_detected"] = True
                    confidence = min(0.70, variance_pct / 20.0 + 0.40)
                    self.logger.info(f"TSC frequency variance: {variance_pct:.2f}% (VM indicator)")
                    return True, confidence, details

        except Exception as e:
            self.logger.debug(f"TSC frequency analysis failed: {e}")

        return False, 0.0, details

    def _check_cache_timing(self) -> tuple[bool, float, dict]:
        """Analyze CPU cache timing for VM artifacts."""
        details = {
            "l1_cache_timing_ns": 0,
            "l2_cache_timing_ns": 0,
            "memory_timing_ns": 0,
            "timing_ratios": {},
            "anomaly_detected": False
        }

        try:
            array_size_l1 = 16 * 1024
            array_size_l2 = 256 * 1024
            array_size_mem = 8 * 1024 * 1024

            iterations = 10000

            arr_l1 = (ctypes.c_uint8 * array_size_l1)()
            arr_l2 = (ctypes.c_uint8 * array_size_l2)()
            arr_mem = (ctypes.c_uint8 * array_size_mem)()

            for i in range(array_size_l1):
                arr_l1[i] = i % 256
            for i in range(array_size_l2):
                arr_l2[i] = i % 256
            for i in range(array_size_mem):
                arr_mem[i] = i % 256

            start = time.perf_counter_ns()
            for _ in range(iterations):
                for i in range(0, array_size_l1, 64):
                    _ = arr_l1[i]
            l1_time = (time.perf_counter_ns() - start) / iterations

            start = time.perf_counter_ns()
            for _ in range(iterations // 10):
                for i in range(0, array_size_l2, 64):
                    _ = arr_l2[i]
            l2_time = (time.perf_counter_ns() - start) / (iterations // 10)

            start = time.perf_counter_ns()
            for _ in range(iterations // 100):
                for i in range(0, array_size_mem, 4096):
                    _ = arr_mem[i]
            mem_time = (time.perf_counter_ns() - start) / (iterations // 100)

            details["l1_cache_timing_ns"] = int(l1_time)
            details["l2_cache_timing_ns"] = int(l2_time)
            details["memory_timing_ns"] = int(mem_time)

            if l1_time > 0:
                details["timing_ratios"]["l2_to_l1"] = round(l2_time / l1_time, 2)
                details["timing_ratios"]["mem_to_l1"] = round(mem_time / l1_time, 2)

                expected_l2_ratio = 3.0
                expected_mem_ratio = 10.0

                actual_l2_ratio = l2_time / l1_time
                actual_mem_ratio = mem_time / l1_time

                if actual_l2_ratio < (expected_l2_ratio * 0.5) or actual_mem_ratio < (expected_mem_ratio * 0.5):
                    details["anomaly_detected"] = True
                    confidence = 0.55
                    self.logger.info(f"Cache timing anomaly: L2/L1={actual_l2_ratio:.2f}, Mem/L1={actual_mem_ratio:.2f}")
                    return True, confidence, details

        except Exception as e:
            self.logger.debug(f"Cache timing analysis failed: {e}")

        return False, 0.0, details

    def get_hardware_fingerprint(self) -> HardwareFingerprint:
        """Collect comprehensive hardware fingerprint."""
        if self._hardware_fingerprint:
            return self._hardware_fingerprint

        fingerprint = HardwareFingerprint()

        try:
            result = self._execute_cpuid(0)
            if result:
                _, ebx, ecx, edx = result
                vendor_bytes = struct.pack("<III", ebx, edx, ecx)
                fingerprint.cpu_vendor = vendor_bytes.decode("ascii", errors="ignore").rstrip("\x00")

            brand_result = self._check_cpuid_brand_string()
            if brand_result[0]:
                fingerprint.cpu_model = brand_result[2].get("brand_string", "")

            if platform.system() == "Windows":
                try:
                    import wmi
                    c = wmi.WMI()

                    for cs in c.Win32_ComputerSystem():
                        if hasattr(cs, "NumberOfLogicalProcessors"):
                            fingerprint.cpu_cores = int(cs.NumberOfLogicalProcessors)
                        if hasattr(cs, "TotalPhysicalMemory"):
                            fingerprint.total_ram_mb = int(cs.TotalPhysicalMemory) // (1024 * 1024)
                        if hasattr(cs, "Manufacturer"):
                            fingerprint.system_manufacturer = cs.Manufacturer
                        if hasattr(cs, "Model"):
                            fingerprint.system_model = cs.Model

                    disks = list(c.Win32_DiskDrive())
                    fingerprint.disk_count = len(disks)

                    for disk in disks[:5]:
                        if hasattr(disk, "SerialNumber"):
                            serial = disk.SerialNumber.strip()
                            if serial:
                                fingerprint.disk_serials.append(serial)

                    for bios in c.Win32_BIOS():
                        if hasattr(bios, "Manufacturer"):
                            fingerprint.bios_vendor = bios.Manufacturer
                        if hasattr(bios, "SMBIOSBIOSVersion"):
                            fingerprint.bios_version = bios.SMBIOSBIOSVersion
                        break

                    for board in c.Win32_BaseBoard():
                        if hasattr(board, "Manufacturer"):
                            fingerprint.motherboard_manufacturer = board.Manufacturer
                        break

                except ImportError:
                    pass

            mac_result = self._check_mac_address_patterns()
            if mac_result[0]:
                fingerprint.mac_addresses = mac_result[2].get("mac_addresses", [])

            fingerprint_data = (
                f"{fingerprint.cpu_vendor}|{fingerprint.cpu_model}|"
                f"{fingerprint.system_manufacturer}|{fingerprint.system_model}|"
                f"{fingerprint.bios_vendor}|{fingerprint.motherboard_manufacturer}|"
                f"{'|'.join(fingerprint.disk_serials)}|"
                f"{'|'.join(fingerprint.mac_addresses)}"
            )
            fingerprint.fingerprint_hash = hashlib.sha256(fingerprint_data.encode()).hexdigest()

            self._hardware_fingerprint = fingerprint

        except Exception as e:
            self.logger.debug(f"Hardware fingerprint collection failed: {e}")

        return fingerprint

    def analyze_timing_patterns(self) -> dict[str, TimingMeasurement]:
        """Perform comprehensive timing analysis across multiple operations."""
        measurements = {}

        operations = {
            "cpuid_leaf1": lambda: self._execute_cpuid(0x1),
            "cpuid_leaf0": lambda: self._execute_cpuid(0x0),
            "nop_sequence": lambda: None,
        }

        for op_name, op_func in operations.items():
            measurement = TimingMeasurement(operation=op_name)

            try:
                for _ in range(1000):
                    start = time.perf_counter_ns()
                    op_func()
                    end = time.perf_counter_ns()
                    measurement.samples.append(end - start)

                if measurement.samples:
                    measurement.mean = sum(measurement.samples) / len(measurement.samples)
                    measurement.variance = sum((s - measurement.mean) ** 2 for s in measurement.samples) / len(measurement.samples)
                    measurement.std_dev = measurement.variance ** 0.5
                    measurement.min_val = min(measurement.samples)
                    measurement.max_val = max(measurement.samples)

                    if measurement.std_dev > (measurement.mean * 0.5):
                        measurement.anomaly_detected = True
                        measurement.confidence = min(0.75, (measurement.std_dev / measurement.mean) * 0.5)

                measurements[op_name] = measurement

            except Exception as e:
                self.logger.debug(f"Timing measurement for {op_name} failed: {e}")

        self._timing_measurements = measurements
        return measurements

    def _identify_vm_type(self, detections: dict[str, Any]) -> str:
        """Identify the specific VM type based on detections."""
        vm_scores = {}

        # Score each VM type based on detections
        for method, result in detections.items():
            if result["detected"]:
                details_str = str(result["details"]).lower()
                self.logger.debug(f"VM detection method '{method}' found evidence")

                for vm_type in self.vm_signatures:
                    if vm_type in details_str:
                        vm_scores[vm_type] = vm_scores.get(vm_type, 0) + result["confidence"]

        # Return VM type with highest score
        if vm_scores:
            return max(vm_scores, key=vm_scores.get)

        return "unknown"

    def _calculate_evasion_score(self, detections: dict[str, Any]) -> int:
        """Calculate how difficult it is to evade detection."""
        # Methods that are hard to evade
        hard_to_evade = ["cpuid", "hardware_signatures", "hypervisor_brand"]

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
        return [
            "cpuid_timing",
            "rdtsc_timing",
            "rdtsc_vmexit_detection",
            "sleep_timing",
            "instruction_timing",
            "paravirt_instructions",
            "memory_artifacts",
            "tsc_frequency_analysis",
            "cache_timing",
        ]

    def get_detection_type(self) -> str:
        """Get the type of detection this class performs."""
        return "virtual_machine"

    def generate_bypass(self, vm_type: str) -> dict[str, Any]:
        """Generate VM detection bypass.

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
            "risks": [],
        }

        # Identify detection methods used by target
        if vm_type.lower() in self.vm_signatures:
            vm_sig = self.vm_signatures[vm_type.lower()]

            # Determine which detection methods to bypass
            if vm_sig.get("processes"):
                bypass_config["detection_methods"].append("Process detection")
            if vm_sig.get("files"):
                bypass_config["detection_methods"].append("File system artifacts")
            if vm_sig.get("registry"):
                bypass_config["detection_methods"].append("Registry keys")
            if vm_sig.get("hardware"):
                bypass_config["detection_methods"].append("Hardware signatures")
            if vm_sig.get("mac_prefixes"):
                bypass_config["detection_methods"].append("MAC address patterns")

        # Generate bypass techniques based on VM type
        if vm_type.lower() == "vmware":
            bypass_config["stealth_level"] = "high"
            bypass_config["success_probability"] = 0.85
            bypass_config["bypass_techniques"] = [
                {
                    "name": "VMware Tools Hiding",
                    "description": "Hide or rename VMware Tools processes and services",
                    "complexity": "medium",
                    "effectiveness": 0.90,
                },
                {
                    "name": "CPUID Masking",
                    "description": "Mask hypervisor CPUID leaf responses",
                    "complexity": "high",
                    "effectiveness": 0.85,
                },
                {
                    "name": "Hardware ID Spoofing",
                    "description": "Change hardware identifiers to non-VM values",
                    "complexity": "medium",
                    "effectiveness": 0.80,
                },
                {
                    "name": "Driver Hiding",
                    "description": "Hide VMware drivers from enumeration",
                    "complexity": "high",
                    "effectiveness": 0.75,
                },
            ]

        elif vm_type.lower() == "virtualbox":
            bypass_config["stealth_level"] = "high"
            bypass_config["success_probability"] = 0.90
            bypass_config["bypass_techniques"] = [
                {
                    "name": "VBoxGuest Hiding",
                    "description": "Hide VirtualBox Guest Additions",
                    "complexity": "medium",
                    "effectiveness": 0.95,
                },
                {
                    "name": "ACPI Table Modification",
                    "description": "Modify ACPI tables to remove VBox signatures",
                    "complexity": "high",
                    "effectiveness": 0.85,
                },
                {
                    "name": "Device Name Changing",
                    "description": "Change VBox device names in registry",
                    "complexity": "low",
                    "effectiveness": 0.90,
                },
            ]

        elif vm_type.lower() == "hyperv":
            bypass_config["stealth_level"] = "medium"
            bypass_config["success_probability"] = 0.70
            bypass_config["bypass_techniques"] = [
                {
                    "name": "Hyper-V Integration Disabling",
                    "description": "Disable Hyper-V integration services",
                    "complexity": "low",
                    "effectiveness": 0.80,
                },
                {
                    "name": "VMBUS Hiding",
                    "description": "Hide VMBUS driver and devices",
                    "complexity": "high",
                    "effectiveness": 0.70,
                },
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
                    "effectiveness": 0.70,
                },
                {
                    "name": "Timing Attack Mitigation",
                    "description": "Normalize timing to hide VM overhead",
                    "complexity": "medium",
                    "effectiveness": 0.65,
                },
                {
                    "name": "Generic Hardware Spoofing",
                    "description": "Replace VM hardware strings",
                    "complexity": "medium",
                    "effectiveness": 0.60,
                },
            ]

        # Add implementation details
        bypass_config["implementation"]["hook_script"] = self._generate_vm_bypass_script(vm_type)
        bypass_config["implementation"]["registry_modifications"] = self._get_registry_mods(vm_type)
        bypass_config["implementation"]["file_operations"] = self._get_file_operations(vm_type)

        # Add requirements
        bypass_config["requirements"] = [
            "Administrator/root privileges",
            "Ability to modify system files",
            "Runtime hooking capability (Frida/similar)",
        ]

        # Add risks
        bypass_config["risks"] = [
            "System instability if modifications fail",
            "VM vendor updates may break bypass",
            "Some applications may depend on VM tools",
        ]

        return bypass_config

    def _generate_vm_bypass_script(self, vm_type: str) -> str:
        """Generate Frida script for VM detection bypass."""
        if vm_type.lower() == "vmware":
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

    def _get_registry_mods(self, vm_type: str) -> list[dict[str, str]]:
        """Get registry modifications for VM bypass."""
        mods = []

        if vm_type.lower() == "vmware":
            mods.extend(
                [
                    {
                        "action": "delete",
                        "key": r"HKLM\SOFTWARE\VMware, Inc.",
                        "description": "Remove VMware software keys",
                    },
                    {
                        "action": "rename",
                        "key": r"HKLM\SYSTEM\CurrentControlSet\Services\vmtools",
                        "new_name": "svchost_helper",
                        "description": "Rename VMware Tools service",
                    },
                ]
            )
        elif vm_type.lower() == "virtualbox":
            mods.extend(
                [
                    {
                        "action": "delete",
                        "key": r"HKLM\SOFTWARE\Oracle\VirtualBox Guest Additions",
                        "description": "Remove VirtualBox guest additions keys",
                    },
                ]
            )

        return mods

    def _get_file_operations(self, vm_type: str) -> list[dict[str, str]]:
        """Get file operations for VM bypass."""
        ops = []

        if vm_type.lower() == "vmware":
            ops.extend(
                [
                    {
                        "action": "rename",
                        "path": r"C:\Program Files\VMware\VMware Tools\vmtoolsd.exe",
                        "new_name": "svchost32.exe",
                        "description": "Rename VMware Tools daemon",
                    },
                    {
                        "action": "hide",
                        "path": r"C:\Windows\System32\drivers\vmmouse.sys",
                        "description": "Hide VMware mouse driver",
                    },
                ]
            )

        return ops

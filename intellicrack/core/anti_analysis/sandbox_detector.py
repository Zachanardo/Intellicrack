"""Sandbox detection utilities for Intellicrack anti-analysis.

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

import contextlib
import ctypes
import logging
import os
import platform
import shutil
import socket
import subprocess
import tempfile
import time
import uuid
from typing import Any

import psutil

from .base_detector import BaseDetector


"""
Sandbox Detection

Implements techniques to detect analysis sandboxes including
Cuckoo, VMRay, Joe Sandbox, and others.
"""


class SandboxDetector(BaseDetector):
    """Comprehensive sandbox detection using behavioral and environmental checks."""

    def __init__(self) -> None:
        """Initialize the sandbox detector with detection methods and signatures."""
        super().__init__()
        self.logger = logging.getLogger("IntellicrackLogger.SandboxDetector")

        self.detection_methods = {
            "environment_checks": self._check_environment,
            "behavioral_detection": self._check_behavioral,
            "resource_limits": self._check_resource_limits,
            "network_connectivity": self._check_network,
            "user_interaction": self._check_user_interaction,
            "file_system": self._check_file_system_artifacts,
            "process_monitoring": self._check_process_monitoring,
            "time_acceleration": self._check_time_acceleration,
            "api_hooks": self._check_api_hooks,
            "mouse_movement": self._check_mouse_movement,
            "hardware_analysis": self._check_hardware_indicators,
            "registry_analysis": self._check_registry_indicators,
            "virtualization": self._check_virtualization_artifacts,
            "environment_variables": self._check_environment_variables,
            "parent_process_analysis": self._check_parent_process,
            "cpuid_hypervisor_check": self._check_cpuid_hypervisor,
            "mac_address_analysis": self._check_mac_address_artifacts,
            "browser_automation": self._check_browser_automation,
            "timing_attacks": self._check_advanced_timing,
        }

        # Build dynamic sandbox signatures
        self.sandbox_signatures = self._build_dynamic_signatures()

        # Build behavioral patterns dynamically
        self.behavioral_patterns = self._build_behavioral_patterns()

        # Initialize detection cache
        self.detection_cache = {}

        # Perform initial system profiling
        self._profile_system()

    def _build_dynamic_signatures(self) -> dict:
        """Build sandbox signatures dynamically based on system analysis."""
        import json

        signatures = {}

        # Common sandbox products and their dynamic detection
        sandbox_products = {
            "cuckoo": {
                "path_patterns": ["analyzer", "sandbox", "cuckoo", "agent"],
                "process_patterns": ["analyzer", "agent.py", "auxiliary"],
                "network_patterns": ["192.168.56.", "10.0.0."],
                "service_names": ["CuckooAgent", "CuckooMon"],
            },
            "vmray": {
                "path_patterns": ["vmray", "controller", "vragent"],
                "process_patterns": ["vmray_", "vragent", "controller"],
                "registry_keys": ["VMRay", "VRAgent"],
            },
            "joe_sandbox": {
                "path_patterns": ["joe", "joebox", "jbxapi"],
                "process_patterns": ["joebox", "joecontrol", "jbx"],
                "service_names": ["JoeBox", "JoeAgent"],
            },
            "threatgrid": {
                "path_patterns": ["threatgrid", "tgrid", "tg_agent"],
                "process_patterns": ["tgrid", "threatgrid"],
                "network_patterns": ["192.168.2."],
            },
            "hybrid_analysis": {
                "path_patterns": ["falcon", "hybrid", "cwsandbox"],
                "process_patterns": ["falcon", "hybrid", "cws"],
                "registry_keys": ["FalconSandbox", "HybridAnalysis"],
            },
            "sandboxie": {
                "path_patterns": ["sandboxie", "sbie"],
                "process_patterns": ["sbie", "sandboxie"],
                "dll_names": ["sbiedll.dll", "sbieapi.dll"],
            },
            "anubis": {
                "path_patterns": ["anubis", "cwapi"],
                "process_patterns": ["anubis", "cwmonitor"],
            },
            "norman": {
                "path_patterns": ["norman", "nvc"],
                "process_patterns": ["norman", "nvc_"],
            },
            "fortinet": {
                "path_patterns": ["fortinet", "forticlient"],
                "process_patterns": ["fortisandbox", "forticlient"],
            },
            "fireeye": {
                "path_patterns": ["fireeye", "feye"],
                "process_patterns": ["fireeye", "feye_"],
                "network_patterns": ["10.10.10."],
            },
            "hatching_triage": {
                "path_patterns": ["triage", "hatching", "tria"],
                "process_patterns": ["triage", "hatching", "tria_"],
                "registry_keys": ["Hatching", "Triage"],
                "network_patterns": ["192.168.30."],
                "environment_vars": ["TRIAGE_ANALYSIS", "HATCHING_TRIAGE"],
            },
            "intezer": {
                "path_patterns": ["intezer", "analyze", "intz"],
                "process_patterns": ["intezer", "analyze_agent"],
                "registry_keys": ["Intezer"],
                "environment_vars": ["INTEZER_ANALYSIS"],
            },
            "virustotal": {
                "path_patterns": ["vt", "virustotal", "vtotal"],
                "process_patterns": ["vt_agent", "virustotal"],
                "network_patterns": ["10.0.2."],
                "environment_vars": ["VT_SANDBOX", "VIRUSTOTAL_ANALYSIS"],
            },
            "browserstack": {
                "path_patterns": ["browserstack", "bstack"],
                "process_patterns": ["browserstack", "bstack"],
                "environment_vars": ["BROWSERSTACK"],
            },
        }

        # Build signatures for each sandbox
        for sandbox_name, patterns in sandbox_products.items():
            signatures[sandbox_name] = {
                "files": [],
                "processes": [],
                "network": [],
                "artifacts": [],
                "registry": [],
                "services": [],
                "dlls": [],
                "environment_vars": [],
            }

            # Build file paths dynamically
            if "path_patterns" in patterns:
                for pattern in patterns["path_patterns"]:
                    # Check common installation directories
                    common_dirs = self._get_common_directories()
                    for base_dir in common_dirs:
                        # Build potential paths
                        potential_paths = [
                            os.path.join(base_dir, pattern),
                            os.path.join(base_dir, pattern.upper()),
                            os.path.join(base_dir, pattern.capitalize()),
                            os.path.join(base_dir, f".{pattern}"),
                        ]
                        signatures[sandbox_name]["files"].extend(potential_paths)

                        # Also check for pattern in path
                        signatures[sandbox_name]["artifacts"].append(pattern)

            # Add process patterns
            if "process_patterns" in patterns:
                for proc_pattern in patterns["process_patterns"]:
                    # Add various executable extensions
                    signatures[sandbox_name]["processes"].extend(
                        [
                            f"{proc_pattern}.exe",
                            f"{proc_pattern}",
                            f"{proc_pattern}32.exe",
                            f"{proc_pattern}64.exe",
                            f"{proc_pattern}_service.exe",
                            f"{proc_pattern}_agent.exe",
                        ],
                    )

            # Add network patterns
            if "network_patterns" in patterns:
                signatures[sandbox_name]["network"].extend(patterns["network_patterns"])

            # Add registry keys
            if "registry_keys" in patterns:
                for key in patterns["registry_keys"]:
                    signatures[sandbox_name]["registry"].extend(
                        [
                            f"HKLM\\SOFTWARE\\{key}",
                            f"HKLM\\SYSTEM\\CurrentControlSet\\Services\\{key}",
                            f"HKCU\\SOFTWARE\\{key}",
                        ],
                    )

            # Add service names
            if "service_names" in patterns:
                signatures[sandbox_name]["services"].extend(patterns["service_names"])

            # Add DLL names
            if "dll_names" in patterns:
                signatures[sandbox_name]["dlls"].extend(patterns["dll_names"])

            # Add environment variables
            if "environment_vars" in patterns:
                signatures[sandbox_name]["environment_vars"].extend(patterns["environment_vars"])

        # Add virtualization platform indicators
        vm_signatures = self._build_vm_signatures()
        signatures |= vm_signatures

        # Load custom signatures from configuration
        config_path = os.path.join(
            os.path.dirname(__file__), "..", "..", "data", "sandbox_signatures.json"
        )

        with contextlib.suppress(OSError, json.JSONDecodeError):
            if os.path.exists(config_path):
                with open(config_path) as f:
                    custom_sigs = json.load(f)
                    # Merge custom signatures
                    for sandbox_name, sig_data in custom_sigs.items():
                        if sandbox_name not in signatures:
                            signatures[sandbox_name] = sig_data
                        else:
                            for sig_type, sig_values in sig_data.items():
                                if sig_type in signatures[sandbox_name]:
                                    signatures[sandbox_name][sig_type].extend(sig_values)
        return signatures

    def _build_behavioral_patterns(self) -> dict:
        """Build behavioral patterns for sandbox detection."""
        import psutil

        patterns = {}

        # Analyze current system to establish baseline
        try:
            # Count user files in common directories
            user_dirs = [
                os.path.expanduser("~/Documents"),
                os.path.expanduser("~/Desktop"),
                os.path.expanduser("~/Downloads"),
                os.path.expanduser("~/Pictures"),
                os.path.expanduser("~/Videos"),
                os.path.expanduser("~/Music"),
            ]

            total_user_files = 0
            for user_dir in user_dirs:
                if os.path.exists(user_dir):
                    with contextlib.suppress(OSError):
                        # Count files (not recursively for performance)
                        files = os.listdir(user_dir)
                        total_user_files += len(files)
            # Establish minimum based on current system
            # Sandboxes typically have very few user files
            patterns["user_files"] = {
                "paths": user_dirs,
                "min_files": max(10, total_user_files // 10),  # At least 10% of current
                "current_count": total_user_files,
            }

            # Process count analysis
            process_count = len(psutil.pids())
            patterns["processes"] = {
                "min_processes": max(30, process_count // 2),  # At least half of current
                "current_count": process_count,
                "common_processes": self._get_common_processes(),
            }

            # System uptime
            boot_time = psutil.boot_time()
            current_time = psutil.time.time()
            uptime = current_time - boot_time

            patterns["uptime"] = {
                "min_uptime": 600,  # 10 minutes minimum for real systems
                "current_uptime": uptime,
                "suspicious_if_less_than": 300,  # 5 minutes
            }

            # Network connections
            connections = psutil.net_connections()
            patterns["network"] = {
                "min_connections": max(5, len(connections) // 4),
                "current_connections": len(connections),
                "suspicious_ports": [3389, 5900, 5901, 6000],  # RDP, VNC, X11
            }

            # Disk usage patterns
            disk_usage = psutil.disk_usage("/")
            patterns["disk"] = {
                "min_used_percent": 20,  # Real systems use disk space
                "current_used_percent": disk_usage.percent,
                "min_total_gb": 50,  # Minimum disk size for real systems
                "current_total_gb": disk_usage.total / (1024**3),
            }

            # Memory patterns
            mem = psutil.virtual_memory()
            patterns["memory"] = {
                "min_total_gb": 2,  # Minimum RAM for real systems
                "current_total_gb": mem.total / (1024**3),
                "min_used_percent": 30,  # Real systems use memory
                "current_used_percent": mem.percent,
            }

            # CPU patterns
            cpu_count = psutil.cpu_count(logical=True)
            patterns["cpu"] = {
                "min_cores": 2,  # Most modern systems have at least 2 cores
                "current_cores": cpu_count,
                "suspicious_if_exactly": [1, 2],  # VMs often have 1-2 cores
            }

        except Exception as e:
            self.logger.debug(f"Error building behavioral patterns: {e}")
            # Use conservative defaults
            patterns = {
                "user_files": {"paths": user_dirs, "min_files": 10},
                "processes": {"min_processes": 40},
                "uptime": {"min_uptime": 600},
                "network": {"min_connections": 5},
                "disk": {"min_used_percent": 20, "min_total_gb": 50},
                "memory": {"min_total_gb": 2, "min_used_percent": 30},
                "cpu": {"min_cores": 2},
            }

        return patterns

    def _get_common_directories(self) -> list:
        """Get common directories where sandbox artifacts might be found."""
        dirs = []

        # Windows paths
        if platform.system() == "Windows":
            system_drive = os.environ.get("SYSTEMDRIVE", "C:")
            dirs.extend(
                [
                    system_drive + "\\",
                    os.environ.get("PROGRAMFILES", "C:\\Program Files"),
                    os.environ.get("PROGRAMFILES(X86)", "C:\\Program Files (x86)"),
                    os.environ.get("PROGRAMDATA", "C:\\ProgramData"),
                    os.environ.get("APPDATA", ""),
                    os.environ.get("LOCALAPPDATA", ""),
                    os.environ.get("TEMP", tempfile.gettempdir()),
                    os.path.join(system_drive, "Windows"),
                    os.path.join(system_drive, "Windows", "System32"),
                    os.path.join(system_drive, "Windows", "SysWOW64"),
                    os.path.join(system_drive, "Users", "Public"),
                ],
            )
        else:
            # Linux/Unix paths
            dirs.extend(
                [
                    "/",
                    tempfile.gettempdir(),
                    tempfile.gettempdir(),  # Using temp dir instead of hardcoded /var/tmp
                    "/opt",
                    "/usr/local",
                    "/usr/share",
                    "/etc",
                    "/var/lib",
                    "/var/log",
                    os.path.expanduser("~"),
                    os.path.expanduser("~/.local"),
                    os.path.expanduser("~/.config"),
                ],
            )

        # Filter out non-existent or inaccessible directories
        valid_dirs = []
        for d in dirs:
            if d and os.path.exists(d):
                with contextlib.suppress(OSError):
                    # Test if we can list the directory
                    os.listdir(d)
                    valid_dirs.append(d)
        return valid_dirs

    def _build_vm_signatures(self) -> dict:
        """Build virtualization platform signatures."""
        vm_sigs = {
            "vmware": {
                "files": [
                    "C:\\Windows\\System32\\drivers\\vmmouse.sys",
                    "C:\\Windows\\System32\\drivers\\vmhgfs.sys",
                    "C:\\Program Files\\VMware\\VMware Tools",
                    "/usr/bin/vmware-toolbox-cmd",
                    "/etc/vmware-tools",
                ],
                "processes": ["vmtoolsd.exe", "vmwaretray.exe", "vmwareuser.exe"],
                "registry": [
                    "HKLM\\SOFTWARE\\VMware, Inc.",
                    "HKLM\\SYSTEM\\CurrentControlSet\\Services\\VMTools",
                ],
                "artifacts": ["vmware", "vmtools", "vmx"],
            },
            "virtualbox": {
                "files": [
                    "C:\\Windows\\System32\\drivers\\VBoxMouse.sys",
                    "C:\\Windows\\System32\\drivers\\VBoxGuest.sys",
                    "C:\\Program Files\\Oracle\\VirtualBox Guest Additions",
                    "/usr/bin/VBoxClient",
                    "/etc/init.d/vboxadd",
                ],
                "processes": ["VBoxTray.exe", "VBoxService.exe", "VBoxClient"],
                "registry": [
                    "HKLM\\SOFTWARE\\Oracle\\VirtualBox Guest Additions",
                    "HKLM\\SYSTEM\\CurrentControlSet\\Services\\VBoxGuest",
                ],
                "artifacts": ["vbox", "virtualbox", "oracle"],
            },
            "hyperv": {
                "files": [
                    "C:\\Windows\\System32\\drivers\\vmbus.sys",
                    "C:\\Windows\\System32\\drivers\\hypervideo.sys",
                ],
                "processes": ["vmconnect.exe"],
                "registry": [
                    "HKLM\\SOFTWARE\\Microsoft\\Virtual Machine\\Guest",
                    "HKLM\\SYSTEM\\CurrentControlSet\\Services\\vmbus",
                ],
                "artifacts": ["hyperv", "vmbus", "microsoft virtual"],
            },
            "qemu": {
                "files": [
                    "/usr/bin/qemu-ga",
                    "/etc/qemu-ga",
                    "C:\\Program Files\\QEMU-GA",
                ],
                "processes": ["qemu-ga", "qemu-ga.exe"],
                "artifacts": ["qemu", "kvm", "bochs", "seabios"],
            },
            "xen": {
                "files": [
                    "/proc/xen",
                    "/sys/hypervisor/type",
                    "C:\\Program Files\\Xen Tools",
                ],
                "processes": ["xenservice.exe", "xen-detect"],
                "artifacts": ["xen", "xvm", "citrix"],
            },
        }

        # Parallels signatures
        vm_sigs["parallels"] = {
            "files": [
                "C:\\Program Files\\Parallels\\Parallels Tools",
                "/usr/bin/prl_tools",
            ],
            "processes": ["prl_tools.exe", "prl_cc.exe"],
            "registry": ["HKLM\\SOFTWARE\\Parallels"],
            "artifacts": ["parallels", "prl"],
        }

        return vm_sigs

    def _get_common_processes(self) -> list:
        """Get list of common processes for real systems."""
        if platform.system() == "Windows":
            return [
                "explorer.exe",
                "svchost.exe",
                "csrss.exe",
                "winlogon.exe",
                "services.exe",
                "lsass.exe",
                "system",
                "smss.exe",
                "dwm.exe",
                "taskhostw.exe",
                "runtime broker.exe",
                "searchindexer.exe",
                "spoolsv.exe",
                "audiodg.exe",
                # Common user applications
                "chrome.exe",
                "firefox.exe",
                "msedge.exe",
                "opera.exe",
                "outlook.exe",
                "teams.exe",
                "discord.exe",
                "slack.exe",
                "spotify.exe",
                "steam.exe",
                "notepad.exe",
                "code.exe",
            ]
        return [
            "systemd",
            "init",
            "kernel",
            "kthreadd",
            "kworker",
            "systemd-journald",
            "systemd-logind",
            "systemd-resolved",
            "NetworkManager",
            "dbus",
            "polkitd",
            "chronyd",
            # Common user applications
            "chrome",
            "firefox",
            "thunderbird",
            "code",
            "sublime",
            "spotify",
            "discord",
            "slack",
            "telegram",
            "signal",
        ]

    def _profile_system(self) -> None:
        """Profile the current system to establish baseline."""
        import hashlib

        profile = {
            "timestamp": psutil.time.time(),
            "boot_time": psutil.boot_time(),
            "cpu_count": psutil.cpu_count(logical=True),
            "memory_total": psutil.virtual_memory().total,
            "disk_total": psutil.disk_usage("/").total,
            "process_count": len(psutil.pids()),
            "network_interfaces": len(psutil.net_if_addrs()),
            "unique_id": str(uuid.getnode()),  # MAC address as unique ID
        }

        # Create system fingerprint
        fingerprint_data = (
            f"{profile['cpu_count']}:{profile['memory_total']}:{profile['unique_id']}"
        )
        profile["fingerprint"] = hashlib.sha256(fingerprint_data.encode()).hexdigest()

        self.system_profile = profile

        # Check if profile matches known sandbox profiles
        self._check_against_known_profiles()

    def _check_against_known_profiles(self) -> None:
        """Check system profile against known sandbox profiles."""
        if not hasattr(self, "system_profile"):
            return
        mem_gb = self.system_profile["memory_total"] / (1024**3)

        known_sandbox_profiles = {
            "cuckoo_default": {
                "cpu_count": [1, 2],
                "memory_total_gb": [1, 2, 4],
                "network_interfaces": [1, 2],
            },
            "vmray_default": {
                "cpu_count": [2, 4],
                "memory_total_gb": [2, 4, 8],
            },
            "generic_sandbox": {
                "cpu_count": [1, 2],
                "memory_total_gb": [1, 2],
                "process_count_max": 50,
            },
        }

        for sandbox_name, profile in known_sandbox_profiles.items():
            matches = 0
            checks = 0

            if "cpu_count" in profile:
                checks += 1
                if self.system_profile["cpu_count"] in profile["cpu_count"]:
                    matches += 1

            if "memory_total_gb" in profile:
                checks += 1
                if int(mem_gb) in profile["memory_total_gb"]:
                    matches += 1

            if "network_interfaces" in profile:
                checks += 1
                if self.system_profile["network_interfaces"] in profile["network_interfaces"]:
                    matches += 1

            if "process_count_max" in profile:
                checks += 1
                if self.system_profile["process_count"] <= profile["process_count_max"]:
                    matches += 1

            # If more than 75% of checks match, flag as potential sandbox
            if checks > 0 and (matches / checks) > 0.75:
                self.logger.warning(
                    f"System profile matches {sandbox_name}: {matches}/{checks}"
                )
                self.detection_cache[f"profile_{sandbox_name}"] = True

    def _check_hardware_indicators(self) -> dict:
        """Check hardware indicators for sandbox/VM detection."""
        indicators = {"detected": False, "confidence": 0, "details": []}

        try:
            # Check CPU vendor
            import subprocess

            if platform.system() == "Windows":
                try:
                    if wmic_path := shutil.which("wmic"):
                        result = subprocess.run(
                            [wmic_path, "cpu", "get", "name"],
                            capture_output=True,
                            text=True,
                            timeout=5,
                        )
                        cpu_name = result.stdout.lower()
                    else:
                        cpu_name = ""

                    # Check for VM CPU signatures
                    vm_cpu_patterns = ["qemu", "virtual", "vmware", "vbox", "hypervisor"]
                    for pattern in vm_cpu_patterns:
                        if pattern in cpu_name:
                            indicators["detected"] = True
                            indicators["confidence"] += 30
                            indicators["details"].append(f"VM CPU pattern: {pattern}")

                except Exception as e:
                    self.logger.debug(f"Error checking CPU info for VM patterns: {e}")
            else:
                try:
                    with open("/proc/cpuinfo") as f:
                        cpu_info = f.read().lower()

                        if "hypervisor" in cpu_info or "qemu" in cpu_info:
                            indicators["detected"] = True
                            indicators["confidence"] += 30
                            indicators["details"].append("Hypervisor detected in cpuinfo")
                except Exception as e:
                    self.logger.debug(f"Error reading /proc/cpuinfo for hypervisor detection: {e}")

            # Check MAC address patterns
            import uuid

            mac = uuid.getnode()
            mac_str = ":".join([f"{(mac >> i) & 0xFF:02x}" for i in range(0, 48, 8)])

            # Known VM MAC prefixes
            vm_mac_prefixes = [
                "00:05:69",  # VMware
                "00:0c:29",  # VMware
                "00:1c:14",  # VMware
                "00:50:56",  # VMware
                "08:00:27",  # VirtualBox
                "52:54:00",  # QEMU/KVM
                "00:16:3e",  # Xen
                "00:1c:42",  # Parallels
                "00:03:ff",  # Microsoft Hyper-V
            ]

            for prefix in vm_mac_prefixes:
                if mac_str.lower().startswith(prefix.lower()):
                    indicators["detected"] = True
                    indicators["confidence"] += 40
                    indicators["details"].append(f"VM MAC prefix: {prefix}")
                    break

        except Exception as e:
            self.logger.debug(f"Hardware check error: {e}")

        return indicators

    def _check_registry_indicators(self) -> dict:
        """Check Windows registry for sandbox indicators."""
        indicators = {"detected": False, "confidence": 0, "details": []}

        if platform.system() != "Windows":
            return indicators

        try:
            import winreg

            # Registry keys to check
            registry_checks = [
                (winreg.HKEY_LOCAL_MACHINE, r"HARDWARE\ACPI\DSDT\VBOX__"),
                (winreg.HKEY_LOCAL_MACHINE, r"HARDWARE\ACPI\FADT\VBOX__"),
                (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Oracle\VirtualBox Guest Additions"),
                (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\VMware, Inc.\VMware Tools"),
                (winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Services\VBoxGuest"),
                (winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Services\VMTools"),
                (winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Services\vmbus"),
                (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Wine"),
                (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Parallels"),
            ]

            for hkey, path in registry_checks:
                with contextlib.suppress(OSError):
                    key = winreg.OpenKey(hkey, path)
                    winreg.CloseKey(key)
                    indicators["detected"] = True
                    indicators["confidence"] += 50
                    indicators["details"].append(f"Registry key found: {path}")
            # Check for sandbox-specific values
            try:
                key = winreg.OpenKey(
                    winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Control\SystemInformation"
                )
                value, _ = winreg.QueryValueEx(key, "SystemManufacturer")
                winreg.CloseKey(key)

                vm_manufacturers = [
                    "vmware",
                    "virtualbox",
                    "qemu",
                    "xen",
                    "parallels",
                    "microsoft corporation",
                ]
                if any(vm in value.lower() for vm in vm_manufacturers):
                    indicators["detected"] = True
                    indicators["confidence"] += 40
                    indicators["details"].append(f"VM manufacturer: {value}")

            except Exception as e:
                self.logger.debug(f"Error checking VM manufacturer in registry: {e}")

        except Exception as e:
            self.logger.debug(f"Registry check error: {e}")

        return indicators

    def _check_virtualization_artifacts(self) -> dict:
        """Check for virtualization artifacts."""
        artifacts = {"detected": False, "confidence": 0, "details": []}

        # Check loaded drivers/modules
        if platform.system() == "Windows":
            try:
                import subprocess

                if driverquery_path := shutil.which("driverquery"):
                    result = subprocess.run(
                        [driverquery_path, "/v"], capture_output=True, text=True, timeout=5
                    )
                    drivers = result.stdout.lower()
                else:
                    drivers = ""

                vm_drivers = [
                    "vboxdrv",
                    "vboxguest",
                    "vmci",
                    "vmhgfs",
                    "vmmouse",
                    "vmrawdsk",
                    "vmusbmouse",
                    "vmx86",
                    "vmware",
                ]

                for driver in vm_drivers:
                    if driver in drivers:
                        artifacts["detected"] = True
                        artifacts["confidence"] += 30
                        artifacts["details"].append(f"VM driver: {driver}")

            except Exception as e:
                self.logger.debug(f"Error checking for VM drivers: {e}")
        else:
            # Check loaded kernel modules on Linux
            try:
                with open("/proc/modules") as f:
                    modules = f.read().lower()

                    vm_modules = [
                        "vboxguest",
                        "vboxsf",
                        "vmw_balloon",
                        "vmxnet",
                        "virtio",
                        "xen",
                        "kvm",
                        "hyperv",
                    ]

                    for module in vm_modules:
                        if module in modules:
                            artifacts["detected"] = True
                            artifacts["confidence"] += 30
                            artifacts["details"].append(f"VM module: {module}")

            except Exception as e:
                self.logger.debug(f"Error checking for VM modules: {e}")

        # Check DMI/SMBIOS information
        try:
            if platform.system() == "Linux":
                import subprocess

                if dmidecode_path := shutil.which("dmidecode"):
                    result = subprocess.run(
                        [dmidecode_path, "-t", "system"], capture_output=True, text=True, timeout=5
                    )
                    dmi_info = result.stdout.lower() if result.returncode == 0 else ""
                else:
                    dmi_info = ""
                    vm_indicators = ["vmware", "virtualbox", "qemu", "kvm", "xen", "parallels"]

                    for indicator in vm_indicators:
                        if indicator in dmi_info:
                            artifacts["detected"] = True
                            artifacts["confidence"] += 50
                            artifacts["details"].append(f"DMI indicator: {indicator}")
                            break
        except Exception as e:
            self.logger.debug(f"Error checking DMI/SMBIOS information: {e}")

        return artifacts

    def detect_sandbox(self, aggressive: bool = False) -> dict[str, Any]:
        """Perform sandbox detection using multiple techniques.

        Args:
            aggressive: Use aggressive detection that might affect analysis

        Returns:
            Detection results with confidence scores

        """
        results = {
            "is_sandbox": False,
            "confidence": 0.0,
            "sandbox_type": None,
            "detections": {},
            "evasion_difficulty": 0,
        }

        try:
            self.logger.info("Starting sandbox detection...")

            # Run detection methods using base class functionality
            detection_results = self.run_detection_loop(aggressive, self.get_aggressive_methods())

            # Merge results
            results |= detection_results

            # Calculate overall results
            if detection_results["detection_count"] > 0:
                results["is_sandbox"] = True
                results["confidence"] = min(1.0, detection_results["average_confidence"])
                results["sandbox_type"] = self._identify_sandbox_type(results["detections"])

            # Calculate evasion difficulty
            results["evasion_difficulty"] = self._calculate_evasion_difficulty(
                results["detections"]
            )

            self.logger.info(
                f"Sandbox detection complete: {results['is_sandbox']} (confidence: {results['confidence']:.2f})"
            )
            return results

        except Exception as e:
            self.logger.error(f"Sandbox detection failed: {e}")
            return results

    def _check_environment(self) -> tuple[bool, float, dict]:
        """Check for sandbox-specific environment variables and settings."""
        details = {"suspicious_env": [], "username": None, "computername": None}

        try:
            # Check username
            username = os.environ.get("USERNAME", os.environ.get("USER", "")).lower()
            details["username"] = username

            suspicious_users = [
                "sandbox",
                "cracked",
                "virus",
                "maltest",
                "test",
                "john",
                "user",
                "analyst",
                "analysis",
            ]
            if any(user in username for user in suspicious_users):
                details["suspicious_env"].append(f"username: {username}")

            # Check computer name
            computername = os.environ.get("COMPUTERNAME", socket.gethostname()).lower()
            details["computername"] = computername

            if suspicious_computers_env := os.environ.get(
                "SANDBOX_SUSPICIOUS_COMPUTERS", ""
            ):
                suspicious_computers = [
                    name.strip().lower() for name in suspicious_computers_env.split(",")
                ]
            else:
                suspicious_computers = [
                    "sandbox",
                    "cracked",
                    "virus",
                    "test",
                    "vmware",
                    "virtualbox",
                    "qemu",
                    "analysis",
                ]
            if any(comp in computername for comp in suspicious_computers):
                details["suspicious_env"].append(f"computername: {computername}")

            # Check for sandbox-specific environment variables
            sandbox_env_vars = [
                "CUCKOO",
                "CUCKOO_ROOT",
                "CUCKOO_ANALYSIS",
                "VMRAY",
                "VMRAY_ANALYSIS",
                "JOEBOX",
                "JOESANDBOX",
                "SANDBOX",
                "SANDBOXIE",
            ]

            for var in sandbox_env_vars:
                if var in os.environ:
                    details["suspicious_env"].append(f"env: {var}")

            if details["suspicious_env"]:
                confidence = min(0.9, len(details["suspicious_env"]) * 0.3)
                return True, confidence, details

        except Exception as e:
            self.logger.debug(f"Environment check failed: {e}")

        return False, 0.0, details

    def _check_behavioral(self) -> tuple[bool, float, dict]:
        """Check for behavioral indicators of sandbox environment."""
        details = {"anomalies": []}

        try:
            # Check user files
            user_file_count = 0
            for path in self.behavioral_patterns["no_user_files"]["paths"]:
                if os.path.exists(path):
                    try:
                        files = os.listdir(path)
                        user_file_count += len(files)
                    except Exception as e:
                        self.logger.debug(f"Error accessing {path}: {e}")

            if user_file_count < self.behavioral_patterns["no_user_files"]["min_files"]:
                details["anomalies"].append(f"Few user files: {user_file_count}")

            # Check process count
            if platform.system() == "Windows":
                result = subprocess.run(["tasklist"], check=False, capture_output=True, text=True)  # nosec S607 - Legitimate subprocess usage for security research and binary analysis
                process_count = len(result.stdout.strip().split("\n")) - 3  # Header lines
            else:
                result = subprocess.run(["ps", "aux"], check=False, capture_output=True, text=True)  # nosec S607 - Legitimate subprocess usage for security research and binary analysis
                process_count = len(result.stdout.strip().split("\n")) - 1  # Header line

            if process_count < self.behavioral_patterns["limited_processes"]["min_processes"]:
                details["anomalies"].append(f"Few processes: {process_count}")

            # Check system uptime
            uptime = self._get_system_uptime()
            if uptime and uptime < self.behavioral_patterns["fast_boot"]["max_uptime"]:
                details["anomalies"].append(f"Low uptime: {uptime}s")

            if details["anomalies"]:
                confidence = min(0.8, len(details["anomalies"]) * 0.25)
                return True, confidence, details

        except Exception as e:
            self.logger.debug(f"Behavioral check failed: {e}")

        return False, 0.0, details

    def _check_resource_limits(self) -> tuple[bool, float, dict]:
        """Check for resource limitations typical of sandboxes."""
        details = {"limitations": []}

        try:
            # Check CPU cores
            cpu_count = os.cpu_count()
            if cpu_count and cpu_count <= 2:
                details["limitations"].append(f"Low CPU count: {cpu_count}")

            # Check memory
            if platform.system() == "Windows":
                try:
                    from intellicrack.handlers.psutil_handler import psutil

                    mem = psutil.virtual_memory()
                    total_gb = mem.total / (1024**3)
                    if total_gb < 4:
                        details["limitations"].append(f"Low memory: {total_gb:.1f}GB")
                except ImportError as e:
                    self.logger.error("Import error in sandbox_detector: %s", e)
            else:
                try:
                    with open("/proc/meminfo") as f:
                        for line in f:
                            if line.startswith("MemTotal:"):
                                total_kb = int(line.split()[1])
                                total_gb = total_kb / (1024**2)
                                if total_gb < 4:
                                    details["limitations"].append(f"Low memory: {total_gb:.1f}GB")
                                break
                except Exception as e:
                    self.logger.debug(f"Error reading memory info: {e}")

            # Check disk space
            if platform.system() == "Windows":
                free_bytes = ctypes.c_ulonglong(0)
                total_bytes = ctypes.c_ulonglong(0)
                ctypes.windll.kernel32.GetDiskFreeSpaceExW(
                    "C:\\",
                    ctypes.byref(free_bytes),
                    ctypes.byref(total_bytes),
                    None,
                )
                total_gb = total_bytes.value / (1024**3)
                if total_gb < 60:
                    details["limitations"].append(f"Small disk: {total_gb:.1f}GB")
            elif hasattr(os, "statvfs"):
                stat = os.statvfs("/")
                total_gb = (stat.f_blocks * stat.f_frsize) / (1024**3)
                if total_gb < 60:
                    details["limitations"].append(f"Small disk: {total_gb:.1f}GB")

            if details["limitations"]:
                confidence = min(0.7, len(details["limitations"]) * 0.25)
                return True, confidence, details

        except Exception as e:
            self.logger.debug(f"Resource limits check failed: {e}")

        return False, 0.0, details

    def _check_network(self) -> tuple[bool, float, dict]:
        """Check network connectivity and configuration."""
        details = {"network_anomalies": [], "connections": 0}

        try:
            # Check network connections
            if platform.system() == "Windows":
                result = (
                    subprocess.run(  # nosec S603 - Legitimate subprocess usage for security research and binary analysis
                        [netstat_path, "-an"],
                        check=False,
                        capture_output=True,
                        text=True,
                        shell=False,  # Explicitly secure - using list format prevents shell injection
                    )
                    if (netstat_path := shutil.which("netstat"))
                    else None
                )
            elif ss_path := shutil.which("ss"):
                result = subprocess.run(  # nosec S603 - Legitimate subprocess usage for security research and binary analysis
                    [ss_path, "-an"],
                    check=False,
                    capture_output=True,
                    text=True,
                    shell=False,  # Explicitly secure - using list format prevents shell injection
                )
            else:
                result = None

            if result and result.stdout:
                connections = len(
                    [line for line in result.stdout.split("\n") if "ESTABLISHED" in line]
                )
                details["connections"] = connections
            else:
                details["connections"] = 0

            if connections < self.behavioral_patterns["limited_network"]["min_connections"]:
                details["network_anomalies"].append(f"Few connections: {connections}")

            # Check for sandbox networks
            try:
                hostname = socket.gethostname()
                local_ip = socket.gethostbyname(hostname)

                for sandbox_type, sigs in self.sandbox_signatures.items():
                    for network in sigs.get("network", []):
                        if self._ip_in_network(local_ip, network):
                            details["network_anomalies"].append(
                                f"Sandbox network: {network} ({sandbox_type})"
                            )

            except Exception as e:
                self.logger.debug(f"Error checking network configuration: {e}")

            # Check DNS resolution
            try:
                # Try to resolve common domains
                test_domains = ["google.com", "microsoft.com", "amazon.com"]
                resolved = 0

                for domain in test_domains:
                    try:
                        socket.gethostbyname(domain)
                        resolved += 1
                    except Exception as e:
                        self.logger.debug(f"DNS resolution failed for {domain}: {e}")

                if resolved == 0:
                    details["network_anomalies"].append("No DNS resolution")

            except Exception as e:
                self.logger.debug(f"Error in DNS resolution test: {e}")

            if details["network_anomalies"]:
                confidence = min(0.8, len(details["network_anomalies"]) * 0.3)
                return True, confidence, details

        except Exception as e:
            self.logger.debug(f"Network check failed: {e}")

        return False, 0.0, details

    def _check_user_interaction(self) -> tuple[bool, float, dict]:
        """Check for signs of user interaction."""
        details = {"interaction_signs": []}

        try:
            # Check recently used files (Windows)
            if platform.system() == "Windows":
                recent_path = os.path.join(os.environ["APPDATA"], "Microsoft\\Windows\\Recent")
                if os.path.exists(recent_path):
                    recent_files = os.listdir(recent_path)
                    if len(recent_files) < 5:
                        details["interaction_signs"].append(
                            f"Few recent files: {len(recent_files)}"
                        )

            # Check browser history/cookies
            browser_paths = {
                "chrome": os.path.join(
                    os.environ.get("LOCALAPPDATA", ""),
                    "Google\\Chrome\\User Data\\Default\\History",
                ),
                "firefox": os.path.join(
                    os.environ.get("APPDATA", ""), "Mozilla\\Firefox\\Profiles"
                ),
            }

            browser_found = False
            found_browsers = []
            for browser, path in browser_paths.items():
                if os.path.exists(path):
                    browser_found = True
                    found_browsers.append(browser)

            if not browser_found:
                details["interaction_signs"].append("No browser data found")
            else:
                details["found_browsers"] = found_browsers

            # Check for running user applications
            user_apps = [
                "chrome.exe",
                "firefox.exe",
                "outlook.exe",
                "spotify.exe",
                "discord.exe",
                "slack.exe",
            ]

            if platform.system() == "Windows":
                result = subprocess.run(["tasklist"], check=False, capture_output=True, text=True)  # nosec S607 - Legitimate subprocess usage for security research and binary analysis
                processes = result.stdout.lower()

                running_apps = [app for app in user_apps if app in processes]
                if not running_apps:
                    details["interaction_signs"].append("No user applications running")

            if details["interaction_signs"]:
                confidence = min(0.7, len(details["interaction_signs"]) * 0.25)
                return True, confidence, details

        except Exception as e:
            self.logger.debug(f"User interaction check failed: {e}")

        return False, 0.0, details

    def _check_file_system_artifacts(self) -> tuple[bool, float, dict]:
        """Check for sandbox-specific files and directories."""
        details = {"artifacts_found": []}

        try:
            # Check for sandbox files
            for sandbox_type, sigs in self.sandbox_signatures.items():
                for file_path in sigs.get("files", []):
                    if os.path.exists(file_path):
                        details["artifacts_found"].append(f"{sandbox_type}: {file_path}")

            # Check for analysis artifacts
            suspicious_paths = [
                os.path.join(os.environ.get("SYSTEMDRIVE", "C:"), "analysis"),
                os.path.join(os.environ.get("SYSTEMDRIVE", "C:"), "analyzer"),
                os.path.join(os.environ.get("SYSTEMDRIVE", "C:"), "sandbox"),
                os.path.join(os.environ.get("SYSTEMDRIVE", "C:"), "analysis"),
                "/tmp/analysis/",  # noqa: S108 - Hardcoded path required for sandbox signature detection
                "/tmp/cuckoo/",  # noqa: S108 - Hardcoded path required for sandbox signature detection
                "/opt/sandbox/",
            ]

            for path in suspicious_paths:
                if os.path.exists(path):
                    details["artifacts_found"].append(f"Suspicious path: {path}")

            # Check for monitoring tools
            monitoring_files = [
                "C:\\\\Windows\\\\System32\\\\drivers\\\\monitor.sys",
                "C:\\\\Windows\\\\System32\\\\api_monitor.dll",
                "C:\\\\hook.dll",
                "C:\\\\inject.dll",
            ]

            for file_path in monitoring_files:
                if os.path.exists(file_path):
                    details["artifacts_found"].append(f"Monitoring file: {file_path}")

            if details["artifacts_found"]:
                confidence = min(0.9, len(details["artifacts_found"]) * 0.3)
                return True, confidence, details

        except Exception as e:
            self.logger.debug(f"File system check failed: {e}")

        return False, 0.0, details

    def _check_process_monitoring(self) -> tuple[bool, float, dict]:
        """Check for process monitoring and injection."""
        details = {"monitoring_signs": []}

        try:
            # Check for monitoring processes
            monitoring_processes = [
                "procmon.exe",
                "procexp.exe",
                "apimonitor.exe",
                "wireshark.exe",
                "tcpdump",
                "strace",
                "ltrace",
                "sysmon.exe",
                "autoruns.exe",
            ]

            # Use base class method to get process list
            processes, process_list = self.get_running_processes()

            for monitor in monitoring_processes:
                if monitor.lower() in processes:
                    details["monitoring_signs"].append(f"Monitoring process: {monitor}")

            # Check for injected DLLs (Windows)
            if platform.system() == "Windows":
                try:
                    # Check for sandbox monitoring processes
                    sandbox_processes = [
                        "procmon",
                        "dbgview",
                        "filemon",
                        "regmon",
                        "wireshark",
                        "tcpdump",
                        "netmon",
                        "apimonitor",
                    ]

                    for proc in sandbox_processes:
                        if proc in processes or any(proc in p for p in process_list):
                            details["monitoring_signs"].append(f"Monitor process: {proc}")

                    # Check current process for suspicious DLLs
                    from intellicrack.handlers.psutil_handler import psutil

                    current_proc = psutil.Process()

                    suspicious_dlls = ["hook", "inject", "monitor", "sandbox", "api"]

                    for dll in current_proc.memory_maps():
                        dll_name = os.path.basename(dll.path).lower()
                        if any(susp in dll_name for susp in suspicious_dlls):
                            details["monitoring_signs"].append(f"Suspicious DLL: {dll_name}")

                except Exception as e:
                    self.logger.debug(f"Error checking loaded DLLs: {e}")

            if details["monitoring_signs"]:
                confidence = min(0.8, len(details["monitoring_signs"]) * 0.3)
                return True, confidence, details

        except Exception as e:
            self.logger.debug(f"Process monitoring check failed: {e}")

        return False, 0.0, details

    def _check_time_acceleration(self) -> tuple[bool, float, dict]:
        """Check for time acceleration using RDTSC instruction."""
        details = {"time_anomaly": False, "rdtsc_drift": 0, "qpc_drift": 0}

        try:
            if platform.system() == "Windows":
                import ctypes

                kernel32 = ctypes.windll.kernel32

                code = bytes(
                    [
                        0x0F,
                        0x31,
                        0x48,
                        0xC1,
                        0xE2,
                        0x20,
                        0x48,
                        0x09,
                        0xD0,
                        0x48,
                        0x89,
                        0x01,
                        0x48,
                        0x8B,
                        0x02,
                        0x48,
                        0x85,
                        0xC0,
                        0x74,
                        0x0E,
                        0x48,
                        0x8D,
                        0x0C,
                        0x00,
                        0x48,
                        0xFF,
                        0xC9,
                        0x75,
                        0xFE,
                        0x90,
                        0x0F,
                        0x31,
                        0x48,
                        0xC1,
                        0xE2,
                        0x20,
                        0x48,
                        0x09,
                        0xD0,
                        0x48,
                        0x2B,
                        0x01,
                        0xC3,
                    ]
                )

                buf = ctypes.create_string_buffer(code)
                exec_mem = kernel32.VirtualAlloc(
                    None,
                    len(code),
                    0x1000 | 0x2000,
                    0x04,
                )

                if not exec_mem:
                    return False, 0.0, details

                try:
                    ctypes.memmove(exec_mem, buf, len(code))

                    old_protect = ctypes.c_ulong()
                    if not kernel32.VirtualProtect(
                        exec_mem,
                        len(code),
                        0x20,
                        ctypes.byref(old_protect),
                    ):
                        return False, 0.0, details

                    func = ctypes.CFUNCTYPE(
                        ctypes.c_uint64,
                        ctypes.POINTER(ctypes.c_uint64),
                        ctypes.POINTER(ctypes.c_uint64),
                    )(exec_mem)

                    tsc_storage = ctypes.c_uint64(0)
                    loop_count = ctypes.c_uint64(1000000)

                    deltas_rdtsc = []
                    for _ in range(100):
                        delta = func(ctypes.byref(tsc_storage), ctypes.byref(loop_count))
                        if 0 < delta < 100000000:
                            deltas_rdtsc.append(delta)

                    if not deltas_rdtsc:
                        return False, 0.0, details

                    avg_rdtsc = sum(deltas_rdtsc) / len(deltas_rdtsc)
                    variance_rdtsc = sum((d - avg_rdtsc) ** 2 for d in deltas_rdtsc) / len(
                        deltas_rdtsc
                    )
                    std_dev_rdtsc = variance_rdtsc**0.5

                    QueryPerformanceFrequency = kernel32.QueryPerformanceFrequency
                    QueryPerformanceFrequency.argtypes = [ctypes.POINTER(ctypes.c_int64)]
                    QueryPerformanceFrequency.restype = ctypes.c_bool

                    QueryPerformanceCounter = kernel32.QueryPerformanceCounter
                    QueryPerformanceCounter.argtypes = [ctypes.POINTER(ctypes.c_int64)]
                    QueryPerformanceCounter.restype = ctypes.c_bool

                    freq = ctypes.c_int64()
                    if not QueryPerformanceFrequency(ctypes.byref(freq)):
                        return False, 0.0, details

                    deltas_qpc = []
                    for _ in range(100):
                        start_qpc = ctypes.c_int64()
                        end_qpc = ctypes.c_int64()

                        QueryPerformanceCounter(ctypes.byref(start_qpc))
                        QueryPerformanceCounter(ctypes.byref(end_qpc))

                        delta_qpc = end_qpc.value - start_qpc.value
                        if delta_qpc > 0:
                            deltas_qpc.append(delta_qpc)

                    if not deltas_qpc:
                        return False, 0.0, details

                    avg_qpc = sum(deltas_qpc) / len(deltas_qpc)
                    variance_qpc = sum((d - avg_qpc) ** 2 for d in deltas_qpc) / len(deltas_qpc)
                    std_dev_qpc = variance_qpc**0.5

                    ratio = std_dev_rdtsc / avg_rdtsc if avg_rdtsc > 0 else 0
                    qpc_ratio = std_dev_qpc / avg_qpc if avg_qpc > 0 else 0

                    details["rdtsc_drift"] = ratio
                    details["qpc_drift"] = qpc_ratio
                    details["rdtsc_avg"] = avg_rdtsc
                    details["qpc_avg"] = avg_qpc

                    if ratio > 0.5 or qpc_ratio > 0.3:
                        details["time_anomaly"] = True
                        return True, 0.8, details

                    if std_dev_rdtsc > avg_rdtsc * 2:
                        details["time_anomaly"] = True
                        return True, 0.7, details

                finally:
                    kernel32.VirtualFree(exec_mem, 0, 0x8000)

            elif platform.system() == "Linux":
                import mmap

                code = bytes(
                    [
                        0x0F,
                        0x31,
                        0x48,
                        0xC1,
                        0xE2,
                        0x20,
                        0x48,
                        0x09,
                        0xD0,
                        0x48,
                        0x89,
                        0x07,
                        0x48,
                        0x85,
                        0xF6,
                        0x74,
                        0x09,
                        0x48,
                        0xFF,
                        0xCE,
                        0x75,
                        0xFB,
                        0x90,
                        0x0F,
                        0x31,
                        0x48,
                        0xC1,
                        0xE2,
                        0x20,
                        0x48,
                        0x09,
                        0xD0,
                        0x48,
                        0x2B,
                        0x07,
                        0xC3,
                    ]
                )

                exec_mem = mmap.mmap(
                    -1,
                    len(code),
                    mmap.MAP_PRIVATE | mmap.MAP_ANONYMOUS,
                    mmap.PROT_READ | mmap.PROT_WRITE | mmap.PROT_EXEC,
                )
                exec_mem.write(code)

                exec_addr = ctypes.addressof(ctypes.c_char.from_buffer(exec_mem))
                func = ctypes.CFUNCTYPE(
                    ctypes.c_uint64, ctypes.POINTER(ctypes.c_uint64), ctypes.c_uint64
                )(exec_addr)

                tsc_storage = ctypes.c_uint64(0)

                deltas = []
                for _ in range(100):
                    delta = func(ctypes.byref(tsc_storage), 1000000)
                    if 0 < delta < 100000000:
                        deltas.append(delta)

                if deltas:
                    avg = sum(deltas) / len(deltas)
                    variance = sum((d - avg) ** 2 for d in deltas) / len(deltas)
                    std_dev = variance**0.5

                    ratio = std_dev / avg if avg > 0 else 0
                    details["rdtsc_drift"] = ratio

                    if ratio > 0.5 or std_dev > avg * 2:
                        details["time_anomaly"] = True
                        return True, 0.7, details

                exec_mem.close()

        except Exception as e:
            self.logger.debug(f"Time acceleration check failed: {e}")

        return False, 0.0, details

    def _check_api_hooks(self) -> tuple[bool, float, dict]:
        """Check for API hooking commonly used by sandboxes."""
        details = {"hooked_apis": []}

        try:
            if platform.system() == "Windows":
                # Check common hooked APIs
                apis_to_check = [
                    ("kernel32.dll", "CreateFileW"),
                    ("kernel32.dll", "WriteFile"),
                    ("kernel32.dll", "ReadFile"),
                    ("ws2_32.dll", "send"),
                    ("ws2_32.dll", "recv"),
                    ("ntdll.dll", "NtCreateFile"),
                    ("ntdll.dll", "NtOpenProcess"),
                ]

                kernel32 = ctypes.windll.kernel32

                for dll_name, api_name in apis_to_check:
                    try:
                        dll = ctypes.windll.LoadLibrary(dll_name)
                        if api_addr := kernel32.GetProcAddress(
                            dll._handle, api_name.encode()
                        ):
                            # Read first bytes of API
                            first_byte = ctypes.c_ubyte.from_address(api_addr).value

                            # Check for common hook patterns
                            if first_byte in {233, 104}:  # JMP
                                details["hooked_apis"].append(f"{dll_name}!{api_name}")

                    except Exception as e:
                        self.logger.debug(f"Error checking API hook for {dll_name}!{api_name}: {e}")

            if details["hooked_apis"]:
                confidence = min(0.8, len(details["hooked_apis"]) * 0.15)
                return True, confidence, details

        except Exception as e:
            self.logger.debug(f"API hook check failed: {e}")

        return False, 0.0, details

    def _check_mouse_movement(self) -> tuple[bool, float, dict]:
        """Check for human-like mouse movement."""
        details = {"mouse_active": False, "movement_count": 0}

        try:
            if platform.system() == "Windows":
                try:
                    from ctypes import wintypes

                    # Ensure all required Windows API structures are available
                    if not hasattr(wintypes, "POINT"):
                        # Real POINT structure implementation
                        class POINT(ctypes.Structure):
                            """Real Windows API POINT structure."""

                            _fields_ = [("x", ctypes.c_long), ("y", ctypes.c_long)]

                            def __repr__(self) -> str:
                                return f"POINT(x={self.x}, y={self.y})"

                        wintypes.POINT = POINT

                except (ImportError, AttributeError) as e:
                    self.logger.warning(
                        "Windows API not available, implementing comprehensive Windows API wrapper: %s",
                        e,
                    )

                    # Real Windows API implementation for cross-platform compatibility
                    class _IntellicrackWindowsAPI:
                        """Production Windows API implementation for Intellicrack."""

                        class POINT(ctypes.Structure):
                            """Real Windows API POINT structure with full functionality."""

                            _fields_ = [("x", ctypes.c_long), ("y", ctypes.c_long)]

                            def __init__(self, x: int = 0, y: int = 0) -> None:
                                super().__init__()
                                self.x = x
                                self.y = y

                            def __repr__(self) -> str:
                                return f"POINT(x={self.x}, y={self.y})"

                            def __eq__(self, other: object) -> bool:
                                return (
                                    isinstance(other, self.__class__)
                                    and self.x == other.x
                                    and self.y == other.y
                                )

                            def __hash__(self) -> int:
                                return hash((self.x, self.y))

                            def distance_to(self, other: "POINT") -> float:
                                """Calculate distance to another point."""
                                return ((self.x - other.x) ** 2 + (self.y - other.y) ** 2) ** 0.5

                        class RECT(ctypes.Structure):
                            """Real Windows API RECT structure."""

                            _fields_ = [
                                ("left", ctypes.c_long),
                                ("top", ctypes.c_long),
                                ("right", ctypes.c_long),
                                ("bottom", ctypes.c_long),
                            ]

                            def __repr__(self) -> str:
                                return f"RECT(left={self.left}, top={self.top}, right={self.right}, bottom={self.bottom})"

                            @property
                            def width(self) -> int:
                                return self.right - self.left

                            @property
                            def height(self) -> int:
                                return self.bottom - self.top

                        class SYSTEMTIME(ctypes.Structure):
                            """Real Windows API SYSTEMTIME structure."""

                            _fields_ = [
                                ("wYear", ctypes.c_uint16),
                                ("wMonth", ctypes.c_uint16),
                                ("wDayOfWeek", ctypes.c_uint16),
                                ("wDay", ctypes.c_uint16),
                                ("wHour", ctypes.c_uint16),
                                ("wMinute", ctypes.c_uint16),
                                ("wSecond", ctypes.c_uint16),
                                ("wMilliseconds", ctypes.c_uint16),
                            ]

                        class MEMORYSTATUSEX(ctypes.Structure):
                            """Real Windows API MEMORYSTATUSEX structure."""

                            _fields_ = [
                                ("dwLength", ctypes.c_uint32),
                                ("dwMemoryLoad", ctypes.c_uint32),
                                ("ullTotalPhys", ctypes.c_uint64),
                                ("ullAvailPhys", ctypes.c_uint64),
                                ("ullTotalPageFile", ctypes.c_uint64),
                                ("ullAvailPageFile", ctypes.c_uint64),
                                ("ullTotalVirtual", ctypes.c_uint64),
                                ("ullAvailVirtual", ctypes.c_uint64),
                                ("ullAvailExtendedVirtual", ctypes.c_uint64),
                            ]

                            def __init__(self) -> None:
                                super().__init__()
                                self.dwLength = ctypes.sizeof(self)

                        class OSVERSIONINFOEX(ctypes.Structure):
                            """Real Windows API OSVERSIONINFOEX structure."""

                            _fields_ = [
                                ("dwOSVersionInfoSize", ctypes.c_uint32),
                                ("dwMajorVersion", ctypes.c_uint32),
                                ("dwMinorVersion", ctypes.c_uint32),
                                ("dwBuildNumber", ctypes.c_uint32),
                                ("dwPlatformId", ctypes.c_uint32),
                                ("szCSDVersion", ctypes.c_char * 128),
                                ("wServicePackMajor", ctypes.c_uint16),
                                ("wServicePackMinor", ctypes.c_uint16),
                                ("wSuiteMask", ctypes.c_uint16),
                                ("wProductType", ctypes.c_uint8),
                                ("wReserved", ctypes.c_uint8),
                            ]

                            def __init__(self) -> None:
                                super().__init__()
                                self.dwOSVersionInfoSize = ctypes.sizeof(self)

                    wintypes = _IntellicrackWindowsAPI()

                user32 = ctypes.windll.user32

                positions = []
                timestamps = []
                click_states = []

                GetCursorPos = user32.GetCursorPos
                GetCursorPos.argtypes = [ctypes.POINTER(wintypes.POINT)]
                GetCursorPos.restype = ctypes.c_bool

                GetAsyncKeyState = user32.GetAsyncKeyState
                GetAsyncKeyState.argtypes = [ctypes.c_int]
                GetAsyncKeyState.restype = ctypes.c_short

                VK_LBUTTON = 0x01
                VK_RBUTTON = 0x02

                for _ in range(20):
                    point = wintypes.POINT()
                    GetCursorPos(ctypes.byref(point))
                    positions.append((point.x, point.y))
                    timestamps.append(time.perf_counter())

                    lbutton = GetAsyncKeyState(VK_LBUTTON) & 0x8000
                    rbutton = GetAsyncKeyState(VK_RBUTTON) & 0x8000
                    click_states.append((bool(lbutton), bool(rbutton)))

                    time.sleep(0.05)

                if len(set(positions)) < 2:
                    return True, 0.7, details

                movements = []
                for i in range(1, len(positions)):
                    dx = positions[i][0] - positions[i - 1][0]
                    dy = positions[i][1] - positions[i - 1][1]
                    distance = (dx * dx + dy * dy) ** 0.5
                    time_delta = timestamps[i] - timestamps[i - 1]

                    if distance > 0:
                        movements.append(
                            {
                                "distance": distance,
                                "time_delta": time_delta,
                                "velocity": distance / time_delta if time_delta > 0 else 0,
                                "dx": dx,
                                "dy": dy,
                            }
                        )

                if not movements:
                    return True, 0.7, details

                velocities = [m["velocity"] for m in movements]
                avg_velocity = sum(velocities) / len(velocities) if velocities else 0
                velocity_variance = (
                    sum((v - avg_velocity) ** 2 for v in velocities) / len(velocities)
                    if velocities
                    else 0
                )

                if velocity_variance < 10:
                    details["suspicious_pattern"] = "constant_velocity"
                    return True, 0.6, details

                direction_changes = sum(bool(
                                                            movements[i]["dx"] * movements[i - 1]["dx"] < 0
                                                            or movements[i]["dy"] * movements[i - 1]["dy"] < 0
                                                        )
                                    for i in range(1, len(movements)))
                if direction_changes == 0 and len(movements) > 5:
                    details["suspicious_pattern"] = "perfectly_linear"
                    return True, 0.7, details

                distances = [m["distance"] for m in movements]
                if all(abs(d - distances[0]) < 1.0 for d in distances):
                    details["suspicious_pattern"] = "identical_distances"
                    return True, 0.8, details

                click_count = sum(bool(lbutton or rbutton)
                              for lbutton, rbutton in click_states)
                movement_count = sum(bool(m["distance"] > 5)
                                 for m in movements)

                if movement_count > 5 and click_count == 0:
                    details["warning"] = "movement_without_clicks"

                details["mouse_active"] = True
                details["movement_count"] = len(movements)
                details["velocity_variance"] = velocity_variance
                details["direction_changes"] = direction_changes
                details["click_count"] = click_count

        except Exception as e:
            self.logger.debug(f"Mouse movement check failed: {e}")

        return False, 0.0, details

    def _get_system_uptime(self) -> int:
        """Get system uptime in seconds."""
        try:
            if platform.system() == "Windows":
                kernel32 = ctypes.windll.kernel32
                return kernel32.GetTickCount64() // 1000
            with open("/proc/uptime") as f:
                uptime = float(f.readline().split()[0])
                return int(uptime)
        except Exception:
            return None

    def _ip_in_network(self, ip: str, network: str) -> bool:
        """Check if IP is in network range."""
        try:
            import ipaddress

            return ipaddress.ip_address(ip) in ipaddress.ip_network(network)
        except Exception:
            # Simple check for common cases
            network_parts = network.split("/")[0].split(".")
            ip_parts = ip.split(".")

            # Check if first 3 octets match (assuming /24)
            return ip_parts[:3] == network_parts[:3]

    def _identify_sandbox_type(self, detections: dict[str, Any]) -> str:
        """Identify specific sandbox based on detections."""
        sandbox_scores = {}

        # Analyze all detection details
        for method, result in detections.items():
            if result["detected"]:
                details_str = str(result["details"]).lower()
                self.logger.debug(f"Analyzing sandbox type from method: {method}")

                # Check for sandbox signatures
                for sandbox_type, sigs in self.sandbox_signatures.items():
                    score = sum(bool(artifact.lower() in details_str)
                            for artifact in sigs.get("artifacts", []))
                    # Check processes
                    for process in sigs.get("processes", []):
                        if process.lower() in details_str:
                            score += 2

                    # Check files
                    for file_path in sigs.get("files", []):
                        if file_path.lower() in details_str:
                            score += 2

                    if score > 0:
                        sandbox_scores[sandbox_type] = sandbox_scores.get(sandbox_type, 0) + score

        # Return sandbox with highest score
        if sandbox_scores:
            return max(sandbox_scores, key=sandbox_scores.get)

        # Generic sandbox if no specific type identified
        return "Generic Sandbox"

    def _calculate_evasion_difficulty(self, detections: dict[str, Any]) -> int:
        """Calculate how difficult it is to evade sandbox detection."""
        # Methods that are hard to evade
        hard_methods = ["file_system", "process_monitoring", "api_hooks"]
        medium_methods = ["environment_checks", "network_connectivity"]

        return self.calculate_detection_score(detections, hard_methods, medium_methods)

    def generate_sandbox_evasion(self) -> str:
        """Generate code to evade sandbox detection."""
        return """
// Sandbox Evasion Code
#include <windows.h>
#include <time.h>

bool IsSandbox() {
    // 1. Check username and computer name
    char username[256], computername[256];
    DWORD size = 256;

    GetUserName(username, &size);
    size = 256;
    GetComputerName(computername, &size);

    // Common sandbox names
    const char* bad_names[] = {"sandbox", "crack", "keygen", "test", "analyst"};
    for (int i = 0; i < 5; i++) {
        if (strstr(username, bad_names[i]) || strstr(computername, bad_names[i])) {
            return true;
        }
    }

    // 2. Check for user files
    WIN32_FIND_DATA findData;
    HANDLE hFind = FindFirstFile("C:\\\\Users\\\\*\\\\Documents\\\\*", &findData);
    int fileCount = 0;

    if (hFind != INVALID_HANDLE_VALUE) {
        do {
            fileCount++;
        } while (FindNextFile(hFind, &findData) && fileCount < 10);
        FindClose(hFind);
    }

    if (fileCount < 5) {
        return true;  // Too few user files
    }

    // 3. Check system uptime
    DWORD uptime = GetTickCount64() / 1000;  // Seconds
    if (uptime < 300) {  // Less than 5 minutes
        return true;
    }

    // 4. Mouse movement check
    POINT pt1, pt2;
    GetCursorPos(&pt1);
    Sleep(1000);
    GetCursorPos(&pt2);

    if (pt1.x == pt2.x && pt1.y == pt2.y) {
        // No mouse movement
        return true;
    }

    // 5. Check for sandbox artifacts
    if (GetModuleHandle("SbieDll.dll") != NULL) {  // Sandboxie
        return true;
    }

    return false;
}

// Evasive execution
if (IsSandbox()) {
    // Appear benign
    MessageBox(NULL, "This application is not compatible with your system", "Error", MB_OK);

    // Sleep to waste sandbox time
    Sleep(120000);  // 2 minutes

    ExitProcess(0);
}

// Delay execution to bypass automated analysis
Sleep(30000);  // 30 seconds

// Continue with malicious payload...
"""

    def get_aggressive_methods(self) -> list[str]:
        """Get list of method names that are considered aggressive."""
        return ["time_acceleration", "mouse_movement"]

    def get_detection_type(self) -> str:
        """Get the type of detection this class performs."""
        return "sandbox"

    def evade_with_behavioral_adaptation(self, aggressive: bool = False) -> dict[str, Any]:
        """Perform sandbox detection and adapt behavior to evade analysis.

        Args:
            aggressive: Use aggressive evasion that might affect analysis

        Returns:
            Evasion results with adapted behavior strategy

        """
        results = {
            "evasion_applied": False,
            "evasion_strategy": None,
            "behavioral_changes": [],
            "detection_bypassed": False,
            "confidence": 0.0,
            "sandbox_detected": False,
            "sandbox_type": None,
            "evasion_techniques": [],
        }

        try:
            self.logger.info("Starting sandbox evasion with behavioral adaptation...")

            detection_results = self.detect_sandbox(aggressive=aggressive)
            results["sandbox_detected"] = detection_results["is_sandbox"]
            results["sandbox_type"] = detection_results.get("sandbox_type")
            results["confidence"] = detection_results["confidence"]

            if results["sandbox_detected"]:
                self.logger.warning(
                    f"Sandbox detected: {results['sandbox_type']} (confidence: {results['confidence']:.2f})"
                )

                evasion_strategy = self._determine_evasion_strategy(detection_results, aggressive)
                results["evasion_strategy"] = evasion_strategy
                results["evasion_applied"] = True

                behavioral_changes = self._apply_behavioral_adaptation(
                    evasion_strategy, detection_results
                )
                results["behavioral_changes"] = behavioral_changes
                results["evasion_techniques"] = list(evasion_strategy.keys())

                bypass_success = self._verify_evasion_effectiveness(
                    detection_results, evasion_strategy
                )
                results["detection_bypassed"] = bypass_success

                self.logger.info(
                    f"Evasion applied with {len(behavioral_changes)} behavioral changes"
                )
            else:
                self.logger.info("No sandbox detected - continuing normal execution")

            return results

        except Exception as e:
            self.logger.error(f"Sandbox evasion failed: {e}")
            return results

    def _determine_evasion_strategy(
        self, detection_results: dict[str, Any], aggressive: bool
    ) -> dict[str, Any]:
        """Determine optimal evasion strategy based on detection results.

        Args:
            detection_results: Results from sandbox detection
            aggressive: Whether to use aggressive evasion

        Returns:
            Evasion strategy with specific techniques

        """
        strategy = {
            "timing": {},
            "interaction": {},
            "environment": {},
            "behavior": {},
            "anti_monitoring": {},
        }

        detections = detection_results.get("detections", {})
        sandbox_type = detection_results.get("sandbox_type", "Generic Sandbox")
        confidence = detection_results.get("confidence", 0.0)

        if confidence > 0.8:
            strategy["timing"]["delay_execution"] = {
                "enabled": True,
                "delay_seconds": 120 if aggressive else 30,
                "reason": "High confidence sandbox detection",
            }

            strategy["timing"]["time_bomb"] = {
                "enabled": True,
                "trigger_time": time.time() + (600 if aggressive else 300),
                "reason": "Delay past typical analysis window",
            }

        if "behavioral_detection" in detections and detections["behavioral_detection"]["detected"]:
            anomalies = detections["behavioral_detection"]["details"].get("anomalies", [])

            if any("Few user files" in a for a in anomalies):
                strategy["behavior"]["user_activity_verification"] = {
                    "enabled": True,
                    "verify_user_files": True,
                    "min_file_count": 10,
                    "reason": "Detected low user file count",
                }

            if any("Few processes" in a for a in anomalies):
                strategy["behavior"]["process_check"] = {
                    "enabled": True,
                    "min_processes": 40,
                    "reason": "Detected low process count",
                }

            if any("Low uptime" in a for a in anomalies):
                strategy["timing"]["uptime_check"] = {
                    "enabled": True,
                    "min_uptime_seconds": 600,
                    "reason": "Detected recent system boot",
                }

        if "user_interaction" in detections and detections["user_interaction"]["detected"]:
            strategy["interaction"]["require_user_input"] = {
                "enabled": True,
                "input_type": "mouse_click",
                "timeout_seconds": 60,
                "reason": "No user interaction detected",
            }

            strategy["interaction"]["mouse_movement_check"] = {
                "enabled": True,
                "duration_seconds": 10,
                "min_movements": 3,
                "reason": "Verify human mouse activity",
            }

        if "process_monitoring" in detections and detections["process_monitoring"]["detected"]:
            if monitoring_signs := detections["process_monitoring"]["details"].get(
                "monitoring_signs", []
            ):
                strategy["anti_monitoring"]["detect_and_exit"] = {
                    "enabled": True,
                    "exit_gracefully": True,
                    "reason": f"Monitoring detected: {len(monitoring_signs)} tools",
                }

                strategy["anti_monitoring"]["api_unhooking"] = {
                    "enabled": aggressive,
                    "reason": "Attempt to unhook monitored APIs",
                }

        if "api_hooks" in detections and detections["api_hooks"]["detected"]:
            if hooked_apis := detections["api_hooks"]["details"].get(
                "hooked_apis", []
            ):
                strategy["anti_monitoring"]["unhook_apis"] = {
                    "enabled": True,
                    "apis": hooked_apis,
                    "reason": f"Detected {len(hooked_apis)} hooked APIs",
                }

        if "time_acceleration" in detections and detections["time_acceleration"]["detected"]:
            strategy["timing"]["time_drift_detection"] = {
                "enabled": True,
                "exit_on_acceleration": True,
                "reason": "Time manipulation detected",
            }

        if "network_connectivity" in detections and detections["network_connectivity"]["detected"]:
            network_anomalies = detections["network_connectivity"]["details"].get(
                "network_anomalies", []
            )

            if any("Sandbox network" in a for a in network_anomalies):
                strategy["environment"]["sandbox_network_exit"] = {
                    "enabled": True,
                    "reason": "Detected sandbox network configuration",
                }

            if "No DNS resolution" in network_anomalies:
                strategy["environment"]["dns_check"] = {
                    "enabled": True,
                    "required_domains": ["google.com", "microsoft.com"],
                    "reason": "No DNS resolution available",
                }

        if sandbox_type in [
            "cuckoo",
            "vmray",
            "joe_sandbox",
            "any.run",
            "cape",
            "triage",
            "hatching_triage",
            "intezer",
            "virustotal",
            "hybrid_analysis",
        ]:
            strategy["behavior"]["sandbox_specific_evasion"] = {
                "enabled": True,
                "sandbox_type": sandbox_type,
                "techniques": self._get_sandbox_specific_techniques(sandbox_type),
            }

        if "resource_limits" in detections and detections["resource_limits"]["detected"]:
            limitations = detections["resource_limits"]["details"].get("limitations", [])

            if any("Low CPU" in limitation for limitation in limitations):
                strategy["environment"]["cpu_check"] = {
                    "enabled": True,
                    "min_cores": 4,
                    "reason": "Detected limited CPU resources",
                }

            if any("Low memory" in limitation for limitation in limitations):
                strategy["environment"]["memory_check"] = {
                    "enabled": True,
                    "min_gb": 4,
                    "reason": "Detected limited memory",
                }

        strategy["timing"]["stalling"] = {
            "enabled": aggressive,
            "technique": "computation_intensive" if aggressive else "sleep_loops",
            "reason": "Exceed sandbox analysis timeout",
        }

        return strategy

    def _get_sandbox_specific_techniques(self, sandbox_type: str) -> list[str]:
        """Get sandbox-specific evasion techniques.

        Args:
            sandbox_type: Type of sandbox detected

        Returns:
            List of applicable evasion techniques

        """
        techniques = {
            "cuckoo": [
                "detect_cuckoo_agent_process",
                "check_for_cuckoo_network_192_168_56",
                "detect_analyzer_py_script",
                "check_for_agent_auxiliary_modules",
                "verify_results_server_accessibility",
            ],
            "vmray": [
                "detect_vmray_controller_process",
                "check_for_vmray_agent",
                "detect_vmray_network_artifacts",
                "verify_vmray_registry_keys",
            ],
            "joe_sandbox": [
                "detect_joebox_processes",
                "check_for_joe_api_hooks",
                "verify_joe_network_config",
                "detect_joecontrol_service",
            ],
            "any.run": [
                "detect_anyrun_browser_environment",
                "check_for_anyrun_network",
                "verify_interactive_session",
                "detect_web_based_analysis",
            ],
            "cape": [
                "detect_cape_monitor_dll",
                "check_for_cape_analyzer",
                "verify_cape_network_config",
                "detect_cape_process_injection",
            ],
            "triage": [
                "detect_triage_analysis_environment",
                "check_for_triage_artifacts",
                "verify_triage_network",
                "detect_automated_browser",
            ],
            "hatching_triage": [
                "detect_triage_analysis_environment",
                "check_for_hatching_process",
                "verify_triage_network_192_168_30",
                "detect_automated_browser",
            ],
            "intezer": [
                "detect_intezer_environment_vars",
                "check_for_intezer_agent",
                "verify_cloud_analysis_indicators",
            ],
            "virustotal": [
                "detect_vt_environment_vars",
                "check_for_vt_network_10_0_2",
                "verify_virtualization_layer",
            ],
            "hybrid_analysis": [
                "detect_falcon_sandbox_artifacts",
                "check_for_cwsandbox_processes",
                "verify_hybrid_analysis_network",
            ],
        }

        return techniques.get(sandbox_type.lower(), ["generic_sandbox_evasion"])

    def _apply_behavioral_adaptation(
        self, strategy: dict[str, Any], detection_results: dict[str, Any]
    ) -> list[str]:
        """Apply behavioral changes based on evasion strategy.

        Args:
            strategy: Evasion strategy to apply
            detection_results: Original detection results

        Returns:
            List of behavioral changes applied

        """
        changes = []

        try:
            if strategy["timing"].get("delay_execution", {}).get("enabled"):
                delay = strategy["timing"]["delay_execution"]["delay_seconds"]
                changes.append(f"Delayed execution by {delay} seconds")
                time.sleep(delay)

            if strategy["timing"].get("uptime_check", {}).get("enabled"):
                min_uptime = strategy["timing"]["uptime_check"]["min_uptime_seconds"]
                current_uptime = self._get_system_uptime()

                if current_uptime and current_uptime < min_uptime:
                    changes.append(
                        f"System uptime too low ({current_uptime}s < {min_uptime}s) - exiting"
                    )
                    return changes

            if strategy["environment"].get("cpu_check", {}).get("enabled"):
                min_cores = strategy["environment"]["cpu_check"]["min_cores"]
                cpu_count = os.cpu_count()

                if cpu_count and cpu_count < min_cores:
                    changes.append(f"CPU count too low ({cpu_count} < {min_cores}) - exiting")
                    return changes

            if strategy["environment"].get("memory_check", {}).get("enabled"):
                min_gb = strategy["environment"]["memory_check"]["min_gb"]
                mem = psutil.virtual_memory()
                total_gb = mem.total / (1024**3)

                if total_gb < min_gb:
                    changes.append(f"Memory too low ({total_gb:.1f}GB < {min_gb}GB) - exiting")
                    return changes

            if (
                strategy["interaction"].get("mouse_movement_check", {}).get("enabled")
                and platform.system() == "Windows"
            ):
                duration = strategy["interaction"]["mouse_movement_check"]["duration_seconds"]
                min_movements = strategy["interaction"]["mouse_movement_check"]["min_movements"]

                mouse_active = self._verify_mouse_movement(duration, min_movements)

                if not mouse_active:
                    changes.append(f"No mouse movement detected in {duration}s - likely sandbox")
                    return changes
                changes.append(f"Mouse movement verified - {min_movements}+ movements detected")

            if strategy["environment"].get("dns_check", {}).get("enabled"):
                required_domains = strategy["environment"]["dns_check"]["required_domains"]
                dns_working = self._verify_dns_resolution(required_domains)

                if not dns_working:
                    changes.append("DNS resolution failed - network restricted environment")
                    return changes
                changes.append("DNS resolution verified")

            if strategy["anti_monitoring"].get("detect_and_exit", {}).get("enabled"):
                if monitoring_detected := self._check_for_monitoring_tools():
                    changes.append("Monitoring tools detected - exiting gracefully")
                    return changes

            if (
                strategy["anti_monitoring"].get("unhook_apis", {}).get("enabled")
                and platform.system() == "Windows"
            ):
                if hooked_apis := strategy["anti_monitoring"]["unhook_apis"].get(
                    "apis", []
                ):
                    unhooked_count = self._attempt_api_unhooking(hooked_apis)
                    changes.append(f"Attempted unhooking {unhooked_count} APIs")

            if strategy["timing"].get("time_drift_detection", {}).get("enabled"):
                if time_accelerated := self._detect_time_acceleration():
                    changes.append("Time acceleration detected - exiting")
                    return changes

            if strategy["behavior"].get("sandbox_specific_evasion", {}).get("enabled"):
                sandbox_type = strategy["behavior"]["sandbox_specific_evasion"]["sandbox_type"]
                techniques = strategy["behavior"]["sandbox_specific_evasion"]["techniques"]

                evasion_applied = self._apply_sandbox_specific_evasion(sandbox_type, techniques)
                changes.append(
                    f"Applied {evasion_applied} {sandbox_type}-specific evasion techniques"
                )

            if strategy["timing"].get("stalling", {}).get("enabled"):
                technique = strategy["timing"]["stalling"]["technique"]
                stall_result = self._apply_stalling_technique(technique)
                changes.append(f"Applied stalling technique: {stall_result}")

            if strategy["timing"].get("time_bomb", {}).get("enabled"):
                trigger_time = strategy["timing"]["time_bomb"]["trigger_time"]
                changes.append(f"Set execution trigger for {time.ctime(trigger_time)}")

        except Exception as e:
            self.logger.error(f"Error applying behavioral adaptation: {e}")
            changes.append(f"Adaptation error: {e!s}")

        return changes

    def _verify_mouse_movement(self, duration_seconds: int, min_movements: int) -> bool:
        """Verify human-like mouse movement over duration.

        Args:
            duration_seconds: How long to monitor
            min_movements: Minimum number of unique positions required

        Returns:
            True if sufficient mouse movement detected

        """
        if platform.system() != "Windows":
            return True

        try:
            try:
                from ctypes import wintypes
            except (ImportError, AttributeError):

                class _TempWinTypes:
                    class POINT(ctypes.Structure):
                        _fields_ = [("x", ctypes.c_long), ("y", ctypes.c_long)]

                wintypes = _TempWinTypes()

            user32 = ctypes.windll.user32
            positions = []
            samples = max(10, duration_seconds)

            for _ in range(samples):
                point = wintypes.POINT()
                user32.GetCursorPos(ctypes.byref(point))
                positions.append((point.x, point.y))
                time.sleep(duration_seconds / samples)

            unique_positions = len(set(positions))
            return unique_positions >= min_movements

        except Exception as e:
            self.logger.debug(f"Mouse movement verification failed: {e}")
            return True

    def _verify_dns_resolution(self, required_domains: list[str]) -> bool:
        """Verify DNS resolution works for required domains.

        Args:
            required_domains: List of domains to test

        Returns:
            True if at least one domain resolves

        """
        try:
            for domain in required_domains:
                try:
                    socket.gethostbyname(domain)
                    return True
                except Exception as e:
                    self.logger.debug(f"DNS resolution failed for {domain}: {e}")

            return False

        except Exception as e:
            self.logger.debug(f"DNS verification failed: {e}")
            return True

    def _check_for_monitoring_tools(self) -> bool:
        """Check if monitoring tools are running.

        Returns:
            True if monitoring detected

        """
        try:
            monitoring_processes = [
                "procmon",
                "procexp",
                "apimonitor",
                "wireshark",
                "tcpdump",
                "strace",
                "ltrace",
                "sysmon",
                "regmon",
                "filemon",
            ]

            processes, process_list = self.get_running_processes()

            return any(
                monitor.lower() in processes
                or any(monitor in p.lower() for p in process_list)
                for monitor in monitoring_processes
            )
        except Exception as e:
            self.logger.debug(f"Monitoring tool check failed: {e}")
            return False

    def _attempt_api_unhooking(self, hooked_apis: list[str]) -> int:
        """Attempt to unhook monitored APIs using PE-based clean memory mapping.

        Args:
            hooked_apis: List of hooked API names

        Returns:
            Number of APIs potentially unhooked

        """
        if platform.system() != "Windows":
            return 0

        unhooked_count = 0

        try:
            import ctypes
            import struct

            kernel32 = ctypes.windll.kernel32
            LoadLibraryExW = kernel32.LoadLibraryExW
            LoadLibraryExW.argtypes = [ctypes.c_wchar_p, ctypes.c_void_p, ctypes.c_uint32]
            LoadLibraryExW.restype = ctypes.c_void_p

            GetModuleHandleW = kernel32.GetModuleHandleW
            GetModuleHandleW.argtypes = [ctypes.c_wchar_p]
            GetModuleHandleW.restype = ctypes.c_void_p

            GetProcAddress = kernel32.GetProcAddress
            GetProcAddress.argtypes = [ctypes.c_void_p, ctypes.c_char_p]
            GetProcAddress.restype = ctypes.c_void_p

            VirtualProtect = kernel32.VirtualProtect
            VirtualProtect.argtypes = [
                ctypes.c_void_p,
                ctypes.c_size_t,
                ctypes.c_uint32,
                ctypes.POINTER(ctypes.c_uint32),
            ]
            VirtualProtect.restype = ctypes.c_bool

            FreeLibrary = kernel32.FreeLibrary
            FreeLibrary.argtypes = [ctypes.c_void_p]
            FreeLibrary.restype = ctypes.c_bool

            DONT_RESOLVE_DLL_REFERENCES = 0x00000001
            LOAD_LIBRARY_AS_DATAFILE = 0x00000002

            for hooked_api in hooked_apis:
                try:
                    if "!" not in hooked_api:
                        continue

                    dll_name, api_name = hooked_api.split("!")

                    loaded_module = GetModuleHandleW(dll_name)
                    if not loaded_module:
                        continue

                    hooked_addr = GetProcAddress(loaded_module, api_name.encode())
                    if not hooked_addr:
                        continue

                    first_bytes = (ctypes.c_ubyte * 5).from_address(hooked_addr)
                    if first_bytes[0] not in [0xE9, 0x68, 0xEB, 0xFF]:
                        continue

                    clean_module = LoadLibraryExW(
                        dll_name, None, DONT_RESOLVE_DLL_REFERENCES | LOAD_LIBRARY_AS_DATAFILE
                    )
                    if not clean_module:
                        continue

                    try:
                        dos_header = (ctypes.c_ubyte * 64).from_address(clean_module)
                        e_lfanew = struct.unpack("<I", bytes(dos_header[60:64]))[0]

                        pe_header_addr = clean_module + e_lfanew
                        pe_signature = (ctypes.c_ubyte * 4).from_address(pe_header_addr)

                        if bytes(pe_signature) != b"PE\x00\x00":
                            continue

                        coff_header_addr = pe_header_addr + 4
                        coff_header = (ctypes.c_ubyte * 20).from_address(coff_header_addr)
                        optional_header_size = struct.unpack("<H", bytes(coff_header[16:18]))[0]

                        optional_header_addr = coff_header_addr + 20
                        optional_header = (ctypes.c_ubyte * optional_header_size).from_address(
                            optional_header_addr
                        )

                        magic = struct.unpack("<H", bytes(optional_header[:2]))[0]
                        if magic == 0x20B:
                            export_table_rva = struct.unpack("<I", bytes(optional_header[112:116]))[
                                0
                            ]
                        else:
                            export_table_rva = struct.unpack("<I", bytes(optional_header[96:100]))[
                                0
                            ]

                        if export_table_rva == 0:
                            continue

                        export_dir_addr = clean_module + export_table_rva
                        export_dir = (ctypes.c_ubyte * 40).from_address(export_dir_addr)

                        num_names = struct.unpack("<I", bytes(export_dir[24:28]))[0]
                        names_rva = struct.unpack("<I", bytes(export_dir[32:36]))[0]
                        ordinals_rva = struct.unpack("<I", bytes(export_dir[36:40]))[0]
                        functions_rva = struct.unpack("<I", bytes(export_dir[28:32]))[0]

                        names_table = clean_module + names_rva
                        ordinals_table = clean_module + ordinals_rva
                        functions_table = clean_module + functions_rva

                        function_rva = None
                        for i in range(num_names):
                            name_rva_addr = names_table + (i * 4)
                            name_rva = struct.unpack(
                                "<I", bytes((ctypes.c_ubyte * 4).from_address(name_rva_addr))
                            )[0]
                            name_addr = clean_module + name_rva

                            name_bytes = ctypes.string_at(name_addr)
                            if name_bytes == api_name.encode():
                                ordinal_addr = ordinals_table + (i * 2)
                                ordinal = struct.unpack(
                                    "<H", bytes((ctypes.c_ubyte * 2).from_address(ordinal_addr))
                                )[0]

                                func_rva_addr = functions_table + (ordinal * 4)
                                function_rva = struct.unpack(
                                    "<I", bytes((ctypes.c_ubyte * 4).from_address(func_rva_addr))
                                )[0]
                                break

                        if function_rva:
                            clean_func_addr = clean_module + function_rva
                            original_bytes = bytes(
                                (ctypes.c_ubyte * 16).from_address(clean_func_addr)
                            )

                            old_protect = ctypes.c_uint32()
                            if VirtualProtect(hooked_addr, 16, 0x40, ctypes.byref(old_protect)):
                                ctypes.memmove(hooked_addr, original_bytes, 16)
                                VirtualProtect(
                                    hooked_addr, 16, old_protect.value, ctypes.byref(old_protect)
                                )

                                unhooked_count += 1
                                self.logger.debug(
                                    f"Unhooked {hooked_api} using PE-based clean copy"
                                )

                    finally:
                        FreeLibrary(clean_module)

                except Exception as e:
                    self.logger.debug(f"Failed to unhook {hooked_api}: {e}")

        except Exception as e:
            self.logger.debug(f"API unhooking failed: {e}")

        return unhooked_count

    def _detect_time_acceleration(self) -> bool:
        """Detect if time is being accelerated by sandbox.

        Returns:
            True if time acceleration detected

        """
        try:
            start_real = time.time()
            start_perf = time.perf_counter()

            time.sleep(1)

            end_real = time.time()
            end_perf = time.perf_counter()

            real_elapsed = end_real - start_real
            perf_elapsed = end_perf - start_perf

            drift = abs(real_elapsed - perf_elapsed)

            return drift > 0.1

        except Exception as e:
            self.logger.debug(f"Time acceleration detection failed: {e}")
            return False

    def _apply_sandbox_specific_evasion(self, sandbox_type: str, techniques: list[str]) -> int:
        """Apply sandbox-specific evasion techniques.

        Args:
            sandbox_type: Type of sandbox to evade
            techniques: List of technique names to apply

        Returns:
            Number of techniques successfully applied

        """
        applied = 0

        try:
            for technique in techniques:
                success = False

                if technique == "detect_cuckoo_agent_process":
                    processes, _ = self.get_running_processes()
                    success = "analyzer" in processes or "agent.py" in processes

                elif technique == "check_for_cuckoo_network_192_168_56":
                    try:
                        hostname = socket.gethostname()
                        local_ip = socket.gethostbyname(hostname)
                        success = local_ip.startswith("192.168.56.")
                    except Exception:
                        success = False

                elif technique == "detect_vmray_controller_process":
                    processes, _ = self.get_running_processes()
                    success = any("vmray" in p for p in processes)

                elif technique == "detect_joebox_processes":
                    processes, _ = self.get_running_processes()
                    success = any("joe" in p or "jbx" in p for p in processes)

                elif technique == "detect_cape_monitor_dll" and platform.system() == "Windows":
                    try:
                        current_proc = psutil.Process()
                        dlls = [
                            os.path.basename(dll.path).lower() for dll in current_proc.memory_maps()
                        ]
                        success = any("cape" in dll or "monitor" in dll for dll in dlls)
                    except Exception:
                        success = False

                elif technique == "detect_anyrun_browser_environment":
                    success = os.environ.get("ANYRUN_ANALYSIS") is not None

                elif technique == "verify_interactive_session" and platform.system() == "Windows":
                    try:
                        processes, _ = self.get_running_processes()
                        success = "explorer.exe" in processes
                    except Exception:
                        success = False

                elif technique == "check_for_hatching_process":
                    processes, _ = self.get_running_processes()
                    success = any(
                        "hatching" in p.lower() or "triage" in p.lower() for p in processes
                    )

                elif technique == "verify_triage_network_192_168_30":
                    try:
                        hostname = socket.gethostname()
                        local_ip = socket.gethostbyname(hostname)
                        success = local_ip.startswith("192.168.30.")
                    except Exception:
                        success = False

                elif technique == "detect_intezer_environment_vars":
                    success = os.environ.get("INTEZER_ANALYSIS") is not None

                elif technique == "check_for_intezer_agent":
                    processes, _ = self.get_running_processes()
                    success = any("intezer" in p.lower() for p in processes)

                elif technique == "detect_vt_environment_vars":
                    success = (
                        os.environ.get("VT_SANDBOX") is not None
                        or os.environ.get("VIRUSTOTAL_ANALYSIS") is not None
                    )

                elif technique == "check_for_vt_network_10_0_2":
                    try:
                        hostname = socket.gethostname()
                        local_ip = socket.gethostbyname(hostname)
                        success = local_ip.startswith("10.0.2.")
                    except Exception:
                        success = False

                elif technique == "detect_falcon_sandbox_artifacts":
                    processes, _ = self.get_running_processes()
                    success = any("falcon" in p.lower() or "hybrid" in p.lower() for p in processes)

                elif technique == "check_for_cwsandbox_processes":
                    processes, _ = self.get_running_processes()
                    success = any("cws" in p.lower() or "cwsandbox" in p.lower() for p in processes)

                elif technique == "generic_sandbox_evasion":
                    success = True

                if success:
                    applied += 1
                    self.logger.debug(f"Applied technique: {technique}")

        except Exception as e:
            self.logger.debug(f"Sandbox-specific evasion failed: {e}")

        return applied

    def _apply_stalling_technique(self, technique: str) -> str:
        """Apply stalling technique to exceed sandbox timeout.

        Args:
            technique: Type of stalling technique

        Returns:
            Description of applied technique

        """
        try:
            if technique == "sleep_loops":
                for _i in range(10):
                    time.sleep(5)
                return "Applied 10x5s sleep loops"

            if technique == "computation_intensive":
                result = sum(i * i % 97 for i in range(10000000))
                return f"Completed computation-intensive loop (result: {result})"

            if technique == "file_operations":
                temp_dir = tempfile.gettempdir()
                temp_file = os.path.join(temp_dir, f"intellicrack_stall_{uuid.uuid4().hex}.tmp")

                try:
                    with open(temp_file, "wb") as f:
                        content = (b"A" * 1024) * 1000
                        f.write(content)
                    os.remove(temp_file)
                    return "Completed file I/O stalling"
                except Exception as e:
                    return f"File I/O stalling failed: {e}"

            return "Unknown stalling technique"

        except Exception as e:
            self.logger.debug(f"Stalling technique failed: {e}")
            return f"Stalling failed: {e}"

    def _verify_evasion_effectiveness(
        self, detection_results: dict[str, Any], evasion_strategy: dict[str, Any]
    ) -> bool:
        """Verify if evasion was effective.

        Args:
            detection_results: Original detection results
            evasion_strategy: Applied evasion strategy

        Returns:
            True if evasion appears effective

        """
        try:
            bypass_indicators = 0
            total_checks = 0

            if evasion_strategy["timing"].get("uptime_check", {}).get("enabled"):
                total_checks += 1
                current_uptime = self._get_system_uptime()
                min_uptime = evasion_strategy["timing"]["uptime_check"]["min_uptime_seconds"]

                if current_uptime and current_uptime >= min_uptime:
                    bypass_indicators += 1

            if evasion_strategy["environment"].get("cpu_check", {}).get("enabled"):
                total_checks += 1
                cpu_count = os.cpu_count()
                min_cores = evasion_strategy["environment"]["cpu_check"]["min_cores"]

                if cpu_count and cpu_count >= min_cores:
                    bypass_indicators += 1

            if evasion_strategy["interaction"].get("mouse_movement_check", {}).get("enabled"):
                total_checks += 1
                duration = evasion_strategy["interaction"]["mouse_movement_check"][
                    "duration_seconds"
                ]
                min_movements = evasion_strategy["interaction"]["mouse_movement_check"][
                    "min_movements"
                ]

                if self._verify_mouse_movement(duration, min_movements):
                    bypass_indicators += 1

            if evasion_strategy["environment"].get("dns_check", {}).get("enabled"):
                total_checks += 1
                required_domains = evasion_strategy["environment"]["dns_check"]["required_domains"]

                if self._verify_dns_resolution(required_domains):
                    bypass_indicators += 1

            return False if total_checks == 0 else bypass_indicators / total_checks >= 0.5
        except Exception as e:
            self.logger.debug(f"Evasion verification failed: {e}")
            return False

    def _check_environment_variables(self) -> tuple[bool, float, dict]:
        """Check environment variables for sandbox indicators."""
        details = {"suspicious_vars": [], "sandbox_indicators": []}

        try:
            for sandbox_name, sig_data in self.sandbox_signatures.items():
                env_vars = sig_data.get("environment_vars", [])

                for var in env_vars:
                    if os.environ.get(var):
                        details["suspicious_vars"].append(var)
                        details["sandbox_indicators"].append(f"{sandbox_name}: {var}")

            common_sandbox_vars = [
                "SANDBOX",
                "ANALYSIS",
                "MONITOR",
                "TRACE",
                "CUCKOO",
                "VMRAY",
                "JOEBOX",
                "TRIAGE",
                "VBOX",
                "VMWARE",
                "WINE",
            ]

            for key, value in os.environ.items():
                key_upper = key.upper()
                for indicator in common_sandbox_vars:
                    if indicator in key_upper or (value and indicator in value.upper()):
                        details["suspicious_vars"].append(f"{key}={value}")

            if details["suspicious_vars"]:
                confidence = min(0.9, len(details["suspicious_vars"]) * 0.2)
                return True, confidence, details

        except Exception as e:
            self.logger.debug(f"Environment variable check failed: {e}")

        return False, 0.0, details

    def _check_parent_process(self) -> tuple[bool, float, dict]:
        """Analyze parent process for sandbox indicators."""
        details = {"parent_name": None, "parent_cmdline": None, "suspicious": False}

        try:
            current_proc = psutil.Process()
            if parent_proc := current_proc.parent():
                details["parent_name"] = parent_proc.name()

                with contextlib.suppress(psutil.AccessDenied, psutil.NoSuchProcess):
                    details["parent_cmdline"] = " ".join(parent_proc.cmdline())

                suspicious_parents = [
                    "python",
                    "python.exe",
                    "pythonw.exe",
                    "perl",
                    "perl.exe",
                    "powershell",
                    "powershell.exe",
                    "cmd.exe",
                    "analyzer",
                    "agent",
                    "sample",
                    "malware",
                    "vboxservice",
                    "vmtoolsd",
                ]

                parent_name_lower = parent_proc.name().lower()
                for suspicious in suspicious_parents:
                    if suspicious in parent_name_lower:
                        details["suspicious"] = True

                        if parent_name_lower in ["python.exe", "pythonw.exe", "python"]:
                            with contextlib.suppress(psutil.AccessDenied, psutil.NoSuchProcess):
                                cmdline = parent_proc.cmdline()
                                if any(
                                    "analyzer" in arg.lower()
                                    or "agent" in arg.lower()
                                    or "monitor" in arg.lower()
                                    for arg in cmdline
                                ):
                                    return True, 0.85, details
                        return True, 0.6, details

                if platform.system() == "Windows":
                    expected_parents = ["explorer.exe", "cmd.exe", "powershell.exe", "services.exe"]
                    if parent_name_lower not in expected_parents:
                        details["suspicious"] = True
                        return True, 0.3, details

        except (psutil.NoSuchProcess, psutil.AccessDenied) as e:
            self.logger.debug(f"Parent process check failed: {e}")

        return False, 0.0, details

    def _check_cpuid_hypervisor(self) -> tuple[bool, float, dict]:
        """Check CPUID for hypervisor presence using hypervisor bit."""
        details = {"hypervisor_present": False, "cpu_brand": None, "hypervisor_vendor": None}

        try:
            if platform.system() == "Windows":
                kernel32 = ctypes.windll.kernel32

                code_cpuid = bytes(
                    [
                        0x53,
                        0x57,
                        0x56,
                        0x89,
                        0xC8,
                        0x0F,
                        0xA2,
                        0x89,
                        0x1F,
                        0x89,
                        0x4F,
                        0x04,
                        0x89,
                        0x57,
                        0x08,
                        0x89,
                        0x77,
                        0x0C,
                        0x5E,
                        0x5F,
                        0x5B,
                        0xC3,
                    ]
                )

                buf = ctypes.create_string_buffer(code_cpuid)
                exec_mem = kernel32.VirtualAlloc(
                    None,
                    len(code_cpuid),
                    0x1000 | 0x2000,
                    0x04,
                )

                if not exec_mem:
                    return False, 0.0, details

                try:
                    ctypes.memmove(exec_mem, buf, len(code_cpuid))

                    old_protect = ctypes.c_ulong()
                    if not kernel32.VirtualProtect(
                        exec_mem,
                        len(code_cpuid),
                        0x20,
                        ctypes.byref(old_protect),
                    ):
                        return False, 0.0, details

                    func = ctypes.CFUNCTYPE(None, ctypes.c_uint32, ctypes.POINTER(ctypes.c_uint32))(
                        exec_mem
                    )

                    result = (ctypes.c_uint32 * 4)()

                    func(1, result)
                    ecx = result[2]

                    hypervisor_bit = (ecx >> 31) & 1
                    details["hypervisor_present"] = bool(hypervisor_bit)

                    if hypervisor_bit:
                        func(0x40000000, result)
                        vendor_string = b""
                        for reg in [result[1], result[2], result[3]]:
                            vendor_string += reg.to_bytes(4, byteorder="little")

                        try:
                            details["hypervisor_vendor"] = vendor_string.decode("ascii").strip(
                                "\x00"
                            )
                        except UnicodeDecodeError:
                            details["hypervisor_vendor"] = vendor_string.hex()

                        return True, 0.75, details

                finally:
                    kernel32.VirtualFree(exec_mem, 0, 0x8000)

            elif platform.system() == "Linux":
                with contextlib.suppress(OSError), open("/proc/cpuinfo") as f:
                    cpuinfo = f.read()

                    if "hypervisor" in cpuinfo.lower():
                        details["hypervisor_present"] = True

                        for line in cpuinfo.split("\n"):
                            if "model name" in line.lower():
                                details["cpu_brand"] = line.split(":")[1].strip()
                                break

                        return True, 0.7, details
        except Exception as e:
            self.logger.debug(f"CPUID hypervisor check failed: {e}")

        return False, 0.0, details

    def _check_mac_address_artifacts(self) -> tuple[bool, float, dict]:
        """Check MAC addresses for VM/sandbox vendor patterns."""
        details = {"mac_addresses": [], "suspicious_vendors": []}

        try:
            if hasattr(psutil, "net_if_addrs"):
                interfaces = psutil.net_if_addrs()

                vm_mac_prefixes = {
                    "00:05:69": "VMware",
                    "00:0C:29": "VMware",
                    "00:1C:14": "VMware",
                    "00:50:56": "VMware",
                    "08:00:27": "VirtualBox",
                    "00:16:3E": "Xen",
                    "00:1C:42": "Parallels",
                    "00:03:FF": "Microsoft Hyper-V",
                    "00:15:5D": "Microsoft Hyper-V",
                    "00:17:FA": "Microsoft Hyper-V",
                    "BC:30:5B": "Microsoft Hyper-V",
                    "52:54:00": "QEMU/KVM",
                }

                for interface_name, addrs in interfaces.items():
                    for addr in addrs:
                        if addr.family == psutil.AF_LINK:
                            mac = addr.address
                            details["mac_addresses"].append(f"{interface_name}: {mac}")

                            mac_upper = mac.upper()
                            for prefix, vendor in vm_mac_prefixes.items():
                                if mac_upper.startswith(prefix):
                                    details["suspicious_vendors"].append(f"{vendor} (MAC: {mac})")

                if details["suspicious_vendors"]:
                    confidence = min(0.9, len(details["suspicious_vendors"]) * 0.3)
                    return True, confidence, details

        except Exception as e:
            self.logger.debug(f"MAC address check failed: {e}")

        return False, 0.0, details

    def _check_browser_automation(self) -> tuple[bool, float, dict]:
        """Detect browser automation frameworks used in sandboxes."""
        details = {"automation_indicators": [], "detected_frameworks": []}

        try:
            _processes, process_list = self.get_running_processes()

            automation_processes = [
                "chromedriver",
                "geckodriver",
                "msedgedriver",
                "selenium",
                "puppeteer",
                "playwright",
                "phantomjs",
                "casperjs",
            ]

            for proc in process_list:
                proc_lower = proc.lower()
                for auto_proc in automation_processes:
                    if auto_proc in proc_lower:
                        details["automation_indicators"].append(f"Process: {proc}")
                        details["detected_frameworks"].append(auto_proc)

            common_dirs = self._get_common_directories()
            for directory in common_dirs:
                for auto_proc in automation_processes:
                    potential_path = os.path.join(directory, f"{auto_proc}.exe")
                    if os.path.exists(potential_path):
                        details["automation_indicators"].append(f"File: {potential_path}")
                        if auto_proc not in details["detected_frameworks"]:
                            details["detected_frameworks"].append(auto_proc)

            if platform.system() == "Windows":
                try:
                    user32 = ctypes.windll.user32
                    enum_windows_proc = ctypes.WINFUNCTYPE(
                        ctypes.c_bool,
                        ctypes.c_void_p,
                        ctypes.c_void_p,
                    )

                    automation_titles = []

                    def enum_callback(hwnd: int, lParam: int) -> bool:
                        length = user32.GetWindowTextLengthW(hwnd)
                        if length > 0:
                            buffer = ctypes.create_unicode_buffer(length + 1)
                            user32.GetWindowTextW(hwnd, buffer, length + 1)
                            title = buffer.value.lower()

                            if any(
                                keyword in title
                                for keyword in [
                                    "selenium",
                                    "webdriver",
                                    "automation",
                                    "puppeteer",
                                    "chromedriver",
                                ]
                            ):
                                automation_titles.append(buffer.value)
                        return True

                    callback = enum_windows_proc(enum_callback)
                    user32.EnumWindows(callback, 0)

                    if automation_titles:
                        details["automation_indicators"].extend(
                            [f"Window: {t}" for t in automation_titles]
                        )

                except Exception as e:
                    self.logger.debug(f"Window enumeration failed: {e}")

            if details["automation_indicators"]:
                confidence = min(0.8, len(details["detected_frameworks"]) * 0.25)
                return True, confidence, details

        except Exception as e:
            self.logger.debug(f"Browser automation check failed: {e}")

        return False, 0.0, details

    def _check_advanced_timing(self) -> tuple[bool, float, dict]:
        """Advanced timing checks using multiple methods to detect time manipulation."""
        details = {"timing_anomalies": [], "methods_checked": []}

        try:
            start_time = time.time()
            start_perf = time.perf_counter()
            start_monotonic = time.monotonic()

            compute_iterations = 1000000
            result = 0
            for i in range(compute_iterations):
                result = (result + i) % 997

            end_time = time.time()
            end_perf = time.perf_counter()
            end_monotonic = time.monotonic()

            elapsed_time = end_time - start_time
            elapsed_perf = end_perf - start_perf
            elapsed_monotonic = end_monotonic - start_monotonic

            details["methods_checked"].extend(["time()", "perf_counter()", "monotonic()"])

            drift_time_perf = abs(elapsed_time - elapsed_perf)
            drift_time_monotonic = abs(elapsed_time - elapsed_monotonic)
            drift_perf_monotonic = abs(elapsed_perf - elapsed_monotonic)

            if drift_time_perf > 0.1:
                details["timing_anomalies"].append(
                    f"time() vs perf_counter() drift: {drift_time_perf:.3f}s"
                )

            if drift_time_monotonic > 0.1:
                details["timing_anomalies"].append(
                    f"time() vs monotonic() drift: {drift_time_monotonic:.3f}s"
                )

            if drift_perf_monotonic > 0.1:
                details["timing_anomalies"].append(
                    f"perf_counter() vs monotonic() drift: {drift_perf_monotonic:.3f}s"
                )

            if elapsed_perf < 0.001:
                details["timing_anomalies"].append(
                    f"Computation too fast: {elapsed_perf:.6f}s (expected >0.001s)"
                )

            if elapsed_perf > 10.0:
                details["timing_anomalies"].append(
                    f"Computation too slow: {elapsed_perf:.3f}s (expected <10s)"
                )

            samples = []
            for _ in range(10):
                t1 = time.perf_counter()
                time.sleep(0.01)
                t2 = time.perf_counter()
                samples.append(t2 - t1)

            if samples:
                avg_sleep = sum(samples) / len(samples)
                variance = sum((s - avg_sleep) ** 2 for s in samples) / len(samples)
                std_dev = variance**0.5

                if std_dev > 0.005:
                    details["timing_anomalies"].append(f"High sleep variance: {std_dev:.6f}s")

                if avg_sleep < 0.005 or avg_sleep > 0.1:
                    details["timing_anomalies"].append(
                        f"Abnormal sleep duration: {avg_sleep:.6f}s (expected ~0.01s)"
                    )

            if details["timing_anomalies"]:
                confidence = min(0.7, len(details["timing_anomalies"]) * 0.15)
                return True, confidence, details

        except Exception as e:
            self.logger.debug(f"Advanced timing check failed: {e}")

        return False, 0.0, details

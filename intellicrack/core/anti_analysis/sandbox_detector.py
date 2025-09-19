"""This file is part of Intellicrack.
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
import logging
import os
import platform
import shutil
import socket
import subprocess
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

    def __init__(self):
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
                            os.path.join(base_dir, "." + pattern),  # Hidden
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
                        ]
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
                        ]
                    )

            # Add service names
            if "service_names" in patterns:
                signatures[sandbox_name]["services"].extend(patterns["service_names"])

            # Add DLL names
            if "dll_names" in patterns:
                signatures[sandbox_name]["dlls"].extend(patterns["dll_names"])

        # Add virtualization platform indicators
        vm_signatures = self._build_vm_signatures()
        signatures.update(vm_signatures)

        # Load custom signatures from configuration
        config_path = os.path.join(os.path.dirname(__file__), "..", "..", "data", "sandbox_signatures.json")

        try:
            if os.path.exists(config_path):
                with open(config_path, "r") as f:
                    custom_sigs = json.load(f)
                    # Merge custom signatures
                    for sandbox_name, sig_data in custom_sigs.items():
                        if sandbox_name not in signatures:
                            signatures[sandbox_name] = sig_data
                        else:
                            for sig_type, sig_values in sig_data.items():
                                if sig_type in signatures[sandbox_name]:
                                    signatures[sandbox_name][sig_type].extend(sig_values)
        except (IOError, json.JSONDecodeError):
            pass

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
                    try:
                        # Count files (not recursively for performance)
                        files = os.listdir(user_dir)
                        total_user_files += len(files)
                    except (OSError, PermissionError):
                        pass

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
        import tempfile

        dirs = []

        # Windows paths
        if platform.system() == "Windows":
            system_drive = os.environ.get("SystemDrive", "C:")
            dirs.extend(
                [
                    system_drive + "\\",
                    os.environ.get("ProgramFiles", "C:\\Program Files"),
                    os.environ.get("ProgramFiles(x86)", "C:\\Program Files (x86)"),
                    os.environ.get("ProgramData", "C:\\ProgramData"),
                    os.environ.get("APPDATA", ""),
                    os.environ.get("LOCALAPPDATA", ""),
                    os.environ.get("TEMP", tempfile.gettempdir()),
                    os.path.join(system_drive, "Windows"),
                    os.path.join(system_drive, "Windows", "System32"),
                    os.path.join(system_drive, "Windows", "SysWOW64"),
                    os.path.join(system_drive, "Users", "Public"),
                ]
            )
        else:
            # Linux/Unix paths
            dirs.extend(
                [
                    "/",
                    "/tmp",
                    "/var/tmp",
                    "/opt",
                    "/usr/local",
                    "/usr/share",
                    "/etc",
                    "/var/lib",
                    "/var/log",
                    os.path.expanduser("~"),
                    os.path.expanduser("~/.local"),
                    os.path.expanduser("~/.config"),
                ]
            )

        # Filter out non-existent or inaccessible directories
        valid_dirs = []
        for d in dirs:
            if d and os.path.exists(d):
                try:
                    # Test if we can list the directory
                    os.listdir(d)
                    valid_dirs.append(d)
                except (OSError, PermissionError):
                    pass

        return valid_dirs

    def _build_vm_signatures(self) -> dict:
        """Build virtualization platform signatures."""
        vm_sigs = {}

        # VMware signatures
        vm_sigs["vmware"] = {
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
        }

        # VirtualBox signatures
        vm_sigs["virtualbox"] = {
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
        }

        # Hyper-V signatures
        vm_sigs["hyperv"] = {
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
        }

        # QEMU/KVM signatures
        vm_sigs["qemu"] = {
            "files": [
                "/usr/bin/qemu-ga",
                "/etc/qemu-ga",
                "C:\\Program Files\\QEMU-GA",
            ],
            "processes": ["qemu-ga", "qemu-ga.exe"],
            "artifacts": ["qemu", "kvm", "bochs", "seabios"],
        }

        # Xen signatures
        vm_sigs["xen"] = {
            "files": [
                "/proc/xen",
                "/sys/hypervisor/type",
                "C:\\Program Files\\Xen Tools",
            ],
            "processes": ["xenservice.exe", "xen-detect"],
            "artifacts": ["xen", "xvm", "citrix"],
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
        else:
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

    def _profile_system(self):
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
        fingerprint_data = f"{profile['cpu_count']}:{profile['memory_total']}:{profile['unique_id']}"
        profile["fingerprint"] = hashlib.sha256(fingerprint_data.encode()).hexdigest()

        self.system_profile = profile

        # Check if profile matches known sandbox profiles
        self._check_against_known_profiles()

    def _check_against_known_profiles(self):
        """Check system profile against known sandbox profiles."""
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

        if hasattr(self, "system_profile"):
            mem_gb = self.system_profile["memory_total"] / (1024**3)

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
                    self.logger.warning(f"System profile matches {sandbox_name}: {matches}/{checks}")
                    self.detection_cache[f"profile_{sandbox_name}"] = True

    def _check_hardware_indicators(self) -> dict:
        """Check hardware indicators for sandbox/VM detection."""
        indicators = {"detected": False, "confidence": 0, "details": []}

        try:
            # Check CPU vendor
            import subprocess

            if platform.system() == "Windows":
                try:
                    wmic_path = shutil.which("wmic")
                    if wmic_path:
                        result = subprocess.run([wmic_path, "cpu", "get", "name"], capture_output=True, text=True, timeout=5)
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

                except Exception:
                    pass
            else:
                try:
                    with open("/proc/cpuinfo", "r") as f:
                        cpu_info = f.read().lower()

                        if "hypervisor" in cpu_info or "qemu" in cpu_info:
                            indicators["detected"] = True
                            indicators["confidence"] += 30
                            indicators["details"].append("Hypervisor detected in cpuinfo")
                except Exception:
                    pass

            # Check MAC address patterns
            import uuid

            mac = uuid.getnode()
            mac_str = ":".join(["{:02x}".format((mac >> i) & 0xFF) for i in range(0, 48, 8)])

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
                try:
                    key = winreg.OpenKey(hkey, path)
                    winreg.CloseKey(key)
                    indicators["detected"] = True
                    indicators["confidence"] += 50
                    indicators["details"].append(f"Registry key found: {path}")
                except WindowsError:
                    pass

            # Check for sandbox-specific values
            try:
                key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Control\SystemInformation")
                value, _ = winreg.QueryValueEx(key, "SystemManufacturer")
                winreg.CloseKey(key)

                vm_manufacturers = ["vmware", "virtualbox", "qemu", "xen", "parallels", "microsoft corporation"]
                if any(vm in value.lower() for vm in vm_manufacturers):
                    indicators["detected"] = True
                    indicators["confidence"] += 40
                    indicators["details"].append(f"VM manufacturer: {value}")

            except Exception:
                pass

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

                driverquery_path = shutil.which("driverquery")
                if driverquery_path:
                    result = subprocess.run([driverquery_path, "/v"], capture_output=True, text=True, timeout=5)
                    drivers = result.stdout.lower()
                else:
                    drivers = ""

                vm_drivers = ["vboxdrv", "vboxguest", "vmci", "vmhgfs", "vmmouse", "vmrawdsk", "vmusbmouse", "vmx86", "vmware"]

                for driver in vm_drivers:
                    if driver in drivers:
                        artifacts["detected"] = True
                        artifacts["confidence"] += 30
                        artifacts["details"].append(f"VM driver: {driver}")

            except Exception:
                pass
        else:
            # Check loaded kernel modules on Linux
            try:
                with open("/proc/modules", "r") as f:
                    modules = f.read().lower()

                    vm_modules = ["vboxguest", "vboxsf", "vmw_balloon", "vmxnet", "virtio", "xen", "kvm", "hyperv"]

                    for module in vm_modules:
                        if module in modules:
                            artifacts["detected"] = True
                            artifacts["confidence"] += 30
                            artifacts["details"].append(f"VM module: {module}")

            except Exception:
                pass

        # Check DMI/SMBIOS information
        try:
            if platform.system() == "Linux":
                import subprocess

                dmidecode_path = shutil.which("dmidecode")
                if dmidecode_path:
                    result = subprocess.run([dmidecode_path, "-t", "system"], capture_output=True, text=True, timeout=5)
                    if result.returncode == 0:
                        dmi_info = result.stdout.lower()
                    else:
                        dmi_info = ""
                else:
                    dmi_info = ""
                    vm_indicators = ["vmware", "virtualbox", "qemu", "kvm", "xen", "parallels"]

                    for indicator in vm_indicators:
                        if indicator in dmi_info:
                            artifacts["detected"] = True
                            artifacts["confidence"] += 50
                            artifacts["details"].append(f"DMI indicator: {indicator}")
                            break
        except Exception:
            pass

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
            results.update(detection_results)

            # Calculate overall results
            if detection_results["detection_count"] > 0:
                results["is_sandbox"] = True
                results["confidence"] = min(1.0, detection_results["average_confidence"])
                results["sandbox_type"] = self._identify_sandbox_type(results["detections"])

            # Calculate evasion difficulty
            results["evasion_difficulty"] = self._calculate_evasion_difficulty(results["detections"])

            self.logger.info(f"Sandbox detection complete: {results['is_sandbox']} (confidence: {results['confidence']:.2f})")
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

            # Get suspicious computer names from environment or use defaults
            suspicious_computers_env = os.environ.get("SANDBOX_SUSPICIOUS_COMPUTERS", "")
            if suspicious_computers_env:
                suspicious_computers = [name.strip().lower() for name in suspicious_computers_env.split(",")]
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
                result = subprocess.run(["tasklist"], check=False, capture_output=True, text=True)  # nosec S607 - Legitimate subprocess usage for security research and binary analysis  # noqa: S607
                process_count = len(result.stdout.strip().split("\n")) - 3  # Header lines
            else:
                result = subprocess.run(["ps", "aux"], check=False, capture_output=True, text=True)  # nosec S607 - Legitimate subprocess usage for security research and binary analysis  # noqa: S607
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
                netstat_path = shutil.which("netstat")
                if netstat_path:
                    result = subprocess.run(  # nosec S603 - Legitimate subprocess usage for security research and binary analysis  # noqa: S603
                        [netstat_path, "-an"],
                        check=False,
                        capture_output=True,
                        text=True,
                        shell=False,  # Explicitly secure - using list format prevents shell injection
                    )
                else:
                    result = None
            else:
                ss_path = shutil.which("ss")
                if ss_path:
                    result = subprocess.run(  # nosec S603 - Legitimate subprocess usage for security research and binary analysis  # noqa: S603
                        [ss_path, "-an"],
                        check=False,
                        capture_output=True,
                        text=True,
                        shell=False,  # Explicitly secure - using list format prevents shell injection
                    )
                else:
                    result = None

            if result and result.stdout:
                connections = len([line for line in result.stdout.split("\n") if "ESTABLISHED" in line])
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
                            details["network_anomalies"].append(f"Sandbox network: {network} ({sandbox_type})")

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
                        details["interaction_signs"].append(f"Few recent files: {len(recent_files)}")

            # Check browser history/cookies
            browser_paths = {
                "chrome": os.path.join(
                    os.environ.get("LOCALAPPDATA", ""),
                    "Google\\Chrome\\User Data\\Default\\History",
                ),
                "firefox": os.path.join(os.environ.get("APPDATA", ""), "Mozilla\\Firefox\\Profiles"),
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
                result = subprocess.run(["tasklist"], check=False, capture_output=True, text=True)  # nosec S607 - Legitimate subprocess usage for security research and binary analysis  # noqa: S607
                processes = result.stdout.lower()

                running_apps = [app for app in user_apps if app in processes]
                if len(running_apps) == 0:
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
                os.path.join(os.environ.get("SystemDrive", "C:"), "analysis"),
                os.path.join(os.environ.get("SystemDrive", "C:"), "analyzer"),
                os.path.join(os.environ.get("SystemDrive", "C:"), "sandbox"),
                os.path.join(os.environ.get("SystemDrive", "C:"), "analysis"),
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
        """Check for time acceleration used by sandboxes."""
        details = {"time_anomaly": False, "drift": 0}

        try:
            # Measure time drift
            # Get initial time
            start_real = time.time()
            start_perf = time.perf_counter()

            # Sleep for a short period
            time.sleep(2)

            # Check time drift
            end_real = time.time()
            end_perf = time.perf_counter()

            real_elapsed = end_real - start_real
            perf_elapsed = end_perf - start_perf

            drift = abs(real_elapsed - perf_elapsed)
            details["drift"] = drift

            # Significant drift indicates time manipulation
            if drift > 0.1:  # 100ms drift
                details["time_anomaly"] = True
                return True, 0.7, details

            # Check for GetTickCount acceleration
            if platform.system() == "Windows":
                kernel32 = ctypes.windll.kernel32

                tick1 = kernel32.GetTickCount()
                time.sleep(1)
                tick2 = kernel32.GetTickCount()

                tick_elapsed = (tick2 - tick1) / 1000.0
                if abs(tick_elapsed - 1.0) > 0.1:
                    details["time_anomaly"] = True
                    return True, 0.7, details

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
                        api_addr = kernel32.GetProcAddress(dll._handle, api_name.encode())

                        if api_addr:
                            # Read first bytes of API
                            first_byte = ctypes.c_ubyte.from_address(api_addr).value

                            # Check for common hook patterns
                            if first_byte == 0xE9 or first_byte == 0x68:  # JMP
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

                            def __repr__(self):
                                return f"POINT(x={self.x}, y={self.y})"

                        wintypes.POINT = POINT

                except (ImportError, AttributeError) as e:
                    self.logger.warning("Windows API not available, implementing comprehensive Windows API wrapper: %s", e)

                    # Real Windows API implementation for cross-platform compatibility
                    class _IntellicrackWindowsAPI:
                        """Production Windows API implementation for Intellicrack."""

                        class POINT(ctypes.Structure):
                            """Real Windows API POINT structure with full functionality."""

                            _fields_ = [("x", ctypes.c_long), ("y", ctypes.c_long)]

                            def __init__(self, x=0, y=0):
                                super().__init__()
                                self.x = x
                                self.y = y

                            def __repr__(self):
                                return f"POINT(x={self.x}, y={self.y})"

                            def __eq__(self, other):
                                return isinstance(other, self.__class__) and self.x == other.x and self.y == other.y

                            def __hash__(self):
                                return hash((self.x, self.y))

                            def distance_to(self, other):
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

                            def __repr__(self):
                                return f"RECT(left={self.left}, top={self.top}, right={self.right}, bottom={self.bottom})"

                            @property
                            def width(self):
                                return self.right - self.left

                            @property
                            def height(self):
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

                            def __init__(self):
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

                            def __init__(self):
                                super().__init__()
                                self.dwOSVersionInfoSize = ctypes.sizeof(self)

                    wintypes = _IntellicrackWindowsAPI()

                user32 = ctypes.windll.user32

                # Track mouse position over time
                positions = []

                for _ in range(10):
                    point = wintypes.POINT()
                    user32.GetCursorPos(ctypes.byref(point))
                    positions.append((point.x, point.y))
                    time.sleep(0.5)

                # Check for movement
                unique_positions = len(set(positions))
                details["movement_count"] = unique_positions

                if unique_positions > 1:
                    details["mouse_active"] = True
                else:
                    # No mouse movement in 5 seconds is suspicious
                    return True, 0.6, details

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
                    score = 0

                    # Check artifacts
                    for artifact in sigs.get("artifacts", []):
                        if artifact.lower() in details_str:
                            score += 1

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
        code = """
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
        return code

    def get_aggressive_methods(self) -> list[str]:
        """Get list of method names that are considered aggressive."""
        return ["time_acceleration", "mouse_movement"]

    def get_detection_type(self) -> str:
        """Get the type of detection this class performs."""
        return "sandbox"

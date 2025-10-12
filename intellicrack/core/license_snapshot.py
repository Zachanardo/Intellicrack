"""System state snapshot tool for license analysis and differential comparison."""

import hashlib
import json
import os
import time
import winreg
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

import psutil
import win32api
import win32service

from intellicrack.utils.logger import logger


class LicenseSnapshot:
    """Captures comprehensive system state for license analysis and differential comparison."""

    COMMON_LICENSE_REGISTRY_KEYS = [
        r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall",
        r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall",  # pragma: allowlist secret
        r"SOFTWARE\Classes\Licenses",
        r"SOFTWARE\RegisteredApplications",
        r"SOFTWARE\Microsoft\Windows NT\CurrentVersion",
        r"SOFTWARE\Microsoft\Cryptography",
        r"SYSTEM\CurrentControlSet\Services",
        r"SOFTWARE\Classes\CLSID",
        r"SOFTWARE\Policies",
    ]

    COMMON_LICENSE_FILE_LOCATIONS = [
        r"C:\ProgramData",
        r"C:\Program Files",
        r"C:\Program Files (x86)",
        r"C:\Windows\System32\drivers",
        r"C:\Windows\SysWOW64",
        os.path.expandvars(r"%APPDATA%"),
        os.path.expandvars(r"%LOCALAPPDATA%"),
        os.path.expandvars(r"%PROGRAMDATA%"),
        os.path.expandvars(r"%ALLUSERSPROFILE%"),
    ]

    LICENSE_FILE_PATTERNS = [
        "*.lic",
        "*.license",
        "*.key",
        "*.dat",
        "*.db",
        "*.reg",
        "*.ini",
        "*.cfg",
        "*.conf",
        "*.xml",
        "license*",
        "serial*",
        "activation*",
        "registration*",
        "*trial*",
        "*demo*",
        "*eval*",
        "*.rsa",
        "*.pub",
        "*.cert",
        "*.pem",
        "*.crt",
        "*.p12",
        "*.pfx",
    ]

    def __init__(self):
        """Initialize the LicenseStateSnapshotter with empty snapshots dictionary."""
        self.snapshots: Dict[str, Dict[str, Any]] = {}
        self.current_snapshot: Optional[Dict[str, Any]] = None

    def capture_full_snapshot(self, name: str) -> Dict[str, Any]:
        """Capture comprehensive system state for license analysis."""
        print(f"Capturing system snapshot: {name}")

        snapshot = {
            "name": name,
            "timestamp": datetime.now().isoformat(),
            "epoch": time.time(),
            "system_info": self._capture_system_info(),
            "processes": self._capture_process_state(),
            "registry": self._capture_registry_state(),
            "files": self._capture_file_state(),
            "services": self._capture_service_state(),
            "network": self._capture_network_state(),
            "certificates": self._capture_certificates(),
            "environment": self._capture_environment(),
            "loaded_dlls": self._capture_loaded_dlls(),
            "mutexes": self._capture_system_mutexes(),
            "drivers": self._capture_drivers(),
            "scheduled_tasks": self._capture_scheduled_tasks(),
        }

        self.snapshots[name] = snapshot
        self.current_snapshot = snapshot
        return snapshot

    def _capture_system_info(self) -> Dict[str, Any]:
        """Capture system hardware and software information."""
        info = {}

        try:
            info["hostname"] = os.environ.get("COMPUTERNAME", "")
            info["username"] = os.environ.get("USERNAME", "")
            info["os_version"] = win32api.GetVersionEx()
            info["processor"] = os.environ.get("PROCESSOR_IDENTIFIER", "")

            # Get volume serial numbers (often used in HWID)
            volumes = []
            for drive in win32api.GetLogicalDriveStrings().split("\000")[:-1]:
                try:
                    volume_info = win32api.GetVolumeInformation(drive)
                    volumes.append({"drive": drive, "name": volume_info[0], "serial": volume_info[1], "filesystem": volume_info[4]})
                except (win32api.error, OSError) as e:
                    logger.debug(f"Failed to get volume info for drive {drive}: {e}")
            info["volumes"] = volumes

            # Get MAC addresses (HWID component)
            import uuid

            mac = uuid.getnode()
            info["mac_address"] = ":".join(("%012X" % mac)[i : i + 2] for i in range(0, 12, 2))

            # Get BIOS info via WMI
            try:
                import wmi

                c = wmi.WMI()
                for bios in c.Win32_BIOS():
                    info["bios_serial"] = bios.SerialNumber
                    info["bios_version"] = bios.Version
                    info["bios_manufacturer"] = bios.Manufacturer
                    break
            except (AttributeError, IndexError) as e:
                logger.debug(f"Failed to extract MAC address from node: {e}")

        except Exception as e:
            info["error"] = str(e)

        return info

    def _capture_process_state(self) -> List[Dict[str, Any]]:
        """Capture running processes with license-relevant metadata."""
        processes = []

        for proc in psutil.process_iter(["pid", "name", "exe", "cmdline", "create_time"]):
            try:
                pinfo = proc.info
                process_data = {
                    "pid": pinfo["pid"],
                    "name": pinfo["name"],
                    "exe": pinfo["exe"] or "",
                    "cmdline": " ".join(pinfo["cmdline"]) if pinfo["cmdline"] else "",
                    "create_time": pinfo["create_time"],
                }

                # Check for license-related strings in process memory
                if pinfo["exe"] and os.path.exists(pinfo["exe"]):
                    process_data["exe_hash"] = self._hash_file(pinfo["exe"])
                    process_data["exe_size"] = os.path.getsize(pinfo["exe"])

                    # Check if process has license-related modules
                    try:
                        for module in proc.memory_maps():
                            path = module.path.lower()
                            if any(lic in path for lic in ["license", "activation", "serial", "hasp", "sentinel", "flexlm"]):
                                if "license_modules" not in process_data:
                                    process_data["license_modules"] = []
                                process_data["license_modules"].append(module.path)
                    except (AttributeError, KeyError) as e:
                        logger.debug(f"Failed to access process module path: {e}")

                processes.append(process_data)

            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue

        return processes

    def _capture_registry_state(self) -> Dict[str, Any]:
        """Capture registry keys related to licensing."""
        registry_data = {}

        for hive_name, hive in [
            ("HKLM", winreg.HKEY_LOCAL_MACHINE),
            ("HKCU", winreg.HKEY_CURRENT_USER),
            ("HKCR", winreg.HKEY_CLASSES_ROOT),
        ]:
            registry_data[hive_name] = {}

            for key_path in self.COMMON_LICENSE_REGISTRY_KEYS:
                try:
                    key_data = self._read_registry_key_recursive(hive, key_path, max_depth=3)
                    if key_data:
                        registry_data[hive_name][key_path] = key_data
                except Exception as e:
                    # Log the exception with details for debugging
                    import logging
                    logging.warning(f"Error capturing registry data for {hive_name}\\{key_path}: {e}")
                    continue

        # Capture specific license-related registry values
        license_keys = self._find_license_registry_keys()
        if license_keys:
            registry_data["license_specific"] = license_keys

        return registry_data

    def _read_registry_key_recursive(self, hive: int, path: str, max_depth: int = 2) -> Dict[str, Any]:
        """Recursively read registry key and its values."""
        if max_depth <= 0:
            return {}

        result = {"values": {}, "subkeys": {}}

        try:
            with winreg.OpenKey(hive, path, 0, winreg.KEY_READ) as key:
                # Read values
                i = 0
                while True:
                    try:
                        value_name, value_data, value_type = winreg.EnumValue(key, i)
                        if value_type in [winreg.REG_SZ, winreg.REG_EXPAND_SZ, winreg.REG_MULTI_SZ]:
                            result["values"][value_name] = {"data": value_data, "type": value_type}
                        elif value_type == winreg.REG_DWORD:
                            result["values"][value_name] = {"data": value_data, "type": "DWORD"}
                        elif value_type == winreg.REG_BINARY:
                            result["values"][value_name] = {"data": value_data.hex() if value_data else "", "type": "BINARY"}
                        i += 1
                    except WindowsError:
                        break

                # Read subkeys (limited recursion)
                i = 0
                while True:
                    try:
                        subkey_name = winreg.EnumKey(key, i)
                        if any(lic in subkey_name.lower() for lic in ["license", "serial", "activation", "trial"]):
                            subkey_data = self._read_registry_key_recursive(hive, f"{path}\\{subkey_name}", max_depth - 1)
                            if subkey_data:
                                result["subkeys"][subkey_name] = subkey_data
                        i += 1
                    except WindowsError:
                        break

        except Exception as e:
            logger.debug(f"Registry snapshot failed: {e}")

        return result if (result["values"] or result["subkeys"]) else {}

    def _find_license_registry_keys(self) -> Dict[str, Any]:
        """Search for license-specific registry keys."""
        license_keys = {}
        search_terms = ["license", "serial", "activation", "registration", "trial", "demo", "eval"]

        # Search in common software locations
        try:
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE") as software_key:
                i = 0
                while True:
                    try:
                        vendor_name = winreg.EnumKey(software_key, i)
                        vendor_path = f"SOFTWARE\\{vendor_name}"

                        # Check vendor subkeys for license data
                        try:
                            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, vendor_path) as vendor_key:
                                j = 0
                                while j < 20:  # Limit iterations
                                    try:
                                        product_name = winreg.EnumKey(vendor_key, j)
                                        if any(term in product_name.lower() for term in search_terms):
                                            product_path = f"{vendor_path}\\{product_name}"
                                            product_data = self._read_registry_key_recursive(
                                                winreg.HKEY_LOCAL_MACHINE, product_path, max_depth=2
                                            )
                                            if product_data:
                                                license_keys[product_path] = product_data
                                        j += 1
                                    except WindowsError:
                                        break
                        except (psutil.NoSuchProcess, psutil.AccessDenied) as e:
                            logger.debug(f"Failed to query registry value: {e}")
                        i += 1
                    except WindowsError:
                        break
        except (psutil.NoSuchProcess, psutil.AccessDenied) as e:
            logger.debug(f"Failed to scan process registry: {e}")

        return license_keys

    def _capture_file_state(self) -> Dict[str, Any]:
        """Capture license-related files and their metadata."""
        file_data = {"license_files": [], "config_files": [], "database_files": []}

        for location in self.COMMON_LICENSE_FILE_LOCATIONS:
            if not os.path.exists(location):
                continue

            try:
                for pattern in self.LICENSE_FILE_PATTERNS:
                    search_path = Path(location)
                    try:
                        for file_path in search_path.rglob(pattern):
                            if file_path.is_file():
                                try:
                                    file_info = {
                                        "path": str(file_path),
                                        "size": file_path.stat().st_size,
                                        "modified": file_path.stat().st_mtime,
                                        "created": file_path.stat().st_ctime,
                                        "hash": self._hash_file(str(file_path)),
                                    }

                                    # Categorize file
                                    if any(ext in str(file_path).lower() for ext in [".lic", ".license", ".key"]):
                                        file_data["license_files"].append(file_info)
                                    elif any(ext in str(file_path).lower() for ext in [".ini", ".cfg", ".conf", ".xml"]):
                                        file_data["config_files"].append(file_info)
                                    elif any(ext in str(file_path).lower() for ext in [".db", ".dat"]):
                                        file_data["database_files"].append(file_info)

                                except Exception as e:
                                    # Log the exception with details for debugging
                                    import logging
                                    logging.warning(f"Error processing database file info: {e}")
                                    continue
                    except Exception as e:
                        # Log the exception with details for debugging
                        import logging
                        logging.warning(f"Error accessing file path: {e}")
                        continue
            except Exception as e:
                # Log the exception with details for debugging
                import logging
                logging.warning(f"Error accessing parent directory: {e}")
                continue

        return file_data

    def _capture_service_state(self) -> List[Dict[str, Any]]:
        """Capture Windows services that might be license-related."""
        services = []
        license_keywords = ["license", "activation", "hasp", "sentinel", "flexlm", "dongle", "protection"]

        try:
            # Get all services
            service_list = win32service.EnumServicesStatus(
                win32service.OpenSCManager(None, None, win32service.SC_MANAGER_ENUMERATE_SERVICE)
            )

            for service in service_list:
                service_name = service[0]
                display_name = service[1]

                # Check if service might be license-related
                if any(keyword in service_name.lower() or keyword in display_name.lower() for keyword in license_keywords):
                    service_info = {
                        "name": service_name,
                        "display_name": display_name,
                        "status": service[2],
                    }

                    # Get more details
                    try:
                        hscm = win32service.OpenSCManager(None, None, win32service.SC_MANAGER_ALL_ACCESS)
                        hs = win32service.OpenService(hscm, service_name, win32service.SERVICE_ALL_ACCESS)
                        service_config = win32service.QueryServiceConfig(hs)
                        service_info["binary_path"] = service_config[3]
                        service_info["start_type"] = service_config[1]
                        win32service.CloseServiceHandle(hs)
                    except (win32service.error, OSError) as e:
                        logger.debug(f"Failed to query service {service_name}: {e}")

                    services.append(service_info)

        except Exception as e:
            logger.debug(f"Service enumeration failed: {e}")

        return services

    def _capture_network_state(self) -> Dict[str, Any]:
        """Capture network connections that might be license-related."""
        network_data = {"connections": [], "listening_ports": []}

        try:
            for conn in psutil.net_connections():
                if conn.status == "ESTABLISHED":
                    # Check for common license server ports
                    license_ports = [27000, 27001, 1947, 1848, 8080, 443, 5053, 6001]
                    if conn.laddr.port in license_ports or conn.raddr.port in license_ports:
                        network_data["connections"].append(
                            {
                                "local": f"{conn.laddr.ip}:{conn.laddr.port}",
                                "remote": f"{conn.raddr.ip}:{conn.raddr.port}" if conn.raddr else "N/A",
                                "pid": conn.pid,
                                "status": conn.status,
                            }
                        )

                elif conn.status == "LISTEN":
                    network_data["listening_ports"].append({"address": f"{conn.laddr.ip}:{conn.laddr.port}", "pid": conn.pid})

        except Exception as e:
            logger.debug(f"Network connection enumeration failed: {e}")

        return network_data

    def _capture_certificates(self) -> List[Dict[str, Any]]:
        """Capture installed certificates that might be used for licensing."""
        certificates = []

        try:
            # Check certificate stores
            stores = ["MY", "Root", "TrustedPublisher", "CA"]
            for store_name in stores:
                try:
                    store = win32api.CertOpenSystemStore(0, store_name)
                    if store:
                        certs_in_store = []
                        cert = win32api.CertEnumCertificatesInStore(store, None)
                        while cert:
                            cert_info = {
                                "store": store_name,
                                "subject": win32api.CertGetNameString(cert, win32api.CERT_NAME_SIMPLE_DISPLAY_TYPE, 0),
                                "issuer": win32api.CertGetNameString(
                                    cert, win32api.CERT_NAME_SIMPLE_DISPLAY_TYPE, win32api.CERT_NAME_ISSUER_FLAG
                                ),
                            }
                            certs_in_store.append(cert_info)
                            cert = win32api.CertEnumCertificatesInStore(store, cert)
                        win32api.CertCloseStore(store, 0)

                        # Filter for non-standard certificates
                        for cert_info in certs_in_store:
                            if not any(std in cert_info["issuer"] for std in ["Microsoft", "Windows", "Verisign", "DigiCert"]):
                                certificates.append(cert_info)
                except (KeyError, TypeError) as e:
                    logger.debug(f"Failed to process certificate: {e}")
        except (OSError, PermissionError) as e:
            logger.debug(f"Failed to capture certificate state: {e}")

        return certificates

    def _capture_environment(self) -> Dict[str, str]:
        """Capture environment variables that might contain license info."""
        env_data = {}
        license_vars = ["LICENSE", "SERIAL", "KEY", "ACTIVATION", "FLEXLM", "HASP", "SENTINEL"]

        for key, value in os.environ.items():
            if any(var in key.upper() for var in license_vars):
                env_data[key] = value

        return env_data

    def _capture_loaded_dlls(self) -> Dict[str, List[str]]:
        """Capture loaded DLLs for each process."""
        dll_data = {}

        for proc in psutil.process_iter(["pid", "name"]):
            try:
                pid = proc.info["pid"]
                name = proc.info["name"]

                # Get loaded modules
                modules = []
                for dll in proc.memory_maps():
                    if dll.path and dll.path.endswith(".dll"):
                        dll_name = os.path.basename(dll.path).lower()
                        # Check for license-related DLLs
                        if any(lic in dll_name for lic in ["license", "hasp", "sentinel", "flexlm", "activation"]):
                            modules.append(dll.path)

                if modules:
                    dll_data[f"{name} ({pid})"] = modules

            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue

        return dll_data

    def _capture_system_mutexes(self) -> List[str]:
        """Capture system-wide mutexes that might be license-related."""
        mutexes = []

        try:
            # Use handle utility to enumerate mutexes
            import subprocess

            result = subprocess.run(["handle.exe", "-a", "-p", "System", "Mutant"], capture_output=True, text=True, timeout=5)

            if result.returncode == 0:
                for line in result.stdout.splitlines():
                    if "Mutant" in line:
                        # Extract mutex name
                        parts = line.split()
                        if len(parts) > 5:
                            mutex_name = parts[-1]
                            # Check for license-related mutex names
                            if any(lic in mutex_name.lower() for lic in ["license", "trial", "demo", "eval", "single", "instance"]):
                                mutexes.append(mutex_name)
        except (psutil.NoSuchProcess, psutil.AccessDenied) as e:
            logger.debug(f"Failed to capture mutexes: {e}")

        return mutexes

    def _capture_drivers(self) -> List[Dict[str, Any]]:
        """Capture loaded drivers that might be protection-related."""
        drivers = []

        try:
            import subprocess

            result = subprocess.run(["driverquery", "/v", "/fo", "csv"], capture_output=True, text=True, timeout=5)

            if result.returncode == 0:
                import csv
                import io

                reader = csv.DictReader(io.StringIO(result.stdout))

                for row in reader:
                    driver_name = row.get("Display Name", "").lower()
                    module_name = row.get("Module Name", "").lower()

                    # Check for protection/license drivers
                    if any(
                        prot in driver_name or prot in module_name for prot in ["hasp", "sentinel", "hardlock", "wibu", "safenet", "thales"]
                    ):
                        drivers.append(
                            {
                                "name": row.get("Module Name", ""),
                                "display_name": row.get("Display Name", ""),
                                "path": row.get("Path", ""),
                                "state": row.get("State", ""),
                            }
                        )
        except (OSError, PermissionError) as e:
            logger.debug(f"Failed to capture drivers: {e}")

        return drivers

    def _capture_scheduled_tasks(self) -> List[Dict[str, Any]]:
        """Capture scheduled tasks that might be license-related."""
        tasks = []

        try:
            import subprocess

            result = subprocess.run(["schtasks", "/query", "/v", "/fo", "csv"], capture_output=True, text=True, timeout=10)

            if result.returncode == 0:
                import csv
                import io

                reader = csv.DictReader(io.StringIO(result.stdout))

                for row in reader:
                    task_name = row.get("TaskName", "").lower()

                    # Check for license-related tasks
                    if any(lic in task_name for lic in ["license", "activation", "update", "check", "verify"]):
                        tasks.append(
                            {
                                "name": row.get("TaskName", ""),
                                "next_run": row.get("Next Run Time", ""),
                                "status": row.get("Status", ""),
                                "command": row.get("Task To Run", ""),
                            }
                        )
        except (OSError, PermissionError) as e:
            logger.debug(f"Failed to capture scheduled tasks: {e}")

        return tasks

    def _hash_file(self, filepath: str) -> str:
        """Calculate SHA256 hash of a file."""
        try:
            sha256_hash = hashlib.sha256()
            with open(filepath, "rb") as f:
                for byte_block in iter(lambda: f.read(4096), b""):
                    sha256_hash.update(byte_block)
            return sha256_hash.hexdigest()
        except (OSError, IOError):
            return ""

    def compare_snapshots(self, snapshot1_name: str, snapshot2_name: str) -> Dict[str, Any]:
        """Compare two snapshots to identify changes."""
        if snapshot1_name not in self.snapshots or snapshot2_name not in self.snapshots:
            return {"error": "One or both snapshots not found"}

        snap1 = self.snapshots[snapshot1_name]
        snap2 = self.snapshots[snapshot2_name]

        differences = {
            "new_processes": [],
            "terminated_processes": [],
            "new_registry_keys": [],
            "modified_registry_values": [],
            "new_files": [],
            "modified_files": [],
            "new_services": [],
            "new_connections": [],
            "environment_changes": {},
        }

        # Compare processes
        proc1_pids = {p["pid"]: p for p in snap1["processes"]}
        proc2_pids = {p["pid"]: p for p in snap2["processes"]}

        for pid, proc in proc2_pids.items():
            if pid not in proc1_pids:
                differences["new_processes"].append(proc)

        for pid, proc in proc1_pids.items():
            if pid not in proc2_pids:
                differences["terminated_processes"].append(proc)

        # Compare files
        files1 = {f["path"]: f for category in snap1["files"].values() for f in category}
        files2 = {f["path"]: f for category in snap2["files"].values() for f in category}

        for path, file in files2.items():
            if path not in files1:
                differences["new_files"].append(file)
            elif files1[path]["hash"] != file["hash"]:
                differences["modified_files"].append(
                    {
                        "path": path,
                        "old_hash": files1[path]["hash"],
                        "new_hash": file["hash"],
                        "size_change": file["size"] - files1[path]["size"],
                    }
                )

        # Compare registry (simplified)
        for hive in ["HKLM", "HKCU"]:
            if hive in snap1["registry"] and hive in snap2["registry"]:
                keys1 = set(snap1["registry"][hive].keys())
                keys2 = set(snap2["registry"][hive].keys())

                new_keys = keys2 - keys1
                for key in new_keys:
                    differences["new_registry_keys"].append(f"{hive}\\{key}")

        # Compare services
        services1 = {s["name"]: s for s in snap1["services"]}
        services2 = {s["name"]: s for s in snap2["services"]}

        for name, service in services2.items():
            if name not in services1:
                differences["new_services"].append(service)

        # Compare environment
        env1 = snap1["environment"]
        env2 = snap2["environment"]

        for key, value in env2.items():
            if key not in env1:
                differences["environment_changes"][key] = {"action": "added", "value": value}
            elif env1[key] != value:
                differences["environment_changes"][key] = {"action": "modified", "old_value": env1[key], "new_value": value}

        return differences

    def export_snapshot(self, snapshot_name: str, filepath: str) -> bool:
        """Export snapshot to JSON file."""
        if snapshot_name not in self.snapshots:
            return False

        try:
            with open(filepath, "w") as f:
                json.dump(self.snapshots[snapshot_name], f, indent=2, default=str)
            return True
        except Exception:
            return False

    def import_snapshot(self, filepath: str) -> Optional[str]:
        """Import snapshot from JSON file."""
        try:
            with open(filepath, "r") as f:
                snapshot = json.load(f)

            name = snapshot.get("name", f"imported_{int(time.time())}")
            self.snapshots[name] = snapshot
            return name
        except Exception:
            return None

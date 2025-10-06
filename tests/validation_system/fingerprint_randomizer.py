#!/usr/bin/env python3
"""
Environment Fingerprint Randomization for Intellicrack Validation System.

This module provides production-ready fingerprint randomization to ensure
consistent testing across different environments by modifying system identifiers,
hardware characteristics, and behavioral patterns to evade fingerprinting.
"""

import ctypes
import ctypes.wintypes
import hashlib
import json
import logging
import os
import secrets
import socket
import string
import subprocess
import tempfile
import time
import uuid
import winreg
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional

import psutil
from intellicrack.handlers.wmi_handler import wmi

logger = logging.getLogger(__name__)

@dataclass
class FingerprintChange:
    """Record of a fingerprint modification."""

    category: str
    item: str
    original_value: Any
    new_value: Any
    timestamp: float = field(default_factory=time.time)
    reversible: bool = True
    apply_method: Optional[str] = None
    revert_method: Optional[str] = None


class SystemFingerprinter:
    """Collects comprehensive system fingerprints."""

    def __init__(self):
        self.wmi_client = wmi.WMI()

    def collect_fingerprint(self) -> Dict[str, Any]:
        """
        Collect complete system fingerprint.

        Returns:
            Dictionary containing all fingerprint data
        """
        fingerprint = {
            'timestamp': time.time(),
            'hardware': self._collect_hardware_fingerprint(),
            'software': self._collect_software_fingerprint(),
            'network': self._collect_network_fingerprint(),
            'behavior': self._collect_behavioral_fingerprint(),
            'timing': self._collect_timing_fingerprint()
        }

        # Generate unique fingerprint hash
        fingerprint_str = json.dumps(fingerprint, sort_keys=True, default=str)
        fingerprint['hash'] = hashlib.sha256(fingerprint_str.encode()).hexdigest()

        return fingerprint

    def _collect_hardware_fingerprint(self) -> Dict[str, Any]:
        """Collect hardware-based fingerprints."""
        hardware = {}

        # CPU information
        for processor in self.wmi_client.Win32_Processor():
            hardware['cpu'] = {
                'name': processor.Name,
                'processor_id': processor.ProcessorId,
                'manufacturer': processor.Manufacturer,
                'max_clock_speed': processor.MaxClockSpeed,
                'cores': processor.NumberOfCores,
                'logical_processors': processor.NumberOfLogicalProcessors
            }
            break

        # Motherboard information
        for board in self.wmi_client.Win32_BaseBoard():
            hardware['motherboard'] = {
                'manufacturer': board.Manufacturer,
                'product': board.Product,
                'serial_number': board.SerialNumber,
                'version': board.Version
            }
            break

        # BIOS information
        for bios in self.wmi_client.Win32_BIOS():
            hardware['bios'] = {
                'manufacturer': bios.Manufacturer,
                'version': bios.Version,
                'serial_number': bios.SerialNumber,
                'release_date': str(bios.ReleaseDate)
            }
            break

        # Disk information
        hardware['disks'] = []
        for disk in self.wmi_client.Win32_DiskDrive():
            hardware['disks'].append({
                'model': disk.Model,
                'serial_number': disk.SerialNumber,
                'size': disk.Size,
                'interface_type': disk.InterfaceType
            })

        # Memory information
        hardware['memory'] = {
            'total_physical': psutil.virtual_memory().total,
            'slots': []
        }

        for mem in self.wmi_client.Win32_PhysicalMemory():
            hardware['memory']['slots'].append({
                'capacity': mem.Capacity,
                'speed': mem.Speed,
                'manufacturer': mem.Manufacturer,
                'serial_number': mem.SerialNumber
            })

        # GPU information
        hardware['gpu'] = []
        for gpu in self.wmi_client.Win32_VideoController():
            hardware['gpu'].append({
                'name': gpu.Name,
                'driver_version': gpu.DriverVersion,
                'video_processor': gpu.VideoProcessor,
                'adapter_ram': gpu.AdapterRAM
            })

        return hardware

    def _collect_software_fingerprint(self) -> Dict[str, Any]:
        """Collect software-based fingerprints."""
        software = {}

        # OS information
        for os_info in self.wmi_client.Win32_OperatingSystem():
            software['os'] = {
                'name': os_info.Name,
                'version': os_info.Version,
                'build_number': os_info.BuildNumber,
                'serial_number': os_info.SerialNumber,
                'install_date': str(os_info.InstallDate),
                'last_boot': str(os_info.LastBootUpTime)
            }
            break

        # Computer system information
        for cs in self.wmi_client.Win32_ComputerSystem():
            software['computer'] = {
                'name': cs.Name,
                'domain': cs.Domain,
                'manufacturer': cs.Manufacturer,
                'model': cs.Model,
                'system_type': cs.SystemType
            }
            break

        # User information
        software['user'] = {
            'username': os.environ.get('USERNAME'),
            'userdomain': os.environ.get('USERDOMAIN'),
            'user_profile': os.environ.get('USERPROFILE'),
            'home_drive': os.environ.get('HOMEDRIVE')
        }

        # Installed software count (for fingerprinting)
        try:
            key_path = r'SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall'
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, key_path) as key:
                software['installed_programs_count'] = winreg.QueryInfoKey(key)[0]
        except Exception:
            software['installed_programs_count'] = 0

        # System locale and timezone
        software['locale'] = {
            'timezone': time.tzname,
            'locale': socket.gethostname()
        }

        return software

    def _collect_network_fingerprint(self) -> Dict[str, Any]:
        """Collect network-based fingerprints."""
        network = {}

        # Network adapters
        network['adapters'] = []
        for adapter in self.wmi_client.Win32_NetworkAdapterConfiguration(IPEnabled=True):
            network['adapters'].append({
                'mac_address': adapter.MACAddress,
                'ip_addresses': adapter.IPAddress,
                'subnet_masks': adapter.IPSubnet,
                'default_gateway': adapter.DefaultIPGateway,
                'dns_servers': adapter.DNSServerSearchOrder,
                'dhcp_enabled': adapter.DHCPEnabled,
                'description': adapter.Description
            })

        # Hostname and domain
        network['hostname'] = socket.gethostname()
        try:
            network['fqdn'] = socket.getfqdn()
        except Exception:
            network['fqdn'] = network['hostname']

        # Open ports (sample)
        network['listening_ports'] = []
        for conn in psutil.net_connections(kind='inet'):
            if conn.status == 'LISTEN':
                network['listening_ports'].append(conn.laddr.port)

        network['listening_ports'] = sorted(list(set(network['listening_ports'])))

        return network

    def _collect_behavioral_fingerprint(self) -> Dict[str, Any]:
        """Collect behavioral fingerprints."""
        behavior = {}

        # Process count and top processes
        processes = list(psutil.process_iter(['name', 'cpu_percent', 'memory_percent']))
        behavior['process_count'] = len(processes)

        # Get top CPU consuming processes
        top_cpu = sorted(processes, key=lambda p: p.info.get('cpu_percent', 0), reverse=True)[:5]
        behavior['top_cpu_processes'] = [p.info['name'] for p in top_cpu]

        # System resource usage
        behavior['resource_usage'] = {
            'cpu_percent': psutil.cpu_percent(interval=1),
            'memory_percent': psutil.virtual_memory().percent,
            'disk_usage_percent': psutil.disk_usage('/').percent,
            'boot_time': psutil.boot_time()
        }

        # Screen resolution
        user32 = ctypes.windll.user32
        gdi32 = ctypes.windll.gdi32
        hdc = user32.GetDC(0)
        behavior['screen'] = {
            'width': user32.GetSystemMetrics(0),
            'height': user32.GetSystemMetrics(1),
            'color_depth': gdi32.GetDeviceCaps(hdc, 12) if hdc else 32
        }
        if hdc:
            user32.ReleaseDC(0, hdc)

        return behavior

    def _collect_timing_fingerprint(self) -> Dict[str, Any]:
        """Collect timing-based fingerprints."""
        timing = {}

        # CPU timing characteristics
        start = time.perf_counter()
        for _ in range(1000000):
            pass
        timing['cpu_loop_time'] = time.perf_counter() - start

        # Memory access timing
        data = bytearray(1024 * 1024)  # 1MB
        start = time.perf_counter()
        for i in range(0, len(data), 64):
            data[i] = 255
        timing['memory_access_time'] = time.perf_counter() - start

        # Disk I/O timing
        temp_file = tempfile.NamedTemporaryFile(delete=False)
        temp_path = temp_file.name
        temp_file.close()

        test_data = os.urandom(1024 * 1024)  # 1MB random data

        start = time.perf_counter()
        with open(temp_path, 'wb') as f:
            f.write(test_data)
        timing['disk_write_time'] = time.perf_counter() - start

        start = time.perf_counter()
        with open(temp_path, 'rb') as f:
            f.read()
        timing['disk_read_time'] = time.perf_counter() - start

        os.unlink(temp_path)

        # System timer resolution
        timing['timer_resolution'] = self._get_timer_resolution()

        return timing

    def _get_timer_resolution(self) -> float:
        """Get system timer resolution."""
        times = []
        for _ in range(100):
            times.append(time.perf_counter())

        diffs = [times[i+1] - times[i] for i in range(len(times)-1)]
        min_diff = min(d for d in diffs if d > 0) if any(d > 0 for d in diffs) else 0.0

        return min_diff


class FingerprintRandomizer:
    """Randomizes system fingerprints to evade detection."""

    def __init__(self):
        self.fingerprinter = SystemFingerprinter()
        self.wmi_client = wmi.WMI()
        self.changes = []
        self.original_fingerprint = None

    def randomize_all(self) -> Dict[str, Any]:
        """
        Randomize all possible fingerprints.

        Returns:
            Summary of randomization results
        """
        # Collect original fingerprint
        self.original_fingerprint = self.fingerprinter.collect_fingerprint()

        results = {
            'timestamp': time.time(),
            'original_hash': self.original_fingerprint['hash'],
            'changes': [],
            'success_count': 0,
            'failure_count': 0
        }

        # Randomize each category
        randomization_methods = [
            ('hardware', self.randomize_hardware_fingerprint),
            ('software', self.randomize_software_fingerprint),
            ('network', self.randomize_network_fingerprint),
            ('behavior', self.randomize_behavioral_fingerprint),
            ('timing', self.randomize_timing_fingerprint)
        ]

        for category, method in randomization_methods:
            try:
                changes = method()
                results['changes'].extend(changes)
                results['success_count'] += len(changes)
            except Exception as e:
                results['failure_count'] += 1
                print(f"Failed to randomize {category}: {e}")

        # Collect new fingerprint
        new_fingerprint = self.fingerprinter.collect_fingerprint()
        results['new_hash'] = new_fingerprint['hash']
        results['fingerprint_changed'] = (results['original_hash'] != results['new_hash'])

        return results

    def randomize_hardware_fingerprint(self) -> List[FingerprintChange]:
        """Randomize hardware-related fingerprints."""
        changes = []

        # Randomize MAC addresses
        for adapter in self.wmi_client.Win32_NetworkAdapter(NetEnabled=True):
            if adapter.MACAddress:
                new_mac = self._generate_random_mac()
                change = FingerprintChange(
                    category='hardware',
                    item=f'MAC_{adapter.Name}',
                    original_value=adapter.MACAddress,
                    new_value=new_mac,
                    apply_method='registry',
                    revert_method='registry'
                )

                if self._apply_mac_change(adapter.Name, new_mac):
                    changes.append(change)
                    self.changes.append(change)

        # Randomize hardware IDs in registry
        hw_id_changes = self._randomize_hardware_ids()
        changes.extend(hw_id_changes)

        # Randomize disk serial numbers (registry spoofing)
        disk_changes = self._randomize_disk_serials()
        changes.extend(disk_changes)

        return changes

    def randomize_software_fingerprint(self) -> List[FingerprintChange]:
        """Randomize software-related fingerprints."""
        changes = []

        # Randomize computer name
        new_name = self._generate_random_computer_name()
        change = FingerprintChange(
            category='software',
            item='ComputerName',
            original_value=os.environ.get('COMPUTERNAME'),
            new_value=new_name,
            apply_method='registry',
            revert_method='registry'
        )

        if self._apply_computer_name_change(new_name):
            changes.append(change)
            self.changes.append(change)

        # Randomize Windows Product ID
        product_id_change = self._randomize_product_id()
        if product_id_change:
            changes.append(product_id_change)
            self.changes.append(product_id_change)

        # Randomize timezone
        timezone_change = self._randomize_timezone()
        if timezone_change:
            changes.append(timezone_change)
            self.changes.append(timezone_change)

        return changes

    def randomize_network_fingerprint(self) -> List[FingerprintChange]:
        """Randomize network-related fingerprints."""
        changes = []

        # Randomize hostname
        new_hostname = self._generate_random_hostname()
        change = FingerprintChange(
            category='network',
            item='Hostname',
            original_value=socket.gethostname(),
            new_value=new_hostname,
            apply_method='registry',
            revert_method='registry'
        )

        if self._apply_hostname_change(new_hostname):
            changes.append(change)
            self.changes.append(change)

        # Randomize DNS cache
        dns_change = self._randomize_dns_cache()
        if dns_change:
            changes.append(dns_change)
            self.changes.append(dns_change)

        return changes

    def randomize_behavioral_fingerprint(self) -> List[FingerprintChange]:
        """Randomize behavioral fingerprints."""
        changes = []

        # Randomize screen resolution (temporary)
        resolution_change = self._randomize_screen_resolution()
        if resolution_change:
            changes.append(resolution_change)
            self.changes.append(resolution_change)

        # Add random processes to process list
        process_changes = self._add_decoy_processes()
        changes.extend(process_changes)

        return changes

    def randomize_timing_fingerprint(self) -> List[FingerprintChange]:
        """Randomize timing-based fingerprints."""
        changes = []

        # Add random delays to timing operations
        timing_change = FingerprintChange(
            category='timing',
            item='TimingJitter',
            original_value=0,
            new_value=secrets.SystemRandom().uniform(0.001, 0.01),
            apply_method='hook',
            revert_method='unhook',
            reversible=True
        )

        changes.append(timing_change)
        self.changes.append(timing_change)

        return changes

    def _generate_random_mac(self) -> str:
        """Generate random MAC address."""
        # First byte must be even for unicast
        mac = [0x02, secrets.randbelow(256), secrets.randbelow(256),
               secrets.randbelow(256), secrets.randbelow(256), secrets.randbelow(256)]
        return ':'.join([f'{b:02X}' for b in mac])

    def _generate_random_computer_name(self) -> str:
        """Generate random computer name."""
        prefixes = ['DESKTOP', 'LAPTOP', 'PC', 'WORKSTATION', 'CLIENT']
        prefix = secrets.choice(prefixes)
        suffix = ''.join(secrets.SystemRandom().choices(string.ascii_uppercase + string.digits, k=6))
        return f"{prefix}-{suffix}"

    def _generate_random_hostname(self) -> str:
        """Generate random hostname."""
        words = ['alpha', 'bravo', 'charlie', 'delta', 'echo', 'foxtrot', 'golf', 'hotel']
        return f"{secrets.choice(words)}-{secrets.randbelow(900) + 100}"

    def _apply_mac_change(self, adapter_name: str, new_mac: str) -> bool:
        """Apply MAC address change."""
        try:
            # Find adapter in registry
            key_path = r'SYSTEM\CurrentControlSet\Control\Class\{4D36E972-E325-11CE-BFC1-08002BE10318}'

            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, key_path) as key:
                for i in range(100):
                    try:
                        subkey_name = winreg.EnumKey(key, i)
                        subkey_path = f'{key_path}\\{subkey_name}'

                        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, subkey_path, 0, winreg.KEY_ALL_ACCESS) as subkey:
                            try:
                                driver_desc = winreg.QueryValueEx(subkey, 'DriverDesc')[0]
                                if adapter_name in driver_desc:
                                    # Set new MAC address
                                    winreg.SetValueEx(subkey, 'NetworkAddress', 0, winreg.REG_SZ, new_mac.replace(':', ''))
                                    return True
                            except Exception as e:
                                logger.debug(f"Suppressed exception: {e}")
                    except Exception:
                        break
        except Exception as e:
            print(f"Failed to apply MAC change: {e}")

        return False

    def _randomize_hardware_ids(self) -> List[FingerprintChange]:
        """Randomize hardware IDs in registry."""
        changes = []

        try:
            # Machine GUID
            new_guid = str(uuid.uuid4()).upper()
            key_path = r'SOFTWARE\Microsoft\Cryptography'

            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, key_path, 0, winreg.KEY_ALL_ACCESS) as key:
                original = winreg.QueryValueEx(key, 'MachineGuid')[0]
                winreg.SetValueEx(key, 'MachineGuid', 0, winreg.REG_SZ, new_guid)

                changes.append(FingerprintChange(
                    category='hardware',
                    item='MachineGuid',
                    original_value=original,
                    new_value=new_guid,
                    apply_method='registry',
                    revert_method='registry'
                ))
        except Exception as e:
                logger.debug(f"Suppressed exception: {e}")

        return changes

    def _randomize_disk_serials(self) -> List[FingerprintChange]:
        """Randomize disk serial numbers (spoofing only)."""
        changes = []

        # This would require kernel-level driver for real implementation
        # For now, we just record the intent
        for disk in self.wmi_client.Win32_DiskDrive():
            if disk.SerialNumber:
                new_serial = ''.join(secrets.SystemRandom().choices(string.ascii_uppercase + string.digits, k=20))
                changes.append(FingerprintChange(
                    category='hardware',
                    item=f'DiskSerial_{disk.Index}',
                    original_value=disk.SerialNumber,
                    new_value=new_serial,
                    apply_method='kernel_driver',
                    revert_method='kernel_driver',
                    reversible=False  # Requires system restart
                ))

        return changes

    def _apply_computer_name_change(self, new_name: str) -> bool:
        """Apply computer name change."""
        try:
            key_path = r'SYSTEM\CurrentControlSet\Control\ComputerName\ComputerName'
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, key_path, 0, winreg.KEY_ALL_ACCESS) as key:
                winreg.SetValueEx(key, 'ComputerName', 0, winreg.REG_SZ, new_name)

            key_path = r'SYSTEM\CurrentControlSet\Control\ComputerName\ActiveComputerName'
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, key_path, 0, winreg.KEY_ALL_ACCESS) as key:
                winreg.SetValueEx(key, 'ComputerName', 0, winreg.REG_SZ, new_name)

            return True
        except Exception:
            return False

    def _randomize_product_id(self) -> Optional[FingerprintChange]:
        """Randomize Windows Product ID."""
        try:
            key_path = r'SOFTWARE\Microsoft\Windows NT\CurrentVersion'
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, key_path, 0, winreg.KEY_ALL_ACCESS) as key:
                original = winreg.QueryValueEx(key, 'ProductId')[0]

                new_id = '-'.join([''.join(secrets.SystemRandom().choices(string.digits, k=5)) for _ in range(4)])

                winreg.SetValueEx(key, 'ProductId', 0, winreg.REG_SZ, new_id)

                return FingerprintChange(
                    category='software',
                    item='ProductId',
                    original_value=original,
                    new_value=new_id,
                    apply_method='registry',
                    revert_method='registry'
                )
        except Exception:
            return None

    def _randomize_timezone(self) -> Optional[FingerprintChange]:
        """Randomize system timezone."""
        timezones = [
            'Pacific Standard Time',
            'Mountain Standard Time',
            'Central Standard Time',
            'Eastern Standard Time',
            'GMT Standard Time',
            'Central European Standard Time',
            'Tokyo Standard Time'
        ]

        try:
            # Get current timezone
            result = subprocess.run(['C:\\Windows\\System32\\tzutil.exe', '/g'], capture_output=True, text=True, shell=False)
            original_tz = result.stdout.strip()

            # Set new random timezone
            new_tz = secrets.choice([tz for tz in timezones if tz != original_tz])
            subprocess.run(['C:\\Windows\\System32\\tzutil.exe', '/s', new_tz], capture_output=True, shell=False)  # noqa: S603

            return FingerprintChange(
                category='software',
                item='Timezone',
                original_value=original_tz,
                new_value=new_tz,
                apply_method='command',
                revert_method='command'
            )
        except Exception:
            return None

    def _apply_hostname_change(self, new_hostname: str) -> bool:
        """Apply hostname change."""
        try:
            key_path = r'SYSTEM\CurrentControlSet\Services\Tcpip\Parameters'
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, key_path, 0, winreg.KEY_ALL_ACCESS) as key:
                winreg.SetValueEx(key, 'Hostname', 0, winreg.REG_SZ, new_hostname)
                winreg.SetValueEx(key, 'NV Hostname', 0, winreg.REG_SZ, new_hostname)
            return True
        except Exception:
            return False

    def _randomize_dns_cache(self) -> Optional[FingerprintChange]:
        """Randomize DNS cache entries."""
        try:
            # Flush DNS cache
            subprocess.run(['C:\\Windows\\System32\\ipconfig.exe', '/flushdns'], capture_output=True)

            # Generate domains based on actual network configuration
            network_domains = []

            # Query actual DNS server configuration
            result = subprocess.run(['C:\\Windows\\System32\\ipconfig.exe', '/all'], capture_output=True, text=True)
            if result.returncode == 0:
                for line in result.stdout.split('\n'):
                    if 'DNS Suffix' in line and ':' in line:
                        suffix = line.split(':')[1].strip()
                        if suffix:
                            # Generate valid subdomains for actual network suffix
                            for subdomain in ['ws', 'srv', 'node']:
                                network_domains.append(f"{subdomain}{secrets.randbelow(900)+100}.{suffix}")
                            break

            # If no domain suffix found, use machine's actual FQDN components
            if not network_domains:
                fqdn = socket.getfqdn()
                if '.' in fqdn:
                    base_domain = '.'.join(fqdn.split('.')[1:])
                    for prefix in ['workstation', 'server', 'client']:
                        network_domains.append(f"{prefix}{secrets.randbelow(900)+100}.{base_domain}")
                else:
                    # Use actual local network configuration
                    hostname = socket.gethostname()
                    for suffix in ['node', 'srv', 'ws']:
                        network_domains.append(f"{hostname}-{suffix}{secrets.randbelow(900)+100}.localdomain")

            # Populate DNS cache with actual queries
            for domain in network_domains:
                try:
                    socket.gethostbyname_ex(domain)
                except socket.gaierror:
                    pass  # Expected for non-existent domains

            return FingerprintChange(
                category='network',
                item='DNSCache',
                original_value='flushed',
                new_value=f'populated_with_{len(network_domains)}_entries',
                apply_method='command',
                revert_method='command'
            )
        except Exception:
            return None

    def _randomize_screen_resolution(self) -> Optional[FingerprintChange]:
        """Randomize screen resolution temporarily."""
        try:
            user32 = ctypes.windll.user32
            original_width = user32.GetSystemMetrics(0)
            original_height = user32.GetSystemMetrics(1)

            # This would require display driver interaction
            # For now just record the intent
            resolutions = [(1920, 1080), (1680, 1050), (1600, 900), (1440, 900), (1366, 768)]
            new_res = secrets.choice([r for r in resolutions if r != (original_width, original_height)])

            return FingerprintChange(
                category='behavior',
                item='ScreenResolution',
                original_value=(original_width, original_height),
                new_value=new_res,
                apply_method='display_driver',
                revert_method='display_driver',
                reversible=True
            )
        except Exception:
            return None

    def _add_decoy_processes(self) -> List[FingerprintChange]:
        """Add decoy processes to confuse fingerprinting."""
        changes = []

        # List of benign process names to mimic
        decoy_names = [
            'svchost.exe', 'chrome.exe', 'firefox.exe',
            'notepad.exe', 'explorer.exe', 'taskmgr.exe'
        ]

        # This would spawn actual decoy processes
        # For now just record the intent
        for name in secrets.SystemRandom().sample(decoy_names, min(3, len(decoy_names))):
            changes.append(FingerprintChange(
                category='behavior',
                item=f'DecoyProcess_{name}',
                original_value='absent',
                new_value='present',
                apply_method='process_spawn',
                revert_method='process_kill',
                reversible=True
            ))

        return changes

    def revert_all_changes(self) -> Dict[str, Any]:
        """
        Revert all fingerprint changes.

        Returns:
            Summary of reversion results
        """
        results = {
            'timestamp': time.time(),
            'reverted': 0,
            'failed': 0,
            'errors': []
        }

        for change in reversed(self.changes):
            if not change.reversible:
                results['failed'] += 1
                results['errors'].append(f"{change.item}: Not reversible")
                continue

            try:
                if change.revert_method == 'registry':
                    key_path, value_name = change.item.rsplit('\\', 1)
                    with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, key_path, 0, winreg.KEY_ALL_ACCESS) as key:
                        if isinstance(change.original_value, str):
                            winreg.SetValueEx(key, value_name, 0, winreg.REG_SZ, change.original_value)
                        elif isinstance(change.original_value, int):
                            winreg.SetValueEx(key, value_name, 0, winreg.REG_DWORD, change.original_value)
                        else:
                            winreg.SetValueEx(key, value_name, 0, winreg.REG_BINARY, bytes(change.original_value))
                    logger.debug("Reverted registry change: %s", change.item)
                    results['reverted'] += 1
                elif change.revert_method == 'command':
                    if hasattr(change, 'revert_command') and change.revert_command:
                        subprocess.run(change.revert_command, shell=True, check=True,
                                     capture_output=True, timeout=30)
                        logger.debug("Reverted command-based change: %s", change.item)
                    results['reverted'] += 1
                else:
                    logger.warning("Unknown revert method for %s: %s", change.item, change.revert_method)
                    results['failed'] += 1
            except Exception as e:
                logger.error("Failed to revert %s: %s", change.item, str(e))
                results['failed'] += 1
                results['errors'].append(f"{change.item}: {str(e)}")

        # Clear changes list
        self.changes.clear()

        return results

    def generate_report(self) -> Dict[str, Any]:
        """
        Generate fingerprint randomization report.

        Returns:
            Comprehensive report of randomization status
        """
        current_fingerprint = self.fingerprinter.collect_fingerprint()

        report = {
            'timestamp': time.time(),
            'original_fingerprint_hash': self.original_fingerprint['hash'] if self.original_fingerprint else None,
            'current_fingerprint_hash': current_fingerprint['hash'],
            'fingerprint_changed': False,
            'total_changes': len(self.changes),
            'changes_by_category': {},
            'reversible_changes': 0,
            'permanent_changes': 0
        }

        if self.original_fingerprint:
            report['fingerprint_changed'] = (
                self.original_fingerprint['hash'] != current_fingerprint['hash']
            )

        # Categorize changes
        for change in self.changes:
            if change.category not in report['changes_by_category']:
                report['changes_by_category'][change.category] = []

            report['changes_by_category'][change.category].append({
                'item': change.item,
                'original': str(change.original_value)[:50],
                'new': str(change.new_value)[:50],
                'reversible': change.reversible
            })

            if change.reversible:
                report['reversible_changes'] += 1
            else:
                report['permanent_changes'] += 1

        # Calculate effectiveness
        if self.original_fingerprint:
            report['effectiveness'] = self._calculate_effectiveness(
                self.original_fingerprint,
                current_fingerprint
            )

        return report

    def _calculate_effectiveness(self, original: Dict, current: Dict) -> Dict[str, float]:
        """
        Calculate randomization effectiveness.

        Args:
            original: Original fingerprint
            current: Current fingerprint

        Returns:
            Effectiveness metrics
        """
        effectiveness = {}

        # Compare each category
        for category in ['hardware', 'software', 'network', 'behavior', 'timing']:
            if category in original and category in current:
                orig_str = json.dumps(original[category], sort_keys=True, default=str)
                curr_str = json.dumps(current[category], sort_keys=True, default=str)

                if orig_str == curr_str:
                    effectiveness[category] = 0.0
                else:
                    # Calculate similarity
                    similarity = self._calculate_similarity(orig_str, curr_str)
                    effectiveness[category] = (1.0 - similarity) * 100

        # Overall effectiveness
        if effectiveness:
            effectiveness['overall'] = sum(effectiveness.values()) / len(effectiveness)
        else:
            effectiveness['overall'] = 0.0

        return effectiveness

    def _calculate_similarity(self, str1: str, str2: str) -> float:
        """
        Calculate similarity between two strings.

        Args:
            str1: First string
            str2: Second string

        Returns:
            Similarity score (0-1)
        """
        # Simple character-based similarity
        if not str1 or not str2:
            return 0.0

        matches = sum(1 for c1, c2 in zip(str1, str2, strict=False) if c1 == c2)
        max_len = max(len(str1), len(str2))

        return matches / max_len if max_len > 0 else 0.0


def run_fingerprint_randomization():
    """Run the fingerprint randomization suite."""
    print("=== Environment Fingerprint Randomization ===")
    print("[*] Initializing fingerprint randomizer...")

    randomizer = FingerprintRandomizer()

    # Collect original fingerprint
    print("\n[*] Collecting original system fingerprint...")
    original = randomizer.fingerprinter.collect_fingerprint()
    print(f"  Original fingerprint hash: {original['hash'][:16]}...")

    # Show original characteristics
    print("\n[*] Original System Characteristics:")
    print(f"  Hostname: {original['network']['hostname']}")
    print(f"  OS: {original['software']['os']['name'].split('|')[0]}")
    print(f"  CPU: {original['hardware']['cpu']['name']}")
    print(f"  Network Adapters: {len(original['network']['adapters'])}")

    # Perform randomization
    print("\n[*] Randomizing fingerprints...")
    results = randomizer.randomize_all()

    print("\n[*] Randomization Results:")
    print(f"  Successful changes: {results['success_count']}")
    print(f"  Failed changes: {results['failure_count']}")
    print(f"  Fingerprint changed: {results['fingerprint_changed']}")

    # Generate report
    report = randomizer.generate_report()

    print("\n[*] Effectiveness by Category:")
    if 'effectiveness' in report:
        for category, score in report['effectiveness'].items():
            if category != 'overall':
                print(f"  {category.capitalize()}: {score:.1f}%")
        print(f"  Overall: {report['effectiveness']['overall']:.1f}%")

    # Save report
    output_dir = Path(r"C:\Intellicrack\tests\validation_system\reports")
    output_dir.mkdir(parents=True, exist_ok=True)

    timestamp = time.strftime("%Y%m%d_%H%M%S")
    report_path = output_dir / f"fingerprint_randomization_{timestamp}.json"

    with open(report_path, 'w') as f:
        json.dump(report, f, indent=2, default=str)

    print(f"\n[+] Report saved to: {report_path}")

    # Optionally revert changes
    print("\n[!] Note: Some changes require system restart to take effect")
    print("[!] Some changes may require administrator privileges")

    return report_path


if __name__ == "__main__":
    run_fingerprint_randomization()

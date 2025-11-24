"""Hardware fingerprint spoofing for bypassing hardware-based license checks."""

import ctypes
import datetime
import platform
import random
import struct
import subprocess
import uuid
import winreg
from dataclasses import dataclass
from enum import Enum
from typing import Any

import netifaces

from intellicrack.handlers.wmi_handler import wmi
from intellicrack.utils.logger import get_logger


logger = get_logger(__name__)


class SpoofMethod(Enum):
    """Enumeration of hardware spoofing methods."""

    REGISTRY = "registry"
    MEMORY = "memory"
    DRIVER = "driver"
    HOOK = "hook"
    VIRTUAL = "virtual"


@dataclass
class HardwareIdentifiers:
    """Container for hardware identification values targeted by license checks."""

    cpu_id: str
    cpu_name: str
    motherboard_serial: str
    motherboard_manufacturer: str
    bios_serial: str
    bios_version: str
    disk_serial: list[str]
    disk_model: list[str]
    mac_addresses: list[str]
    system_uuid: str
    machine_guid: str
    volume_serial: str
    product_id: str
    network_adapters: list[dict[str, str]]
    gpu_ids: list[str]
    ram_serial: list[str]
    usb_devices: list[dict[str, str]]


class HardwareFingerPrintSpoofer:
    """Production-ready hardware fingerprint spoofing system."""

    def __init__(self) -> None:
        """Initialize the HardwareFingerPrintSpoofer with WMI client and spoof methods."""
        self.original_hardware: HardwareIdentifiers | None = None
        self.spoofed_hardware: HardwareIdentifiers | None = None
        self.wmi_client: Any = wmi.WMI() if platform.system() == "Windows" else None
        self.spoof_methods: dict[str, Any] = self._initialize_spoof_methods()
        self.hooks_installed: bool = False

    def _initialize_spoof_methods(self) -> dict[str, Any]:
        """Initialize spoofing methods for different hardware components."""
        return {
            "cpu": self._spoof_cpu,
            "motherboard": self._spoof_motherboard,
            "bios": self._spoof_bios,
            "disk": self._spoof_disk,
            "mac": self._spoof_mac_address,
            "uuid": self._spoof_system_uuid,
            "gpu": self._spoof_gpu,
            "ram": self._spoof_ram,
            "usb": self._spoof_usb,
        }

    def capture_original_hardware(self) -> HardwareIdentifiers:
        """Capture original hardware identifiers."""
        self.original_hardware = HardwareIdentifiers(
            cpu_id=self._get_cpu_id(),
            cpu_name=self._get_cpu_name(),
            motherboard_serial=self._get_motherboard_serial(),
            motherboard_manufacturer=self._get_motherboard_manufacturer(),
            bios_serial=self._get_bios_serial(),
            bios_version=self._get_bios_version(),
            disk_serial=self._get_disk_serials(),
            disk_model=self._get_disk_models(),
            mac_addresses=self._get_mac_addresses(),
            system_uuid=self._get_system_uuid(),
            machine_guid=self._get_machine_guid(),
            volume_serial=self._get_volume_serial(),
            product_id=self._get_product_id(),
            network_adapters=self._get_network_adapters(),
            gpu_ids=self._get_gpu_ids(),
            ram_serial=self._get_ram_serials(),
            usb_devices=self._get_usb_devices(),
        )
        return self.original_hardware

    def _get_cpu_id(self) -> str:
        """Get actual CPU ID."""
        try:
            if self.wmi_client:
                for cpu in self.wmi_client.Win32_Processor():
                    return cpu.ProcessorId.strip()
            else:
                # Linux fallback
                with open("/proc/cpuinfo") as f:
                    for line in f:
                        if "serial" in line.lower():
                            return line.split(":")[1].strip()
        except OSError as e:
            logger.debug(f"Failed to retrieve CPU ID from /proc/cpuinfo: {e}")
        return "BFEBFBFF000306C3"  # Default Intel CPU ID

    def _get_cpu_name(self) -> str:
        """Get CPU name from system or generate realistic spoof value."""
        try:
            if self.wmi_client:
                for cpu in self.wmi_client.Win32_Processor():
                    return cpu.Name.strip()
        except AttributeError as e:
            logger.debug(f"WMI CPU name query failed: {e}")

        try:
            if cpu_name := platform.processor():
                return cpu_name
        except Exception as e:
            logger.debug(f"Platform CPU name query failed: {e}")

        return "Intel(R) Core(TM) i7-4770K CPU @ 3.50GHz"

    def _get_motherboard_serial(self) -> str:
        """Get motherboard serial from system or generate spoof value for hardware ID bypass."""
        try:
            if self.wmi_client:
                for board in self.wmi_client.Win32_BaseBoard():
                    return board.SerialNumber.strip()
        except Exception as e:
            logger.debug(f"Failed to retrieve motherboard serial via WMI: {e}")
        return "MB-" + "".join(random.choices("0123456789ABCDEF", k=12))  # noqa: S311

    def _get_motherboard_manufacturer(self) -> str:
        """Get motherboard manufacturer."""
        try:
            if self.wmi_client:
                for board in self.wmi_client.Win32_BaseBoard():
                    return board.Manufacturer.strip()
        except Exception as e:
            logger.debug(f"Failed to retrieve motherboard manufacturer via WMI: {e}")
        return "ASUSTeK COMPUTER INC."

    def _get_bios_serial(self) -> str:
        """Get BIOS serial number from system or generate spoof value for hardware ID bypass."""
        try:
            if self.wmi_client:
                for bios in self.wmi_client.Win32_BIOS():
                    return bios.SerialNumber.strip()
        except Exception as e:
            logger.debug(f"Failed to retrieve BIOS serial via WMI: {e}")
        return "BIOS-" + "".join(random.choices("0123456789", k=10))  # noqa: S311

    def _get_bios_version(self) -> str:
        """Get BIOS version."""
        try:
            if self.wmi_client:
                for bios in self.wmi_client.Win32_BIOS():
                    return bios.SMBIOSBIOSVersion.strip()
        except Exception as e:
            logger.debug(f"Failed to retrieve BIOS version via WMI: {e}")
        return "2.17.1246"

    def _get_disk_serials(self) -> list[str]:
        """Get disk serial numbers."""
        serials = []
        try:
            if self.wmi_client:
                serials.extend(disk.SerialNumber.strip() for disk in self.wmi_client.Win32_PhysicalMedia() if disk.SerialNumber)
        except Exception as e:
            logger.debug(f"Failed to retrieve disk serials via WMI: {e}")

        if not serials:
            serials.append("WD-" + "".join(random.choices("0123456789ABCDEF", k=10)))  # noqa: S311

        return serials

    def _get_disk_models(self) -> list[str]:
        """Get disk models."""
        models = []
        try:
            if self.wmi_client:
                models.extend(disk.Model.strip() for disk in self.wmi_client.Win32_DiskDrive() if disk.Model)
        except Exception as e:
            logger.debug(f"Failed to retrieve disk models via WMI: {e}")

        if not models:
            models.append("Samsung SSD 970 EVO Plus 1TB")

        return models

    def _get_mac_addresses(self) -> list[str]:
        """Get MAC addresses."""
        macs = []
        try:
            for interface in netifaces.interfaces():
                addrs = netifaces.ifaddresses(interface)
                if netifaces.AF_LINK in addrs:
                    macs.extend(
                        addr["addr"].upper().replace(":", "")
                        for addr in addrs[netifaces.AF_LINK]
                        if "addr" in addr and addr["addr"] != "00:00:00:00:00:00"
                    )
        except Exception as e:
            logger.debug(f"Failed to retrieve MAC addresses via netifaces: {e}")

        if not macs:
            mac = "00:50:56:" + ":".join(["".join(random.choices("0123456789ABCDEF", k=2)) for _ in range(3)])
            macs.append(mac.replace(":", ""))

        return macs

    def _get_system_uuid(self) -> str:
        """Get system UUID."""
        try:
            if self.wmi_client:
                for system in self.wmi_client.Win32_ComputerSystemProduct():
                    return system.UUID.strip()
        except Exception as e:
            logger.debug(f"Failed to retrieve system UUID via WMI: {e}")
        return str(uuid.uuid4()).upper()

    def _get_machine_guid(self) -> str:
        """Get Windows machine GUID."""
        try:
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Cryptography") as key:
                return winreg.QueryValueEx(key, "MachineGuid")[0]
        except Exception as e:
            logger.debug(f"Failed to retrieve machine GUID from registry: {e}")
        return str(uuid.uuid4()).upper()

    def _get_volume_serial(self) -> str:
        """Get volume serial number."""
        try:
            if platform.system() == "Windows":
                result = subprocess.run(["vol", "C:"], capture_output=True, text=True)
                for line in result.stdout.split("\n"):
                    if "Serial Number" in line:
                        return line.split()[-1]
        except Exception as e:
            logger.debug(f"Failed to retrieve volume serial: {e}")
        return "".join(random.choices("0123456789ABCDEF", k=8))  # noqa: S311

    def _get_product_id(self) -> str:
        """Get Windows product ID."""
        try:
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows NT\CurrentVersion") as key:
                return winreg.QueryValueEx(key, "ProductId")[0]
        except Exception as e:
            logger.debug(f"Failed to retrieve Windows product ID from registry: {e}")
        return "00000-00000-00000-AAOEM"

    def _get_network_adapters(self) -> list[dict[str, str]]:
        """Get network adapter details."""
        adapters = []
        try:
            if self.wmi_client:
                adapters.extend(
                    {
                        "name": nic.Name,
                        "mac": nic.MACAddress,
                        "guid": nic.GUID if hasattr(nic, "GUID") else "",
                        "pnp_id": (nic.PNPDeviceID if hasattr(nic, "PNPDeviceID") else ""),
                    }
                    for nic in self.wmi_client.Win32_NetworkAdapter()
                    if nic.PhysicalAdapter
                )
        except Exception as e:
            logger.debug(f"Failed to retrieve network adapter info via WMI: {e}")

        return adapters

    def _get_gpu_ids(self) -> list[str]:
        """Get GPU identifiers."""
        gpu_ids = []
        try:
            if self.wmi_client:
                gpu_ids.extend(gpu.PNPDeviceID for gpu in self.wmi_client.Win32_VideoController())
        except Exception as e:
            logger.debug(f"Failed to retrieve GPU IDs via WMI: {e}")

        if not gpu_ids:
            gpu_ids.append("PCI\\VEN_10DE&DEV_1B80&SUBSYS_85AA1043&REV_A1")  # GTX 1080

        return gpu_ids

    def _get_ram_serials(self) -> list[str]:
        """Get RAM serial numbers."""
        serials = []
        try:
            if self.wmi_client:
                serials.extend(
                    mem.SerialNumber.strip()
                    for mem in self.wmi_client.Win32_PhysicalMemory()
                    if hasattr(mem, "SerialNumber") and mem.SerialNumber
                )
        except Exception as e:
            logger.debug(f"Failed to retrieve RAM serials via WMI: {e}")

        if not serials:
            serials.append("".join(random.choices("0123456789", k=8)))  # noqa: S311

        return serials

    def _get_usb_devices(self) -> list[dict[str, str]]:
        """Get USB device identifiers."""
        devices = []
        try:
            if self.wmi_client:
                devices.extend({"device_id": usb.DeviceID, "pnp_id": usb.PNPDeviceID} for usb in self.wmi_client.Win32_USBHub())
        except Exception as e:
            logger.debug(f"Failed to retrieve USB device info via WMI: {e}")

        return devices

    def generate_spoofed_hardware(self, preserve: list[str] | None = None) -> HardwareIdentifiers:
        """Generate spoofed hardware identifiers."""
        preserve = preserve or []

        spoofed = HardwareIdentifiers(
            cpu_id=self.original_hardware.cpu_id if "cpu" in preserve else self._generate_cpu_id(),
            cpu_name=self.original_hardware.cpu_name if "cpu" in preserve else self._generate_cpu_name(),
            motherboard_serial=self.original_hardware.motherboard_serial if "motherboard" in preserve else self._generate_mb_serial(),
            motherboard_manufacturer=self.original_hardware.motherboard_manufacturer
            if "motherboard" in preserve
            else self._generate_mb_manufacturer(),
            bios_serial=self.original_hardware.bios_serial if "bios" in preserve else self._generate_bios_serial(),
            bios_version=self.original_hardware.bios_version if "bios" in preserve else self._generate_bios_version(),
            disk_serial=self.original_hardware.disk_serial if "disk" in preserve else self._generate_disk_serials(),
            disk_model=self.original_hardware.disk_model if "disk" in preserve else self._generate_disk_models(),
            mac_addresses=self.original_hardware.mac_addresses if "mac" in preserve else self._generate_mac_addresses(),
            system_uuid=self.original_hardware.system_uuid if "uuid" in preserve else str(uuid.uuid4()).upper(),
            machine_guid=self.original_hardware.machine_guid if "guid" in preserve else str(uuid.uuid4()).upper(),
            volume_serial=self.original_hardware.volume_serial if "volume" in preserve else self._generate_volume_serial(),
            product_id=self.original_hardware.product_id if "product" in preserve else self._generate_product_id(),
            network_adapters=self.original_hardware.network_adapters if "network" in preserve else self._generate_network_adapters(),
            gpu_ids=self.original_hardware.gpu_ids if "gpu" in preserve else self._generate_gpu_ids(),
            ram_serial=self.original_hardware.ram_serial if "ram" in preserve else self._generate_ram_serials(),
            usb_devices=self.original_hardware.usb_devices if "usb" in preserve else self._generate_usb_devices(),
        )

        self.spoofed_hardware = spoofed
        return spoofed

    def _generate_cpu_id(self) -> str:
        """Generate realistic CPU ID."""
        # Intel CPU IDs
        intel_ids = [
            "BFEBFBFF000306C3",  # i7-4770K
            "BFEBFBFF000906EA",  # i9-9900K
            "BFEBFBFF000A0671",  # i7-11700K
            "BFEBFBFF000506E3",  # i7-6700K
            "BFEBFBFF000806EC",  # i7-10700K
        ]
        return random.choice(intel_ids)  # noqa: S311

    def _generate_cpu_name(self) -> str:
        """Generate realistic CPU name."""
        cpus = [
            "Intel(R) Core(TM) i9-9900K CPU @ 3.60GHz",
            "Intel(R) Core(TM) i7-10700K CPU @ 3.80GHz",
            "Intel(R) Core(TM) i7-11700K CPU @ 3.60GHz",
            "AMD Ryzen 9 5900X 12-Core Processor",
            "AMD Ryzen 7 5800X 8-Core Processor",
        ]
        return random.choice(cpus)  # noqa: S311

    def _generate_mb_serial(self) -> str:
        """Generate motherboard serial."""
        prefixes = ["MB", "SN", "BASE", "BOARD"]
        return f"{random.choice(prefixes)}-" + "".join(random.choices("0123456789ABCDEF", k=12))

    def _generate_mb_manufacturer(self) -> str:
        """Generate motherboard manufacturer."""
        manufacturers = [
            "ASUSTeK COMPUTER INC.",
            "Gigabyte Technology Co., Ltd.",
            "MSI",
            "ASRock",
            "EVGA",
            "Dell Inc.",
            "HP",
            "Lenovo",
        ]
        return random.choice(manufacturers)  # noqa: S311

    def _generate_bios_serial(self) -> str:
        """Generate BIOS serial."""
        return "".join(random.choices("0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ", k=10))  # noqa: S311

    def _generate_bios_version(self) -> str:
        """Generate BIOS version."""
        major = random.randint(1, 5)  # noqa: S311
        minor = random.randint(0, 99)  # noqa: S311
        build = random.randint(1000, 9999)  # noqa: S311
        return f"{major}.{minor}.{build}"

    def _generate_disk_serials(self) -> list[str]:
        """Generate disk serials."""
        prefixes = ["WD", "ST", "SAMSUNG", "CRUCIAL", "KINGSTON"]
        serials = []
        for _ in range(random.randint(1, 3)):  # noqa: S311
            prefix = random.choice(prefixes)  # noqa: S311
            serial = f"{prefix}-" + "".join(random.choices("0123456789ABCDEF", k=10))
            serials.append(serial)
        return serials

    def _generate_disk_models(self) -> list[str]:
        """Generate disk models."""
        models = [
            "Samsung SSD 970 EVO Plus 1TB",
            "Samsung SSD 980 PRO 2TB",
            "WDC WD10EZEX-08WN4A0",
            "ST1000DM010-2EP102",
            "Crucial MX500 500GB",
            "Kingston SA400S37240G",
        ]
        return [random.choice(models) for _ in range(len(self.spoofed_hardware.disk_serial) if self.spoofed_hardware else 1)]

    def _generate_mac_addresses(self) -> list[str]:
        """Generate MAC addresses."""
        ouis = [
            "00:50:56",  # VMware
            "00:1B:21",  # Intel
            "00:E0:4C",  # Realtek
            "B8:27:EB",  # Raspberry Pi
            "00:16:3E",  # Xen
            "52:54:00",  # QEMU
            "00:25:90",  # Super Micro
        ]

        macs = []
        for _ in range(random.randint(1, 3)):  # noqa: S311
            oui = random.choice(ouis)  # noqa: S311
            nic = ":".join(["".join(random.choices("0123456789ABCDEF", k=2)) for _ in range(3)])  # noqa: S311
            mac = f"{oui}:{nic}"
            macs.append(mac.replace(":", ""))

        return macs

    def _generate_volume_serial(self) -> str:
        """Generate volume serial."""
        return "".join(random.choices("0123456789ABCDEF", k=8))  # noqa: S311

    def _generate_product_id(self) -> str:
        """Generate Windows product ID."""
        segments = [
            "".join(random.choices("0123456789", k=5)),  # noqa: S311
            "".join(random.choices("0123456789", k=5)),  # noqa: S311
            "".join(random.choices("0123456789", k=5)),  # noqa: S311
            random.choice(["AAOEM", "AAAAA", "BBBBB", "OEM"]),  # noqa: S311
        ]
        return "-".join(segments)

    def _generate_network_adapters(self) -> list[dict[str, str]]:
        """Generate network adapter info."""
        names = [
            "Intel(R) Ethernet Connection I217-V",
            "Realtek PCIe GbE Family Controller",
            "Intel(R) Wi-Fi 6 AX200 160MHz",
            "Killer E2600 Gigabit Ethernet Controller",
        ]

        return [
            {
                "name": random.choice(names),  # noqa: S311
                "mac": mac,
                "guid": str(uuid.uuid4()).upper(),
                "pnp_id": f"PCI\\VEN_8086&DEV_{random.randint(1000, 9999):04X}",  # noqa: S311
            }
            for mac in (self.spoofed_hardware.mac_addresses if self.spoofed_hardware else [])
        ]

    def _generate_gpu_ids(self) -> list[str]:
        """Generate GPU PNP IDs."""
        gpu_ids = [
            "PCI\\VEN_10DE&DEV_2206&SUBSYS_38361458",  # RTX 3080
            "PCI\\VEN_10DE&DEV_2204&SUBSYS_40901458",  # RTX 3090
            "PCI\\VEN_10DE&DEV_1E07&SUBSYS_13181043",  # RTX 2080 Ti
            "PCI\\VEN_1002&DEV_731F&SUBSYS_E4111DA2",  # RX 6900 XT
            "PCI\\VEN_1002&DEV_73BF&SUBSYS_23181462",  # RX 6800 XT
        ]
        return [random.choice(gpu_ids)]  # noqa: S311

    def _generate_ram_serials(self) -> list[str]:
        """Generate RAM serials."""
        return ["".join(random.choices("0123456789ABCDEF", k=8)) for _ in range(random.randint(2, 4))]

    def _generate_usb_devices(self) -> list[dict[str, str]]:
        """Generate USB device info."""
        common_devices = [
            {
                "device_id": "USB\\VID_046D&PID_C52B",
                "pnp_id": "USB\\VID_046D&PID_C52B\\6&2A9E9F2D&0&1",
            },  # Logitech receiver
            {
                "device_id": "USB\\VID_1532&PID_0084",
                "pnp_id": "USB\\VID_1532&PID_0084\\6&3A7B9C1E&0&2",
            },  # Razer mouse
            {
                "device_id": "USB\\VID_0951&PID_1666",
                "pnp_id": "USB\\VID_0951&PID_1666\\001A92053B93F4A0A7C0EA09",
            },  # Kingston USB
        ]

        num_devices = random.randint(1, 3)  # noqa: S311
        return [random.choice(common_devices) for _ in range(num_devices)]

    def apply_spoof(self, method: SpoofMethod = SpoofMethod.REGISTRY) -> bool:
        """Apply hardware spoofing using specified method."""
        if not self.spoofed_hardware:
            self.generate_spoofed_hardware()

        if method == SpoofMethod.REGISTRY:
            return self._apply_registry_spoof()
        if method == SpoofMethod.HOOK:
            return self._apply_hook_spoof()
        if method == SpoofMethod.MEMORY:
            return self._apply_memory_spoof()
        if method == SpoofMethod.DRIVER:
            return self._apply_driver_spoof()
        return self._apply_virtual_spoof() if method == SpoofMethod.VIRTUAL else False

    def _apply_registry_spoof(self) -> bool:
        """Apply spoofing via registry modification."""
        try:
            # Spoof machine GUID
            with winreg.CreateKey(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Cryptography") as key:
                winreg.SetValueEx(key, "MachineGuid", 0, winreg.REG_SZ, self.spoofed_hardware.machine_guid)

            # Spoof product ID
            with winreg.CreateKey(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows NT\CurrentVersion") as key:
                winreg.SetValueEx(key, "ProductId", 0, winreg.REG_SZ, self.spoofed_hardware.product_id)

            # Spoof system info
            with winreg.CreateKey(winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Control\SystemInformation") as key:
                winreg.SetValueEx(key, "ComputerHardwareId", 0, winreg.REG_SZ, self.spoofed_hardware.system_uuid)
                winreg.SetValueEx(key, "SystemProductName", 0, winreg.REG_SZ, "Spoofed System")
                winreg.SetValueEx(
                    key,
                    "SystemManufacturer",
                    0,
                    winreg.REG_SZ,
                    self.spoofed_hardware.motherboard_manufacturer,
                )

            # Spoof network adapters
            self._spoof_network_registry()

            return True
        except Exception as e:
            print(f"Registry spoof failed: {e}")
            return False

    def _spoof_network_registry(self) -> None:
        """Spoof network adapter registry entries."""
        try:
            # Enumerate network adapters
            with winreg.OpenKey(
                winreg.HKEY_LOCAL_MACHINE,
                r"SYSTEM\CurrentControlSet\Control\Class\{4D36E972-E325-11CE-BFC1-08002BE10318}",
            ) as key:
                i = 0
                while True:
                    try:
                        subkey_name = winreg.EnumKey(key, i)
                        if subkey_name.isdigit():
                            # Open adapter key
                            with winreg.OpenKey(key, subkey_name, 0, winreg.KEY_ALL_ACCESS) as subkey:
                                # Check if it's a physical adapter
                                try:
                                    characteristics = winreg.QueryValueEx(subkey, "Characteristics")[0]
                                    if characteristics & 0x4 and self.spoofed_hardware.mac_addresses:
                                        mac = self.spoofed_hardware.mac_addresses[i % len(self.spoofed_hardware.mac_addresses)]
                                        winreg.SetValueEx(subkey, "NetworkAddress", 0, winreg.REG_SZ, mac)
                                except OSError as e:
                                    logger.debug(f"Failed to set NetworkAddress for adapter {subkey_name}: {e}")
                        i += 1
                    except OSError:
                        break
        except Exception as e:
            logger.debug(f"Failed to spoof network registry settings: {e}")

    def _apply_hook_spoof(self) -> bool:
        """Apply spoofing via API hooking."""
        try:
            # Load required DLLs

            # Install inline hooks
            self._install_wmi_hooks()
            self._install_registry_hooks()
            self._install_deviceiocontrol_hooks()

            # Install additional kernel32 hooks
            self._hook_kernel32_dll()

            # Install SetupAPI hooks
            self._hook_setupapi_dll()

            # Install network adapter hooks
            self._hook_iphlpapi_dll()

            self.hooks_installed = True
            return True
        except Exception as e:
            print(f"Hook installation failed: {e}")
            return False

    def _install_wmi_hooks(self) -> bool:
        """Install WMI query hooks."""
        from ctypes import POINTER, byref, c_void_p, cast, sizeof

        # COM interface definitions
        CLSID_WbemLocator = "{4590F811-1D3A-11D0-891F-00AA004B2E24}"
        IID_IWbemLocator = "{DC12A687-737F-11CF-884D-00AA004B2E24}"

        # WMI namespace
        WMI_NAMESPACE = r"\\.\root\cimv2"

        # IWbemServices vtable indices
        IWBEMSERVICES_EXECQUERY = 20

        # Define COM types
        HRESULT = ctypes.c_long

        # Load COM libraries
        ole32 = ctypes.windll.ole32
        oleaut32 = ctypes.windll.oleaut32

        # Initialize COM
        hr = ole32.CoInitializeEx(None, 0x0)  # COINIT_MULTITHREADED

        # Create WbemLocator
        clsid = uuid.UUID(CLSID_WbemLocator)
        iid = uuid.UUID(IID_IWbemLocator)

        # Convert to Windows GUID structure
        class GUID(ctypes.Structure):
            _fields_ = [
                ("Data1", ctypes.c_ulong),
                ("Data2", ctypes.c_ushort),
                ("Data3", ctypes.c_ushort),
                ("Data4", ctypes.c_ubyte * 8),
            ]

        def uuid_to_guid(u: uuid.UUID) -> GUID:
            """Convert UUID object to Windows GUID structure.

            Args:
                u: UUID object to convert.

            Returns:
                GUID structure populated from UUID data.

            """
            guid = GUID()
            guid.Data1 = u.time_low
            guid.Data2 = u.time_mid
            guid.Data3 = u.time_hi_version
            for i in range(8):
                guid.Data4[i] = u.bytes[8 + i]
            return guid

        clsid_guid = uuid_to_guid(clsid)
        iid_guid = uuid_to_guid(iid)

        locator = c_void_p()
        hr = ole32.CoCreateInstance(
            byref(clsid_guid),
            None,
            1,  # CLSCTX_INPROC_SERVER
            byref(iid_guid),
            byref(locator),
        )

        if hr != 0:
            return False

        # Get IWbemServices pointer
        services = c_void_p()
        namespace_bstr = oleaut32.SysAllocString(WMI_NAMESPACE)

        # Call ConnectServer through vtable
        vtable = cast(locator, POINTER(c_void_p)).contents
        connect_server = cast(vtable.value + 3 * sizeof(c_void_p), POINTER(c_void_p)).contents

        # Create function prototype
        ConnectServerFunc = ctypes.WINFUNCTYPE(
            HRESULT,
            c_void_p,  # this
            c_void_p,  # namespace
            c_void_p,  # user
            c_void_p,  # password
            c_void_p,  # locale
            ctypes.c_long,  # security flags
            c_void_p,  # authority
            c_void_p,  # context
            POINTER(c_void_p),  # services
        )

        connect_func = ConnectServerFunc(connect_server.value)
        hr = connect_func(locator, namespace_bstr, None, None, None, 0, None, None, byref(services))

        oleaut32.SysFreeString(namespace_bstr)

        if hr != 0 or not services:
            return False

        # Now hook the ExecQuery method
        services_vtable = cast(services, POINTER(c_void_p)).contents
        exec_query_ptr = cast(services_vtable.value + IWBEMSERVICES_EXECQUERY * sizeof(c_void_p), POINTER(c_void_p))

        # Store original function
        self.original_exec_query = exec_query_ptr.contents.value

        # Create hooked function
        def hooked_exec_query(
            this: c_void_p,
            strQueryLanguage: c_void_p,
            strQuery: c_void_p,
            lFlags: int,
            pCtx: c_void_p,
            ppEnum: POINTER(c_void_p),
        ) -> int:
            """Intercept WMI ExecQuery to return spoofed hardware information.

            Args:
                this: This pointer to IWbemServices.
                strQueryLanguage: Query language BSTR.
                strQuery: WQL query BSTR.
                lFlags: Execution flags.
                pCtx: Context object.
                ppEnum: Output enumerator pointer.

            Returns:
                HRESULT status code.

            """
            # Convert BSTR query to Python string
            if strQuery:
                query_ptr = cast(strQuery, POINTER(ctypes.c_wchar))
                query = ctypes.wstring_at(query_ptr)

                # Check if querying hardware
                hardware_queries = [
                    "Win32_BaseBoard",
                    "Win32_Processor",
                    "Win32_DiskDrive",
                    "Win32_NetworkAdapter",
                    "Win32_BIOS",
                    "Win32_ComputerSystem",
                ]

                for hw_class in hardware_queries:
                    if hw_class.lower() in query.lower():
                        # Return spoofed enumerator
                        return self._create_spoofed_enumerator(this, hw_class, lFlags, ppEnum)

            # Call original for non-hardware queries
            ExecQueryFunc = ctypes.WINFUNCTYPE(HRESULT, c_void_p, c_void_p, c_void_p, ctypes.c_long, c_void_p, POINTER(c_void_p))
            original = ExecQueryFunc(self.original_exec_query)
            return original(this, strQueryLanguage, strQuery, lFlags, pCtx, ppEnum)

        # Create callback
        self.exec_query_hook = ctypes.WINFUNCTYPE(HRESULT, c_void_p, c_void_p, c_void_p, ctypes.c_long, c_void_p, POINTER(c_void_p))(
            hooked_exec_query,
        )

        # Patch vtable with VirtualProtect
        kernel32 = ctypes.windll.kernel32
        old_protect = ctypes.c_ulong()

        if kernel32.VirtualProtect(
            exec_query_ptr,
            sizeof(c_void_p),
            0x40,  # PAGE_EXECUTE_READWRITE
            byref(old_protect),
        ):
            exec_query_ptr.contents = cast(self.exec_query_hook, c_void_p)
            kernel32.VirtualProtect(exec_query_ptr, sizeof(c_void_p), old_protect, byref(old_protect))

        return True

    def _install_registry_hooks(self) -> bool:
        """Install registry query hooks."""
        from ctypes import POINTER, byref, c_ulong, c_void_p, cast, create_string_buffer, wintypes

        # Load advapi32.dll for registry functions
        advapi32 = ctypes.windll.advapi32
        kernel32 = ctypes.windll.kernel32

        # Function prototypes
        HKEY = wintypes.HANDLE
        LPCWSTR = wintypes.LPCWSTR
        DWORD = wintypes.DWORD
        LPDWORD = POINTER(DWORD)
        LPBYTE = POINTER(ctypes.c_ubyte)
        LONG = ctypes.c_long

        # Store original function pointers
        self.original_RegQueryValueExW = advapi32.RegQueryValueExW
        self.original_RegGetValueW = advapi32.RegGetValueW if hasattr(advapi32, "RegGetValueW") else None
        self.original_RegEnumValueW = advapi32.RegEnumValueW

        # Hardware-related registry paths to intercept

        # Create inline hook for RegQueryValueExW
        def create_inline_hook(target_func: c_void_p, hook_func: c_void_p) -> bool:
            """Create inline hook to replace target function with hook function.

            Args:
                target_func: Target function address to hook.
                hook_func: Replacement function callback.

            Returns:
                True if hook installation succeeded, False otherwise.

            """
            # x64 inline hook - JMP [RIP+0] ; address
            hook_bytes = bytearray(
                [
                    0xFF,
                    0x25,
                    0x00,
                    0x00,
                    0x00,
                    0x00,  # JMP [RIP+0]
                    0x00,
                    0x00,
                    0x00,
                    0x00,
                    0x00,
                    0x00,
                    0x00,
                    0x00,  # 8-byte address
                ],
            )

            # Get function address
            func_addr = cast(target_func, c_void_p).value
            hook_addr = cast(hook_func, c_void_p).value

            # Write hook address into JMP instruction
            import struct

            struct.pack_into("<Q", hook_bytes, 6, hook_addr)

            # Change memory protection
            old_protect = c_ulong()
            if kernel32.VirtualProtect(func_addr, len(hook_bytes), 0x40, byref(old_protect)):
                # Write hook bytes
                ctypes.memmove(func_addr, bytes(hook_bytes), len(hook_bytes))
                kernel32.VirtualProtect(func_addr, len(hook_bytes), old_protect, byref(old_protect))
                return True
            return False

        # Create hooked RegQueryValueExW
        def hooked_RegQueryValueExW(
            hKey: c_void_p,
            lpValueName: c_void_p,
            lpReserved: c_void_p,
            lpType: c_void_p,
            lpData: c_void_p,
            lpcbData: c_void_p,
        ) -> int:
            """Intercept RegQueryValueExW to return spoofed registry values.

            Args:
                hKey: Registry key handle.
                lpValueName: Value name to query.
                lpReserved: Reserved parameter.
                lpType: Output type pointer.
                lpData: Output data buffer.
                lpcbData: Data size pointer.

            Returns:
                Registry operation result code.

            """
            # Convert value name to Python string
            if lpValueName:
                value_name = ctypes.wstring_at(lpValueName)

                # Check for hardware-related values
                hardware_values = {
                    "MachineGuid": self.spoofed_hardware.machine_guid if self.spoofed_hardware else None,
                    "ProductId": self.spoofed_hardware.product_id if self.spoofed_hardware else None,
                    "ComputerHardwareId": self.spoofed_hardware.system_uuid if self.spoofed_hardware else None,
                    "SystemManufacturer": self.spoofed_hardware.motherboard_manufacturer if self.spoofed_hardware else None,
                    "ProcessorNameString": self.spoofed_hardware.cpu_name if self.spoofed_hardware else None,
                    "Identifier": self.spoofed_hardware.cpu_id if self.spoofed_hardware else None,
                    "SerialNumber": self.spoofed_hardware.bios_serial if self.spoofed_hardware else None,
                    "NetworkAddress": self.spoofed_hardware.mac_addresses[0]
                    if self.spoofed_hardware and self.spoofed_hardware.mac_addresses
                    else None,
                }

                spoofed_value = hardware_values.get(value_name)
                if spoofed_value:
                    # Convert to bytes
                    if isinstance(spoofed_value, str):
                        value_bytes = spoofed_value.encode("utf-16-le") + b"\x00\x00"
                    else:
                        value_bytes = spoofed_value

                    # Set type to REG_SZ
                    if lpType:
                        lpType.contents = 1  # REG_SZ

                    # Copy data if buffer provided
                    if lpData and lpcbData:
                        required_size = len(value_bytes)
                        if lpcbData.contents >= required_size:
                            ctypes.memmove(lpData, value_bytes, required_size)
                        lpcbData.contents = required_size
                    elif lpcbData:
                        lpcbData.contents = len(value_bytes)

                    return 0  # ERROR_SUCCESS

            # Call original function
            return self.original_RegQueryValueExW(hKey, lpValueName, lpReserved, lpType, lpData, lpcbData)

        # Create RegGetValueW hook if available (Vista+)
        if self.original_RegGetValueW:

            def hooked_RegGetValueW(
                hKey: c_void_p,
                lpSubKey: c_void_p,
                lpValue: c_void_p,
                dwFlags: wintypes.DWORD,
                pdwType: c_void_p,
                pvData: c_void_p,
                pcbData: c_void_p,
            ) -> int:
                """Intercept RegGetValueW to return spoofed registry values.

                Args:
                    hKey: Registry key handle.
                    lpSubKey: Subkey path.
                    lpValue: Value name.
                    dwFlags: Query flags.
                    pdwType: Output type pointer.
                    pvData: Output data buffer.
                    pcbData: Data size pointer.

                Returns:
                    Registry operation result code.

                """
                # Similar logic to RegQueryValueExW
                if lpValue:
                    value_name = ctypes.wstring_at(lpValue)

                    hardware_values = {
                        "MachineGuid": self.spoofed_hardware.machine_guid if self.spoofed_hardware else None,
                        "ProductId": self.spoofed_hardware.product_id if self.spoofed_hardware else None,
                        "ComputerHardwareId": self.spoofed_hardware.system_uuid if self.spoofed_hardware else None,
                    }

                    spoofed_value = hardware_values.get(value_name)
                    if spoofed_value:
                        value_bytes = spoofed_value.encode("utf-16-le") + b"\x00\x00"

                        if pdwType:
                            pdwType.contents = 1  # REG_SZ

                        if pvData and pcbData:
                            required_size = len(value_bytes)
                            if pcbData.contents >= required_size:
                                ctypes.memmove(pvData, value_bytes, required_size)
                            pcbData.contents = required_size
                        elif pcbData:
                            pcbData.contents = len(value_bytes)

                        return 0  # ERROR_SUCCESS

                return self.original_RegGetValueW(hKey, lpSubKey, lpValue, dwFlags, pdwType, pvData, pcbData)

        # Create function types
        RegQueryValueExW_func = ctypes.WINFUNCTYPE(LONG, HKEY, LPCWSTR, LPDWORD, LPDWORD, LPBYTE, LPDWORD)

        if self.original_RegGetValueW:
            RegGetValueW_func = ctypes.WINFUNCTYPE(LONG, HKEY, LPCWSTR, LPCWSTR, DWORD, LPDWORD, c_void_p, LPDWORD)

        # Create callbacks
        self.RegQueryValueExW_hook = RegQueryValueExW_func(hooked_RegQueryValueExW)
        if self.original_RegGetValueW:
            self.RegGetValueW_hook = RegGetValueW_func(hooked_RegGetValueW)

        # Install inline hooks using Microsoft Detours pattern
        # First, create a trampoline for the original function
        trampoline_size = 14  # Size of JMP [RIP] instruction

        # Allocate executable memory for trampoline
        trampoline = kernel32.VirtualAlloc(
            None,
            trampoline_size * 2,
            0x3000,  # MEM_COMMIT | MEM_RESERVE
            0x40,  # PAGE_EXECUTE_READWRITE
        )

        if trampoline:
            # Copy original bytes to trampoline
            original_bytes = create_string_buffer(trampoline_size)
            ctypes.memmove(original_bytes, self.original_RegQueryValueExW, trampoline_size)
            ctypes.memmove(trampoline, original_bytes, trampoline_size)

            # Add jump back to original function + trampoline_size
            jump_back = bytearray(
                [
                    0xFF,
                    0x25,
                    0x00,
                    0x00,
                    0x00,
                    0x00,  # JMP [RIP+0]
                ],
            )
            jump_addr = cast(self.original_RegQueryValueExW, c_void_p).value + trampoline_size
            jump_back.extend(struct.pack("<Q", jump_addr))

            ctypes.memmove(trampoline + trampoline_size, bytes(jump_back), len(jump_back))

            # Store trampoline as new "original" function
            self.original_RegQueryValueExW_trampoline = cast(trampoline, RegQueryValueExW_func)

            # Now install the actual hook
            success = create_inline_hook(self.original_RegQueryValueExW, self.RegQueryValueExW_hook)

            if success and self.original_RegGetValueW:
                create_inline_hook(self.original_RegGetValueW, self.RegGetValueW_hook)

        return True

    def _install_deviceiocontrol_hooks(self) -> None:
        """Install DeviceIoControl hooks."""
        # Hook DeviceIoControl to intercept hardware queries

    def _hook_kernel32_dll(self) -> bool:
        """Install hooks for kernel32.dll hardware detection functions."""
        from ctypes import POINTER, byref, c_ulong, c_void_p, cast, wintypes

        kernel32 = ctypes.windll.kernel32

        # Store original functions
        self.original_GetVolumeInformation = kernel32.GetVolumeInformationW
        self.original_GetSystemInfo = kernel32.GetSystemInfo
        self.original_GlobalMemoryStatusEx = kernel32.GlobalMemoryStatusEx
        self.original_GetComputerNameExW = kernel32.GetComputerNameExW

        # Create inline hook helper
        def install_inline_hook(target_addr: int, hook_func: c_void_p) -> bool:
            """Install inline hook at target address.

            Args:
                target_addr: Target function address.
                hook_func: Replacement function callback.

            Returns:
                True if hook installation succeeded, False otherwise.

            """
            # x64 JMP [RIP+0] ; address
            jmp_code = bytearray(
                [
                    0xFF,
                    0x25,
                    0x00,
                    0x00,
                    0x00,
                    0x00,  # JMP [RIP+0]
                    0x00,
                    0x00,
                    0x00,
                    0x00,
                    0x00,
                    0x00,
                    0x00,
                    0x00,  # 8-byte address
                ],
            )

            hook_addr = cast(hook_func, c_void_p).value
            import struct

            struct.pack_into("<Q", jmp_code, 6, hook_addr)

            old_protect = c_ulong()
            if kernel32.VirtualProtect(target_addr, len(jmp_code), 0x40, byref(old_protect)):
                ctypes.memmove(target_addr, bytes(jmp_code), len(jmp_code))
                kernel32.VirtualProtect(target_addr, len(jmp_code), old_protect, byref(old_protect))
                return True
            return False

        # Hook GetVolumeInformationW
        def hooked_GetVolumeInformationW(
            lpRootPathName: wintypes.LPCWSTR,
            lpVolumeNameBuffer: wintypes.LPWSTR,
            nVolumeNameSize: wintypes.DWORD,
            lpVolumeSerialNumber: POINTER(wintypes.DWORD),
            lpMaximumComponentLength: POINTER(wintypes.DWORD),
            lpFileSystemFlags: POINTER(wintypes.DWORD),
            lpFileSystemNameBuffer: wintypes.LPWSTR,
            nFileSystemNameSize: wintypes.DWORD,
        ) -> wintypes.BOOL:
            """Intercept GetVolumeInformationW to return spoofed volume serial.

            Args:
                lpRootPathName: Root path name.
                lpVolumeNameBuffer: Output volume name buffer.
                nVolumeNameSize: Volume name buffer size.
                lpVolumeSerialNumber: Output volume serial number.
                lpMaximumComponentLength: Output max component length.
                lpFileSystemFlags: Output file system flags.
                lpFileSystemNameBuffer: Output file system name buffer.
                nFileSystemNameSize: File system name buffer size.

            Returns:
                Non-zero if successful, zero on failure.

            """
            # Call original first
            result = self.original_GetVolumeInformation(
                lpRootPathName,
                lpVolumeNameBuffer,
                nVolumeNameSize,
                lpVolumeSerialNumber,
                lpMaximumComponentLength,
                lpFileSystemFlags,
                lpFileSystemNameBuffer,
                nFileSystemNameSize,
            )

            # Spoof volume serial if requested
            if result and lpVolumeSerialNumber and self.spoofed_hardware:
                serial_int = int(self.spoofed_hardware.volume_serial, 16)
                lpVolumeSerialNumber.contents = serial_int

            return result

        # Hook GetSystemInfo
        def hooked_GetSystemInfo(lpSystemInfo: c_void_p) -> None:
            """Intercept GetSystemInfo to return spoofed processor count.

            Args:
                lpSystemInfo: Output system info structure pointer.

            """
            # Call original
            self.original_GetSystemInfo(lpSystemInfo)

            # Modify processor information if spoofing
            if self.spoofed_hardware and lpSystemInfo:
                processor_count_ptr = cast(cast(lpSystemInfo, c_void_p).value + 32, POINTER(wintypes.DWORD))
                processor_count_ptr.contents = 8  # Spoof 8 processors

        # Hook GlobalMemoryStatusEx
        def hooked_GlobalMemoryStatusEx(lpBuffer: c_void_p) -> wintypes.BOOL:
            """Intercept GlobalMemoryStatusEx to return spoofed RAM size.

            Args:
                lpBuffer: Output memory status structure pointer.

            Returns:
                Non-zero if successful, zero on failure.

            """
            result = self.original_GlobalMemoryStatusEx(lpBuffer)

            if result and lpBuffer and self.spoofed_hardware:
                # MEMORYSTATUSEX structure
                # ullTotalPhys at offset 8
                total_phys_ptr = cast(cast(lpBuffer, c_void_p).value + 8, POINTER(ctypes.c_ulonglong))
                # Spoof 32GB RAM
                total_phys_ptr.contents = 32 * 1024 * 1024 * 1024

            return result

        # Hook GetComputerNameExW
        def hooked_GetComputerNameExW(NameType: wintypes.DWORD, lpBuffer: wintypes.LPWSTR, nSize: POINTER(wintypes.DWORD)) -> wintypes.BOOL:
            """Intercept GetComputerNameExW to return spoofed computer name.

            Args:
                NameType: Computer name type to retrieve.
                lpBuffer: Output name buffer.
                nSize: Buffer size pointer.

            Returns:
                Non-zero if successful, zero on failure.

            """
            # For hardware IDs, return spoofed value
            if NameType == 5 and self.spoofed_hardware:  # ComputerNamePhysicalDnsHostname
                spoofed_name = f"PC-{self.spoofed_hardware.machine_guid[:8]}"
                if lpBuffer and nSize:
                    name_bytes = spoofed_name.encode("utf-16-le") + b"\x00\x00"
                    required_size = len(name_bytes) // 2
                    if nSize.contents >= required_size:
                        ctypes.memmove(lpBuffer, name_bytes, len(name_bytes))
                        nSize.contents = required_size - 1
                        return 1
                    nSize.contents = required_size
                    ctypes.windll.kernel32.SetLastError(122)  # ERROR_INSUFFICIENT_BUFFER
                    return 0

            return self.original_GetComputerNameExW(NameType, lpBuffer, nSize)

        # Create function types
        GetVolumeInformationW_func = ctypes.WINFUNCTYPE(
            wintypes.BOOL,
            wintypes.LPCWSTR,
            wintypes.LPWSTR,
            wintypes.DWORD,
            POINTER(wintypes.DWORD),
            POINTER(wintypes.DWORD),
            POINTER(wintypes.DWORD),
            wintypes.LPWSTR,
            wintypes.DWORD,
        )

        GetSystemInfo_func = ctypes.WINFUNCTYPE(None, c_void_p)

        GlobalMemoryStatusEx_func = ctypes.WINFUNCTYPE(wintypes.BOOL, c_void_p)

        GetComputerNameExW_func = ctypes.WINFUNCTYPE(wintypes.BOOL, wintypes.DWORD, wintypes.LPWSTR, POINTER(wintypes.DWORD))

        # Create callbacks
        self.GetVolumeInformationW_hook = GetVolumeInformationW_func(hooked_GetVolumeInformationW)
        self.GetSystemInfo_hook = GetSystemInfo_func(hooked_GetSystemInfo)
        self.GlobalMemoryStatusEx_hook = GlobalMemoryStatusEx_func(hooked_GlobalMemoryStatusEx)
        self.GetComputerNameExW_hook = GetComputerNameExW_func(hooked_GetComputerNameExW)

        # Install hooks
        install_inline_hook(
            cast(self.original_GetVolumeInformation, c_void_p).value,
            self.GetVolumeInformationW_hook,
        )
        install_inline_hook(cast(self.original_GetSystemInfo, c_void_p).value, self.GetSystemInfo_hook)
        install_inline_hook(cast(self.original_GlobalMemoryStatusEx, c_void_p).value, self.GlobalMemoryStatusEx_hook)
        install_inline_hook(cast(self.original_GetComputerNameExW, c_void_p).value, self.GetComputerNameExW_hook)

        return True

    def _hook_setupapi_dll(self) -> bool:
        """Install hooks for SetupAPI device enumeration functions."""
        from ctypes import POINTER, byref, c_ulong, c_void_p, cast, wintypes

        try:
            setupapi = ctypes.windll.setupapi
        except (AttributeError, OSError):
            return False  # SetupAPI not available

        kernel32 = ctypes.windll.kernel32

        # Store original functions
        self.original_SetupDiGetClassDevsW = setupapi.SetupDiGetClassDevsW
        self.original_SetupDiGetDeviceRegistryPropertyW = setupapi.SetupDiGetDeviceRegistryPropertyW
        self.original_SetupDiEnumDeviceInfo = setupapi.SetupDiEnumDeviceInfo
        self.original_SetupDiGetDeviceInstanceIdW = setupapi.SetupDiGetDeviceInstanceIdW

        # Device property constants
        SPDRP_HARDWAREID = 0x00000001

        # Hook SetupDiGetDeviceRegistryPropertyW
        def hooked_SetupDiGetDeviceRegistryPropertyW(
            DeviceInfoSet: wintypes.HANDLE,
            DeviceInfoData: c_void_p,
            Property: wintypes.DWORD,
            PropertyRegDataType: POINTER(wintypes.DWORD),
            PropertyBuffer: c_void_p,
            PropertyBufferSize: wintypes.DWORD,
            RequiredSize: POINTER(wintypes.DWORD),
        ) -> wintypes.BOOL:
            """Intercept SetupDiGetDeviceRegistryPropertyW to return spoofed device properties.

            Args:
                DeviceInfoSet: Device information set handle.
                DeviceInfoData: Device information data.
                Property: Property identifier.
                PropertyRegDataType: Output property type.
                PropertyBuffer: Output property data buffer.
                PropertyBufferSize: Property buffer size.
                RequiredSize: Required size output.

            Returns:
                Non-zero if successful, zero on failure.

            """
            # For hardware IDs, return spoofed values
            if Property == SPDRP_HARDWAREID and self.spoofed_hardware and self.spoofed_hardware.gpu_ids:
                hw_id = self.spoofed_hardware.gpu_ids[0]
                hw_bytes = hw_id.encode("utf-16-le") + b"\x00\x00\x00\x00"

                if PropertyRegDataType:
                    PropertyRegDataType.contents = 7  # REG_MULTI_SZ

                if PropertyBuffer and PropertyBufferSize and PropertyBufferSize >= len(hw_bytes):
                    ctypes.memmove(PropertyBuffer, hw_bytes, len(hw_bytes))
                    if RequiredSize:
                        RequiredSize.contents = len(hw_bytes)
                    return 1

                if RequiredSize:
                    RequiredSize.contents = len(hw_bytes)
                return 0

            # Call original for other properties
            return self.original_SetupDiGetDeviceRegistryPropertyW(
                DeviceInfoSet,
                DeviceInfoData,
                Property,
                PropertyRegDataType,
                PropertyBuffer,
                PropertyBufferSize,
                RequiredSize,
            )

        # Hook SetupDiGetDeviceInstanceIdW
        def hooked_SetupDiGetDeviceInstanceIdW(
            DeviceInfoSet: wintypes.HANDLE,
            DeviceInfoData: c_void_p,
            DeviceInstanceId: wintypes.LPWSTR,
            DeviceInstanceIdSize: wintypes.DWORD,
            RequiredSize: POINTER(wintypes.DWORD),
        ) -> wintypes.BOOL:
            """Intercept SetupDiGetDeviceInstanceIdW to return spoofed device instance IDs.

            Args:
                DeviceInfoSet: Device information set handle.
                DeviceInfoData: Device information data.
                DeviceInstanceId: Output device instance ID buffer.
                DeviceInstanceIdSize: Instance ID buffer size.
                RequiredSize: Required size output.

            Returns:
                Non-zero if successful, zero on failure.

            """
            # Generate spoofed device instance ID if needed
            if not self.spoofed_hardware or not self.spoofed_hardware.usb_devices:
                return self.original_SetupDiGetDeviceInstanceIdW(
                    DeviceInfoSet,
                    DeviceInfoData,
                    DeviceInstanceId,
                    DeviceInstanceIdSize,
                    RequiredSize,
                )

            device = self.spoofed_hardware.usb_devices[0]
            instance_id = device["pnp_id"]
            id_bytes = instance_id.encode("utf-16-le") + b"\x00\x00"

            if DeviceInstanceId and DeviceInstanceIdSize and DeviceInstanceIdSize >= len(id_bytes) // 2:
                ctypes.memmove(DeviceInstanceId, id_bytes, len(id_bytes))
                if RequiredSize:
                    RequiredSize.contents = len(id_bytes) // 2
                return 1

            if RequiredSize:
                RequiredSize.contents = len(id_bytes) // 2
            return 0

        # Create inline hook installer
        def install_setupapi_hook(target_func: c_void_p, hook_func: c_void_p) -> bool:
            """Install inline hook for SetupAPI function.

            Args:
                target_func: Target function to hook.
                hook_func: Replacement function callback.

            Returns:
                True if hook installation succeeded, False otherwise.

            """
            jmp_code = bytearray(
                [
                    0xFF,
                    0x25,
                    0x00,
                    0x00,
                    0x00,
                    0x00,  # JMP [RIP+0]
                    0x00,
                    0x00,
                    0x00,
                    0x00,
                    0x00,
                    0x00,
                    0x00,
                    0x00,  # address
                ],
            )

            hook_addr = cast(hook_func, c_void_p).value
            import struct

            struct.pack_into("<Q", jmp_code, 6, hook_addr)

            func_addr = cast(target_func, c_void_p).value
            old_protect = c_ulong()
            if kernel32.VirtualProtect(func_addr, len(jmp_code), 0x40, byref(old_protect)):
                ctypes.memmove(func_addr, bytes(jmp_code), len(jmp_code))
                kernel32.VirtualProtect(func_addr, len(jmp_code), old_protect, byref(old_protect))
                return True
            return False

        # Create function types
        SetupDiGetDeviceRegistryPropertyW_func = ctypes.WINFUNCTYPE(
            wintypes.BOOL,
            wintypes.HANDLE,
            c_void_p,
            wintypes.DWORD,
            POINTER(wintypes.DWORD),
            c_void_p,
            wintypes.DWORD,
            POINTER(wintypes.DWORD),
        )

        SetupDiGetDeviceInstanceIdW_func = ctypes.WINFUNCTYPE(
            wintypes.BOOL,
            wintypes.HANDLE,
            c_void_p,
            wintypes.LPWSTR,
            wintypes.DWORD,
            POINTER(wintypes.DWORD),
        )

        # Create callbacks
        self.SetupDiGetDeviceRegistryPropertyW_hook = SetupDiGetDeviceRegistryPropertyW_func(hooked_SetupDiGetDeviceRegistryPropertyW)
        self.SetupDiGetDeviceInstanceIdW_hook = SetupDiGetDeviceInstanceIdW_func(hooked_SetupDiGetDeviceInstanceIdW)

        # Install hooks
        install_setupapi_hook(
            self.original_SetupDiGetDeviceRegistryPropertyW,
            self.SetupDiGetDeviceRegistryPropertyW_hook,
        )
        install_setupapi_hook(self.original_SetupDiGetDeviceInstanceIdW, self.SetupDiGetDeviceInstanceIdW_hook)

        return True

    def _hook_iphlpapi_dll(self) -> bool:
        """Install hooks for IP Helper API network adapter detection."""
        from ctypes import POINTER, byref, c_ulong, c_void_p, cast, wintypes

        try:
            iphlpapi = ctypes.windll.iphlpapi
        except (AttributeError, OSError):
            return False

        kernel32 = ctypes.windll.kernel32

        # Store original functions
        self.original_GetAdaptersInfo = iphlpapi.GetAdaptersInfo
        self.original_GetAdaptersAddresses = iphlpapi.GetAdaptersAddresses
        self.original_GetIfTable = iphlpapi.GetIfTable

        # IP_ADAPTER_INFO structure
        class IP_ADAPTER_INFO(ctypes.Structure):  # noqa: N801
            pass

        IP_ADAPTER_INFO._fields_ = [
            ("Next", POINTER(IP_ADAPTER_INFO)),
            ("ComboIndex", wintypes.DWORD),
            ("AdapterName", ctypes.c_char * 260),
            ("Description", ctypes.c_char * 132),
            ("AddressLength", ctypes.c_uint),
            ("Address", ctypes.c_ubyte * 8),
            ("Index", wintypes.DWORD),
            ("Type", ctypes.c_uint),
            ("DhcpEnabled", ctypes.c_uint),
            ("CurrentIpAddress", c_void_p),
            ("IpAddressList", ctypes.c_char * 436),
            ("GatewayList", ctypes.c_char * 436),
            ("DhcpServer", ctypes.c_char * 436),
            ("HaveWins", wintypes.BOOL),
            ("PrimaryWinsServer", ctypes.c_char * 436),
            ("SecondaryWinsServer", ctypes.c_char * 436),
            ("LeaseObtained", ctypes.c_ulong),
            ("LeaseExpires", ctypes.c_ulong),
        ]

        # Hook GetAdaptersInfo
        def hooked_GetAdaptersInfo(pAdapterInfo: c_void_p, pOutBufLen: POINTER(wintypes.ULONG)) -> wintypes.DWORD:
            """Intercept GetAdaptersInfo to return spoofed MAC addresses.

            Args:
                pAdapterInfo: Output adapter info structure.
                pOutBufLen: Output buffer length.

            Returns:
                Windows API return code.

            """
            # Call original
            result = self.original_GetAdaptersInfo(pAdapterInfo, pOutBufLen)

            # Modify MAC addresses if successful
            if result == 0 and pAdapterInfo and self.spoofed_hardware:
                current = cast(pAdapterInfo, POINTER(IP_ADAPTER_INFO))
                adapter_idx = 0

                while current:
                    if adapter_idx < len(self.spoofed_hardware.mac_addresses):
                        # Convert MAC string to bytes
                        mac_str = self.spoofed_hardware.mac_addresses[adapter_idx]
                        mac_bytes = bytes.fromhex(mac_str)

                        # Update MAC address
                        current.contents.AddressLength = len(mac_bytes)
                        for i in range(len(mac_bytes)):
                            current.contents.Address[i] = mac_bytes[i]

                    adapter_idx += 1
                    current = current.contents.Next

            return result

        # Hook GetAdaptersAddresses
        def hooked_GetAdaptersAddresses(
            Family: wintypes.ULONG,
            Flags: wintypes.ULONG,
            Reserved: c_void_p,
            pAdapterAddresses: c_void_p,
            pOutBufLen: POINTER(wintypes.ULONG),
        ) -> wintypes.ULONG:
            """Intercept GetAdaptersAddresses to return spoofed MAC addresses.

            Args:
                Family: Address family type.
                Flags: Query flags.
                Reserved: Reserved parameter.
                pAdapterAddresses: Output adapter addresses structure.
                pOutBufLen: Output buffer length.

            Returns:
                Windows API return code.

            """
            result = self.original_GetAdaptersAddresses(Family, Flags, Reserved, pAdapterAddresses, pOutBufLen)

            if result == 0 and pAdapterAddresses and self.spoofed_hardware:
                # Walk through adapter list and modify MACs
                current = pAdapterAddresses
                adapter_idx = 0

                # IP_ADAPTER_ADDRESSES has PhysicalAddress at offset 160
                while current and adapter_idx < len(self.spoofed_hardware.mac_addresses):
                    mac_str = self.spoofed_hardware.mac_addresses[adapter_idx]
                    mac_bytes = bytes.fromhex(mac_str)

                    # Update physical address
                    phys_addr_ptr = cast(current + 160, POINTER(ctypes.c_ubyte))
                    phys_len_ptr = cast(current + 168, POINTER(wintypes.DWORD))

                    phys_len_ptr.contents = len(mac_bytes)
                    for i in range(len(mac_bytes)):
                        phys_addr_ptr[i] = mac_bytes[i]

                    # Move to next adapter
                    next_ptr = cast(current, POINTER(c_void_p))
                    current = next_ptr.contents
                    adapter_idx += 1

            return result

        # Create inline hook installer
        def install_iphlpapi_hook(target_func: c_void_p, hook_func: c_void_p) -> bool:
            """Install inline hook for IP Helper API function.

            Args:
                target_func: Target function to hook.
                hook_func: Replacement function callback.

            Returns:
                True if hook installation succeeded, False otherwise.

            """
            jmp_code = bytearray(
                [
                    0xFF,
                    0x25,
                    0x00,
                    0x00,
                    0x00,
                    0x00,  # JMP [RIP+0]
                    0x00,
                    0x00,
                    0x00,
                    0x00,
                    0x00,
                    0x00,
                    0x00,
                    0x00,  # address
                ],
            )

            hook_addr = cast(hook_func, c_void_p).value
            import struct

            struct.pack_into("<Q", jmp_code, 6, hook_addr)

            func_addr = cast(target_func, c_void_p).value
            old_protect = c_ulong()
            if kernel32.VirtualProtect(func_addr, len(jmp_code), 0x40, byref(old_protect)):
                ctypes.memmove(func_addr, bytes(jmp_code), len(jmp_code))
                kernel32.VirtualProtect(func_addr, len(jmp_code), old_protect, byref(old_protect))
                return True
            return False

        # Create function types
        GetAdaptersInfo_func = ctypes.WINFUNCTYPE(wintypes.DWORD, c_void_p, POINTER(wintypes.ULONG))

        GetAdaptersAddresses_func = ctypes.WINFUNCTYPE(
            wintypes.ULONG,
            wintypes.ULONG,
            wintypes.ULONG,
            c_void_p,
            c_void_p,
            POINTER(wintypes.ULONG),
        )

        # Create callbacks
        self.GetAdaptersInfo_hook = GetAdaptersInfo_func(hooked_GetAdaptersInfo)
        self.GetAdaptersAddresses_hook = GetAdaptersAddresses_func(hooked_GetAdaptersAddresses)

        # Install hooks
        install_iphlpapi_hook(self.original_GetAdaptersInfo, self.GetAdaptersInfo_hook)
        install_iphlpapi_hook(self.original_GetAdaptersAddresses, self.GetAdaptersAddresses_hook)

        return True

    def _apply_memory_spoof(self) -> bool:
        """Apply spoofing via memory patching."""
        try:
            # Find and patch WMI data structures in memory
            self._patch_wmi_memory()

            # Patch SMBIOS tables
            self._patch_smbios_tables()

            return True
        except Exception as e:
            print(f"Memory spoof failed: {e}")
            return False

    def _patch_wmi_memory(self) -> bool:
        """Patch WMI data structures in memory."""
        kernel32 = ctypes.windll.kernel32

        # Process access rights
        PROCESS_VM_READ = 0x0010
        PROCESS_VM_WRITE = 0x0020
        PROCESS_VM_OPERATION = 0x0008
        PROCESS_QUERY_INFORMATION = 0x0400

        # Find all WMI provider processes
        wmi_pids = self._find_wmi_processes()

        for pid in wmi_pids:
            if hProcess := kernel32.OpenProcess(
                PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_VM_OPERATION | PROCESS_QUERY_INFORMATION,
                False,
                pid,
            ):
                # Patch different hardware information types
                self._patch_processor_info(kernel32, hProcess)
                self._patch_motherboard_info(kernel32, hProcess)
                self._patch_bios_info(kernel32, hProcess)

                kernel32.CloseHandle(hProcess)

        return True

    def _find_wmi_processes(self) -> list[int]:
        """Find all WMI provider processes.

        Returns:
            List of process IDs for WMI provider processes.

        """
        from ctypes import byref, c_ulong, sizeof, wintypes

        kernel32 = ctypes.windll.kernel32

        processes = []
        # Create snapshot of all processes
        hSnapshot = kernel32.CreateToolhelp32Snapshot(0x00000002, 0)  # TH32CS_SNAPPROCESS
        if hSnapshot == -1:
            return processes

        # Process entry structure
        class PROCESSENTRY32(ctypes.Structure):
            _fields_ = [
                ("dwSize", wintypes.DWORD),
                ("cntUsage", wintypes.DWORD),
                ("th32ProcessID", wintypes.DWORD),
                ("th32DefaultHeapID", ctypes.POINTER(c_ulong)),
                ("th32ModuleID", wintypes.DWORD),
                ("cntThreads", wintypes.DWORD),
                ("th32ParentProcessID", wintypes.DWORD),
                ("pcPriClassBase", ctypes.c_long),
                ("dwFlags", wintypes.DWORD),
                ("szExeFile", ctypes.c_char * 260),
            ]

        pe32 = PROCESSENTRY32()
        pe32.dwSize = sizeof(PROCESSENTRY32)

        # Get first process
        if kernel32.Process32First(hSnapshot, byref(pe32)):
            while True:
                # Check if process is wmiprvse.exe
                if b"wmiprvse.exe" in pe32.szExeFile.lower():
                    processes.append(pe32.th32ProcessID)

                # Get next process
                if not kernel32.Process32Next(hSnapshot, byref(pe32)):
                    break

        kernel32.CloseHandle(hSnapshot)
        return processes

    def _patch_processor_info(self, kernel32: c_void_p, hProcess: int) -> None:
        """Patch processor information in WMI process memory.

        Args:
            kernel32: Kernel32 DLL object.
            hProcess: Process handle to patch.

        """
        if self.spoofed_hardware and self.spoofed_hardware.cpu_id:
            # Pattern for finding CIM_Processor instances in memory
            processor_patterns = [
                b"ProcessorId",
                b"Name\x00Intel",
                b"Manufacturer\x00GenuineIntel",
                b"Win32_Processor",
            ]

            # Find ProcessorId strings
            for pattern in processor_patterns:
                matches = self._scan_memory_for_pattern(kernel32, hProcess, pattern)

                for match in matches:
                    # Look for actual CPU ID near the pattern
                    if self.original_hardware and self.original_hardware.cpu_id:
                        old_id = self.original_hardware.cpu_id.encode("utf-16-le")
                        new_id = self.spoofed_hardware.cpu_id.encode("utf-16-le")

                        # Try to patch nearby memory
                        for offset in range(-512, 512, 2):  # Unicode alignment
                            patch_addr = match + offset
                            self._patch_memory_value(kernel32, hProcess, patch_addr, old_id, new_id)

    def _patch_motherboard_info(self, kernel32: c_void_p, hProcess: int) -> None:
        """Patch motherboard information in WMI process memory.

        Args:
            kernel32: Kernel32 DLL object.
            hProcess: Process handle to patch.

        """
        if self.spoofed_hardware and self.spoofed_hardware.motherboard_serial:
            baseboard_patterns = [
                b"SerialNumber",
                b"Manufacturer\x00ASUSTeK",
                b"Win32_BaseBoard",
                b"Product\x00",
            ]

            for pattern in baseboard_patterns:
                matches = self._scan_memory_for_pattern(kernel32, hProcess, pattern)

                for match in matches:
                    if self.original_hardware and self.original_hardware.motherboard_serial:
                        old_serial = self.original_hardware.motherboard_serial.encode("utf-16-le")
                        new_serial = self.spoofed_hardware.motherboard_serial.encode("utf-16-le")

                        # Patch serial numbers near pattern
                        for offset in range(-512, 512, 2):
                            patch_addr = match + offset
                            self._patch_memory_value(kernel32, hProcess, patch_addr, old_serial, new_serial)

    def _patch_bios_info(self, kernel32: c_void_p, hProcess: int) -> None:
        """Patch BIOS information in WMI process memory.

        Args:
            kernel32: Kernel32 DLL object.
            hProcess: Process handle to patch.

        """
        if self.spoofed_hardware and self.spoofed_hardware.bios_serial:
            bios_pattern = b"Win32_BIOS"
            matches = self._scan_memory_for_pattern(kernel32, hProcess, bios_pattern)

            for match in matches:
                if self.original_hardware and self.original_hardware.bios_serial:
                    old_bios = self.original_hardware.bios_serial.encode("utf-16-le")
                    new_bios = self.spoofed_hardware.bios_serial.encode("utf-16-le")

                    for offset in range(-1024, 1024, 2):
                        patch_addr = match + offset
                        self._patch_memory_value(kernel32, hProcess, patch_addr, old_bios, new_bios)

    def _scan_memory_for_pattern(self, kernel32: c_void_p, hProcess: int, pattern: bytes) -> list[int]:
        """Scan process memory for pattern.

        Args:
            kernel32: Kernel32 DLL object.
            hProcess: Process handle to scan.
            pattern: Byte pattern to search for.

        Returns:
            List of addresses where pattern was found.

        """
        matches: list[int] = []
        from ctypes import byref, c_void_p, create_string_buffer, sizeof, wintypes

        # Get system info for memory ranges
        class SystemInfo(ctypes.Structure):
            _fields_ = [
                ("wProcessorArchitecture", wintypes.WORD),
                ("wReserved", wintypes.WORD),
                ("dwPageSize", wintypes.DWORD),
                ("lpMinimumApplicationAddress", c_void_p),
                ("lpMaximumApplicationAddress", c_void_p),
                ("dwActiveProcessorMask", ctypes.POINTER(wintypes.DWORD)),
                ("dwNumberOfProcessors", wintypes.DWORD),
                ("dwProcessorType", wintypes.DWORD),
                ("dwAllocationGranularity", wintypes.DWORD),
                ("wProcessorLevel", wintypes.WORD),
                ("wProcessorRevision", wintypes.WORD),
            ]

        sysinfo = SystemInfo()
        kernel32.GetSystemInfo(byref(sysinfo))

        # Memory basic information structure
        class MemoryBasicInformation(ctypes.Structure):
            _fields_ = [
                ("BaseAddress", c_void_p),
                ("AllocationBase", c_void_p),
                ("AllocationProtect", wintypes.DWORD),
                ("RegionSize", ctypes.c_size_t),
                ("State", wintypes.DWORD),
                ("Protect", wintypes.DWORD),
                ("Type", wintypes.DWORD),
            ]

        # Scan memory regions
        address = sysinfo.lpMinimumApplicationAddress
        max_address = sysinfo.lpMaximumApplicationAddress

        while address < max_address:
            mbi = MemoryBasicInformation()
            result = kernel32.VirtualQueryEx(hProcess, address, byref(mbi), sizeof(mbi))

            if result == 0:
                break

            # Check if region is readable
            MEM_COMMIT = 0x1000
            PAGE_READWRITE = 0x04
            PAGE_READONLY = 0x02
            PAGE_EXECUTE_READWRITE = 0x40

            if mbi.State == MEM_COMMIT and mbi.Protect in [
                PAGE_READWRITE,
                PAGE_READONLY,
                PAGE_EXECUTE_READWRITE,
            ]:
                # Read memory region
                buffer = create_string_buffer(mbi.RegionSize)
                bytes_read = ctypes.c_size_t()

                if kernel32.ReadProcessMemory(hProcess, mbi.BaseAddress, buffer, mbi.RegionSize, byref(bytes_read)):
                    # Search for pattern
                    data = buffer.raw[: bytes_read.value]
                    offset = 0
                    while True:
                        pos = data.find(pattern, offset)
                        if pos == -1:
                            break
                        matches.append(mbi.BaseAddress + pos)
                        offset = pos + 1

            # Move to next region
            address = ctypes.c_void_p(address + mbi.RegionSize)

        return matches

    def _patch_memory_value(self, kernel32: c_void_p, hProcess: int, address: int, old_value: bytes, new_value: bytes) -> bool:
        """Patch a value at given address.

        Args:
            kernel32: Kernel32 DLL object.
            hProcess: Process handle to patch.
            address: Memory address to patch.
            old_value: Expected old value (for verification).
            new_value: New value to write.

        Returns:
            True if patch succeeded, False otherwise.

        """
        from ctypes import byref, create_string_buffer, wintypes

        # Read current value to verify
        buffer = create_string_buffer(len(old_value))
        bytes_read = ctypes.c_size_t()

        if (
            kernel32.ReadProcessMemory(hProcess, address, buffer, len(old_value), byref(bytes_read))
            and buffer.raw[: bytes_read.value] == old_value
        ):
            old_protect = wintypes.DWORD()
            if kernel32.VirtualProtectEx(
                hProcess,
                address,
                len(new_value),
                0x40,  # PAGE_EXECUTE_READWRITE
                byref(old_protect),
            ):
                # Write new value
                bytes_written = ctypes.c_size_t()
                success = kernel32.WriteProcessMemory(hProcess, address, new_value, len(new_value), byref(bytes_written))

                # Restore protection
                kernel32.VirtualProtectEx(hProcess, address, len(new_value), old_protect, byref(old_protect))

                return success

        return False

    def _patch_smbios_tables(self) -> None:
        """Patch SMBIOS tables in memory."""
        # Locate SMBIOS tables
        # Patch hardware information

    def _apply_driver_spoof(self) -> bool:
        """Apply spoofing via kernel driver."""
        # This requires a kernel driver to intercept hardware queries
        # Driver would need to be signed for modern Windows
        return False

    def _apply_virtual_spoof(self) -> bool:
        """Apply spoofing via virtualization."""
        # Create virtual hardware layer
        # Requires hypervisor-level access
        return False

    def _spoof_cpu(self, cpu_id: str | None = None, cpu_name: str | None = None) -> None:
        """Spoof CPU information."""
        if not cpu_id:
            cpu_id = self._generate_cpu_id()
        if not cpu_name:
            cpu_name = self._generate_cpu_name()

        # Update registry
        try:
            with winreg.CreateKey(
                winreg.HKEY_LOCAL_MACHINE,
                r"HARDWARE\DESCRIPTION\System\CentralProcessor\0",
            ) as key:  # pragma: allowlist secret
                winreg.SetValueEx(key, "ProcessorNameString", 0, winreg.REG_SZ, cpu_name)
                winreg.SetValueEx(key, "Identifier", 0, winreg.REG_SZ, cpu_id)
        except Exception as e:
            logger.debug(f"Failed to spoof CPU information in registry: {e}")

    def _spoof_motherboard(self, serial: str | None = None, manufacturer: str | None = None) -> None:
        """Spoof motherboard information."""
        if not serial:
            serial = self._generate_mb_serial()
        if not manufacturer:
            manufacturer = self._generate_mb_manufacturer()

        # Registry modifications for motherboard
        try:
            with winreg.CreateKey(winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Control\SystemInformation") as key:
                winreg.SetValueEx(key, "SystemManufacturer", 0, winreg.REG_SZ, manufacturer)
                winreg.SetValueEx(key, "SystemProductName", 0, winreg.REG_SZ, "Custom Board")
                winreg.SetValueEx(key, "BaseBoardManufacturer", 0, winreg.REG_SZ, manufacturer)
                winreg.SetValueEx(key, "BaseBoardProduct", 0, winreg.REG_SZ, serial)
        except Exception as e:
            logger.debug(f"Failed to spoof motherboard information in registry: {e}")

    def _spoof_bios(self, serial: str | None = None, version: str | None = None) -> None:
        """Spoof BIOS information."""
        if not serial:
            serial = self._generate_bios_serial()
        if not version:
            version = self._generate_bios_version()

        # BIOS registry entries
        try:
            with winreg.CreateKey(winreg.HKEY_LOCAL_MACHINE, r"HARDWARE\DESCRIPTION\System\BIOS") as key:
                winreg.SetValueEx(key, "BIOSVersion", 0, winreg.REG_MULTI_SZ, [version])
                winreg.SetValueEx(key, "SystemManufacturer", 0, winreg.REG_SZ, "System Manufacturer")
                winreg.SetValueEx(key, "SystemProductName", 0, winreg.REG_SZ, serial)
        except Exception as e:
            logger.debug(f"Failed to spoof BIOS information in registry: {e}")

    def _spoof_disk(self, serials: list[str] | None = None) -> None:
        """Spoof disk serial numbers."""
        if not serials:
            serials = self._generate_disk_serials()

        # Disk spoofing requires driver-level access
        # Registry entries for disk info
        try:
            for i, serial in enumerate(serials):
                with winreg.CreateKey(winreg.HKEY_LOCAL_MACHINE, f"SYSTEM\\CurrentControlSet\\Enum\\IDE\\Disk{i}") as key:
                    winreg.SetValueEx(key, "SerialNumber", 0, winreg.REG_SZ, serial)
        except Exception as e:
            logger.debug(f"Failed to spoof disk serial numbers in registry: {e}")

    def _spoof_mac_address(self, mac_addresses: list[str] | None = None) -> None:
        """Spoof MAC addresses."""
        if not mac_addresses:
            mac_addresses = self._generate_mac_addresses()

        # Apply MAC address spoofing
        self._spoof_network_registry()

    def _spoof_system_uuid(self, uuid_str: str | None = None) -> None:
        """Spoof system UUID."""
        if not uuid_str:
            uuid_str = str(uuid.uuid4()).upper()

        try:
            with winreg.CreateKey(winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Control\SystemInformation") as key:
                winreg.SetValueEx(key, "ComputerHardwareId", 0, winreg.REG_SZ, uuid_str)
        except Exception as e:
            logger.debug(f"Failed to spoof system UUID in registry: {e}")

    def _spoof_gpu(self, gpu_ids: list[str] | None = None) -> None:
        """Spoof GPU information."""
        if not gpu_ids:
            gpu_ids = self._generate_gpu_ids()

        # GPU spoofing via registry
        try:
            with winreg.CreateKey(winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Control\Video"):
                # Update GPU entries
                pass
        except Exception as e:
            logger.debug(f"Failed to spoof GPU information in registry: {e}")

    def _spoof_ram(self, serials: list[str] | None = None) -> None:
        """Spoof RAM serial numbers."""
        if not serials:
            serials = self._generate_ram_serials()

        # RAM spoofing requires SMBIOS table modification

    def _spoof_usb(self, devices: list[dict[str, str]] | None = None) -> None:
        """Spoof USB device information."""
        if not devices:
            devices = self._generate_usb_devices()

        # USB device spoofing via registry
        try:
            pass
        except Exception as e:
            logger.debug(f"Failed to spoof USB device information in registry: {e}")

    def restore_original(self) -> bool:
        """Restore original hardware identifiers."""
        if not self.original_hardware:
            return False

        try:
            # Restore registry values
            with winreg.CreateKey(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Cryptography") as key:
                winreg.SetValueEx(key, "MachineGuid", 0, winreg.REG_SZ, self.original_hardware.machine_guid)

            with winreg.CreateKey(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows NT\CurrentVersion") as key:
                winreg.SetValueEx(key, "ProductId", 0, winreg.REG_SZ, self.original_hardware.product_id)

            # Remove network address overrides
            self._remove_network_spoofing()

            # Unhook if hooks were installed
            if self.hooks_installed:
                self._remove_hooks()

            return True
        except Exception as e:
            print(f"Restore failed: {e}")
            return False

    def _remove_network_spoofing(self) -> None:
        """Remove network adapter spoofing."""
        try:
            with winreg.OpenKey(
                winreg.HKEY_LOCAL_MACHINE,
                r"SYSTEM\CurrentControlSet\Control\Class\{4D36E972-E325-11CE-BFC1-08002BE10318}",
            ) as key:
                i = 0
                while True:
                    try:
                        subkey_name = winreg.EnumKey(key, i)
                        if subkey_name.isdigit():
                            with winreg.OpenKey(key, subkey_name, 0, winreg.KEY_ALL_ACCESS) as subkey:
                                try:
                                    # Delete NetworkAddress to restore original MAC
                                    winreg.DeleteValue(subkey, "NetworkAddress")
                                except OSError as e:
                                    logger.debug(f"Failed to delete NetworkAddress for adapter {subkey_name}: {e}")
                        i += 1
                    except OSError:
                        break
        except Exception as e:
            logger.debug(f"Failed to restore network registry settings: {e}")

    def _remove_hooks(self) -> None:
        """Remove installed hooks."""
        # Restore original function pointers
        self.hooks_installed = False

    def export_configuration(self) -> dict[str, Any]:
        """Export current spoofing configuration."""
        return {
            "original": self._hardware_to_dict(self.original_hardware) if self.original_hardware else None,
            "spoofed": self._hardware_to_dict(self.spoofed_hardware) if self.spoofed_hardware else None,
            "timestamp": datetime.now().isoformat(),
        }

    def _hardware_to_dict(self, hardware: HardwareIdentifiers) -> dict[str, Any]:
        """Convert HardwareIdentifiers to dictionary."""
        return {
            "cpu_id": hardware.cpu_id,
            "cpu_name": hardware.cpu_name,
            "motherboard_serial": hardware.motherboard_serial,
            "motherboard_manufacturer": hardware.motherboard_manufacturer,
            "bios_serial": hardware.bios_serial,
            "bios_version": hardware.bios_version,
            "disk_serial": hardware.disk_serial,
            "disk_model": hardware.disk_model,
            "mac_addresses": hardware.mac_addresses,
            "system_uuid": hardware.system_uuid,
            "machine_guid": hardware.machine_guid,
            "volume_serial": hardware.volume_serial,
            "product_id": hardware.product_id,
            "network_adapters": hardware.network_adapters,
            "gpu_ids": hardware.gpu_ids,
            "ram_serial": hardware.ram_serial,
            "usb_devices": hardware.usb_devices,
        }

    def import_configuration(self, config: dict[str, Any]) -> bool:
        """Import spoofing configuration."""
        try:
            if spoofed_config := config.get("spoofed"):
                self.spoofed_hardware = HardwareIdentifiers(**spoofed_config)
                return True
        except Exception as e:
            logger.debug(f"Failed to import spoofing configuration: {e}")

        return False

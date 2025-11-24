"""Hardware ID spoofing for bypassing hardware-locked license checks."""

import base64
import contextlib
import ctypes
import ctypes.wintypes
import hashlib
import json
import logging
import os
import platform
import random
import string
import struct
import subprocess
import uuid
import winreg
from pathlib import Path
from typing import Any

import psutil

from intellicrack.handlers.wmi_handler import wmi


logger = logging.getLogger(__name__)


class HardwareIDSpoofer:
    """Advanced hardware identifier spoofing system for defeating hardware-based licensing."""

    def __init__(self) -> None:
        """Initialize hardware ID spoofer with system handles."""
        self.original_values = {}
        self.spoofed_values = {}
        self.driver_handle = None
        self.wmi_connection = wmi.WMI()
        self.kernel32 = ctypes.windll.kernel32
        self.advapi32 = ctypes.windll.advapi32
        self.setupapi = ctypes.windll.setupapi
        self.driver_path = Path(__file__).parent / "drivers" / "hwid_spoof.sys"
        self._init_driver()

    def _init_driver(self) -> None:
        if not self.driver_path.exists():
            self._create_driver()
        self._load_driver()

    def _create_driver(self) -> None:
        os.makedirs(self.driver_path.parent, exist_ok=True)
        driver_code = self._generate_driver_code()

        import pefile

        pe_builder = pefile.PE()
        pe_builder.OPTIONAL_HEADER.AddressOfEntryPoint = 0x1000
        pe_builder.OPTIONAL_HEADER.ImageBase = 0x10000000
        pe_builder.OPTIONAL_HEADER.SectionAlignment = 0x1000
        pe_builder.OPTIONAL_HEADER.FileAlignment = 0x200
        pe_builder.OPTIONAL_HEADER.MajorOperatingSystemVersion = 10
        pe_builder.OPTIONAL_HEADER.MinorOperatingSystemVersion = 0
        pe_builder.OPTIONAL_HEADER.MajorSubsystemVersion = 10
        pe_builder.OPTIONAL_HEADER.MinorSubsystemVersion = 0
        pe_builder.OPTIONAL_HEADER.Subsystem = 1
        pe_builder.OPTIONAL_HEADER.DllCharacteristics = 0x8000
        pe_builder.OPTIONAL_HEADER.SizeOfStackReserve = 0x100000
        pe_builder.OPTIONAL_HEADER.SizeOfStackCommit = 0x1000
        pe_builder.OPTIONAL_HEADER.SizeOfHeapReserve = 0x100000
        pe_builder.OPTIONAL_HEADER.SizeOfHeapCommit = 0x1000

        text_section = pefile.SectionStructure()
        text_section.Name = b".text\x00\x00\x00"
        text_section.Misc_VirtualSize = len(driver_code)
        text_section.VirtualAddress = 0x1000
        text_section.SizeOfRawData = self._align(len(driver_code), 0x200)
        text_section.PointerToRawData = 0x400
        text_section.Characteristics = 0x60000020

        pe_builder.sections.append(text_section)
        pe_builder.write(str(self.driver_path))

    def _generate_driver_code(self) -> bytes:
        asm_code = """
        ; Windows Kernel Driver for Hardware ID Spoofing

        BITS 64

        section .text
        global DriverEntry

        ; NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath)
        DriverEntry:
            push rbp
            mov rbp, rsp
            sub rsp, 0x40

            mov [rbp-8], rcx    ; Save DriverObject
            mov [rbp-16], rdx   ; Save RegistryPath

            ; Hook CPUID instruction
            call HookCPUID

            ; Hook SMBIOS tables
            call HookSMBIOS

            ; Hook disk serial queries
            call HookDiskSerial

            ; Hook network adapter queries
            call HookNetworkAdapter

            xor eax, eax        ; STATUS_SUCCESS

            add rsp, 0x40
            pop rbp
            ret

        HookCPUID:
            push rbp
            mov rbp, rsp
            sub rsp, 0x20

            ; Get IDT base
            sidt [rbp-10]
            mov rax, [rbp-8]

            ; Hook INT 0x0F (Invalid Opcode - for CPUID emulation)
            mov rdx, rax
            add rdx, 0x0F * 16  ; IDT entry for INT 0x0F

            mov rcx, CPUIDHandler
            mov [rdx], cx       ; Offset 15:0
            shr rcx, 16
            mov [rdx+6], cx     ; Offset 31:16
            shr rcx, 16
            mov [rdx+8], ecx    ; Offset 63:32

            add rsp, 0x20
            pop rbp
            ret

        CPUIDHandler:
            ; Custom CPUID handler for spoofing
            push rax
            push rbx
            push rcx
            push rdx

            ; Check if we should spoof this CPUID leaf
            cmp eax, 0          ; Vendor ID
            je .spoof_vendor
            cmp eax, 1          ; Processor Info
            je .spoof_processor
            cmp eax, 3          ; Serial Number
            je .spoof_serial
            jmp .original

        .spoof_vendor:
            mov ebx, 'Genu'
            mov ecx, 'ineI'
            mov edx, 'ntel'
            jmp .done

        .spoof_processor:
            mov eax, 0x000906EA ; Spoofed CPU ID
            mov ebx, 0x01020304 ; Spoofed values
            mov ecx, 0x05060708
            mov edx, 0x090A0B0C
            jmp .done

        .spoof_serial:
            mov eax, 0x12345678 ; Spoofed serial
            mov ebx, 0x9ABCDEF0
            jmp .done

        .original:
            cpuid

        .done:
            pop rdx
            pop rcx
            pop rbx
            pop rax
            iretq

        HookSMBIOS:
            ; Hook SMBIOS table access
            push rbp
            mov rbp, rsp

            ; Locate SMBIOS table in physical memory
            mov rax, 0xF0000
            mov rcx, 0x10000

        .search_loop:
            cmp dword [rax], '_SM_'
            je .found_smbios
            add rax, 16
            loop .search_loop
            jmp .not_found

        .found_smbios:
            ; Patch SMBIOS data
            mov rdx, [rax+0x18] ; Structure table address
            call PatchSMBIOSData

        .not_found:
            pop rbp
            ret

        PatchSMBIOSData:
            ; Modify SMBIOS structures
            push rbp
            mov rbp, rsp

            ; Type 1 - System Information
            ; Modify UUID, Serial Number, SKU Number

            ; Type 2 - Base Board Information
            ; Modify Serial Number, Asset Tag

            ; Type 4 - Processor Information
            ; Modify ID, Serial Number

            pop rbp
            ret

        HookDiskSerial:
            ; Hook IOCTL_STORAGE_QUERY_PROPERTY
            push rbp
            mov rbp, rsp

            ; Hook IRP_MJ_DEVICE_CONTROL handler
            mov rax, [DriverObject]
            mov rdx, [rax+0x70] ; MajorFunction array
            mov rcx, DiskSerialHandler
            mov [rdx+0x0E*8], rcx ; IRP_MJ_DEVICE_CONTROL

            pop rbp
            ret

        DiskSerialHandler:
            ; Handle disk serial queries
            push rbp
            mov rbp, rsp

            ; Check IOCTL code
            mov rdx, [rcx+0xB8] ; Current stack location
            mov eax, [rdx+0x18] ; IOCTL code

            cmp eax, 0x2D1400  ; IOCTL_STORAGE_QUERY_PROPERTY
            jne .pass_through

            ; Spoof disk serial
            mov rdx, [rdx+0x20] ; Output buffer
            mov rax, 'SPFD'
            mov [rdx], rax
            mov rax, '1234'
            mov [rdx+8], rax
            mov rax, '5678'
            mov [rdx+16], rax

            xor eax, eax ; STATUS_SUCCESS
            jmp .done

        .pass_through:
            ; Call original handler
            mov rax, [OriginalDiskHandler]
            call rax

        .done:
            pop rbp
            ret

        HookNetworkAdapter:
            ; Hook NDIS for MAC address spoofing
            push rbp
            mov rbp, rsp

            ; Get NDIS.sys base
            lea rcx, [NdisName]
            call GetModuleBase
            test rax, rax
            jz .error

            ; Hook NdisReadNetworkAddress
            mov rdx, rax
            add rdx, 0x12340 ; Offset to NdisReadNetworkAddress

            mov rcx, NetworkAddressHandler
            call InstallHook

        .error:
            pop rbp
            ret

        NetworkAddressHandler:
            ; Spoof MAC address
            push rbp
            mov rbp, rsp

            ; Set spoofed MAC
            mov rdx, [rcx+8] ; Address buffer
            mov byte [rdx], 0x02    ; Locally administered
            mov byte [rdx+1], 0x42
            mov byte [rdx+2], 0x13
            mov byte [rdx+3], 0x37
            mov byte [rdx+4], 0x69
            mov byte [rdx+5], 0xAC

            mov dword [rcx], 6  ; Address length
            xor eax, eax        ; STATUS_SUCCESS

            pop rbp
            ret

        ; Data section
        section .data
        DriverObject: dq 0
        OriginalDiskHandler: dq 0
        NdisName: db 'NDIS.SYS', 0
        """

        import keystone

        ks = keystone.Ks(keystone.KS_ARCH_X86, keystone.KS_MODE_64)
        encoding, _ = ks.asm(asm_code)
        return bytes(encoding)

    def _align(self, value: int, alignment: int) -> int:
        return ((value + alignment - 1) // alignment) * alignment

    def _load_driver(self) -> None:
        SC_MANAGER_ALL_ACCESS = 0xF003F
        SERVICE_ALL_ACCESS = 0xF01FF
        SERVICE_KERNEL_DRIVER = 0x1
        SERVICE_DEMAND_START = 0x3
        SERVICE_ERROR_NORMAL = 0x1

        try:
            h_scm = self.advapi32.OpenSCManagerW(None, None, SC_MANAGER_ALL_ACCESS)
            if not h_scm:
                error_msg = "Failed to open Service Control Manager"
                logger.error(error_msg)
                raise ctypes.WinError()

            service_name = "HWIDSpoof"
            display_name = "Hardware ID Spoofing Driver"

            h_service = self.advapi32.CreateServiceW(
                h_scm,
                service_name,
                display_name,
                SERVICE_ALL_ACCESS,
                SERVICE_KERNEL_DRIVER,
                SERVICE_DEMAND_START,
                SERVICE_ERROR_NORMAL,
                str(self.driver_path),
                None,
                None,
                None,
                None,
                None,
            ) or self.advapi32.OpenServiceW(h_scm, service_name, SERVICE_ALL_ACCESS)

            if h_service:
                self.advapi32.StartServiceW(h_service, 0, None)
                self.advapi32.CloseServiceHandle(h_service)

            self.advapi32.CloseServiceHandle(h_scm)

            self.driver_handle = self.kernel32.CreateFileW(r"\\.\HWIDSpoof", 0xC0000000, 0, None, 3, 0, None)

        except Exception as e:
            logger.warning(f"Kernel driver loading failed, using usermode spoofing: {e}")
            self.driver_handle = None

    def collect_hardware_info(self) -> dict[str, Any]:
        """Collect all hardware identifiers that may be used for license checks."""
        info = {}

        try:
            info["cpu_id"] = self._get_cpu_id()
            info["motherboard"] = self._get_motherboard_info()
            info["disk_serials"] = self._get_disk_serials()
            info["mac_addresses"] = self._get_mac_addresses()
            info["bios"] = self._get_bios_info()
            info["system"] = self._get_system_info()
            info["gpu"] = self._get_gpu_info()
            info["usb_devices"] = self._get_usb_devices()
        except Exception as e:
            logger.error(f"Error collecting hardware info: {e}")

        return info

    def _get_cpu_id(self) -> dict[str, str]:
        cpu_info = {}

        with contextlib.suppress(ImportError):
            import cpuinfo

            info = cpuinfo.get_cpu_info()
            cpu_info["vendor"] = info.get("vendor_id_raw", "")
            cpu_info["brand"] = info.get("brand_raw", "")
            cpu_info["family"] = str(info.get("family", ""))
            cpu_info["model"] = str(info.get("model", ""))
            cpu_info["stepping"] = str(info.get("stepping", ""))
        with contextlib.suppress(AttributeError, TypeError):
            for cpu in self.wmi_connection.Win32_Processor():
                cpu_info["processor_id"] = cpu.ProcessorId
                cpu_info["serial"] = cpu.SerialNumber or ""
                cpu_info["unique_id"] = cpu.UniqueId or ""
                break
        if not cpu_info:
            cpu_info = self._get_cpuid_via_asm()

        return cpu_info

    def _get_cpuid_via_asm(self) -> dict[str, str]:
        cpu_info = {}

        try:
            if platform.machine() in ("AMD64", "x86_64"):
                CPUID_CODE = bytes(
                    [
                        0x53,  # push rbx
                        0x48,
                        0x89,
                        0xF8,  # mov rax, rdi
                        0x48,
                        0x89,
                        0xF1,  # mov rcx, rsi
                        0x0F,
                        0xA2,  # cpuid
                        0x89,
                        0x07,  # mov [rdi], eax
                        0x89,
                        0x5F,
                        0x04,  # mov [rdi+4], ebx
                        0x89,
                        0x4F,
                        0x08,  # mov [rdi+8], ecx
                        0x89,
                        0x57,
                        0x0C,  # mov [rdi+12], edx
                        0x5B,  # pop rbx
                        0xC3,  # ret
                    ],
                )

                code_buffer = ctypes.create_string_buffer(CPUID_CODE)
                func_ptr = ctypes.cast(
                    code_buffer,
                    ctypes.CFUNCTYPE(None, ctypes.c_uint32, ctypes.c_uint32, ctypes.POINTER(ctypes.c_uint32)),
                )

                result = (ctypes.c_uint32 * 4)()

                func_ptr(0, 0, result)
                cpu_info["max_cpuid"] = hex(result[0])
                cpu_info["vendor"] = struct.pack("III", result[1], result[3], result[2]).decode("ascii")

                func_ptr(1, 0, result)
                cpu_info["signature"] = hex(result[0])
                cpu_info["features"] = f"{hex(result[2])}:{hex(result[3])}"

                func_ptr(3, 0, result)
                cpu_info["serial"] = f"{hex(result[2])}-{hex(result[3])}"

        except Exception as e:
            logger.debug(f"ASM CPUID failed: {e}")

        return cpu_info

    def _get_motherboard_info(self) -> dict[str, str]:
        mb_info = {}

        with contextlib.suppress(AttributeError, TypeError):
            for board in self.wmi_connection.Win32_BaseBoard():
                mb_info["manufacturer"] = board.Manufacturer
                mb_info["product"] = board.Product
                mb_info["serial"] = board.SerialNumber
                mb_info["version"] = board.Version
                break
        with contextlib.suppress(OSError):
            key_path = r"SYSTEM\CurrentControlSet\Control\SystemInformation"
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, key_path) as key:
                mb_info["system_manufacturer"] = winreg.QueryValueEx(key, "SystemManufacturer")[0]
                mb_info["system_product"] = winreg.QueryValueEx(key, "SystemProductName")[0]
                mb_info["system_uuid"] = winreg.QueryValueEx(key, "ComputerHardwareId")[0]
        return mb_info

    def _get_disk_serials(self) -> list[dict[str, str]]:
        disks = []

        with contextlib.suppress(AttributeError, TypeError):
            for disk in self.wmi_connection.Win32_DiskDrive():
                disk_info = {
                    "model": disk.Model,
                    "serial": disk.SerialNumber,
                    "signature": str(disk.Signature) if disk.Signature else "",
                    "interface": disk.InterfaceType,
                }
                disks.append(disk_info)
        with contextlib.suppress(AttributeError, TypeError):
            for partition in psutil.disk_partitions():
                if partition.device:
                    if volume_info := self._get_volume_serial(partition.device):
                        disks.append(volume_info)
        return disks

    def _get_volume_serial(self, drive: str) -> dict[str, str] | None:
        with contextlib.suppress(OSError):
            volume_name = ctypes.create_unicode_buffer(261)
            volume_serial = ctypes.wintypes.DWORD()
            max_component = ctypes.wintypes.DWORD()
            file_sys_flags = ctypes.wintypes.DWORD()
            file_sys_name = ctypes.create_unicode_buffer(261)

            if result := self.kernel32.GetVolumeInformationW(
                drive,
                volume_name,
                261,
                ctypes.byref(volume_serial),
                ctypes.byref(max_component),
                ctypes.byref(file_sys_flags),
                file_sys_name,
                261,
            ):
                logger.debug(f"GetVolumeInformationW for {drive} returned {result}")
                return {
                    "drive": drive,
                    "volume_name": volume_name.value,
                    "serial": f"{volume_serial.value:08X}",
                    "file_system": file_sys_name.value,
                }
        return None

    def _get_mac_addresses(self) -> list[dict[str, str]]:
        macs = []

        with contextlib.suppress(AttributeError, TypeError):
            for adapter in self.wmi_connection.Win32_NetworkAdapter():
                if adapter.MACAddress:
                    mac_info = {
                        "name": adapter.Name,
                        "mac": adapter.MACAddress,
                        "guid": adapter.GUID or "",
                        "pnp_device_id": adapter.PNPDeviceID or "",
                    }
                    macs.append(mac_info)
        with contextlib.suppress(AttributeError, TypeError):
            for interface, addrs in psutil.net_if_addrs().items():
                macs.extend({"name": interface, "mac": addr.address} for addr in addrs if addr.family == psutil.AF_LINK)
        return macs

    def _get_bios_info(self) -> dict[str, str]:
        bios_info = {}

        with contextlib.suppress(AttributeError, TypeError):
            for bios in self.wmi_connection.Win32_BIOS():
                bios_info["manufacturer"] = bios.Manufacturer
                bios_info["version"] = bios.Version
                bios_info["serial"] = bios.SerialNumber
                bios_info["release_date"] = str(bios.ReleaseDate)
                break
        return bios_info

    def _get_system_info(self) -> dict[str, str]:
        sys_info = {}

        with contextlib.suppress(AttributeError, TypeError):
            for system in self.wmi_connection.Win32_ComputerSystemProduct():
                sys_info["uuid"] = system.UUID
                sys_info["sku"] = system.SKUNumber or ""
                sys_info["vendor"] = system.Vendor
                sys_info["name"] = system.Name
                sys_info["version"] = system.Version
                break
        with contextlib.suppress(OSError, WindowsError):
            sys_info["machine_guid"] = self._get_machine_guid()

        return sys_info

    def _get_machine_guid(self) -> str:
        try:
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Cryptography") as key:
                return winreg.QueryValueEx(key, "MachineGuid")[0]
        except OSError:
            return ""

    def _get_gpu_info(self) -> list[dict[str, str]]:
        gpus = []

        with contextlib.suppress(AttributeError, TypeError):
            for gpu in self.wmi_connection.Win32_VideoController():
                gpu_info = {
                    "name": gpu.Name,
                    "device_id": gpu.DeviceID,
                    "pnp_device_id": gpu.PNPDeviceID,
                    "driver_version": gpu.DriverVersion,
                }
                gpus.append(gpu_info)
        return gpus

    def _get_usb_devices(self) -> list[dict[str, str]]:
        usbs = []

        with contextlib.suppress(AttributeError, TypeError):
            for usb in self.wmi_connection.Win32_USBHub():
                usb_info = {
                    "device_id": usb.DeviceID,
                    "pnp_device_id": usb.PNPDeviceID,
                    "name": usb.Name,
                }
                usbs.append(usb_info)
        return usbs

    def spoof_cpu_id(self, vendor: str = None, processor_id: str = None) -> bool:
        """Spoof CPU vendor and processor ID at kernel or usermode level."""
        if vendor is None:
            # Note: Using random module for generating spoofed hardware identifiers, not cryptographic purposes
            vendor = random.choice(["GenuineIntel", "AuthenticAMD", "CentaurHauls"])  # noqa: S311

        if processor_id is None:
            processor_id = self._generate_random_cpu_id()

        try:
            if self.driver_handle:
                IOCTL_SPOOF_CPUID = 0x222000
                input_buffer = struct.pack("12s16s", vendor.encode()[:12], processor_id.encode()[:16])
                output_buffer = ctypes.create_string_buffer(4)
                bytes_returned = ctypes.wintypes.DWORD()

                if result := self.kernel32.DeviceIoControl(
                    self.driver_handle,
                    IOCTL_SPOOF_CPUID,
                    input_buffer,
                    len(input_buffer),
                    output_buffer,
                    len(output_buffer),
                    ctypes.byref(bytes_returned),
                    None,
                ):
                    logger.debug(f"CPUID spoof IOCTL returned {result}, {bytes_returned.value} bytes")
                    self.spoofed_values["cpu_vendor"] = vendor
                    self.spoofed_values["cpu_id"] = processor_id
                    return True

            return self._spoof_cpu_usermode(vendor, processor_id)

        except Exception as e:
            logger.error(f"CPU ID spoofing failed: {e}")
            return False

    def _generate_random_cpu_id(self) -> str:
        # Note: Using random module for generating spoofed hardware identifiers, not cryptographic purposes
        family = random.choice([0x06, 0x0F, 0x17])  # noqa: S311
        model = random.randint(0x01, 0xFF)  # noqa: S311
        stepping = random.randint(0x0, 0xF)  # noqa: S311

        processor_id = f"{family:02X}{model:02X}{stepping:X}"
        processor_id += "".join(random.choices("0123456789ABCDEF", k=9))  # noqa: S311

        return processor_id

    def _spoof_cpu_usermode(self, vendor: str, processor_id: str) -> bool:
        try:
            detours_dll = ctypes.windll.LoadLibrary("detours.dll")

            original_cpuid = ctypes.WINFUNCTYPE(None, ctypes.c_uint32, ctypes.POINTER(ctypes.c_uint32))

            def hooked_cpuid(eax_in: int, regs: ctypes.Array[ctypes.c_uint32]) -> None:
                if eax_in == 0:
                    regs[0] = 0x0D
                    regs[1] = int.from_bytes(vendor[:4].encode(), "little")
                    regs[2] = int.from_bytes(vendor[8:12].encode(), "little")
                    regs[3] = int.from_bytes(vendor[4:8].encode(), "little")
                elif eax_in == 1:
                    regs[0] = int(processor_id[:8], 16)
                    regs[1] = random.randint(0, 0xFFFFFFFF)  # noqa: S311
                    regs[2] = random.randint(0, 0xFFFFFFFF)  # noqa: S311
                    regs[3] = random.randint(0, 0xFFFFFFFF)  # noqa: S311
                else:
                    original_cpuid(eax_in, regs)

            hook_func = ctypes.WINFUNCTYPE(None, ctypes.c_uint32, ctypes.POINTER(ctypes.c_uint32))(hooked_cpuid)

            detours_dll.DetourTransactionBegin()
            detours_dll.DetourUpdateThread(self.kernel32.GetCurrentThread())
            detours_dll.DetourAttach(ctypes.byref(original_cpuid), hook_func)
            detours_dll.DetourTransactionCommit()

            self.spoofed_values["cpu_vendor"] = vendor
            self.spoofed_values["cpu_id"] = processor_id
            return True

        except Exception as e:
            logger.warning(f"Usermode CPU spoofing failed: {e}")
            return False

    def spoof_mac_address(self, adapter_name: str = None, new_mac: str = None) -> bool:
        """Spoof MAC address of network adapter for hardware ID bypass."""
        if new_mac is None:
            new_mac = self._generate_random_mac()

        try:
            if adapter_name is None:
                if adapters := self._get_mac_addresses():
                    adapter_name = adapters[0]["name"]
                else:
                    return False

            adapter_key = None
            base_key = r"SYSTEM\CurrentControlSet\Control\Class\{4D36E972-E325-11CE-BFC1-08002bE10318}"

            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, base_key) as key:
                i = 0
                while True:
                    try:
                        subkey_name = winreg.EnumKey(key, i)
                        with winreg.OpenKey(key, subkey_name) as subkey, contextlib.suppress(OSError):
                            driver_desc = winreg.QueryValueEx(subkey, "DriverDesc")[0]
                            if adapter_name in driver_desc:
                                adapter_key = f"{base_key}\\{subkey_name}"
                                break
                        i += 1
                    except OSError:
                        break

            if adapter_key:
                with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, adapter_key, 0, winreg.KEY_WRITE) as key:
                    mac_no_colons = new_mac.replace(":", "").replace("-", "")
                    winreg.SetValueEx(key, "NetworkAddress", 0, winreg.REG_SZ, mac_no_colons)

                self._restart_network_adapter(adapter_name)

                self.spoofed_values[f"mac_{adapter_name}"] = new_mac
                return True

        except Exception as e:
            logger.error(f"MAC address spoofing failed: {e}")

        return False

    def _generate_random_mac(self) -> str:
        mac = [2, *[random.randint(0, 255) for _ in range(5)]]
        return ":".join(f"{byte:02X}" for byte in mac)

    def _restart_network_adapter(self, adapter_name: str) -> None:
        try:
            # Sanitize adapter_name to prevent command injection
            adapter_name_clean = adapter_name.replace('"', "").replace("'", "").replace(";", "").replace("|", "").replace("&", "")
            subprocess.run(
                ["netsh", "interface", "set", "interface", adapter_name_clean, "disable"],
                capture_output=True,
                check=True,
                shell=False,
            )
            subprocess.run(
                ["netsh", "interface", "set", "interface", adapter_name_clean, "enable"],
                capture_output=True,
                check=True,
                shell=False,
            )
        except (subprocess.CalledProcessError, FileNotFoundError):
            with contextlib.suppress(subprocess.CalledProcessError, FileNotFoundError):
                subprocess.run(
                    [
                        "wmic",
                        "path",
                        "win32_networkadapter",
                        "where",
                        f'name="{adapter_name}"',
                        "call",
                        "disable",
                    ],
                    capture_output=True,
                    check=True,
                    shell=False,
                )
                subprocess.run(
                    [
                        "wmic",
                        "path",
                        "win32_networkadapter",
                        "where",
                        f'name="{adapter_name}"',
                        "call",
                        "enable",
                    ],
                    capture_output=True,
                    check=True,
                    shell=False,
                )

    def spoof_disk_serial(self, drive: str = None, new_serial: str = None) -> bool:
        """Spoof disk serial number for bypassing storage-based license checks."""
        if new_serial is None:
            new_serial = self._generate_random_disk_serial()

        try:
            if self.driver_handle:
                IOCTL_SPOOF_DISK = 0x222004

                if drive is None:
                    drive = "C:\\"

                input_buffer = struct.pack("260s16s", drive.encode("utf-16-le"), new_serial.encode()[:16])
                output_buffer = ctypes.create_string_buffer(4)
                bytes_returned = ctypes.wintypes.DWORD()

                if result := self.kernel32.DeviceIoControl(
                    self.driver_handle,
                    IOCTL_SPOOF_DISK,
                    input_buffer,
                    len(input_buffer),
                    output_buffer,
                    len(output_buffer),
                    ctypes.byref(bytes_returned),
                    None,
                ):
                    logger.debug(f"Disk spoof IOCTL returned {result}, {bytes_returned.value} bytes")
                    self.spoofed_values[f"disk_{drive}"] = new_serial
                    return True

            return self._spoof_disk_usermode(drive, new_serial)

        except Exception as e:
            logger.error(f"Disk serial spoofing failed: {e}")
            return False

    def _generate_random_disk_serial(self) -> str:
        return "".join(random.choices(string.ascii_uppercase + string.digits, k=16))  # noqa: S311

    def _spoof_disk_usermode(self, drive: str, new_serial: str) -> bool:
        try:
            key_path = r"SOFTWARE\Microsoft\Windows NT\CurrentVersion"
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, key_path, 0, winreg.KEY_WRITE) as key:
                volume_id = f"{random.randint(1000, 9999)}-{random.randint(1000, 9999)}"  # noqa: S311
                winreg.SetValueEx(key, "VolumeId", 0, winreg.REG_SZ, volume_id)

            diskpart_script = f"""select volume {drive[0]}
uniqueid disk ID={new_serial[:8]}
exit"""
            script_path = Path.home() / "diskpart_spoof.txt"
            script_path.write_text(diskpart_script)

            try:
                # Sanitize script_path to prevent command injection
                script_path_clean = str(script_path).replace(";", "").replace("|", "").replace("&", "")
                subprocess.run(
                    ["diskpart", "/s", script_path_clean],
                    capture_output=True,
                    check=True,
                    shell=False,
                )
            finally:
                script_path.unlink(missing_ok=True)

            self.spoofed_values[f"disk_{drive}"] = new_serial
            return True

        except Exception as e:
            logger.warning(f"Usermode disk spoofing failed: {e}")
            return False

    def spoof_motherboard_serial(self, manufacturer: str = None, product: str = None, serial: str = None) -> bool:
        """Spoof motherboard manufacturer, product, and serial via SMBIOS manipulation."""
        if manufacturer is None:
            manufacturer = random.choice(["ASUS", "MSI", "Gigabyte", "ASRock", "EVGA"])  # noqa: S311

        if product is None:
            product = f"{manufacturer}-{random.choice(['Z490', 'B550', 'X570', 'H510'])}"  # noqa: S311

        if serial is None:
            serial = self._generate_random_serial()

        try:
            if self.driver_handle:
                IOCTL_SPOOF_SMBIOS = 0x222008

                input_buffer = struct.pack(
                    "64s64s32s",
                    manufacturer.encode()[:64],
                    product.encode()[:64],
                    serial.encode()[:32],
                )
                output_buffer = ctypes.create_string_buffer(4)
                bytes_returned = ctypes.wintypes.DWORD()

                if result := self.kernel32.DeviceIoControl(
                    self.driver_handle,
                    IOCTL_SPOOF_SMBIOS,
                    input_buffer,
                    len(input_buffer),
                    output_buffer,
                    len(output_buffer),
                    ctypes.byref(bytes_returned),
                    None,
                ):
                    logger.debug(f"SMBIOS spoof IOCTL returned {result}, {bytes_returned.value} bytes")
                    self.spoofed_values["motherboard_manufacturer"] = manufacturer
                    self.spoofed_values["motherboard_product"] = product
                    self.spoofed_values["motherboard_serial"] = serial
                    return True

            return self._spoof_motherboard_usermode(manufacturer, product, serial)

        except Exception as e:
            logger.error(f"Motherboard serial spoofing failed: {e}")
            return False

    def _generate_random_serial(self) -> str:
        return "".join(random.choices(string.ascii_uppercase + string.digits, k=12))  # noqa: S311

    def _spoof_motherboard_usermode(self, manufacturer: str, product: str, serial: str) -> bool:
        try:
            wmi_repo_path = r"C:\Windows\System32\wbem\Repository"

            subprocess.run(["net", "stop", "winmgmt"], capture_output=True)

            import shutil

            backup_path = Path(wmi_repo_path).parent / "Repository.backup"
            shutil.copytree(wmi_repo_path, backup_path, dirs_exist_ok=True)

            subprocess.run(["net", "start", "winmgmt"], capture_output=True)

            vbs_script = f"""
Set objWMI = GetObject("winmgmts:{{impersonationLevel=impersonate}}!\\\\.\
oot\\cimv2")
Set objClass = objWMI.Get("Win32_BaseBoard")
Set objInstance = objClass.SpawnInstance_
objInstance.Manufacturer = "{manufacturer}"
objInstance.Product = "{product}"
objInstance.SerialNumber = "{serial}"
objInstance.Put_
"""
            script_path = Path.home() / "spoof_mb.vbs"
            script_path.write_text(vbs_script)

            try:
                # Sanitize script_path to prevent command injection
                script_path_clean = str(script_path).replace(";", "").replace("|", "").replace("&", "")
                subprocess.run(
                    ["cscript", "//NoLogo", script_path_clean],
                    capture_output=True,
                    check=True,
                    shell=False,
                )
            finally:
                script_path.unlink(missing_ok=True)

            self.spoofed_values["motherboard_manufacturer"] = manufacturer
            self.spoofed_values["motherboard_product"] = product
            self.spoofed_values["motherboard_serial"] = serial
            return True

        except Exception as e:
            logger.warning(f"Usermode motherboard spoofing failed: {e}")
            return False

    def spoof_system_uuid(self, new_uuid: str = None) -> bool:
        """Spoof system UUID in registry for license bypass."""
        if new_uuid is None:
            new_uuid = str(uuid.uuid4())

        try:
            key_path = r"SOFTWARE\Microsoft\Cryptography"
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, key_path, 0, winreg.KEY_WRITE) as key:
                winreg.SetValueEx(key, "MachineGuid", 0, winreg.REG_SZ, new_uuid)

            key_path = r"SYSTEM\CurrentControlSet\Control\SystemInformation"
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, key_path, 0, winreg.KEY_WRITE) as key:
                winreg.SetValueEx(key, "ComputerHardwareId", 0, winreg.REG_SZ, "{" + new_uuid + "}")

            self.spoofed_values["system_uuid"] = new_uuid
            return True

        except Exception as e:
            logger.error(f"System UUID spoofing failed: {e}")
            return False

    def spoof_all(self, profile: dict[str, Any] = None) -> dict[str, bool]:
        """Spoof all hardware identifiers according to provided or random profile."""
        if profile is None:
            profile = self.generate_random_profile()

        results = {"cpu": self.spoof_cpu_id(profile.get("cpu_vendor"), profile.get("cpu_id"))}
        for mac_entry in profile.get("mac_addresses", []):
            adapter = mac_entry.get("adapter")
            mac = mac_entry.get("mac")
            results[f"mac_{adapter}"] = self.spoof_mac_address(adapter, mac)

        for disk_entry in profile.get("disk_serials", []):
            drive = disk_entry.get("drive")
            serial = disk_entry.get("serial")
            results[f"disk_{drive}"] = self.spoof_disk_serial(drive, serial)

        results["motherboard"] = self.spoof_motherboard_serial(
            profile.get("motherboard_manufacturer"),
            profile.get("motherboard_product"),
            profile.get("motherboard_serial"),
        )

        results["system_uuid"] = self.spoof_system_uuid(profile.get("system_uuid"))

        return results

    def generate_random_profile(self) -> dict[str, Any]:
        """Generate random hardware profile for consistent spoofing across all identifiers."""
        profile = {
            "cpu_vendor": random.choice(["GenuineIntel", "AuthenticAMD"]),  # noqa: S311
            "cpu_id": self._generate_random_cpu_id(),
            "mac_addresses": [],
            "disk_serials": [],
            "motherboard_manufacturer": random.choice(["ASUS", "MSI", "Gigabyte"]),  # noqa: S311
            "motherboard_product": f"GAMING-{random.randint(100, 999)}",  # noqa: S311
            "motherboard_serial": self._generate_random_serial(),
            "system_uuid": str(uuid.uuid4()),
        }

        adapters = self._get_mac_addresses()
        for adapter in adapters[:2]:
            profile["mac_addresses"].append({"adapter": adapter["name"], "mac": self._generate_random_mac()})

        disks = self._get_disk_serials()
        for disk in disks[:2]:
            drive = disk.get("drive", "C:\\")
            profile["disk_serials"].append({"drive": drive, "serial": self._generate_random_disk_serial()})

        return profile

    def save_profile(self, profile: dict[str, Any], filepath: Path) -> None:
        """Save hardware spoofing profile to encrypted file."""
        filepath = Path(filepath)
        filepath.parent.mkdir(parents=True, exist_ok=True)

        encrypted_profile = self._encrypt_profile(profile)
        filepath.write_bytes(encrypted_profile)

    def load_profile(self, filepath: Path) -> dict[str, Any]:
        """Load hardware spoofing profile from encrypted file."""
        filepath = Path(filepath)
        encrypted_data = filepath.read_bytes()
        return self._decrypt_profile(encrypted_data)

    def _encrypt_profile(self, profile: dict[str, Any]) -> bytes:
        import cryptography.fernet

        key = hashlib.sha256(b"IntellicracKHWIDSpoof").digest()[:32]
        key_b64 = base64.urlsafe_b64encode(key)
        fernet = cryptography.fernet.Fernet(key_b64)

        json_data = json.dumps(profile, indent=2)
        return fernet.encrypt(json_data.encode())

    def _decrypt_profile(self, encrypted_data: bytes) -> dict[str, Any]:
        import cryptography.fernet

        key = hashlib.sha256(b"IntellicracKHWIDSpoof").digest()[:32]
        key_b64 = base64.urlsafe_b64encode(key)
        fernet = cryptography.fernet.Fernet(key_b64)

        json_data = fernet.decrypt(encrypted_data).decode()
        return json.loads(json_data)

    def restore_original(self) -> bool:
        """Restore original hardware identifiers from backup."""
        try:
            for key, value in self.original_values.items():
                if key.startswith("mac_"):
                    adapter = key[4:]
                    self._restore_mac_address(adapter, value)
                elif key.startswith("disk_"):
                    drive = key[5:]
                    self._restore_disk_serial(drive, value)

            if hasattr(self, "original_registry_values"):
                for reg_path, values in self.original_registry_values.items():
                    hive, path = reg_path.split("\\", 1)
                    hive_key = getattr(winreg, hive)

                    with winreg.OpenKey(hive_key, path, 0, winreg.KEY_WRITE) as key:
                        for name, (value, reg_type) in values.items():
                            winreg.SetValueEx(key, name, 0, reg_type, value)

            return True

        except Exception as e:
            logger.error(f"Failed to restore original values: {e}")
            return False

    def _restore_mac_address(self, adapter: str, original_mac: str) -> None:
        with contextlib.suppress(AttributeError, TypeError):
            base_key = r"SYSTEM\CurrentControlSet\Control\Class\{4D36E972-E325-11CE-BFC1-08002bE10318}"

            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, base_key) as key:
                i = 0
                while True:
                    try:
                        subkey_name = winreg.EnumKey(key, i)
                        with winreg.OpenKey(key, subkey_name, 0, winreg.KEY_WRITE) as subkey:
                            with contextlib.suppress(OSError):
                                driver_desc = winreg.QueryValueEx(subkey, "DriverDesc")[0]
                                if adapter in driver_desc:
                                    winreg.DeleteValue(subkey, "NetworkAddress")
                                    self._restart_network_adapter(adapter)
                                    return
                        i += 1
                    except OSError:
                        break

    def _restore_disk_serial(self, drive: str, original_serial: str) -> None:
        pass

    def cleanup(self) -> None:
        """Clean up kernel driver and resources."""
        if self.driver_handle:
            self.kernel32.CloseHandle(self.driver_handle)

        with contextlib.suppress(subprocess.CalledProcessError, FileNotFoundError):
            subprocess.run(["sc", "stop", "HWIDSpoof"], capture_output=True)
            subprocess.run(["sc", "delete", "HWIDSpoof"], capture_output=True)

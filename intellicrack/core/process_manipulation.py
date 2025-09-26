"""
Process manipulation module for license protection analysis.
Provides memory reading/writing and process control for identifying
and bypassing licensing mechanisms in software.
"""

import ctypes
import ctypes.wintypes
import logging
import struct
from datetime import datetime
from enum import IntEnum
from typing import Any, Dict, List, Optional

import psutil

logger = logging.getLogger(__name__)

kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
ntdll = ctypes.WinDLL("ntdll", use_last_error=True)
advapi32 = ctypes.WinDLL("advapi32", use_last_error=True)


class ProcessAccess(IntEnum):
    PROCESS_VM_READ = 0x0010
    PROCESS_VM_WRITE = 0x0020
    PROCESS_VM_OPERATION = 0x0008
    PROCESS_CREATE_THREAD = 0x0002
    PROCESS_QUERY_INFORMATION = 0x0400
    PROCESS_ALL_ACCESS = 0x1F0FFF


class LicenseAnalyzer:
    """Analyzes and manipulates processes for license protection research."""

    COMMON_LICENSE_STRINGS = [
        b"license",
        b"LICENSE",
        b"License",
        b"trial",
        b"TRIAL",
        b"Trial",
        b"evaluation",
        b"EVALUATION",
        b"expired",
        b"EXPIRED",
        b"registered",
        b"REGISTERED",
        b"activation",
        b"ACTIVATION",
        b"serial",
        b"SERIAL",
        b"key",
        b"KEY",
        b"valid",
        b"VALID",
        b"invalid",
        b"INVALID",
        b"demo",
        b"DEMO",
        b"full version",
        b"FULL VERSION",
        b"unregistered",
        b"UNREGISTERED",
        b"days remaining",
        b"DAYS REMAINING",
        b"license.dat",
        b"license.key",
        b"license.lic",
    ]

    def __init__(self):
        self.process_handle = None
        self.pid = None
        self.license_check_locations = []
        self.patched_locations = []
        self.protection_signatures = {
            "themida": [b"\x8b\xc0\x60\x0f\x31", b"Themida", b"SecureEngine"],
            "vmprotect": [b"VMProtect", b".vmp", b"VProtect"],
            "enigma": [b"EnigmaProtector", b"ENIGMA", b".enigma"],
            "asprotect": [b"ASProtect", b"ASPack", b".aspr"],
            "armadillo": [b"Armadillo", b"ArmAccess.dll", b"ArmadilloEngine"],
            "safengine": [b"Safengine", b"SELicenseGetStatus", b"SE_ProtectStart"],
            "obsidium": [b"Obsidium", b"obsidium.dll", b"ObsidiumProtected"],
            "winlicense": [b"WinLicense", b"WLRegGetStatus", b"WLHardwareID"],
        }
        self._setup_windows_apis()

    def attach(self, target: str) -> bool:
        """Attach to target process for license analysis."""
        try:
            if target.isdigit():
                self.pid = int(target)
            else:
                for proc in psutil.process_iter(["pid", "name"]):
                    if proc.info["name"].lower() == target.lower():
                        self.pid = proc.info["pid"]
                        break

            if not self.pid:
                logger.error(f"Process '{target}' not found")
                return False

            self.process_handle = kernel32.OpenProcess(ProcessAccess.PROCESS_ALL_ACCESS, False, self.pid)

            if not self.process_handle:
                logger.error(f"Failed to attach to process {self.pid}")
                return False

            logger.info(f"Attached to process {self.pid} for license analysis")
            return True

        except Exception as e:
            logger.error(f"Error attaching to process: {e}")
            return False

    def find_license_checks(self) -> List[Dict[str, Any]]:
        """Scan memory for potential license check locations."""
        if not self.process_handle:
            return []

        license_checks = []

        # Get memory regions
        regions = self._get_memory_regions()

        for region in regions:
            # Only scan executable regions (likely code)
            if region["protection"] & 0x10:  # PAGE_EXECUTE
                memory = self.read_memory(region["base_address"], min(region["size"], 0x10000))
                if memory:
                    # Look for license-related strings
                    for license_string in self.COMMON_LICENSE_STRINGS:
                        offset = 0
                        while True:
                            index = memory.find(license_string, offset)
                            if index == -1:
                                break

                            check_addr = region["base_address"] + index

                            # Analyze surrounding code for conditional jumps
                            context = self._analyze_license_check_context(check_addr)
                            if context:
                                license_checks.append(
                                    {
                                        "address": check_addr,
                                        "string": license_string.decode("utf-8", errors="ignore"),
                                        "type": context["type"],
                                        "jump_addresses": context["jumps"],
                                    }
                                )

                            offset = index + 1

        self.license_check_locations = license_checks
        return license_checks

    def _analyze_license_check_context(self, address: int) -> Optional[Dict[str, Any]]:
        """Analyze code around potential license check."""
        # Read surrounding bytes
        before = self.read_memory(max(address - 100, 0), 100)
        after = self.read_memory(address, 100)

        if not before or not after:
            return None

        context = {"type": "unknown", "jumps": []}

        # Look for conditional jumps (common in license checks)
        jump_opcodes = [
            (b"\x74", "JZ"),  # Jump if zero (equal)
            (b"\x75", "JNZ"),  # Jump if not zero
            (b"\x84", "JE"),  # Jump if equal
            (b"\x85", "JNE"),  # Jump if not equal
            (b"\x0f\x84", "JE (long)"),
            (b"\x0f\x85", "JNE (long)"),
        ]

        for opcode, jump_type in jump_opcodes:
            if opcode in after[:20]:
                index = after.find(opcode)
                jump_addr = address + index
                context["jumps"].append({"address": jump_addr, "type": jump_type, "opcode": opcode.hex()})
                context["type"] = "conditional_check"

        # Look for function calls (license validation functions)
        if b"\xe8" in after[:20]:  # CALL instruction
            context["type"] = "function_call"

        return context if context["jumps"] or context["type"] != "unknown" else None

    def patch_license_check(self, address: int, patch_type: str = "nop") -> bool:
        """Patch a license check at the given address."""
        if not self.process_handle:
            return False

        success = False

        if patch_type == "nop":
            # NOP out the check (0x90)
            success = self.write_memory(address, b"\x90" * 5)

        elif patch_type == "always_true":
            # Change conditional jump to unconditional
            original = self.read_memory(address, 2)
            if original:
                if original[0] == 0x74:  # JZ
                    # Change to JMP
                    success = self.write_memory(address, b"\xeb")
                elif original[0] == 0x75:  # JNZ
                    # NOP it out
                    success = self.write_memory(address, b"\x90\x90")
                elif original[:2] == b"\x0f\x84":  # Long JE
                    # Change to JMP
                    success = self.write_memory(address, b"\xe9")

        elif patch_type == "always_false":
            # Inverse of always_true
            original = self.read_memory(address, 2)
            if original:
                if original[0] == 0x75:  # JNZ
                    success = self.write_memory(address, b"\xeb")
                elif original[0] == 0x74:  # JZ
                    success = self.write_memory(address, b"\x90\x90")

        elif patch_type == "return_true":
            # Make function return 1/true
            success = self.write_memory(address, b"\xb8\x01\x00\x00\x00\xc3")  # MOV EAX, 1; RET

        if success:
            self.patched_locations.append({"address": address, "type": patch_type, "timestamp": str(datetime.now())})
            logger.info(f"Patched license check at 0x{address:X} with {patch_type}")

        return success

    def read_memory(self, address: int, size: int) -> Optional[bytes]:
        """Read memory from attached process."""
        if not self.process_handle:
            return None

        buffer = (ctypes.c_char * size)()
        bytes_read = ctypes.c_size_t()

        success = kernel32.ReadProcessMemory(self.process_handle, ctypes.c_void_p(address), buffer, size, ctypes.byref(bytes_read))

        return bytes(buffer) if success else None

    def write_memory(self, address: int, data: bytes) -> bool:
        """Write memory to attached process."""
        if not self.process_handle:
            return False

        # Change memory protection to writable
        old_protect = ctypes.wintypes.DWORD()
        kernel32.VirtualProtectEx(
            self.process_handle,
            ctypes.c_void_p(address),
            len(data),
            0x40,  # PAGE_EXECUTE_READWRITE
            ctypes.byref(old_protect),
        )

        bytes_written = ctypes.c_size_t()
        success = kernel32.WriteProcessMemory(self.process_handle, ctypes.c_void_p(address), data, len(data), ctypes.byref(bytes_written))

        # Restore original protection
        kernel32.VirtualProtectEx(self.process_handle, ctypes.c_void_p(address), len(data), old_protect, ctypes.byref(old_protect))

        return bool(success)

    def _get_memory_regions(self) -> List[Dict[str, Any]]:
        """Get memory regions of attached process."""
        if not self.process_handle:
            return []

        regions = []
        address = 0

        class MEMORY_BASIC_INFORMATION(ctypes.Structure):
            _fields_ = [
                ("BaseAddress", ctypes.c_void_p),
                ("AllocationBase", ctypes.c_void_p),
                ("AllocationProtect", ctypes.wintypes.DWORD),
                ("RegionSize", ctypes.c_size_t),
                ("State", ctypes.wintypes.DWORD),
                ("Protect", ctypes.wintypes.DWORD),
                ("Type", ctypes.wintypes.DWORD),
            ]

        mbi = MEMORY_BASIC_INFORMATION()

        while address < 0x7FFFFFFFFFFFFFFF:
            result = kernel32.VirtualQueryEx(self.process_handle, ctypes.c_void_p(address), ctypes.byref(mbi), ctypes.sizeof(mbi))

            if not result:
                break

            if mbi.State == 0x1000:  # MEM_COMMIT
                regions.append({"base_address": mbi.BaseAddress, "size": mbi.RegionSize, "protection": mbi.Protect})

            address = mbi.BaseAddress + mbi.RegionSize

        return regions

    def detach(self):
        """Detach from current process."""
        if self.process_handle:
            kernel32.CloseHandle(self.process_handle)
            self.process_handle = None
            self.pid = None
            logger.info("Detached from process")

    def _setup_windows_apis(self):
        """Set up Windows API function signatures."""
        self.kernel32 = kernel32
        self.ntdll = ntdll
        self.advapi32 = advapi32
        self.user32 = ctypes.WinDLL("user32", use_last_error=True)
        self.dbghelp = ctypes.WinDLL("dbghelp", use_last_error=True)

        # Configure API signatures
        self.kernel32.OpenProcess.argtypes = [ctypes.wintypes.DWORD, ctypes.wintypes.BOOL, ctypes.wintypes.DWORD]
        self.kernel32.OpenProcess.restype = ctypes.wintypes.HANDLE

        self.kernel32.ReadProcessMemory.argtypes = [
            ctypes.wintypes.HANDLE,
            ctypes.c_void_p,
            ctypes.c_void_p,
            ctypes.c_size_t,
            ctypes.POINTER(ctypes.c_size_t),
        ]
        self.kernel32.ReadProcessMemory.restype = ctypes.wintypes.BOOL

        self.kernel32.WriteProcessMemory.argtypes = [
            ctypes.wintypes.HANDLE,
            ctypes.c_void_p,
            ctypes.c_void_p,
            ctypes.c_size_t,
            ctypes.POINTER(ctypes.c_size_t),
        ]
        self.kernel32.WriteProcessMemory.restype = ctypes.wintypes.BOOL

        self.kernel32.VirtualAllocEx.argtypes = [
            ctypes.wintypes.HANDLE,
            ctypes.c_void_p,
            ctypes.c_size_t,
            ctypes.wintypes.DWORD,
            ctypes.wintypes.DWORD,
        ]
        self.kernel32.VirtualAllocEx.restype = ctypes.c_void_p

        self.kernel32.CreateRemoteThread.argtypes = [
            ctypes.wintypes.HANDLE,
            ctypes.c_void_p,
            ctypes.c_size_t,
            ctypes.c_void_p,
            ctypes.c_void_p,
            ctypes.wintypes.DWORD,
            ctypes.POINTER(ctypes.wintypes.DWORD),
        ]
        self.kernel32.CreateRemoteThread.restype = ctypes.wintypes.HANDLE

        self.kernel32.GetModuleHandleA.argtypes = [ctypes.c_char_p]
        self.kernel32.GetModuleHandleA.restype = ctypes.wintypes.HMODULE

        self.kernel32.GetProcAddress.argtypes = [ctypes.wintypes.HMODULE, ctypes.c_char_p]
        self.kernel32.GetProcAddress.restype = ctypes.c_void_p

    def scan_pattern(self, pattern: bytes, mask: Optional[bytes] = None) -> List[int]:
        """Scan memory for byte pattern."""
        if not self.process_handle:
            return []

        matches = []
        regions = self._get_memory_regions()

        for region in regions:
            if region["protection"] & 0x10:  # PAGE_EXECUTE
                memory = self.read_memory(region["base_address"], min(region["size"], 0x100000))
                if memory:
                    if mask:
                        matches.extend(self._masked_pattern_scan(memory, pattern, mask, region["base_address"]))
                    else:
                        offset = 0
                        while True:
                            index = memory.find(pattern, offset)
                            if index == -1:
                                break
                            matches.append(region["base_address"] + index)
                            offset = index + 1

        return matches

    def _masked_pattern_scan(self, memory: bytes, pattern: bytes, mask: bytes, base_addr: int) -> List[int]:
        """Scan with wildcard mask support."""
        matches = []
        pattern_len = len(pattern)

        for i in range(len(memory) - pattern_len + 1):
            match = True
            for j in range(pattern_len):
                if mask[j] != ord("?") and memory[i + j] != pattern[j]:
                    match = False
                    break
            if match:
                matches.append(base_addr + i)

        return matches

    def patch_bytes(self, address: int, new_bytes: bytes) -> bool:
        """Patch bytes at specified address."""
        return self.write_memory(address, new_bytes)

    def find_conditional_jumps(self, start_addr: int, size: int = 0x1000) -> List[Dict[str, Any]]:
        """Find all conditional jumps in code region."""
        jumps = []
        memory = self.read_memory(start_addr, size)

        if not memory:
            return jumps

        jump_opcodes = {
            0x70: ("JO", 1),
            0x71: ("JNO", 1),
            0x72: ("JB", 1),
            0x73: ("JAE", 1),
            0x74: ("JE", 1),
            0x75: ("JNE", 1),
            0x76: ("JBE", 1),
            0x77: ("JA", 1),
            0x78: ("JS", 1),
            0x79: ("JNS", 1),
            0x7A: ("JP", 1),
            0x7B: ("JNP", 1),
            0x7C: ("JL", 1),
            0x7D: ("JGE", 1),
            0x7E: ("JLE", 1),
            0x7F: ("JG", 1),
            0xE3: ("JECXZ", 1),
        }

        for i in range(len(memory) - 1):
            if memory[i] in jump_opcodes:
                mnemonic, offset_size = jump_opcodes[memory[i]]
                target_offset = struct.unpack("b", memory[i + 1 : i + 2])[0]
                jump_target = start_addr + i + 2 + target_offset

                jumps.append({"address": start_addr + i, "opcode": memory[i], "mnemonic": mnemonic, "target": jump_target, "size": 2})

            elif i < len(memory) - 6 and memory[i] == 0x0F:
                if 0x80 <= memory[i + 1] <= 0x8F:
                    mnemonic = ["JO", "JNO", "JB", "JAE", "JE", "JNE", "JBE", "JA", "JS", "JNS", "JP", "JNP", "JL", "JGE", "JLE", "JG"][
                        memory[i + 1] - 0x80
                    ]
                    target_offset = struct.unpack("<i", memory[i + 2 : i + 6])[0]
                    jump_target = start_addr + i + 6 + target_offset

                    jumps.append(
                        {
                            "address": start_addr + i,
                            "opcode": (memory[i] << 8) | memory[i + 1],
                            "mnemonic": mnemonic,
                            "target": jump_target,
                            "size": 6,
                        }
                    )

        return jumps

    def bypass_serial_check(self, address: int) -> bool:
        """Bypass serial validation at specified address."""
        jumps = self.find_conditional_jumps(address, 0x100)

        for jump in jumps:
            if jump["mnemonic"] in ["JE", "JNE", "JZ", "JNZ"]:
                nop_bytes = b"\x90" * jump["size"]
                if self.patch_bytes(jump["address"], nop_bytes):
                    logger.info(f"Bypassed serial check at 0x{jump['address']:X}")
                    return True

        return self.patch_bytes(address, b"\xb8\x01\x00\x00\x00\xc3")

    def patch_trial_expiration(self, address: int, days: int = 9999) -> bool:
        """Patch trial expiration to extend trial period."""
        days_bytes = struct.pack("<I", days)
        patch = b"\xb8" + days_bytes + b"\xc3"
        return self.patch_bytes(address, patch)

    def manipulate_registry(self, key_path: str, value_name: str, new_value: Any) -> bool:
        """Manipulate registry entries for license keys."""
        try:
            import winreg

            key_parts = key_path.split("\\")
            hive = getattr(winreg, key_parts[0], winreg.HKEY_CURRENT_USER)
            sub_key = "\\".join(key_parts[1:])

            with winreg.OpenKey(hive, sub_key, 0, winreg.KEY_SET_VALUE) as key:
                if isinstance(new_value, str):
                    winreg.SetValueEx(key, value_name, 0, winreg.REG_SZ, new_value)
                elif isinstance(new_value, int):
                    winreg.SetValueEx(key, value_name, 0, winreg.REG_DWORD, new_value)
                elif isinstance(new_value, bytes):
                    winreg.SetValueEx(key, value_name, 0, winreg.REG_BINARY, new_value)

            logger.info(f"Registry manipulation successful: {key_path}\\{value_name}")
            return True

        except Exception as e:
            logger.error(f"Registry manipulation failed: {e}")
            return False

    def inject_dll(self, dll_path: str) -> bool:
        """Inject DLL into target process."""
        if not self.process_handle:
            return False

        try:
            dll_path_bytes = dll_path.encode("utf-8")
            dll_path_size = len(dll_path_bytes) + 1

            remote_buffer = self.kernel32.VirtualAllocEx(
                self.process_handle,
                None,
                dll_path_size,
                0x3000,  # MEM_COMMIT | MEM_RESERVE
                0x40,  # PAGE_EXECUTE_READWRITE
            )

            if not remote_buffer:
                return False

            bytes_written = ctypes.c_size_t()
            self.kernel32.WriteProcessMemory(self.process_handle, remote_buffer, dll_path_bytes, dll_path_size, ctypes.byref(bytes_written))

            kernel32_handle = self.kernel32.GetModuleHandleA(b"kernel32.dll")
            loadlibrary_addr = self.kernel32.GetProcAddress(kernel32_handle, b"LoadLibraryA")

            thread_handle = self.kernel32.CreateRemoteThread(self.process_handle, None, 0, loadlibrary_addr, remote_buffer, 0, None)

            if thread_handle:
                self.kernel32.WaitForSingleObject(thread_handle, 0xFFFFFFFF)
                self.kernel32.CloseHandle(thread_handle)
                logger.info(f"Successfully injected DLL: {dll_path}")
                return True

        except Exception as e:
            logger.error(f"DLL injection failed: {e}")

        return False

    def hook_api(self, module_name: str, function_name: str, hook_address: int) -> bool:
        """Hook Windows API function."""
        if not self.process_handle:
            return False

        try:
            module_handle = self.kernel32.GetModuleHandleA(module_name.encode("utf-8"))
            if not module_handle:
                return False

            func_addr = self.kernel32.GetProcAddress(module_handle, function_name.encode("utf-8"))
            if not func_addr:
                return False

            jump_bytes = b"\xe9" + struct.pack("<I", hook_address - func_addr - 5)

            old_protect = ctypes.wintypes.DWORD()
            self.kernel32.VirtualProtectEx(
                self.process_handle,
                ctypes.c_void_p(func_addr),
                5,
                0x40,  # PAGE_EXECUTE_READWRITE
                ctypes.byref(old_protect),
            )

            if self.patch_bytes(func_addr, jump_bytes):
                logger.info(f"Hooked {module_name}!{function_name} at 0x{func_addr:X}")
                return True

        except Exception as e:
            logger.error(f"API hooking failed: {e}")

        return False

    def detect_protection(self) -> Optional[str]:
        """Detect protection scheme used by target."""
        if not self.process_handle:
            return None

        for protection_name, signatures in self.protection_signatures.items():
            for signature in signatures:
                if self.scan_pattern(signature):
                    logger.info(f"Detected protection: {protection_name}")
                    return protection_name

        return None

    def read_process_memory(self, address: int, size: int) -> Optional[bytes]:
        """Alias for read_memory for compatibility."""
        return self.read_memory(address, size)

    def write_process_memory(self, address: int, data: bytes) -> bool:
        """Alias for write_memory for compatibility."""
        return self.write_memory(address, data)

    def get_module_base(self, module_name: str) -> Optional[int]:
        """Get base address of loaded module."""
        if not self.pid:
            return None

        try:
            process = psutil.Process(self.pid)
            for dll in process.memory_maps():
                if module_name.lower() in dll.path.lower():
                    return dll.addr
        except Exception:
            pass

        return None

    def enumerate_processes(self) -> List[Dict[str, Any]]:
        """Enumerate all running processes."""
        processes = []

        for proc in psutil.process_iter(["pid", "name", "exe", "memory_info"]):
            try:
                processes.append(
                    {
                        "pid": proc.info["pid"],
                        "name": proc.info["name"],
                        "exe": proc.info.get("exe", ""),
                        "memory": proc.info.get("memory_info", {}),
                    }
                )
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue

        return processes

    def enumerate_modules(self, pid: Optional[int] = None) -> List[Dict[str, Any]]:
        """Enumerate loaded modules in process."""
        target_pid = pid or self.pid
        if not target_pid:
            return []

        modules = []

        try:
            process = psutil.Process(target_pid)
            for dll in process.memory_maps():
                modules.append({"base": dll.addr, "size": dll.size, "path": dll.path})
        except Exception as e:
            logger.error(f"Module enumeration failed: {e}")

        return modules

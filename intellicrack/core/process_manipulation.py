"""Process manipulation module for license protection analysis.

Provides memory reading/writing and process control for identifying
and bypassing licensing mechanisms in software.
"""

import ctypes
import ctypes.wintypes
import logging
import random
import struct
import time
from datetime import datetime
from enum import IntEnum
from typing import Any

import psutil

from intellicrack.utils.logger import log_all_methods


logger = logging.getLogger(__name__)

kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
ntdll = ctypes.WinDLL("ntdll", use_last_error=True)
advapi32 = ctypes.WinDLL("advapi32", use_last_error=True)


class ProcessAccess(IntEnum):
    """Process access rights for Windows API."""

    PROCESS_VM_READ = 0x0010
    PROCESS_VM_WRITE = 0x0020
    PROCESS_VM_OPERATION = 0x0008
    PROCESS_CREATE_THREAD = 0x0002
    PROCESS_QUERY_INFORMATION = 0x0400
    PROCESS_ALL_ACCESS = 0x1F0FFF


class ProcessInformationClass(IntEnum):
    """Process information classes for NtQueryInformationProcess."""

    ProcessBasicInformation = 0
    ProcessDebugPort = 7
    ProcessWow64Information = 26
    ProcessImageFileName = 27
    ProcessDebugObjectHandle = 30
    ProcessDebugFlags = 31


class ListEntry(ctypes.Structure):
    """Windows LIST_ENTRY structure for doubly-linked lists."""

    _fields_ = [
        ("Flink", ctypes.c_void_p),
        ("Blink", ctypes.c_void_p),
    ]


class UnicodeString(ctypes.Structure):
    """Windows UNICODE_STRING structure for string handling."""

    _fields_ = [
        ("Length", ctypes.c_ushort),
        ("MaximumLength", ctypes.c_ushort),
        ("Buffer", ctypes.c_wchar_p),
    ]


class RtlUserProcessParameters(ctypes.Structure):
    """Windows RTL_USER_PROCESS_PARAMETERS structure from PEB."""

    _fields_ = [
        ("MaximumLength", ctypes.c_ulong),
        ("Length", ctypes.c_ulong),
        ("Flags", ctypes.c_ulong),
        ("DebugFlags", ctypes.c_ulong),
        ("ConsoleHandle", ctypes.c_void_p),
        ("ConsoleFlags", ctypes.c_ulong),
        ("StandardInput", ctypes.c_void_p),
        ("StandardOutput", ctypes.c_void_p),
        ("StandardError", ctypes.c_void_p),
        ("CurrentDirectory", UnicodeString),
        ("DllPath", UnicodeString),
        ("ImagePathName", UnicodeString),
        ("CommandLine", UnicodeString),
        ("Environment", ctypes.c_void_p),
    ]


class PebLdrData(ctypes.Structure):
    """Windows PEB_LDR_DATA structure containing loader information."""

    _fields_ = [
        ("Length", ctypes.c_ulong),
        ("Initialized", ctypes.c_ubyte),
        ("SsHandle", ctypes.c_void_p),
        ("InLoadOrderModuleList", ListEntry),
        ("InMemoryOrderModuleList", ListEntry),
        ("InInitializationOrderModuleList", ListEntry),
    ]


class Peb(ctypes.Structure):
    """Windows Process Environment Block structure for process information."""

    _fields_ = [
        ("InheritedAddressSpace", ctypes.c_ubyte),
        ("ReadImageFileExecOptions", ctypes.c_ubyte),
        ("BeingDebugged", ctypes.c_ubyte),
        ("BitField", ctypes.c_ubyte),
        ("Mutant", ctypes.c_void_p),
        ("ImageBaseAddress", ctypes.c_void_p),
        ("Ldr", ctypes.POINTER(PebLdrData)),
        ("ProcessParameters", ctypes.POINTER(RtlUserProcessParameters)),
        ("SubSystemData", ctypes.c_void_p),
        ("ProcessHeap", ctypes.c_void_p),
        ("FastPebLock", ctypes.c_void_p),
        ("AtlThunkSListPtr", ctypes.c_void_p),
        ("IFEOKey", ctypes.c_void_p),
        ("CrossProcessFlags", ctypes.c_ulong),
        ("UserSharedInfoPtr", ctypes.c_void_p),
        ("SystemReserved", ctypes.c_ulong),
        ("AtlThunkSListPtr32", ctypes.c_ulong),
        ("ApiSetMap", ctypes.c_void_p),
        ("TlsExpansionCounter", ctypes.c_ulong),
        ("TlsBitmap", ctypes.c_void_p),
        ("TlsBitmapBits", ctypes.c_ulong * 2),
        ("ReadOnlySharedMemoryBase", ctypes.c_void_p),
        ("SharedData", ctypes.c_void_p),
        ("ReadOnlyStaticServerData", ctypes.c_void_p),
        ("AnsiCodePageData", ctypes.c_void_p),
        ("OemCodePageData", ctypes.c_void_p),
        ("UnicodeCaseTableData", ctypes.c_void_p),
        ("NumberOfProcessors", ctypes.c_ulong),
        ("NtGlobalFlag", ctypes.c_ulong),
    ]


class ProcessBasicInformation(ctypes.Structure):
    """Windows PROCESS_BASIC_INFORMATION structure from NtQueryInformationProcess."""

    _fields_ = [
        ("ExitStatus", ctypes.c_void_p),
        ("PebBaseAddress", ctypes.POINTER(Peb)),
        ("AffinityMask", ctypes.c_void_p),
        ("BasePriority", ctypes.c_void_p),
        ("UniqueProcessId", ctypes.c_void_p),
        ("InheritedFromUniqueProcessId", ctypes.c_void_p),
    ]


class MemoryBasicInformation(ctypes.Structure):
    """Windows MEMORY_BASIC_INFORMATION structure for memory region information."""

    _fields_ = [
        ("BaseAddress", ctypes.c_void_p),
        ("AllocationBase", ctypes.c_void_p),
        ("AllocationProtect", ctypes.c_ulong),
        ("PartitionId", ctypes.c_ushort),
        ("RegionSize", ctypes.c_size_t),
        ("State", ctypes.c_ulong),
        ("Protect", ctypes.c_ulong),
        ("Type", ctypes.c_ulong),
    ]


class MemoryInformationClass(IntEnum):
    """Memory information classes for NtQueryVirtualMemory."""

    MemoryBasicInformation = 0
    MemoryWorkingSetList = 1
    MemorySectionName = 2
    MemoryBasicVlmInformation = 3
    MemoryWorkingSetExList = 4


@log_all_methods
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

    def __init__(self) -> None:
        """Initialize the ProcessManipulator with empty handles and protection signatures."""
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

        # Initialize pattern cache for performance
        self._pattern_cache = {}
        self._cache_max_size = 100
        self._cache_ttl = 300  # 5 minutes
        self._cache_timestamps = {}
        self._cache_stats = {"hits": 0, "misses": 0, "evictions": 0}
        self._memory_snapshot_cache = {}
        self._cache_lock = None

        import threading

        self._cache_lock = threading.RLock()

        self._setup_windows_apis()

    def attach(self, target: str) -> bool:
        """Attach to target process for license analysis."""
        logger.debug(f"Attempting to attach to target: '{target}'")
        try:
            if target.isdigit():
                self.pid = int(target)
                logger.debug(f"Target is PID: {self.pid}")
            else:
                for proc in psutil.process_iter(["pid", "name"]):
                    if proc.info["name"].lower() == target.lower():
                        self.pid = proc.info["pid"]
                        logger.debug(f"Found process '{target}' with PID: {self.pid}")
                        break

            if not self.pid:
                logger.error(f"Process '{target}' not found")
                logger.debug(f"Failed to find PID for target: '{target}'")
                return False

            self.process_handle = kernel32.OpenProcess(
                ProcessAccess.PROCESS_ALL_ACCESS, False, self.pid
            )

            if not self.process_handle:
                logger.error(f"Failed to attach to process {self.pid}")
                logger.debug(
                    f"OpenProcess failed for PID {self.pid}. Error: {ctypes.get_last_error()}"
                )
                return False

            logger.info(f"Attached to process {self.pid} for license analysis")
            logger.debug(
                f"Successfully attached to PID {self.pid}. Process handle: {self.process_handle}"
            )
            return True

        except Exception as e:
            logger.error(f"Error attaching to process: {e}")
            logger.debug(f"Exception during attach to process: {e}", exc_info=True)
            return False

    def find_license_checks(self) -> list[dict[str, Any]]:
        """Scan memory for potential license check locations."""
        if not self.process_handle:
            logger.debug("No process attached. Cannot find license checks.")
            return []

        license_checks = []
        logger.debug("Starting memory scan for potential license check locations.")

        # Get memory regions
        regions = self._get_memory_regions()
        logger.debug(f"Found {len(regions)} memory regions to scan.")

        for region in regions:
            # Only scan executable regions (likely code)
            if region["protection"] & 0x10:  # PAGE_EXECUTE
                logger.debug(
                    f"Scanning executable region at 0x{region['base_address']:X} (size: 0x{region['size']:X})"
                )
                if memory := self.read_memory(
                    region["base_address"], min(region["size"], 0x10000)
                ):
                    # Look for license-related strings
                    for license_string in self.COMMON_LICENSE_STRINGS:
                        offset = 0
                        while True:
                            index = memory.find(license_string, offset)
                            if index == -1:
                                break

                            check_addr = region["base_address"] + index
                            logger.debug(
                                f"Found license string '{license_string.decode(errors='ignore')}' at 0x{check_addr:X}. Analyzing context."
                            )

                            if context := self._analyze_license_check_context(
                                check_addr
                            ):
                                license_checks.append(
                                    {
                                        "address": check_addr,
                                        "string": license_string.decode("utf-8", errors="ignore"),
                                        "type": context["type"],
                                        "jump_addresses": context["jumps"],
                                    },
                                )
                                logger.debug(
                                    f"Context analysis for 0x{check_addr:X} successful. Type: {context['type']}"
                                )

                            offset = index + 1
                else:
                    logger.debug(f"Failed to read memory from region 0x{region['base_address']:X}.")

        self.license_check_locations = license_checks
        logger.debug(f"Finished finding license checks. Total found: {len(license_checks)}")
        return license_checks

    def _analyze_license_check_context(self, address: int) -> dict[str, Any] | None:
        """Analyze code around potential license check."""
        logger.debug(f"Analyzing license check context around address 0x{address:X}.")
        # Read surrounding bytes
        before = self.read_memory(max(address - 100, 0), 100)
        after = self.read_memory(address, 100)
        logger.debug(
            f"Read {len(before) if before else 0} bytes before and {len(after) if after else 0} bytes after 0x{address:X}."
        )

        if not before or not after:
            logger.debug("Insufficient memory read for context analysis.")
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
                context["jumps"].append(
                    {"address": jump_addr, "type": jump_type, "opcode": opcode.hex()}
                )
                context["type"] = "conditional_check"
                logger.debug(f"Detected conditional jump '{jump_type}' at 0x{jump_addr:X}.")

        # Look for function calls (license validation functions)
        if b"\xe8" in after[:20]:  # CALL instruction
            context["type"] = "function_call"
            logger.debug("Detected function call instruction.")

        if context["jumps"] or context["type"] != "unknown":
            logger.debug(
                f"Context analysis for 0x{address:X} complete. Type: {context['type']}, Jumps: {len(context['jumps'])}"
            )
            return context
        logger.debug(f"No significant context found around 0x{address:X}.")
        return None

    def patch_license_check(self, address: int, patch_type: str = "nop") -> bool:
        """Patch a license check at the given address."""
        if not self.process_handle:
            logger.debug("No process attached. Cannot patch license check.")
            return False

        success = False
        logger.debug(
            f"Attempting to patch license check at 0x{address:X} with patch type: '{patch_type}'"
        )

        if patch_type == "nop":
            # NOP out the check (0x90)
            logger.debug(f"Applying NOP patch at 0x{address:X}.")
            success = self.write_memory(address, b"\x90" * 5)

        elif patch_type == "always_true":
            # Change conditional jump to unconditional
            logger.debug(f"Applying 'always_true' patch at 0x{address:X}.")
            if original := self.read_memory(address, 2):
                if original[0] == 0x74:  # JZ
                    # Change to JMP
                    success = self.write_memory(address, b"\xeb")
                    logger.debug(f"Changed JZ to JMP at 0x{address:X}.")
                elif original[0] == 0x75:  # JNZ
                    # NOP it out
                    success = self.write_memory(address, b"\x90\x90")
                    logger.debug(f"NOP'd out JNZ at 0x{address:X}.")
                elif original[:2] == b"\x0f\x84":  # Long JE
                    # Change to JMP
                    success = self.write_memory(address, b"\xe9")
                    logger.debug(f"Changed long JE to JMP at 0x{address:X}.")

        elif patch_type == "always_false":
            # Inverse of always_true
            logger.debug(f"Applying 'always_false' patch at 0x{address:X}.")
            if original := self.read_memory(address, 2):
                if original[0] == 0x75:  # JNZ
                    success = self.write_memory(address, b"\xeb")
                    logger.debug(f"Changed JNZ to JMP at 0x{address:X}.")
                elif original[0] == 0x74:  # JZ
                    success = self.write_memory(address, b"\x90\x90")
                    logger.debug(f"NOP'd out JZ at 0x{address:X}.")

        elif patch_type == "return_true":
            # Make function return 1/true
            logger.debug(f"Applying 'return_true' patch at 0x{address:X}.")
            success = self.write_memory(address, b"\xb8\x01\x00\x00\x00\xc3")  # MOV EAX, 1; RET

        if success:
            self.patched_locations.append(
                {"address": address, "type": patch_type, "timestamp": str(datetime.now())}
            )
            logger.info(f"Patched license check at 0x{address:X} with {patch_type}")
            logger.debug(f"Patch operation successful at 0x{address:X}.")
        else:
            logger.warning(
                f"Patch operation failed at 0x{address:X} with patch type: '{patch_type}'."
            )

        return success

    def read_memory(self, address: int, size: int) -> bytes | None:
        """Read memory from attached process."""
        logger.debug(f"Attempting to read {size} bytes from address 0x{address:X}.")
        if not self.process_handle:
            logger.debug("No process attached. Cannot read memory.")
            return None

        buffer = (ctypes.c_char * size)()
        bytes_read = ctypes.c_size_t()

        if success := kernel32.ReadProcessMemory(
            self.process_handle,
            ctypes.c_void_p(address),
            buffer,
            size,
            ctypes.byref(bytes_read),
        ):
            logger.debug(f"Successfully read {bytes_read.value} bytes from 0x{address:X}.")
            return bytes(buffer)
        logger.debug(f"Failed to read memory from 0x{address:X}. Error: {ctypes.get_last_error()}")
        return None

    def write_memory(self, address: int, data: bytes) -> bool:
        """Write memory to attached process."""
        logger.debug(f"Attempting to write {len(data)} bytes to address 0x{address:X}.")
        if not self.process_handle:
            logger.debug("No process attached. Cannot write memory.")
            return False

        # Change memory protection to writable
        old_protect = ctypes.wintypes.DWORD()
        logger.debug(
            f"Changing memory protection at 0x{address:X} to PAGE_EXECUTE_READWRITE (0x40)."
        )
        kernel32.VirtualProtectEx(
            self.process_handle,
            ctypes.c_void_p(address),
            len(data),
            0x40,  # PAGE_EXECUTE_READWRITE
            ctypes.byref(old_protect),
        )
        logger.debug(f"Original protection was 0x{old_protect.value:X}.")

        bytes_written = ctypes.c_size_t()
        success = kernel32.WriteProcessMemory(
            self.process_handle,
            ctypes.c_void_p(address),
            data,
            len(data),
            ctypes.byref(bytes_written),
        )

        # Restore original protection
        kernel32.VirtualProtectEx(
            self.process_handle,
            ctypes.c_void_p(address),
            len(data),
            old_protect,
            ctypes.byref(old_protect),
        )
        logger.debug(f"Restored original protection 0x{old_protect.value:X} at 0x{address:X}.")

        if success:
            logger.debug(f"Successfully wrote {bytes_written.value} bytes to 0x{address:X}.")
        else:
            logger.debug(
                f"Failed to write memory to 0x{address:X}. Error: {ctypes.get_last_error()}"
            )
        return bool(success)

    def _get_memory_regions(self) -> list[dict[str, Any]]:
        """Get memory regions of attached process."""
        if not self.process_handle:
            logger.debug("No process attached. Cannot get memory regions.")
            return []

        regions = []
        address = 0
        logger.debug("Starting enumeration of memory regions.")

        class MEMORY_BASIC_INFORMATION(ctypes.Structure):  # noqa: N801
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
            result = kernel32.VirtualQueryEx(
                self.process_handle, ctypes.c_void_p(address), ctypes.byref(mbi), ctypes.sizeof(mbi)
            )

            if not result:
                logger.debug(
                    f"VirtualQueryEx failed at address 0x{address:X}. Error: {ctypes.get_last_error()}"
                )
                break

            if mbi.State == 0x1000:  # MEM_COMMIT
                regions.append(
                    {
                        "base_address": mbi.BaseAddress,
                        "size": mbi.RegionSize,
                        "protection": mbi.Protect,
                    }
                )
                logger.debug(
                    f"Found committed region: Base=0x{mbi.BaseAddress:X}, Size=0x{mbi.RegionSize:X}, Protect=0x{mbi.Protect:X}"
                )

            address = mbi.BaseAddress + mbi.RegionSize
            if address == mbi.BaseAddress:  # Prevent infinite loop if RegionSize is 0
                address += 0x1000  # Move to next page

        logger.debug(f"Finished enumerating memory regions. Total found: {len(regions)}")
        return regions

    def detach(self) -> None:
        """Detach from current process."""
        if self.process_handle:
            kernel32.CloseHandle(self.process_handle)
            self.process_handle = None
            self.pid = None
            logger.info("Detached from process")
            logger.debug("Process handle closed and PID cleared.")
        else:
            logger.debug("No process attached to detach from.")

    def _setup_windows_apis(self) -> None:
        """Set up Windows API function signatures."""
        self.kernel32 = kernel32
        self.ntdll = ntdll
        self.advapi32 = advapi32
        self.user32 = ctypes.WinDLL("user32", use_last_error=True)
        self.dbghelp = ctypes.WinDLL("dbghelp", use_last_error=True)

        # Configure API signatures
        self.kernel32.OpenProcess.argtypes = [
            ctypes.wintypes.DWORD,
            ctypes.wintypes.BOOL,
            ctypes.wintypes.DWORD,
        ]
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

    def scan_pattern(self, pattern: bytes, mask: bytes | None = None) -> list[int]:
        """Scan memory for byte pattern."""
        if not self.process_handle:
            logger.debug("No process attached. Cannot scan pattern.")
            return []

        matches = []
        regions = self._get_memory_regions()
        logger.debug(
            f"Scanning for pattern '{pattern.hex()}' (mask: {mask.hex() if mask else 'None'}) in {len(regions)} memory regions."
        )

        for region in regions:
            if region["protection"] & 0x10:  # PAGE_EXECUTE
                logger.debug(
                    f"Scanning executable region 0x{region['base_address']:X} for pattern."
                )
                if memory := self.read_memory(
                    region["base_address"], min(region["size"], 0x100000)
                ):
                    if mask:
                        region_matches = self._masked_pattern_scan(
                            memory, pattern, mask, region["base_address"]
                        )
                        matches.extend(region_matches)
                        logger.debug(
                            f"Found {len(region_matches)} masked matches in region 0x{region['base_address']:X}."
                        )
                    else:
                        offset = 0
                        while True:
                            index = memory.find(pattern, offset)
                            if index == -1:
                                break
                            matches.append(region["base_address"] + index)
                            offset = index + 1
                        logger.debug(f"Found 0 direct matches in region 0x{region['base_address']:X}.")
                else:
                    logger.debug(f"Failed to read memory from region 0x{region['base_address']:X}.")
        logger.debug(f"Finished pattern scan. Total matches found: {len(matches)}")
        return matches

    def _masked_pattern_scan(
        self, memory: bytes, pattern: bytes, mask: bytes, base_addr: int
    ) -> list[int]:
        """Scan with wildcard mask support."""
        matches = []
        pattern_len = len(pattern)
        logger.debug(
            f"Performing masked pattern scan for pattern '{pattern.hex()}' with mask '{mask.hex()}' in memory region at 0x{base_addr:X}."
        )

        for i in range(len(memory) - pattern_len + 1):
            match = not any(
                mask[j] != ord("?") and memory[i + j] != pattern[j]
                for j in range(pattern_len)
            )
            if match:
                matches.append(base_addr + i)
                logger.debug(f"Masked pattern match found at 0x{base_addr + i:X}.")
        logger.debug(f"Masked pattern scan completed. Found {len(matches)} matches.")
        return matches

    def scan_patterns_concurrent(
        self, patterns: list[dict[str, Any]], max_workers: int = 4
    ) -> dict[str, list[int]]:
        """Scan for multiple patterns concurrently using thread pool.

        Args:
            patterns: List of pattern dictionaries with 'name', 'bytes', and optional 'mask' keys
            max_workers: Maximum number of concurrent worker threads

        Returns:
            Dictionary mapping pattern names to lists of match addresses

        """
        import concurrent.futures
        import threading

        if not self.process_handle:
            logger.debug("No process attached. Cannot scan patterns concurrently.")
            return {}

        results = {pattern["name"]: [] for pattern in patterns}
        regions = self._get_memory_regions()

        # Filter for executable regions
        exec_regions = [r for r in regions if r["protection"] & 0x10]  # PAGE_EXECUTE
        logger.debug(
            f"Starting concurrent scan for {len(patterns)} patterns across {len(exec_regions)} executable regions."
        )

        if not exec_regions:
            logger.debug("No executable regions found for concurrent scan.")
            return results

        # Thread-safe result collection
        results_lock = threading.Lock()

        def scan_region_for_patterns(region: dict[str, Any]) -> dict[str, list[int]]:
            """Worker function to scan a single region for all patterns."""
            local_results = {pattern["name"]: [] for pattern in patterns}
            logger.debug(
                f"Worker scanning region 0x{region['base_address']:X} (size: 0x{region['size']:X})."
            )
            try:
                # Read memory region once
                memory = self.read_memory(region["base_address"], min(region["size"], 0x100000))
                if not memory:
                    logger.debug(f"Failed to read memory from region 0x{region['base_address']:X}.")
                    return local_results

                # Scan for each pattern in this region
                for pattern in patterns:
                    pattern_bytes = pattern["bytes"]
                    pattern_mask = pattern.get("mask")
                    pattern_name = pattern["name"]

                    if pattern_mask:
                        matches = self._masked_pattern_scan(
                            memory, pattern_bytes, pattern_mask, region["base_address"]
                        )
                    else:
                        # Direct pattern search
                        offset = 0
                        matches = []
                        while True:
                            index = memory.find(pattern_bytes, offset)
                            if index == -1:
                                break
                            matches.append(region["base_address"] + index)
                            offset = index + 1

                    local_results[pattern_name].extend(matches)
                    logger.debug(
                        f"Pattern '{pattern_name}' found {len(matches)} matches in region 0x{region['base_address']:X}."
                    )

            except Exception as e:
                logger.error(f"Error scanning region 0x{region['base_address']:X}: {e}")
                logger.debug(f"Exception during region scan: {e}", exc_info=True)

            return local_results

        # Use ThreadPoolExecutor for concurrent scanning
        with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
            # Submit all region scan tasks
            future_to_region = {
                executor.submit(scan_region_for_patterns, region): region for region in exec_regions
            }

            # Collect results as they complete
            for future in concurrent.futures.as_completed(future_to_region):
                region = future_to_region[future]
                try:
                    region_results = future.result(timeout=10)  # 10 second timeout per region

                    # Merge results thread-safely
                    with results_lock:
                        for pattern_name, matches in region_results.items():
                            results[pattern_name].extend(matches)

                    logger.debug(f"Completed scanning region 0x{region['base_address']:X}")

                except concurrent.futures.TimeoutError:
                    logger.warning(f"Timeout scanning region 0x{region['base_address']:X}")
                    logger.debug(f"Timeout scanning region 0x{region['base_address']:X}.")
                except Exception as e:
                    logger.error(f"Error processing region 0x{region['base_address']:X}: {e}")
                    logger.debug(
                        f"Exception processing region 0x{region['base_address']:X}: {e}",
                        exc_info=True,
                    )

        # Sort results for each pattern
        for _pattern_name, pattern_results in results.items():
            pattern_results.sort()

        logger.info(
            f"Concurrent scan complete: {sum(len(v) for v in results.values())} total matches"
        )
        logger.debug(f"Final concurrent scan results: {results}")
        return results

    def _initialize_disassembler(self) -> Any:
        """Initialize Capstone disassembler based on architecture."""
        import capstone

        is_64bit = ctypes.sizeof(ctypes.c_voidp) == 8
        md = capstone.Cs(
            capstone.CS_ARCH_X86,
            capstone.CS_MODE_64 if is_64bit else capstone.CS_MODE_32
        )
        md.detail = True
        logger.debug(f"Capstone initialized for {'x64' if is_64bit else 'x86'} architecture.")
        return md

    def _scan_references_to(
        self, address: int, start_addr: int, end_addr: int, md: Any
    ) -> list[dict[str, Any]]:
        """Scan memory regions for references TO target address."""
        import struct

        import capstone

        references = []
        regions = self._get_memory_regions()
        regions_in_range = [
            r for r in regions
            if r["base_address"] <= end_addr and r["base_address"] + r["size"] >= start_addr
        ]
        is_64bit = ctypes.sizeof(ctypes.c_voidp) == 8

        for region in regions_in_range:
            if not (region["protection"] & 0x10):
                continue

            try:
                region_start = max(region["base_address"], start_addr)
                region_end = min(region["base_address"] + region["size"], end_addr)
                size = min(region_end - region_start, 0x100000)
                memory = self.read_memory(region_start, size)
                if not memory:
                    continue

                references.extend(self._disassemble_for_references(
                    memory, region_start, address, md
                ))
                references.extend(self._scan_data_pointers(
                    memory, region_start, address, is_64bit
                ))
            except Exception as e:
                logger.error(f"Error analyzing region 0x{region['base_address']:X}: {e}")

        return references

    def _disassemble_for_references(
        self, memory: bytes, region_start: int, target_address: int, md: Any
    ) -> list[dict[str, Any]]:
        """Disassemble memory and find instruction references to target address."""
        import capstone

        references = []
        for insn in md.disasm(memory, region_start):
            if ref := self._check_direct_branch(insn, target_address):
                references.append(ref)
            elif refs := self._check_memory_references(insn, target_address):
                references.extend(refs)
        return references

    def _check_direct_branch(self, insn: Any, target_address: int) -> dict[str, Any] | None:
        """Check if instruction is a direct branch to target address."""
        import capstone

        branch_mnemonics = ["call", "jmp", "je", "jne", "jz", "jnz", "ja", "jb", "jg", "jl"]
        if insn.mnemonic in branch_mnemonics and len(insn.operands) > 0:
            op = insn.operands[0]
            if op.type == capstone.x86.X86_OP_IMM and op.value.imm == target_address:
                return {
                    "from_address": insn.address,
                    "instruction": insn.mnemonic,
                    "bytes": insn.bytes.hex(),
                    "type": "direct_branch",
                }
        return None

    def _check_memory_references(self, insn: Any, target_address: int) -> list[dict[str, Any]]:
        """Check instruction operands for memory references to target address."""
        import capstone

        references = []
        if insn.mnemonic not in ["mov", "lea", "push", "cmp", "test"]:
            return references

        for op in insn.operands:
            if op.type == capstone.x86.X86_OP_MEM and op.mem.disp == target_address:
                references.append({
                    "from_address": insn.address,
                    "instruction": insn.mnemonic,
                    "bytes": insn.bytes.hex(),
                    "type": "memory_reference",
                })
            elif op.type == capstone.x86.X86_OP_IMM and op.value.imm == target_address:
                references.append({
                    "from_address": insn.address,
                    "instruction": insn.mnemonic,
                    "bytes": insn.bytes.hex(),
                    "type": "immediate_reference",
                })
        return references

    def _scan_data_pointers(
        self, memory: bytes, region_start: int, target_address: int, is_64bit: bool
    ) -> list[dict[str, Any]]:
        """Scan memory for raw pointer references to target address."""
        import struct

        references = []
        ptr_size = 8 if is_64bit else 4
        ptr_format = "<Q" if is_64bit else "<I"

        for offset in range(0, len(memory) - ptr_size + 1, ptr_size):
            ptr_value = struct.unpack(ptr_format, memory[offset:offset + ptr_size])[0]
            if ptr_value == target_address:
                references.append({
                    "from_address": region_start + offset,
                    "instruction": "DATA_PTR",
                    "bytes": memory[offset:offset + ptr_size].hex(),
                    "type": "data_pointer",
                })
        return references

    def _scan_references_from(
        self, address: int, scan_range: int, md: Any
    ) -> list[dict[str, Any]]:
        """Scan for references FROM the target address."""
        import capstone

        references = []
        try:
            if code_memory := self.read_memory(address, min(scan_range, 0x1000)):
                for insn in md.disasm(code_memory, address):
                    if insn.address > address + 0x100:
                        break

                    if ref := self._check_branch_from(insn, address):
                        references.append(ref)
                    references.extend(self._check_operand_references(insn, address))
        except Exception as e:
            logger.error(f"Error analyzing references from 0x{address:X}: {e}")
        return references

    def _check_branch_from(self, insn: Any, base_address: int) -> dict[str, Any] | None:
        """Check if instruction branches to another address."""
        import capstone

        branch_mnemonics = ["call", "jmp", "je", "jne", "jz", "jnz", "ja", "jb", "jg", "jl"]
        if insn.mnemonic in branch_mnemonics and len(insn.operands) > 0:
            op = insn.operands[0]
            if op.type == capstone.x86.X86_OP_IMM:
                return {
                    "to_address": op.value.imm,
                    "instruction": insn.mnemonic,
                    "offset": insn.address - base_address,
                    "type": "branch",
                }
        return None

    def _check_operand_references(self, insn: Any, base_address: int) -> list[dict[str, Any]]:
        """Check instruction operands for address references."""
        import capstone

        references = []
        for op in insn.operands:
            if op.type == capstone.x86.X86_OP_MEM and op.mem.disp != 0:
                references.append({
                    "to_address": op.mem.disp,
                    "instruction": insn.mnemonic,
                    "offset": insn.address - base_address,
                    "type": "memory_access",
                })
            elif op.type == capstone.x86.X86_OP_IMM:
                imm_val = op.value.imm
                if (0x400000 <= imm_val <= 0x7FFFFFFF) or (0x10000000000 <= imm_val <= 0x7FFFFFFFFFFF):
                    references.append({
                        "to_address": imm_val,
                        "instruction": insn.mnemonic,
                        "offset": insn.address - base_address,
                        "type": "immediate",
                    })
        return references

    def analyze_cross_references(
        self, address: int, scan_range: int = 0x10000
    ) -> dict[str, list[dict[str, Any]]]:
        """Analyze cross-references to/from a given address.

        Args:
            address: Target address to analyze references for
            scan_range: Range to scan around the address

        Returns:
            Dictionary with 'references_to' and 'references_from' lists

        """
        logger.debug(
            f"Analyzing cross-references for address 0x{address:X} with scan range 0x{scan_range:X}."
        )
        if not self.process_handle:
            logger.debug("No process attached. Cannot analyze cross-references.")
            return {"references_to": [], "references_from": []}

        try:
            md = self._initialize_disassembler()
        except Exception as e:
            logger.error(f"Failed to initialize Capstone: {e}")
            return {"references_to": [], "references_from": []}

        start_addr = max(0, address - scan_range)
        end_addr = address + scan_range

        references_to = self._scan_references_to(address, start_addr, end_addr, md)
        references_from = self._scan_references_from(address, scan_range, md)

        logger.info(
            f"Cross-reference analysis: {len(references_to)} refs to, "
            f"{len(references_from)} refs from 0x{address:X}",
        )
        return {"references_to": references_to, "references_from": references_from}

    def generate_signature_from_sample(
        self, sample_addresses: list[int], context_size: int = 32
    ) -> dict[str, Any]:
        """Generate signature pattern from sample addresses.

        Args:
            sample_addresses: List of addresses containing similar code patterns
            context_size: Bytes to capture around each address

        Returns:
            Dictionary containing generated signature with pattern, mask, and confidence

        """
        import collections

        logger.debug(
            f"Generating signature from {len(sample_addresses)} sample addresses with context size {context_size}."
        )
        if not self.process_handle or not sample_addresses:
            logger.debug("Insufficient data for signature generation.")
            return {"pattern": b"", "mask": b"", "confidence": 0.0, "common_bytes": []}

        # Collect byte sequences from all samples
        samples = []
        for addr in sample_addresses:
            memory = self.read_memory(addr, context_size)
            if memory and len(memory) == context_size:
                samples.append(memory)
            else:
                logger.debug(f"Failed to read memory for sample at 0x{addr:X}.")

        if len(samples) < 2:
            logger.warning("Insufficient samples for signature generation")
            return {"pattern": b"", "mask": b"", "confidence": 0.0, "common_bytes": []}
        logger.debug(f"Collected {len(samples)} valid samples.")

        # Find common byte patterns across samples
        pattern = bytearray()
        mask = bytearray()
        confidence_scores = []

        for byte_pos in range(context_size):
            # Collect all bytes at this position across samples
            bytes_at_pos = [sample[byte_pos] for sample in samples]

            # Count occurrences of each byte value
            byte_counts = collections.Counter(bytes_at_pos)
            most_common_byte, count = byte_counts.most_common(1)[0]

            # Calculate confidence for this byte position
            confidence = count / len(samples)

            if confidence >= 0.8:  # 80% threshold for considering byte stable
                pattern.append(most_common_byte)
                mask.append(0xFF)  # Fixed byte
                confidence_scores.append(confidence)
            else:
                pattern.append(0x00)  # Wildcard
                mask.append(0x00)  # Variable byte
                confidence_scores.append(0.0)

        # Calculate overall signature confidence
        overall_confidence = (
            sum(confidence_scores) / len(confidence_scores) if confidence_scores else 0.0
        )
        logger.debug(
            f"Initial pattern generated with overall confidence: {overall_confidence:.2%}."
        )

        # Find longest common subsequences for better signature
        common_sequences = self._find_common_sequences(samples)
        logger.debug(f"Found {len(common_sequences)} common sequences.")

        # Refine signature based on common sequences
        refined_pattern, refined_mask = self._refine_signature(pattern, mask, common_sequences)
        logger.debug("Signature refined using common sequences.")

        # Generate YARA-compatible hex string
        yara_hex = self._generate_yara_hex(refined_pattern, refined_mask)

        signature = {
            "pattern": bytes(refined_pattern),
            "mask": bytes(refined_mask),
            "confidence": overall_confidence,
            "common_bytes": len([b for b in refined_mask if b == 0xFF]),
            "wildcard_bytes": len([b for b in refined_mask if b == 0x00]),
            "yara_hex": yara_hex,
            "sample_count": len(samples),
            "signature_length": len(refined_pattern),
        }

        logger.info(
            f"Generated signature: {signature['common_bytes']} fixed bytes, "
            f"{signature['wildcard_bytes']} wildcards, confidence: {overall_confidence:.2%}",
        )
        logger.debug(f"Final generated signature: {signature}")
        return signature

    def _find_common_sequences(self, samples: list[bytes], min_length: int = 4) -> list[bytes]:
        """Find common byte sequences across samples."""
        logger.debug(
            f"Finding common sequences across {len(samples)} samples (min_length: {min_length})."
        )
        if len(samples) < 2:
            logger.debug("Less than 2 samples, no common sequences to find.")
            return []

        common_sequences = []
        reference = samples[0]

        # Find all subsequences in reference sample
        for start in range(len(reference) - min_length + 1):
            for length in range(min_length, min(16, len(reference) - start + 1)):
                subsequence = reference[start : start + length]

                # Check if this subsequence appears in all other samples
                if all(subsequence in sample for sample in samples[1:]) and all(
                                        subsequence not in existing
                                        for existing in common_sequences
                                    ):
                    common_sequences.append(subsequence)
                    logger.debug(f"Found common subsequence: {subsequence.hex()}")

        # Sort by length (longer sequences first)
        common_sequences.sort(key=len, reverse=True)
        logger.debug(
            f"Finished finding common sequences. Total found: {len(common_sequences)}. Top 10: {[s.hex() for s in common_sequences[:10]]}"
        )
        return common_sequences[:10]  # Return top 10 sequences

    def _refine_signature(
        self, pattern: bytearray, mask: bytearray, common_sequences: list[bytes]
    ) -> tuple[bytearray, bytearray]:
        """Refine signature using common sequences."""
        logger.debug("Refining signature using common sequences.")
        refined_pattern = bytearray(pattern)
        refined_mask = bytearray(mask)

        # Mark bytes in common sequences as fixed
        for sequence in common_sequences:
            # Find sequence in pattern
            for i in range(len(pattern) - len(sequence) + 1):
                if all(
                    pattern[i + j] == sequence[j] or mask[i + j] == 0x00
                    for j in range(len(sequence))
                ):
                    # Update pattern and mask for this sequence
                    for j in range(len(sequence)):
                        refined_pattern[i + j] = sequence[j]
                        refined_mask[i + j] = 0xFF
                    logger.debug(
                        f"Marked common sequence '{sequence.hex()}' as fixed in signature."
                    )
        logger.debug(
            f"Signature refinement complete. Refined pattern: {refined_pattern.hex()}, Refined mask: {refined_mask.hex()}"
        )
        return refined_pattern, refined_mask

    def _generate_yara_hex(self, pattern: bytearray, mask: bytearray) -> str:
        """Generate YARA-compatible hex string with wildcards."""
        hex_parts = []

        i = 0
        while i < len(pattern):
            if mask[i] == 0xFF:
                # Fixed byte
                hex_parts.append(f"{pattern[i]:02X}")
            else:
                # Wildcard - count consecutive wildcards
                wildcard_count = 0
                j = i
                while j < len(mask) and mask[j] == 0x00:
                    wildcard_count += 1
                    j += 1

                if wildcard_count == 1:
                    hex_parts.append("??")
                else:
                    # Use jump for multiple wildcards
                    hex_parts.append(f"[{wildcard_count}]")
                    i = j - 1  # Will be incremented at loop end

            i += 1
        yara_hex_string = " ".join(hex_parts)
        logger.debug(f"Generated YARA hex string: {yara_hex_string}")
        return yara_hex_string

    def auto_generate_signatures(self, target_functions: list[str]) -> dict[str, dict[str, Any]]:
        """Automatically generate signatures for known protection functions.

        Args:
            target_functions: List of function names to generate signatures for

        Returns:
            Dictionary mapping function names to generated signatures

        """
        signatures = {}
        logger.debug(
            f"Automatically generating signatures for target functions: {target_functions}"
        )

        # Common licensing function patterns to search for
        license_patterns = {
            "CheckLicense": [
                b"\x55\x8b\xec",  # push ebp; mov ebp, esp
                b"\x48\x89\x5c\x24",  # mov [rsp+X], rbx (x64)
            ],
            "ValidateSerial": [
                b"\x55\x8b\xec\x81\xec",  # Function prologue with stack allocation
                b"\x48\x83\xec",  # sub rsp, X (x64)
            ],
            "IsTrialExpired": [
                b"\x55\x8b\xec\x51",  # push ebp; mov ebp, esp; push ecx
                b"\x40\x53\x48\x83\xec",  # push rbx; sub rsp, X (x64)
            ],
            "GetHardwareID": [
                b"\x55\x8b\xec\x83\xec",  # Standard x86 prologue
                b"\x48\x89\x4c\x24",  # mov [rsp+X], rcx (x64)
            ],
        }

        for func_name in target_functions:
            logger.debug(f"Generating signature for function: {func_name}")
            # Search for function patterns
            found_addresses = []
            if func_name in license_patterns:
                logger.debug(
                    f"Searching for specific patterns for {func_name}: {[p.hex() for p in license_patterns[func_name]]}"
                )

                for pattern in license_patterns[func_name]:
                    matches = self.scan_pattern(pattern)
                    found_addresses.extend(matches[:5])  # Take first 5 matches
                logger.debug(f"Found {len(found_addresses)} addresses for {func_name}.")

                if found_addresses:
                    # Generate signature from found samples
                    signature = self.generate_signature_from_sample(
                        found_addresses, context_size=48
                    )

                    if signature["confidence"] > 0.5:
                        signatures[func_name] = signature
                        logger.info(
                            f"Generated signature for {func_name}: confidence {signature['confidence']:.2%}"
                        )
                        logger.debug(f"Signature for {func_name} generated: {signature}")
            else:
                # Try generic function prologue search
                logger.debug(
                    f"No specific patterns for {func_name}. Trying generic function prologue search."
                )
                generic_patterns = [
                    b"\x55\x8b\xec",  # x86: push ebp; mov ebp, esp
                    b"\x55\x48\x89\xe5",  # x64: push rbp; mov rbp, rsp
                    b"\x48\x89\x5c\x24",  # x64: mov [rsp+X], rbx
                    b"\x40\x55",  # x64: push rbp with REX prefix
                ]

                for pattern in generic_patterns:
                    if matches := self.scan_pattern(pattern):
                        found_addresses.extend(matches[:3])
                logger.debug(
                    f"Found {len(found_addresses)} addresses using generic patterns for {func_name}."
                )

                if found_addresses:
                    signature = self.generate_signature_from_sample(
                        found_addresses, context_size=64
                    )
                    signatures[func_name] = signature
                    logger.debug(
                        f"Signature for {func_name} generated using generic patterns: {signature}"
                    )
        logger.debug(f"Auto-signature generation complete. Total signatures: {len(signatures)}")
        return signatures

    def _get_cache_key(self, pattern: bytes, mask: bytes | None = None) -> str:
        """Generate unique cache key for pattern."""
        import hashlib

        key_data = pattern
        if mask:
            key_data += b"|" + mask
        return hashlib.sha256(key_data).hexdigest()[:16]

    def _is_cache_valid(self, key: str) -> bool:
        """Check if cache entry is still valid."""
        import time

        if key not in self._cache_timestamps:
            return False
        age = time.time() - self._cache_timestamps[key]
        return age < self._cache_ttl

    def _evict_oldest_cache(self) -> None:
        """Evict oldest cache entries when cache is full."""
        import time

        if len(self._pattern_cache) >= self._cache_max_size:
            # Find oldest entry
            oldest_key = None
            oldest_time = time.time()

            for key, timestamp in self._cache_timestamps.items():
                if timestamp < oldest_time:
                    oldest_time = timestamp
                    oldest_key = key

            if oldest_key:
                del self._pattern_cache[oldest_key]
                del self._cache_timestamps[oldest_key]
                self._cache_stats["evictions"] += 1
                logger.debug(f"Evicted cache entry: {oldest_key}")

    def scan_pattern_cached(self, pattern: bytes, mask: bytes | None = None) -> list[int]:
        """Scan memory for byte pattern with caching."""
        import time

        cache_key = self._get_cache_key(pattern, mask)
        logger.debug(f"Scanning for pattern (cached). Cache key: {cache_key}")

        with self._cache_lock:
            # Check cache
            if cache_key in self._pattern_cache and self._is_cache_valid(cache_key):
                self._cache_stats["hits"] += 1
                logger.debug(f"Cache hit for pattern {cache_key}. Returning cached results.")
                return self._pattern_cache[cache_key].copy()

            self._cache_stats["misses"] += 1
            logger.debug(f"Cache miss for pattern {cache_key}. Performing actual scan.")

            # Perform actual scan
            results = self.scan_pattern(pattern, mask)

            # Update cache
            self._evict_oldest_cache()
            self._pattern_cache[cache_key] = results.copy()
            self._cache_timestamps[cache_key] = time.time()
            logger.debug(f"Pattern {cache_key} scanned and added to cache.")

            return results

    def invalidate_cache(self, pattern: bytes | None = None) -> None:
        """Invalidate cache entries."""
        with self._cache_lock:
            if pattern:
                # Invalidate specific pattern
                cache_key = self._get_cache_key(pattern)
                if cache_key in self._pattern_cache:
                    del self._pattern_cache[cache_key]
                    del self._cache_timestamps[cache_key]
                    logger.info(f"Invalidated cache for pattern {cache_key}")
                    logger.debug(f"Specific cache entry '{cache_key}' invalidated.")
                else:
                    logger.debug(f"Pattern '{cache_key}' not found in cache for invalidation.")
            else:
                # Invalidate all cache
                self._pattern_cache.clear()
                self._cache_timestamps.clear()
                self._memory_snapshot_cache.clear()
                logger.info("Invalidated entire pattern cache")
                logger.debug("All cache entries invalidated.")

    def get_cache_stats(self) -> dict[str, Any]:
        """Get cache performance statistics."""
        with self._cache_lock:
            total_requests = self._cache_stats["hits"] + self._cache_stats["misses"]
            hit_rate = self._cache_stats["hits"] / total_requests if total_requests > 0 else 0.0

            stats = {
                "hits": self._cache_stats["hits"],
                "misses": self._cache_stats["misses"],
                "evictions": self._cache_stats["evictions"],
                "hit_rate": hit_rate,
                "cache_size": len(self._pattern_cache),
                "max_size": self._cache_max_size,
                "ttl_seconds": self._cache_ttl,
            }
            logger.debug(f"Cache statistics: {stats}")
            return stats

    def optimize_cache_performance(self) -> None:
        """Optimize cache based on usage patterns."""
        import time

        logger.debug("Optimizing cache performance.")
        with self._cache_lock:
            # Remove expired entries
            current_time = time.time()
            expired_keys = [
                key
                for key, timestamp in self._cache_timestamps.items()
                if current_time - timestamp >= self._cache_ttl
            ]

            for key in expired_keys:
                del self._pattern_cache[key]
                del self._cache_timestamps[key]
                logger.debug(f"Evicted expired cache entry: {key}")

            # Adjust cache size based on hit rate
            stats = self.get_cache_stats()
            if stats["hit_rate"] < 0.3 and self._cache_max_size < 200:
                self._cache_max_size = min(200, self._cache_max_size + 20)
                logger.info(f"Increased cache size to {self._cache_max_size}")
                logger.debug(f"Cache size increased to {self._cache_max_size} due to low hit rate.")
            elif stats["hit_rate"] > 0.8 and stats["evictions"] < 5:
                self._cache_max_size = max(50, self._cache_max_size - 10)
                logger.info(f"Decreased cache size to {self._cache_max_size}")
                logger.debug(
                    f"Cache size decreased to {self._cache_max_size} due to high hit rate and low evictions."
                )
            logger.debug("Cache optimization complete.")

    def batch_scan_with_cache(self, patterns: list[dict[str, Any]]) -> dict[str, list[int]]:
        """Batch scan multiple patterns with intelligent caching."""
        logger.debug(f"Starting batch scan for {len(patterns)} patterns.")
        results = {}
        cached_patterns = []
        uncached_patterns = []

        # Separate cached and uncached patterns
        for pattern in patterns:
            cache_key = self._get_cache_key(pattern["bytes"], pattern.get("mask"))
            if cache_key in self._pattern_cache and self._is_cache_valid(cache_key):
                cached_patterns.append(pattern)
                logger.debug(f"Pattern '{pattern['name']}' is cached.")
            else:
                uncached_patterns.append(pattern)
                logger.debug(f"Pattern '{pattern['name']}' is not cached.")

        # Get cached results immediately
        with self._cache_lock:
            for pattern in cached_patterns:
                cache_key = self._get_cache_key(pattern["bytes"], pattern.get("mask"))
                results[pattern["name"]] = self._pattern_cache[cache_key].copy()
                self._cache_stats["hits"] += 1
                logger.debug(f"Retrieved cached results for pattern '{pattern['name']}'.")

        # Scan uncached patterns concurrently
        if uncached_patterns:
            logger.debug(f"Scanning {len(uncached_patterns)} uncached patterns concurrently.")
            new_results = self.scan_patterns_concurrent(uncached_patterns)

            # Update cache with new results
            with self._cache_lock:
                for pattern in uncached_patterns:
                    pattern_name = pattern["name"]
                    if pattern_name in new_results:
                        cache_key = self._get_cache_key(pattern["bytes"], pattern.get("mask"))
                        self._evict_oldest_cache()
                        self._pattern_cache[cache_key] = new_results[pattern_name].copy()
                        self._cache_timestamps[cache_key] = time.time()
                        results[pattern_name] = new_results[pattern_name]
                        self._cache_stats["misses"] += 1
                        logger.debug(f"Scanned pattern '{pattern_name}' and added to cache.")

        logger.info(
            f"Batch scan complete: {len(cached_patterns)} cached, {len(uncached_patterns)} scanned"
        )
        logger.debug(f"Final batch scan results: {results}")
        return results

    def get_peb_address(self) -> int | None:
        """Get PEB address for current process."""
        logger.debug("Attempting to retrieve PEB address.")
        if not self.process_handle:
            logger.debug("No process attached. Cannot get PEB address.")
            return None

        try:
            # Setup NtQueryInformationProcess
            self.ntdll.NtQueryInformationProcess.argtypes = [
                ctypes.wintypes.HANDLE,
                ctypes.c_int,
                ctypes.c_void_p,
                ctypes.c_ulong,
                ctypes.POINTER(ctypes.c_ulong),
            ]
            self.ntdll.NtQueryInformationProcess.restype = ctypes.c_long

            pbi = ProcessBasicInformation()
            return_length = ctypes.c_ulong()

            status = self.ntdll.NtQueryInformationProcess(
                self.process_handle,
                ProcessInformationClass.ProcessBasicInformation,
                ctypes.byref(pbi),
                ctypes.sizeof(pbi),
                ctypes.byref(return_length),
            )

            if status == 0:  # STATUS_SUCCESS
                peb_address = ctypes.addressof(pbi.PebBaseAddress.contents)
                logger.debug(f"Successfully retrieved PEB address: 0x{peb_address:X}.")
                return peb_address
            logger.error(f"NtQueryInformationProcess failed with status: 0x{status:X}")
            logger.debug(f"NtQueryInformationProcess failed. Status: 0x{status:X}.")
            return None

        except Exception as e:
            logger.error(f"Failed to get PEB address: {e}")
            logger.debug(f"Exception during PEB address retrieval: {e}", exc_info=True)
            return None

    def read_peb(self) -> Peb | None:
        """Read PEB structure from target process."""
        logger.debug("Attempting to read PEB structure.")
        if not self.process_handle:
            logger.debug("No process attached. Cannot read PEB.")
            return None

        peb_addr = self.get_peb_address()
        if not peb_addr:
            logger.debug("Failed to get PEB address. Cannot read PEB.")
            return None
        logger.debug(f"PEB address: 0x{peb_addr:X}.")

        try:
            peb = Peb()
            bytes_read = ctypes.c_size_t()

            if success := self.kernel32.ReadProcessMemory(
                self.process_handle,
                ctypes.c_void_p(peb_addr),
                ctypes.byref(peb),
                ctypes.sizeof(Peb),
                ctypes.byref(bytes_read),
            ):
                logger.debug(f"Successfully read PEB from 0x{peb_addr:X}.")
                return peb
            logger.error(f"Failed to read PEB: {ctypes.GetLastError()}")
            logger.debug(f"Failed to read PEB. Error: {ctypes.GetLastError()}.")
            return None

        except Exception as e:
            logger.error(f"Error reading PEB: {e}")
            logger.debug(f"Exception during PEB reading: {e}", exc_info=True)
            return None

    def manipulate_peb_flags(
        self,
        clear_being_debugged: bool = True,
        clear_nt_global_flag: bool = True,
        clear_heap_flags: bool = True,
    ) -> bool:
        """Manipulate PEB flags to bypass anti-debugging checks."""
        logger.debug(
            f"Manipulating PEB flags: clear_being_debugged={clear_being_debugged}, clear_nt_global_flag={clear_nt_global_flag}, clear_heap_flags={clear_heap_flags}"
        )
        if not self.process_handle:
            logger.debug("No process attached. Cannot manipulate PEB flags.")
            return False

        peb_addr = self.get_peb_address()
        if not peb_addr:
            logger.debug("Failed to get PEB address. Cannot manipulate PEB flags.")
            return False
        logger.debug(f"PEB address: 0x{peb_addr:X}.")

        try:
            modifications_made = []

            # Clear BeingDebugged flag
            if clear_being_debugged:
                being_debugged_offset = 0x02  # Offset of BeingDebugged in PEB
                zero_byte = ctypes.c_ubyte(0)
                bytes_written = ctypes.c_size_t()
                logger.debug(
                    f"Attempting to clear PEB.BeingDebugged flag at offset 0x{being_debugged_offset:X}."
                )
                if success := self.kernel32.WriteProcessMemory(
                    self.process_handle,
                    ctypes.c_void_p(peb_addr + being_debugged_offset),
                    ctypes.byref(zero_byte),
                    1,
                    ctypes.byref(bytes_written),
                ):
                    modifications_made.append("BeingDebugged")
                    logger.info("Cleared PEB.BeingDebugged flag")
                    logger.debug("PEB.BeingDebugged flag cleared successfully.")
                else:
                    logger.debug(
                        f"Failed to clear PEB.BeingDebugged flag. Error: {ctypes.get_last_error()}"
                    )

            # Clear NtGlobalFlag
            if clear_nt_global_flag:
                # NtGlobalFlag offset varies by architecture
                is_64bit = ctypes.sizeof(ctypes.c_voidp) == 8
                nt_global_flag_offset = 0xBC if is_64bit else 0x68
                logger.debug(
                    f"Attempting to clear PEB.NtGlobalFlag at offset 0x{nt_global_flag_offset:X} (64-bit: {is_64bit})."
                )
                zero_dword = ctypes.c_ulong(0)
                bytes_written = ctypes.c_size_t()

                if success := self.kernel32.WriteProcessMemory(
                    self.process_handle,
                    ctypes.c_void_p(peb_addr + nt_global_flag_offset),
                    ctypes.byref(zero_dword),
                    ctypes.sizeof(zero_dword),
                    ctypes.byref(bytes_written),
                ):
                    modifications_made.append("NtGlobalFlag")
                    logger.info("Cleared PEB.NtGlobalFlag")
                    logger.debug("PEB.NtGlobalFlag cleared successfully.")
                else:
                    logger.debug(
                        f"Failed to clear PEB.NtGlobalFlag. Error: {ctypes.get_last_error()}"
                    )

            # Clear heap flags
            if clear_heap_flags:
                logger.debug("Attempting to clear heap debugging flags.")
                peb = self.read_peb()
                if peb and peb.ProcessHeap:
                    # Clear heap flags that indicate debugging
                    heap_flags_offset = 0x70 if ctypes.sizeof(ctypes.c_voidp) == 8 else 0x40
                    # Clear Flags field
                    flags_value = ctypes.c_ulong(2)  # HEAP_GROWABLE
                    bytes_written = ctypes.c_size_t()
                    logger.debug(
                        f"Clearing heap Flags field at 0x{int(peb.ProcessHeap) + heap_flags_offset:X}."
                    )
                    if success := self.kernel32.WriteProcessMemory(
                        self.process_handle,
                        ctypes.c_void_p(int(peb.ProcessHeap) + heap_flags_offset),
                        ctypes.byref(flags_value),
                        ctypes.sizeof(flags_value),
                        ctypes.byref(bytes_written),
                    ):
                        # Clear ForceFlags field
                        zero_dword = ctypes.c_ulong(0)
                        heap_force_flags_offset = heap_flags_offset + 4

                        logger.debug(
                            f"Clearing heap ForceFlags field at 0x{int(peb.ProcessHeap) + heap_force_flags_offset:X}."
                        )
                        self.kernel32.WriteProcessMemory(
                            self.process_handle,
                            ctypes.c_void_p(int(peb.ProcessHeap) + heap_force_flags_offset),
                            ctypes.byref(zero_dword),
                            ctypes.sizeof(zero_dword),
                            ctypes.byref(bytes_written),
                        )

                        modifications_made.append("HeapFlags")
                        logger.info("Cleared heap debugging flags")
                        logger.debug("Heap debugging flags cleared successfully.")
                    else:
                        logger.debug(
                            f"Failed to clear heap Flags field. Error: {ctypes.get_last_error()}"
                        )
                else:
                    logger.debug("PEB or ProcessHeap not available for heap flag manipulation.")

            if modifications_made:
                logger.info(f"PEB manipulation complete: {', '.join(modifications_made)}")
                logger.debug("PEB manipulation successful.")
                return True
            logger.warning("No PEB modifications were successful")
            logger.debug("PEB manipulation completed with no successful modifications.")
            return False

        except Exception as e:
            logger.error(f"PEB manipulation failed: {e}")
            logger.debug(f"Exception during PEB manipulation: {e}", exc_info=True)
            return False

    def hide_from_debugger(self) -> bool:
        """Hide process from debugger detection using multiple techniques."""
        logger.debug("Attempting to hide process from debugger detection.")
        if not self.process_handle:
            logger.debug("No process attached. Cannot hide from debugger.")
            return False

        techniques_applied = []

        # 1. PEB manipulation
        logger.debug("Applying PEB manipulation technique.")
        if self.manipulate_peb_flags():
            techniques_applied.append("PEB_flags")
            logger.debug("PEB flags manipulated successfully.")
        else:
            logger.debug("PEB flags manipulation failed.")

        # 2. Set DebugPort to 0
        try:
            self.ntdll.NtSetInformationProcess.argtypes = [
                ctypes.wintypes.HANDLE,
                ctypes.c_int,
                ctypes.c_void_p,
                ctypes.c_ulong,
            ]
            self.ntdll.NtSetInformationProcess.restype = ctypes.c_long

            debug_port = ctypes.c_void_p(0)
            logger.debug("Attempting to set ProcessDebugPort to 0.")
            status = self.ntdll.NtSetInformationProcess(
                self.process_handle,
                ProcessInformationClass.ProcessDebugPort,
                ctypes.byref(debug_port),
                ctypes.sizeof(debug_port),
            )

            if status == 0:
                techniques_applied.append("DebugPort")
                logger.info("Set ProcessDebugPort to 0")
                logger.debug("ProcessDebugPort set to 0 successfully.")
            else:
                logger.debug(f"Failed to set ProcessDebugPort to 0. Status: 0x{status:X}.")

        except Exception as e:
            logger.error(f"Failed to set debug port: {e}")
            logger.debug(f"Exception during setting debug port: {e}", exc_info=True)

        # 3. Set DebugObjectHandle to 0
        try:
            debug_object = ctypes.c_void_p(0)
            logger.debug("Attempting to set ProcessDebugObjectHandle to 0.")
            status = self.ntdll.NtSetInformationProcess(
                self.process_handle,
                ProcessInformationClass.ProcessDebugObjectHandle,
                ctypes.byref(debug_object),
                ctypes.sizeof(debug_object),
            )

            if status == 0:
                techniques_applied.append("DebugObjectHandle")
                logger.info("Set ProcessDebugObjectHandle to 0")
                logger.debug("ProcessDebugObjectHandle set to 0 successfully.")
            else:
                logger.debug(f"Failed to set ProcessDebugObjectHandle to 0. Status: 0x{status:X}.")

        except Exception as e:
            logger.error(f"Failed to set debug object handle: {e}")
            logger.debug(f"Exception during setting debug object handle: {e}", exc_info=True)

        # 4. Set DebugFlags to 0
        try:
            debug_flags = ctypes.c_ulong(0)
            logger.debug("Attempting to set ProcessDebugFlags to 0.")
            status = self.ntdll.NtSetInformationProcess(
                self.process_handle,
                ProcessInformationClass.ProcessDebugFlags,
                ctypes.byref(debug_flags),
                ctypes.sizeof(debug_flags),
            )

            if status == 0:
                techniques_applied.append("DebugFlags")
                logger.info("Set ProcessDebugFlags to 0")
                logger.debug("ProcessDebugFlags set to 0 successfully.")
            else:
                logger.debug(f"Failed to set ProcessDebugFlags to 0. Status: 0x{status:X}.")

        except Exception as e:
            logger.error(f"Failed to set debug flags: {e}")
            logger.debug(f"Exception during setting debug flags: {e}", exc_info=True)

        if techniques_applied:
            logger.info(
                f"Applied {len(techniques_applied)} anti-debug bypass techniques: {', '.join(techniques_applied)}"
            )
            logger.debug("Anti-debug bypass techniques applied successfully.")
            return True
        logger.warning("Failed to apply any anti-debug bypass techniques")
        logger.debug("No anti-debug bypass techniques were successfully applied.")
        return False

    def check_peb_for_debugger(self) -> dict[str, bool]:
        """Check PEB for various debugger indicators."""
        logger.debug("Checking PEB for debugger indicators.")
        indicators = {
            "BeingDebugged": False,
            "NtGlobalFlag": False,
            "HeapFlags": False,
            "DebuggerPresent": False,
        }

        peb = self.read_peb()
        if not peb:
            logger.debug("Failed to read PEB. Cannot check for debugger indicators.")
            return indicators

        # Check BeingDebugged flag
        indicators["BeingDebugged"] = bool(peb.BeingDebugged)
        logger.debug(f"PEB.BeingDebugged: {indicators['BeingDebugged']}")

        # Check NtGlobalFlag for debug flags (0x70 = FLG_HEAP_ENABLE_TAIL_CHECK | FLG_HEAP_ENABLE_FREE_CHECK | FLG_HEAP_VALIDATE_PARAMETERS)
        indicators["NtGlobalFlag"] = (peb.NtGlobalFlag & 0x70) != 0
        logger.debug(f"PEB.NtGlobalFlag (0x{peb.NtGlobalFlag:X}): {indicators['NtGlobalFlag']}")

        # Check heap flags
        if peb.ProcessHeap:
            try:
                heap_flags_offset = 0x70 if ctypes.sizeof(ctypes.c_voidp) == 8 else 0x40
                heap_flags = ctypes.c_ulong()
                bytes_read = ctypes.c_size_t()
                logger.debug(
                    f"Checking heap flags at 0x{int(peb.ProcessHeap) + heap_flags_offset:X}."
                )
                self.kernel32.ReadProcessMemory(
                    self.process_handle,
                    ctypes.c_void_p(int(peb.ProcessHeap) + heap_flags_offset),
                    ctypes.byref(heap_flags),
                    ctypes.sizeof(heap_flags),
                    ctypes.byref(bytes_read),
                )

                # Check for debug heap flags
                indicators["HeapFlags"] = (heap_flags.value & 0x50000062) != 2
                logger.debug(f"HeapFlags (0x{heap_flags.value:X}): {indicators['HeapFlags']}")

            except Exception as e:
                logger.error(f"Failed to check heap flags: {e}")
                logger.debug(f"Exception during heap flags check: {e}", exc_info=True)
        else:
            logger.debug("ProcessHeap not available for heap flags check.")

        # Check IsDebuggerPresent API
        try:
            indicators["DebuggerPresent"] = bool(kernel32.IsDebuggerPresent())
            logger.debug(f"IsDebuggerPresent API result: {indicators['DebuggerPresent']}")
        except (AttributeError, OSError) as e:
            logger.debug(f"Failed to check IsDebuggerPresent: {e}")
        logger.debug(f"PEB debugger indicators check completed. Results: {indicators}")
        return indicators

    def modify_peb_image_path(self, new_path: str) -> bool:
        """Modify the image path in PEB to disguise process."""
        logger.debug(f"Attempting to modify PEB image path to: '{new_path}'")
        if not self.process_handle:
            logger.debug("No process attached. Cannot modify PEB image path.")
            return False

        peb = self.read_peb()
        if not peb or not peb.ProcessParameters:
            logger.debug("Failed to read PEB or ProcessParameters. Cannot modify PEB image path.")
            return False
        logger.debug(
            f"Current ImagePathName buffer address: 0x{peb.ProcessParameters.contents.ImagePathName.Buffer:X}"
        )

        try:
            # Read process parameters
            params = RtlUserProcessParameters()
            bytes_read = ctypes.c_size_t()

            success = self.kernel32.ReadProcessMemory(
                self.process_handle,
                peb.ProcessParameters,
                ctypes.byref(params),
                ctypes.sizeof(params),
                ctypes.byref(bytes_read),
            )

            if not success:
                logger.debug(f"Failed to read ProcessParameters. Error: {ctypes.get_last_error()}")
                return False
            logger.debug("ProcessParameters read successfully.")

            # Create new Unicode string for image path
            new_path_unicode = (new_path + "\0").encode("utf-16le")
            new_path_len = len(new_path_unicode) - 2  # Exclude null terminator
            logger.debug(f"New image path Unicode string length: {new_path_len} bytes.")

            # Allocate memory in target process for new path
            new_path_addr = self.kernel32.VirtualAllocEx(
                self.process_handle,
                None,
                len(new_path_unicode),
                0x3000,  # MEM_COMMIT | MEM_RESERVE
                0x04,  # PAGE_READWRITE
            )

            if not new_path_addr:
                logger.debug(
                    f"Failed to allocate memory for new image path. Error: {ctypes.get_last_error()}"
                )
                return False
            logger.debug(f"Allocated memory for new image path at 0x{new_path_addr:X}.")

            # Write new path to allocated memory
            bytes_written = ctypes.c_size_t()
            if success := self.kernel32.WriteProcessMemory(
                self.process_handle,
                new_path_addr,
                new_path_unicode,
                len(new_path_unicode),
                ctypes.byref(bytes_written),
            ):
                logger.debug(f"New image path written to 0x{new_path_addr:X}.")
                # Update ImagePathName in process parameters
                params.ImagePathName.Length = new_path_len
                params.ImagePathName.MaximumLength = len(new_path_unicode)
                params.ImagePathName.Buffer = ctypes.cast(new_path_addr, ctypes.c_wchar_p)

                if success := self.kernel32.WriteProcessMemory(
                    self.process_handle,
                    peb.ProcessParameters,
                    ctypes.byref(params),
                    ctypes.sizeof(params),
                    ctypes.byref(bytes_written),
                ):
                    logger.info(f"Modified PEB image path to: {new_path}")
                    logger.debug("PEB image path modified successfully.")
                    return True
                logger.debug(
                    f"Failed to write updated ProcessParameters back. Error: {ctypes.get_last_error()}"
                )
            else:
                logger.debug(
                    f"Failed to write new image path to allocated memory. Error: {ctypes.get_last_error()}"
                )

        except Exception as e:
            logger.error(f"Failed to modify PEB image path: {e}")
            logger.debug(f"Exception during PEB image path modification: {e}", exc_info=True)

        return False

    def walk_vad_tree(self) -> list[dict[str, Any]]:
        """Walk Virtual Address Descriptor tree to enumerate all memory regions."""
        logger.debug("Starting VAD tree walk to enumerate memory regions.")
        if not self.process_handle:
            logger.debug("No process attached. Cannot walk VAD tree.")
            return []

        vad_entries = []
        current_address = 0
        max_address = 0x7FFFFFFFFFFFFFFF if ctypes.sizeof(ctypes.c_voidp) == 8 else 0x7FFFFFFF
        logger.debug(f"Scanning memory from 0x{current_address:X} to 0x{max_address:X}.")

        # Setup NtQueryVirtualMemory
        self.ntdll.NtQueryVirtualMemory.argtypes = [
            ctypes.wintypes.HANDLE,
            ctypes.c_void_p,
            ctypes.c_int,
            ctypes.c_void_p,
            ctypes.c_size_t,
            ctypes.POINTER(ctypes.c_size_t),
        ]
        self.ntdll.NtQueryVirtualMemory.restype = ctypes.c_long

        while current_address < max_address:
            mbi = MemoryBasicInformation()
            return_length = ctypes.c_size_t()

            status = self.ntdll.NtQueryVirtualMemory(
                self.process_handle,
                ctypes.c_void_p(current_address),
                MemoryInformationClass.MemoryBasicInformation,
                ctypes.byref(mbi),
                ctypes.sizeof(mbi),
                ctypes.byref(return_length),
            )

            if status == 0:  # STATUS_SUCCESS
                # Parse memory protection flags
                protection = self._parse_protection_flags(mbi.Protect)
                state = self._parse_memory_state(mbi.State)
                mem_type = self._parse_memory_type(mbi.Type)

                vad_entry = {
                    "base_address": mbi.BaseAddress,
                    "allocation_base": mbi.AllocationBase,
                    "region_size": mbi.RegionSize,
                    "state": state,
                    "protection": protection,
                    "type": mem_type,
                    "allocation_protect": self._parse_protection_flags(mbi.AllocationProtect),
                    "is_executable": bool(mbi.Protect & 0xF0),  # Any execute permission
                    "is_writable": bool(mbi.Protect & 0xCC),  # Any write permission
                    "is_guarded": bool(mbi.Protect & 0x100),  # PAGE_GUARD
                    "is_nocache": bool(mbi.Protect & 0x200),  # PAGE_NOCACHE
                }

                # Only add committed memory regions
                if mbi.State == 0x1000:  # MEM_COMMIT
                    vad_entries.append(vad_entry)
                    logger.debug(
                        f"Found VAD entry: Base=0x{mbi.BaseAddress:X}, Size=0x{mbi.RegionSize:X}, State={state}, Protect={protection}, Type={mem_type}"
                    )

                # Move to next region
                current_address = (
                    ctypes.cast(mbi.BaseAddress, ctypes.c_ulong).value + mbi.RegionSize
                )
            else:
                # Move forward on error
                current_address += 0x1000
                logger.debug(
                    f"NtQueryVirtualMemory failed at 0x{current_address:X}. Moving to next page. Error: {ctypes.get_last_error()}"
                )

            # Safety check to prevent infinite loop
            if current_address <= 0:
                logger.debug("Current address wrapped around or became zero. Breaking loop.")
                break

        logger.info(f"VAD walk complete: Found {len(vad_entries)} memory regions")
        logger.debug(f"VAD walk completed. Total regions found: {len(vad_entries)}.")
        return vad_entries

    def _parse_protection_flags(self, protect: int) -> str:
        """Parse memory protection flags to human-readable string."""
        protections = []

        if protect & 0x01:
            protections.append("NOACCESS")
        if protect & 0x02:
            protections.append("READONLY")
        if protect & 0x04:
            protections.append("READWRITE")
        if protect & 0x08:
            protections.append("WRITECOPY")
        if protect & 0x10:
            protections.append("EXECUTE")
        if protect & 0x20:
            protections.append("EXECUTE_READ")
        if protect & 0x40:
            protections.append("EXECUTE_READWRITE")
        if protect & 0x80:
            protections.append("EXECUTE_WRITECOPY")
        if protect & 0x100:
            protections.append("GUARD")
        if protect & 0x200:
            protections.append("NOCACHE")
        if protect & 0x400:
            protections.append("WRITECOMBINE")

        return "|".join(protections) if protections else "UNKNOWN"

    def _parse_memory_state(self, state: int) -> str:
        """Parse memory state to human-readable string."""
        states = {0x1000: "COMMIT", 0x2000: "RESERVE", 0x10000: "FREE"}
        return states.get(state, f"UNKNOWN(0x{state:X})")

    def _parse_memory_type(self, mem_type: int) -> str:
        """Parse memory type to human-readable string."""
        types = {0x20000: "PRIVATE", 0x40000: "MAPPED", 0x1000000: "IMAGE"}
        return types.get(mem_type, f"UNKNOWN(0x{mem_type:X})")

    def find_hidden_memory_regions(self) -> list[dict[str, Any]]:
        """Find potentially hidden memory regions using VAD analysis."""
        logger.debug("Starting search for potentially hidden memory regions.")
        vad_entries = self.walk_vad_tree()
        hidden_regions = []

        for i, entry in enumerate(vad_entries):
            # Check for suspicious characteristics
            suspicious_indicators = []

            # 1. Executable memory without image backing
            if entry["is_executable"] and entry["type"] != "IMAGE":
                suspicious_indicators.append("executable_non_image")
                logger.debug(
                    f"Suspicious: Executable non-image region at 0x{entry['base_address']:X}."
                )

            # 2. RWX permissions (Read-Write-Execute)
            if "EXECUTE_READWRITE" in entry["protection"]:
                suspicious_indicators.append("rwx_permissions")
                logger.debug(f"Suspicious: RWX permissions at 0x{entry['base_address']:X}.")

            # 3. Guarded pages (often used for anti-debugging)
            if entry["is_guarded"]:
                suspicious_indicators.append("guard_page")
                logger.debug(f"Suspicious: Guard page at 0x{entry['base_address']:X}.")

            # 4. Check for gaps (potential hidden regions)
            if i > 0:
                prev_entry = vad_entries[i - 1]
                prev_end = (
                    ctypes.cast(prev_entry["base_address"], ctypes.c_ulong).value
                    + prev_entry["region_size"]
                )
                current_start = ctypes.cast(entry["base_address"], ctypes.c_ulong).value

                gap_size = current_start - prev_end
                if gap_size > 0x10000:  # Significant gap (> 64KB)
                    suspicious_indicators.append(f"large_gap_{gap_size:X}")
                    logger.debug(
                        f"Suspicious: Large gap (0x{gap_size:X}) before region at 0x{entry['base_address']:X}."
                    )

            # 5. Unusual allocation protection vs current protection
            if entry["allocation_protect"] != entry["protection"]:
                suspicious_indicators.append("protection_changed")
                logger.debug(
                    f"Suspicious: Protection changed for region at 0x{entry['base_address']:X}."
                )

            if suspicious_indicators:
                hidden_regions.append(
                    {
                        **entry,
                        "suspicious_indicators": suspicious_indicators,
                        "suspicion_level": len(suspicious_indicators),
                    },
                )
                logger.debug(
                    f"Identified suspicious region at 0x{entry['base_address']:X} with indicators: {suspicious_indicators}."
                )

        # Sort by suspicion level
        hidden_regions.sort(key=lambda x: x["suspicion_level"], reverse=True)

        logger.info(f"Found {len(hidden_regions)} potentially hidden memory regions")
        logger.debug(
            f"Finished searching for hidden memory regions. Total found: {len(hidden_regions)}."
        )
        return hidden_regions

    def enumerate_executable_regions(self) -> list[dict[str, Any]]:
        """Enumerate all executable memory regions."""
        vad_entries = self.walk_vad_tree()
        executable_regions = []

        for entry in vad_entries:
            if entry["is_executable"]:
                # Try to identify the region
                region_info = {**entry, "identified_as": "unknown", "confidence": 0.0}

                # Check if it's a loaded module
                if entry["type"] == "IMAGE":
                    region_info["identified_as"] = "module"
                    region_info["confidence"] = 0.9

                    # Try to get module name
                    try:
                        if module_name := self._get_module_name_at_address(
                            ctypes.cast(
                                entry["base_address"], ctypes.c_ulong
                            ).value
                        ):
                            region_info["module_name"] = module_name
                            region_info["confidence"] = 1.0
                    except (KeyError, TypeError) as e:
                        logger.debug(
                            f"Failed to get module name for region at {entry['base_address']}: {e}"
                        )

                elif "EXECUTE_READWRITE" in entry["protection"]:
                    region_info["identified_as"] = "jit_code"
                    region_info["confidence"] = 0.7

                elif entry["type"] == "PRIVATE" and entry["region_size"] < 0x10000:
                    region_info["identified_as"] = "potential_shellcode"
                    region_info["confidence"] = 0.5

                executable_regions.append(region_info)

        logger.info(f"Found {len(executable_regions)} executable regions")
        return executable_regions

    def _get_module_name_at_address(self, address: int) -> str | None:
        """Get module name at specified address."""
        try:
            for module in self.enumerate_modules():
                module_base = module["base"]
                module_end = module_base + module["size"]

                if module_base <= address < module_end:
                    import os

                    return os.path.basename(module["path"])
        except (KeyError, TypeError, ImportError) as e:
            logger.debug(f"Failed to get module name at address {address:#x}: {e}")

        return None

    def analyze_memory_gaps(self) -> list[dict[str, Any]]:
        """Analyze gaps between memory regions for potential hiding spots."""
        vad_entries = self.walk_vad_tree()
        gaps = []

        for i in range(len(vad_entries) - 1):
            current = vad_entries[i]
            next_region = vad_entries[i + 1]

            current_end = (
                ctypes.cast(current["base_address"], ctypes.c_ulong).value + current["region_size"]
            )
            next_start = ctypes.cast(next_region["base_address"], ctypes.c_ulong).value

            gap_size = next_start - current_end

            if gap_size > 0:
                gap_info = {
                    "start_address": current_end,
                    "end_address": next_start,
                    "size": gap_size,
                    "size_kb": gap_size // 1024,
                    "size_mb": gap_size // (1024 * 1024),
                    "before_region": {
                        "address": current["base_address"],
                        "type": current["type"],
                        "protection": current["protection"],
                    },
                    "after_region": {
                        "address": next_region["base_address"],
                        "type": next_region["type"],
                        "protection": next_region["protection"],
                    },
                    "suitable_for_injection": gap_size >= 0x1000 and gap_size <= 0x100000,
                }

                gaps.append(gap_info)

        # Sort gaps by size
        gaps.sort(key=lambda x: x["size"], reverse=True)

        logger.info(
            f"Found {len(gaps)} memory gaps, {sum(bool(g['suitable_for_injection'])
                                              for g in gaps)} suitable for injection"
        )
        return gaps

    def detect_vad_manipulation(self) -> dict[str, Any]:
        """Detect signs of VAD manipulation or hiding techniques."""
        detection_results = {
            "vad_hiding_detected": False,
            "anomalies": [],
            "suspicious_regions": [],
            "confidence": 0.0,
        }

        vad_entries = self.walk_vad_tree()

        # 1. Check for unlisted executable regions
        all_regions = self._get_all_memory_regions_raw()
        vad_addresses = {ctypes.cast(e["base_address"], ctypes.c_ulong).value for e in vad_entries}

        for region in all_regions:
            if region["base_address"] not in vad_addresses and region["is_executable"]:
                detection_results["anomalies"].append(
                    {
                        "type": "unlisted_executable",
                        "address": region["base_address"],
                        "size": region["size"],
                    },
                )
                detection_results["vad_hiding_detected"] = True

        # 2. Check for manual memory allocations with suspicious permissions
        private_exec_regions = [
            e for e in vad_entries if e["type"] == "PRIVATE" and e["is_executable"]
        ]

        for region in private_exec_regions:
            # Check if region starts with common shellcode patterns
            try:
                if first_bytes := self.read_memory(
                    ctypes.cast(region["base_address"], ctypes.c_ulong).value,
                    min(16, region["region_size"]),
                ):
                    # Common shellcode/injection patterns
                    suspicious_patterns = [
                        b"\xfc\x48\x83\xe4",  # CLD; AND RSP
                        b"\x60\x89\xe5\x31",  # PUSHAD; MOV EBP,ESP
                        b"\x55\x8b\xec\x83",  # PUSH EBP; MOV EBP,ESP
                        b"\xe8\x00\x00\x00\x00",  # CALL $+5
                        b"\xeb\x0e\x5b",  # JMP SHORT; POP
                    ]

                    for pattern in suspicious_patterns:
                        if first_bytes.startswith(pattern):
                            detection_results["suspicious_regions"].append(
                                {
                                    "address": region["base_address"],
                                    "pattern_matched": pattern.hex(),
                                    "type": "shellcode_signature",
                                },
                            )
                            break
            except (KeyError, TypeError) as e:
                logger.debug(f"Failed to check shellcode patterns for region: {e}")

        # 3. Check for VAD unlink signs
        if len(vad_entries) < 10 and self.pid:
            # Suspiciously few VAD entries for an active process
            detection_results["anomalies"].append(
                {"type": "low_vad_count", "count": len(vad_entries), "expected_minimum": 10}
            )

        # Calculate confidence score
        confidence = 0.0
        if detection_results["vad_hiding_detected"]:
            confidence = 0.9
        elif detection_results["suspicious_regions"]:
            confidence = 0.7
        elif detection_results["anomalies"]:
            confidence = 0.5

        detection_results["confidence"] = confidence

        logger.info(
            f"VAD manipulation detection: {confidence:.1%} confidence, {len(detection_results['anomalies'])} anomalies found"
        )

        return detection_results

    def _get_all_memory_regions_raw(self) -> list[dict[str, Any]]:
        """Get all memory regions using low-level scanning."""
        regions = []
        current_address = 0
        max_address = 0x7FFFFFFFFFFFFFFF if ctypes.sizeof(ctypes.c_voidp) == 8 else 0x7FFFFFFF

        mbi = MemoryBasicInformation()
        size = ctypes.sizeof(mbi)

        while current_address < max_address:
            if result := kernel32.VirtualQueryEx(
                self.process_handle,
                ctypes.c_void_p(current_address),
                ctypes.byref(mbi),
                size,
            ):
                if mbi.State == 0x1000:  # MEM_COMMIT
                    regions.append(
                        {
                            "base_address": ctypes.cast(mbi.BaseAddress, ctypes.c_ulong).value,
                            "size": mbi.RegionSize,
                            "protection": mbi.Protect,
                            "is_executable": bool(mbi.Protect & 0xF0),
                        },
                    )

                current_address = (
                    ctypes.cast(mbi.BaseAddress, ctypes.c_ulong).value + mbi.RegionSize
                )
            else:
                break

        return regions

    def find_code_caves(self, min_size: int = 16, max_size: int = 0x10000) -> list[dict[str, Any]]:
        """Find code caves suitable for injection."""
        caves = []

        # 1. Find caves in loaded modules (section slack space)
        module_caves = self._find_section_slack_caves(min_size, max_size)
        caves.extend(module_caves)

        # 2. Find caves in memory gaps
        gap_caves = self._find_memory_gap_caves(min_size, max_size)
        caves.extend(gap_caves)

        # 3. Find caves in allocated but unused regions
        unused_caves = self._find_unused_region_caves(min_size, max_size)
        caves.extend(unused_caves)

        # 4. Find padding between functions
        padding_caves = self._find_padding_caves(min_size, max_size)
        caves.extend(padding_caves)

        # Sort by size and accessibility
        caves.sort(key=lambda x: (x["score"], x["size"]), reverse=True)

        logger.info(f"Found {len(caves)} code caves suitable for injection")
        return caves

    def _find_section_slack_caves(self, min_size: int, max_size: int) -> list[dict[str, Any]]:
        """Find caves in PE section slack space."""
        caves = []

        try:
            modules = self.enumerate_modules()

            for module in modules:
                module_base = module["base"]

                # Read PE headers
                pe_header = self.read_memory(module_base, 0x1000)
                if not pe_header or pe_header[:2] != b"MZ":
                    continue

                # Get PE header offset
                e_lfanew = struct.unpack("<I", pe_header[0x3C:0x40])[0]

                if e_lfanew > 0x800:  # Sanity check
                    continue

                # Check PE signature
                if pe_header[e_lfanew : e_lfanew + 4] != b"PE\x00\x00":
                    continue

                # Get number of sections
                num_sections = struct.unpack("<H", pe_header[e_lfanew + 6 : e_lfanew + 8])[0]
                optional_header_size = struct.unpack(
                    "<H", pe_header[e_lfanew + 20 : e_lfanew + 22]
                )[0]

                # Section headers start after optional header
                section_header_offset = e_lfanew + 24 + optional_header_size

                for i in range(num_sections):
                    section_offset = section_header_offset + (i * 40)

                    if section_offset + 40 > len(pe_header):
                        break

                    # Parse section header
                    section_data = pe_header[section_offset : section_offset + 40]

                    virtual_size = struct.unpack("<I", section_data[8:12])[0]
                    virtual_address = struct.unpack("<I", section_data[12:16])[0]
                    size_of_raw_data = struct.unpack("<I", section_data[16:20])[0]
                    characteristics = struct.unpack("<I", section_data[36:40])[0]

                    # Calculate slack space
                    if size_of_raw_data > virtual_size:
                        slack_start = module_base + virtual_address + virtual_size
                        slack_size = size_of_raw_data - virtual_size

                        if min_size <= slack_size <= max_size:
                            # Check if section is executable
                            is_executable = bool(characteristics & 0x20000000)

                            if slack_data := self.read_memory(
                                slack_start, min(slack_size, 32)
                            ):
                                # Count null/padding bytes
                                null_count = sum(bool(b in [0x00, 0xCC, 0x90])
                                             for b in slack_data)
                                padding_ratio = null_count / len(slack_data)

                                if padding_ratio > 0.8:  # 80% padding
                                    caves.append(
                                        {
                                            "address": slack_start,
                                            "size": slack_size,
                                            "type": "section_slack",
                                            "module": module["path"],
                                            "is_executable": is_executable,
                                            "score": 10 if is_executable else 5,
                                            "characteristics": f"0x{characteristics:08X}",
                                        },
                                    )

        except Exception as e:
            logger.error(f"Error finding section slack caves: {e}")

        return caves

    def _find_memory_gap_caves(self, min_size: int, max_size: int) -> list[dict[str, Any]]:
        """Find caves in memory gaps between regions."""
        caves = []
        gaps = self.analyze_memory_gaps()

        for gap in gaps:
            if min_size <= gap["size"] <= max_size:
                # Score based on surrounding regions
                score = 5

                # Higher score if between executable regions
                if (
                    "EXECUTE" in gap["before_region"]["protection"]
                    or "EXECUTE" in gap["after_region"]["protection"]
                ):
                    score += 3

                # Higher score if moderate size
                if 0x100 <= gap["size"] <= 0x1000:
                    score += 2

                caves.append(
                    {
                        "address": gap["start_address"],
                        "size": gap["size"],
                        "type": "memory_gap",
                        "is_executable": False,  # Would need allocation
                        "score": score,
                        "before_region": gap["before_region"]["type"],
                        "after_region": gap["after_region"]["type"],
                    },
                )

        return caves

    def _find_unused_region_caves(self, min_size: int, max_size: int) -> list[dict[str, Any]]:
        """Find caves in allocated but unused memory regions."""
        caves = []
        vad_entries = self.walk_vad_tree()

        for entry in vad_entries:
            # Look for committed, writable regions
            if entry["state"] == "COMMIT" and entry["is_writable"]:
                # Sample the region to check for unused space
                region_addr = ctypes.cast(entry["base_address"], ctypes.c_ulong).value
                region_size = min(entry["region_size"], 0x10000)  # Limit scan size

                try:
                    memory = self.read_memory(region_addr, region_size)
                    if not memory:
                        continue

                    # Find contiguous null/padding sequences
                    cave_start = None
                    cave_size = 0

                    for i, byte in enumerate(memory):
                        if byte in [0x00, 0xCC]:  # Null or INT3 padding
                            if cave_start is None:
                                cave_start = i
                                cave_size = 1
                            else:
                                cave_size += 1
                        else:
                            if cave_start is not None and min_size <= cave_size <= max_size:
                                caves.append(
                                    {
                                        "address": region_addr + cave_start,
                                        "size": cave_size,
                                        "type": "unused_region",
                                        "is_executable": entry["is_executable"],
                                        "score": 7 if entry["is_executable"] else 4,
                                        "region_protection": entry["protection"],
                                    },
                                )
                            cave_start = None
                            cave_size = 0

                    # Check last cave
                    if cave_start is not None and min_size <= cave_size <= max_size:
                        caves.append(
                            {
                                "address": region_addr + cave_start,
                                "size": cave_size,
                                "type": "unused_region",
                                "is_executable": entry["is_executable"],
                                "score": 7 if entry["is_executable"] else 4,
                                "region_protection": entry["protection"],
                            },
                        )

                except Exception as e:
                    logger.debug(f"Cave identification failed: {e}")

        return caves

    def _find_padding_caves(self, min_size: int, max_size: int) -> list[dict[str, Any]]:
        """Find caves in padding between functions."""
        caves = []

        try:
            # Look for common padding patterns in executable regions
            executable_regions = self.enumerate_executable_regions()

            for region in executable_regions:
                if region["type"] != "IMAGE":
                    continue

                region_addr = ctypes.cast(region["base_address"], ctypes.c_ulong).value
                region_size = min(region["region_size"], 0x100000)

                memory = self.read_memory(region_addr, region_size)
                if not memory:
                    continue

                # Common function padding patterns
                padding_patterns = [
                    b"\xcc" * 8,  # INT3 padding
                    b"\x90" * 8,  # NOP padding
                    b"\x00" * 8,  # NULL padding
                    b"\x0f\x1f\x44\x00\x00",  # Multi-byte NOP
                    b"\x0f\x1f\x40\x00",  # Multi-byte NOP
                    b"\x0f\x1f\x00",  # Multi-byte NOP
                ]

                for pattern in padding_patterns:
                    offset = 0
                    while True:
                        index = memory.find(pattern, offset)
                        if index == -1:
                            break

                        # Measure the full extent of padding
                        padding_byte = memory[index]
                        padding_end = index

                        while padding_end < len(memory) and memory[padding_end] == padding_byte:
                            padding_end += 1

                        padding_size = padding_end - index

                        if min_size <= padding_size <= max_size:
                            # Check if this looks like inter-function padding
                            # (preceded by RET or JMP and followed by function prologue)
                            is_inter_function = False

                            if index > 0:
                                # Check for preceding RET or JMP
                                prev_byte = memory[index - 1]
                                if prev_byte in [0xC3, 0xC2, 0xE9, 0xEB]:  # RET, RETN, JMP
                                    is_inter_function = True

                            if padding_end < len(memory) - 3:
                                # Check for following function prologue
                                next_bytes = memory[padding_end : padding_end + 3]
                                if next_bytes in [
                                    b"\x55\x8b\xec",
                                    b"\x55\x89\xe5",
                                    b"\x48\x89\x5c",
                                ]:
                                    is_inter_function = True

                            caves.append(
                                {
                                    "address": region_addr + index,
                                    "size": padding_size,
                                    "type": "function_padding",
                                    "is_executable": True,
                                    "score": 9 if is_inter_function else 6,
                                    "padding_byte": f"0x{padding_byte:02X}",
                                    "is_inter_function": is_inter_function,
                                },
                            )

                        offset = padding_end

        except Exception as e:
            logger.error(f"Error finding padding caves: {e}")

        return caves

    def validate_code_cave(self, address: int, size: int) -> dict[str, Any]:
        """Validate a code cave for safety and accessibility."""
        validation = {
            "is_valid": False,
            "is_safe": False,
            "is_accessible": False,
            "issues": [],
            "score": 0,
        }

        try:
            # Check if we can read/write to the cave
            validation_data = self.read_memory(address, min(size, 16))
            if not validation_data:
                validation["issues"].append("Cannot read cave memory")
                return validation

            validation["is_accessible"] = True

            # Check if cave is empty/padding
            non_padding = sum(bool(b not in [0x00, 0x90, 0xCC])
                          for b in validation_data)
            if non_padding > len(validation_data) * 0.2:  # More than 20% non-padding
                validation["issues"].append("Cave contains non-padding data")
            else:
                validation["is_safe"] = True

            # Check protection
            mbi = MemoryBasicInformation()
            if result := kernel32.VirtualQueryEx(
                self.process_handle,
                ctypes.c_void_p(address),
                ctypes.byref(mbi),
                ctypes.sizeof(mbi),
            ):
                if mbi.Protect & 0xF0:  # Executable
                    validation["score"] += 5
                if mbi.Protect & 0xCC:  # Writable
                    validation["score"] += 3
                if mbi.Type == 0x1000000:  # IMAGE
                    validation["score"] += 2

                if mbi.RegionSize < size:
                    validation["issues"].append("Cave crosses region boundary")
                    validation["is_safe"] = False

            # Final validation
            validation["is_valid"] = validation["is_accessible"] and validation["is_safe"]

            if validation["is_valid"]:
                validation["score"] = max(1, validation["score"])

        except Exception as e:
            validation["issues"].append(f"Validation error: {e}")

        return validation

    def select_optimal_cave(
        self, caves: list[dict[str, Any]], required_size: int
    ) -> dict[str, Any] | None:
        """Select the most suitable code cave for injection."""
        suitable_caves = []

        for cave in caves:
            if cave["size"] >= required_size:
                # Validate the cave
                validation = self.validate_code_cave(cave["address"], cave["size"])

                if validation["is_valid"]:
                    cave_score = cave["score"] + validation["score"]

                    # Prefer caves that don't need size adjustment
                    if cave["size"] < required_size * 2:
                        cave_score += 2

                    suitable_caves.append(
                        {**cave, "final_score": cave_score, "validation": validation}
                    )

        if not suitable_caves:
            return None

        # Select cave with highest score
        best_cave = max(suitable_caves, key=lambda x: x["final_score"])

        logger.info(
            f"Selected optimal cave at 0x{best_cave['address']:X}, size: 0x{best_cave['size']:X}, score: {best_cave['final_score']}",
        )

        return best_cave

    def generate_polymorphic_nops(self, length: int, arch: str = "x86") -> bytes:
        """Generate polymorphic NOP sled with varying instructions."""
        import random

        if length <= 0:
            return b""

        nop_sled = bytearray()

        if arch == "x86":
            # x86 NOP variations
            nop_variants = [
                (b"\x90", 1),  # NOP
                (b"\x87\xc0", 2),  # XCHG EAX,EAX
                (b"\x87\xdb", 2),  # XCHG EBX,EBX
                (b"\x87\xc9", 2),  # XCHG ECX,ECX
                (b"\x87\xd2", 2),  # XCHG EDX,EDX
                (b"\x8b\xc0", 2),  # MOV EAX,EAX
                (b"\x8b\xdb", 2),  # MOV EBX,EBX
                (b"\x8b\xc9", 2),  # MOV ECX,ECX
                (b"\x8b\xd2", 2),  # MOV EDX,EDX
                (b"\x66\x90", 2),  # 66 NOP (2-byte NOP)
                (b"\x0f\x1f\x00", 3),  # NOP DWORD PTR [EAX]
                (b"\x0f\x1f\x40\x00", 4),  # NOP DWORD PTR [EAX+0]
                (b"\x0f\x1f\x44\x00\x00", 5),  # NOP DWORD PTR [EAX+EAX+0]
                (b"\x66\x0f\x1f\x44\x00\x00", 6),  # NOP WORD PTR [EAX+EAX+0]
                (b"\x0f\x1f\x80\x00\x00\x00\x00", 7),  # NOP DWORD PTR [EAX+00000000]
                (b"\x0f\x1f\x84\x00\x00\x00\x00\x00", 8),  # NOP DWORD PTR [EAX+EAX+00000000]
                (b"\x66\x0f\x1f\x84\x00\x00\x00\x00\x00", 9),  # NOP WORD PTR [EAX+EAX+00000000]
                (b"\x8d\x04\x20", 3),  # LEA EAX,[EAX]
                (b"\x8d\x1c\x23", 3),  # LEA EBX,[EBX]
                (b"\x8d\x0c\x21", 3),  # LEA ECX,[ECX]
                (b"\x8d\x14\x22", 3),  # LEA EDX,[EDX]
                (b"\x8d\x40\x00", 3),  # LEA EAX,[EAX+0]
                (b"\x8d\x49\x00", 3),  # LEA ECX,[ECX+0]
                (b"\x8d\x52\x00", 3),  # LEA EDX,[EDX+0]
                (b"\x8d\x5b\x00", 3),  # LEA EBX,[EBX+0]
                (b"\x8d\x80\x00\x00\x00\x00", 6),  # LEA EAX,[EAX+00000000]
                (b"\x8d\x89\x00\x00\x00\x00", 6),  # LEA ECX,[ECX+00000000]
                (b"\x25\xff\xff\xff\xff", 5),  # AND EAX,FFFFFFFF
                (b"\x81\xe1\xff\xff\xff\xff", 6),  # AND ECX,FFFFFFFF
                (b"\x0d\x00\x00\x00\x00", 5),  # OR EAX,00000000
                (b"\x81\xc9\x00\x00\x00\x00", 6),  # OR ECX,00000000
                (b"\x35\x00\x00\x00\x00", 5),  # XOR EAX,00000000
                (b"\x81\xf1\x00\x00\x00\x00", 6),  # XOR ECX,00000000
                (b"\x05\x00\x00\x00\x00", 5),  # ADD EAX,00000000
                (b"\x81\xc1\x00\x00\x00\x00", 6),  # ADD ECX,00000000
                (b"\x2d\x00\x00\x00\x00", 5),  # SUB EAX,00000000
                (b"\x81\xe9\x00\x00\x00\x00", 6),  # SUB ECX,00000000
            ]

        elif arch == "x64":
            # x64 NOP variations
            nop_variants = [
                (b"\x90", 1),  # NOP
                (b"\x48\x87\xc0", 3),  # XCHG RAX,RAX
                (b"\x48\x87\xdb", 3),  # XCHG RBX,RBX
                (b"\x48\x87\xc9", 3),  # XCHG RCX,RCX
                (b"\x48\x87\xd2", 3),  # XCHG RDX,RDX
                (b"\x48\x8b\xc0", 3),  # MOV RAX,RAX
                (b"\x48\x8b\xdb", 3),  # MOV RBX,RBX
                (b"\x48\x8b\xc9", 3),  # MOV RCX,RCX
                (b"\x48\x8b\xd2", 3),  # MOV RDX,RDX
                (b"\x66\x90", 2),  # 66 NOP
                (b"\x0f\x1f\x00", 3),  # NOP DWORD PTR [RAX]
                (b"\x0f\x1f\x40\x00", 4),  # NOP DWORD PTR [RAX+0]
                (b"\x0f\x1f\x44\x00\x00", 5),  # NOP DWORD PTR [RAX+RAX+0]
                (b"\x66\x0f\x1f\x44\x00\x00", 6),  # NOP WORD PTR [RAX+RAX+0]
                (b"\x0f\x1f\x80\x00\x00\x00\x00", 7),  # NOP DWORD PTR [RAX+00000000]
                (b"\x0f\x1f\x84\x00\x00\x00\x00\x00", 8),  # NOP DWORD PTR [RAX+RAX+00000000]
                (b"\x66\x0f\x1f\x84\x00\x00\x00\x00\x00", 9),  # NOP WORD PTR [RAX+RAX+00000000]
                (b"\x48\x8d\x04\x20", 4),  # LEA RAX,[RAX]
                (b"\x48\x8d\x1c\x23", 4),  # LEA RBX,[RBX]
                (b"\x48\x8d\x0c\x21", 4),  # LEA RCX,[RCX]
                (b"\x48\x8d\x14\x22", 4),  # LEA RDX,[RDX]
                (b"\x48\x8d\x40\x00", 4),  # LEA RAX,[RAX+0]
                (b"\x48\x8d\x49\x00", 4),  # LEA RCX,[RCX+0]
                (b"\x48\x8d\x52\x00", 4),  # LEA RDX,[RDX+0]
                (b"\x48\x8d\x5b\x00", 4),  # LEA RBX,[RBX+0]
                (b"\x48\x8d\x80\x00\x00\x00\x00", 7),  # LEA RAX,[RAX+00000000]
                (b"\x48\x25\xff\xff\xff\xff", 6),  # AND RAX,FFFFFFFF
                (b"\x48\x81\xe1\xff\xff\xff\xff", 7),  # AND RCX,FFFFFFFF
                (b"\x48\x0d\x00\x00\x00\x00", 6),  # OR RAX,00000000
                (b"\x48\x81\xc9\x00\x00\x00\x00", 7),  # OR RCX,00000000
                (b"\x48\x35\x00\x00\x00\x00", 6),  # XOR RAX,00000000
                (b"\x48\x81\xf1\x00\x00\x00\x00", 7),  # XOR RCX,00000000
                (b"\x48\x05\x00\x00\x00\x00", 6),  # ADD RAX,00000000
                (b"\x48\x81\xc1\x00\x00\x00\x00", 7),  # ADD RCX,00000000
                (b"\x48\x2d\x00\x00\x00\x00", 6),  # SUB RAX,00000000
                (b"\x48\x81\xe9\x00\x00\x00\x00", 7),  # SUB RCX,00000000
                (b"\x40\x90", 2),  # REX.B NOP
                (b"\x41\x90", 2),  # REX.B NOP
                (b"\x42\x90", 2),  # REX.X NOP
                (b"\x43\x90", 2),  # REX.XB NOP
                (b"\x44\x90", 2),  # REX.R NOP
                (b"\x45\x90", 2),  # REX.RB NOP
                (b"\x46\x90", 2),  # REX.RX NOP
                (b"\x47\x90", 2),  # REX.RXB NOP
            ]
        else:
            # Default to simple NOPs
            return b"\x90" * length

        # Build NOP sled with random variations
        while len(nop_sled) < length:
            remaining = length - len(nop_sled)

            # Filter variants that fit in remaining space
            fitting_variants = [(nop, size) for nop, size in nop_variants if size <= remaining]

            if not fitting_variants:
                # Fill remaining with single NOPs
                nop_sled.extend(b"\x90" * remaining)
                break

        # Randomly select a NOP variant
        # Note: Using random module for generating NOP sleds, not cryptographic purposes
        if random.random() < 0.7:  # noqa: S311  # 70% chance of using diverse NOPs
            # Prefer longer NOPs for better diversity
            weights = [size for _, size in fitting_variants]
            # Note: Using random module for generating NOP sleds, not cryptographic purposes
            chosen_nop, _ = random.choices(fitting_variants, weights=weights)[0]  # noqa: S311
        else:
            # Use simple NOP occasionally
            # Note: Using random module for generating NOP sleds, not cryptographic purposes
            chosen_nop, _ = random.choice(fitting_variants)  # noqa: S311

        nop_sled.extend(chosen_nop)

        # Ensure exact length (trim if necessary)
        return bytes(nop_sled[:length])

    def generate_semantic_nops(self, length: int, preserve_registers: bool = True) -> bytes:
        """Generate semantic NOPs that perform no-effect operations."""
        import random

        if length <= 0:
            return b""

        semantic_sled = bytearray()

        # Semantic NOP patterns (operations that cancel out)
        semantic_patterns = [
            # Push/Pop pairs (preserve registers)
            (b"\x50\x58", 2, "PUSH EAX; POP EAX"),
            (b"\x51\x59", 2, "PUSH ECX; POP ECX"),
            (b"\x52\x5a", 2, "PUSH EDX; POP EDX"),
            (b"\x53\x5b", 2, "PUSH EBX; POP EBX"),
            # Increment/Decrement pairs
            (b"\x40\x48", 2, "INC EAX; DEC EAX"),
            (b"\x41\x49", 2, "INC ECX; DEC ECX"),
            (b"\x42\x4a", 2, "INC EDX; DEC EDX"),
            (b"\x43\x4b", 2, "INC EBX; DEC EBX"),
            # Add/Sub cancellation
            (b"\x83\xc0\x01\x83\xe8\x01", 5, "ADD EAX,1; SUB EAX,1"),
            (b"\x83\xc1\x01\x83\xe9\x01", 5, "ADD ECX,1; SUB ECX,1"),
            (b"\x83\xc2\x01\x83\xea\x01", 5, "ADD EDX,1; SUB EDX,1"),
            # XOR twice (restore original value)
            (b"\x34\x42\x34\x42", 4, "XOR AL,42h; XOR AL,42h"),
            (
                b"\x35\x12\x34\x56\x78\x35\x12\x34\x56\x78",
                10,
                "XOR EAX,12345678h; XOR EAX,12345678h",
            ),
            # ROL/ROR pairs
            (b"\xd0\xc0\xd0\xc8", 4, "ROL AL,1; ROR AL,1"),
            (b"\xd0\xc1\xd0\xc9", 4, "ROL CL,1; ROR CL,1"),
            # NEG twice
            (b"\xf6\xd8\xf6\xd8", 4, "NEG AL; NEG AL"),
            (b"\xf7\xd8\xf7\xd8", 4, "NEG EAX; NEG EAX"),
            # NOT twice
            (b"\xf6\xd0\xf6\xd0", 4, "NOT AL; NOT AL"),
            (b"\xf7\xd0\xf7\xd0", 4, "NOT EAX; NOT EAX"),
        ]

        if not preserve_registers:
            # Add patterns that modify registers
            semantic_patterns.extend(
                [
                    (b"\x31\xc0", 2, "XOR EAX,EAX"),
                    (b"\x31\xc9", 2, "XOR ECX,ECX"),
                    (b"\x31\xd2", 2, "XOR EDX,EDX"),
                    (b"\x31\xdb", 2, "XOR EBX,EBX"),
                    (b"\xb8\x00\x00\x00\x00", 5, "MOV EAX,0"),
                    (b"\xb9\x00\x00\x00\x00", 5, "MOV ECX,0"),
                    (b"\xba\x00\x00\x00\x00", 5, "MOV EDX,0"),
                ],
            )

        while len(semantic_sled) < length:
            remaining = length - len(semantic_sled)

            # Filter patterns that fit
            fitting_patterns = [
                (pattern, size, desc)
                for pattern, size, desc in semantic_patterns
                if size <= remaining
            ]

            if not fitting_patterns:
                # Fill with simple NOPs
                semantic_sled.extend(b"\x90" * remaining)
                break

            # Choose random semantic pattern
            # Note: Using random module for generating semantic patterns, not cryptographic purposes
            pattern, _size, _desc = random.choice(fitting_patterns)  # noqa: S311
            semantic_sled.extend(pattern)

        return bytes(semantic_sled[:length])

    def generate_antidisassembly_nops(self, length: int) -> bytes:
        """Generate NOPs with anti-disassembly tricks."""
        if length <= 0:
            return b""

        anti_sled = bytearray()

        # Anti-disassembly patterns
        anti_patterns = [
            # Overlapping instructions
            (b"\xeb\x02\x90\x90", 4),  # JMP +2; NOPs (confuses linear disassembly)
            (b"\xeb\x01\x90\x90", 3),  # JMP +1; NOP (jump into middle)
            (b"\xe8\xff\xff\xff\xff\x58", 6),  # CALL $+5; POP EAX (gets EIP)
            (b"\xeb\x00", 2),  # JMP $+2 (null jump)
            # Conditional jumps that always/never execute
            (b"\x74\x01\x75", 3),  # JZ +1; JNZ (one will always execute)
            (b"\x72\x02\x90\x90", 4),  # JB +2; NOPs
            (b"\x73\x02\x90\x90", 4),  # JNC +2; NOPs
            # Garbage bytes between valid instructions
            (b"\x90\xf1\x90", 3),  # NOP; ICEBP; NOP
            (b"\x90\xf4\x90", 3),  # NOP; HLT; NOP (if skipped)
            # Multi-byte NOPs that look like other instructions
            (b"\x0f\x0b", 2),  # UD2 (undefined instruction if not handled)
            (b"\x0f\x05", 2),  # SYSCALL (on x64, harmless on x86)
        ]

        while len(anti_sled) < length:
            remaining = length - len(anti_sled)

            if remaining >= 4:
                # Use anti-disassembly pattern
                # Not used for cryptographic purposes, just to add variety to anti-disasm patterns
                pattern, _size = random.choice([p for p in anti_patterns if p[1] <= remaining])  # noqa: S311
                anti_sled.extend(pattern)
            else:
                # Fill with simple NOPs
                anti_sled.extend(b"\x90" * remaining)

        return bytes(anti_sled[:length])

    def create_randomized_nop_sled(self, length: int, techniques: list[str] = None) -> bytes:
        """Create a highly randomized NOP sled using multiple techniques."""
        if length <= 0:
            return b""

        if techniques is None:
            techniques = ["polymorphic", "semantic", "anti_disassembly"]

        import random

        # Detect architecture
        arch = "x64" if ctypes.sizeof(ctypes.c_voidp) == 8 else "x86"

        # Build sled using mixed techniques
        sled = bytearray()
        remaining = length

        while remaining > 0:
            # Choose technique for this segment
            # Note: Using random module for generating polymorphic code, not cryptographic purposes
            technique = random.choice(techniques)  # noqa: S311

            # Determine segment size (variable for more randomness)
            # Note: Using random module for generating polymorphic code, not cryptographic purposes
            segment_size = min(remaining, random.randint(4, min(32, remaining)))  # noqa: S311

            if technique == "polymorphic":
                segment = self.generate_polymorphic_nops(segment_size, arch)
            elif technique == "semantic":
                segment = self.generate_semantic_nops(segment_size, preserve_registers=True)
            elif technique == "anti_disassembly":
                segment = self.generate_antidisassembly_nops(segment_size)
            else:
                segment = b"\x90" * segment_size

            sled.extend(segment)
            remaining -= len(segment)

        # Ensure exact length
        result = bytes(sled[:length])

        logger.info(f"Generated {length}-byte randomized NOP sled using techniques: {techniques}")
        return result

    def patch_bytes(self, address: int, new_bytes: bytes) -> bool:
        """Patch bytes at specified address."""
        return self.write_memory(address, new_bytes)

    def find_conditional_jumps(self, start_addr: int, size: int = 0x1000) -> list[dict[str, Any]]:
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
                mnemonic, _offset_size = jump_opcodes[memory[i]]
                target_offset = struct.unpack("b", memory[i + 1 : i + 2])[0]
                jump_target = start_addr + i + 2 + target_offset

                jumps.append(
                    {
                        "address": start_addr + i,
                        "opcode": memory[i],
                        "mnemonic": mnemonic,
                        "target": jump_target,
                        "size": 2,
                    }
                )

            elif i < len(memory) - 6 and memory[i] == 0x0F:
                if 0x80 <= memory[i + 1] <= 0x8F:
                    mnemonic = [
                        "JO",
                        "JNO",
                        "JB",
                        "JAE",
                        "JE",
                        "JNE",
                        "JBE",
                        "JA",
                        "JS",
                        "JNS",
                        "JP",
                        "JNP",
                        "JL",
                        "JGE",
                        "JLE",
                        "JG",
                    ][memory[i + 1] - 0x80]
                    target_offset = struct.unpack("<i", memory[i + 2 : i + 6])[0]
                    jump_target = start_addr + i + 6 + target_offset

                    jumps.append(
                        {
                            "address": start_addr + i,
                            "opcode": (memory[i] << 8) | memory[i + 1],
                            "mnemonic": mnemonic,
                            "target": jump_target,
                            "size": 6,
                        },
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

    def manipulate_registry(
        self, key_path: str, value_name: str, new_value: str | int | bytes
    ) -> bool:
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
            self.kernel32.WriteProcessMemory(
                self.process_handle,
                remote_buffer,
                dll_path_bytes,
                dll_path_size,
                ctypes.byref(bytes_written),
            )

            kernel32_handle = self.kernel32.GetModuleHandleA(b"kernel32.dll")
            loadlibrary_addr = self.kernel32.GetProcAddress(kernel32_handle, b"LoadLibraryA")

            if thread_handle := self.kernel32.CreateRemoteThread(
                self.process_handle,
                None,
                0,
                loadlibrary_addr,
                remote_buffer,
                0,
                None,
            ):
                self.kernel32.WaitForSingleObject(thread_handle, 0xFFFFFFFF)
                self.kernel32.CloseHandle(thread_handle)
                logger.info(f"Successfully injected DLL: {dll_path}")
                return True

        except Exception as e:
            logger.error(f"DLL injection failed: {e}")

        return False

    def hook_api(self, module_name: str, function_name: str, hook_address: int) -> bool:
        """Install hook for Windows API function."""
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

    def detect_protection(self) -> str | None:
        """Detect protection scheme used by target."""
        if not self.process_handle:
            return None

        for protection_name, signatures in self.protection_signatures.items():
            for signature in signatures:
                if self.scan_pattern(signature):
                    logger.info(f"Detected protection: {protection_name}")
                    return protection_name

        return None

    def read_process_memory(self, address: int, size: int) -> bytes | None:
        """Alias for read_memory for compatibility."""
        return self.read_memory(address, size)

    def write_process_memory(self, address: int, data: bytes) -> bool:
        """Alias for write_memory for compatibility."""
        return self.write_memory(address, data)

    def get_module_base(self, module_name: str) -> int | None:
        """Get base address of loaded module."""
        if not self.pid:
            return None

        try:
            process = psutil.Process(self.pid)
            for dll in process.memory_maps():
                if module_name.lower() in dll.path.lower():
                    return dll.addr
        except Exception as e:
            logger.debug(f"Module base address lookup failed: {e}")

        return None

    def enumerate_processes(self) -> list[dict[str, Any]]:
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
                    },
                )
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue

        return processes

    def enumerate_modules(self, pid: int | None = None) -> list[dict[str, Any]]:
        """Enumerate loaded modules in process."""
        target_pid = pid or self.pid
        if not target_pid:
            return []

        modules = []

        try:
            process = psutil.Process(target_pid)
            modules.extend(
                {"base": dll.addr, "size": dll.size, "path": dll.path}
                for dll in process.memory_maps()
            )
        except Exception as e:
            logger.error(f"Module enumeration failed: {e}")

        return modules

    def _compile_pattern(self, pattern_hex: str) -> bytes:
        """Compile hex string pattern to bytes.

        Args:
            pattern_hex: Hex string pattern (e.g., "48 8B 05" or "488B05")

        Returns:
            Compiled bytes pattern

        """
        # Remove spaces and convert to bytes
        pattern_hex = pattern_hex.replace(" ", "").replace("??", "00")
        try:
            return bytes.fromhex(pattern_hex)
        except ValueError as e:
            logger.error(f"Invalid hex pattern: {e}")
            return b""

    def allocate_memory(self, size: int, protection: int = 0x40) -> int:
        """Allocate memory in the target process.

        Args:
            size: Size of memory to allocate
            protection: Memory protection flags (default PAGE_EXECUTE_READWRITE)

        Returns:
            Address of allocated memory or 0 on failure

        """
        if not self.process_handle:
            return 0

        MEM_COMMIT = 0x1000
        MEM_RESERVE = 0x2000

        address = kernel32.VirtualAllocEx(
            self.process_handle, None, size, MEM_RESERVE | MEM_COMMIT, protection
        )

        if address:
            logger.info(f"Allocated {size} bytes at 0x{address:X}")
        else:
            logger.error(f"Failed to allocate memory: {ctypes.get_last_error()}")

        return address

    def protect_memory(self, address: int, size: int, protection: int) -> bool:
        """Change memory protection flags.

        Args:
            address: Memory address
            size: Size of region
            protection: New protection flags

        Returns:
            True if successful

        """
        if not self.process_handle:
            return False

        old_protect = ctypes.wintypes.DWORD()
        success = kernel32.VirtualProtectEx(
            self.process_handle,
            ctypes.c_void_p(address),
            size,
            protection,
            ctypes.byref(old_protect),
        )

        if success:
            logger.info(
                f"Changed protection at 0x{address:X} from 0x{old_protect.value:X} to 0x{protection:X}"
            )
        else:
            logger.error(f"Failed to change protection: {ctypes.get_last_error()}")

        return bool(success)

    def query_memory(self, address: int) -> dict[str, Any]:
        """Query memory information at specific address.

        Args:
            address: Memory address to query

        Returns:
            Dictionary with memory region information

        """
        if not self.process_handle:
            return {}

        class MEMORY_BASIC_INFORMATION(ctypes.Structure):  # noqa: N801
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
        if result := kernel32.VirtualQueryEx(
            self.process_handle,
            ctypes.c_void_p(address),
            ctypes.byref(mbi),
            ctypes.sizeof(mbi),
        ):
            return {
                "base_address": mbi.BaseAddress,
                "allocation_base": mbi.AllocationBase,
                "allocation_protect": mbi.AllocationProtect,
                "size": mbi.RegionSize,
                "state": mbi.State,
                "protection": mbi.Protect,
                "type": mbi.Type,
            }
        logger.error(f"Failed to query memory at 0x{address:X}")
        return {}

    def enumerate_regions(self) -> list[dict[str, Any]]:
        """Enumerate all memory regions in the process.

        Returns:
            List of memory region information dictionaries

        """
        if not self.process_handle:
            return []

        regions = []
        address = 0
        max_address = 0x7FFFFFFFFFFFFFFF if ctypes.sizeof(ctypes.c_voidp) == 8 else 0x7FFFFFFF

        while address < max_address:
            info = self.query_memory(address)
            if not info:
                break

            if info["state"] == 0x1000:  # MEM_COMMIT
                regions.append(
                    {
                        "base_address": info["base_address"],
                        "size": info["size"],
                        "protection": info["protection"],
                        "type": info["type"],
                        "state": "committed",
                        "is_executable": bool(info["protection"] & 0xF0),  # Any execute permission
                        "is_writable": bool(info["protection"] & 0x0C),  # Write or copy-on-write
                        "is_readable": bool(info["protection"] & 0x06),  # Read or execute_read
                    },
                )

            # Move to next region
            if info.get("size", 0) > 0:
                address = info["base_address"] + info["size"]
            else:
                address += 0x1000  # Move by page size if query failed

        logger.info(f"Enumerated {len(regions)} memory regions")
        return regions

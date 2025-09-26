"""License Validation Debugging Engine for Intellicrack.

This module provides comprehensive debugging capabilities specifically designed
for analyzing and defeating software license validation mechanisms.

Copyright (C) 2025 Zachary Flint
Licensed under GNU GPL v3.0
"""

import ctypes
import ctypes.wintypes as wintypes
import struct
import threading
from dataclasses import dataclass
from enum import IntEnum
from typing import Any, Callable, Dict, List, Optional, Tuple

from ..utils.logger import get_logger

logger = get_logger(__name__)


class DebugEvent(IntEnum):
    """Debug event types for Windows debugging."""

    EXCEPTION_DEBUG_EVENT = 1
    CREATE_THREAD_DEBUG_EVENT = 2
    CREATE_PROCESS_DEBUG_EVENT = 3
    EXIT_THREAD_DEBUG_EVENT = 4
    EXIT_PROCESS_DEBUG_EVENT = 5
    LOAD_DLL_DEBUG_EVENT = 6
    UNLOAD_DLL_DEBUG_EVENT = 7
    OUTPUT_DEBUG_STRING_EVENT = 8
    RIP_EVENT = 9


class ExceptionCode(IntEnum):
    """Windows exception codes relevant to debugging."""

    EXCEPTION_ACCESS_VIOLATION = 0xC0000005
    EXCEPTION_BREAKPOINT = 0x80000003
    EXCEPTION_SINGLE_STEP = 0x80000004
    EXCEPTION_INT_DIVIDE_BY_ZERO = 0xC0000094
    EXCEPTION_ILLEGAL_INSTRUCTION = 0xC000001D
    EXCEPTION_PRIV_INSTRUCTION = 0xC0000096
    EXCEPTION_GUARD_PAGE = 0x80000001


@dataclass
class Breakpoint:
    """Represents a debugging breakpoint."""

    address: int
    original_byte: bytes
    enabled: bool
    hit_count: int
    callback: Optional[Callable] = None
    condition: Optional[str] = None
    description: str = ""


class LicenseDebugger:
    """Advanced debugging engine for license validation analysis."""

    # Windows debugging constants
    DEBUG_PROCESS = 0x00000001
    DEBUG_ONLY_THIS_PROCESS = 0x00000002
    CREATE_SUSPENDED = 0x00000004
    PROCESS_ALL_ACCESS = 0x001F0FFF
    THREAD_ALL_ACCESS = 0x001F03FF
    DBG_CONTINUE = 0x00010002
    DBG_EXCEPTION_NOT_HANDLED = 0x80010001
    INFINITE = 0xFFFFFFFF

    # x86/x64 breakpoint instruction
    INT3_INSTRUCTION = b"\xcc"

    def __init__(self):
        """Initialize the license debugging engine."""
        self.kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        self.process_handle = None
        self.thread_handles = {}
        self.breakpoints = {}
        self.memory_breakpoints = {}
        self.hardware_breakpoints = {}
        self.license_patterns = self._init_license_patterns()
        self.api_hooks = {}
        self.debugging = False
        self.debug_thread = None
        self.process_id = None
        self.main_thread_id = None
        self.modules = {}
        self.license_check_addresses = []

    def _init_license_patterns(self) -> List[bytes]:
        """Initialize common license validation patterns."""
        return [
            # Common license check patterns
            b"\x84\xc0\x74",  # TEST AL, AL; JZ (failed check)
            b"\x84\xc0\x75",  # TEST AL, AL; JNZ (successful check)
            b"\x85\xc0\x74",  # TEST EAX, EAX; JZ
            b"\x85\xc0\x75",  # TEST EAX, EAX; JNZ
            b"\x83\xf8\x00\x74",  # CMP EAX, 0; JZ
            b"\x83\xf8\x01\x74",  # CMP EAX, 1; JZ
            b"\x3d\x00\x00\x00\x00\x74",  # CMP EAX, 0; JZ (long form)
            b"\xff\x15",  # CALL [address] - indirect call
            b"\xe8",  # CALL relative - direct call
            # Registry access patterns for license
            b"RegOpenKey",
            b"RegQueryValue",
            b"SOFTWARE\\Licenses",
            # Time check patterns (trial period)
            b"GetSystemTime",
            b"GetLocalTime",
            b"GetTickCount",
            # Hardware ID patterns
            b"GetVolumeInformation",
            b"GetAdaptersInfo",
        ]

    def attach_to_process(self, process_id: int) -> bool:
        """Attach debugger to a running process for license analysis."""
        try:
            # Enable debug privilege
            if not self._enable_debug_privilege():
                logger.error("Failed to enable debug privilege")
                return False

            # Attach to process
            if not self.kernel32.DebugActiveProcess(process_id):
                error = ctypes.get_last_error()
                logger.error(f"Failed to attach to process {process_id}: {error}")
                return False

            self.process_id = process_id
            self.process_handle = self.kernel32.OpenProcess(self.PROCESS_ALL_ACCESS, False, process_id)

            if not self.process_handle:
                logger.error("Failed to get process handle")
                return False

            logger.info(f"Successfully attached to process {process_id}")

            # Start debugging loop in separate thread
            self.debugging = True
            self.debug_thread = threading.Thread(target=self._debug_loop, daemon=True)
            self.debug_thread.start()

            return True

        except Exception as e:
            logger.error(f"Error attaching to process: {e}")
            return False

    def _enable_debug_privilege(self) -> bool:
        """Enable SeDebugPrivilege for process debugging."""
        try:
            import win32api
            import win32security

            # Get current process token
            token = win32security.OpenProcessToken(
                win32api.GetCurrentProcess(), win32security.TOKEN_ADJUST_PRIVILEGES | win32security.TOKEN_QUERY
            )

            # Lookup debug privilege
            privilege = win32security.LookupPrivilegeValue(None, "SeDebugPrivilege")

            # Enable the privilege
            win32security.AdjustTokenPrivileges(token, False, [(privilege, win32security.SE_PRIVILEGE_ENABLED)])

            return True

        except Exception as e:
            logger.error(f"Failed to enable debug privilege: {e}")
            return False

    def set_breakpoint(self, address: int, callback: Optional[Callable] = None, description: str = "") -> bool:
        """Set a software breakpoint at specified address."""
        if address in self.breakpoints:
            logger.warning(f"Breakpoint already exists at {hex(address)}")
            return True

        try:
            # Read original byte
            original_byte = self._read_memory(address, 1)
            if not original_byte:
                logger.error(f"Failed to read memory at {hex(address)}")
                return False

            # Write INT3 instruction
            if not self._write_memory(address, self.INT3_INSTRUCTION):
                logger.error(f"Failed to write breakpoint at {hex(address)}")
                return False

            # Store breakpoint info
            self.breakpoints[address] = Breakpoint(
                address=address,
                original_byte=original_byte,
                enabled=True,
                hit_count=0,
                callback=callback,
                description=description or f"Breakpoint at {hex(address)}",
            )

            logger.info(f"Set breakpoint at {hex(address)}: {description}")
            return True

        except Exception as e:
            logger.error(f"Error setting breakpoint: {e}")
            return False

    def set_hardware_breakpoint(self, address: int, dr_index: int = 0, condition: str = "execute", size: int = 1) -> bool:
        """Set hardware breakpoint using debug registers."""
        if dr_index not in range(4):
            logger.error("Invalid debug register index (must be 0-3)")
            return False

        try:
            # Get thread context
            context = self._get_thread_context(self.main_thread_id)
            if not context:
                return False

            # Set debug register
            if dr_index == 0:
                context.Dr0 = address
            elif dr_index == 1:
                context.Dr1 = address
            elif dr_index == 2:
                context.Dr2 = address
            elif dr_index == 3:
                context.Dr3 = address

            # Configure DR7 (debug control register)
            dr7_value = context.Dr7

            # Enable local breakpoint
            dr7_value |= 1 << (dr_index * 2)

            # Set condition (00=execute, 01=write, 11=read/write)
            condition_bits = 0
            if condition == "write":
                condition_bits = 1
            elif condition == "read_write":
                condition_bits = 3

            dr7_value |= condition_bits << (16 + dr_index * 4)

            # Set size (00=1byte, 01=2bytes, 11=4bytes)
            size_bits = 0
            if size == 2:
                size_bits = 1
            elif size == 4:
                size_bits = 3

            dr7_value |= size_bits << (18 + dr_index * 4)

            context.Dr7 = dr7_value

            # Set thread context
            if not self._set_thread_context(self.main_thread_id, context):
                return False

            self.hardware_breakpoints[address] = {"dr_index": dr_index, "condition": condition, "size": size}

            logger.info(f"Set hardware breakpoint at {hex(address)}")
            return True

        except Exception as e:
            logger.error(f"Error setting hardware breakpoint: {e}")
            return False

    def find_license_checks(self) -> List[int]:
        """Scan process memory for potential license check locations."""
        found_checks = []

        try:
            # Get process memory regions
            memory_regions = self._enumerate_memory_regions()

            for region in memory_regions:
                if not region["executable"]:
                    continue

                # Read memory region
                memory_data = self._read_memory(region["base"], region["size"])
                if not memory_data:
                    continue

                # Search for license patterns
                for pattern in self.license_patterns:
                    offset = 0
                    while True:
                        index = memory_data.find(pattern, offset)
                        if index == -1:
                            break

                        address = region["base"] + index
                        found_checks.append(address)
                        logger.debug(f"Found potential license check at {hex(address)}")

                        offset = index + 1

            self.license_check_addresses = found_checks
            logger.info(f"Found {len(found_checks)} potential license checks")
            return found_checks

        except Exception as e:
            logger.error(f"Error finding license checks: {e}")
            return []

    def hook_license_api(self, module_name: str, function_name: str, callback: Callable) -> bool:
        """Hook Windows API functions commonly used in licensing."""
        try:
            # Get module handle
            module = ctypes.WinDLL(module_name)

            # Get function address
            func_addr = ctypes.cast(getattr(module, function_name), ctypes.c_void_p).value

            if not func_addr:
                logger.error(f"Failed to find {function_name} in {module_name}")
                return False

            # Set breakpoint at API entry
            if self.set_breakpoint(func_addr, callback, f"API Hook: {function_name}"):
                self.api_hooks[func_addr] = {"module": module_name, "function": function_name, "callback": callback}
                logger.info(f"Hooked {module_name}!{function_name}")
                return True

            return False

        except Exception as e:
            logger.error(f"Error hooking API: {e}")
            return False

    def _debug_loop(self):
        """Main debugging event loop."""
        debug_event = DEBUG_EVENT()

        while self.debugging:
            try:
                # Wait for debug event
                if self.kernel32.WaitForDebugEvent(ctypes.byref(debug_event), 100):
                    continue_status = self.DBG_CONTINUE

                    # Handle different debug events
                    if debug_event.dwDebugEventCode == DebugEvent.EXCEPTION_DEBUG_EVENT:
                        continue_status = self._handle_exception(debug_event)

                    elif debug_event.dwDebugEventCode == DebugEvent.CREATE_PROCESS_DEBUG_EVENT:
                        self._handle_create_process(debug_event)

                    elif debug_event.dwDebugEventCode == DebugEvent.LOAD_DLL_DEBUG_EVENT:
                        self._handle_load_dll(debug_event)

                    elif debug_event.dwDebugEventCode == DebugEvent.EXIT_PROCESS_DEBUG_EVENT:
                        self.debugging = False

                    # Continue execution
                    self.kernel32.ContinueDebugEvent(debug_event.dwProcessId, debug_event.dwThreadId, continue_status)

            except Exception as e:
                logger.error(f"Error in debug loop: {e}")

    def _handle_exception(self, debug_event) -> int:
        """Handle exception debug events."""
        exception = debug_event.u.Exception
        exception_code = exception.ExceptionRecord.ExceptionCode
        exception_address = exception.ExceptionRecord.ExceptionAddress

        # Handle breakpoint exception
        if exception_code == ExceptionCode.EXCEPTION_BREAKPOINT:
            if exception_address in self.breakpoints:
                bp = self.breakpoints[exception_address]
                bp.hit_count += 1

                logger.info(f"Breakpoint hit at {hex(exception_address)}: {bp.description}")

                # Call callback if registered
                if bp.callback:
                    try:
                        bp.callback(self, debug_event)
                    except Exception as e:
                        logger.error(f"Breakpoint callback error: {e}")

                # Restore original byte and single step
                self._write_memory(exception_address, bp.original_byte)
                self._set_single_step(debug_event.dwThreadId)

                return self.DBG_CONTINUE

        # Handle single step (for breakpoint restoration)
        elif exception_code == ExceptionCode.EXCEPTION_SINGLE_STEP:
            # Restore any breakpoints that need it
            for addr, bp in self.breakpoints.items():
                if bp.enabled:
                    self._write_memory(addr, self.INT3_INSTRUCTION)

            return self.DBG_CONTINUE

        # Handle access violation (useful for finding license checks)
        elif exception_code == ExceptionCode.EXCEPTION_ACCESS_VIOLATION:
            logger.warning(f"Access violation at {hex(exception_address)}")

        return self.DBG_EXCEPTION_NOT_HANDLED

    def _handle_create_process(self, debug_event):
        """Handle process creation event."""
        create_process = debug_event.u.CreateProcessInfo

        self.main_thread_id = debug_event.dwThreadId
        self.thread_handles[debug_event.dwThreadId] = create_process.hThread

        # Scan for license checks in main module
        self.find_license_checks()

        logger.info("Process created and analyzed for license checks")

    def _handle_load_dll(self, debug_event):
        """Handle DLL load event with sophisticated license analysis."""
        load_dll = debug_event.u.LoadDll

        # Get DLL name
        dll_name = self._read_string(load_dll.lpImageName)

        if dll_name:
            self.modules[load_dll.lpBaseOfDll] = dll_name
            dll_base = ctypes.c_void_p(load_dll.lpBaseOfDll).value

            # Comprehensive DLL analysis
            dll_analysis = self._analyze_dll_comprehensive(dll_base, dll_name)

            if dll_analysis["is_license_related"] or dll_analysis["suspicious_score"] > 0.5:
                logger.info(f"Analyzing potentially license-related DLL: {dll_name}")
                logger.info(f"Suspicious score: {dll_analysis['suspicious_score']:.2f}")

                # Set breakpoints on all detected license functions
                for func_addr in dll_analysis["license_functions"]:
                    self.set_breakpoint(func_addr, description=f"License function at {hex(func_addr)} in {dll_name}")
                    self.license_check_addresses.append(func_addr)

                # Hook imported license APIs
                for api_addr, api_name in dll_analysis["license_imports"].items():
                    self.set_breakpoint(api_addr, description=f"License API {api_name} imported by {dll_name}")

    def _analyze_dll_comprehensive(self, dll_base: int, dll_name: str) -> Dict[str, Any]:
        """Perform comprehensive DLL analysis for license detection."""
        analysis = {
            "is_license_related": False,
            "suspicious_score": 0.0,
            "license_functions": [],
            "license_imports": {},
            "license_exports": [],
            "license_strings": [],
            "protection_signatures": [],
        }

        # Read PE headers
        pe_header = self._read_memory(dll_base, 0x1000)
        if not pe_header or pe_header[:2] != b"MZ":
            return analysis

        # Parse DOS header
        e_lfanew = struct.unpack("<I", pe_header[0x3C:0x40])[0]
        if e_lfanew >= 0x1000:
            return analysis

        # Parse PE header
        nt_header_offset = e_lfanew
        if pe_header[nt_header_offset : nt_header_offset + 4] != b"PE\x00\x00":
            return analysis

        # Get image size and architecture
        machine = struct.unpack("<H", pe_header[nt_header_offset + 4 : nt_header_offset + 6])[0]
        is_64bit = machine == 0x8664  # AMD64

        # Parse optional header
        opt_header_offset = nt_header_offset + 24
        opt_header_size = struct.unpack("<H", pe_header[nt_header_offset + 20 : nt_header_offset + 22])[0]

        if is_64bit:
            size_of_image = struct.unpack("<I", pe_header[opt_header_offset + 56 : opt_header_offset + 60])[0]
            import_dir_rva = struct.unpack("<I", pe_header[opt_header_offset + 120 : opt_header_offset + 124])[0]
            import_dir_size = struct.unpack("<I", pe_header[opt_header_offset + 124 : opt_header_offset + 128])[0]
            export_dir_rva = struct.unpack("<I", pe_header[opt_header_offset + 112 : opt_header_offset + 116])[0]
            export_dir_size = struct.unpack("<I", pe_header[opt_header_offset + 116 : opt_header_offset + 120])[0]
        else:
            size_of_image = struct.unpack("<I", pe_header[opt_header_offset + 56 : opt_header_offset + 60])[0]
            import_dir_rva = struct.unpack("<I", pe_header[opt_header_offset + 104 : opt_header_offset + 108])[0]
            import_dir_size = struct.unpack("<I", pe_header[opt_header_offset + 108 : opt_header_offset + 112])[0]
            export_dir_rva = struct.unpack("<I", pe_header[opt_header_offset + 96 : opt_header_offset + 100])[0]
            export_dir_size = struct.unpack("<I", pe_header[opt_header_offset + 100 : opt_header_offset + 104])[0]

        # Analyze imports for license-related APIs
        if import_dir_rva and import_dir_size:
            license_apis = self._analyze_imports(dll_base, import_dir_rva, import_dir_size)
            analysis["license_imports"] = license_apis
            if license_apis:
                analysis["suspicious_score"] += 0.3 * len(license_apis)

        # Analyze exports for license validation functions
        if export_dir_rva and export_dir_size:
            license_exports = self._analyze_exports(dll_base, export_dir_rva, export_dir_size)
            analysis["license_exports"] = license_exports
            if license_exports:
                analysis["suspicious_score"] += 0.4
                analysis["is_license_related"] = True

        # Scan code sections for license patterns
        sections = self._parse_sections(pe_header, nt_header_offset)
        for section in sections:
            if section["characteristics"] & 0x20:  # IMAGE_SCN_CNT_CODE
                section_data = self._read_memory(dll_base + section["virtual_address"], section["virtual_size"])
                if section_data:
                    # Advanced pattern matching with disassembly analysis
                    found_patterns = self._scan_code_patterns(section_data, dll_base + section["virtual_address"])
                    analysis["license_functions"].extend(found_patterns)

                    # String analysis
                    license_strings = self._extract_license_strings(section_data)
                    analysis["license_strings"].extend(license_strings)
                    if license_strings:
                        analysis["suspicious_score"] += 0.1 * len(license_strings)

        # Check for known protection signatures
        dll_memory = self._read_memory(dll_base, min(size_of_image, 0x100000))
        if dll_memory:
            protections = self._detect_protection_signatures(dll_memory)
            analysis["protection_signatures"] = protections
            if protections:
                analysis["is_license_related"] = True
                analysis["suspicious_score"] += 0.5

        # Check DLL name patterns
        dll_name_lower = dll_name.lower() if dll_name else ""
        license_dll_patterns = [
            "license",
            "activation",
            "hasp",
            "sentinel",
            "flexlm",
            "flexnet",
            "wibu",
            "codemeter",
            "safenet",
            "thales",
            "gemalto",
            "crypto",
            "auth",
            "valid",
            "serial",
            "regist",
            "trial",
            "eval",
            "demo",
        ]

        for pattern in license_dll_patterns:
            if pattern in dll_name_lower:
                analysis["is_license_related"] = True
                analysis["suspicious_score"] += 0.3
                break

        # Normalize suspicious score
        analysis["suspicious_score"] = min(1.0, analysis["suspicious_score"])

        return analysis

    def _analyze_imports(self, dll_base: int, import_dir_rva: int, import_dir_size: int) -> Dict[int, str]:
        """Analyze import table for license-related APIs."""
        license_apis = {}

        # License-related API names
        suspicious_apis = [
            # Registry APIs for license storage
            "RegOpenKeyExA",
            "RegOpenKeyExW",
            "RegQueryValueExA",
            "RegQueryValueExW",
            "RegSetValueExA",
            "RegSetValueExW",
            "RegCreateKeyExA",
            "RegCreateKeyExW",
            # Hardware ID APIs
            "GetVolumeInformationA",
            "GetVolumeInformationW",
            "GetAdaptersInfo",
            "GetAdaptersAddresses",
            "DeviceIoControl",
            "GetSystemInfo",
            # Time-based trial checks
            "GetSystemTime",
            "GetLocalTime",
            "GetTickCount",
            "GetTickCount64",
            "QueryPerformanceCounter",
            "GetSystemTimeAsFileTime",
            # Cryptography for license validation
            "CryptAcquireContextA",
            "CryptAcquireContextW",
            "CryptCreateHash",
            "CryptHashData",
            "CryptVerifySignatureA",
            "CryptVerifySignatureW",
            # Network for online activation
            "InternetOpenA",
            "InternetOpenW",
            "InternetConnectA",
            "InternetConnectW",
            "HttpSendRequestA",
            "HttpSendRequestW",
            "WSAStartup",
            "connect",
            "send",
            "recv",
            # File operations for license files
            "CreateFileA",
            "CreateFileW",
            "ReadFile",
            "WriteFile",
            "GetPrivateProfileStringA",
            "GetPrivateProfileStringW",
        ]

        # Read import directory
        import_desc_size = 20  # sizeof(IMAGE_IMPORT_DESCRIPTOR)
        import_data = self._read_memory(dll_base + import_dir_rva, import_dir_size)

        if not import_data:
            return license_apis

        # Parse each import descriptor
        offset = 0
        while offset + import_desc_size <= len(import_data):
            # Parse IMAGE_IMPORT_DESCRIPTOR
            characteristics = struct.unpack("<I", import_data[offset : offset + 4])[0]
            if characteristics == 0:  # End of import descriptors
                break

            name_rva = struct.unpack("<I", import_data[offset + 12 : offset + 16])[0]
            first_thunk = struct.unpack("<I", import_data[offset + 16 : offset + 20])[0]

            if name_rva and first_thunk:
                # Read DLL name
                dll_name = self._read_string(dll_base + name_rva, 256)

                # Check each imported function
                thunk_offset = 0
                while True:
                    thunk_data = self._read_memory(dll_base + first_thunk + thunk_offset, 8)
                    if not thunk_data:
                        break

                    thunk_value = struct.unpack(
                        "<Q" if len(thunk_data) == 8 else "<I",
                        thunk_data[:8] if len(thunk_data) >= 8 else thunk_data + b"\x00" * (8 - len(thunk_data)),
                    )[0]
                    if thunk_value == 0:
                        break

                    # Check if import by name (not ordinal)
                    if not (thunk_value & 0x8000000000000000):
                        hint_name_rva = thunk_value & 0x7FFFFFFF
                        func_name = self._read_string(dll_base + hint_name_rva + 2, 256)

                        if func_name and func_name in suspicious_apis:
                            iat_address = dll_base + first_thunk + thunk_offset
                            license_apis[iat_address] = func_name
                            logger.debug(f"Found license API: {func_name} at IAT {hex(iat_address)}")

                    thunk_offset += 8 if len(thunk_data) >= 8 else 4

            offset += import_desc_size

        return license_apis

    def _analyze_exports(self, dll_base: int, export_dir_rva: int, export_dir_size: int) -> List[str]:
        """Analyze export table for license validation functions."""
        license_exports = []

        # Read export directory
        export_data = self._read_memory(dll_base + export_dir_rva, export_dir_size)
        if not export_data or len(export_data) < 40:
            return license_exports

        # Parse IMAGE_EXPORT_DIRECTORY
        num_functions = struct.unpack("<I", export_data[20:24])[0]
        num_names = struct.unpack("<I", export_data[24:28])[0]
        addr_functions = struct.unpack("<I", export_data[28:32])[0]
        addr_names = struct.unpack("<I", export_data[32:36])[0]

        # License-related export patterns
        license_patterns = [
            "IsLicenseValid",
            "CheckLicense",
            "ValidateLicense",
            "VerifyLicense",
            "GetLicenseStatus",
            "IsRegistered",
            "IsTrial",
            "IsActivated",
            "CheckSerial",
            "ValidateSerial",
            "VerifyRegistration",
            "GetHardwareID",
            "GetMachineCode",
            "GenerateHWID",
            "CheckExpiration",
            "GetTrialDays",
            "IsExpired",
        ]

        # Read function names
        if addr_names and num_names > 0:
            names_array = self._read_memory(dll_base + addr_names, num_names * 4)
            if names_array:
                for i in range(min(num_names, 1000)):  # Limit to prevent excessive reads
                    name_rva = struct.unpack("<I", names_array[i * 4 : (i + 1) * 4])[0]
                    func_name = self._read_string(dll_base + name_rva, 256)

                    if func_name:
                        # Check for license-related patterns
                        for pattern in license_patterns:
                            if pattern.lower() in func_name.lower():
                                license_exports.append(func_name)
                                logger.info(f"Found license export: {func_name}")
                                break

        return license_exports

    def _parse_sections(self, pe_header: bytes, nt_header_offset: int) -> List[Dict[str, Any]]:
        """Parse PE sections."""
        sections = []

        # Get number of sections
        num_sections = struct.unpack("<H", pe_header[nt_header_offset + 6 : nt_header_offset + 8])[0]

        # Section header starts after optional header
        opt_header_size = struct.unpack("<H", pe_header[nt_header_offset + 20 : nt_header_offset + 22])[0]
        section_offset = nt_header_offset + 24 + opt_header_size

        for i in range(min(num_sections, 20)):  # Limit sections
            if section_offset + 40 > len(pe_header):
                break

            section_data = pe_header[section_offset : section_offset + 40]

            sections.append(
                {
                    "name": section_data[:8].rstrip(b"\x00").decode("ascii", errors="ignore"),
                    "virtual_size": struct.unpack("<I", section_data[8:12])[0],
                    "virtual_address": struct.unpack("<I", section_data[12:16])[0],
                    "raw_size": struct.unpack("<I", section_data[16:20])[0],
                    "raw_address": struct.unpack("<I", section_data[20:24])[0],
                    "characteristics": struct.unpack("<I", section_data[36:40])[0],
                }
            )

            section_offset += 40

        return sections

    def _scan_code_patterns(self, code_data: bytes, base_address: int) -> List[int]:
        """Scan code for license check patterns using advanced analysis."""
        found_addresses = []

        # Advanced x86/x64 patterns for license checks
        advanced_patterns = [
            # Common license check sequences
            (b"\x84\xc0\x0f\x84", 4),  # TEST AL,AL; JE (long jump)
            (b"\x84\xc0\x0f\x85", 4),  # TEST AL,AL; JNE (long jump)
            (b"\x85\xc0\x0f\x84", 4),  # TEST EAX,EAX; JE (long jump)
            (b"\x85\xc0\x0f\x85", 4),  # TEST EAX,EAX; JNE (long jump)
            (b"\x83\xf8\x00\x0f\x84", 5),  # CMP EAX,0; JE (long jump)
            (b"\x83\xf8\x01\x0f\x84", 5),  # CMP EAX,1; JE (long jump)
            (b"\x48\x85\xc0\x74", 4),  # TEST RAX,RAX; JE (64-bit)
            (b"\x48\x85\xc0\x75", 4),  # TEST RAX,RAX; JNE (64-bit)
            # Return value checks
            (b"\xb8\x00\x00\x00\x00\xc3", 6),  # MOV EAX,0; RET (failure)
            (b"\xb8\x01\x00\x00\x00\xc3", 6),  # MOV EAX,1; RET (success)
            (b"\x31\xc0\xc3", 3),  # XOR EAX,EAX; RET (failure)
            (b"\x33\xc0\xc3", 3),  # XOR EAX,EAX; RET (alt encoding)
        ]

        for pattern, length in advanced_patterns:
            offset = 0
            while offset < len(code_data) - length:
                index = code_data.find(pattern, offset)
                if index == -1:
                    break

                addr = base_address + index
                found_addresses.append(addr)
                logger.debug(f"Found license pattern at {hex(addr)}")
                offset = index + 1

        return found_addresses

    def _extract_license_strings(self, data: bytes) -> List[str]:
        """Extract license-related strings from data."""
        license_strings = []

        # License-related string patterns
        string_patterns = [
            b"license",
            b"LICENSE",
            b"License",
            b"serial",
            b"SERIAL",
            b"Serial",
            b"trial",
            b"TRIAL",
            b"Trial",
            b"activation",
            b"ACTIVATION",
            b"registration",
            b"REGISTRATION",
            b"expired",
            b"EXPIRED",
            b"valid",
            b"VALID",
            b"crack",
            b"CRACK",
            b"patch",
            b"PATCH",
            b"keygen",
            b"KEYGEN",
        ]

        for pattern in string_patterns:
            if pattern in data:
                # Extract context around the string
                index = data.find(pattern)
                start = max(0, index - 20)
                end = min(len(data), index + len(pattern) + 20)
                context = data[start:end]

                # Try to extract full string
                extracted = self._extract_full_string(context, index - start)
                if extracted and len(extracted) > 3:
                    license_strings.append(extracted)

        return license_strings

    def _extract_full_string(self, data: bytes, offset: int) -> str:
        """Extract full null-terminated string from data."""
        # Find start of string
        start = offset
        while start > 0 and data[start - 1] >= 32 and data[start - 1] < 127:
            start -= 1

        # Find end of string
        end = offset
        while end < len(data) and data[end] >= 32 and data[end] < 127:
            end += 1

        if end > start:
            return data[start:end].decode("ascii", errors="ignore")
        return ""

    def _detect_protection_signatures(self, dll_memory: bytes) -> List[str]:
        """Detect known license protection signatures."""
        protections = []

        # Known protection signatures
        signatures = {
            b"HASP": "SafeNet HASP",
            b"Sentinel": "SafeNet Sentinel",
            b"WibuCmRc": "Wibu CodeMeter",
            b"FlexNet": "FlexNet Licensing",
            b"FLEXLM": "FlexLM",
            b"Themida": "Themida/WinLicense",
            b"VMProtect": "VMProtect",
            b"ASProtect": "ASProtect",
            b"Armadillo": "Armadillo",
            b"SecuROM": "SecuROM",
            b"SafeDisc": "SafeDisc",
            b"StarForce": "StarForce",
            b"Denuvo": "Denuvo",
            b"EXECryptor": "EXECryptor",
            b"Obsidium": "Obsidium",
        }

        for signature, protection_name in signatures.items():
            if signature in dll_memory:
                protections.append(protection_name)
                logger.info(f"Detected protection: {protection_name}")

        return protections

    def _read_memory(self, address: int, size: int) -> Optional[bytes]:
        """Read process memory."""
        if not self.process_handle:
            return None

        buffer = ctypes.create_string_buffer(size)
        bytes_read = ctypes.c_size_t()

        if self.kernel32.ReadProcessMemory(self.process_handle, ctypes.c_void_p(address), buffer, size, ctypes.byref(bytes_read)):
            return buffer.raw[: bytes_read.value]

        return None

    def _write_memory(self, address: int, data: bytes) -> bool:
        """Write to process memory."""
        if not self.process_handle:
            return False

        bytes_written = ctypes.c_size_t()

        # Change memory protection if needed
        old_protect = wintypes.DWORD()
        PAGE_EXECUTE_READWRITE = 0x40

        self.kernel32.VirtualProtectEx(
            self.process_handle, ctypes.c_void_p(address), len(data), PAGE_EXECUTE_READWRITE, ctypes.byref(old_protect)
        )

        success = self.kernel32.WriteProcessMemory(
            self.process_handle, ctypes.c_void_p(address), data, len(data), ctypes.byref(bytes_written)
        )

        # Restore original protection
        self.kernel32.VirtualProtectEx(self.process_handle, ctypes.c_void_p(address), len(data), old_protect, ctypes.byref(old_protect))

        return success and bytes_written.value == len(data)

    def _enumerate_memory_regions(self) -> List[Dict[str, Any]]:
        """Enumerate process memory regions."""
        regions = []

        if not self.process_handle:
            return regions

        # MEMORY_BASIC_INFORMATION structure
        class MEMORY_BASIC_INFORMATION(ctypes.Structure):
            _fields_ = [
                ("BaseAddress", ctypes.c_void_p),
                ("AllocationBase", ctypes.c_void_p),
                ("AllocationProtect", wintypes.DWORD),
                ("RegionSize", ctypes.c_size_t),
                ("State", wintypes.DWORD),
                ("Protect", wintypes.DWORD),
                ("Type", wintypes.DWORD),
            ]

        mbi = MEMORY_BASIC_INFORMATION()
        address = 0

        while self.kernel32.VirtualQueryEx(self.process_handle, ctypes.c_void_p(address), ctypes.byref(mbi), ctypes.sizeof(mbi)):
            MEM_COMMIT = 0x1000
            PAGE_EXECUTE = 0x10
            PAGE_EXECUTE_READ = 0x20
            PAGE_EXECUTE_READWRITE = 0x40

            if mbi.State == MEM_COMMIT:
                regions.append(
                    {
                        "base": mbi.BaseAddress,
                        "size": mbi.RegionSize,
                        "protection": mbi.Protect,
                        "executable": mbi.Protect in [PAGE_EXECUTE, PAGE_EXECUTE_READ, PAGE_EXECUTE_READWRITE],
                    }
                )

            address = mbi.BaseAddress + mbi.RegionSize
            if address >= 0x7FFFFFFF0000:  # Max user space address
                break

        return regions

    def _get_thread_context(self, thread_id: int):
        """Get thread context including registers."""
        if thread_id not in self.thread_handles:
            return None

        # CONTEXT structure for x64
        class CONTEXT(ctypes.Structure):
            _fields_ = [
                ("P1Home", ctypes.c_uint64),
                ("P2Home", ctypes.c_uint64),
                ("P3Home", ctypes.c_uint64),
                ("P4Home", ctypes.c_uint64),
                ("P5Home", ctypes.c_uint64),
                ("P6Home", ctypes.c_uint64),
                ("ContextFlags", wintypes.DWORD),
                ("MxCsr", wintypes.DWORD),
                ("SegCs", wintypes.WORD),
                ("SegDs", wintypes.WORD),
                ("SegEs", wintypes.WORD),
                ("SegFs", wintypes.WORD),
                ("SegGs", wintypes.WORD),
                ("SegSs", wintypes.WORD),
                ("EFlags", wintypes.DWORD),
                ("Dr0", ctypes.c_uint64),
                ("Dr1", ctypes.c_uint64),
                ("Dr2", ctypes.c_uint64),
                ("Dr3", ctypes.c_uint64),
                ("Dr6", ctypes.c_uint64),
                ("Dr7", ctypes.c_uint64),
                ("Rax", ctypes.c_uint64),
                ("Rcx", ctypes.c_uint64),
                ("Rdx", ctypes.c_uint64),
                ("Rbx", ctypes.c_uint64),
                ("Rsp", ctypes.c_uint64),
                ("Rbp", ctypes.c_uint64),
                ("Rsi", ctypes.c_uint64),
                ("Rdi", ctypes.c_uint64),
                ("R8", ctypes.c_uint64),
                ("R9", ctypes.c_uint64),
                ("R10", ctypes.c_uint64),
                ("R11", ctypes.c_uint64),
                ("R12", ctypes.c_uint64),
                ("R13", ctypes.c_uint64),
                ("R14", ctypes.c_uint64),
                ("R15", ctypes.c_uint64),
                ("Rip", ctypes.c_uint64),
            ]

        context = CONTEXT()
        context.ContextFlags = 0x10001F  # CONTEXT_ALL

        if self.kernel32.GetThreadContext(self.thread_handles[thread_id], ctypes.byref(context)):
            return context

        return None

    def _set_thread_context(self, thread_id: int, context) -> bool:
        """Set thread context including registers."""
        if thread_id not in self.thread_handles:
            return False

        return bool(self.kernel32.SetThreadContext(self.thread_handles[thread_id], ctypes.byref(context)))

    def _set_single_step(self, thread_id: int) -> bool:
        """Enable single-step mode for thread."""
        context = self._get_thread_context(thread_id)
        if not context:
            return False

        # Set trap flag (bit 8 of EFLAGS)
        context.EFlags |= 0x100

        return self._set_thread_context(thread_id, context)

    def _read_string(self, address: int, max_length: int = 260) -> Optional[str]:
        """Read null-terminated string from process memory."""
        if not address:
            return None

        data = self._read_memory(address, max_length)
        if not data:
            return None

        try:
            # Find null terminator
            null_index = data.index(b"\x00")
            return data[:null_index].decode("utf-8", errors="ignore")
        except (ValueError, UnicodeDecodeError):
            return None

    def attach(self, process_id: int) -> bool:
        """Alias for attach_to_process for compatibility."""
        return self.attach_to_process(process_id)

    def continue_execution(self) -> bool:
        """Continue execution after breakpoint or exception."""
        if not self.process_id or not self.debugging:
            return False

        # Signal the debug loop to continue
        return True

    def single_step(self, thread_id: Optional[int] = None) -> bool:
        """Execute single instruction step."""
        target_thread = thread_id or self.main_thread_id
        if not target_thread:
            return False

        return self._set_single_step(target_thread)

    def get_registers(self, thread_id: Optional[int] = None) -> Optional[Dict[str, int]]:
        """Get CPU registers for thread."""
        target_thread = thread_id or self.main_thread_id
        if not target_thread:
            return None

        context = self._get_thread_context(target_thread)
        if not context:
            return None

        return {
            "rax": context.Rax,
            "rbx": context.Rbx,
            "rcx": context.Rcx,
            "rdx": context.Rdx,
            "rsi": context.Rsi,
            "rdi": context.Rdi,
            "rbp": context.Rbp,
            "rsp": context.Rsp,
            "r8": context.R8,
            "r9": context.R9,
            "r10": context.R10,
            "r11": context.R11,
            "r12": context.R12,
            "r13": context.R13,
            "r14": context.R14,
            "r15": context.R15,
            "rip": context.Rip,
            "eflags": context.EFlags,
            "dr0": context.Dr0,
            "dr1": context.Dr1,
            "dr2": context.Dr2,
            "dr3": context.Dr3,
            "dr6": context.Dr6,
            "dr7": context.Dr7,
        }

    def set_registers(self, registers: Dict[str, int], thread_id: Optional[int] = None) -> bool:
        """Set CPU registers for thread."""
        target_thread = thread_id or self.main_thread_id
        if not target_thread:
            return False

        context = self._get_thread_context(target_thread)
        if not context:
            return False

        # Update specified registers
        for reg_name, value in registers.items():
            if hasattr(context, reg_name.capitalize()):
                setattr(context, reg_name.capitalize(), value)

        return self._set_thread_context(target_thread, context)

    def read_memory(self, address: int, size: int) -> Optional[bytes]:
        """Public alias for _read_memory."""
        return self._read_memory(address, size)

    def write_memory(self, address: int, data: bytes) -> bool:
        """Public alias for _write_memory."""
        return self._write_memory(address, data)

    def handle_exception(self, debug_event) -> int:
        """Public alias for _handle_exception."""
        return self._handle_exception(debug_event)

    def bypass_anti_debug(self) -> bool:
        """Bypass common anti-debugging techniques."""
        if not self.process_handle:
            return False

        try:
            # Patch IsDebuggerPresent
            kernel32_base = self.kernel32.GetModuleHandleA(b"kernel32.dll")
            if kernel32_base:
                is_debugger_present = self.kernel32.GetProcAddress(kernel32_base, b"IsDebuggerPresent")
                if is_debugger_present:
                    # Patch to always return 0 (false)
                    self._write_memory(is_debugger_present, b"\x31\xc0\xc3")  # XOR EAX,EAX; RET

            # Clear PEB BeingDebugged flag
            import struct

            pbi_size = ctypes.sizeof(ctypes.c_void_p) * 6
            pbi = ctypes.create_string_buffer(pbi_size)
            return_length = ctypes.c_ulong()

            # NtQueryInformationProcess
            ntdll = ctypes.WinDLL("ntdll", use_last_error=True)
            if (
                ntdll.NtQueryInformationProcess(
                    self.process_handle,
                    0,  # ProcessBasicInformation
                    pbi,
                    pbi_size,
                    ctypes.byref(return_length),
                )
                == 0
            ):
                peb_address = struct.unpack("P", pbi[ctypes.sizeof(ctypes.c_void_p) : ctypes.sizeof(ctypes.c_void_p) * 2])[0]
                # Clear BeingDebugged flag at PEB+2
                self._write_memory(peb_address + 2, b"\x00")

                # Clear NtGlobalFlag at PEB+0x68 (32-bit) or PEB+0xBC (64-bit)
                if ctypes.sizeof(ctypes.c_void_p) == 8:
                    self._write_memory(peb_address + 0xBC, b"\x00\x00\x00\x00")
                else:
                    self._write_memory(peb_address + 0x68, b"\x00\x00\x00\x00")

            logger.info("Applied anti-debugging bypasses")
            return True

        except Exception as e:
            logger.error(f"Failed to bypass anti-debug: {e}")
            return False

    def hide_debugger(self) -> bool:
        """Hide debugger from detection."""
        if not self.process_handle:
            return False

        try:
            # Use NtSetInformationThread to hide debugger
            ntdll = ctypes.WinDLL("ntdll", use_last_error=True)
            ThreadHideFromDebugger = 0x11

            for thread_handle in self.thread_handles.values():
                ntdll.NtSetInformationThread(thread_handle, ThreadHideFromDebugger, None, 0)

            # Hook and patch common anti-debug APIs
            anti_debug_apis = [
                ("kernel32.dll", "IsDebuggerPresent"),
                ("kernel32.dll", "CheckRemoteDebuggerPresent"),
                ("ntdll.dll", "NtQueryInformationProcess"),
            ]

            for dll_name, api_name in anti_debug_apis:
                self.hook_license_api(dll_name, api_name, self._anti_debug_callback)

            logger.info("Debugger hidden from detection")
            return True

        except Exception as e:
            logger.error(f"Failed to hide debugger: {e}")
            return False

    def _anti_debug_callback(self, debugger, debug_event):
        """Callback for anti-debug API hooks."""
        # Modify return value to indicate no debugger
        context = self.get_registers()
        if context:
            context["rax"] = 0  # Return false/0
            self.set_registers(context)

    def analyze_tls_callbacks(self) -> List[int]:
        """Analyze Thread Local Storage callbacks."""
        tls_callbacks = []

        if not self.process_handle:
            return tls_callbacks

        try:
            # Get main module base
            modules = list(self.modules.keys())
            if not modules:
                return tls_callbacks

            module_base = modules[0]  # First module is usually main executable

            # Read PE header
            pe_header = self._read_memory(module_base, 0x1000)
            if not pe_header or pe_header[:2] != b"MZ":
                return tls_callbacks

            # Parse DOS header
            e_lfanew = struct.unpack("<I", pe_header[0x3C:0x40])[0]

            # Parse NT headers
            nt_header_offset = e_lfanew
            if pe_header[nt_header_offset : nt_header_offset + 4] != b"PE\x00\x00":
                return tls_callbacks

            # Get optional header
            machine = struct.unpack("<H", pe_header[nt_header_offset + 4 : nt_header_offset + 6])[0]
            is_64bit = machine == 0x8664

            opt_header_offset = nt_header_offset + 24

            # Get TLS directory RVA
            if is_64bit:
                tls_dir_offset = opt_header_offset + 144  # TLS directory offset in optional header
            else:
                tls_dir_offset = opt_header_offset + 128

            tls_rva = struct.unpack("<I", pe_header[tls_dir_offset : tls_dir_offset + 4])[0]
            tls_size = struct.unpack("<I", pe_header[tls_dir_offset + 4 : tls_dir_offset + 8])[0]

            if tls_rva and tls_size:
                # Read TLS directory
                tls_dir = self._read_memory(module_base + tls_rva, tls_size)
                if tls_dir and len(tls_dir) >= 24:
                    # Get callbacks array pointer
                    if is_64bit:
                        callbacks_ptr = struct.unpack("<Q", tls_dir[16:24])[0]
                    else:
                        callbacks_ptr = struct.unpack("<I", tls_dir[12:16])[0]

                    if callbacks_ptr:
                        # Read callback addresses
                        callback_size = 8 if is_64bit else 4
                        for i in range(10):  # Limit to 10 callbacks
                            callback_data = self._read_memory(callbacks_ptr + i * callback_size, callback_size)
                            if not callback_data:
                                break

                            if is_64bit:
                                callback_addr = struct.unpack("<Q", callback_data)[0]
                            else:
                                callback_addr = struct.unpack("<I", callback_data)[0]

                            if callback_addr == 0:
                                break

                            tls_callbacks.append(callback_addr)
                            logger.info(f"Found TLS callback at 0x{callback_addr:X}")

        except Exception as e:
            logger.error(f"Error analyzing TLS callbacks: {e}")

        return tls_callbacks

    def parse_iat(self) -> Dict[str, List[Tuple[int, str]]]:
        """Parse Import Address Table."""
        iat_entries = {}

        if not self.process_handle:
            return iat_entries

        try:
            # Get main module base
            modules = list(self.modules.keys())
            if not modules:
                return iat_entries

            module_base = modules[0]

            # Use existing import analysis
            import_data = self._analyze_imports(module_base, 0, 0x10000)

            # Group by DLL
            for addr, api_name in import_data.items():
                dll_name = "unknown.dll"  # Could be enhanced to track DLL names
                if dll_name not in iat_entries:
                    iat_entries[dll_name] = []
                iat_entries[dll_name].append((addr, api_name))

        except Exception as e:
            logger.error(f"Error parsing IAT: {e}")

        return iat_entries

    def parse_eat(self) -> List[Tuple[int, str]]:
        """Parse Export Address Table."""
        eat_entries = []

        if not self.process_handle:
            return eat_entries

        try:
            # Get main module base
            modules = list(self.modules.keys())
            if not modules:
                return eat_entries

            module_base = modules[0]

            # Read PE header to get export directory
            pe_header = self._read_memory(module_base, 0x1000)
            if not pe_header or pe_header[:2] != b"MZ":
                return eat_entries

            # Parse DOS header
            e_lfanew = struct.unpack("<I", pe_header[0x3C:0x40])[0]

            # Parse NT headers
            nt_header_offset = e_lfanew
            if pe_header[nt_header_offset : nt_header_offset + 4] != b"PE\x00\x00":
                return eat_entries

            # Get architecture
            machine = struct.unpack("<H", pe_header[nt_header_offset + 4 : nt_header_offset + 6])[0]
            is_64bit = machine == 0x8664

            # Get export directory RVA and size
            opt_header_offset = nt_header_offset + 24
            if is_64bit:
                export_dir_rva = struct.unpack("<I", pe_header[opt_header_offset + 112 : opt_header_offset + 116])[0]
                export_dir_size = struct.unpack("<I", pe_header[opt_header_offset + 116 : opt_header_offset + 120])[0]
            else:
                export_dir_rva = struct.unpack("<I", pe_header[opt_header_offset + 96 : opt_header_offset + 100])[0]
                export_dir_size = struct.unpack("<I", pe_header[opt_header_offset + 100 : opt_header_offset + 104])[0]

            if not export_dir_rva or not export_dir_size:
                return eat_entries

            # Read export directory
            export_data = self._read_memory(module_base + export_dir_rva, min(export_dir_size, 0x1000))
            if not export_data or len(export_data) < 40:
                return eat_entries

            # Parse IMAGE_EXPORT_DIRECTORY
            num_functions = struct.unpack("<I", export_data[20:24])[0]
            num_names = struct.unpack("<I", export_data[24:28])[0]
            addr_functions_rva = struct.unpack("<I", export_data[28:32])[0]
            addr_names_rva = struct.unpack("<I", export_data[32:36])[0]
            addr_ordinals_rva = struct.unpack("<I", export_data[36:40])[0]

            # Read function addresses array
            if addr_functions_rva and num_functions > 0:
                func_addresses = self._read_memory(module_base + addr_functions_rva, num_functions * 4)

                # Read names array
                if addr_names_rva and num_names > 0:
                    names_array = self._read_memory(module_base + addr_names_rva, num_names * 4)
                    ordinals_array = self._read_memory(module_base + addr_ordinals_rva, num_names * 2)

                    if func_addresses and names_array and ordinals_array:
                        for i in range(min(num_names, 1000)):  # Limit to prevent excessive processing
                            # Get name RVA
                            name_rva = struct.unpack("<I", names_array[i * 4 : (i + 1) * 4])[0]
                            func_name = self._read_string(module_base + name_rva, 256)

                            # Get ordinal
                            ordinal = struct.unpack("<H", ordinals_array[i * 2 : (i + 1) * 2])[0]

                            # Get function address using ordinal as index
                            if ordinal < num_functions:
                                func_rva = struct.unpack("<I", func_addresses[ordinal * 4 : (ordinal + 1) * 4])[0]

                                # Check if it's a forwarded export (RVA points within export directory)
                                if func_rva >= export_dir_rva and func_rva < export_dir_rva + export_dir_size:
                                    # Forwarded export - the RVA points to a string
                                    forward_name = self._read_string(module_base + func_rva, 256)
                                    if forward_name:
                                        func_name = f"{func_name} -> {forward_name}"
                                    func_addr = 0  # Forwarded exports don't have a direct address
                                else:
                                    func_addr = module_base + func_rva

                                if func_name:
                                    eat_entries.append((func_addr, func_name))

        except Exception as e:
            logger.error(f"Error parsing EAT: {e}")

        return eat_entries

    def detach(self) -> bool:
        """Detach debugger from process."""
        if not self.process_id:
            return False

        self.debugging = False

        # Wait for debug thread to finish
        if self.debug_thread and self.debug_thread.is_alive():
            self.debug_thread.join(timeout=2.0)

        # Remove all breakpoints
        for addr, bp in self.breakpoints.items():
            if bp.enabled:
                self._write_memory(addr, bp.original_byte)

        # Detach from process
        success = bool(self.kernel32.DebugActiveProcessStop(self.process_id))

        # Close handles
        if self.process_handle:
            self.kernel32.CloseHandle(self.process_handle)
            self.process_handle = None

        for handle in self.thread_handles.values():
            self.kernel32.CloseHandle(handle)
        self.thread_handles.clear()

        logger.info(f"Detached from process {self.process_id}")
        self.process_id = None

        return success


# DEBUG_EVENT structure for Windows debugging
class EXCEPTION_DEBUG_INFO(ctypes.Structure):
    _fields_ = [
        ("ExceptionRecord", ctypes.c_void_p),  # Simplified
        ("dwFirstChance", wintypes.DWORD),
    ]


class CREATE_THREAD_DEBUG_INFO(ctypes.Structure):
    _fields_ = [
        ("hThread", wintypes.HANDLE),
        ("lpThreadLocalBase", ctypes.c_void_p),
        ("lpStartAddress", ctypes.c_void_p),
    ]


class CREATE_PROCESS_DEBUG_INFO(ctypes.Structure):
    _fields_ = [
        ("hFile", wintypes.HANDLE),
        ("hProcess", wintypes.HANDLE),
        ("hThread", wintypes.HANDLE),
        ("lpBaseOfImage", ctypes.c_void_p),
        ("dwDebugInfoFileOffset", wintypes.DWORD),
        ("nDebugInfoSize", wintypes.DWORD),
        ("lpThreadLocalBase", ctypes.c_void_p),
        ("lpStartAddress", ctypes.c_void_p),
        ("lpImageName", ctypes.c_void_p),
        ("fUnicode", wintypes.WORD),
    ]


class EXIT_THREAD_DEBUG_INFO(ctypes.Structure):
    _fields_ = [
        ("dwExitCode", wintypes.DWORD),
    ]


class EXIT_PROCESS_DEBUG_INFO(ctypes.Structure):
    _fields_ = [
        ("dwExitCode", wintypes.DWORD),
    ]


class LOAD_DLL_DEBUG_INFO(ctypes.Structure):
    _fields_ = [
        ("hFile", wintypes.HANDLE),
        ("lpBaseOfDll", ctypes.c_void_p),
        ("dwDebugInfoFileOffset", wintypes.DWORD),
        ("nDebugInfoSize", wintypes.DWORD),
        ("lpImageName", ctypes.c_void_p),
        ("fUnicode", wintypes.WORD),
    ]


class UNLOAD_DLL_DEBUG_INFO(ctypes.Structure):
    _fields_ = [
        ("lpBaseOfDll", ctypes.c_void_p),
    ]


class OUTPUT_DEBUG_STRING_INFO(ctypes.Structure):
    _fields_ = [
        ("lpDebugStringData", ctypes.c_char_p),
        ("fUnicode", wintypes.WORD),
        ("nDebugStringLength", wintypes.WORD),
    ]


class RIP_INFO(ctypes.Structure):
    _fields_ = [
        ("dwError", wintypes.DWORD),
        ("dwType", wintypes.DWORD),
    ]


class DEBUG_EVENT_UNION(ctypes.Union):
    _fields_ = [
        ("Exception", EXCEPTION_DEBUG_INFO),
        ("CreateThread", CREATE_THREAD_DEBUG_INFO),
        ("CreateProcessInfo", CREATE_PROCESS_DEBUG_INFO),
        ("ExitThread", EXIT_THREAD_DEBUG_INFO),
        ("ExitProcess", EXIT_PROCESS_DEBUG_INFO),
        ("LoadDll", LOAD_DLL_DEBUG_INFO),
        ("UnloadDll", UNLOAD_DLL_DEBUG_INFO),
        ("DebugString", OUTPUT_DEBUG_STRING_INFO),
        ("RipInfo", RIP_INFO),
    ]


class DEBUG_EVENT(ctypes.Structure):
    _fields_ = [
        ("dwDebugEventCode", wintypes.DWORD),
        ("dwProcessId", wintypes.DWORD),
        ("dwThreadId", wintypes.DWORD),
        ("u", DEBUG_EVENT_UNION),
    ]


# Export functions
__all__ = [
    "LicenseDebugger",
    "Breakpoint",
    "DebugEvent",
    "ExceptionCode",
]

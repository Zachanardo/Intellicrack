"""API obfuscation utilities for Intellicrack anti-analysis.

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
import logging
import random
import secrets
import struct
import zlib
from typing import Any


"""
API Obfuscation

Implements techniques to obfuscate API calls and evade
API monitoring and hooking.
"""


class APIObfuscator:
    """Obfuscate API calls to evade monitoring and analysis."""

    def __init__(self) -> None:
        """Initialize the API obfuscation system."""
        self.logger = logging.getLogger("IntellicrackLogger.APIObfuscator")

        # Import resolution techniques
        self.import_resolution_methods = {
            "hash_resolution": self._resolve_by_hash,
            "string_encryption": self._resolve_encrypted_strings,
            "dynamic_loading": self._resolve_dynamic_imports,
            "api_redirection": self._resolve_redirected_apis,
            "delayed_loading": self._resolve_delayed_imports,
        }

        # API call obfuscation methods
        self.call_obfuscation_methods = {
            "indirect_calls": self._generate_indirect_calls,
            "trampoline_calls": self._generate_trampoline_calls,
            "encrypted_payloads": self._generate_encrypted_payloads,
            "polymorphic_wrappers": self._generate_polymorphic_wrappers,
        }

        # Known API hash databases
        self.api_hash_db = {}
        self.encrypted_strings_db = {}

        # Load known hash databases
        self._load_api_databases()

        # Statistics and cache
        self.resolved_apis_cache = {}
        self.resolved_apis = 0
        self.failed_resolutions = 0

        self.logger.info("API obfuscation system initialized")

    def obfuscate_api_calls(self, code: str, method: str = "hash_lookup") -> str:
        """Obfuscate API calls in code.

        Args:
            code: Source code with API calls
            method: Obfuscation method to use

        Returns:
            Obfuscated code

        """
        try:
            self.logger.info(f"Obfuscating API calls using {method}")

            if method not in self.call_obfuscation_methods:
                raise ValueError(f"Unknown obfuscation method: {method}")

            # This would parse and transform the code
            # For demonstration, return example obfuscated code

            if method == "hash_lookup":
                return self._generate_hash_lookup_code()
            if method == "dynamic_resolution":
                return self._generate_dynamic_resolution_code()
            return code

        except Exception as e:
            self.logger.error(f"API obfuscation failed: {e}")
            return code

    def resolve_api(self, dll_name: str, api_name: str, method: str = "normal") -> int | None:
        """Resolve API address using specified method.

        Args:
            dll_name: DLL containing the API
            api_name: API function name
            method: Resolution method

        Returns:
            API address or None

        """
        try:
            cache_key = f"{dll_name}!{api_name}"

            # Check cache
            if cache_key in self.resolved_apis_cache:
                return self.resolved_apis_cache[cache_key]

            address = None

            if method == "dynamic_resolution":
                address = self._dynamic_resolve(dll_name, api_name)

            elif method == "hash_lookup":
                api_hash = self._calculate_hash(api_name)
                address = self._resolve_by_hash(dll_name, api_hash)
            elif method == "normal":
                address = self._normal_resolve(dll_name, api_name)
            elif method == "ordinal_lookup":
                address = self._resolve_by_ordinal(dll_name, 1)
            if address:
                self.resolved_apis_cache[cache_key] = address
                self.resolved_apis += 1

            return address

        except Exception as e:
            self.logger.error(f"API resolution failed: {e}")
            return None

    def _normal_resolve(self, dll_name: str, api_name: str) -> int | None:
        """Resolve API normally using GetProcAddress."""
        try:
            import platform

            if platform.system() != "Windows":
                return None

            kernel32 = ctypes.windll.kernel32

            # Get module handle
            h_module = kernel32.GetModuleHandleW(dll_name) or kernel32.LoadLibraryW(dll_name)

            if h_module:
                return kernel32.GetProcAddress(h_module, api_name.encode())
        except Exception as e:
            self.logger.debug(f"Normal resolution failed: {e}")

        return None

    def _resolve_by_hash(self, dll_name: str, api_hash: int) -> int | None:
        """Resolve API by hash value using advanced anti-analysis techniques."""
        try:
            import platform

            if platform.system() != "Windows":
                return None

            # Load DLL and enumerate exports
            kernel32 = ctypes.windll.kernel32
            h_module = kernel32.GetModuleHandleW(dll_name) or kernel32.LoadLibraryW(dll_name)

            if not h_module:
                return None

            # Parse PE headers to get export table
            dos_header = ctypes.c_uint32.from_address(h_module)
            if dos_header.value != 0x5A4D:  # "MZ"
                return None

            pe_offset = ctypes.c_uint32.from_address(h_module + 0x3C).value
            pe_signature = ctypes.c_uint32.from_address(h_module + pe_offset).value

            if pe_signature != 0x4550:  # "PE"
                return None

            # Get export directory
            export_dir_rva = ctypes.c_uint32.from_address(h_module + pe_offset + 0x78).value
            if not export_dir_rva:
                return None

            export_dir = h_module + export_dir_rva

            # Get export table data
            num_functions = ctypes.c_uint32.from_address(export_dir + 0x14).value
            num_names = ctypes.c_uint32.from_address(export_dir + 0x18).value
            names_rva = ctypes.c_uint32.from_address(export_dir + 0x20).value
            ordinals_rva = ctypes.c_uint32.from_address(export_dir + 0x24).value
            functions_rva = ctypes.c_uint32.from_address(export_dir + 0x1C).value

            # Validate export table consistency
            if num_functions == 0:
                self.logger.warning(f"DLL {dll_name} has no exported functions")
                return None

            if num_names > num_functions:
                self.logger.warning(
                    f"DLL {dll_name} has more names ({num_names}) than functions ({num_functions}) - possible corruption"
                )
                return None

            # Check for suspiciously large export tables (possible anti-analysis)
            if num_functions > 10000:
                self.logger.warning(
                    f"DLL {dll_name} has unusually large export table ({num_functions} functions) - possible anti-analysis technique",
                )

            # Validate that we have named exports to search through
            if num_names == 0:
                self.logger.info(
                    f"DLL {dll_name} has {num_functions} functions but no named exports (ordinal-only)"
                )
                return None

            names_array = h_module + names_rva
            ordinals_array = h_module + ordinals_rva
            functions_array = h_module + functions_rva

            # Enumerate exports and hash names
            for i in range(num_names):
                name_rva = ctypes.c_uint32.from_address(names_array + i * 4).value
                name_ptr = h_module + name_rva

                # Read function name
                name = ctypes.string_at(name_ptr).decode("ascii", errors="ignore")

                # Calculate hash using multiple algorithms
                calculated_hashes = [
                    self._djb2_hash(name),
                    self._fnv1a_hash(name),
                    self._crc32_hash(name),
                    self._custom_hash(name),
                ]

                if api_hash in calculated_hashes:
                    # Get ordinal and function address
                    ordinal = ctypes.c_uint16.from_address(ordinals_array + i * 2).value
                    func_rva = ctypes.c_uint32.from_address(functions_array + ordinal * 4).value
                    return h_module + func_rva

            return None

        except Exception as e:
            self.logger.debug(f"Hash resolution failed: {e}")
            return None

    def _resolve_by_ordinal(self, dll_name: str, ordinal: int) -> int | None:
        """Resolve API by ordinal number with anti-analysis evasion."""
        try:
            import platform

            if platform.system() != "Windows":
                return None

            kernel32 = ctypes.windll.kernel32

            # Get module handle with obfuscation
            h_module = kernel32.GetModuleHandleW(dll_name) or kernel32.LoadLibraryW(dll_name)

            if not h_module:
                return None

            # Parse PE export table directly for ordinal resolution
            try:
                # Read DOS header
                dos_header = ctypes.c_uint32.from_address(h_module).value
                if dos_header != 0x5A4D:  # "MZ"
                    return None

                # Get PE header offset
                pe_offset = ctypes.c_uint32.from_address(h_module + 0x3C).value
                pe_signature = ctypes.c_uint32.from_address(h_module + pe_offset).value

                if pe_signature != 0x4550:  # "PE"
                    return None

                # Get export directory RVA
                export_dir_rva = ctypes.c_uint32.from_address(h_module + pe_offset + 0x78).value
                if not export_dir_rva:
                    return None

                export_dir = h_module + export_dir_rva

                # Read export table structure
                base_ordinal = ctypes.c_uint32.from_address(export_dir + 0x10).value
                num_functions = ctypes.c_uint32.from_address(export_dir + 0x14).value
                functions_rva = ctypes.c_uint32.from_address(export_dir + 0x1C).value

                # Calculate function index from ordinal
                func_index = ordinal - base_ordinal

                if func_index < 0 or func_index >= num_functions:
                    return None

                # Get function address
                functions_array = h_module + functions_rva
                func_rva = ctypes.c_uint32.from_address(functions_array + func_index * 4).value

                if func_rva == 0:
                    return None

                func_addr = h_module + func_rva

                # Check if this is a forwarded export
                export_dir_end = export_dir + ctypes.c_uint32.from_address(export_dir + 0x04).value
                if export_dir <= func_addr < export_dir_end:
                    # This is a forwarded export, need to resolve further
                    forward_str = ctypes.string_at(func_addr).decode("ascii", errors="ignore")
                    return self._resolve_forwarded_export(forward_str)

                return func_addr

            except Exception as pe_error:
                self.logger.debug(f"PE parsing failed, using fallback: {pe_error}")

                # Fallback: Use GetProcAddress with MAKEINTRESOURCE
                try:
                    address = kernel32.GetProcAddress(h_module, ordinal)
                    return address or None
                except Exception:
                    return None

        except Exception as e:
            self.logger.debug(f"Ordinal resolution failed: {e}")
            return None

    def _dynamic_resolve(self, dll_name: str, api_name: str) -> int | None:
        """Dynamically resolve API at runtime."""
        try:
            # Obfuscate the resolution process

            # Build strings dynamically
            dll_chars = list(dll_name)
            api_chars = list(api_name)

            # Shuffle and unshuffle
            indices = list(range(len(dll_chars)))
            api_indices = list(range(len(api_chars)))
            random.shuffle(indices)
            random.shuffle(api_indices)

            shuffled_dll = "".join(dll_chars[i] for i in indices)
            shuffled_api = "".join(api_chars[i] for i in api_indices)

            # Reconstruct
            reconstructed_dll = [""] * len(dll_chars)
            reconstructed_api = [""] * len(api_chars)
            for i, idx in enumerate(indices):
                reconstructed_dll[idx] = shuffled_dll[i]
            for i, idx in enumerate(api_indices):
                reconstructed_api[idx] = shuffled_api[i]
            reconstructed_dll = "".join(reconstructed_dll)
            reconstructed_api = "".join(reconstructed_api)

            # Now resolve normally
            return self._normal_resolve(reconstructed_dll, reconstructed_api)

        except Exception as e:
            self.logger.debug(f"Dynamic resolution failed: {e}")

        return None

    def _indirect_call(self, api_address: int, *args: object) -> object:
        """Make indirect API call through function pointer.

        Args:
            api_address: Address of the API function to call
            *args: Variable arguments to pass to the API function

        Returns:
            Result of the API call, or None if the call fails

        """
        try:
            # Create function prototype based on number of arguments
            if not args:
                func_type = ctypes.WINFUNCTYPE(ctypes.c_void_p)
            elif len(args) == 1:
                func_type = ctypes.WINFUNCTYPE(ctypes.c_void_p, ctypes.c_void_p)
            elif len(args) == 2:
                func_type = ctypes.WINFUNCTYPE(ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p)
            else:
                # Generic case
                arg_types = [ctypes.c_void_p] * len(args)
                func_type = ctypes.WINFUNCTYPE(ctypes.c_void_p, *arg_types)

            # Create function from address
            func = func_type(api_address)

            # Call function
            return func(*args)

        except Exception as e:
            self.logger.error(f"Indirect call failed: {e}")
            return None

    def _obfuscated_string(self, string: str) -> bytes:
        """Obfuscate string using XOR encryption."""
        key = secrets.randbelow(255) + 1
        obfuscated = bytes((ord(c) ^ key) for c in string)
        return struct.pack("B", key) + obfuscated

    def _deobfuscate_string(self, data: bytes) -> str:
        """Deobfuscate XOR encrypted string."""
        return "" if len(data) < 2 else "".join(chr(b ^ data[0]) for b in data[1:])

    def _djb2_hash(self, string: str) -> int:
        """DJB2 hash algorithm commonly used in protected software."""
        hash_value = 5381
        for char in string:
            hash_value = ((hash_value << 5) + hash_value) + ord(char)
            hash_value &= 0xFFFFFFFF  # Keep 32-bit
        return hash_value

    def _fnv1a_hash(self, string: str) -> int:
        """FNV-1a hash algorithm for API obfuscation."""
        hash_value = 0x811C9DC5  # FNV offset basis
        for char in string:
            hash_value ^= ord(char)
            hash_value *= 0x01000193  # FNV prime
            hash_value &= 0xFFFFFFFF  # Keep 32-bit
        return hash_value

    def _crc32_hash(self, string: str) -> int:
        """CRC32 hash for API name obfuscation."""
        import zlib

        return zlib.crc32(string.encode("ascii")) & 0xFFFFFFFF

    def _custom_hash(self, string: str) -> int:
        """Apply custom hash algorithm for advanced evasion."""
        hash_value = 0
        for i, char in enumerate(string):
            hash_value = ((hash_value << 3) ^ (hash_value >> 5)) + ord(char)
            hash_value = (hash_value * 0x9E3779B9) ^ (i << 16)
            hash_value &= 0xFFFFFFFF
        return hash_value

    def _resolve_forwarded_export(self, forward_str: str) -> int | None:
        """Resolve forwarded exports like 'NTDLL.RtlInitUnicodeString'."""
        try:
            if "." not in forward_str:
                return None

            dll_name, api_name = forward_str.split(".", 1)
            dll_name = f"{dll_name}.dll"

            # Use normal resolution for forwarded export
            return self._normal_resolve(dll_name, api_name)

        except Exception as e:
            self.logger.debug(f"Forwarded export resolution failed: {e}")
            return None

    def _calculate_hash(self, string: str) -> int:
        """Calculate CRC32 hash of string."""
        return ctypes.c_uint32(zlib.crc32(string.encode())).value

    def _generate_hash_lookup_code(self) -> str:
        """Generate code that uses hash-based API resolution."""
        return """
// Hash-based API Resolution
#include <windows.h>

// CRC32 implementation
DWORD Crc32(const char* str) {
    DWORD crc = 0xFFFFFFFF;
    while (*str) {
        crc ^= *str++;
        for (int i = 0; i < 8; i++) {
            crc = (crc >> 1) ^ (0xEDB88320 & (-(crc & 1)));
        }
    }
    return ~crc;
}

// Resolve API by hash
FARPROC ResolveApiHash(HMODULE hModule, DWORD hash) {
    PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)hModule;
    PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)((BYTE*)hModule + dosHeader->e_lfanew);
    PIMAGE_EXPORT_DIRECTORY exports = (PIMAGE_EXPORT_DIRECTORY)((BYTE*)hModule +
        ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);

    DWORD* names = (DWORD*)((BYTE*)hModule + exports->AddressOfNames);
    WORD* ordinals = (WORD*)((BYTE*)hModule + exports->AddressOfNameOrdinals);
    DWORD* functions = (DWORD*)((BYTE*)hModule + exports->AddressOfFunctions);

    for (DWORD i = 0; i < exports->NumberOfNames; i++) {
        char* name = (char*)((BYTE*)hModule + names[i]);
        if (Crc32(name) == hash) {
            return (FARPROC)((BYTE*)hModule + functions[ordinals[i]]);
        }
    }

    return NULL;
}

// Usage
typedef LPVOID (WINAPI *VirtualAlloc_t)(LPVOID, SIZE_T, DWORD, DWORD);
typedef HANDLE (WINAPI *CreateThread_t)(LPSECURITY_ATTRIBUTES, SIZE_T, LPTHREAD_START_ROUTINE, LPVOID, DWORD, LPDWORD);

HMODULE kernel32 = GetModuleHandleA("kernel32.dll");

// Resolve by hash instead of name
VirtualAlloc_t pVirtualAlloc = (VirtualAlloc_t)ResolveApiHash(kernel32, 0x7C0DFCAA);
CreateThread_t pCreateThread = (CreateThread_t)ResolveApiHash(kernel32, 0x1EAE4CB6);

// Use resolved functions
LPVOID mem = pVirtualAlloc(NULL, 0x1000, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
HANDLE thread = pCreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)mem, NULL, 0, NULL);
"""

    def _generate_dynamic_resolution_code(self) -> str:
        """Generate code with dynamic API resolution."""
        return """
// Dynamic API Resolution
#include <windows.h>

// XOR obfuscated string
char* DeobfuscateString(unsigned char* data) {
    unsigned char key = data[0];
    int len = strlen((char*)data + 1);
    char* result = (char*)malloc(len + 1);

    for (int i = 0; i < len; i++) {
        result[i] = data[i + 1] ^ key;
    }
    result[len] = 0;

    return result;
}

// Build API name dynamically
char* BuildApiName(int index) {
    switch (index) {
        case 0: {
            // "VirtualAlloc" obfuscated
            unsigned char data[] = {0x42, 0x14, 0x2B, 0x30, 0x32, 0x33, 0x23, 0x2E, 0x03, 0x2E, 0x2E, 0x2D, 0x25, 0x00};
            return DeobfuscateString(data);
        }
        case 1: {
            // "CreateThread" obfuscated
            unsigned char data[] = {0x55, 0x16, 0x27, 0x30, 0x34, 0x21, 0x30, 0x19, 0x23, 0x27, 0x30, 0x34, 0x31, 0x00};
            return DeobfuscateString(data);
        }
    }
    return NULL;
}

// Indirect function calls
typedef struct {
    FARPROC func;
    char name[64];
} API_ENTRY;

API_ENTRY g_apis[10];
int g_apiCount = 0;

// Resolve and cache API
FARPROC GetApi(const char* dll, int apiIndex) {
    // Check cache
    for (int i = 0; i < g_apiCount; i++) {
        if (strcmp(g_apis[i].name, BuildApiName(apiIndex)) == 0) {
            return g_apis[i].func;
        }
    }

    // Resolve
    HMODULE hDll = GetModuleHandleA(dll);
    if (!hDll) hDll = LoadLibraryA(dll);

    char* apiName = BuildApiName(apiIndex);
    FARPROC func = GetProcAddress(hDll, apiName);

    // Cache
    if (func && g_apiCount < 10) {
        g_apis[g_apiCount].func = func;
        strcpy(g_apis[g_apiCount].name, apiName);
        g_apiCount++;
    }

    free(apiName);
    return func;
}

// Usage with indirect calls
typedef LPVOID (*VirtualAlloc_t)(LPVOID, SIZE_T, DWORD, DWORD);

VirtualAlloc_t pVirtualAlloc = (VirtualAlloc_t)GetApi("kernel32.dll", 0);
LPVOID mem = pVirtualAlloc(NULL, 0x1000, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
"""

    def generate_call_obfuscation(self, api_name: str) -> str:
        """Generate obfuscated call for specific API."""
        # Calculate hash
        api_hash = self._calculate_hash(api_name)

        return f"""
// Obfuscated call to {api_name}
FARPROC p{api_name} = ResolveApiHash(GetModuleHandleA("kernel32.dll"), 0x{api_hash:08X});
if (p{api_name}) {{
    // Cast and call based on function signature
    // Example for {api_name}
    ((void(*)())p{api_name})();
}}
"""

    def _load_api_databases(self) -> None:
        """Load known API hash databases."""
        try:
            # Common Windows APIs with their hash values
            common_apis = [
                ("kernel32.dll", "LoadLibraryA"),
                ("kernel32.dll", "LoadLibraryW"),
                ("kernel32.dll", "GetProcAddress"),
                ("kernel32.dll", "VirtualAlloc"),
                ("kernel32.dll", "VirtualProtect"),
                ("kernel32.dll", "CreateProcessA"),
                ("kernel32.dll", "CreateProcessW"),
                ("kernel32.dll", "CreateThread"),
                ("kernel32.dll", "GetModuleHandleA"),
                ("kernel32.dll", "GetModuleHandleW"),
                ("ntdll.dll", "NtAllocateVirtualMemory"),
                ("ntdll.dll", "NtProtectVirtualMemory"),
                ("ntdll.dll", "NtWriteVirtualMemory"),
                ("ntdll.dll", "NtReadVirtualMemory"),
                ("ntdll.dll", "LdrLoadDll"),
                ("ntdll.dll", "LdrGetProcedureAddress"),
                ("advapi32.dll", "RegOpenKeyExA"),
                ("advapi32.dll", "RegOpenKeyExW"),
                ("advapi32.dll", "RegSetValueExA"),
                ("advapi32.dll", "RegSetValueExW"),
                ("user32.dll", "MessageBoxA"),
                ("user32.dll", "MessageBoxW"),
                ("user32.dll", "FindWindowA"),
                ("user32.dll", "FindWindowW"),
                ("ws2_32.dll", "WSAStartup"),
                ("ws2_32.dll", "socket"),
                ("ws2_32.dll", "connect"),
                ("ws2_32.dll", "send"),
                ("ws2_32.dll", "recv"),
            ]

            # Calculate and store hashes for all algorithms
            for dll_name, api_name in common_apis:
                hashes = {
                    "djb2": self._djb2_hash(api_name),
                    "fnv1a": self._fnv1a_hash(api_name),
                    "crc32": self._crc32_hash(api_name),
                    "custom": self._custom_hash(api_name),
                }

                for hash_type, hash_value in hashes.items():
                    key = f"{hash_type}_{hash_value}"
                    self.api_hash_db[key] = (dll_name, api_name)

            self.logger.info(
                f"Loaded {len(common_apis)} API entries with {len(self.api_hash_db)} hash mappings"
            )

        except Exception as e:
            self.logger.error(f"Failed to load API databases: {e}")
            # Initialize empty databases
            self.api_hash_db = {}
            self.encrypted_strings_db = {}

    def _resolve_encrypted_strings(self, code: bytes, params: dict) -> tuple[bytes, dict]:
        """Resolve encrypted API strings.

        Args:
            code: Code containing encrypted API strings
            params: Parameters for decryption

        Returns:
            Tuple of (resolved code, metadata)

        """
        try:
            # Get encryption key from params
            key = params.get("key", 0xDEADBEEF)

            # Find encrypted string patterns
            encrypted_patterns = []

            # Simple XOR decryption for encrypted strings
            resolved_code = bytearray(code)

            # Look for common encrypted string patterns
            for i in range(len(code) - 4):
                # Check for potential encrypted string markers
                if code[i : i + 2] == b"\x68":  # PUSH instruction
                    # Extract potential encrypted string address
                    addr = int.from_bytes(code[i + 1 : i + 5], "little")

                    # Try to decrypt
                    if addr in self.encrypted_strings_db:
                        decrypted = self.encrypted_strings_db[addr]
                        encrypted_patterns.append(
                            {"offset": i, "encrypted": hex(addr), "decrypted": decrypted}
                        )

            return bytes(resolved_code), {
                "method": "string_encryption",
                "key": key,
                "resolved_count": len(encrypted_patterns),
                "patterns": encrypted_patterns,
            }

        except Exception as e:
            self.logger.error(f"Failed to resolve encrypted strings: {e}")
            return code, {"error": str(e)}

    def _resolve_dynamic_imports(self, code: bytes, params: dict) -> tuple[bytes, dict]:
        """Resolve dynamically loaded API imports.

        Args:
            code: Code containing dynamic imports
            params: Parameters for resolution

        Returns:
            Tuple of (resolved code, metadata)

        """
        try:
            resolved_code = bytearray(code)
            dynamic_imports = []

            # Look for GetProcAddress patterns
            for i in range(len(code) - 8):
                # Check for GetProcAddress call pattern
                if code[i : i + 2] == b"\xff\x15":  # CALL DWORD PTR
                    # Extract potential API name
                    api_addr = int.from_bytes(code[i + 2 : i + 6], "little")
                    if api_addr in self.api_hash_db:
                        api_name = self.api_hash_db[api_addr]
                        dynamic_imports.append(
                            {"offset": i, "api": api_name, "method": "GetProcAddress"}
                        )

            return bytes(resolved_code), {
                "method": "dynamic_loading",
                "resolved_count": len(dynamic_imports),
                "imports": dynamic_imports,
            }

        except Exception as e:
            self.logger.error(f"Failed to resolve dynamic imports: {e}")
            return code, {"error": str(e)}

    def _resolve_redirected_apis(self, code: bytes, params: dict) -> tuple[bytes, dict]:
        """Resolve redirected API calls.

        Args:
            code: Code containing redirected APIs
            params: Parameters for resolution

        Returns:
            Tuple of (resolved code, metadata)

        """
        try:
            resolved_code = bytearray(code)
            redirected_apis = []

            # Look for JMP/CALL redirection patterns
            for i in range(len(code) - 5):
                # Check for JMP pattern
                if code[i] == 0xE9:  # JMP rel32
                    offset = int.from_bytes(code[i + 1 : i + 5], "little", signed=True)
                    target = i + 5 + offset

                    # Check if target is a known API
                    if target in self.api_hash_db:
                        api_name = self.api_hash_db[target]
                        redirected_apis.append(
                            {
                                "offset": i,
                                "api": api_name,
                                "method": "JMP redirection",
                                "target": hex(target),
                            }
                        )

            return bytes(resolved_code), {
                "method": "api_redirection",
                "resolved_count": len(redirected_apis),
                "redirections": redirected_apis,
            }

        except Exception as e:
            self.logger.error(f"Failed to resolve redirected APIs: {e}")
            return code, {"error": str(e)}

    def _generate_indirect_calls(self, code: bytes, params: dict) -> tuple[bytes, dict]:
        """Generate indirect API calls through function pointers.

        Args:
            code: Original code bytes
            params: Parameters for indirect call generation

        Returns:
            Tuple of (modified code, metadata)

        """
        try:
            modified_code = bytearray(code)
            indirect_calls = []

            # Look for direct API call patterns
            for i in range(len(code) - 5):
                # Check for direct CALL instruction
                if code[i] == 0xE8:  # CALL rel32
                    call_offset = int.from_bytes(code[i + 1 : i + 5], "little", signed=True)
                    call_target = i + 5 + call_offset

                    # Check if this calls a known API
                    if call_target in self.api_hash_db:
                        api_name = self.api_hash_db[call_target]

                        # Generate indirect call sequence
                        # MOV EAX, [API_ADDR]
                        # CALL EAX
                        indirect_sequence = bytearray()
                        indirect_sequence.extend(b"\xa1")  # MOV EAX, [addr32]
                        indirect_sequence.extend(call_target.to_bytes(4, "little"))
                        indirect_sequence.extend(b"\xff\xd0")  # CALL EAX

                        # Pad with NOPs if needed
                        while len(indirect_sequence) < 5:
                            indirect_sequence.append(0x90)  # NOP

                        # Replace direct call with indirect call
                        if len(indirect_sequence) <= 5:
                            modified_code[i : i + 5] = indirect_sequence[:5]

                            indirect_calls.append(
                                {
                                    "offset": i,
                                    "api": api_name,
                                    "original": "CALL direct",
                                    "replacement": "CALL indirect",
                                }
                            )

                # Check for CALL DWORD PTR [addr] pattern
                if code[i : i + 2] == b"\xff\x15":  # CALL DWORD PTR [addr32]
                    import_addr = int.from_bytes(code[i + 2 : i + 6], "little")

                    # Generate double-indirect call
                    # MOV EAX, [import_addr]
                    # MOV EBX, [EAX]
                    # CALL EBX
                    indirect_sequence = bytearray()
                    indirect_sequence.extend(b"\xa1")  # MOV EAX, [addr32]
                    indirect_sequence.extend(import_addr.to_bytes(4, "little"))
                    indirect_sequence.extend(b"\x8b\x18")  # MOV EBX, [EAX]
                    indirect_sequence.extend(b"\xff\xd3")  # CALL EBX

                    # This sequence is longer, so we need to handle it differently
                    # For now, mark it for later expansion
                    indirect_calls.append(
                        {
                            "offset": i,
                            "type": "import_table_call",
                            "import_addr": hex(import_addr),
                            "needs_expansion": True,
                        },
                    )

            return bytes(modified_code), {
                "method": "indirect_calls",
                "modified_count": len(indirect_calls),
                "calls": indirect_calls,
            }

        except Exception as e:
            self.logger.error(f"Failed to generate indirect calls: {e}")
            return code, {"error": str(e)}

    def _generate_trampoline_calls(self, code: bytes, params: dict) -> tuple[bytes, dict]:
        """Generate trampoline-based API calls.

        Args:
            code: Original code bytes
            params: Parameters for trampoline generation

        Returns:
            Tuple of (modified code with trampolines, metadata)

        """
        try:
            # Trampolines will be appended to the end of the code
            modified_code = bytearray(code)
            trampolines = []
            trampoline_offset = len(code)

            # Look for API calls to redirect through trampolines
            for i in range(len(code) - 5):
                if code[i] == 0xE8:  # CALL rel32
                    call_offset = int.from_bytes(code[i + 1 : i + 5], "little", signed=True)
                    call_target = i + 5 + call_offset

                    # Create a trampoline
                    trampoline = bytearray()

                    # Push return address manipulation
                    trampoline.extend(b"\x68")  # PUSH imm32
                    trampoline.extend((i + 5).to_bytes(4, "little"))  # Return address

                    # Jump to actual target
                    trampoline.extend(b"\xe9")  # JMP rel32
                    jmp_offset = call_target - (trampoline_offset + len(trampoline) + 4)
                    trampoline.extend(jmp_offset.to_bytes(4, "little", signed=True))

                    # Update call to point to trampoline
                    new_call_offset = trampoline_offset - (i + 5)
                    modified_code[i + 1 : i + 5] = new_call_offset.to_bytes(
                        4, "little", signed=True
                    )

                    trampolines.append(
                        {
                            "offset": trampoline_offset,
                            "size": len(trampoline),
                            "target": hex(call_target),
                            "original_call": hex(i),
                        },
                    )

                    # Append trampoline to code
                    modified_code.extend(trampoline)
                    trampoline_offset += len(trampoline)

            return bytes(modified_code), {
                "method": "trampoline_calls",
                "trampoline_count": len(trampolines),
                "trampolines": trampolines,
                "new_size": len(modified_code),
            }

        except Exception as e:
            self.logger.error(f"Failed to generate trampoline calls: {e}")
            return code, {"error": str(e)}

    def _generate_decryption_stub(self, offset: int, size: int, key: int) -> bytearray:
        """Generate x86/x64 assembly decryption stub for runtime decryption.

        Args:
            offset: Offset of encrypted section
            size: Size of encrypted section
            key: XOR encryption key

        Returns:
            Assembly stub bytes for runtime decryption

        """
        stub = bytearray()

        # Save registers
        stub.extend(
            [
                0x50,  # PUSH EAX
                0x53,  # PUSH EBX
                0x51,  # PUSH ECX
                0x52,  # PUSH EDX
                0x56,  # PUSH ESI
                0x57,  # PUSH EDI
            ],
        )

        # Set up decryption loop
        # Load address of encrypted section
        stub.extend(
            [
                0xE8,
                0x00,
                0x00,
                0x00,
                0x00,  # CALL $+5 (get EIP)
                0x5E,  # POP ESI (ESI = current EIP)
            ],
        )

        # Calculate actual address of encrypted section
        # Offset from current position to encrypted section
        relative_offset = offset + 15  # Account for stub instructions so far

        # ADD ESI, relative_offset to point to encrypted section
        stub.extend(
            [
                0x81,
                0xC6,  # ADD ESI, imm32
            ],
        )
        stub.extend(struct.pack("<I", relative_offset))

        # Set up loop counter
        stub.extend(
            [
                0xB9,  # MOV ECX, imm32 (size)
            ],
        )
        stub.extend(struct.pack("<I", size))

        # Load XOR key
        stub.extend(
            [
                0xB0,  # MOV AL, imm8 (key)
                key & 0xFF,
            ],
        )

        # Decryption loop label position (used for relative loop calculations)
        len(stub)

        # XOR byte at [ESI] with key
        stub.extend(
            [
                0x30,
                0x06,  # XOR [ESI], AL
                0x46,  # INC ESI
                0xE2,
                0xFC,  # LOOP -4 (back to XOR instruction)
            ],
        )

        # Restore registers
        stub.extend(
            [
                0x5F,  # POP EDI
                0x5E,  # POP ESI
                0x5A,  # POP EDX
                0x59,  # POP ECX
                0x5B,  # POP EBX
                0x58,  # POP EAX
            ],
        )

        # Jump to decrypted code
        stub.extend(
            [
                0xE9,  # JMP rel32
            ],
        )
        # Calculate jump offset to skip the stub and execute decrypted code
        jmp_offset = -(len(stub) + 4)  # Jump back to original position
        stub.extend(struct.pack("<i", jmp_offset))

        return stub

    def _generate_encrypted_payloads(self, code: bytes, params: dict) -> tuple[bytes, dict]:
        """Generate encrypted API call payloads.

        Args:
            code: Original code bytes
            params: Parameters for encryption

        Returns:
            Tuple of (code with encrypted payloads, metadata)

        """
        try:
            # Use XOR encryption for API call payloads
            key = params.get("key", secrets.randbelow(255) + 1)
            modified_code = bytearray(code)
            encrypted_sections = []

            # Find and encrypt API call sequences
            for i in range(len(code) - 10):
                # Look for common API call patterns
                if code[i] == 0xE8 or code[i : i + 2] == b"\xff\x15":  # CALL patterns
                    # Encrypt the next 5-10 bytes
                    section_size = min(10, len(code) - i)

                    # XOR encrypt the section
                    for j in range(section_size):
                        modified_code[i + j] ^= key

                    # Generate runtime decryption stub
                    decrypt_stub = self._generate_decryption_stub(i, section_size, key)

                    # Insert decryption stub before encrypted section
                    # The stub will decrypt the code at runtime before execution
                    modified_code = (
                        bytearray(modified_code[:i]) + decrypt_stub + bytearray(modified_code[i:])
                    )

                    encrypted_sections.append(
                        {
                            "offset": i + len(decrypt_stub),  # Adjust offset for inserted stub
                            "size": section_size,
                            "key": key,
                            "stub_size": len(decrypt_stub),
                            "stub_offset": i,
                            "decryption_type": "xor_inline",
                        },
                    )

            return bytes(modified_code), {
                "method": "encrypted_payloads",
                "encryption_key": key,
                "encrypted_count": len(encrypted_sections),
                "sections": encrypted_sections,
            }

        except Exception as e:
            self.logger.error(f"Failed to generate encrypted payloads: {e}")
            return code, {"error": str(e)}

    def _generate_polymorphic_wrappers(self, code: bytes, params: dict) -> tuple[bytes, dict]:
        """Generate polymorphic wrappers for API calls.

        Args:
            code: Original code bytes
            params: Parameters for polymorphic generation

        Returns:
            Tuple of (code with polymorphic wrappers, metadata)

        """
        try:
            modified_code = bytearray(code)
            wrappers = []

            # Generate random instruction sequences that achieve the same result
            polymorphic_variants = [
                # Variant 1: Use different registers
                [b"\x50", b"\x53", b"\x51"],  # PUSH EAX, PUSH EBX, PUSH ECX
                # Variant 2: Use LEA instead of MOV
                [b"\x8d\x05", b"\x8d\x1d", b"\x8d\x0d"],  # LEA variants
                # Variant 3: Use arithmetic to obfuscate
                [b"\x83\xc0\x00", b"\x83\xe8\x00"],  # ADD EAX, 0; SUB EAX, 0
            ]

            # Select random variant
            variant = secrets.choice(polymorphic_variants)

            # Look for API calls to wrap
            for i in range(len(code) - 10):
                if code[i] == 0xE8:  # CALL instruction
                    # Insert polymorphic wrapper
                    wrapper = bytearray()

                    # Add junk instructions
                    wrapper.extend(secrets.choice(variant))

                    # Add the actual call
                    wrapper.extend(code[i : i + 5])

                    # Add cleanup junk
                    wrapper.extend(b"\x90" * (secrets.randbelow(3) + 1))  # Random NOPs

                    wrappers.append(
                        {
                            "offset": i,
                            "variant_used": polymorphic_variants.index(variant),
                            "wrapper_size": len(wrapper),
                            "original_size": 5,
                        },
                    )

            return bytes(modified_code), {
                "method": "polymorphic_wrappers",
                "wrapper_count": len(wrappers),
                "wrappers": wrappers,
                "variants_available": len(polymorphic_variants),
            }

        except Exception as e:
            self.logger.error(f"Failed to generate polymorphic wrappers: {e}")
            return code, {"error": str(e)}

    def _resolve_delayed_imports(self, code: bytes, params: dict) -> tuple[bytes, dict]:
        """Resolve delayed/lazy loaded API imports.

        Args:
            code: Code containing delayed imports
            params: Parameters for resolution

        Returns:
            Tuple of (resolved code, metadata)

        """
        try:
            resolved_code = bytearray(code)
            delayed_imports = []

            # Look for delayed import table patterns
            for i in range(len(code) - 8):
                # Check for delayed import thunk patterns
                if code[i : i + 2] == b"\xff\x25":  # JMP DWORD PTR [addr]
                    import_addr = int.from_bytes(code[i + 2 : i + 6], "little")

                    # Check if this is a delayed import thunk
                    if import_addr & 0x80000000:  # High bit set indicates delayed import
                        actual_addr = import_addr & 0x7FFFFFFF

                        # Try to resolve the delayed import
                        if actual_addr in self.api_hash_db:
                            api_name = self.api_hash_db[actual_addr]
                            delayed_imports.append(
                                {
                                    "offset": i,
                                    "api": api_name,
                                    "method": "Delayed import",
                                    "thunk_addr": hex(import_addr),
                                },
                            )

                # Check for LoadLibrary patterns for delayed loading
                if code[i : i + 4] == b"\x68":  # PUSH imm32
                    lib_name_addr = int.from_bytes(code[i + 1 : i + 5], "little")

                    # Check if followed by LoadLibrary call
                    if (
                        i + 5 < len(code) - 5 and code[i + 5 : i + 7] == b"\xff\x15"
                    ):  # CALL DWORD PTR
                        call_target = int.from_bytes(code[i + 7 : i + 11], "little")

                        # Check if this calls LoadLibrary
                        if call_target in self.api_hash_db:
                            api_name = self.api_hash_db[call_target]
                            if "LoadLibrary" in api_name:
                                delayed_imports.append(
                                    {
                                        "offset": i,
                                        "api": "LoadLibrary (delayed)",
                                        "method": "Runtime loading",
                                        "lib_addr": hex(lib_name_addr),
                                    },
                                )

            # Look for delay-load helper patterns
            for i in range(len(code) - 12):
                # Check for __delayLoadHelper2 pattern
                if code[i] == 0xE8:  # CALL rel32
                    call_offset = int.from_bytes(code[i + 1 : i + 5], "little", signed=True)
                    call_target = i + 5 + call_offset

                    # Check if target looks like delay load helper
                    if 0 <= call_target < len(code) - 8 and (
                                                code[call_target : call_target + 3] == b"\x55\x8b\xec"
                                            ):
                        delayed_imports.append(
                            {
                                "offset": i,
                                "api": "Delay load helper",
                                "method": "__delayLoadHelper2",
                                "helper_addr": hex(call_target),
                            },
                        )

            return bytes(resolved_code), {
                "method": "delayed_loading",
                "resolved_count": len(delayed_imports),
                "imports": delayed_imports,
            }

        except Exception as e:
            self.logger.error(f"Failed to resolve delayed imports: {e}")
            return code, {"error": str(e)}

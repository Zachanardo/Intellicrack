"""
This file is part of Intellicrack.
Copyright (C) 2025 Zachary Flint

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <https://www.gnu.org/licenses/>.
"""

import ctypes
import logging
import random
import struct
import zlib
from typing import Any, Optional

"""
API Obfuscation

Implements techniques to obfuscate API calls and evade
API monitoring and hooking.
"""


class APIObfuscator:
    """
    Obfuscate API calls to evade monitoring and analysis.
    """

    def __init__(self):
        """Initialize the API obfuscation system."""
        self.logger = logging.getLogger("IntellicrackLogger.APIObfuscator")

        # Import resolution techniques
        self.import_resolution_methods = {
            'hash_resolution': self._resolve_by_hash,
            'string_encryption': self._resolve_encrypted_strings,
            'dynamic_loading': self._resolve_dynamic_imports,
            'api_redirection': self._resolve_redirected_apis,
            'delayed_loading': self._resolve_delayed_imports
        }

        # API call obfuscation methods
        self.call_obfuscation_methods = {
            'indirect_calls': self._generate_indirect_calls,
            'trampoline_calls': self._generate_trampoline_calls,
            'encrypted_payloads': self._generate_encrypted_payloads,
            'polymorphic_wrappers': self._generate_polymorphic_wrappers
        }

        # Known API hash databases
        self.api_hash_db = {}
        self.encrypted_strings_db = {}

        # Load known hash databases
        self._load_api_databases()

        # Statistics
        self.resolved_apis = 0
        self.failed_resolutions = 0

        self.logger.info("API obfuscation system initialized")

    def obfuscate_api_calls(self, code: str, method: str = 'hash_lookup') -> str:
        """
        Obfuscate API calls in code.

        Args:
            code: Source code with API calls
            method: Obfuscation method to use

        Returns:
            Obfuscated code
        """
        try:
            self.logger.info(f"Obfuscating API calls using {method}")

            if method not in self.obfuscation_methods:
                raise ValueError(f"Unknown obfuscation method: {method}")

            # This would parse and transform the code
            # For demonstration, return example obfuscated code

            if method == 'hash_lookup':
                return self._generate_hash_lookup_code()
            elif method == 'dynamic_resolution':
                return self._generate_dynamic_resolution_code()
            else:
                return code

        except Exception as e:
            self.logger.error(f"API obfuscation failed: {e}")
            return code

    def resolve_api(self, dll_name: str, api_name: str, method: str = 'normal') -> Optional[int]:
        """
        Resolve API address using specified method.

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
            if cache_key in self.resolved_apis:
                return self.resolved_apis[cache_key]

            address = None

            if method == 'normal':
                address = self._normal_resolve(dll_name, api_name)
            elif method == 'hash_lookup':
                api_hash = self._calculate_hash(api_name)
                address = self._resolve_by_hash(dll_name, api_hash)
            elif method == 'ordinal_lookup':
                # Would need ordinal number
                pass
            elif method == 'dynamic_resolution':
                address = self._dynamic_resolve(dll_name, api_name)

            if address:
                self.resolved_apis[cache_key] = address

            return address

        except Exception as e:
            self.logger.error(f"API resolution failed: {e}")
            return None

    def _normal_resolve(self, dll_name: str, api_name: str) -> Optional[int]:
        """Normal API resolution using GetProcAddress."""
        try:
            import platform
            if platform.system() != 'Windows':
                return None

            kernel32 = ctypes.windll.kernel32

            # Get module handle
            h_module = kernel32.GetModuleHandleW(dll_name)
            if not h_module:
                h_module = kernel32.LoadLibraryW(dll_name)

            if h_module:
                # Get API address
                address = kernel32.GetProcAddress(h_module, api_name.encode())
                return address

        except Exception as e:
            self.logger.debug(f"Normal resolution failed: {e}")

        return None

    def _resolve_by_hash(self, dll_name: str, api_hash: int) -> Optional[int]:
        """Resolve API by hash value using advanced anti-analysis techniques."""
        try:
            import platform
            if platform.system() != 'Windows':
                return None

            # Load DLL and enumerate exports
            kernel32 = ctypes.windll.kernel32
            h_module = kernel32.GetModuleHandleW(dll_name)
            if not h_module:
                h_module = kernel32.LoadLibraryW(dll_name)

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
                self.logger.warning(f"DLL {dll_name} has more names ({num_names}) than functions ({num_functions}) - possible corruption")
                return None

            # Check for suspiciously large export tables (possible anti-analysis)
            if num_functions > 10000:
                self.logger.warning(f"DLL {dll_name} has unusually large export table ({num_functions} functions) - possible anti-analysis technique")

            # Validate that we have named exports to search through
            if num_names == 0:
                self.logger.info(f"DLL {dll_name} has {num_functions} functions but no named exports (ordinal-only)")
                return None

            names_array = h_module + names_rva
            ordinals_array = h_module + ordinals_rva
            functions_array = h_module + functions_rva

            # Enumerate exports and hash names
            for i in range(num_names):
                name_rva = ctypes.c_uint32.from_address(names_array + i * 4).value
                name_ptr = h_module + name_rva

                # Read function name
                name = ctypes.string_at(name_ptr).decode('ascii', errors='ignore')

                # Calculate hash using multiple algorithms
                calculated_hashes = [
                    self._djb2_hash(name),
                    self._fnv1a_hash(name),
                    self._crc32_hash(name),
                    self._custom_hash(name)
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
            import platform
            if platform.system() != 'Windows':
                return None

            kernel32 = ctypes.windll.kernel32

            # Get module handle
            h_module = kernel32.GetModuleHandleW(dll_name)
            if not h_module:
                h_module = kernel32.LoadLibraryW(dll_name)

            if not h_module:
                return None

            # Get module info to enumerate exports
            # This would require parsing PE export table
            # Simplified: check against known hashes

            for known_hash, (known_dll, known_api) in self.api_hashes.items():
                if known_hash == api_hash and known_dll == dll_name:
                    return self._normal_resolve(dll_name, known_api)

        except Exception as e:
            self.logger.debug(f"Hash resolution failed: {e}")

        return None

    def _resolve_by_ordinal(self, dll_name: str, ordinal: int) -> Optional[int]:
        """Resolve API by ordinal number with anti-analysis evasion."""
        try:
            import platform
            if platform.system() != 'Windows':
                return None

            kernel32 = ctypes.windll.kernel32

            # Get module handle with obfuscation
            h_module = kernel32.GetModuleHandleW(dll_name)
            if not h_module:
                h_module = kernel32.LoadLibraryW(dll_name)

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
                    forward_str = ctypes.string_at(func_addr).decode('ascii', errors='ignore')
                    return self._resolve_forwarded_export(forward_str)

                return func_addr

            except Exception as pe_error:
                self.logger.debug(f"PE parsing failed, using fallback: {pe_error}")

                # Fallback: Use GetProcAddress with MAKEINTRESOURCE
                try:
                    address = kernel32.GetProcAddress(h_module, ordinal)
                    return address if address else None
                except:
                    return None

        except Exception as e:
            self.logger.debug(f"Ordinal resolution failed: {e}")
            return None

            # Get module handle
            h_module = kernel32.GetModuleHandleW(dll_name)
            if not h_module:
                h_module = kernel32.LoadLibraryW(dll_name)

            if h_module:
                # Get API by ordinal
                address = kernel32.GetProcAddress(h_module, ordinal)
                return address

        except Exception as e:
            self.logger.debug(f"Ordinal resolution failed: {e}")

        return None

    def _dynamic_resolve(self, dll_name: str, api_name: str) -> Optional[int]:
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

            shuffled_dll = ''.join(dll_chars[i] for i in indices)
            shuffled_api = ''.join(api_chars[i] for i in api_indices)

            # Reconstruct
            reconstructed_dll = [''] * len(dll_chars)
            reconstructed_api = [''] * len(api_chars)
            for i, idx in enumerate(indices):
                reconstructed_dll[idx] = shuffled_dll[i]
            for i, idx in enumerate(api_indices):
                reconstructed_api[idx] = shuffled_api[i]
            reconstructed_dll = ''.join(reconstructed_dll)
            reconstructed_api = ''.join(reconstructed_api)

            # Now resolve normally
            return self._normal_resolve(reconstructed_dll, reconstructed_api)

        except Exception as e:
            self.logger.debug(f"Dynamic resolution failed: {e}")

        return None

    def _indirect_call(self, api_address: int, *args) -> Any:
        """Make indirect API call through function pointer."""
        try:
            # Create function prototype based on number of arguments
            if len(args) == 0:
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
        key = random.randint(1, 255)
        obfuscated = bytes((ord(c) ^ key) for c in string)
        return struct.pack('B', key) + obfuscated

    def _deobfuscate_string(self, data: bytes) -> str:
        """Deobfuscate XOR encrypted string."""
        if len(data) < 2:
            return ""
        key = data[0]
        return ''.join(chr(b ^ key) for b in data[1:])

    def _djb2_hash(self, string: str) -> int:
        """DJB2 hash algorithm commonly used in malware."""
        hash_value = 5381
        for char in string:
            hash_value = ((hash_value << 5) + hash_value) + ord(char)
            hash_value &= 0xFFFFFFFF  # Keep 32-bit
        return hash_value

    def _fnv1a_hash(self, string: str) -> int:
        """FNV-1a hash algorithm for API obfuscation."""
        hash_value = 0x811c9dc5  # FNV offset basis
        for char in string:
            hash_value ^= ord(char)
            hash_value *= 0x01000193  # FNV prime
            hash_value &= 0xFFFFFFFF  # Keep 32-bit
        return hash_value

    def _crc32_hash(self, string: str) -> int:
        """CRC32 hash for API name obfuscation."""
        import zlib
        return zlib.crc32(string.encode('ascii')) & 0xFFFFFFFF

    def _custom_hash(self, string: str) -> int:
        """Custom hash algorithm for advanced evasion."""
        hash_value = 0
        for i, char in enumerate(string):
            hash_value = ((hash_value << 3) ^ (hash_value >> 5)) + ord(char)
            hash_value = (hash_value * 0x9e3779b9) ^ (i << 16)
            hash_value &= 0xFFFFFFFF
        return hash_value

    def _resolve_forwarded_export(self, forward_str: str) -> Optional[int]:
        """Resolve forwarded exports like 'NTDLL.RtlInitUnicodeString'."""
        try:
            if '.' not in forward_str:
                return None

            dll_name, api_name = forward_str.split('.', 1)
            dll_name = dll_name + '.dll'

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
        code = """
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
        return code

    def _generate_dynamic_resolution_code(self) -> str:
        """Generate code with dynamic API resolution."""
        code = """
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
        return code

    def generate_call_obfuscation(self, api_name: str) -> str:
        """Generate obfuscated call for specific API."""
        # Calculate hash
        api_hash = self._calculate_hash(api_name)

        code = f"""
// Obfuscated call to {api_name}
FARPROC p{api_name} = ResolveApiHash(GetModuleHandleA("kernel32.dll"), 0x{api_hash:08X});
if (p{api_name}) {{
    // Cast and call based on function signature
    // Example for {api_name}
    ((void(*)())p{api_name})();
}}
"""
        return code

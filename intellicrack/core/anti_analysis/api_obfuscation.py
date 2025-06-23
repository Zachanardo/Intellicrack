"""
API Obfuscation

Implements techniques to obfuscate API calls and evade
API monitoring and hooking.
"""

import ctypes
import logging
import random
import struct
import zlib
from typing import Any, Optional


class APIObfuscator:
    """
    Obfuscate API calls to evade monitoring and analysis.
    """

    def __init__(self):
        self.logger = logging.getLogger("IntellicrackLogger.APIObfuscator")
        self.resolved_apis = {}
        self.obfuscation_methods = {
            'hash_lookup': self._resolve_by_hash,
            'ordinal_lookup': self._resolve_by_ordinal,
            'dynamic_resolution': self._dynamic_resolve,
            'string_obfuscation': self._obfuscated_string,
            'indirect_call': self._indirect_call
        }

        # Common API hashes (CRC32)
        self.api_hashes = {
            0x7C0DFCAA: ('kernel32.dll', 'VirtualAlloc'),
            0x91AFCA54: ('kernel32.dll', 'VirtualProtect'),
            0x1EAE4CB6: ('kernel32.dll', 'CreateThread'),
            0x4FD18963: ('kernel32.dll', 'ExitProcess'),
            0xE183277B: ('kernel32.dll', 'LoadLibraryA'),
            0x7802F749: ('kernel32.dll', 'GetProcAddress'),
            0x876F8B31: ('ws2_32.dll', 'WSAStartup'),
            0xE0DF0FEA: ('ws2_32.dll', 'socket'),
            0x6174A599: ('ws2_32.dll', 'connect'),
            0x5FC8D902: ('ws2_32.dll', 'send'),
            0x5F38EBC2: ('ws2_32.dll', 'recv')
        }

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
        """Resolve API by hash value."""
        try:
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
        """Resolve API by ordinal number."""
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

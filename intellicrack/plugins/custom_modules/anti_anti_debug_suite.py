#!/usr/bin/env python3
"""Anti-anti-debug suite plugin for Intellicrack.

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
import ctypes.util
import json
import logging
import os
import struct
import time
import winreg
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

from intellicrack.handlers.psutil_handler import psutil
from intellicrack.utils.logger import log_all_methods


logger = logging.getLogger(__name__)


"""
Anti-Anti-Debug Suite

Comprehensive anti-debugging detection and bypass system for defeating all
common anti-debugging techniques used by modern software protection systems.

Author: Intellicrack Framework
Version: 2.0.0
License: GPL v3
"""


class AntiDebugTechnique(Enum):
    """Types of anti-debug techniques."""

    API_HOOKS = "api_hooks"
    PEB_FLAGS = "peb_flags"
    HARDWARE_BREAKPOINTS = "hardware_breakpoints"
    TIMING_CHECKS = "timing_checks"
    MEMORY_SCANNING = "memory_scanning"
    EXCEPTION_HANDLING = "exception_handling"
    PROCESS_ENVIRONMENT = "process_environment"
    REGISTRY_CHECKS = "registry_checks"
    FILE_SYSTEM_CHECKS = "file_system_checks"
    ADVANCED_EVASION = "advanced_evasion"


class BypassResult(Enum):
    """Results of bypass attempts."""

    SUCCESS = "success"
    FAILED = "failed"
    PARTIAL = "partial"
    NOT_APPLICABLE = "not_applicable"


@dataclass
class BypassOperation:
    """Bypass operation tracking."""

    technique: AntiDebugTechnique
    description: str
    result: BypassResult
    details: str = ""
    timestamp: float = field(default_factory=time.time)
    error: str | None = None


@log_all_methods
class WindowsAPIHooker:
    """Hooks and neutralizes anti-debug Windows APIs."""

    def __init__(self) -> None:
        """Initialize Windows API hooker for anti-debug function interception."""
        self.logger = logging.getLogger(f"{__name__}.APIHooker")
        self.hooked_functions: dict[int, Any] = {}
        self.original_functions: dict[int, bytes] = {}

        # Load required DLLs
        self.kernel32 = ctypes.windll.kernel32
        self.ntdll = ctypes.windll.ntdll
        self.user32 = ctypes.windll.user32

        # Hook tracking
        self.active_hooks: set[str] = set()

    def hook_is_debugger_present(self) -> bool:
        """Install hook for IsDebuggerPresent to always return FALSE."""
        try:
            # Get function address
            func_addr = self.kernel32.GetProcAddress(
                self.kernel32.GetModuleHandleW("kernel32.dll"),
                b"IsDebuggerPresent",
            )

            if not func_addr:
                return False

            # Save original
            if func_addr not in self.original_functions:
                original_bytes = ctypes.create_string_buffer(5)
                ctypes.memmove(original_bytes, func_addr, 5)
                self.original_functions[func_addr] = bytes(original_bytes)

            # Create hook code: xor eax, eax; ret (always return 0)
            hook_code = b"\x33\xc0\xc3"  # xor eax,eax; ret

            # Make memory writable
            old_protect = ctypes.c_ulong()
            self.kernel32.VirtualProtect(
                func_addr,
                len(hook_code),
                0x40,  # PAGE_EXECUTE_READWRITE
                ctypes.byref(old_protect),
            )

            # Install hook
            ctypes.memmove(func_addr, hook_code, len(hook_code))

            # Restore protection
            self.kernel32.VirtualProtect(
                func_addr,
                len(hook_code),
                old_protect.value,
                ctypes.byref(old_protect),
            )

            self.active_hooks.add("IsDebuggerPresent")
            self.logger.info("Hooked IsDebuggerPresent")
            return True

        except Exception as e:
            self.logger.exception("Failed to hook IsDebuggerPresent: %s", e)
            return False

    def hook_check_remote_debugger_present(self) -> bool:
        """Install hook for CheckRemoteDebuggerPresent to always return FALSE."""
        try:
            func_addr = self.kernel32.GetProcAddress(
                self.kernel32.GetModuleHandleW("kernel32.dll"),
                b"CheckRemoteDebuggerPresent",
            )

            if not func_addr:
                return False

            # Save original
            if func_addr not in self.original_functions:
                original_bytes = ctypes.create_string_buffer(20)
                ctypes.memmove(original_bytes, func_addr, 20)
                self.original_functions[func_addr] = bytes(original_bytes)

            # Hook code: zero out the result and return success
            # mov dword ptr [edx], 0; xor eax, eax; ret
            hook_code = b"\xc7\x02\x00\x00\x00\x00\x33\xc0\xc3"

            old_protect = ctypes.c_ulong()
            self.kernel32.VirtualProtect(
                func_addr,
                len(hook_code),
                0x40,
                ctypes.byref(old_protect),
            )

            ctypes.memmove(func_addr, hook_code, len(hook_code))

            self.kernel32.VirtualProtect(
                func_addr,
                len(hook_code),
                old_protect.value,
                ctypes.byref(old_protect),
            )

            self.active_hooks.add("CheckRemoteDebuggerPresent")
            self.logger.info("Hooked CheckRemoteDebuggerPresent")
            return True

        except Exception as e:
            self.logger.exception("Failed to hook CheckRemoteDebuggerPresent: %s", e)
            return False

    def hook_nt_query_information_process(self) -> bool:
        """Install hook for NtQueryInformationProcess for debug-related queries."""
        try:
            func_addr = self.ntdll.GetProcAddress(self.ntdll.LoadLibraryW("ntdll.dll"), b"NtQueryInformationProcess")

            if not func_addr:
                return False

            # Save original
            if func_addr not in self.original_functions:
                original_bytes = ctypes.create_string_buffer(32)
                ctypes.memmove(original_bytes, func_addr, 32)
                self.original_functions[func_addr] = bytes(original_bytes)

            # Create sophisticated hook that filters debug-related queries
            # mov eax, 0 (STATUS_SUCCESS); ret 0x14 (5 params * 4 bytes + return addr)
            hook_code = b"\xb8\x00\x00\x00\x00\xc2\x14\x00"

            old_protect = ctypes.c_ulong()
            self.kernel32.VirtualProtect(
                func_addr,
                len(hook_code),
                0x40,  # PAGE_EXECUTE_READWRITE
                ctypes.byref(old_protect),
            )

            ctypes.memmove(func_addr, hook_code, len(hook_code))

            self.kernel32.VirtualProtect(
                func_addr,
                len(hook_code),
                old_protect.value,
                ctypes.byref(old_protect),
            )

            self.active_hooks.add("NtQueryInformationProcess")
            self.logger.info("Hooked NtQueryInformationProcess")
            return True

        except Exception as e:
            self.logger.exception("Failed to hook NtQueryInformationProcess: %s", e)
            return False

    def hook_nt_set_information_thread(self) -> bool:
        """Install hook for NtSetInformationThread to prevent thread hiding."""
        try:
            func_addr = self.ntdll.GetProcAddress(self.ntdll.LoadLibraryW("ntdll.dll"), b"NtSetInformationThread")

            if not func_addr:
                return False

            # Save original
            if func_addr not in self.original_functions:
                original_bytes = ctypes.create_string_buffer(32)
                ctypes.memmove(original_bytes, func_addr, 32)
                self.original_functions[func_addr] = bytes(original_bytes)

            # Hook to prevent ThreadHideFromDebugger (0x11)
            # Check if ThreadInformationClass == 0x11, if so, return success without action
            hook_code = (
                b"\x8b\x54\x24\x08"  # mov edx, [esp+8] (ThreadInformationClass)
                b"\x83\xfa\x11"  # cmp edx, 0x11 (ThreadHideFromDebugger)
                b"\x75\x05"  # jne original_function
                b"\x33\xc0"  # xor eax, eax (STATUS_SUCCESS)
                b"\xc2\x10\x00"  # ret 0x10
            )

            old_protect = ctypes.c_ulong()
            self.kernel32.VirtualProtect(
                func_addr,
                len(hook_code),
                0x40,
                ctypes.byref(old_protect),
            )

            ctypes.memmove(func_addr, hook_code, len(hook_code))

            self.kernel32.VirtualProtect(
                func_addr,
                len(hook_code),
                old_protect.value,
                ctypes.byref(old_protect),
            )

            self.active_hooks.add("NtSetInformationThread")
            self.logger.info("Hooked NtSetInformationThread")
            return True

        except Exception as e:
            self.logger.exception("Failed to hook NtSetInformationThread: %s", e)
            return False

    def hook_output_debug_string(self) -> bool:
        """Install hook for OutputDebugString to prevent detection."""
        try:
            func_addr = self.kernel32.GetProcAddress(
                self.kernel32.GetModuleHandleW("kernel32.dll"),
                b"OutputDebugStringA",
            )

            if not func_addr:
                return False

            # Hook to just return without doing anything
            hook_code = b"\xc3"  # ret

            old_protect = ctypes.c_ulong()
            self.kernel32.VirtualProtect(
                func_addr,
                1,
                0x40,
                ctypes.byref(old_protect),
            )

            ctypes.memmove(func_addr, hook_code, 1)

            self.kernel32.VirtualProtect(
                func_addr,
                1,
                old_protect.value,
                ctypes.byref(old_protect),
            )

            self.active_hooks.add("OutputDebugStringA")
            self.logger.info("Hooked OutputDebugStringA")
            return True

        except Exception as e:
            self.logger.exception("Failed to hook OutputDebugStringA: %s", e)
            return False

    def hook_nt_close(self) -> bool:
        """Install hook for NtClose to prevent invalid handle detection."""
        try:
            func_addr = self.ntdll.GetProcAddress(self.ntdll.LoadLibraryW("ntdll.dll"), b"NtClose")

            if not func_addr:
                return False

            # Always return success even for invalid handles
            hook_code = b"\x33\xc0\xc3"  # xor eax, eax; ret

            old_protect = ctypes.c_ulong()
            self.kernel32.VirtualProtect(
                func_addr,
                len(hook_code),
                0x40,
                ctypes.byref(old_protect),
            )

            if func_addr not in self.original_functions:
                original_bytes = ctypes.create_string_buffer(len(hook_code))
                ctypes.memmove(original_bytes, func_addr, len(hook_code))
                self.original_functions[func_addr] = bytes(original_bytes)

            ctypes.memmove(func_addr, hook_code, len(hook_code))

            self.kernel32.VirtualProtect(
                func_addr,
                len(hook_code),
                old_protect.value,
                ctypes.byref(old_protect),
            )

            self.active_hooks.add("NtClose")
            return True

        except Exception as e:
            self.logger.exception("Failed to hook NtClose: %s", e)
            return False

    def hook_close_handle(self) -> bool:
        """Install hook for CloseHandle to prevent invalid handle detection."""
        try:
            func_addr = self.kernel32.GetProcAddress(self.kernel32.GetModuleHandleW("kernel32.dll"), b"CloseHandle")

            if not func_addr:
                return False

            # Always return TRUE
            hook_code = b"\xb8\x01\x00\x00\x00\xc3"  # mov eax, 1; ret

            old_protect = ctypes.c_ulong()
            self.kernel32.VirtualProtect(
                func_addr,
                len(hook_code),
                0x40,
                ctypes.byref(old_protect),
            )

            if func_addr not in self.original_functions:
                original_bytes = ctypes.create_string_buffer(len(hook_code))
                ctypes.memmove(original_bytes, func_addr, len(hook_code))
                self.original_functions[func_addr] = bytes(original_bytes)

            ctypes.memmove(func_addr, hook_code, len(hook_code))

            self.kernel32.VirtualProtect(
                func_addr,
                len(hook_code),
                old_protect.value,
                ctypes.byref(old_protect),
            )

            self.active_hooks.add("CloseHandle")
            return True

        except Exception as e:
            self.logger.exception("Failed to hook CloseHandle: %s", e)
            return False

    def hook_get_last_error(self) -> bool:
        """Install hook for GetLastError to hide debug-related errors."""
        try:
            func_addr = self.kernel32.GetProcAddress(self.kernel32.GetModuleHandleW("kernel32.dll"), b"GetLastError")

            if not func_addr:
                return False

            # Always return ERROR_SUCCESS (0)
            hook_code = b"\x33\xc0\xc3"  # xor eax, eax; ret

            old_protect = ctypes.c_ulong()
            self.kernel32.VirtualProtect(
                func_addr,
                len(hook_code),
                0x40,
                ctypes.byref(old_protect),
            )

            if func_addr not in self.original_functions:
                original_bytes = ctypes.create_string_buffer(len(hook_code))
                ctypes.memmove(original_bytes, func_addr, len(hook_code))
                self.original_functions[func_addr] = bytes(original_bytes)

            ctypes.memmove(func_addr, hook_code, len(hook_code))

            self.kernel32.VirtualProtect(
                func_addr,
                len(hook_code),
                old_protect.value,
                ctypes.byref(old_protect),
            )

            self.active_hooks.add("GetLastError")
            return True

        except Exception as e:
            self.logger.exception("Failed to hook GetLastError: %s", e)
            return False

    def hook_set_last_error(self) -> bool:
        """Install hook for SetLastError to prevent error code manipulation."""
        try:
            func_addr = self.kernel32.GetProcAddress(self.kernel32.GetModuleHandleW("kernel32.dll"), b"SetLastError")

            if not func_addr:
                return False

            # Do nothing
            hook_code = b"\xc3"  # ret

            old_protect = ctypes.c_ulong()
            self.kernel32.VirtualProtect(
                func_addr,
                1,
                0x40,
                ctypes.byref(old_protect),
            )

            if func_addr not in self.original_functions:
                original_bytes = ctypes.create_string_buffer(1)
                ctypes.memmove(original_bytes, func_addr, 1)
                self.original_functions[func_addr] = bytes(original_bytes)

            ctypes.memmove(func_addr, hook_code, 1)

            self.kernel32.VirtualProtect(
                func_addr,
                1,
                old_protect.value,
                ctypes.byref(old_protect),
            )

            self.active_hooks.add("SetLastError")
            return True

        except Exception as e:
            self.logger.exception("Failed to hook SetLastError: %s", e)
            return False

    def hook_nt_query_object(self) -> bool:
        """Install hook for NtQueryObject to prevent debug object detection."""
        try:
            func_addr = self.ntdll.GetProcAddress(self.ntdll.LoadLibraryW("ntdll.dll"), b"NtQueryObject")

            if not func_addr:
                return False

            # Return STATUS_UNSUCCESSFUL
            hook_code = b"\xb8\x01\x00\x00\xc0\xc2\x14\x00"  # mov eax, 0xC0000001; ret 0x14

            old_protect = ctypes.c_ulong()
            self.kernel32.VirtualProtect(
                func_addr,
                len(hook_code),
                0x40,
                ctypes.byref(old_protect),
            )

            if func_addr not in self.original_functions:
                original_bytes = ctypes.create_string_buffer(len(hook_code))
                ctypes.memmove(original_bytes, func_addr, len(hook_code))
                self.original_functions[func_addr] = bytes(original_bytes)

            ctypes.memmove(func_addr, hook_code, len(hook_code))

            self.kernel32.VirtualProtect(
                func_addr,
                len(hook_code),
                old_protect.value,
                ctypes.byref(old_protect),
            )

            self.active_hooks.add("NtQueryObject")
            return True

        except Exception as e:
            self.logger.exception("Failed to hook NtQueryObject: %s", e)
            return False

    def hook_nt_query_system_information(self) -> bool:
        """Install hook for NtQuerySystemInformation to hide debugger processes."""
        try:
            func_addr = self.ntdll.GetProcAddress(self.ntdll.LoadLibraryW("ntdll.dll"), b"NtQuerySystemInformation")

            if not func_addr:
                return False

            # Return STATUS_ACCESS_DENIED for process information queries
            hook_code = b"\xb8\x22\x00\x00\xc0\xc2\x10\x00"  # mov eax, 0xC0000022; ret 0x10

            old_protect = ctypes.c_ulong()
            self.kernel32.VirtualProtect(
                func_addr,
                len(hook_code),
                0x40,
                ctypes.byref(old_protect),
            )

            if func_addr not in self.original_functions:
                original_bytes = ctypes.create_string_buffer(len(hook_code))
                ctypes.memmove(original_bytes, func_addr, len(hook_code))
                self.original_functions[func_addr] = bytes(original_bytes)

            ctypes.memmove(func_addr, hook_code, len(hook_code))

            self.kernel32.VirtualProtect(
                func_addr,
                len(hook_code),
                old_protect.value,
                ctypes.byref(old_protect),
            )

            self.active_hooks.add("NtQuerySystemInformation")
            return True

        except Exception as e:
            self.logger.exception("Failed to hook NtQuerySystemInformation: %s", e)
            return False

    def hook_find_window(self) -> bool:
        """Install hook for FindWindow to hide debugger windows."""
        try:
            func_addr = self.user32.GetProcAddress(self.user32.GetModuleHandleW("user32.dll"), b"FindWindowA")

            if not func_addr:
                return False

            # Always return NULL (window not found)
            hook_code = b"\x33\xc0\xc2\x08\x00"  # xor eax, eax; ret 8

            old_protect = ctypes.c_ulong()
            self.kernel32.VirtualProtect(
                func_addr,
                len(hook_code),
                0x40,
                ctypes.byref(old_protect),
            )

            if func_addr not in self.original_functions:
                original_bytes = ctypes.create_string_buffer(len(hook_code))
                ctypes.memmove(original_bytes, func_addr, len(hook_code))
                self.original_functions[func_addr] = bytes(original_bytes)

            ctypes.memmove(func_addr, hook_code, len(hook_code))

            self.kernel32.VirtualProtect(
                func_addr,
                len(hook_code),
                old_protect.value,
                ctypes.byref(old_protect),
            )

            self.active_hooks.add("FindWindow")
            return True

        except Exception as e:
            self.logger.exception("Failed to hook FindWindow: %s", e)
            return False

    def hook_enum_windows(self) -> bool:
        """Install hook for EnumWindows to skip debugger windows."""
        try:
            func_addr = self.user32.GetProcAddress(self.user32.GetModuleHandleW("user32.dll"), b"EnumWindows")

            if not func_addr:
                return False

            # Return TRUE (success) without enumerating
            hook_code = b"\xb8\x01\x00\x00\x00\xc2\x08\x00"  # mov eax, 1; ret 8

            old_protect = ctypes.c_ulong()
            self.kernel32.VirtualProtect(
                func_addr,
                len(hook_code),
                0x40,
                ctypes.byref(old_protect),
            )

            if func_addr not in self.original_functions:
                original_bytes = ctypes.create_string_buffer(len(hook_code))
                ctypes.memmove(original_bytes, func_addr, len(hook_code))
                self.original_functions[func_addr] = bytes(original_bytes)

            ctypes.memmove(func_addr, hook_code, len(hook_code))

            self.kernel32.VirtualProtect(
                func_addr,
                len(hook_code),
                old_protect.value,
                ctypes.byref(old_protect),
            )

            self.active_hooks.add("EnumWindows")
            return True

        except Exception as e:
            self.logger.exception("Failed to hook EnumWindows: %s", e)
            return False

    def hook_get_foreground_window(self) -> bool:
        """Install hook for GetForegroundWindow to hide debugger focus."""
        try:
            func_addr = self.user32.GetProcAddress(self.user32.GetModuleHandleW("user32.dll"), b"GetForegroundWindow")

            if not func_addr:
                return False

            # Return the desktop window handle (always valid)
            desktop_hwnd = self.user32.GetDesktopWindow()
            hook_code = struct.pack("<BI", 0xB8, desktop_hwnd) + b"\xc3"  # mov eax, desktop_hwnd; ret

            old_protect = ctypes.c_ulong()
            self.kernel32.VirtualProtect(
                func_addr,
                len(hook_code),
                0x40,
                ctypes.byref(old_protect),
            )

            if func_addr not in self.original_functions:
                original_bytes = ctypes.create_string_buffer(len(hook_code))
                ctypes.memmove(original_bytes, func_addr, len(hook_code))
                self.original_functions[func_addr] = bytes(original_bytes)

            ctypes.memmove(func_addr, hook_code, len(hook_code))

            self.kernel32.VirtualProtect(
                func_addr,
                len(hook_code),
                old_protect.value,
                ctypes.byref(old_protect),
            )

            self.active_hooks.add("GetForegroundWindow")
            return True

        except Exception as e:
            self.logger.exception("Failed to hook GetForegroundWindow: %s", e)
            return False

    def hook_nt_yield_execution(self) -> bool:
        """Install hook for NtYieldExecution to prevent thread timing detection."""
        try:
            func_addr = self.ntdll.GetProcAddress(self.ntdll.LoadLibraryW("ntdll.dll"), b"NtYieldExecution")

            if not func_addr:
                return False

            # Return STATUS_NO_YIELD_PERFORMED
            hook_code = b"\xb8\x23\x00\x00\x40\xc3"  # mov eax, 0x40000023; ret

            old_protect = ctypes.c_ulong()
            self.kernel32.VirtualProtect(
                func_addr,
                len(hook_code),
                0x40,
                ctypes.byref(old_protect),
            )

            if func_addr not in self.original_functions:
                original_bytes = ctypes.create_string_buffer(len(hook_code))
                ctypes.memmove(original_bytes, func_addr, len(hook_code))
                self.original_functions[func_addr] = bytes(original_bytes)

            ctypes.memmove(func_addr, hook_code, len(hook_code))

            self.kernel32.VirtualProtect(
                func_addr,
                len(hook_code),
                old_protect.value,
                ctypes.byref(old_protect),
            )

            self.active_hooks.add("NtYieldExecution")
            return True

        except Exception as e:
            self.logger.exception("Failed to hook NtYieldExecution: %s", e)
            return False

    def hook_switch_to_thread(self) -> bool:
        """Install hook for SwitchToThread to prevent thread timing detection."""
        try:
            func_addr = self.kernel32.GetProcAddress(self.kernel32.GetModuleHandleW("kernel32.dll"), b"SwitchToThread")

            if not func_addr:
                return False

            # Return FALSE (no yield)
            hook_code = b"\x33\xc0\xc3"  # xor eax, eax; ret

            old_protect = ctypes.c_ulong()
            self.kernel32.VirtualProtect(
                func_addr,
                len(hook_code),
                0x40,
                ctypes.byref(old_protect),
            )

            if func_addr not in self.original_functions:
                original_bytes = ctypes.create_string_buffer(len(hook_code))
                ctypes.memmove(original_bytes, func_addr, len(hook_code))
                self.original_functions[func_addr] = bytes(original_bytes)

            ctypes.memmove(func_addr, hook_code, len(hook_code))

            self.kernel32.VirtualProtect(
                func_addr,
                len(hook_code),
                old_protect.value,
                ctypes.byref(old_protect),
            )

            self.active_hooks.add("SwitchToThread")
            return True

        except Exception as e:
            self.logger.exception("Failed to hook SwitchToThread: %s", e)
            return False

    def install_all_hooks(self) -> list[str]:
        """Install all API hooks."""
        results = []

        hooks = [
            ("IsDebuggerPresent", self.hook_is_debugger_present),
            ("CheckRemoteDebuggerPresent", self.hook_check_remote_debugger_present),
            ("NtQueryInformationProcess", self.hook_nt_query_information_process),
            ("NtSetInformationThread", self.hook_nt_set_information_thread),
            ("OutputDebugString", self.hook_output_debug_string),
            ("NtClose", self.hook_nt_close),
            ("CloseHandle", self.hook_close_handle),
            ("GetLastError", self.hook_get_last_error),
            ("SetLastError", self.hook_set_last_error),
            ("NtQueryObject", self.hook_nt_query_object),
            ("NtQuerySystemInformation", self.hook_nt_query_system_information),
            ("FindWindowA", self.hook_find_window),
            ("FindWindowW", self.hook_find_window),
            ("EnumWindows", self.hook_enum_windows),
            ("GetForegroundWindow", self.hook_get_foreground_window),
            ("NtYieldExecution", self.hook_nt_yield_execution),
            ("SwitchToThread", self.hook_switch_to_thread),
        ]

        for name, hook_func in hooks:
            try:
                if hook_func():
                    results.append(f"OK {name}")
                else:
                    results.append(f"FAIL {name}")
            except Exception as e:
                results.append(f"FAIL {name}: {e}")

        return results

    def restore_hooks(self) -> bool:
        """Restore original function code."""
        try:
            for func_addr, original_bytes in self.original_functions.items():
                old_protect = ctypes.c_ulong()
                self.kernel32.VirtualProtect(
                    func_addr,
                    len(original_bytes),
                    0x40,
                    ctypes.byref(old_protect),
                )

                ctypes.memmove(func_addr, original_bytes, len(original_bytes))

                self.kernel32.VirtualProtect(
                    func_addr,
                    len(original_bytes),
                    old_protect.value,
                    ctypes.byref(old_protect),
                )

            self.active_hooks.clear()
            self.logger.info("Restored all hooks")
            return True

        except Exception as e:
            self.logger.exception("Failed to restore hooks: %s", e)
            return False


@log_all_methods
class PEBManipulator:
    """Manipulates Process Environment Block to hide debugging."""

    def __init__(self) -> None:
        """Initialize PEB manipulator for process environment block modification."""
        self.logger = logging.getLogger(f"{__name__}.PEBManipulator")
        self.kernel32 = ctypes.windll.kernel32
        self.ntdll = ctypes.windll.ntdll

        # PEB structure offsets (x64)
        self.PEB_BEING_DEBUGGED_OFFSET = 0x02
        self.PEB_NT_GLOBAL_FLAG_OFFSET = 0x68
        self.PEB_HEAP_FLAGS_OFFSET = 0x70

    def get_peb_address(self) -> int | None:
        """Get PEB address for current process."""
        try:
            # Get current process handle
            process_handle = self.kernel32.GetCurrentProcess()

            # Process basic information structure
            class PROCESS_BASIC_INFORMATION(ctypes.Structure):  # noqa: N801
                _fields_ = [
                    ("Reserved1", ctypes.c_void_p),
                    ("PebBaseAddress", ctypes.c_void_p),
                    ("Reserved2", ctypes.c_void_p * 2),
                    ("UniqueProcessId", ctypes.c_void_p),
                    ("Reserved3", ctypes.c_void_p),
                ]

            pbi = PROCESS_BASIC_INFORMATION()
            return_length = ctypes.c_ulong()

            # Query process information
            status = self.ntdll.NtQueryInformationProcess(
                process_handle,
                0,  # ProcessBasicInformation
                ctypes.byref(pbi),
                ctypes.sizeof(pbi),
                ctypes.byref(return_length),
            )

            if status == 0:  # STATUS_SUCCESS
                peb_value: int | None = pbi.PebBaseAddress
                return peb_value

        except Exception as e:
            self.logger.exception("Failed to get PEB address: %s", e)

        return None

    def patch_being_debugged_flag(self) -> bool:
        """Patch PEB BeingDebugged flag."""
        try:
            peb_addr = self.get_peb_address()
            if not peb_addr:
                return False

            # Calculate flag address
            flag_addr = peb_addr + self.PEB_BEING_DEBUGGED_OFFSET

            # Read current value
            current_value = ctypes.c_ubyte()
            bytes_read = ctypes.c_size_t()

            if not self.kernel32.ReadProcessMemory(
                self.kernel32.GetCurrentProcess(),
                flag_addr,
                ctypes.byref(current_value),
                1,
                ctypes.byref(bytes_read),
            ):
                return False

            # Set to FALSE (0)
            new_value = ctypes.c_ubyte(0)
            bytes_written = ctypes.c_size_t()

            if success := self.kernel32.WriteProcessMemory(
                self.kernel32.GetCurrentProcess(),
                flag_addr,
                ctypes.byref(new_value),
                1,
                ctypes.byref(bytes_written),
            ):
                self.logger.info(
                    "Patched BeingDebugged flag: %d -> 0 (success: %s, wrote %d bytes)",
                    current_value.value,
                    success,
                    bytes_written.value,
                )
                return True

        except Exception as e:
            self.logger.exception("Failed to patch BeingDebugged flag: %s", e)

        return False

    def patch_nt_global_flag(self) -> bool:
        """Patch PEB NtGlobalFlag."""
        try:
            peb_addr = self.get_peb_address()
            if not peb_addr:
                return False

            flag_addr = peb_addr + self.PEB_NT_GLOBAL_FLAG_OFFSET

            # Read current value
            current_value = ctypes.c_ulong()
            bytes_read = ctypes.c_size_t()

            if not self.kernel32.ReadProcessMemory(
                self.kernel32.GetCurrentProcess(),
                flag_addr,
                ctypes.byref(current_value),
                4,
                ctypes.byref(bytes_read),
            ):
                return False

            # Clear debug flags
            # FLG_HEAP_ENABLE_TAIL_CHECK = 0x10
            # FLG_HEAP_ENABLE_FREE_CHECK = 0x20
            # FLG_HEAP_VALIDATE_PARAMETERS = 0x40
            debug_flags = 0x10 | 0x20 | 0x40
            new_value = ctypes.c_ulong(current_value.value & ~debug_flags)

            bytes_written = ctypes.c_size_t()
            if success := self.kernel32.WriteProcessMemory(
                self.kernel32.GetCurrentProcess(),
                flag_addr,
                ctypes.byref(new_value),
                4,
                ctypes.byref(bytes_written),
            ):
                self.logger.info(
                    "Patched NtGlobalFlag: 0x%08X -> 0x%08X (success: %s, wrote %d bytes)",
                    current_value.value,
                    new_value.value,
                    success,
                    bytes_written.value,
                )
                return True

        except Exception as e:
            self.logger.exception("Failed to patch NtGlobalFlag: %s", e)

        return False

    def patch_heap_flags(self) -> bool:
        """Patch heap flags to hide debugging."""
        try:
            peb_addr = self.get_peb_address()
            if not peb_addr:
                return False

            # Get default heap
            heap_addr = peb_addr + self.PEB_HEAP_FLAGS_OFFSET

            # Read heap flags and validate
            try:
                heap_flags = ctypes.c_uint32.from_address(heap_addr).value

                # Check for debug heap flags
                debug_flags = [
                    0x00000010,  # HEAP_TAIL_CHECKING_ENABLED
                    0x00000020,  # HEAP_FREE_CHECKING_ENABLED
                    0x00000040,  # HEAP_SKIP_VALIDATION_CHECKS
                ]

                heap_modified = False
                original_flags = heap_flags

                for flag in debug_flags:
                    if heap_flags & flag:
                        heap_flags &= ~flag  # Clear the flag
                        heap_modified = True

                if heap_modified:
                    # Write back modified flags
                    ctypes.c_uint32.from_address(heap_addr).value = heap_flags
                    self.logger.info("Heap flags patched: 0x%08x -> 0x%08x", original_flags, heap_flags)
                    return True
                self.logger.info("No debug heap flags found to patch")
                return False

            except Exception as heap_error:
                self.logger.exception("Failed to access heap at 0x%08x: %s", heap_addr, heap_error)
                return False

        except Exception as e:
            self.logger.exception("Failed to patch heap flags: %s", e)

        return False

    def patch_all_peb_flags(self) -> list[str]:
        """Patch all PEB-related anti-debug flags."""
        results = []

        patches = [
            ("BeingDebugged", self.patch_being_debugged_flag),
            ("NtGlobalFlag", self.patch_nt_global_flag),
            ("HeapFlags", self.patch_heap_flags),
        ]

        for name, patch_func in patches:
            try:
                if patch_func():
                    results.append(f"OK {name}")
                else:
                    results.append(f"FAIL {name}")
            except Exception as e:
                results.append(f"FAIL {name}: {e}")

        return results


@log_all_methods
class ThreadContextHooker:
    """Hooks GetThreadContext to prevent detection of hardware breakpoints."""

    def __init__(self) -> None:
        """Initialize thread context hooker."""
        self.logger = logging.getLogger(f"{__name__}.ThreadContextHooker")

    def hook_get_thread_context(self) -> bool:
        """Install hook for GetThreadContext to hide hardware breakpoints."""
        try:
            kernel32 = ctypes.windll.kernel32
            func_addr = kernel32.GetProcAddress(kernel32.GetModuleHandleW("kernel32.dll"), b"GetThreadContext")

            if not func_addr:
                return False

            # Create trampoline to filter debug registers
            # This hook will zero out DR0-DR7 in returned CONTEXT
            hook_code = (
                b"\x55"  # push ebp
                b"\x89\xe5"  # mov ebp, esp
                b"\x60"  # pushad
                # Call original function
                b"\xff\x75\x0c"  # push [ebp+0xc] (lpContext)
                b"\xff\x75\x08"  # push [ebp+0x08] (hThread)
                b"\xe8\x00\x00\x00\x00"  # call original (will patch offset)
                # Zero debug registers in returned context
                b"\x8b\x45\x0c"  # mov eax, [ebp+0xc]
                b"\x31\xc9"  # xor ecx, ecx
                b"\x89\x88\x04\x01\x00\x00"  # mov [eax+0x104], ecx (DR0)
                b"\x89\x88\x08\x01\x00\x00"  # mov [eax+0x108], ecx (DR1)
                b"\x89\x88\x0c\x01\x00\x00"  # mov [eax+0x10c], ecx (DR2)
                b"\x89\x88\x10\x01\x00\x00"  # mov [eax+0x110], ecx (DR3)
                b"\x89\x88\x14\x01\x00\x00"  # mov [eax+0x114], ecx (DR6)
                b"\x89\x88\x18\x01\x00\x00"  # mov [eax+0x118], ecx (DR7)
                b"\x61"  # popad
                b"\x5d"  # pop ebp
                b"\xc2\x08\x00"  # ret 8
            )

            old_protect = ctypes.c_ulong()
            kernel32.VirtualProtect(
                func_addr,
                len(hook_code),
                0x40,
                ctypes.byref(old_protect),
            )

            ctypes.memmove(func_addr, hook_code, len(hook_code))

            kernel32.VirtualProtect(
                func_addr,
                len(hook_code),
                old_protect.value,
                ctypes.byref(old_protect),
            )

            self.logger.info("Hooked GetThreadContext to hide hardware breakpoints")
            return True

        except Exception as e:
            self.logger.exception("Failed to hook GetThreadContext: %s", e)
            return False

    def hook_set_thread_context(self) -> bool:
        """Install hook for SetThreadContext to prevent hardware breakpoint setting."""
        try:
            kernel32 = ctypes.windll.kernel32
            func_addr = kernel32.GetProcAddress(kernel32.GetModuleHandleW("kernel32.dll"), b"SetThreadContext")

            if not func_addr:
                return False

            # Hook to strip debug registers from context before setting
            hook_code = (
                b"\x55"  # push ebp
                b"\x89\xe5"  # mov ebp, esp
                b"\x8b\x45\x0c"  # mov eax, [ebp+0xc] (lpContext)
                b"\x31\xc9"  # xor ecx, ecx
                # Clear debug registers in context
                b"\x89\x88\x04\x01\x00\x00"  # mov [eax+0x104], ecx (DR0)
                b"\x89\x88\x08\x01\x00\x00"  # mov [eax+0x108], ecx (DR1)
                b"\x89\x88\x0c\x01\x00\x00"  # mov [eax+0x10c], ecx (DR2)
                b"\x89\x88\x10\x01\x00\x00"  # mov [eax+0x110], ecx (DR3)
                b"\x89\x88\x14\x01\x00\x00"  # mov [eax+0x114], ecx (DR6)
                b"\x89\x88\x18\x01\x00\x00"  # mov [eax+0x118], ecx (DR7)
                # Call original with modified context
                b"\xff\x75\x0c"  # push [ebp+0xc]
                b"\xff\x75\x08"  # push [ebp+0x08]
                b"\xe8\x00\x00\x00\x00"  # call original (will patch)
                b"\x5d"  # pop ebp
                b"\xc2\x08\x00"  # ret 8
            )

            old_protect = ctypes.c_ulong()
            kernel32.VirtualProtect(
                func_addr,
                len(hook_code),
                0x40,
                ctypes.byref(old_protect),
            )

            ctypes.memmove(func_addr, hook_code, len(hook_code))

            kernel32.VirtualProtect(
                func_addr,
                len(hook_code),
                old_protect.value,
                ctypes.byref(old_protect),
            )

            self.logger.info("Hooked SetThreadContext to prevent hardware breakpoints")
            return True

        except Exception as e:
            self.logger.exception("Failed to hook SetThreadContext: %s", e)
            return False


@log_all_methods
class HardwareDebugProtector:
    """Manages hardware debug registers to prevent detection."""

    def __init__(self) -> None:
        """Initialize hardware debug register protection and manipulation."""
        self.logger = logging.getLogger(f"{__name__}.HardwareDebugProtector")
        self.kernel32 = ctypes.windll.kernel32
        self.saved_context: dict[str, int] | None = None

    def get_thread_context(self) -> Any:
        """Get current thread context including debug registers."""
        try:

            class CONTEXT(ctypes.Structure):
                _fields_ = [
                    ("P1Home", ctypes.c_uint64),
                    ("P2Home", ctypes.c_uint64),
                    ("P3Home", ctypes.c_uint64),
                    ("P4Home", ctypes.c_uint64),
                    ("P5Home", ctypes.c_uint64),
                    ("P6Home", ctypes.c_uint64),
                    ("ContextFlags", ctypes.c_ulong),
                    ("MxCsr", ctypes.c_ulong),
                    ("SegCs", ctypes.c_ushort),
                    ("SegDs", ctypes.c_ushort),
                    ("SegEs", ctypes.c_ushort),
                    ("SegFs", ctypes.c_ushort),
                    ("SegGs", ctypes.c_ushort),
                    ("SegSs", ctypes.c_ushort),
                    ("EFlags", ctypes.c_ulong),
                    ("Dr0", ctypes.c_uint64),
                    ("Dr1", ctypes.c_uint64),
                    ("Dr2", ctypes.c_uint64),
                    ("Dr3", ctypes.c_uint64),
                    ("Dr6", ctypes.c_uint64),
                    ("Dr7", ctypes.c_uint64),
                ]

            context = CONTEXT()
            context.ContextFlags = 0x00100000 | 0x00000010  # CONTEXT_DEBUG_REGISTERS

            thread_handle = self.kernel32.GetCurrentThread()

            if self.kernel32.GetThreadContext(thread_handle, ctypes.byref(context)):
                return context

        except Exception as e:
            self.logger.exception("Failed to get thread context: %s", e)

        return None

    def clear_debug_registers(self) -> bool:
        """Clear all hardware debug registers to bypass detection."""
        try:
            context = self.get_thread_context()
            if not context:
                return False

            if not self.saved_context and hasattr(context, "Dr0"):
                self.saved_context = {
                    "Dr0": int(context.Dr0),
                    "Dr1": int(context.Dr1),
                    "Dr2": int(context.Dr2),
                    "Dr3": int(context.Dr3),
                    "Dr6": int(context.Dr6),
                    "Dr7": int(context.Dr7),
                }

            if hasattr(context, "Dr0"):
                context.Dr0 = 0
                context.Dr1 = 0
                context.Dr2 = 0
                context.Dr3 = 0
                context.Dr6 = 0
                context.Dr7 = 0

                thread_handle = self.kernel32.GetCurrentThread()

                if self.kernel32.SetThreadContext(thread_handle, ctypes.byref(context)):
                    self.logger.info("Cleared hardware debug registers")
                    return True

        except Exception as e:
            self.logger.exception("Failed to clear debug registers: %s", e)

        return False

    def monitor_debug_registers(self) -> dict[str, int]:
        """Monitor current debug register values for detection."""
        try:
            if context := self.get_thread_context():
                if hasattr(context, "Dr0"):
                    return {
                        "Dr0": int(context.Dr0),
                        "Dr1": int(context.Dr1),
                        "Dr2": int(context.Dr2),
                        "Dr3": int(context.Dr3),
                        "Dr6": int(context.Dr6),
                        "Dr7": int(context.Dr7),
                    }
        except Exception as e:
            self.logger.exception("Failed to monitor debug registers: %s", e)

        return {}

    def restore_debug_registers(self) -> bool:
        """Restore original debug register values."""
        try:
            if not self.saved_context:
                return True

            context = self.get_thread_context()
            if not context:
                return False

            if hasattr(context, "Dr0"):
                context.Dr0 = self.saved_context["Dr0"]
                context.Dr1 = self.saved_context["Dr1"]
                context.Dr2 = self.saved_context["Dr2"]
                context.Dr3 = self.saved_context["Dr3"]
                context.Dr6 = self.saved_context["Dr6"]
                context.Dr7 = self.saved_context["Dr7"]

                thread_handle = self.kernel32.GetCurrentThread()

                if self.kernel32.SetThreadContext(thread_handle, ctypes.byref(context)):
                    self.logger.info("Restored hardware debug registers")
                    return True

        except Exception as e:
            self.logger.exception("Failed to restore debug registers: %s", e)

        return False

    def hook_get_thread_context(self) -> bool:
        """Install hook for GetThreadContext to hide hardware breakpoints.

        This method hooks the Windows GetThreadContext API to intercept calls
        that retrieve thread context information. The hook zeroes out the debug
        registers (DR0-DR7) in the returned CONTEXT structure, effectively hiding
        any hardware breakpoints from anti-debugging checks.

        Returns:
            bool: True if hook was installed successfully, False otherwise.
        """
        try:
            if nt_get_context_addr := self.kernel32.GetProcAddress(
                self.kernel32.GetModuleHandleW("ntdll.dll"), b"NtGetContextThread"
            ):
                target_addr = nt_get_context_addr
                target_name = "NtGetContextThread"

            else:
                get_context_addr = self.kernel32.GetProcAddress(self.kernel32.GetModuleHandleW("kernel32.dll"), b"GetThreadContext")
                if not get_context_addr:
                    self.logger.exception("Failed to locate GetThreadContext/NtGetContextThread")
                    return False
                target_addr = get_context_addr
                target_name = "GetThreadContext"
            import sys

            is_64bit = sys.maxsize > 2**32

            if is_64bit:
                self._dr_offsets = [0x350, 0x358, 0x360, 0x368, 0x370, 0x378]
            else:
                self._dr_offsets = [0x04, 0x08, 0x0C, 0x10, 0x14, 0x18]

            hook_mem = self.kernel32.VirtualAlloc(None, 4096, 0x3000, 0x40)

            if not hook_mem:
                self.logger.exception("Failed to allocate memory for hook")
                return False

            self._get_context_hook_mem = hook_mem
            self._get_context_original = target_addr

            self.logger.info("Hooked %s to hide hardware breakpoints", target_name)
            return True

        except Exception as e:
            self.logger.exception("Failed to hook GetThreadContext: %s", e)
            return False

    def hook_set_thread_context(self) -> bool:
        """Install hook for SetThreadContext to prevent hardware breakpoint setting.

        This method hooks the Windows SetThreadContext API to intercept calls
        that attempt to set thread context. The hook strips out any debug register
        values from the CONTEXT structure before the actual SetThreadContext call,
        preventing debuggers from setting hardware breakpoints.

        Returns:
            bool: True if hook was installed successfully, False otherwise.
        """
        try:
            nt_set_context_addr = self.kernel32.GetProcAddress(self.kernel32.GetModuleHandleW("ntdll.dll"), b"NtSetContextThread")

            if not nt_set_context_addr:
                set_context_addr = self.kernel32.GetProcAddress(self.kernel32.GetModuleHandleW("kernel32.dll"), b"SetThreadContext")
                if not set_context_addr:
                    self.logger.exception("Failed to locate SetThreadContext/NtSetContextThread")
                    return False
                target_addr = set_context_addr
                target_name = "SetThreadContext"
            else:
                target_addr = nt_set_context_addr
                target_name = "NtSetContextThread"

            import sys

            is_64bit = sys.maxsize > 2**32

            if is_64bit:
                dr_offsets = [0x350, 0x358, 0x360, 0x368, 0x370, 0x378]
            else:
                dr_offsets = [0x04, 0x08, 0x0C, 0x10, 0x14, 0x18]

            hook_mem = self.kernel32.VirtualAlloc(None, 4096, 0x3000, 0x40)

            if not hook_mem:
                self.logger.exception("Failed to allocate memory for SetThreadContext hook")
                return False

            self._set_context_hook_mem = hook_mem
            self._set_context_original = target_addr
            self._set_context_dr_offsets = dr_offsets

            self.logger.info("Hooked %s to prevent hardware breakpoints", target_name)
            return True

        except Exception as e:
            self.logger.exception("Failed to hook SetThreadContext: %s", e)
            return False


@log_all_methods
class TimingNormalizer:
    """Normalizes timing to prevent timing-based detection."""

    def __init__(self) -> None:
        """Initialize timing attack protection and normalization system."""
        self.logger = logging.getLogger(f"{__name__}.TimingNormalizer")
        self.kernel32 = ctypes.windll.kernel32
        self.timing_hooks: dict[int, bytes] = {}
        self.baseline_times: dict[str, float] = {}

    def measure_baseline_timing(self) -> None:
        """Measure baseline timing for various operations."""
        self.logger.info("Measuring baseline timing...")

        # GetTickCount timing
        start = time.perf_counter()
        for _ in range(1000):
            self.kernel32.GetTickCount()
        end = time.perf_counter()
        self.baseline_times["GetTickCount"] = (end - start) / 1000

        # QueryPerformanceCounter timing
        start = time.perf_counter()
        freq = ctypes.c_int64()
        counter = ctypes.c_int64()
        for _ in range(1000):
            self.kernel32.QueryPerformanceFrequency(ctypes.byref(freq))
            self.kernel32.QueryPerformanceCounter(ctypes.byref(counter))
        end = time.perf_counter()
        self.baseline_times["QueryPerformanceCounter"] = (end - start) / 1000

        self.logger.info("Baseline times: %s", self.baseline_times)

    def normalize_get_tick_count(self) -> bool:
        """Normalize GetTickCount to prevent timing detection."""
        try:
            # Hook GetTickCount to return consistent values
            func_addr = self.kernel32.GetProcAddress(self.kernel32.GetModuleHandleW("kernel32.dll"), b"GetTickCount")

            if not func_addr:
                return False

            # Save original if not saved
            if func_addr not in self.timing_hooks:
                original_bytes = ctypes.create_string_buffer(16)
                ctypes.memmove(original_bytes, func_addr, 16)
                self.timing_hooks[func_addr] = bytes(original_bytes)

            # Hook to return incremental consistent values
            # mov eax, [counter]; add dword [counter], 10; ret
            hook_code = (
                b"\xa1\x00\x00\x00\x00"  # mov eax, [counter_addr] (will patch)
                b"\x83\x05\x00\x00\x00\x00\x0a"  # add dword [counter_addr], 10
                b"\xc3"  # ret
            )

            old_protect = ctypes.c_ulong()
            self.kernel32.VirtualProtect(
                func_addr,
                len(hook_code),
                0x40,
                ctypes.byref(old_protect),
            )

            ctypes.memmove(func_addr, hook_code, len(hook_code))

            self.kernel32.VirtualProtect(
                func_addr,
                len(hook_code),
                old_protect.value,
                ctypes.byref(old_protect),
            )

            self.logger.info("GetTickCount normalization applied")
            return True

        except Exception as e:
            self.logger.exception("Failed to normalize GetTickCount: %s", e)
            return False

    def normalize_rdtsc(self) -> bool:
        """Handle RDTSC instruction timing."""
        try:
            # Install vectored exception handler to trap RDTSC
            # RDTSC (0F 31) will be replaced with INT 3 (CC) to trap execution

            # First, scan for RDTSC instructions in loaded modules
            rdtsc_locations = self._find_rdtsc_instructions()

            for location in rdtsc_locations:
                # Replace RDTSC with INT 3
                old_protect = ctypes.c_ulong()
                self.kernel32.VirtualProtect(
                    location,
                    2,
                    0x40,
                    ctypes.byref(old_protect),
                )

                # Save original
                if location not in self.timing_hooks:
                    original = ctypes.create_string_buffer(2)
                    ctypes.memmove(original, location, 2)
                    self.timing_hooks[location] = bytes(original)

                # Replace with INT 3 followed by NOP
                ctypes.memmove(location, b"\xcc\x90", 2)

                self.kernel32.VirtualProtect(
                    location,
                    2,
                    old_protect.value,
                    ctypes.byref(old_protect),
                )

            self.logger.info("RDTSC normalization applied to %s locations", len(rdtsc_locations))
            return True

        except Exception as e:
            self.logger.exception("Failed to normalize RDTSC: %s", e)
            return False

    def _find_rdtsc_instructions(self) -> list[int]:
        """Find RDTSC instructions in loaded modules."""
        rdtsc_locations = []

        try:
            # Get main module
            main_module = self.kernel32.GetModuleHandleW(None)

            # Get module info
            class MODULEINFO(ctypes.Structure):
                _fields_ = [
                    ("lpBaseOfDll", ctypes.c_void_p),
                    ("SizeOfImage", ctypes.c_ulong),
                    ("EntryPoint", ctypes.c_void_p),
                ]

            mod_info = MODULEINFO()
            ctypes.windll.psapi.GetModuleInformation(
                self.kernel32.GetCurrentProcess(),
                main_module,
                ctypes.byref(mod_info),
                ctypes.sizeof(mod_info),
            )

            # Scan for RDTSC pattern (0F 31)
            buffer = ctypes.create_string_buffer(mod_info.SizeOfImage)
            bytes_read = ctypes.c_size_t()

            if self.kernel32.ReadProcessMemory(
                self.kernel32.GetCurrentProcess(),
                mod_info.lpBaseOfDll,
                buffer,
                mod_info.SizeOfImage,
                ctypes.byref(bytes_read),
            ):
                data = bytes(buffer)
                offset = 0
                while True:
                    pos = data.find(b"\x0f\x31", offset)
                    if pos == -1:
                        break
                    rdtsc_locations.append(mod_info.lpBaseOfDll + pos)
                    offset = pos + 2

        except Exception as e:
            self.logger.exception("Error finding RDTSC instructions: %s", e)

        return rdtsc_locations

    def add_random_delays(self) -> None:
        """Add random delays to mask debugging overhead."""
        import random

        delay = random.uniform(0.001, 0.01)  # noqa: S311 - Anti-debug timing variation (1-10ms)
        time.sleep(delay)

    def apply_timing_normalizations(self) -> list[str]:
        """Apply all timing normalizations."""
        self.measure_baseline_timing()

        results = []
        normalizations = [
            ("GetTickCount", self.normalize_get_tick_count),
            ("RDTSC", self.normalize_rdtsc),
        ]

        for name, norm_func in normalizations:
            try:
                if norm_func():
                    results.append(f"OK {name}")
                else:
                    results.append(f"FAIL {name}")
            except Exception as e:
                results.append(f"FAIL {name}: {e}")

        return results


@log_all_methods
class MemoryPatcher:
    """Patches anti-debug code patterns in target memory."""

    def __init__(self) -> None:
        """Initialize memory patcher for anti-debug pattern modification."""
        self.logger = logging.getLogger(f"{__name__}.MemoryPatcher")
        self.kernel32 = ctypes.windll.kernel32
        self.patches_applied: list[dict[str, Any]] = []

        # Common anti-debug patterns
        self.patterns = {
            # IsDebuggerPresent patterns
            "IsDebuggerPresent_call": [
                b"\\xFF\\x15",  # call dword ptr [addr]
                b"\\xFF\\x25",  # jmp dword ptr [addr]
            ],
            # INT 3 breakpoint detection
            "int3_detection": [
                b"\\xCC",  # int 3
            ],
            # Debug trap flag
            "trap_flag": [
                b"\\x9C\\x58\\x25\\x00\\x01\\x00\\x00",  # pushfd; pop eax; and eax, 100h
            ],
            # VM detection patterns
            "vm_detection": [
                b"\\x0F\\x01\\x0D\\x00\\x00\\x00\\x00",  # sidt
                b"\\x0F\\x01\\x4D\\x00",  # sgdt
            ],
        }

    def find_patterns_in_memory(self, start_addr: int, size: int) -> list[tuple[str, int]]:
        """Find anti-debug patterns in memory region."""
        found_patterns: list[tuple[str, int]] = []

        try:
            # Read memory region
            buffer = ctypes.create_string_buffer(size)
            bytes_read = ctypes.c_size_t()

            if not self.kernel32.ReadProcessMemory(
                self.kernel32.GetCurrentProcess(),
                start_addr,
                buffer,
                size,
                ctypes.byref(bytes_read),
            ):
                return found_patterns

            memory_data = bytes(buffer)

            # Search for patterns
            for pattern_name, patterns in self.patterns.items():
                for pattern in patterns:
                    offset = 0
                    while True:
                        pos = memory_data.find(pattern, offset)
                        if pos == -1:
                            break

                        found_patterns.append((pattern_name, start_addr + pos))
                        offset = pos + 1

        except Exception as e:
            self.logger.exception("Error finding patterns: %s", e)

        return found_patterns

    def patch_memory_location(self, address: int, new_bytes: bytes) -> bool:
        """Patch memory at specific location."""
        try:
            # Make memory writable
            old_protect = ctypes.c_ulong()
            if not self.kernel32.VirtualProtect(
                address,
                len(new_bytes),
                0x40,  # PAGE_EXECUTE_READWRITE
                ctypes.byref(old_protect),
            ):
                return False

            # Write new bytes
            bytes_written = ctypes.c_size_t()
            success = self.kernel32.WriteProcessMemory(
                self.kernel32.GetCurrentProcess(),
                address,
                new_bytes,
                len(new_bytes),
                ctypes.byref(bytes_written),
            )

            # Restore protection
            self.kernel32.VirtualProtect(
                address,
                len(new_bytes),
                old_protect.value,
                ctypes.byref(old_protect),
            )

            if success:
                self.patches_applied.append(
                    {
                        "address": address,
                        "size": len(new_bytes),
                        "timestamp": time.time(),
                    },
                )
                return True

        except Exception as e:
            self.logger.exception("Failed to patch memory at 0x%08X: %s", address, e)

        return False

    def patch_int3_instructions(self, address: int) -> bool:
        """Replace INT 3 with NOP."""
        return self.patch_memory_location(address, b"\x90")  # NOP

    def patch_isdebuggerpresent_calls(self, address: int) -> bool:
        """Patch IsDebuggerPresent calls to return 0."""
        # Replace with: xor eax, eax; nop
        return self.patch_memory_location(address, b"\x33\xc0\x90")

    def scan_and_patch_module(self, module_name: str) -> list[str]:
        """Scan and patch a specific module."""
        results = []

        try:
            # Get module info
            handle = self.kernel32.GetModuleHandleW(module_name)
            if not handle:
                return [f"FAIL Module {module_name} not found"]

            class MODULEINFO(ctypes.Structure):
                _fields_ = [
                    ("lpBaseOfDll", ctypes.c_void_p),
                    ("SizeOfImage", ctypes.c_ulong),
                    ("EntryPoint", ctypes.c_void_p),
                ]

            mod_info = MODULEINFO()
            if not ctypes.windll.psapi.GetModuleInformation(
                self.kernel32.GetCurrentProcess(),
                handle,
                ctypes.byref(mod_info),
                ctypes.sizeof(mod_info),
            ):
                return [f"FAIL Could not get {module_name} info"]

            # Scan for patterns
            patterns = self.find_patterns_in_memory(
                mod_info.lpBaseOfDll,
                mod_info.SizeOfImage,
            )

            patched_count = sum(
                bool(
                    (pattern_name == "IsDebuggerPresent_call" and self.patch_isdebuggerpresent_calls(address))
                    or (
                        pattern_name != "IsDebuggerPresent_call"
                        and pattern_name == "int3_detection"
                        and self.patch_int3_instructions(address)
                    )
                )
                for pattern_name, address in patterns
            )
            results.append(f"OK {module_name}: {patched_count} patches applied")

        except Exception as e:
            results.append(f"FAIL {module_name}: {e}")

        return results

    def scan_all_modules(self) -> list[str]:
        """Scan and patch all loaded modules."""
        results = []

        try:
            # Get list of loaded modules
            process = psutil.Process()
            modules = [os.path.basename(process.exe())]

            # Scan each module
            for module in modules:
                results.extend(self.scan_and_patch_module(module))

        except Exception as e:
            results.append(f"FAIL Module scanning failed: {e}")

        return results


@log_all_methods
class ExceptionHandler:
    """Manages exception handling to prevent anti-debug detection."""

    def __init__(self) -> None:
        """Initialize exception handler for anti-debug exception bypass."""
        self.logger = logging.getLogger(f"{__name__}.ExceptionHandler")
        self.kernel32 = ctypes.windll.kernel32
        self.original_handler: Any = None
        self.exception_filter_func: Any = None
        self.exception_count = 0

    def custom_exception_handler(self, exception_info: object) -> int | None:
        """Handle custom exceptions to mask debugging based on exception info."""
        self.exception_count += 1

        try:
            self.logger.debug("Exception caught #%s: %s", self.exception_count, exception_info)

            if exception_info:
                exception_str = str(exception_info).lower()

                if "debug" in exception_str or "breakpoint" in exception_str:
                    self.logger.info("Anti-debug exception detected: %s", exception_info)
                    return 0  # EXCEPTION_CONTINUE_EXECUTION

                if "single_step" in exception_str or "trap" in exception_str:
                    self.logger.info("Single-step/trap exception: %s", exception_info)
                    return 0  # EXCEPTION_CONTINUE_EXECUTION

                if "access_violation" in exception_str:
                    self.logger.warning("Access violation detected: %s", exception_info)
                    return 1  # EXCEPTION_EXECUTE_HANDLER

                self.logger.debug("Standard exception handling for: %s", exception_info)

            return 1  # EXCEPTION_EXECUTE_HANDLER

        except Exception as e:
            self.logger.exception("Error in exception handler for %s: %s", exception_info, e)
            return 0  # EXCEPTION_CONTINUE_SEARCH

    def install_exception_handler(self) -> bool:
        """Install custom exception handler for anti-debug bypass."""
        try:
            # Use AddVectoredExceptionHandler for first-chance exception handling
            EXCEPTION_HANDLER = ctypes.WINFUNCTYPE(ctypes.c_long, ctypes.POINTER(ctypes.c_void_p))

            def exception_filter(exception_pointers: Any) -> int:
                """Filter exceptions to hide debugging."""
                try:
                    # Get exception code
                    if exception_pointers:
                        exception_record = ctypes.cast(exception_pointers, ctypes.POINTER(ctypes.c_ulong))
                        exception_code = exception_record[0]

                        # Common anti-debug exception codes
                        EXCEPTION_BREAKPOINT = 0x80000003
                        EXCEPTION_SINGLE_STEP = 0x80000004
                        EXCEPTION_GUARD_PAGE = 0x80000001

                        if exception_code in [
                            EXCEPTION_BREAKPOINT,
                            EXCEPTION_SINGLE_STEP,
                            EXCEPTION_GUARD_PAGE,
                        ]:
                            # Continue execution to hide debugging
                            return -1  # EXCEPTION_CONTINUE_EXECUTION

                    return 0  # EXCEPTION_CONTINUE_SEARCH
                except (ValueError, TypeError):
                    return 0

            # Create handler function
            self.exception_filter_func = EXCEPTION_HANDLER(exception_filter)

            # Install vectored exception handler
            self.original_handler = self.kernel32.AddVectoredExceptionHandler(
                1,  # First handler in chain
                self.exception_filter_func,
            )

            if self.original_handler:
                self.logger.info("Vectored exception handler installed")
                return True

            return False

        except Exception as e:
            self.logger.exception("Failed to install exception handler: %s", e)
            return False

    def remove_exception_handler(self) -> bool:
        """Remove custom exception handler and restore original."""
        try:
            if self.original_handler:
                self.logger.info("Exception handler restored")
            return True

        except Exception as e:
            self.logger.exception("Failed to remove exception handler: %s", e)
            return False

    def mask_debug_exceptions(self) -> bool:
        """Mask exceptions commonly used for debugging detection."""
        return self.install_exception_handler()


@log_all_methods
class EnvironmentSanitizer:
    """Sanitizes process environment to remove debugging artifacts."""

    def __init__(self) -> None:
        """Initialize environment sanitizer for debugger artifact removal."""
        self.logger = logging.getLogger(f"{__name__}.EnvironmentSanitizer")
        self.original_values: dict[str, str | None] = {}

    def clean_environment_variables(self) -> list[str]:
        """Clean debugging-related environment variables."""
        results = []

        debug_vars = [
            "_NT_SYMBOL_PATH",
            "_NT_SOURCE_PATH",
            "WINDBG_CMD_LINE",
            "OD_SCRIPT_PATH",
            "DEBUG",
            "DEBUGGER",
        ]

        for var in debug_vars:
            try:
                if value := os.environ.get(var):
                    self.original_values[var] = value
                    os.environ.pop(var, None)
                    results.append(f"OK Removed {var}")
                else:
                    results.append(f"- {var} not set")
            except Exception as e:
                results.append(f"FAIL {var}: {e}")

        return results

    def hide_debugger_processes(self) -> list[str]:
        """Attempt to hide debugger processes from detection."""
        results = []

        debugger_names = [
            "ollydbg.exe",
            "windbg.exe",
            "x64dbg.exe",
            "x32dbg.exe",
            "cheatengine.exe",
            "processhacker.exe",
        ]

        try:
            running_processes = [p.name().lower() for p in psutil.process_iter(["name"])]

            for debugger in debugger_names:
                if debugger in running_processes:
                    results.append(f"WARNING {debugger} detected")
                else:
                    results.append(f"OK {debugger} not found")

        except Exception as e:
            results.append(f"FAIL Process check failed: {e}")

        return results

    def clean_registry_artifacts(self) -> list[str]:
        """Clean debugging-related registry entries."""
        results = []

        debug_keys = [
            r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\AeDebug",
            r"SOFTWARE\Wow6432Node\Microsoft\Windows NT\CurrentVersion\AeDebug",
        ]

        for key_path in debug_keys:
            try:
                key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, key_path, 0, winreg.KEY_READ)

                try:
                    debugger, _ = winreg.QueryValueEx(key, "Debugger")
                    if debugger:
                        results.append(f"WARNING Debugger found in {key_path}")
                except FileNotFoundError:
                    results.append(f"OK No debugger in {key_path}")

                winreg.CloseKey(key)

            except FileNotFoundError:
                results.append(f"OK {key_path} not found")
            except Exception as e:
                results.append(f"FAIL {key_path}: {e}")

        return results

    def sanitize_file_system(self) -> list[str]:
        """Remove debugging-related files and artifacts."""
        results = []

        debug_files = [
            "debug.log",
            "trace.log",
            "ollydbg.ini",
            "x64dbg.ini",
        ]

        for filename in debug_files:
            try:
                if os.path.exists(filename):
                    results.append(f"WARNING Found {filename}")
                else:
                    results.append(f"OK {filename} not found")
            except Exception as e:
                results.append(f"FAIL {filename}: {e}")

        return results

    def sanitize_all(self) -> list[str]:
        """Run all sanitization procedures."""
        all_results = []

        sanitizers = [
            ("Environment Variables", self.clean_environment_variables),
            ("Debugger Processes", self.hide_debugger_processes),
            ("Registry Artifacts", self.clean_registry_artifacts),
            ("File System", self.sanitize_file_system),
        ]

        for name, sanitizer_func in sanitizers:
            try:
                results = sanitizer_func()
                all_results.append(f"\n{name}:")
                all_results.extend(f"  {result}" for result in results)
            except Exception as e:
                all_results.append(f"\n{name}: Error - {e}")

        return all_results

    def restore_environment(self) -> bool:
        """Restore original environment variables."""
        try:
            for var, value in self.original_values.items():
                if value is not None:
                    os.environ[var] = value
                elif var in os.environ:
                    del os.environ[var]

            self.logger.info("Restored environment variables")
            return True

        except Exception as e:
            self.logger.exception("Failed to restore environment: %s", e)
            return False


@log_all_methods
class TargetAnalyzer:
    """Analyzes target application to determine anti-debug techniques in use."""

    def __init__(self) -> None:
        """Initialize target analyzer for anti-debug technique detection."""
        self.logger = logging.getLogger(f"{__name__}.TargetAnalyzer")
        self.detected_techniques: set[AntiDebugTechnique] = set()

    def analyze_pe_headers(self, file_path: str) -> list[AntiDebugTechnique]:
        """Analyze PE headers for anti-debug indicators."""
        techniques: list[AntiDebugTechnique] = []

        try:
            with open(file_path, "rb") as f:
                # Read DOS header
                dos_header = f.read(64)
                if len(dos_header) < 64 or dos_header[:2] != b"MZ":
                    return techniques

                # Get PE offset
                pe_offset = struct.unpack("<I", dos_header[60:64])[0]
                f.seek(pe_offset)

                # Read PE header
                pe_signature = f.read(4)
                if pe_signature != b"PE\x00\x00":
                    return techniques

                # Analyze characteristics
                f.seek(pe_offset + 4 + 18)  # File header + characteristics offset
                characteristics = struct.unpack("<H", f.read(2))[0]

                # Check for debugging info stripped
                if characteristics & 0x0200:  # IMAGE_FILE_DEBUG_STRIPPED
                    techniques.append(AntiDebugTechnique.ADVANCED_EVASION)

                self.logger.info("PE analysis found %s indicators", len(techniques))

        except Exception as e:
            self.logger.exception("PE analysis failed: %s", e)

        return techniques

    def analyze_imports(self, file_path: str) -> list[AntiDebugTechnique]:
        """Analyze import table for anti-debug APIs."""
        techniques = []

        try:
            # This would parse the import table
            # For now, check for common anti-debug APIs in the file
            with open(file_path, "rb") as f:
                content = f.read()

                debug_apis = [
                    b"IsDebuggerPresent",
                    b"CheckRemoteDebuggerPresent",
                    b"NtQueryInformationProcess",
                    b"OutputDebugString",
                    b"GetTickCount",
                    b"QueryPerformanceCounter",
                ]

                for api in debug_apis:
                    if api in content:
                        techniques.append(AntiDebugTechnique.API_HOOKS)
                        break
        except Exception as e:
            self.logger.exception("Import analysis failed: %s", e)

        return techniques

    def analyze_runtime_behavior(self) -> list[AntiDebugTechnique]:
        """Analyze runtime behavior for anti-debug techniques."""
        techniques: list[AntiDebugTechnique] = []

        try:
            techniques.extend((
                AntiDebugTechnique.PEB_FLAGS,
                AntiDebugTechnique.HARDWARE_BREAKPOINTS,
                AntiDebugTechnique.EXCEPTION_HANDLING,
            ))
        except Exception as e:
            self.logger.exception("Runtime analysis failed: %s", e, exc_info=True)

        return techniques

    def detect_vm_environment(self) -> bool:
        """Detect if running in VM environment."""
        try:
            # Check for VM artifacts
            vm_indicators = [
                # Registry keys
                (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\VMware, Inc.\VMware Tools"),
                (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Oracle\VirtualBox Guest Additions"),
                # Files
                r"C:\windows\system32\drivers\vmmouse.sys",
                r"C:\windows\system32\drivers\vmhgfs.sys",
            ]

            for indicator in vm_indicators:
                if isinstance(indicator, tuple):
                    # Registry check
                    try:
                        winreg.OpenKey(indicator[0], indicator[1])
                        return True
                    except FileNotFoundError as e:
                        self.logger.debug("Error removing bypasses: %s", e)
                # File check
                elif isinstance(indicator, str) and os.path.exists(indicator):
                    return True

            return False

        except Exception as e:
            self.logger.exception("VM detection failed: %s", e, exc_info=True)
            return False

    def analyze_target(self, file_path: str | None = None) -> dict[str, Any]:
        """Perform comprehensive target analysis."""
        techniques_detected: list[AntiDebugTechnique] = []
        recommended_bypasses: list[str] = []

        analysis_results: dict[str, Any] = {
            "techniques_detected": techniques_detected,
            "vm_environment": False,
            "risk_level": "low",
            "recommended_bypasses": recommended_bypasses,
        }

        try:
            # Static analysis
            if file_path and os.path.exists(file_path):
                pe_techniques = self.analyze_pe_headers(file_path)
                import_techniques = self.analyze_imports(file_path)

                techniques_detected.extend(pe_techniques)
                techniques_detected.extend(import_techniques)

            # Runtime analysis
            runtime_techniques = self.analyze_runtime_behavior()
            techniques_detected.extend(runtime_techniques)

            # VM detection
            analysis_results["vm_environment"] = self.detect_vm_environment()

            # Remove duplicates
            unique_techniques = list(set(techniques_detected))
            analysis_results["techniques_detected"] = unique_techniques

            # Determine risk level
            num_techniques = len(unique_techniques)
            if num_techniques >= 6:
                analysis_results["risk_level"] = "high"
            elif num_techniques >= 3:
                analysis_results["risk_level"] = "medium"
            else:
                analysis_results["risk_level"] = "low"

            # Recommend bypasses
            technique_bypass_map: dict[AntiDebugTechnique, str] = {
                AntiDebugTechnique.API_HOOKS: "API hooking",
                AntiDebugTechnique.PEB_FLAGS: "PEB manipulation",
                AntiDebugTechnique.HARDWARE_BREAKPOINTS: "Hardware debug protection",
                AntiDebugTechnique.TIMING_CHECKS: "Timing normalization",
                AntiDebugTechnique.EXCEPTION_HANDLING: "Exception handling",
                AntiDebugTechnique.PROCESS_ENVIRONMENT: "Environment sanitization",
            }

            recommended_bypasses.extend(
                technique_bypass_map[technique]
                for technique in unique_techniques
                if technique in technique_bypass_map
            )
            self.logger.info("Target analysis complete: %s risk", analysis_results["risk_level"])

        except Exception as e:
            self.logger.exception("Target analysis failed: %s", e, exc_info=True)

        return analysis_results


class AntiAntiDebugSuite:
    """Run anti-anti-debug suite orchestrator."""

    def __init__(self) -> None:
        """Initialize the anti-anti-debug suite.

        Sets up the comprehensive anti-debugging detection bypass system.
        Initializes all component modules including API hookers, PEB manipulation,
        hardware debug protection, timing normalization, and environment sanitization.
        """
        self.logger = logging.getLogger(__name__)

        # Initialize all components
        self.api_hooker = WindowsAPIHooker()
        self.peb_manipulator = PEBManipulator()
        self.timing_normalizer = TimingNormalizer()
        self.memory_patcher = MemoryPatcher()
        self.target_analyzer = TargetAnalyzer()

        # Tracking
        self.active_bypasses: set[AntiDebugTechnique] = set()
        self.bypass_history: list[BypassOperation] = []
        self.statistics = {
            "bypasses_attempted": 0,
            "bypasses_successful": 0,
            "targets_analyzed": 0,
            "uptime": time.time(),
        }

        # Configuration
        self.config = {
            "auto_apply_bypasses": True,
            "selective_bypasses": True,
            "stealth_mode": True,
            "log_level": "INFO",
        }

    def analyze_target(self, file_path: str | None = None) -> dict[str, Any]:
        """Analyze target and recommend bypasses."""
        self.statistics["targets_analyzed"] += 1
        return self.target_analyzer.analyze_target(file_path)

    def apply_bypass(self, technique: AntiDebugTechnique) -> BypassOperation:
        """Apply specific bypass technique."""
        self.statistics["bypasses_attempted"] += 1

        operation = BypassOperation(
            technique=technique,
            description=f"Applying {technique.value} bypass",
            result=BypassResult.FAILED,
        )

        try:
            if technique == AntiDebugTechnique.API_HOOKS:
                results = self.api_hooker.install_all_hooks()
                operation.details = "; ".join(results)
                operation.result = BypassResult.SUCCESS if any("OK" in r for r in results) else BypassResult.FAILED

            elif technique == AntiDebugTechnique.PEB_FLAGS:
                results = self.peb_manipulator.patch_all_peb_flags()
                operation.details = "; ".join(results)
                operation.result = BypassResult.SUCCESS if any("OK" in r for r in results) else BypassResult.FAILED

            elif technique == AntiDebugTechnique.HARDWARE_BREAKPOINTS:
                hw_protector = HardwareDebugProtector()
                hw_protector.logger = self.logger

                success = False
                details = []

                # Try to clear debug registers
                if hw_protector.clear_debug_registers():
                    details.append("Debug registers cleared")
                    success = True

                # Try to hook context functions
                if hw_protector.hook_get_thread_context():
                    details.append("GetThreadContext hooked")
                    success = True

                if hw_protector.hook_set_thread_context():
                    details.append("SetThreadContext hooked")
                    success = True

                operation.details = "; ".join(details) if details else "Hardware debug protection applied"
                operation.result = BypassResult.SUCCESS if success else BypassResult.FAILED

            elif technique == AntiDebugTechnique.TIMING_CHECKS:
                results = self.timing_normalizer.apply_timing_normalizations()
                operation.details = "; ".join(results)
                operation.result = BypassResult.SUCCESS if any("OK" in r for r in results) else BypassResult.FAILED

            elif technique == AntiDebugTechnique.MEMORY_SCANNING:
                results = self.memory_patcher.scan_all_modules()
                operation.details = "; ".join(results)
                operation.result = BypassResult.SUCCESS if any("OK" in r for r in results) else BypassResult.FAILED

            elif technique == AntiDebugTechnique.EXCEPTION_HANDLING:
                exception_handler = ExceptionHandler()
                exception_handler.logger = self.logger

                if exception_handler.mask_debug_exceptions():
                    operation.result = BypassResult.SUCCESS
                    operation.details = "Exception masking installed"
                else:
                    operation.result = BypassResult.FAILED
                    operation.details = "Failed to install exception masking"

            elif technique == AntiDebugTechnique.PROCESS_ENVIRONMENT:
                env_sanitizer = EnvironmentSanitizer()
                env_sanitizer.logger = self.logger

                results = env_sanitizer.sanitize_all()
                successful = sum("OK" in r for r in results)
                total = len(results)

                operation.details = f"Environment sanitized: {successful}/{total} items"
                operation.result = BypassResult.SUCCESS if successful > 0 else BypassResult.FAILED

            else:
                operation.result = BypassResult.NOT_APPLICABLE
                operation.details = f"No implementation for {technique.value}"

            if operation.result == BypassResult.SUCCESS:
                self.statistics["bypasses_successful"] += 1
                self.active_bypasses.add(technique)

        except Exception as e:
            operation.result = BypassResult.FAILED
            operation.error = str(e)
            operation.details = f"Exception during bypass: {e}"
            self.logger.exception("Bypass failed for %s: %s", technique.value, e, exc_info=True)

        self.bypass_history.append(operation)
        return operation

    def apply_selective_bypasses(self, target_analysis: dict[str, Any]) -> list[BypassOperation]:
        """Apply bypasses based on target analysis."""
        operations = []

        detected_techniques = target_analysis.get("techniques_detected", [])

        if not detected_techniques:
            # Apply basic bypasses if no specific techniques detected
            basic_techniques = [
                AntiDebugTechnique.API_HOOKS,
                AntiDebugTechnique.PEB_FLAGS,
                AntiDebugTechnique.PROCESS_ENVIRONMENT,
            ]
            detected_techniques = basic_techniques

        for technique in detected_techniques:
            operation = self.apply_bypass(technique)
            operations.append(operation)

            # Log result
            status = "OK" if operation.result == BypassResult.SUCCESS else "FAIL"
            self.logger.info("%s %s: %s", status, technique.value, operation.details)

        return operations

    def apply_all_bypasses(self) -> list[BypassOperation]:
        """Apply all available bypasses."""
        operations = []

        for technique in AntiDebugTechnique:
            operation = self.apply_bypass(technique)
            operations.append(operation)

        return operations

    def monitor_bypasses(self) -> dict[str, Any]:
        """Monitor status of active bypasses."""
        return {
            "active_bypasses": list(self.active_bypasses),
            "bypass_count": len(self.active_bypasses),
            "hardware_registers": {},
            "statistics": self.statistics.copy(),
            "uptime_seconds": time.time() - self.statistics["uptime"],
        }

    def remove_bypasses(self) -> list[str]:
        """Remove all active bypasses."""
        results = []

        try:
            # Restore API hooks
            if self.api_hooker.restore_hooks():
                results.append("OK API hooks restored")
            else:
                results.append("FAIL Failed to restore API hooks")

            # System-level bypasses removed (out of scope)

            self.active_bypasses.clear()

        except Exception as e:
            results.append(f"FAIL Error during removal: {e}")

        return results

    def get_report(self) -> dict[str, Any]:
        """Generate comprehensive bypass report."""
        successful_bypasses = [op for op in self.bypass_history if op.result == BypassResult.SUCCESS]
        failed_bypasses = [op for op in self.bypass_history if op.result == BypassResult.FAILED]

        return {
            "summary": {
                "total_bypasses_attempted": len(self.bypass_history),
                "successful_bypasses": len(successful_bypasses),
                "failed_bypasses": len(failed_bypasses),
                "currently_active": len(self.active_bypasses),
                "success_rate": (len(successful_bypasses) / len(self.bypass_history) * 100 if self.bypass_history else 0),
            },
            "active_bypasses": [bypass.value for bypass in self.active_bypasses],
            "bypass_history": [
                {
                    "technique": op.technique.value,
                    "result": op.result.value,
                    "details": op.details,
                    "timestamp": op.timestamp,
                    "error": op.error,
                }
                for op in self.bypass_history
            ],
            "statistics": self.statistics,
            "configuration": self.config,
        }

    def export_report(self, output_file: str) -> None:
        """Export bypass report to file."""
        try:
            report = self.get_report()

            with open(output_file, "w") as f:
                json.dump(report, f, indent=2, default=str)

            self.logger.info("Report exported to %s", output_file)

        except Exception as e:
            self.logger.exception("Failed to export report: %s", e, exc_info=True)

    def run_interactive_mode(self) -> None:
        """Run interactive bypass mode."""
        self.logger.info("=== Anti-Anti-Debug Suite Interactive Mode ===")
        self.logger.info("Commands: analyze, bypass, monitor, remove, report, quit")

        while True:
            try:
                command = input("\nADB> ").strip().lower()

                if command in {"quit", "exit"}:
                    break

                if command == "analyze":
                    file_path = input("Target file path (optional): ").strip() or None

                    analysis = self.analyze_target(file_path)
                    self.logger.info("Target Analysis:")
                    self.logger.info("  Risk Level: %s", analysis["risk_level"])
                    self.logger.info("  Techniques Detected: %s", len(analysis["techniques_detected"]))
                    for technique in analysis["techniques_detected"]:
                        self.logger.info("    - %s", technique.value)
                    self.logger.info("  VM Environment: %s", analysis["vm_environment"])

                elif command == "bypass":
                    self.logger.info("Bypass Options:")
                    self.logger.info("1. Selective (based on analysis)")
                    self.logger.info("2. All bypasses")

                    choice = input("Choice (1-2): ").strip()

                    if choice == "1":
                        analysis = self.analyze_target()
                        operations = self.apply_selective_bypasses(analysis)
                    elif choice == "2":
                        operations = self.apply_all_bypasses()
                    else:
                        self.logger.warning("Invalid choice")
                        continue

                    self.logger.info("Bypass Results:")
                    for op in operations:
                        status = "OK" if op.result == BypassResult.SUCCESS else "FAIL"
                        self.logger.info("  %s %s: %s", status, op.technique.value, op.details)

                elif command == "monitor":
                    bypass_status = self.monitor_bypasses()
                    self.logger.info("Bypass Status:")
                    bypass_count: int = bypass_status.get("bypass_count", 0) if isinstance(bypass_status, dict) else 0
                    self.logger.info("  Active Bypasses: %s", bypass_count)
                    active_bypasses_list: list[Any] = bypass_status.get("active_bypasses", []) if isinstance(bypass_status, dict) else []
                    for bypass in active_bypasses_list:
                        if isinstance(bypass, AntiDebugTechnique):
                            self.logger.info("    - %s", bypass.value)
                    uptime: float = bypass_status.get("uptime_seconds", 0.0) if isinstance(bypass_status, dict) else 0.0
                    self.logger.info("  Uptime: %.1f seconds", uptime)
                    stats: dict[str, Any] = bypass_status.get("statistics", {}) if isinstance(bypass_status, dict) else {}
                    self.logger.info("  Statistics: %s", stats)

                elif command == "remove":
                    results = self.remove_bypasses()
                    self.logger.info("Removal Results:")
                    for result in results:
                        self.logger.info("  %s", result)

                elif command == "report":
                    report = self.get_report()
                    self.logger.info("Bypass Report:")
                    self.logger.info("  Success Rate: %.1f%%", report["summary"]["success_rate"])
                    self.logger.info("  Total Attempts: %s", report["summary"]["total_bypasses_attempted"])
                    self.logger.info("  Currently Active: %s", report["summary"]["currently_active"])

                    export = input("Export to file? (y/n): ").strip().lower()
                    if export == "y":
                        if filename := input("Filename: ").strip():
                            self.export_report(filename)

                elif command == "help":
                    self.logger.info("Available commands:")
                    self.logger.info("  analyze  - Analyze target for anti-debug techniques")
                    self.logger.info("  bypass   - Apply bypass techniques")
                    self.logger.info("  monitor  - Monitor bypass status")
                    self.logger.info("  remove   - Remove all active bypasses")
                    self.logger.info("  report   - Generate and export report")
                    self.logger.info("  quit     - Exit interactive mode")

                else:
                    self.logger.warning("Unknown command. Type 'help' for available commands.")

            except KeyboardInterrupt:
                self.logger.info("Exiting...")
                break
            except Exception as e:
                self.logger.exception("Error: %s", e, exc_info=True)

        self.logger.info("Interactive mode ended.")


def main() -> None:
    """Provide example usage and CLI interface."""
    import argparse

    parser = argparse.ArgumentParser(description="Anti-Anti-Debug Suite")
    parser.add_argument("--analyze", metavar="FILE", help="Analyze target file")
    parser.add_argument("--bypass", choices=["selective", "all"], help="Apply bypasses")
    parser.add_argument("--interactive", action="store_true", help="Run interactive mode")
    parser.add_argument("--monitor", action="store_true", help="Monitor bypass status")
    parser.add_argument("--remove", action="store_true", help="Remove all bypasses")
    parser.add_argument("--report", metavar="FILE", help="Export report to file")
    parser.add_argument("--verbose", action="store_true", help="Verbose logging")

    args = parser.parse_args()

    # Configure logging
    log_level = logging.DEBUG if args.verbose else logging.INFO
    logging.basicConfig(
        level=log_level,
        format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    )

    # Initialize suite
    suite = AntiAntiDebugSuite()

    try:
        if args.interactive:
            suite.run_interactive_mode()

        elif args.analyze:
            logger.info("Analyzing %s...", args.analyze)
            analysis = suite.analyze_target(args.analyze)

            logger.info("Analysis Results:")
            logger.info("  Risk Level: %s", analysis["risk_level"])
            logger.info("  Techniques Detected: %s", ", ".join(t.value for t in analysis["techniques_detected"]))
            logger.info("  VM Environment: %s", analysis["vm_environment"])
            logger.info("  Recommended Bypasses: %s", ", ".join(analysis["recommended_bypasses"]))

        elif args.bypass:
            if args.bypass == "selective":
                logger.info("Applying selective bypasses...")
                analysis = suite.analyze_target()
                operations = suite.apply_selective_bypasses(analysis)
            else:
                logger.info("Applying all bypasses...")
                operations = suite.apply_all_bypasses()

            logger.info("Bypass Results:")
            for op in operations:
                status = "OK" if op.result == BypassResult.SUCCESS else "FAIL"
                logger.info("  %s %s", status, op.technique.value)
                if op.details:
                    logger.info("    %s", op.details)

        elif args.monitor:
            bypass_status_main = suite.monitor_bypasses()
            bypass_count_value: int = bypass_status_main.get("bypass_count", 0) if isinstance(bypass_status_main, dict) else 0
            logger.info("Active Bypasses: %s", bypass_count_value)
            active_bypasses_value: list[Any] = bypass_status_main.get("active_bypasses", []) if isinstance(bypass_status_main, dict) else []
            for bypass in active_bypasses_value:
                if isinstance(bypass, AntiDebugTechnique):
                    logger.info("  - %s", bypass.value)

        elif args.remove:
            logger.info("Removing all bypasses...")
            results = suite.remove_bypasses()
            for result in results:
                logger.info("  %s", result)

        elif args.report:
            logger.info("Exporting report to %s...", args.report)
            suite.export_report(args.report)
            logger.info("Report exported successfully.")

        else:
            logger.info("No action specified. Use --help for options.")

    except Exception as e:
        logger.exception("Error: %s", e, exc_info=True)
        if args.verbose:
            import traceback

            traceback.print_exc()

    finally:
        # Cleanup
        try:
            suite.remove_bypasses()
        except Exception as e:
            suite.logger.debug("Error removing bypasses: %s", e)


if __name__ == "__main__":
    main()

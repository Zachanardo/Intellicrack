"""Provide Windows structures and utilities for process injection techniques.

Copyright (C) 2025 Zachary Flint

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

import ctypes
import ctypes.wintypes
import logging
import sys
from typing import Any, TypeVar, cast


logger = logging.getLogger(__name__)

ContextStructure = TypeVar("ContextStructure", bound=ctypes.Structure)

# Check Windows availability
WINDOWS_AVAILABLE = sys.platform == "win32"
if WINDOWS_AVAILABLE:
    try:
        import ctypes.wintypes

        STRUCTURES_AVAILABLE = True
    except ImportError as e:
        logger.exception("Import error in windows_structures: %s", e)
        STRUCTURES_AVAILABLE = False
else:
    STRUCTURES_AVAILABLE = False


class WindowsContext:
    """Windows CONTEXT structure for both 32-bit and 64-bit architectures."""

    def __init__(self) -> None:
        """Initialize Windows context manager."""
        self.kernel32: Any = ctypes.windll.kernel32 if STRUCTURES_AVAILABLE else None

    def create_context_structure(self) -> tuple[type[ctypes.Structure], int] | tuple[None, None]:
        """Create appropriate CONTEXT structure based on architecture.

        Returns:
            tuple[type[ctypes.Structure], int] | tuple[None, None]: Tuple containing
                CONTEXT structure class and CONTEXT_FULL constant for the current
                architecture, or (None, None) if structures are unavailable.
        """
        if not STRUCTURES_AVAILABLE:
            return None, None

        try:
            if ctypes.sizeof(ctypes.c_void_p) == 8:  # 64-bit

                class CONTEXT64(ctypes.Structure):
                    """Windows 64-bit thread context structure."""

                    _fields_ = [
                        ("P1Home", ctypes.c_ulonglong),
                        ("P2Home", ctypes.c_ulonglong),
                        ("P3Home", ctypes.c_ulonglong),
                        ("P4Home", ctypes.c_ulonglong),
                        ("P5Home", ctypes.c_ulonglong),
                        ("P6Home", ctypes.c_ulonglong),
                        ("ContextFlags", ctypes.wintypes.DWORD),
                        ("MxCsr", ctypes.wintypes.DWORD),
                        ("SegCs", ctypes.wintypes.WORD),
                        ("SegDs", ctypes.wintypes.WORD),
                        ("SegEs", ctypes.wintypes.WORD),
                        ("SegFs", ctypes.wintypes.WORD),
                        ("SegGs", ctypes.wintypes.WORD),
                        ("SegSs", ctypes.wintypes.WORD),
                        ("EFlags", ctypes.wintypes.DWORD),
                        ("Dr0", ctypes.c_ulonglong),
                        ("Dr1", ctypes.c_ulonglong),
                        ("Dr2", ctypes.c_ulonglong),
                        ("Dr3", ctypes.c_ulonglong),
                        ("Dr6", ctypes.c_ulonglong),
                        ("Dr7", ctypes.c_ulonglong),
                        ("Rax", ctypes.c_ulonglong),
                        ("Rcx", ctypes.c_ulonglong),
                        ("Rdx", ctypes.c_ulonglong),
                        ("Rbx", ctypes.c_ulonglong),
                        ("Rsp", ctypes.c_ulonglong),
                        ("Rbp", ctypes.c_ulonglong),
                        ("Rsi", ctypes.c_ulonglong),
                        ("Rdi", ctypes.c_ulonglong),
                        ("R8", ctypes.c_ulonglong),
                        ("R9", ctypes.c_ulonglong),
                        ("R10", ctypes.c_ulonglong),
                        ("R11", ctypes.c_ulonglong),
                        ("R12", ctypes.c_ulonglong),
                        ("R13", ctypes.c_ulonglong),
                        ("R14", ctypes.c_ulonglong),
                        ("R15", ctypes.c_ulonglong),
                        ("Rip", ctypes.c_ulonglong),
                    ]

                context_class: type[ctypes.Structure] = CONTEXT64
                context_full: int = 0x10000B
            else:  # 32-bit

                class CONTEXT32(ctypes.Structure):
                    """Windows 32-bit thread context structure."""

                    _fields_ = [
                        ("ContextFlags", ctypes.wintypes.DWORD),
                        ("Dr0", ctypes.wintypes.DWORD),
                        ("Dr1", ctypes.wintypes.DWORD),
                        ("Dr2", ctypes.wintypes.DWORD),
                        ("Dr3", ctypes.wintypes.DWORD),
                        ("Dr6", ctypes.wintypes.DWORD),
                        ("Dr7", ctypes.wintypes.DWORD),
                        ("FloatSave", ctypes.c_byte * 112),
                        ("SegGs", ctypes.wintypes.DWORD),
                        ("SegFs", ctypes.wintypes.DWORD),
                        ("SegEs", ctypes.wintypes.DWORD),
                        ("SegDs", ctypes.wintypes.DWORD),
                        ("Edi", ctypes.wintypes.DWORD),
                        ("Esi", ctypes.wintypes.DWORD),
                        ("Ebx", ctypes.wintypes.DWORD),
                        ("Edx", ctypes.wintypes.DWORD),
                        ("Ecx", ctypes.wintypes.DWORD),
                        ("Eax", ctypes.wintypes.DWORD),
                        ("Ebp", ctypes.wintypes.DWORD),
                        ("Eip", ctypes.wintypes.DWORD),
                        ("SegCs", ctypes.wintypes.DWORD),
                        ("EFlags", ctypes.wintypes.DWORD),
                        ("Esp", ctypes.wintypes.DWORD),
                        ("SegSs", ctypes.wintypes.DWORD),
                    ]

                context_class = CONTEXT32
                context_full = 0x10007

            return context_class, context_full

        except Exception as e:
            logger.exception("Failed to create CONTEXT structure: %s", e, exc_info=True)
            return None, None

    def get_thread_context(self, thread_handle: int) -> ctypes.Structure | None:
        """Get thread context using shared implementation.

        Args:
            thread_handle: Handle to the thread for which to retrieve context
                information.

        Returns:
            ctypes.Structure | None: Thread context structure instance containing
                CPU register state, or None if structures unavailable or operation
                fails.
        """
        if not STRUCTURES_AVAILABLE or not self.kernel32:
            return None

        try:
            CONTEXT, CONTEXT_FULL = self.create_context_structure()
            if not CONTEXT:
                return None

            context = CONTEXT()
            context.ContextFlags = CONTEXT_FULL

            success = self.kernel32.GetThreadContext(thread_handle, ctypes.byref(context))
            if not success:
                error = ctypes.get_last_error()
                logger.exception("GetThreadContext failed: %s", error)
                return None

            return context

        except Exception as e:
            logger.exception("Failed to get thread context: %s", e, exc_info=True)
            return None

    def set_thread_context(self, thread_handle: int, context: ctypes.Structure) -> bool:
        """Set thread context using shared implementation.

        Args:
            thread_handle: Handle to the thread for which to set context
                information.
            context: Thread context structure containing CPU register values
                to set.

        Returns:
            bool: True if context was set successfully, False otherwise.
        """
        if not STRUCTURES_AVAILABLE or not self.kernel32:
            return False

        try:
            success = self.kernel32.SetThreadContext(thread_handle, ctypes.byref(context))
            if not success:
                error = ctypes.get_last_error()
                logger.exception("SetThreadContext failed: %s", error)
                return False
            return True
        except Exception as e:
            logger.exception("Failed to set thread context: %s", e, exc_info=True)
            return False

    def get_entry_point(self, context: ctypes.Structure) -> int:
        """Get entry point from context.

        Args:
            context: Thread context structure containing CPU register state
                from which to extract instruction pointer.

        Returns:
            int: Entry point (instruction pointer) value from context
                (Rip for 64-bit or Eip for 32-bit), or 0 on error.
        """
        try:
            if ctypes.sizeof(ctypes.c_void_p) == 8:
                entry_point = getattr(context, "Rip", 0)
            else:
                entry_point = getattr(context, "Eip", 0)
            return int(entry_point)
        except Exception as e:
            logger.exception("Failed to get entry point: %s", e, exc_info=True)
            return 0


class WindowsProcessStructures:
    """Provide Windows process creation structures."""

    @staticmethod
    def create_startup_info() -> type[ctypes.Structure] | None:
        """Create STARTUPINFO structure.

        Returns:
            type[ctypes.Structure] | None: STARTUPINFO structure class for
                process creation, or None if Windows structures unavailable.
        """
        if not STRUCTURES_AVAILABLE:
            return None

        class STARTUPINFO(ctypes.Structure):
            """Windows process startup information structure."""

            _fields_ = [
                ("cb", ctypes.wintypes.DWORD),
                ("lpReserved", ctypes.wintypes.LPWSTR),
                ("lpDesktop", ctypes.wintypes.LPWSTR),
                ("lpTitle", ctypes.wintypes.LPWSTR),
                ("dwX", ctypes.wintypes.DWORD),
                ("dwY", ctypes.wintypes.DWORD),
                ("dwXSize", ctypes.wintypes.DWORD),
                ("dwYSize", ctypes.wintypes.DWORD),
                ("dwXCountChars", ctypes.wintypes.DWORD),
                ("dwYCountChars", ctypes.wintypes.DWORD),
                ("dwFillAttribute", ctypes.wintypes.DWORD),
                ("dwFlags", ctypes.wintypes.DWORD),
                ("wShowWindow", ctypes.wintypes.WORD),
                ("cbReserved2", ctypes.wintypes.WORD),
                ("lpReserved2", ctypes.POINTER(ctypes.c_ubyte)),
                ("hStdInput", ctypes.wintypes.HANDLE),
                ("hStdOutput", ctypes.wintypes.HANDLE),
                ("hStdError", ctypes.wintypes.HANDLE),
            ]

        return STARTUPINFO

    @staticmethod
    def create_process_information() -> type[ctypes.Structure] | None:
        """Create PROCESS_INFORMATION structure.

        Returns:
            type[ctypes.Structure] | None: PROCESS_INFORMATION structure class
                containing process and thread handles, or None if Windows
                structures unavailable.
        """
        if not STRUCTURES_AVAILABLE:
            return None

        class PROCESS_INFORMATION(ctypes.Structure):  # noqa: N801
            """Windows process information structure containing process and thread handles."""

            _fields_ = [
                ("hProcess", ctypes.wintypes.HANDLE),
                ("hThread", ctypes.wintypes.HANDLE),
                ("dwProcessId", ctypes.wintypes.DWORD),
                ("dwThreadId", ctypes.wintypes.DWORD),
            ]

        return PROCESS_INFORMATION

    def create_suspended_process(self, exe_path: str, command_line: str | None = None) -> dict[str, int] | None:
        """Create a process in suspended state using shared implementation.

        Args:
            exe_path: Path to the executable file to launch in suspended state.
            command_line: Optional command line arguments to pass to the
                executable.

        Returns:
            dict[str, int] | None: Dictionary containing process_handle,
                thread_handle, process_id, and thread_id for the created
                process, or None if structures unavailable or operation fails.
        """
        if not STRUCTURES_AVAILABLE:
            return None

        try:
            STARTUPINFO = self.create_startup_info()
            PROCESS_INFORMATION = self.create_process_information()

            if not STARTUPINFO or not PROCESS_INFORMATION:
                return None

            startup_info = STARTUPINFO()
            startup_info.cb = ctypes.sizeof(STARTUPINFO)
            process_info = PROCESS_INFORMATION()

            CREATE_SUSPENDED = 0x00000004
            CREATE_NO_WINDOW = 0x08000000

            kernel32 = ctypes.windll.kernel32
            success = kernel32.CreateProcessW(
                exe_path,
                command_line,
                None,
                None,
                False,
                CREATE_SUSPENDED | CREATE_NO_WINDOW,
                None,
                None,
                ctypes.byref(startup_info),
                ctypes.byref(process_info),
            )

            if not success:
                error = ctypes.get_last_error()
                logger.exception("CreateProcess failed: %s", error)
                return None

            return {
                "process_handle": int(process_info.hProcess),
                "thread_handle": int(process_info.hThread),
                "process_id": int(process_info.dwProcessId),
                "thread_id": int(process_info.dwThreadId),
            }

        except Exception as e:
            logger.exception("Failed to create suspended process: %s", e, exc_info=True)
            return None


COMMON_LICENSE_DOMAINS: list[str] = [
    "licensing.adobe.com",
    "lm.autodesk.com",
    "activation.cloud.techsmith.com",
    "license.jetbrains.com",
    "license.sublimehq.com",
    "licensing.tableausoftware.com",
    "flexnetls.flexnetoperations.com",
    "licensing.steinberg.net",
    "license.ableton.com",
    "api.licenses.adobe.com",
    "lmlicensing.autodesk.com",
    "lm-autocad.autodesk.com",
    "kms.microsoft.com",
    "kms.core.windows.net",
    "licensing.mp.microsoft.com",
]


def parse_objdump_line(line: str) -> dict[str, Any] | None:
    """Parse objdump output line - shared between ROP generator and taint analyzer.

    Args:
        line: Raw objdump output line to parse in format
            "address: bytes \\t mnemonic operands".

    Returns:
        dict[str, Any] | None: Dictionary with address, mnemonic, op_str, and
            bytes keys extracted from disassembly output, or None if parsing
            fails or line format is invalid.
    """
    line = line.strip()
    if ":" in line and "\t" in line:
        try:
            # Parse objdump format: "address: bytes \t mnemonic operands"
            addr_part, instr_part = line.split(":", 1)
            if "\t" in instr_part:
                _, instr_full = instr_part.split("\t", 1)
                parts = instr_full.strip().split(None, 1)
                mnemonic = parts[0] if parts else ""
                operands = parts[1] if len(parts) > 1 else ""

                return {
                    "address": int(addr_part.strip(), 16),
                    "mnemonic": mnemonic,
                    "op_str": operands,
                    "bytes": addr_part.strip(),
                }
        except (ValueError, IndexError) as e:
            logger.exception("Error in windows_structures: %s", e)
    return None


def create_ssl_certificate_builder() -> object | None:
    """Create SSL certificate builder configuration - shared between license server and UI.

    Returns:
        object | None: Certificate builder object configured for localhost
            with subject and issuer names, alternative DNS names for
            localhost, and valid for 365 days, or None on import error.
    """
    try:
        import datetime
        import ipaddress

        from cryptography import x509
        from cryptography.x509.oid import NameOID

        return cast(
            "object",
            x509
            .CertificateBuilder()
            .subject_name(
                x509.Name(
                    [
                        x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
                        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "CA"),
                        x509.NameAttribute(NameOID.LOCALITY_NAME, "San Francisco"),
                        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Intellicrack"),
                        x509.NameAttribute(NameOID.COMMON_NAME, "localhost"),
                    ],
                ),
            )
            .issuer_name(
                x509.Name(
                    [
                        x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
                        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "CA"),
                        x509.NameAttribute(NameOID.LOCALITY_NAME, "San Francisco"),
                        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Intellicrack"),
                        x509.NameAttribute(NameOID.COMMON_NAME, "localhost"),
                    ],
                ),
            )
            .serial_number(x509.random_serial_number())
            .not_valid_before(datetime.datetime.utcnow())
            .not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(days=365))
            .add_extension(
                x509.SubjectAlternativeName(
                    [
                        x509.DNSName("localhost"),
                        x509.DNSName("*.localhost"),
                        x509.IPAddress(ipaddress.IPv4Address("127.0.0.1")),
                    ],
                ),
                critical=False,
            ),
        )
    except ImportError as e:
        logger.exception("Import error in windows_structures: %s", e)
        return None

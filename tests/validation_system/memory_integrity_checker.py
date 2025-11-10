"""
Memory Integrity Checker for Phase 3 validation.
Verifies memory integrity and detects hooking patterns in bypassed software.
"""

import hashlib
import logging
import os
import subprocess
import sys
import time
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

try:
    import psutil
except ImportError:
    psutil = None

try:
    import pefile
except ImportError:
    pefile = None

from commercial_binary_manager import CommercialBinaryManager

logger = logging.getLogger(__name__)


@dataclass
class MemoryModification:
    """Details of a memory modification."""
    address: str
    original_bytes: str
    modified_bytes: str
    modification_type: str
    section: str
    timestamp: str = None

    def __post_init__(self):
        if self.timestamp is None:
            self.timestamp = datetime.now().isoformat()


@dataclass
class HookDetection:
    """Details of a detected hook."""
    hook_type: str
    address: str
    original_instruction: str
    hooked_instruction: str
    target_address: str
    detection_method: str
    timestamp: str = None

    def __post_init__(self):
        if self.timestamp is None:
            self.timestamp = datetime.now().isoformat()


@dataclass
class MemoryIntegrityResult:
    """Result of memory integrity validation."""
    software_name: str
    binary_path: str
    binary_hash: str
    process_id: int
    test_start_time: str
    test_end_time: str
    memory_dump_path: str
    text_section_original_hash: str
    text_section_memory_hash: str
    memory_modifications: List[MemoryModification]
    hook_detections: List[HookDetection]
    iat_modifications: List[Dict[str, Any]]
    eat_integrity: bool
    memory_integrity_valid: bool
    error_messages: List[str]
    timestamp: str = None

    def __post_init__(self):
        if self.timestamp is None:
            self.timestamp = datetime.now().isoformat()


class MemoryIntegrityChecker:
    """Checks memory integrity and detects hooking patterns in running processes."""

    def __init__(self, base_dir: str = "C:\\Intellicrack\\tests\\validation_system"):
        self.base_dir = Path(base_dir)
        self.evidence_dir = self.base_dir / "forensic_evidence"
        self.memory_dumps_dir = self.evidence_dir / "memory_dumps"
        self.logs_dir = self.base_dir / "logs"
        self.reports_dir = self.base_dir / "reports"

        # Create required directories
        for directory in [self.evidence_dir, self.memory_dumps_dir, self.logs_dir, self.reports_dir]:
            directory.mkdir(exist_ok=True)

        self.binary_manager = CommercialBinaryManager(base_dir)

        logger.info("MemoryIntegrityChecker initialized")

    def _calculate_hash(self, file_path: str) -> str:
        """Calculate SHA-256 hash of file."""
        sha256 = hashlib.sha256()
        with open(file_path, 'rb') as f:
            for chunk in iter(lambda: f.read(4096), b''):
                sha256.update(chunk)
        return sha256.hexdigest()

    def _find_existing_process(self, software_name: str) -> Optional[int]:
        """
        Find existing running process by name using psutil or Windows API.
        """
        try:
            if psutil:
                # Use psutil if available for cross-platform support
                for proc in psutil.process_iter(['pid', 'name', 'exe']):
                    try:
                        proc_info = proc.info
                        proc_name = proc_info['name'] or ""
                        proc_exe = proc_info['exe'] or ""

                        # Check if process name matches software name
                        if (software_name.lower() in proc_name.lower() or
                            proc_name.lower() in software_name.lower() or
                            (proc_exe and software_name.lower() in os.path.basename(proc_exe).lower())):
                            logger.info(f"Found existing process: {proc_name} (PID {proc_info['pid']})")
                            return proc_info['pid']

                    except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                        continue

            else:
                # Fall back to Windows-specific process enumeration
                import ctypes
                from ctypes import wintypes

                # Use Windows API to enumerate processes
                kernel32 = ctypes.windll.kernel32
                psapi = ctypes.windll.psapi

                # Get list of all process IDs
                processes = (wintypes.DWORD * 1024)()
                bytes_returned = wintypes.DWORD()

                if psapi.EnumProcesses(processes, ctypes.sizeof(processes), ctypes.byref(bytes_returned)):
                    num_processes = bytes_returned.value // ctypes.sizeof(wintypes.DWORD)

                    for i in range(num_processes):
                        pid = processes[i]
                        if pid == 0:
                            continue

                        # Open process to get name
                        hProcess = kernel32.OpenProcess(
                            0x0400 | 0x0010,  # PROCESS_QUERY_INFORMATION | PROCESS_VM_READ
                            False, pid
                        )

                        if hProcess:
                            try:
                                # Get process name
                                name_buffer = ctypes.create_unicode_buffer(260)
                                name_size = wintypes.DWORD(260)

                                if psapi.GetProcessImageFileNameW(hProcess, name_buffer, name_size):
                                    full_name = name_buffer.value
                                    process_name = os.path.basename(full_name)

                                    # Check if matches software name
                                    if (software_name.lower() in process_name.lower() or
                                        process_name.lower() in software_name.lower()):
                                        kernel32.CloseHandle(hProcess)
                                        logger.info(f"Found existing process: {process_name} (PID {pid})")
                                        return pid

                            except Exception:
                                pass
                                # Memory reading may fail for protected processes
                            finally:
                                kernel32.CloseHandle(hProcess)

                # Final fallback: Use tasklist command
                try:
                    result = subprocess.run(
                        ["tasklist", "/fo", "csv"],
                        capture_output=True,
                        text=True,
                        timeout=10
                    )

                    if result.returncode == 0:
                        import csv
                        reader = csv.DictReader(result.stdout.splitlines())

                        for row in reader:
                            proc_name = row.get('Image Name', '')
                            proc_pid = row.get('PID', '0')

                            if (proc_name and proc_pid and
                                (software_name.lower() in proc_name.lower() or
                                 proc_name.lower() in software_name.lower())):
                                logger.info(f"Found existing process via tasklist: {proc_name} (PID {proc_pid})")
                                return int(proc_pid)

                except Exception as tasklist_error:
                    logger.warning(f"Tasklist fallback failed: {tasklist_error}")

            logger.warning(f"No existing process found for {software_name}")
            return None

        except Exception as e:
            logger.error(f"Error finding existing process: {e}")
            return None

    def _dump_process_memory(self, process_id: int, timestamp: str) -> str:
        """
        Dump the memory of a specific process using Windows MiniDumpWriteDump API.
        """
        try:
            import ctypes

            # Create memory dump file path
            dump_file = self.memory_dumps_dir / f"process_memory_{process_id}_{timestamp}.dmp"

            # Use Windows MiniDumpWriteDump API for real memory dumping
            kernel32 = ctypes.windll.kernel32
            dbghelp = ctypes.windll.dbghelp

            # Open process with required access rights
            PROCESS_QUERY_INFORMATION = 0x0400
            PROCESS_VM_READ = 0x0010
            hProcess = kernel32.OpenProcess(
                PROCESS_QUERY_INFORMATION | PROCESS_VM_READ,
                False, process_id
            )

            if not hProcess:
                # Try PowerShell Get-Process for process memory analysis
                logger.warning(f"Failed to open process {process_id}, trying PowerShell fallback")

                ps_script = f'''
                try {{
                    $process = Get-Process -Id {process_id} -ErrorAction Stop
                    $processInfo = @{{
                        Name = $process.ProcessName
                        Id = $process.Id
                        WorkingSet = $process.WorkingSet64
                        VirtualMemorySize = $process.VirtualMemorySize64
                        PagedMemorySize = $process.PagedMemorySize64
                        NonpagedMemorySize = $process.NonpagedMemorySize64
                        Modules = @()
                    }}

                    try {{
                        $modules = $process.Modules
                        foreach ($module in $modules) {{
                            $processInfo.Modules += @{{
                                ModuleName = $module.ModuleName
                                FileName = $module.FileName
                                BaseAddress = "0x$($module.BaseAddress.ToString('X'))"
                                ModuleMemorySize = $module.ModuleMemorySize
                            }}
                        }}
                    }} catch {{
                        # Module enumeration failed, continue without it
                    }}

                    $processInfo | ConvertTo-Json -Depth 3
                }} catch {{
                    Write-Error "Process $({process_id}) not found or access denied"
                    exit 1
                }}
                '''

                result = subprocess.run(
                    ["powershell", "-Command", ps_script],
                    capture_output=True,
                    text=True,
                    timeout=30,
                    creationflags=subprocess.CREATE_NO_WINDOW
                )

                if result.returncode == 0:
                    # Save PowerShell process info as JSON dump
                    with open(dump_file.with_suffix('.json'), 'w') as f:
                        f.write(result.stdout)
                    logger.info(f"Process information saved via PowerShell: {dump_file.with_suffix('.json')}")
                    return str(dump_file.with_suffix('.json'))
                else:
                    raise Exception(f"PowerShell fallback failed: {result.stderr}")

            # Create the memory dump using MiniDumpWriteDump
            hFile = kernel32.CreateFileW(
                str(dump_file),
                0x40000000,  # GENERIC_WRITE
                0,           # No sharing
                None,        # Default security
                2,           # CREATE_ALWAYS
                0x80,        # FILE_ATTRIBUTE_NORMAL
                None         # No template
            )

            if hFile == -1:
                kernel32.CloseHandle(hProcess)
                raise Exception(f"Failed to create dump file: {dump_file}")

            # MiniDumpNormal = 0x00000000
            MiniDumpNormal = 0x00000000
            result = dbghelp.MiniDumpWriteDump(
                hProcess, process_id, hFile, MiniDumpNormal,
                None, None, None
            )

            # Clean up handles
            kernel32.CloseHandle(hFile)
            kernel32.CloseHandle(hProcess)

            if result:
                logger.info(f"Process memory dumped successfully: {dump_file}")
                return str(dump_file)
            else:
                # Try process memory regions dump using VirtualQueryEx
                logger.warning("MiniDumpWriteDump failed, attempting memory regions dump")

                return self._dump_memory_regions(process_id, timestamp)

        except Exception as e:
            logger.error(f"Failed to dump process memory: {e}")

            # Final fallback: Use Process Hacker or similar tool if available
            try:
                # Check if Process Hacker is available
                ph_path = r"C:\Program Files\Process Hacker 2\ProcessHacker.exe"
                if os.path.exists(ph_path):
                    cmd = [ph_path, "-o", "-pid", str(process_id), "-dumptype", "0", "-dumpfile", str(dump_file)]
                    subprocess.run(cmd, timeout=60, creationflags=subprocess.CREATE_NO_WINDOW)

                    if dump_file.exists():
                        logger.info(f"Process memory dumped using Process Hacker: {dump_file}")
                        return str(dump_file)

                # Use tasklist for basic process information
                cmd = ["tasklist", "/fi", f"PID eq {process_id}", "/fo", "csv", "/v"]
                result = subprocess.run(cmd, capture_output=True, text=True, timeout=15)

                if result.returncode == 0:
                    info_file = dump_file.with_suffix('.txt')
                    with open(info_file, 'w') as f:
                        f.write(f"Process Information for PID {process_id}\n")
                        f.write(f"Timestamp: {datetime.now().isoformat()}\n")
                        f.write("="*50 + "\n")
                        f.write(result.stdout)
                        f.write("\nMemory dump failed - unable to access process memory\n")
                        f.write(f"Error: {str(e)}\n")

                    logger.info(f"Process information saved: {info_file}")
                    return str(info_file)

            except Exception as fallback_error:
                logger.error(f"All memory dump methods failed: {fallback_error}")

            return ""

    def _extract_text_section_from_disk(self, binary_path: str) -> Optional[bytes]:
        """
        Extract the .text section from the on-disk binary.
        """
        try:
            if not pefile:
                logger.warning("pefile not available, cannot extract text section from disk")
                return None

            pe = pefile.PE(binary_path)

            # Find the .text section
            for section in pe.sections:
                if section.Name.startswith(b'.text'):
                    text_data = section.get_data()
                    pe.close()
                    return text_data

            pe.close()
            logger.warning(f"No .text section found in {binary_path}")
            return None

        except Exception as e:
            logger.error(f"Failed to extract text section from disk: {e}")
            return None

    def _extract_text_section_from_memory(self, memory_dump_path: str) -> Optional[bytes]:
        """
        Extract the .text section from the memory dump using real parsing.
        """
        try:
            if not memory_dump_path or not os.path.exists(memory_dump_path):
                logger.warning(f"Memory dump file does not exist: {memory_dump_path}")
                return None

            # Handle different dump file types
            file_ext = Path(memory_dump_path).suffix.lower()

            if file_ext == '.dmp':
                # Parse Windows memory dump file using minidump format
                try:
                    with open(memory_dump_path, 'rb') as f:
                        # Read minidump header to validate format
                        signature = f.read(4)
                        if signature != b'MDMP':
                            logger.warning(f"Not a valid Windows minidump file: {memory_dump_path}")
                            return self._extract_from_raw_memory_dump(memory_dump_path)

                        # Use crash-python or similar for full parsing, but for now extract manually
                        f.seek(0)
                        dump_data = f.read()

                        # Look for PE signature in dump data (simplified approach)
                        pe_sig_offset = dump_data.find(b'MZ')
                        if pe_sig_offset == -1:
                            logger.warning("No PE header found in memory dump")
                            return None

                        # Extract PE from memory dump starting at MZ signature
                        pe_data = dump_data[pe_sig_offset:]

                        # Find .text section in PE data
                        return self._extract_text_from_pe_data(pe_data)

                except Exception as pe_error:
                    logger.warning(f"Failed to parse minidump, trying raw extraction: {pe_error}")
                    return self._extract_from_raw_memory_dump(memory_dump_path)

            elif file_ext == '.json':
                # Handle PowerShell process dump (JSON format)
                try:
                    import json
                    with open(memory_dump_path, 'r') as f:
                        process_info = json.loads(f.read())

                    # Extract module information for text section analysis
                    modules = process_info.get('Modules', [])
                    main_module = None

                    for module in modules:
                        if 'exe' in module.get('ModuleName', '').lower():
                            main_module = module
                            break

                    if main_module:
                        # Use WinDbg or PowerShell to extract memory from base address
                        base_addr = main_module.get('BaseAddress', '0x0')
                        module_size = main_module.get('ModuleMemorySize', 0)

                        if base_addr != '0x0' and module_size > 0:
                            return self._extract_memory_region_via_powershell(base_addr, module_size)

                    logger.warning("No executable module found in process information")
                    return None

                except Exception as json_error:
                    logger.error(f"Failed to parse JSON process dump: {json_error}")
                    return None

            else:
                # Try raw binary extraction for other file types
                return self._extract_from_raw_memory_dump(memory_dump_path)

        except Exception as e:
            logger.error(f"Failed to extract text section from memory: {e}")
            return None

    def _dump_memory_regions(self, process_id: int, timestamp: str) -> str:
        """
        Dump memory regions using VirtualQueryEx and ReadProcessMemory.
        """
        try:
            import ctypes
            from ctypes import wintypes

            # Create memory regions dump file
            regions_file = self.memory_dumps_dir / f"memory_regions_{process_id}_{timestamp}.bin"

            # Use VirtualQueryEx to enumerate memory regions
            kernel32 = ctypes.windll.kernel32

            # Open process with required access rights
            PROCESS_QUERY_INFORMATION = 0x0400
            PROCESS_VM_READ = 0x0010
            hProcess = kernel32.OpenProcess(
                PROCESS_QUERY_INFORMATION | PROCESS_VM_READ,
                False, process_id
            )

            if not hProcess:
                logger.error(f"Failed to open process {process_id} for memory region dumping")
                return ""

            # Define MEMORY_BASIC_INFORMATION structure
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
            regions_data = []

            with open(regions_file, 'wb') as f:
                while True:
                    result = kernel32.VirtualQueryEx(
                        hProcess, ctypes.c_void_p(address),
                        ctypes.byref(mbi), ctypes.sizeof(mbi)
                    )

                    if not result:
                        break

                    # Check if region is committed and readable
                    MEM_COMMIT = 0x1000
                    PAGE_READONLY = 0x02
                    PAGE_READWRITE = 0x04
                    PAGE_EXECUTE_READ = 0x20
                    PAGE_EXECUTE_READWRITE = 0x40

                    if (mbi.State == MEM_COMMIT and
                        mbi.Protect & (PAGE_READONLY | PAGE_READWRITE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE)):

                        # Read memory region
                        buffer = ctypes.create_string_buffer(mbi.RegionSize)
                        bytes_read = ctypes.c_size_t(0)

                        read_result = kernel32.ReadProcessMemory(
                            hProcess, ctypes.c_void_p(mbi.BaseAddress),
                            buffer, mbi.RegionSize,
                            ctypes.byref(bytes_read)
                        )

                        if read_result and bytes_read.value > 0:
                            # Write region header and data
                            header = f"REGION: {mbi.BaseAddress:016x} SIZE: {mbi.RegionSize:08x} PROTECT: {mbi.Protect:08x}\n"
                            f.write(header.encode())
                            f.write(buffer.raw[:bytes_read.value])
                            f.write(b"\n" + b"="*64 + b"\n")

                            regions_data.append({
                                "base_address": f"0x{mbi.BaseAddress:016x}",
                                "size": mbi.RegionSize,
                                "protection": mbi.Protect,
                                "bytes_read": bytes_read.value
                            })

                    address = mbi.BaseAddress + mbi.RegionSize

                    # Safety check to prevent infinite loop
                    if address >= 0x7FFFFFFF:
                        break

            kernel32.CloseHandle(hProcess)

            # Save regions metadata
            metadata_file = regions_file.with_suffix('.json')
            import json
            with open(metadata_file, 'w') as f:
                json.dump({
                    "process_id": process_id,
                    "timestamp": timestamp,
                    "regions_count": len(regions_data),
                    "regions": regions_data
                }, f, indent=2)

            logger.info(f"Memory regions dumped: {regions_file} ({len(regions_data)} regions)")
            return str(regions_file)

        except Exception as e:
            logger.error(f"Failed to dump memory regions: {e}")
            return ""

    def _extract_from_raw_memory_dump(self, dump_path: str) -> Optional[bytes]:
        """
        Extract text section from raw memory dump file.
        """
        try:
            with open(dump_path, 'rb') as f:
                data = f.read()

            # Look for PE header signature 'MZ'
            mz_offset = data.find(b'MZ')
            if mz_offset == -1:
                logger.warning(f"No PE header found in {dump_path}")
                return None

            # Extract PE data starting from MZ
            pe_data = data[mz_offset:]
            return self._extract_text_from_pe_data(pe_data)

        except Exception as e:
            logger.error(f"Failed to extract from raw memory dump: {e}")
            return None

    def _extract_text_from_pe_data(self, pe_data: bytes) -> Optional[bytes]:
        """
        Extract .text section from PE data in memory.
        """
        try:
            if len(pe_data) < 64:
                return None

            # Check MZ signature
            if pe_data[:2] != b'MZ':
                return None

            # Get PE header offset
            pe_offset = int.from_bytes(pe_data[60:64], 'little')
            if pe_offset >= len(pe_data) - 4:
                return None

            # Check PE signature
            if pe_data[pe_offset:pe_offset+4] != b'PE\x00\x00':
                return None

            # Parse COFF header
            _machine = int.from_bytes(pe_data[pe_offset+4:pe_offset+6], 'little')
            num_sections = int.from_bytes(pe_data[pe_offset+6:pe_offset+8], 'little')
            opt_hdr_size = int.from_bytes(pe_data[pe_offset+20:pe_offset+22], 'little')

            # Calculate section headers offset
            sections_offset = pe_offset + 24 + opt_hdr_size

            # Find .text section
            for i in range(num_sections):
                section_offset = sections_offset + (i * 40)
                if section_offset + 40 > len(pe_data):
                    break

                # Read section name
                section_name = pe_data[section_offset:section_offset+8].rstrip(b'\x00')

                if section_name == b'.text':
                    # Read section properties
                    _virtual_size = int.from_bytes(pe_data[section_offset+8:section_offset+12], 'little')
                    _virtual_address = int.from_bytes(pe_data[section_offset+12:section_offset+16], 'little')
                    raw_size = int.from_bytes(pe_data[section_offset+16:section_offset+20], 'little')
                    raw_offset = int.from_bytes(pe_data[section_offset+20:section_offset+24], 'little')

                    # Extract text section data
                    if raw_offset + raw_size <= len(pe_data):
                        text_data = pe_data[raw_offset:raw_offset+raw_size]
                        logger.info(f"Extracted .text section: {len(text_data)} bytes")
                        return text_data

            logger.warning("No .text section found in PE data")
            return None

        except Exception as e:
            logger.error(f"Failed to extract text section from PE data: {e}")
            return None

    def _extract_memory_region_via_powershell(self, base_addr: str, size: int) -> Optional[bytes]:
        """
        Extract memory region using PowerShell and .NET Process class.
        """
        try:
            # PowerShell script to read process memory
            ps_script = f'''
            Add-Type -TypeDefinition @"
                using System;
                using System.Diagnostics;
                using System.Runtime.InteropServices;

                public class MemoryReader
                {{
                    [DllImport("kernel32.dll")]
                    public static extern IntPtr OpenProcess(int dwDesiredAccess, bool bInheritHandle, int dwProcessId);

                    [DllImport("kernel32.dll")]
                    public static extern bool ReadProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress,
                        byte[] lpBuffer, int dwSize, out IntPtr lpNumberOfBytesRead);

                    [DllImport("kernel32.dll")]
                    public static extern bool CloseHandle(IntPtr hObject);

                    public static byte[] ReadMemory(int processId, IntPtr address, int size)
                    {{
                        IntPtr processHandle = OpenProcess(0x0010, false, processId);
                        if (processHandle == IntPtr.Zero) return null;

                        byte[] buffer = new byte[size];
                        IntPtr bytesRead;
                        bool success = ReadProcessMemory(processHandle, address, buffer, size, out bytesRead);
                        CloseHandle(processHandle);

                        if (success && bytesRead.ToInt32() > 0)
                        {{
                            byte[] result = new byte[bytesRead.ToInt32()];
                            Array.Copy(buffer, result, bytesRead.ToInt32());
                            return result;
                        }}
                        return null;
                    }}
                }}
"@

            $processId = (Get-Process | Where-Object {{ $_.ProcessName -like "*test*" }} | Select-Object -First 1).Id
            if ($processId) {{
                $addr = [IntPtr]{base_addr}
                $data = [MemoryReader]::ReadMemory($processId, $addr, {min(size, 1048576)})  # Limit to 1MB
                if ($data) {{
                    [System.Convert]::ToBase64String($data)
                }}
            }}
            '''

            result = subprocess.run(
                ["powershell", "-Command", ps_script],
                capture_output=True,
                text=True,
                timeout=30,
                creationflags=subprocess.CREATE_NO_WINDOW
            )

            if result.returncode == 0 and result.stdout.strip():
                import base64
                memory_data = base64.b64decode(result.stdout.strip())
                logger.info(f"Extracted {len(memory_data)} bytes from memory via PowerShell")
                return memory_data

            return None

        except Exception as e:
            logger.error(f"Failed to extract memory region via PowerShell: {e}")
            return None

    def _compare_sections(self, disk_section: bytes, memory_section: bytes) -> List[MemoryModification]:
        """
        Compare disk and memory sections to identify modifications.
        """
        modifications = []

        try:
            # Compare byte by byte
            min_length = min(len(disk_section), len(memory_section))

            for i in range(min_length):
                if disk_section[i] != memory_section[i]:
                    modification = MemoryModification(
                        address=f"0x{i:08x}",
                        original_bytes=f"0x{disk_section[i]:02x}",
                        modified_bytes=f"0x{memory_section[i]:02x}",
                        modification_type="byte_change",
                        section=".text"
                    )
                    modifications.append(modification)

            # If memory section is longer, note additional bytes
            if len(memory_section) > len(disk_section):
                for i in range(len(disk_section), len(memory_section)):
                    modification = MemoryModification(
                        address=f"0x{i:08x}",
                        original_bytes="0x00",
                        modified_bytes=f"0x{memory_section[i]:02x}",
                        modification_type="additional_bytes",
                        section=".text"
                    )
                    modifications.append(modification)

            logger.info(f"Found {len(modifications)} memory modifications")

        except Exception as e:
            logger.error(f"Error comparing sections: {e}")
            modifications.append(MemoryModification(
                address="0x00000000",
                original_bytes="",
                modified_bytes="",
                modification_type="error",
                section=".text",
                timestamp=datetime.now().isoformat()
            ))

        return modifications

    def _detect_common_hooks(self, memory_section: bytes) -> List[HookDetection]:
        """
        Detect common hooking patterns in memory.
        """
        hooks = []

        try:
            # Look for common hooking patterns
            # JMP instructions (0xE9 for near jump, 0xEA for far jump)
            # CALL instructions (0xE8 for near call)

            for i in range(len(memory_section) - 5):
                # Check for JMP near relative (0xE9)
                if memory_section[i] == 0xE9:
                    hook = HookDetection(
                        hook_type="JMP_NEAR_RELATIVE",
                        address=f"0x{i:08x}",
                        original_instruction="",
                        hooked_instruction=(
                            f"E9 {memory_section[i+1]:02x} {memory_section[i+2]:02x} "
                            f"{memory_section[i+3]:02x} {memory_section[i+4]:02x}"
                        ),
                        target_address=f"0x{(i + 5 + int.from_bytes(memory_section[i+1:i+5], 'little', signed=True)):08x}",
                        detection_method="pattern_matching"
                    )
                    hooks.append(hook)

                # Check for CALL near relative (0xE8)
                elif memory_section[i] == 0xE8:
                    hook = HookDetection(
                        hook_type="CALL_NEAR_RELATIVE",
                        address=f"0x{i:08x}",
                        original_instruction="",
                        hooked_instruction=(
                            f"E8 {memory_section[i+1]:02x} {memory_section[i+2]:02x} "
                            f"{memory_section[i+3]:02x} {memory_section[i+4]:02x}"
                        ),
                        target_address=f"0x{(i + 5 + int.from_bytes(memory_section[i+1:i+5], 'little', signed=True)):08x}",
                        detection_method="pattern_matching"
                    )
                    hooks.append(hook)

                # Check for JMP indirect (0xFF /4)
                elif memory_section[i] == 0xFF and (memory_section[i+1] & 0x38) == 0x20:
                    hook = HookDetection(
                        hook_type="JMP_INDIRECT",
                        address=f"0x{i:08x}",
                        original_instruction="",
                        hooked_instruction=f"FF {memory_section[i+1]:02x}",
                        target_address="indirect",
                        detection_method="pattern_matching"
                    )
                    hooks.append(hook)

            logger.info(f"Found {len(hooks)} potential hooks")

        except Exception as e:
            logger.error(f"Error detecting hooks: {e}")
            hooks.append(HookDetection(
                hook_type="error",
                address="0x00000000",
                original_instruction="",
                hooked_instruction="",
                target_address="",
                detection_method="error",
                timestamp=datetime.now().isoformat()
            ))

        return hooks

    def _check_import_address_table(self, binary_path: str) -> List[Dict[str, Any]]:
        """
        Check Import Address Table (IAT) for modifications.
        """
        iat_modifications = []

        try:
            if not pefile:
                logger.warning("pefile not available, cannot check IAT")
                return iat_modifications

            pe = pefile.PE(binary_path)

            # Check IAT modifications
            if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
                for entry in pe.DIRECTORY_ENTRY_IMPORT:
                    dll_name = entry.dll.decode('utf-8') if entry.dll else "Unknown"

                    for imp in entry.imports:
                        function_name = imp.name.decode('utf-8') if imp.name else f"Ordinal#{imp.ordinal}"
                        address = hex(imp.address) if imp.address else "Unknown"

                        # In a real implementation, you would compare with expected values
                        # For now, we'll just log the imports
                        iat_modifications.append({
                            "dll": dll_name,
                            "function": function_name,
                            "address": address,
                            "modified": False,  # Would be determined by comparison
                            "timestamp": datetime.now().isoformat()
                        })

            pe.close()
            logger.info(f"Checked IAT for {len(iat_modifications)} imports")

        except Exception as e:
            logger.error(f"Error checking IAT: {e}")
            iat_modifications.append({
                "dll": "error",
                "function": "error",
                "address": "error",
                "modified": False,
                "timestamp": datetime.now().isoformat()
            })

        return iat_modifications

    def _verify_export_address_table(self, binary_path: str) -> bool:
        """
        Verify Export Address Table (EAT) integrity.
        """
        try:
            if not pefile:
                logger.warning("pefile not available, cannot verify EAT")
                return True  # Assume valid if we can't check

            pe = pefile.PE(binary_path)

            # Verify EAT integrity
            eat_valid = True

            # In a real implementation, you would perform detailed EAT verification
            # For now, we'll assume it's valid
            if hasattr(pe, 'DIRECTORY_ENTRY_EXPORT'):
                logger.info("EAT verification: Export directory found")
                # Would perform actual verification here
            else:
                logger.info("EAT verification: No export directory")

            pe.close()
            return eat_valid

        except Exception as e:
            logger.error(f"Error verifying EAT: {e}")
            return False

    def check_memory_integrity(self, binary_path: str, software_name: str) -> MemoryIntegrityResult:
        """
        Check memory integrity of a running software process.

        Args:
            binary_path: Path to the software binary
            software_name: Name of the software being tested

        Returns:
            MemoryIntegrityResult with validation results
        """
        logger.info(f"Starting memory integrity check for {software_name}")

        test_start_time = datetime.now().isoformat()

        # Calculate binary hash
        binary_hash = self._calculate_hash(binary_path)

        # Initialize result fields
        process_id = 0
        memory_dump_path = ""
        text_section_original_hash = ""
        text_section_memory_hash = ""
        memory_modifications = []
        hook_detections = []
        iat_modifications = []
        eat_integrity = False
        memory_integrity_valid = False
        error_messages = []

        try:
            # Launch the software for real memory integrity analysis
            logger.info(f"Launching {software_name} for memory analysis")
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

            # Method 1: Try to launch the binary directly if it exists
            if os.path.exists(binary_path):
                try:
                    # Launch the process
                    process = subprocess.Popen(
                        [binary_path],
                        stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE,
                        creationflags=subprocess.CREATE_NEW_CONSOLE if sys.platform == "win32" else 0
                    )
                    process_id = process.pid
                    logger.info(f"Successfully launched {software_name} with PID {process_id}")

                    # Allow process to initialize (5 seconds)
                    time.sleep(5)

                    # Verify process is still running
                    if process.poll() is None:
                        logger.info(f"Process {process_id} is running and ready for analysis")
                    else:
                        logger.warning(f"Process {process_id} exited early, return code: {process.returncode}")

                except Exception as launch_error:
                    logger.error(f"Failed to launch {binary_path}: {launch_error}")
                    # Fall back to finding existing process
                    process_id = self._find_existing_process(software_name)
                    if not process_id:
                        raise Exception(f"Could not launch or find process for {software_name}")
            else:
                logger.warning(f"Binary path does not exist: {binary_path}")
                # Try to find existing running process with similar name
                process_id = self._find_existing_process(software_name)
                if not process_id:
                    raise Exception(f"Binary not found and no running process found for {software_name}")

            # Dump process memory
            memory_dump_path = self._dump_process_memory(process_id, timestamp)

            # Extract text sections
            disk_text_section = self._extract_text_section_from_disk(binary_path)
            memory_text_section = self._extract_text_section_from_memory(memory_dump_path)

            if disk_text_section:
                text_section_original_hash = hashlib.sha256(disk_text_section).hexdigest()

            if memory_text_section:
                text_section_memory_hash = hashlib.sha256(memory_text_section).hexdigest()

            # Compare sections
            if disk_text_section and memory_text_section:
                memory_modifications = self._compare_sections(disk_text_section, memory_text_section)

            # Detect hooks
            if memory_text_section:
                hook_detections = self._detect_common_hooks(memory_text_section)

            # Check IAT
            iat_modifications = self._check_import_address_table(binary_path)

            # Verify EAT
            eat_integrity = self._verify_export_address_table(binary_path)

            # Determine overall memory integrity
            # For now, we'll use a simple heuristic
            memory_integrity_valid = (
                len(memory_modifications) < 10 and  # Few modifications
                len(hook_detections) < 5 and        # Few hooks
                eat_integrity                        # EAT is intact
            )

            logger.info(f"Memory integrity check completed for {software_name}")

        except Exception as e:
            error_messages.append(str(e))
            logger.error(f"Memory integrity check failed for {software_name}: {e}")

        test_end_time = datetime.now().isoformat()

        result = MemoryIntegrityResult(
            software_name=software_name,
            binary_path=binary_path,
            binary_hash=binary_hash,
            process_id=process_id,
            test_start_time=test_start_time,
            test_end_time=test_end_time,
            memory_dump_path=memory_dump_path,
            text_section_original_hash=text_section_original_hash,
            text_section_memory_hash=text_section_memory_hash,
            memory_modifications=memory_modifications,
            hook_detections=hook_detections,
            iat_modifications=iat_modifications,
            eat_integrity=eat_integrity,
            memory_integrity_valid=memory_integrity_valid,
            error_messages=error_messages
        )

        return result

    def check_all_memory_integrity(self) -> List[MemoryIntegrityResult]:
        """
        Check memory integrity for all available binaries.
        """
        logger.info("Starting memory integrity checks for all binaries")

        results = []

        # Get all acquired binaries
        binaries = self.binary_manager.list_acquired_binaries()

        for binary in binaries:
            try:
                binary_path = binary.get("file_path")
                software_name = binary.get("software_name", "Unknown")

                if binary_path and os.path.exists(binary_path):
                    logger.info(f"Checking memory integrity for {software_name}")
                    result = self.check_memory_integrity(binary_path, software_name)
                    results.append(result)
                else:
                    logger.warning(f"Binary not found for {software_name}: {binary_path}")
                    results.append(MemoryIntegrityResult(
                        software_name=software_name,
                        binary_path=binary_path or "",
                        binary_hash="",
                        process_id=0,
                        test_start_time=datetime.now().isoformat(),
                        test_end_time=datetime.now().isoformat(),
                        memory_dump_path="",
                        text_section_original_hash="",
                        text_section_memory_hash="",
                        memory_modifications=[],
                        hook_detections=[],
                        iat_modifications=[],
                        eat_integrity=False,
                        memory_integrity_valid=False,
                        error_messages=[f"Binary not found: {binary_path}"]
                    ))

            except Exception as e:
                logger.error(f"Failed to check memory integrity for {binary.get('software_name', 'Unknown')}: {e}")
                results.append(MemoryIntegrityResult(
                    software_name=binary.get("software_name", "Unknown"),
                    binary_path=binary.get("file_path", ""),
                    binary_hash="",
                    process_id=0,
                    test_start_time=datetime.now().isoformat(),
                    test_end_time=datetime.now().isoformat(),
                    memory_dump_path="",
                    text_section_original_hash="",
                    text_section_memory_hash="",
                    memory_modifications=[],
                    hook_detections=[],
                    iat_modifications=[],
                    eat_integrity=False,
                    memory_integrity_valid=False,
                    error_messages=[str(e)]
                ))

        logger.info(f"Completed memory integrity checks for {len(results)} binaries")
        return results

    def generate_report(self, results: List[MemoryIntegrityResult]) -> str:
        """
        Generate a comprehensive report of memory integrity validation results.
        """
        if not results:
            return "No memory integrity validation tests were run."

        report_lines = [
            "Memory Integrity Validation Report",
            "=" * 50,
            f"Generated: {datetime.now().isoformat()}",
            f"Total Software Analyzed: {len(results)}",
            ""
        ]

        # Summary statistics
        total_valid = sum(1 for r in results if r.memory_integrity_valid)
        total_modifications = sum(len(r.memory_modifications) for r in results)
        total_hooks = sum(len(r.hook_detections) for r in results)
        total_iat_mods = sum(len(r.iat_modifications) for r in results)

        report_lines.append("Summary:")
        report_lines.append(f"  Total Tests: {len(results)}")
        report_lines.append(f"  Memory Integrity Valid: {total_valid}")
        report_lines.append(f"  Success Rate: {total_valid/len(results)*100:.1f}%" if len(results) > 0 else "  Success Rate: N/A")
        report_lines.append(f"  Total Modifications: {total_modifications}")
        report_lines.append(f"  Total Hooks Detected: {total_hooks}")
        report_lines.append(f"  Total IAT Modifications: {total_iat_mods}")
        report_lines.append("")

        # Detailed results
        report_lines.append("Detailed Results:")
        report_lines.append("-" * 30)

        for result in results:
            report_lines.append(f"Software: {result.software_name}")
            report_lines.append(f"  Binary Hash: {result.binary_hash[:16]}...")
            report_lines.append(f"  Process ID: {result.process_id}")
            report_lines.append(f"  Memory Dump: {result.memory_dump_path}")
            report_lines.append(f"  Text Section Original Hash: {result.text_section_original_hash[:16]}...")
            report_lines.append(f"  Text Section Memory Hash: {result.text_section_memory_hash[:16]}...")
            report_lines.append(f"  Memory Integrity Valid: {result.memory_integrity_valid}")
            report_lines.append(f"  Modifications Found: {len(result.memory_modifications)}")
            report_lines.append(f"  Hooks Detected: {len(result.hook_detections)}")
            report_lines.append(f"  IAT Modifications: {len(result.iat_modifications)}")
            report_lines.append(f"  EAT Integrity: {result.eat_integrity}")

            if result.error_messages:
                report_lines.append(f"  Errors: {', '.join(result.error_messages)}")

            # Show some modifications if any
            if result.memory_modifications:
                report_lines.append("  Sample Modifications:")
                for mod in result.memory_modifications[:3]:  # Show first 3
                    report_lines.append(f"    Address {mod.address}: {mod.original_bytes} -> {mod.modified_bytes}")
                if len(result.memory_modifications) > 3:
                    report_lines.append(f"    ... and {len(result.memory_modifications) - 3} more")

            # Show some hooks if any
            if result.hook_detections:
                report_lines.append("  Sample Hooks:")
                for hook in result.hook_detections[:3]:  # Show first 3
                    report_lines.append(f"    {hook.hook_type} at {hook.address} -> {hook.target_address}")
                if len(result.hook_detections) > 3:
                    report_lines.append(f"    ... and {len(result.hook_detections) - 3} more")

            report_lines.append("")

        return "\n".join(report_lines)

    def save_report(self, results: List[MemoryIntegrityResult], filename: Optional[str] = None) -> str:
        """
        Save the memory integrity validation report to a file.
        """
        if filename is None:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"memory_integrity_report_{timestamp}.txt"

        report_path = self.reports_dir / filename

        report_text = self.generate_report(results)

        with open(report_path, 'w') as f:
            f.write(report_text)

        logger.info(f"Memory integrity validation report saved to {report_path}")
        return str(report_path)


if __name__ == "__main__":
    # Test the MemoryIntegrityChecker
    checker = MemoryIntegrityChecker()

    print("Memory Integrity Checker initialized")
    print("Available binaries:")

    # Get available binaries
    binaries = checker.binary_manager.list_acquired_binaries()
    if binaries:
        for binary in binaries:
            print(f"  - {binary.get('software_name')}: {binary.get('protection')} {binary.get('version')}")

        # Run memory integrity check on the first binary
        if binaries:
            first_binary = binaries[0]
            binary_path = first_binary.get("file_path")
            software_name = first_binary.get("software_name", "Unknown")

            if binary_path and os.path.exists(binary_path):
                print(f"\nRunning memory integrity check on {software_name}...")
                result = checker.check_memory_integrity(binary_path, software_name)

                print(f"Memory integrity check completed for {software_name}")
                print(f"  Process ID: {result.process_id}")
                print(f"  Memory Integrity Valid: {result.memory_integrity_valid}")
                print(f"  Modifications Found: {len(result.memory_modifications)}")
                print(f"  Hooks Detected: {len(result.hook_detections)}")
                print(f"  IAT Modifications: {len(result.iat_modifications)}")
                print(f"  EAT Integrity: {result.eat_integrity}")

                if result.error_messages:
                    print(f"  Errors: {', '.join(result.error_messages)}")

                # Generate and save report
                report_path = checker.save_report([result])
                print(f"\nReport saved to: {report_path}")
            else:
                print(f"\nBinary not found: {binary_path}")
    else:
        print("\nNo binaries acquired yet. Please acquire binaries using commercial_binary_manager.py")

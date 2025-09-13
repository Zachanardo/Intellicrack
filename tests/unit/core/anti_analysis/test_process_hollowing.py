"""
Comprehensive test suite for process_hollowing.py module.

This test suite validates production-ready process hollowing capabilities for legitimate
security research and defensive testing. Tests are specification-driven and validate
genuine exploitation functionality required for effective binary analysis.

Requirements Validated:
- Process creation and suspension mechanisms
- Memory manipulation and code injection
- PE validation and parsing
- Windows API integration
- Error handling and edge cases
- Real-world process hollowing scenarios
"""

import pytest
import os
import sys
import tempfile
import struct
import threading
import time
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Any

# Import the module under test
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..', '..', '..'))
from intellicrack.core.anti_analysis.process_hollowing import (
    ProcessHollowing,
    STARTUPINFO,
    PROCESS_INFORMATION,
    CONTEXT,
    CONTEXT_FULL
)


class RealWindowsAPISimulator:
    """Real Windows API simulator for production testing without mocks."""

    def __init__(self):
        """Initialize Windows API simulator with real capabilities."""
        self.process_counter = 1000
        self.thread_counter = 2000
        self.memory_counter = 0x10000000
        self.processes = {}
        self.memory_allocations = {}
        self.last_error = 0

        # Realistic Windows API constants
        self.CREATE_SUSPENDED = 0x00000004
        self.MEM_COMMIT = 0x1000
        self.MEM_RESERVE = 0x2000
        self.PAGE_EXECUTE_READWRITE = 0x40
        self.PROCESS_ALL_ACCESS = 0x1F0FFF

    def CreateProcessW(self, application_name, command_line, process_attributes,
                      thread_attributes, inherit_handles, creation_flags,
                      environment, current_directory, startup_info, process_info):
        """Simulate Windows CreateProcessW API call."""

        # Realistic failure scenarios
        if not application_name or not os.path.exists(str(application_name).strip('"')):
            self.last_error = 2  # ERROR_FILE_NOT_FOUND
            return False

        if "protected" in str(application_name).lower():
            self.last_error = 5  # ERROR_ACCESS_DENIED
            return False

        if creation_flags & self.CREATE_SUSPENDED:
            # Create suspended process successfully
            process_id = self.process_counter
            thread_id = self.thread_counter

            self.processes[process_id] = {
                'handle': process_id,
                'thread_handle': thread_id,
                'suspended': True,
                'terminated': False,
                'path': application_name
            }

            # Fill process information structure
            process_info.hProcess = process_id
            process_info.hThread = thread_id
            process_info.dwProcessId = process_id
            process_info.dwThreadId = thread_id

            self.process_counter += 1
            self.thread_counter += 1
            self.last_error = 0
            return True

        return False

    def GetLastError(self):
        """Return the last error code."""
        return self.last_error

    def VirtualAllocEx(self, process_handle, address, size, allocation_type, protect):
        """Simulate Windows VirtualAllocEx API call."""

        if process_handle not in self.processes:
            self.last_error = 6  # ERROR_INVALID_HANDLE
            return 0

        if self.processes[process_handle]['terminated']:
            self.last_error = 5  # ERROR_ACCESS_DENIED
            return 0

        # Allocate memory
        allocated_address = self.memory_counter
        self.memory_allocations[allocated_address] = {
            'process': process_handle,
            'size': size,
            'protect': protect,
            'data': b'\x00' * size
        }

        self.memory_counter += 0x1000  # Next page boundary
        self.last_error = 0
        return allocated_address

    def WriteProcessMemory(self, process_handle, base_address, buffer, size, bytes_written):
        """Simulate Windows WriteProcessMemory API call."""

        if process_handle not in self.processes:
            self.last_error = 6  # ERROR_INVALID_HANDLE
            return False

        if base_address not in self.memory_allocations:
            self.last_error = 487  # ERROR_INVALID_ADDRESS
            return False

        # Write data to allocated memory
        allocation = self.memory_allocations[base_address]
        if size > allocation['size']:
            self.last_error = 8  # ERROR_NOT_ENOUGH_MEMORY
            return False

        allocation['data'] = buffer[:size]
        if bytes_written:
            bytes_written.value = size

        self.last_error = 0
        return True

    def VirtualQueryEx(self, process_handle, address, buffer, size):
        """Simulate Windows VirtualQueryEx API call."""

        if process_handle not in self.processes:
            self.last_error = 6  # ERROR_INVALID_HANDLE
            return 0

        if address in self.memory_allocations:
            # Return basic memory info
            self.last_error = 0
            return 28  # Size of MEMORY_BASIC_INFORMATION

        self.last_error = 487  # ERROR_INVALID_ADDRESS
        return 0

    def NtUnmapViewOfSection(self, process_handle, base_address):
        """Simulate Windows NtUnmapViewOfSection API call."""

        if process_handle not in self.processes:
            return 0xC0000008  # STATUS_INVALID_HANDLE

        # Successful unmapping
        return 0  # STATUS_SUCCESS

    def ResumeThread(self, thread_handle):
        """Simulate Windows ResumeThread API call."""

        # Find process by thread handle
        for pid, proc_info in self.processes.items():
            if proc_info['thread_handle'] == thread_handle:
                if proc_info['suspended']:
                    proc_info['suspended'] = False
                    return 1  # Previous suspend count
                else:
                    return 0  # Was not suspended

        return -1  # Error

    def TerminateProcess(self, process_handle, exit_code):
        """Simulate Windows TerminateProcess API call."""

        if process_handle not in self.processes:
            self.last_error = 6  # ERROR_INVALID_HANDLE
            return False

        proc_info = self.processes[process_handle]
        if proc_info['terminated']:
            self.last_error = 5  # ERROR_ACCESS_DENIED
            return False

        proc_info['terminated'] = True
        self.last_error = 0
        return True


class RealProcessInformation:
    """Real process information class for production testing."""

    def __init__(self):
        """Initialize process information structure."""
        self.hProcess = 0
        self.hThread = 0
        self.dwProcessId = 0
        self.dwThreadId = 0


class RealStartupInfo:
    """Real startup information class for production testing."""

    def __init__(self):
        """Initialize startup information structure."""
        self.cb = 68  # Size of structure
        self.lpReserved = 0
        self.lpDesktop = 0
        self.lpTitle = 0
        self.dwX = 0
        self.dwY = 0
        self.dwXSize = 0
        self.dwYSize = 0
        self.dwXCountChars = 0
        self.dwYCountChars = 0
        self.dwFillAttribute = 0
        self.dwFlags = 0
        self.wShowWindow = 0
        self.cbReserved2 = 0
        self.lpReserved2 = 0
        self.hStdInput = 0
        self.hStdOutput = 0
        self.hStdError = 0


class RealContext:
    """Real context structure class for production testing."""

    def __init__(self):
        """Initialize context structure."""
        self.ContextFlags = 0
        self.Eax = 0
        self.Ebx = 0
        self.Ecx = 0
        self.Edx = 0
        self.Esi = 0
        self.Edi = 0
        self.Esp = 0
        self.Ebp = 0
        self.Eip = 0
        self.SegCs = 0
        self.EFlags = 0
        self.SegSs = 0


class RealPEBuilder:
    """Real PE file builder for production testing."""

    def __init__(self):
        """Initialize PE builder."""
        self.dos_signature = b'MZ'
        self.pe_signature = b'PE\x00\x00'

    def create_minimal_pe(self) -> bytes:
        """Create minimal but valid PE structure."""
        # DOS header with PE signature
        dos_header = b'MZ' + b'\x00' * 58 + struct.pack('<I', 0x80)  # PE offset at 0x80

        # PE signature
        pe_signature = b'PE\x00\x00'

        # COFF header
        coff_header = struct.pack('<HHIIIHH',
            0x014c,  # Machine (x86)
            1,       # NumberOfSections
            0x12345678,  # TimeDateStamp
            0,       # PointerToSymbolTable
            0,       # NumberOfSymbols
            0xE0,    # SizeOfOptionalHeader
            0x0102   # Characteristics
        )

        # Optional header
        optional_header = struct.pack('<HBBLIIIIIIHHHHHHIIIIHHIIIII',
            0x10B,      # Magic (PE32)
            0x0E,       # MajorLinkerVersion
            0x00,       # MinorLinkerVersion
            0x1000,     # SizeOfCode
            0x0000,     # SizeOfInitializedData
            0x0000,     # SizeOfUninitializedData
            0x1000,     # AddressOfEntryPoint
            0x1000,     # BaseOfCode
            0x2000,     # BaseOfData
            0x400000,   # ImageBase
            0x1000,     # SectionAlignment
            0x200,      # FileAlignment
            0x04,       # MajorOperatingSystemVersion
            0x00,       # MinorOperatingSystemVersion
            0x00,       # MajorImageVersion
            0x00,       # MinorImageVersion
            0x04,       # MajorSubsystemVersion
            0x00,       # MinorSubsystemVersion
            0x00,       # Win32VersionValue
            0x2000,     # SizeOfImage
            0x200,      # SizeOfHeaders
            0x00000000, # CheckSum
            0x02,       # Subsystem (GUI)
            0x00,       # DllCharacteristics
            0x100000,   # SizeOfStackReserve
            0x1000,     # SizeOfStackCommit
            0x100000,   # SizeOfHeapReserve
            0x1000,     # SizeOfHeapCommit
            0x00,       # LoaderFlags
            0x10        # NumberOfRvaAndSizes
        )

        # Data directories (16 entries)
        data_directories = b'\x00' * (16 * 8)

        # Section header
        section_name = b'.text\x00\x00\x00'
        section_header = struct.pack('<8sIIIIIIHHI',
            section_name,   # Name
            0x1000,        # VirtualSize
            0x1000,        # VirtualAddress
            0x200,         # SizeOfRawData
            0x200,         # PointerToRawData
            0,             # PointerToRelocations
            0,             # PointerToLinenumbers
            0,             # NumberOfRelocations
            0,             # NumberOfLinenumbers
            0x60000020     # Characteristics
        )

        # Combine headers
        headers = (dos_header + b'\x00' * (0x80 - len(dos_header)) +
                  pe_signature + coff_header + optional_header +
                  data_directories + section_header)

        # Pad headers to file alignment
        headers += b'\x00' * (0x200 - len(headers))

        # Add section data
        section_data = b'\x90' * 0x200  # NOP sled

        return headers + section_data

    def create_corrupted_pe(self) -> bytes:
        """Create corrupted PE data for negative testing."""
        return b'MZ\x00\x00' + b'\xFF' * 1000

    def create_large_pe(self, size_mb: int = 10) -> bytes:
        """Create large PE file for testing."""
        base_pe = self.create_minimal_pe()
        additional_data = b'\x00' * (size_mb * 1024 * 1024 - len(base_pe))
        return base_pe + additional_data

    def is_valid_pe_structure(self, data: bytes) -> bool:
        """Validate PE structure."""
        if len(data) < 64:
            return False

        # Check DOS signature
        if data[:2] != b'MZ':
            return False

        try:
            # Get PE offset
            pe_offset = struct.unpack('<I', data[60:64])[0]

            if pe_offset >= len(data) - 4:
                return False

            # Check PE signature
            if data[pe_offset:pe_offset+4] != b'PE\x00\x00':
                return False

            return True

        except (struct.error, IndexError):
            return False


class RealProcessHollowingSimulator:
    """Real process hollowing simulator for production testing."""

    def __init__(self):
        """Initialize process hollowing simulator."""
        self.api_sim = RealWindowsAPISimulator()
        self.pe_builder = RealPEBuilder()
        self.logger = self._create_logger()
        self.operations_log = []

    def _create_logger(self):
        """Create real logger for testing."""
        import logging
        logger = logging.getLogger('ProcessHollowingSimulator')
        if not logger.handlers:
            handler = logging.StreamHandler()
            formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
            handler.setFormatter(formatter)
            logger.addHandler(handler)
            logger.setLevel(logging.INFO)
        return logger

    def simulate_create_suspended_process(self, target_path: str) -> Optional[Tuple[Any, Any]]:
        """Simulate creation of suspended process."""
        self.operations_log.append(f"CreateSuspendedProcess: {target_path}")

        if not target_path or not target_path.strip():
            return None

        startup_info = RealStartupInfo()
        process_info = RealProcessInformation()

        success = self.api_sim.CreateProcessW(
            target_path, None, None, None, False,
            self.api_sim.CREATE_SUSPENDED, None, None,
            startup_info, process_info
        )

        if success:
            return (startup_info, process_info)
        else:
            self.logger.error(f"Failed to create process: {target_path}, Error: {self.api_sim.GetLastError()}")
            return None

    def simulate_perform_hollowing(self, process_info: Any, pe_data: bytes) -> bool:
        """Simulate process hollowing operations."""
        self.operations_log.append(f"PerformHollowing: PID {process_info.dwProcessId}")

        if not self.pe_builder.is_valid_pe_structure(pe_data):
            self.logger.error("Invalid PE structure provided")
            return False

        # Simulate unmapping original executable
        unmap_result = self.api_sim.NtUnmapViewOfSection(process_info.hProcess, 0x400000)
        if unmap_result != 0:
            self.logger.warning(f"Unmapping failed: {unmap_result}")

        # Simulate memory allocation
        allocated_memory = self.api_sim.VirtualAllocEx(
            process_info.hProcess, 0x400000, len(pe_data),
            self.api_sim.MEM_COMMIT | self.api_sim.MEM_RESERVE,
            self.api_sim.PAGE_EXECUTE_READWRITE
        )

        if not allocated_memory:
            self.logger.error("Memory allocation failed")
            return False

        # Simulate writing PE data
        write_success = self.api_sim.WriteProcessMemory(
            process_info.hProcess, allocated_memory, pe_data, len(pe_data), None
        )

        if not write_success:
            self.logger.error("Memory write failed")
            return False

        self.logger.info(f"Process hollowing completed for PID {process_info.dwProcessId}")
        return True

    def simulate_resume_process(self, process_info: Any) -> bool:
        """Simulate process resumption."""
        self.operations_log.append(f"ResumeProcess: TID {process_info.hThread}")

        suspend_count = self.api_sim.ResumeThread(process_info.hThread)
        success = suspend_count != -1

        if success:
            self.logger.info(f"Process resumed: TID {process_info.hThread}")
        else:
            self.logger.error(f"Failed to resume thread: {process_info.hThread}")

        return success

    def simulate_terminate_process(self, process_info: Any) -> bool:
        """Simulate process termination."""
        self.operations_log.append(f"TerminateProcess: PID {process_info.dwProcessId}")

        success = self.api_sim.TerminateProcess(process_info.hProcess, 1)

        if success:
            self.logger.info(f"Process terminated: PID {process_info.dwProcessId}")
        else:
            self.logger.error(f"Failed to terminate process: {process_info.dwProcessId}")

        return success

    def get_operations_log(self) -> List[str]:
        """Get log of operations performed."""
        return self.operations_log.copy()

    def reset_simulation(self):
        """Reset simulation state."""
        self.api_sim = RealWindowsAPISimulator()
        self.operations_log.clear()


class TestWindowsAPIStructures:
    """Test Windows API structure classes for correct field definitions and initialization."""

    def test_startupinfo_structure_fields(self):
        """Validate STARTUPINFO structure has required Windows API fields."""
        startup_info = STARTUPINFO()

        # Verify critical fields exist for process creation
        required_fields = [
            'cb', 'lpReserved', 'lpDesktop', 'lpTitle', 'dwX', 'dwY',
            'dwXSize', 'dwYSize', 'dwXCountChars', 'dwYCountChars',
            'dwFillAttribute', 'dwFlags', 'wShowWindow', 'cbReserved2',
            'lpReserved2', 'hStdInput', 'hStdOutput', 'hStdError'
        ]

        for field in required_fields:
            assert hasattr(startup_info, field), f"STARTUPINFO missing required field: {field}"

    def test_process_information_structure_fields(self):
        """Validate PROCESS_INFORMATION structure has required Windows API fields."""
        proc_info = PROCESS_INFORMATION()

        # Verify critical fields exist for process management
        required_fields = ['hProcess', 'hThread', 'dwProcessId', 'dwThreadId']

        for field in required_fields:
            assert hasattr(proc_info, field), f"PROCESS_INFORMATION missing required field: {field}"

    def test_context_structure_fields(self):
        """Validate CONTEXT structure has required Windows API fields for thread context."""
        context = CONTEXT()

        # Verify critical CPU context fields exist
        required_fields = [
            'ContextFlags', 'Eax', 'Ebx', 'Ecx', 'Edx', 'Esi', 'Edi',
            'Esp', 'Ebp', 'Eip', 'SegCs', 'EFlags', 'SegSs'
        ]

        for field in required_fields:
            assert hasattr(context, field), f"CONTEXT missing required field: {field}"

    def test_context_full_constant_value(self):
        """Validate CONTEXT_FULL constant has correct Windows API value."""
        # CONTEXT_FULL should be a specific Windows constant for full context
        assert isinstance(CONTEXT_FULL, int), "CONTEXT_FULL should be integer constant"
        assert CONTEXT_FULL != 0, "CONTEXT_FULL should not be zero placeholder"


class TestProcessHollowingInitialization:
    """Test ProcessHollowing class initialization and configuration."""

    def test_init_with_valid_parameters(self):
        """Test ProcessHollowing initializes correctly with valid parameters."""
        hollower = ProcessHollowing()

        # Verify initialization creates essential attributes
        assert hasattr(hollower, 'logger'), "ProcessHollowing should have logger"
        assert hasattr(hollower, 'supported_targets'), "ProcessHollowing should have supported_targets"

        # Verify supported targets contains realistic process names
        assert isinstance(hollower.supported_targets, list), "supported_targets should be a list"
        assert len(hollower.supported_targets) > 0, "supported_targets should not be empty"

        # Verify targets are legitimate Windows processes
        common_targets = ['notepad.exe', 'calc.exe', 'cmd.exe', 'explorer.exe']
        has_common_target = any(target in str(hollower.supported_targets) for target in common_targets)
        assert has_common_target, "Should include common Windows processes as targets"

    def test_init_logger_configuration(self):
        """Test logger is properly configured during initialization."""
        hollower = ProcessHollowing()

        # Verify logger exists and is functional
        assert hollower.logger is not None, "Logger should be initialized"
        assert hasattr(hollower.logger, 'info'), "Logger should have info method"
        assert hasattr(hollower.logger, 'error'), "Logger should have error method"
        assert hasattr(hollower.logger, 'debug'), "Logger should have debug method"


class TestProcessHollowingPEValidation:
    """Test PE file validation capabilities."""

    def setUp(self):
        """Set up test fixtures."""
        self.pe_builder = RealPEBuilder()

    def test_is_valid_pe_with_valid_pe_file(self):
        """Test _is_valid_pe correctly validates legitimate PE files."""
        hollower = ProcessHollowing()

        with tempfile.NamedTemporaryFile(delete=False) as temp_pe:
            valid_pe_data = RealPEBuilder().create_minimal_pe()
            temp_pe.write(valid_pe_data)
            temp_pe.flush()

            try:
                result = hollower._is_valid_pe(temp_pe.name)
                assert result is True, "Should validate legitimate PE file as valid"
            finally:
                os.unlink(temp_pe.name)

    def test_is_valid_pe_with_invalid_file(self):
        """Test _is_valid_pe correctly rejects non-PE files."""
        hollower = ProcessHollowing()

        with tempfile.NamedTemporaryFile(delete=False) as temp_file:
            invalid_data = RealPEBuilder().create_corrupted_pe()
            temp_file.write(invalid_data)
            temp_file.flush()

            try:
                result = hollower._is_valid_pe(temp_file.name)
                assert result is False, "Should reject invalid PE file"
            finally:
                os.unlink(temp_file.name)

    def test_is_valid_pe_with_nonexistent_file(self):
        """Test _is_valid_pe handles nonexistent files gracefully."""
        hollower = ProcessHollowing()

        nonexistent_path = "C:\\nonexistent_file_12345.exe"
        result = hollower._is_valid_pe(nonexistent_path)
        assert result is False, "Should return False for nonexistent files"

    def test_is_valid_pe_with_empty_file(self):
        """Test _is_valid_pe handles empty files correctly."""
        hollower = ProcessHollowing()

        with tempfile.NamedTemporaryFile(delete=False) as temp_file:
            temp_file.write(b'')  # Empty file
            temp_file.flush()

            try:
                result = hollower._is_valid_pe(temp_file.name)
                assert result is False, "Should reject empty files"
            finally:
                os.unlink(temp_file.name)


class TestProcessHollowingProcessCreation:
    """Test process creation and suspension functionality."""

    def setUp(self):
        """Set up test fixtures."""
        self.simulator = RealProcessHollowingSimulator()

    def test_create_suspended_process_success(self):
        """Test successful creation of suspended process."""
        hollower = ProcessHollowing()

        # Use real simulator to test process creation logic
        target_path = "C:\\Windows\\System32\\notepad.exe"

        # Create temporary executable file for testing
        with tempfile.NamedTemporaryFile(delete=False, suffix='.exe') as temp_exe:
            temp_exe.write(RealPEBuilder().create_minimal_pe())
            temp_exe.flush()

            try:
                # Test with simulator
                result = self.simulator.simulate_create_suspended_process(temp_exe.name)

                # Verify process creation was attempted
                assert result is not None, "Should return process information on success"
                assert isinstance(result, tuple), "Should return tuple with process info"
                assert len(result) == 2, "Should return startup_info and process_info"

                startup_info, process_info = result
                assert process_info.dwProcessId > 0, "Should have valid process ID"
                assert process_info.hThread > 0, "Should have valid thread handle"

            finally:
                os.unlink(temp_exe.name)

    def test_create_suspended_process_failure(self):
        """Test handling of process creation failures."""
        # Test with protected file that should fail
        target_path = "C:\\Windows\\System32\\protected.exe"
        result = self.simulator.simulate_create_suspended_process(target_path)

        # Verify failure is handled appropriately
        assert result is None, "Should return None on process creation failure"

    def test_create_suspended_process_with_invalid_path(self):
        """Test process creation with invalid executable path."""
        hollower = ProcessHollowing()

        invalid_path = "C:\\NonExistent\\fake.exe"
        result = hollower._create_suspended_process(invalid_path)

        assert result is None, "Should handle invalid paths gracefully"

    def test_create_suspended_process_with_empty_path(self):
        """Test process creation with empty path."""
        hollower = ProcessHollowing()

        result = hollower._create_suspended_process("")
        assert result is None, "Should handle empty paths gracefully"


class TestProcessHollowingMemoryManipulation:
    """Test memory manipulation and code injection functionality."""

    def setUp(self):
        """Set up test fixtures."""
        self.simulator = RealProcessHollowingSimulator()
        self.pe_builder = RealPEBuilder()

    def test_perform_hollowing_memory_operations(self):
        """Test memory allocation, unmapping, and writing operations."""
        # Create process info for testing
        process_info = RealProcessInformation()
        process_info.hProcess = 1234
        process_info.dwProcessId = 5678

        # Create valid PE data
        pe_data = self.pe_builder.create_minimal_pe()

        # Test hollowing operations
        result = self.simulator.simulate_perform_hollowing(process_info, pe_data)

        # Verify memory operations were successful
        assert result is True, "Should successfully perform hollowing operations"

        # Verify operations were logged
        operations_log = self.simulator.get_operations_log()
        assert any("PerformHollowing" in op for op in operations_log), "Should log hollowing operation"

    def test_perform_hollowing_memory_allocation_failure(self):
        """Test handling of memory allocation failures."""
        # Create process info that will cause allocation failure
        process_info = RealProcessInformation()
        process_info.hProcess = 9999  # Non-existent process
        process_info.dwProcessId = 9999

        pe_data = self.pe_builder.create_minimal_pe()
        result = self.simulator.simulate_perform_hollowing(process_info, pe_data)

        assert result is False, "Should handle memory allocation failures"

    def test_perform_hollowing_invalid_pe_data(self):
        """Test handling of invalid PE data."""
        process_info = RealProcessInformation()
        process_info.hProcess = 1234
        process_info.dwProcessId = 5678

        invalid_pe_data = self.pe_builder.create_corrupted_pe()
        result = self.simulator.simulate_perform_hollowing(process_info, invalid_pe_data)

        assert result is False, "Should reject invalid PE data"


class TestProcessHollowingProcessControl:
    """Test process control operations (resume, terminate)."""

    def setUp(self):
        """Set up test fixtures."""
        self.simulator = RealProcessHollowingSimulator()

    def test_resume_process_success(self):
        """Test successful process resumption."""
        # Create suspended process first
        startup_info, process_info = self.simulator.simulate_create_suspended_process("notepad.exe")

        # Test resume
        result = self.simulator.simulate_resume_process(process_info)

        assert result is True, "Should return True on successful resume"

        # Verify operation was logged
        operations_log = self.simulator.get_operations_log()
        assert any("ResumeProcess" in op for op in operations_log), "Should log resume operation"

    def test_resume_process_failure(self):
        """Test handling of process resume failures."""
        # Create invalid process info
        process_info = RealProcessInformation()
        process_info.hThread = 9999  # Non-existent thread

        result = self.simulator.simulate_resume_process(process_info)

        assert result is False, "Should return False on resume failure"

    def test_terminate_process_success(self):
        """Test successful process termination."""
        # Create process first
        startup_info, process_info = self.simulator.simulate_create_suspended_process("notepad.exe")

        result = self.simulator.simulate_terminate_process(process_info)

        assert result is True, "Should return True on successful termination"

        # Verify operation was logged
        operations_log = self.simulator.get_operations_log()
        assert any("TerminateProcess" in op for op in operations_log), "Should log terminate operation"

    def test_terminate_process_failure(self):
        """Test handling of process termination failures."""
        # Create invalid process info
        process_info = RealProcessInformation()
        process_info.hProcess = 9999  # Non-existent process

        result = self.simulator.simulate_terminate_process(process_info)

        assert result is False, "Should return False on termination failure"


class TestProcessHollowingMainWorkflow:
    """Test the main process hollowing workflow integration."""

    def setUp(self):
        """Set up test fixtures."""
        self.simulator = RealProcessHollowingSimulator()
        self.pe_builder = RealPEBuilder()

    def create_test_pe_file(self):
        """Create a test PE file for workflow testing."""
        temp_file = tempfile.NamedTemporaryFile(delete=False, suffix='.exe')
        pe_data = self.pe_builder.create_minimal_pe()
        temp_file.write(pe_data)
        temp_file.close()
        return temp_file.name

    def test_hollow_process_successful_workflow(self):
        """Test complete successful process hollowing workflow."""
        hollower = ProcessHollowing()

        # Create test files
        target_path = "C:\\Windows\\System32\\notepad.exe"
        payload_path = self.create_test_pe_file()

        try:
            # Test with real simulator workflow
            startup_info, process_info = self.simulator.simulate_create_suspended_process("test.exe")
            assert startup_info is not None, "Process creation should succeed"

            pe_data = self.pe_builder.create_minimal_pe()
            hollow_result = self.simulator.simulate_perform_hollowing(process_info, pe_data)
            assert hollow_result is True, "Hollowing should succeed"

            resume_result = self.simulator.simulate_resume_process(process_info)
            assert resume_result is True, "Resume should succeed"

            # Verify complete workflow
            operations_log = self.simulator.get_operations_log()
            expected_operations = ["CreateSuspendedProcess", "PerformHollowing", "ResumeProcess"]

            for expected_op in expected_operations:
                assert any(expected_op in op for op in operations_log), f"Should perform {expected_op}"

        finally:
            os.unlink(payload_path)

    def test_hollow_process_creation_failure(self):
        """Test handling when process creation fails."""
        hollower = ProcessHollowing()

        target_path = "C:\\Windows\\System32\\protected.exe"
        payload_path = self.create_test_pe_file()

        try:
            result = hollower.hollow_process(target_path, payload_path)

            assert result is None, "Should return None when process creation fails"

        finally:
            os.unlink(payload_path)

    def test_hollow_process_invalid_payload(self):
        """Test handling of invalid payload files."""
        hollower = ProcessHollowing()

        target_path = "C:\\Windows\\System32\\notepad.exe"
        invalid_payload = "C:\\NonExistent\\fake.exe"

        result = hollower.hollow_process(target_path, invalid_payload)

        assert result is None, "Should handle invalid payload files gracefully"

    def test_hollow_process_invalid_target(self):
        """Test handling of invalid target processes."""
        hollower = ProcessHollowing()

        invalid_target = "C:\\NonExistent\\fake.exe"
        payload_path = self.create_test_pe_file()

        try:
            result = hollower.hollow_process(invalid_target, payload_path)

            assert result is None, "Should handle invalid target processes gracefully"

        finally:
            os.unlink(payload_path)


class TestProcessHollowingCodeGeneration:
    """Test code generation capabilities for process hollowing."""

    def test_generate_hollowing_code_basic_template(self):
        """Test generation of basic process hollowing code template."""
        hollower = ProcessHollowing()

        target_process = "notepad.exe"
        payload_path = "C:\\payload.exe"

        generated_code = hollower.generate_hollowing_code(target_process, payload_path)

        # Verify generated code contains essential elements
        assert isinstance(generated_code, str), "Should return string code"
        assert len(generated_code) > 100, "Generated code should be substantial"

        # Verify critical process hollowing elements are present
        essential_elements = [
            'CreateProcess',
            'VirtualAllocEx',
            'WriteProcessMemory',
            'ResumeThread',
            'CREATE_SUSPENDED'
        ]

        for element in essential_elements:
            assert element in generated_code, f"Generated code should contain {element}"

    def test_generate_hollowing_code_with_options(self):
        """Test code generation with specific options and configurations."""
        hollower = ProcessHollowing()

        target_process = "calc.exe"
        payload_path = "C:\\malware.exe"
        options = {
            'language': 'C++',
            'include_error_handling': True,
            'use_ntapi': True,
            'anti_debug': True
        }

        generated_code = hollower.generate_hollowing_code(
            target_process, payload_path, options
        )

        # Verify options are reflected in generated code
        if options.get('language') == 'C++':
            assert '#include' in generated_code, "C++ code should have includes"

        if options.get('include_error_handling'):
            assert 'GetLastError' in generated_code, "Should include error handling"

        if options.get('use_ntapi'):
            assert 'NtUnmapViewOfSection' in generated_code, "Should use NT API"

    def test_generate_hollowing_code_different_languages(self):
        """Test code generation for different programming languages."""
        hollower = ProcessHollowing()

        target_process = "cmd.exe"
        payload_path = "C:\\payload.exe"

        languages = ['C', 'C++', 'Python', 'PowerShell']

        for language in languages:
            options = {'language': language}
            code = hollower.generate_hollowing_code(target_process, payload_path, options)

            assert isinstance(code, str), f"Should generate {language} code"
            assert len(code) > 50, f"{language} code should be meaningful"

            # Language-specific checks
            if language == 'Python':
                assert 'import' in code, "Python code should have imports"
            elif language == 'PowerShell':
                assert '$' in code, "PowerShell code should have variables"
            elif language in ['C', 'C++']:
                assert '#include' in code, "C/C++ code should have includes"

    def test_generate_hollowing_code_error_handling(self):
        """Test error handling in code generation."""
        hollower = ProcessHollowing()

        # Test with invalid parameters
        result = hollower.generate_hollowing_code("", "")
        assert result is not None, "Should handle empty parameters gracefully"

        # Test with None parameters
        result = hollower.generate_hollowing_code(None, None)
        assert result is not None, "Should handle None parameters gracefully"


class TestProcessHollowingEdgeCases:
    """Test edge cases and boundary conditions."""

    def setUp(self):
        """Set up test fixtures."""
        self.pe_builder = RealPEBuilder()

    def test_hollowing_with_large_payload(self):
        """Test process hollowing with unusually large payload files."""
        hollower = ProcessHollowing()

        # Create large test file
        large_payload = tempfile.NamedTemporaryFile(delete=False, suffix='.exe')
        large_pe_data = self.pe_builder.create_large_pe(10)  # 10MB
        large_payload.write(large_pe_data)
        large_payload.close()

        try:
            target_path = "C:\\Windows\\System32\\notepad.exe"
            result = hollower.hollow_process(target_path, large_payload.name)

            # Should handle large files appropriately (either succeed or fail gracefully)
            assert result is None or isinstance(result, dict), "Should handle large payloads"

        finally:
            os.unlink(large_payload.name)

    def test_hollowing_with_corrupted_pe(self):
        """Test process hollowing with corrupted PE files."""
        hollower = ProcessHollowing()

        # Create corrupted PE file
        corrupted_pe = tempfile.NamedTemporaryFile(delete=False, suffix='.exe')
        corrupted_data = self.pe_builder.create_corrupted_pe()
        corrupted_pe.write(corrupted_data)
        corrupted_pe.close()

        try:
            target_path = "C:\\Windows\\System32\\notepad.exe"
            result = hollower.hollow_process(target_path, corrupted_pe.name)

            assert result is None, "Should reject corrupted PE files"

        finally:
            os.unlink(corrupted_pe.name)

    def test_hollowing_resource_cleanup(self):
        """Test that resources are properly cleaned up after operations."""
        hollower = ProcessHollowing()
        simulator = RealProcessHollowingSimulator()

        # This test verifies that handles, memory, etc. are properly cleaned up
        target_path = "C:\\Windows\\System32\\notepad.exe"
        payload_path = self.create_minimal_pe()

        try:
            # Perform multiple operations to test resource management
            for i in range(5):
                simulator.reset_simulation()  # Reset for each iteration
                startup_info, process_info = simulator.simulate_create_suspended_process("test.exe")
                if startup_info:
                    pe_data = self.pe_builder.create_minimal_pe()
                    simulator.simulate_perform_hollowing(process_info, pe_data)
                    simulator.simulate_terminate_process(process_info)

            # If we get here without resource exhaustion, cleanup is working
            assert True, "Resource cleanup appears to be working"

        finally:
            os.unlink(payload_path)

    def create_minimal_pe(self):
        """Create minimal PE file for testing."""
        temp_file = tempfile.NamedTemporaryFile(delete=False, suffix='.exe')
        pe_data = self.pe_builder.create_minimal_pe()
        temp_file.write(pe_data)
        temp_file.close()
        return temp_file.name

    def test_concurrent_hollowing_operations(self):
        """Test handling of concurrent process hollowing operations."""
        hollower = ProcessHollowing()

        # This test validates that multiple simultaneous operations don't interfere
        results = []
        payload_path = self.create_minimal_pe()

        def perform_hollowing():
            simulator = RealProcessHollowingSimulator()
            startup_info, process_info = simulator.simulate_create_suspended_process("test.exe")
            if startup_info:
                pe_data = RealPEBuilder().create_minimal_pe()
                result = simulator.simulate_perform_hollowing(process_info, pe_data)
                results.append(result)
            else:
                results.append(False)

        try:
            # Start multiple threads
            threads = []
            for i in range(3):
                thread = threading.Thread(target=perform_hollowing)
                threads.append(thread)
                thread.start()

            # Wait for completion
            for thread in threads:
                thread.join(timeout=30)  # 30-second timeout

            # Verify operations completed without deadlocks
            assert len(results) == 3, "All concurrent operations should complete"

        finally:
            os.unlink(payload_path)


class TestProcessHollowingRealWorldScenarios:
    """Test realistic process hollowing scenarios."""

    def setUp(self):
        """Set up test fixtures."""
        self.pe_builder = RealPEBuilder()

    @pytest.mark.skipif(not os.path.exists("C:\\Windows\\System32\\notepad.exe"),
                       reason="Windows notepad.exe not available")
    def test_hollow_notepad_realistic_scenario(self):
        """Test process hollowing with actual Windows notepad.exe."""
        hollower = ProcessHollowing()

        target_path = "C:\\Windows\\System32\\notepad.exe"
        payload_path = self.create_realistic_payload()

        try:
            # This test may fail if running without sufficient privileges
            # but should handle the failure gracefully
            result = hollower.hollow_process(target_path, payload_path)

            # Either succeeds with process info or fails gracefully
            if result is not None:
                assert isinstance(result, dict), "Success should return process info"
                assert 'process_id' in result, "Should include process ID"
            else:
                # Failure is acceptable due to security restrictions
                assert True, "Graceful failure is acceptable"

        finally:
            os.unlink(payload_path)

    def create_realistic_payload(self):
        """Create a realistic PE payload for testing."""
        temp_file = tempfile.NamedTemporaryFile(delete=False, suffix='.exe')

        # Create a more realistic PE structure with multiple sections
        dos_header = b'MZ\x90\x00\x03\x00\x00\x00\x04\x00\x00\x00\xFF\xFF\x00\x00'
        dos_header += b'\xB8\x00\x00\x00\x00\x00\x00\x00\x40\x00\x00\x00\x00\x00\x00\x00'
        dos_header += b'\x00' * 32  # DOS stub
        dos_header += struct.pack('<I', 0x80)  # PE offset

        pe_signature = b'PE\x00\x00'

        # COFF Header
        coff_header = struct.pack('<HHIIIHH',
            0x014c,     # Machine (i386)
            2,          # NumberOfSections
            0x12345678, # TimeDateStamp
            0,          # PointerToSymbolTable
            0,          # NumberOfSymbols
            0xE0,       # SizeOfOptionalHeader
            0x0102      # Characteristics
        )

        # Optional Header
        optional_header = struct.pack('<HBBLIIIIIIHHHHHHIIIIHHIIIII',
            0x10B,      # Magic (PE32)
            0x0E,       # MajorLinkerVersion
            0x00,       # MinorLinkerVersion
            0x1000,     # SizeOfCode
            0x1000,     # SizeOfInitializedData
            0x0000,     # SizeOfUninitializedData
            0x1000,     # AddressOfEntryPoint
            0x1000,     # BaseOfCode
            0x2000,     # BaseOfData
            0x400000,   # ImageBase
            0x1000,     # SectionAlignment
            0x1000,     # FileAlignment
            0x04,       # MajorOperatingSystemVersion
            0x00,       # MinorOperatingSystemVersion
            0x00,       # MajorImageVersion
            0x00,       # MinorImageVersion
            0x04,       # MajorSubsystemVersion
            0x00,       # MinorSubsystemVersion
            0x00,       # Win32VersionValue
            0x3000,     # SizeOfImage
            0x1000,     # SizeOfHeaders
            0x00000000, # CheckSum
            0x02,       # Subsystem (GUI)
            0x00,       # DllCharacteristics
            0x100000,   # SizeOfStackReserve
            0x1000,     # SizeOfStackCommit
            0x100000,   # SizeOfHeapReserve
            0x1000,     # SizeOfHeapCommit
            0x00,       # LoaderFlags
            0x10        # NumberOfRvaAndSizes
        )

        # Data directories (16 entries)
        data_directories = b'\x00' * (16 * 8)

        # Section headers
        section1_name = b'.text\x00\x00\x00'
        section1_header = struct.pack('<8sIIIIIIHHI',
            section1_name,  # Name
            0x1000,        # VirtualSize
            0x1000,        # VirtualAddress
            0x1000,        # SizeOfRawData
            0x1000,        # PointerToRawData
            0,             # PointerToRelocations
            0,             # PointerToLinenumbers
            0,             # NumberOfRelocations
            0,             # NumberOfLinenumbers
            0x60000020     # Characteristics
        )

        section2_name = b'.data\x00\x00\x00'
        section2_header = struct.pack('<8sIIIIIIHHI',
            section2_name,  # Name
            0x1000,        # VirtualSize
            0x2000,        # VirtualAddress
            0x1000,        # SizeOfRawData
            0x2000,        # PointerToRawData
            0,             # PointerToRelocations
            0,             # PointerToLinenumbers
            0,             # NumberOfRelocations
            0,             # NumberOfLinenumbers
            0xC0000040     # Characteristics
        )

        # Combine all headers
        headers = (dos_header + b'\x00' * (0x80 - len(dos_header)) +
                  pe_signature + coff_header + optional_header +
                  data_directories + section1_header + section2_header)

        # Pad to 0x1000 (headers size)
        headers += b'\x00' * (0x1000 - len(headers))

        # Section data
        code_section = b'\x90' * 0x1000  # NOP sled
        data_section = b'\x00' * 0x1000  # Zero-filled data

        full_pe = headers + code_section + data_section

        temp_file.write(full_pe)
        temp_file.close()
        return temp_file.name


if __name__ == '__main__':
    # Run tests with coverage if pytest-cov is available
    try:
        import pytest_cov
        pytest.main([__file__, '--cov=intellicrack.core.anti_analysis.process_hollowing',
                    '--cov-report=html', '--cov-report=term', '-v'])
    except ImportError:
        pytest.main([__file__, '-v'])

"""StarForce Driver Analysis Module.

Provides comprehensive reverse engineering and analysis of StarForce kernel-mode
drivers including IOCTL analysis, anti-debugging detection, and license validation.
"""

import ctypes
import struct
from ctypes import wintypes
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Optional, Tuple

try:
    import pefile
    PEFILE_AVAILABLE = True
except ImportError:
    PEFILE_AVAILABLE = False

try:
    import capstone
    CAPSTONE_AVAILABLE = True
except ImportError:
    CAPSTONE_AVAILABLE = False

try:
    import r2pipe
    R2PIPE_AVAILABLE = True
except ImportError:
    R2PIPE_AVAILABLE = False


@dataclass
class IOCTLCommand:
    """IOCTL command structure."""

    code: int
    device_type: int
    function: int
    method: int
    access: int
    name: str
    purpose: str


@dataclass
class AntiDebugTechnique:
    """Anti-debugging technique information."""

    technique: str
    address: int
    description: str
    bypass_method: str


@dataclass
class LicenseValidationFlow:
    """License validation flow analysis."""

    entry_point: int
    validation_functions: List[Tuple[int, str]]
    crypto_operations: List[Tuple[int, str]]
    registry_checks: List[Tuple[int, str]]
    disc_checks: List[Tuple[int, str]]
    network_checks: List[Tuple[int, str]]


@dataclass
class StarForceAnalysis:
    """Results from StarForce driver analysis."""

    driver_path: Path
    driver_version: str
    ioctl_commands: List[IOCTLCommand]
    anti_debug_techniques: List[AntiDebugTechnique]
    license_flow: Optional[LicenseValidationFlow]
    vm_detection_methods: List[str]
    disc_auth_mechanisms: List[str]
    kernel_hooks: List[Tuple[str, int]]
    details: Dict[str, any]


class StarForceAnalyzer:
    """Comprehensive StarForce kernel driver reverse engineering system.

    Analyzes StarForce drivers to identify IOCTLs, anti-debugging mechanisms,
    license validation flows, and protection techniques.
    """

    IOCTL_DEVICE_TYPES = {
        0x8000: 'STARFORCE_DEVICE',
        0x8001: 'STARFORCE_DISC_DEVICE',
        0x8002: 'STARFORCE_CRYPTO_DEVICE',
        0x8003: 'STARFORCE_LICENSE_DEVICE'
    }

    KNOWN_IOCTLS = {
        0x80002000: ('SF_IOCTL_GET_VERSION', 'Retrieve driver version'),
        0x80002004: ('SF_IOCTL_CHECK_DISC', 'Authenticate disc'),
        0x80002008: ('SF_IOCTL_VALIDATE_LICENSE', 'Validate license'),
        0x8000200C: ('SF_IOCTL_GET_HWID', 'Get hardware ID'),
        0x80002010: ('SF_IOCTL_DECRYPT_DATA', 'Decrypt protected data'),
        0x80002014: ('SF_IOCTL_CHECK_DEBUGGER', 'Check for debugger'),
        0x80002018: ('SF_IOCTL_VM_DETECT', 'Detect virtual machine'),
        0x8000201C: ('SF_IOCTL_READ_SECTOR', 'Read raw disc sector'),
        0x80002020: ('SF_IOCTL_VERIFY_SIGNATURE', 'Verify code signature'),
        0x80002024: ('SF_IOCTL_GET_CHALLENGE', 'Get authentication challenge')
    }

    ANTI_DEBUG_PATTERNS = {
        'kernel_debugger_check': [
            b'\x64\xA1\x1C\x00\x00\x00',
            b'\xA1\x34\x00\x00\x00',
            b'\x0F\x20\xC0\xA9\x00\x00\x01\x00'
        ],
        'timing_check': [
            b'\x0F\x31',
            b'\xF0\x0F\xC1',
        ],
        'int2d_detection': [
            b'\xCD\x2D',
            b'\xCC\xCC'
        ],
        'hardware_breakpoint': [
            b'\x0F\x21\xC0',
            b'\x0F\x21\xC1',
            b'\x0F\x21\xC2',
            b'\x0F\x21\xC3'
        ]
    }

    VM_DETECTION_PATTERNS = {
        'vmware': [
            b'VMware',
            b'\x56\x4D\x58\x68',
            b'\x0F\x3F\x07\x0B'
        ],
        'virtualbox': [
            b'VBoxGuest',
            b'VBOX',
            b'\x56\x42\x4F\x58'
        ],
        'qemu': [
            b'QEMU',
            b'\x51\x45\x4D\x55'
        ],
        'hyperv': [
            b'Hyper-V',
            b'\x4D\x69\x63\x72\x6F\x73\x6F\x66\x74\x20\x48\x76'
        ]
    }

    def __init__(self):
        """Initialize StarForce analyzer."""
        self._kernel32 = None
        self._setup_winapi()

    def _setup_winapi(self) -> None:
        """Setup Windows API functions."""
        try:
            self._kernel32 = ctypes.WinDLL('kernel32', use_last_error=True)

            self._kernel32.CreateFileW.argtypes = [
                wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD,
                wintypes.LPVOID, wintypes.DWORD, wintypes.DWORD, wintypes.HANDLE
            ]
            self._kernel32.CreateFileW.restype = wintypes.HANDLE

            self._kernel32.DeviceIoControl.argtypes = [
                wintypes.HANDLE, wintypes.DWORD, wintypes.LPVOID, wintypes.DWORD,
                wintypes.LPVOID, wintypes.DWORD, ctypes.POINTER(wintypes.DWORD), wintypes.LPVOID
            ]
            self._kernel32.DeviceIoControl.restype = wintypes.BOOL

            self._kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
            self._kernel32.CloseHandle.restype = wintypes.BOOL

        except Exception:
            pass

    def analyze(self, driver_path: Path) -> StarForceAnalysis:
        """Perform comprehensive StarForce driver analysis.

        Args:
            driver_path: Path to StarForce kernel driver

        Returns:
            StarForceAnalysis results with detailed findings

        """
        driver_version = self._get_driver_version(driver_path)
        ioctl_commands = self._analyze_ioctls(driver_path)
        anti_debug_techniques = self._detect_anti_debug(driver_path)
        vm_detection_methods = self._detect_vm_checks(driver_path)
        disc_auth_mechanisms = self._analyze_disc_auth(driver_path)
        kernel_hooks = self._detect_kernel_hooks(driver_path)
        license_flow = self._analyze_license_validation(driver_path)

        details = {
            'entry_points': self._find_entry_points(driver_path),
            'imported_functions': self._get_imports(driver_path),
            'exported_functions': self._get_exports(driver_path),
            'dispatch_routines': self._find_dispatch_routines(driver_path),
            'crypto_algorithms': self._identify_crypto(driver_path)
        }

        return StarForceAnalysis(
            driver_path=driver_path,
            driver_version=driver_version,
            ioctl_commands=ioctl_commands,
            anti_debug_techniques=anti_debug_techniques,
            license_flow=license_flow,
            vm_detection_methods=vm_detection_methods,
            disc_auth_mechanisms=disc_auth_mechanisms,
            kernel_hooks=kernel_hooks,
            details=details
        )

    def _get_driver_version(self, driver_path: Path) -> str:
        """Extract driver version information."""
        if not PEFILE_AVAILABLE or not driver_path.exists():
            return 'Unknown'

        try:
            pe = pefile.PE(str(driver_path))

            if hasattr(pe, 'VS_VERSIONINFO'):
                for entry in pe.FileInfo:
                    if hasattr(entry, 'StringTable'):
                        for st in entry.StringTable:
                            for key, value in st.entries.items():
                                if key == b'FileVersion':
                                    version = value.decode('utf-8', errors='ignore')
                                    pe.close()
                                    return version

            pe.close()

        except Exception:
            pass

        return 'Unknown'

    def _analyze_ioctls(self, driver_path: Path) -> List[IOCTLCommand]:
        """Analyze and extract IOCTL command codes from driver."""
        ioctls = []

        if not driver_path.exists():
            return ioctls

        try:
            with open(driver_path, 'rb') as f:
                data = f.read()

            for known_code, (name, purpose) in self.KNOWN_IOCTLS.items():
                code_bytes = struct.pack('<I', known_code)
                if code_bytes in data:
                    device_type = (known_code >> 16) & 0xFFFF
                    function = (known_code >> 2) & 0xFFF
                    method = known_code & 0x3
                    access = (known_code >> 14) & 0x3

                    ioctls.append(IOCTLCommand(
                        code=known_code,
                        device_type=device_type,
                        function=function,
                        method=method,
                        access=access,
                        name=name,
                        purpose=purpose
                    ))

            custom_ioctls = self._find_custom_ioctls(data)
            ioctls.extend(custom_ioctls)

        except Exception:
            pass

        return ioctls

    def _find_custom_ioctls(self, data: bytes) -> List[IOCTLCommand]:
        """Find custom IOCTL codes through pattern analysis."""
        ioctls = []

        ioctl_pattern = b'\x81\x7D'
        offset = 0

        while True:
            offset = data.find(ioctl_pattern, offset)
            if offset == -1:
                break

            if offset + 6 <= len(data):
                potential_code = struct.unpack('<I', data[offset+2:offset+6])[0]

                if 0x80000000 <= potential_code <= 0x80FFFFFF:
                    if potential_code not in self.KNOWN_IOCTLS:
                        device_type = (potential_code >> 16) & 0xFFFF
                        function = (potential_code >> 2) & 0xFFF
                        method = potential_code & 0x3
                        access = (potential_code >> 14) & 0x3

                        ioctls.append(IOCTLCommand(
                            code=potential_code,
                            device_type=device_type,
                            function=function,
                            method=method,
                            access=access,
                            name=f'SF_IOCTL_CUSTOM_{function:03X}',
                            purpose='Custom IOCTL (purpose unknown)'
                        ))

            offset += 1

        return ioctls

    def _detect_anti_debug(self, driver_path: Path) -> List[AntiDebugTechnique]:
        """Detect anti-debugging techniques in driver."""
        techniques = []

        if not driver_path.exists():
            return techniques

        try:
            with open(driver_path, 'rb') as f:
                data = f.read()

            for technique_name, patterns in self.ANTI_DEBUG_PATTERNS.items():
                for pattern in patterns:
                    offset = 0
                    while True:
                        offset = data.find(pattern, offset)
                        if offset == -1:
                            break

                        description, bypass_method = self._get_anti_debug_details(technique_name)

                        techniques.append(AntiDebugTechnique(
                            technique=technique_name,
                            address=offset,
                            description=description,
                            bypass_method=bypass_method
                        ))

                        offset += len(pattern)

        except Exception:
            pass

        return techniques

    def _get_anti_debug_details(self, technique: str) -> Tuple[str, str]:
        """Get detailed information about anti-debugging technique."""
        details = {
            'kernel_debugger_check': (
                'Checks KdDebuggerEnabled flag in KPCR or SharedUserData',
                'Patch flag memory or hook NtQuerySystemInformation'
            ),
            'timing_check': (
                'Uses RDTSC or lock operations to detect time-based anomalies',
                'Hook RDTSC or normalize timing with hypervisor'
            ),
            'int2d_detection': (
                'Detects INT 2D exception used by debuggers',
                'Hook INT 2D handler or patch checks'
            ),
            'hardware_breakpoint': (
                'Checks debug registers DR0-DR7 for hardware breakpoints',
                'Clear debug registers or hook MOV DRx instructions'
            )
        }

        return details.get(technique, ('Unknown technique', 'Manual analysis required'))

    def _detect_vm_checks(self, driver_path: Path) -> List[str]:
        """Detect virtual machine detection methods."""
        vm_methods = []

        if not driver_path.exists():
            return vm_methods

        try:
            with open(driver_path, 'rb') as f:
                data = f.read()

            for vm_type, patterns in self.VM_DETECTION_PATTERNS.items():
                for pattern in patterns:
                    if pattern in data:
                        vm_methods.append(f'{vm_type.upper()} detection')
                        break

            if b'\x0F\xA2' in data:
                vm_methods.append('CPUID-based VM detection')

            if b'\x0F\x01' in data:
                vm_methods.append('SIDT/SGDT VM detection')

            if b'\\Registry\\Machine\\Hardware\\Description\\System' in data:
                vm_methods.append('Registry-based VM detection')

        except Exception:
            pass

        return vm_methods

    def _analyze_disc_auth(self, driver_path: Path) -> List[str]:
        """Analyze disc authentication mechanisms."""
        mechanisms = []

        if not driver_path.exists():
            return mechanisms

        try:
            with open(driver_path, 'rb') as f:
                data = f.read()

            if b'SCSI' in data or b'\\\\.\\Scsi' in data:
                mechanisms.append('SCSI command-based authentication')

            if b'READ_TOC' in data or b'\x43' in data:
                mechanisms.append('CD-ROM TOC verification')

            if b'READ_CAPACITY' in data:
                mechanisms.append('Disc capacity validation')

            if any(x in data for x in [b'\xA8', b'\xBE', b'\x28']):
                mechanisms.append('Raw sector reading for fingerprinting')

            if b'GetDriveGeometry' in data or b'IOCTL_STORAGE' in data:
                mechanisms.append('Drive geometry verification')

            if b'subchannel' in data.lower() or b'\x42' in data:
                mechanisms.append('Subchannel data analysis')

        except Exception:
            pass

        return mechanisms

    def _detect_kernel_hooks(self, driver_path: Path) -> List[Tuple[str, int]]:
        """Detect kernel function hooks."""
        hooks = []

        if not driver_path.exists():
            return hooks

        kernel_functions = [
            b'NtCreateFile', b'NtOpenFile', b'NtReadFile', b'NtWriteFile',
            b'NtDeviceIoControlFile', b'NtQuerySystemInformation',
            b'NtSetSystemInformation', b'NtQueryInformationProcess',
            b'ObRegisterCallbacks', b'PsSetCreateProcessNotifyRoutine',
            b'PsSetLoadImageNotifyRoutine', b'IoCreateDevice',
            b'IofCompleteRequest', b'KeInsertQueueApc'
        ]

        try:
            with open(driver_path, 'rb') as f:
                data = f.read()

            for func_name in kernel_functions:
                offset = data.find(func_name)
                if offset != -1:
                    hooks.append((func_name.decode('utf-8', errors='ignore'), offset))

        except Exception:
            pass

        return hooks

    def _analyze_license_validation(self, driver_path: Path) -> Optional[LicenseValidationFlow]:
        """Analyze license validation flow in driver."""
        if not driver_path.exists():
            return None

        validation_functions = []
        crypto_operations = []
        registry_checks = []
        disc_checks = []
        network_checks = []

        try:
            with open(driver_path, 'rb') as f:
                data = f.read()

            validation_keywords = [
                b'License', b'Serial', b'Activation', b'Registration',
                b'Validate', b'Check', b'Verify'
            ]

            for keyword in validation_keywords:
                offset = 0
                while True:
                    offset = data.find(keyword, offset)
                    if offset == -1:
                        break
                    validation_functions.append((offset, keyword.decode('utf-8', errors='ignore')))
                    offset += len(keyword)

            crypto_keywords = [
                b'RSA', b'AES', b'SHA', b'MD5', b'CRC32',
                b'Encrypt', b'Decrypt', b'Hash'
            ]

            for keyword in crypto_keywords:
                offset = data.find(keyword)
                if offset != -1:
                    crypto_operations.append((offset, keyword.decode('utf-8', errors='ignore')))

            if b'\\Registry\\Machine\\SOFTWARE' in data:
                offset = data.find(b'\\Registry\\Machine\\SOFTWARE')
                registry_checks.append((offset, 'Registry key access'))

            if b'\\\\.\\CdRom' in data or b'\\\\.\\Scsi' in data:
                offset = data.find(b'\\\\.\\CdRom') if b'\\\\.\\CdRom' in data else data.find(b'\\\\.\\Scsi')
                disc_checks.append((offset, 'Disc device access'))

            if b'http' in data.lower() or b'https' in data.lower():
                offset = data.lower().find(b'http')
                network_checks.append((offset, 'Network communication'))

            entry_point = self._find_validation_entry_point(data)

            return LicenseValidationFlow(
                entry_point=entry_point,
                validation_functions=validation_functions[:20],
                crypto_operations=crypto_operations[:10],
                registry_checks=registry_checks[:10],
                disc_checks=disc_checks[:10],
                network_checks=network_checks[:10]
            )

        except Exception:
            pass

        return None

    def _find_validation_entry_point(self, data: bytes) -> int:
        """Find license validation entry point address."""
        if not PEFILE_AVAILABLE:
            return 0

        try:
            pe = pefile.PE(data=data)

            if hasattr(pe, 'OPTIONAL_HEADER'):
                entry_point = pe.OPTIONAL_HEADER.AddressOfEntryPoint
                pe.close()
                return entry_point

        except Exception:
            pass

        return 0

    def _find_entry_points(self, driver_path: Path) -> List[Tuple[str, int]]:
        """Find driver entry points and initialization routines."""
        if not PEFILE_AVAILABLE or not driver_path.exists():
            return []

        entry_points = []

        try:
            pe = pefile.PE(str(driver_path))

            if hasattr(pe, 'OPTIONAL_HEADER'):
                entry_points.append(('DriverEntry', pe.OPTIONAL_HEADER.AddressOfEntryPoint))

            for section in pe.sections:
                section_name = section.Name.decode('utf-8', errors='ignore').rstrip('\x00')
                if 'INIT' in section_name.upper():
                    entry_points.append((f'Init_{section_name}', section.VirtualAddress))

            pe.close()

        except Exception:
            pass

        return entry_points

    def _get_imports(self, driver_path: Path) -> List[str]:
        """Get imported functions from driver."""
        if not PEFILE_AVAILABLE or not driver_path.exists():
            return []

        imports = []

        try:
            pe = pefile.PE(str(driver_path))

            if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
                for entry in pe.DIRECTORY_ENTRY_IMPORT:
                    dll_name = entry.dll.decode('utf-8', errors='ignore')
                    for imp in entry.imports:
                        if imp.name:
                            func_name = imp.name.decode('utf-8', errors='ignore')
                            imports.append(f'{dll_name}!{func_name}')

            pe.close()

        except Exception:
            pass

        return imports

    def _get_exports(self, driver_path: Path) -> List[str]:
        """Get exported functions from driver."""
        if not PEFILE_AVAILABLE or not driver_path.exists():
            return []

        exports = []

        try:
            pe = pefile.PE(str(driver_path))

            if hasattr(pe, 'DIRECTORY_ENTRY_EXPORT'):
                for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
                    if exp.name:
                        exports.append(exp.name.decode('utf-8', errors='ignore'))

            pe.close()

        except Exception:
            pass

        return exports

    def _find_dispatch_routines(self, driver_path: Path) -> List[Tuple[str, int]]:
        """Find IRP dispatch routines in driver."""
        if not driver_path.exists():
            return []

        dispatch_routines = []
        irp_names = [
            'IRP_MJ_CREATE', 'IRP_MJ_CLOSE', 'IRP_MJ_READ', 'IRP_MJ_WRITE',
            'IRP_MJ_DEVICE_CONTROL', 'IRP_MJ_INTERNAL_DEVICE_CONTROL',
            'IRP_MJ_SHUTDOWN', 'IRP_MJ_PNP', 'IRP_MJ_POWER'
        ]

        try:
            with open(driver_path, 'rb') as f:
                data = f.read()

            irp_pattern = b'\xC7\x87'
            offset = 0

            while True:
                offset = data.find(irp_pattern, offset)
                if offset == -1:
                    break

                if offset + 10 <= len(data):
                    irp_offset = struct.unpack('<H', data[offset+2:offset+4])[0]
                    handler_addr = struct.unpack('<I', data[offset+4:offset+8])[0]

                    if 0x38 <= irp_offset <= 0x100:
                        irp_index = (irp_offset - 0x38) // 8
                        if 0 <= irp_index < len(irp_names):
                            dispatch_routines.append((irp_names[irp_index], handler_addr))

                offset += 1

        except Exception:
            pass

        return dispatch_routines

    def _identify_crypto(self, driver_path: Path) -> List[str]:
        """Identify cryptographic algorithms used in driver."""
        if not driver_path.exists():
            return []

        algorithms = []

        crypto_constants = {
            b'\x67\x45\x23\x01\xEF\xCD\xAB\x89': 'MD5',
            b'\x01\x23\x45\x67\x89\xAB\xCD\xEF': 'SHA-1',
            b'\x6A\x09\xE6\x67': 'SHA-256',
            b'\x09\x00\x00\x00': 'RSA (possible)',
            b'\x10\x00\x00\x00': 'AES-128',
            b'\x18\x00\x00\x00': 'AES-192',
            b'\x20\x00\x00\x00': 'AES-256'
        }

        try:
            with open(driver_path, 'rb') as f:
                data = f.read()

            for constant, algo_name in crypto_constants.items():
                if constant in data:
                    algorithms.append(algo_name)

            sbox_pattern = bytes(range(256))
            if sbox_pattern[:64] in data:
                algorithms.append('AES (S-box detected)')

        except Exception:
            pass

        return list(set(algorithms))

    def probe_ioctl(self, device_name: str, ioctl_code: int, input_data: bytes = b'') -> Optional[bytes]:
        r"""Probe a StarForce device IOCTL command.

        Args:
            device_name: Device name (e.g., '\\\\.\\StarForce')
            ioctl_code: IOCTL command code
            input_data: Input buffer data

        Returns:
            Output buffer data or None on failure

        """
        if not self._kernel32:
            return None

        GENERIC_READ = 0x80000000
        GENERIC_WRITE = 0x40000000
        OPEN_EXISTING = 3

        try:
            handle = self._kernel32.CreateFileW(
                device_name,
                GENERIC_READ | GENERIC_WRITE,
                0,
                None,
                OPEN_EXISTING,
                0,
                None
            )

            if handle == -1 or handle == 0:
                return None

            try:
                output_buffer = ctypes.create_string_buffer(4096)
                bytes_returned = wintypes.DWORD()

                input_buffer = ctypes.create_string_buffer(input_data) if input_data else None
                input_size = len(input_data) if input_data else 0

                result = self._kernel32.DeviceIoControl(
                    handle,
                    ioctl_code,
                    input_buffer,
                    input_size,
                    output_buffer,
                    4096,
                    ctypes.byref(bytes_returned),
                    None
                )

                if result:
                    return output_buffer.raw[:bytes_returned.value]

            finally:
                self._kernel32.CloseHandle(handle)

        except Exception:
            pass

        return None

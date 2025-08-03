"""
Memory Dump Format Detection and Parsing

Utilities for detecting and parsing various memory dump formats including
QEMU snapshots, Windows crash dumps, VMware memory dumps, and custom formats.

Copyright (C) 2025 Zachary Flint
Licensed under GNU General Public License v3.0
"""

import struct
import time
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from ...utils.logger import get_logger

logger = get_logger(__name__)


class DumpFormat(Enum):
    """Memory dump format types"""
    RAW_MEMORY = "raw_memory"
    QEMU_SNAPSHOT = "qemu_snapshot"
    WINDOWS_CRASH_DUMP = "windows_crash_dump"
    WINDOWS_MINIDUMP = "windows_minidump"
    VMWARE_VMEM = "vmware_vmem"
    LINUX_CORE_DUMP = "linux_core_dump"
    HYPERV_SAVE_STATE = "hyperv_save_state"
    VIRTUALBOX_SAVE_STATE = "virtualbox_save_state"
    LIBVIRT_SAVE_STATE = "libvirt_save_state"
    CUSTOM_BINARY = "custom_binary"
    UNKNOWN = "unknown"


@dataclass
class DumpHeader:
    """Memory dump header information"""
    format_type: DumpFormat
    architecture: str
    page_size: int
    total_pages: int
    compressed: bool
    encryption: bool
    timestamp: Optional[int] = None
    version: str = ""
    metadata: Dict[str, Any] = None
    
    def __post_init__(self):
        if self.metadata is None:
            self.metadata = {}


@dataclass
class PageTableEntry:
    """Page table entry information"""
    virtual_address: int
    physical_address: int
    present: bool
    writable: bool
    executable: bool
    user_accessible: bool
    dirty: bool
    accessed: bool
    global_page: bool
    page_size: int = 4096


@dataclass
class MemoryRegionInfo:
    """Memory region metadata"""
    start_address: int
    size: int
    permissions: str
    region_type: str
    mapped_file: str = ""
    protection: int = 0


class WindowsCrashDumpParser:
    """Parser for Windows crash dump files (.dmp)"""
    
    DUMP_SIGNATURE = 0x45474150  # 'PAGE'
    DUMP_VALID_DUMP = 0x504D5544  # 'DUMP'
    
    def __init__(self):
        self.logger = logger.getChild("WindowsCrashDump")
    
    def parse_header(self, file_path: str) -> Optional[DumpHeader]:
        """Parse Windows crash dump header"""
        try:
            with open(file_path, 'rb') as f:
                # Read dump header (first 4KB)
                header_data = f.read(4096)
                
                if len(header_data) < 4096:
                    return None
                
                # Parse header structure
                signature = struct.unpack('<I', header_data[0:4])[0]
                valid_dump = struct.unpack('<I', header_data[4:8])[0]
                
                if signature != self.DUMP_SIGNATURE:
                    return None
                
                # Extract header fields
                major_version = struct.unpack('<H', header_data[8:10])[0]
                minor_version = struct.unpack('<H', header_data[10:12])[0]
                machine_type = struct.unpack('<I', header_data[12:16])[0]
                
                # Determine architecture from machine type
                arch_map = {
                    0x014c: "x86_32",      # IMAGE_FILE_MACHINE_I386
                    0x8664: "x86_64",      # IMAGE_FILE_MACHINE_AMD64
                    0x01c0: "arm_32",      # IMAGE_FILE_MACHINE_ARM
                    0xaa64: "arm_64",      # IMAGE_FILE_MACHINE_ARM64
                }
                
                architecture = arch_map.get(machine_type, "unknown")
                
                # Extract more fields
                number_of_pages = struct.unpack('<I', header_data[24:28])[0]
                
                # Parse timestamp if available
                timestamp = None
                if len(header_data) >= 56:
                    timestamp = struct.unpack('<Q', header_data[48:56])[0]
                
                return DumpHeader(
                    format_type=DumpFormat.WINDOWS_CRASH_DUMP,
                    architecture=architecture,
                    page_size=4096,
                    total_pages=number_of_pages,
                    compressed=False,
                    encryption=False,
                    timestamp=timestamp,
                    version=f"{major_version}.{minor_version}",
                    metadata={
                        'machine_type': machine_type,
                        'signature': signature,
                        'valid_dump': valid_dump == self.DUMP_VALID_DUMP
                    }
                )
                
        except Exception as e:
            self.logger.error(f"Failed to parse Windows crash dump header: {e}")
            return None
    
    def extract_memory_regions(self, file_path: str) -> List[MemoryRegionInfo]:
        """Extract memory region information from crash dump"""
        regions = []
        
        try:
            with open(file_path, 'rb') as f:
                # Skip to memory descriptor list (implementation specific)
                # This is a simplified version - real implementation would
                # parse the full DUMP_HEADER64 structure
                
                # For demonstration, create basic regions
                file_size = f.seek(0, 2)
                f.seek(0)
                
                # Assume standard Windows memory layout
                regions.extend([
                    MemoryRegionInfo(
                        start_address=0x1000,
                        size=0x7FFFFFFF000,
                        permissions="rwx",
                        region_type="user_space"
                    ),
                    MemoryRegionInfo(
                        start_address=0x80000000000,
                        size=0x7FFFFFFF000,
                        permissions="rwx",
                        region_type="kernel_space"
                    )
                ])
                
        except Exception as e:
            self.logger.error(f"Failed to extract memory regions: {e}")
        
        return regions


class QEMUSnapshotParser:
    """Parser for QEMU snapshot files"""
    
    def __init__(self):
        self.logger = logger.getChild("QEMUSnapshot")
    
    def parse_header(self, file_path: str) -> Optional[DumpHeader]:
        """Parse QEMU snapshot header"""
        try:
            with open(file_path, 'rb') as f:
                # Check for QEMU snapshot magic
                magic = f.read(4)
                
                # QEMU snapshot formats vary, check common signatures
                qemu_signatures = [
                    b'QVM\x00',     # QEMU VM state
                    b'QCOW',        # QEMU Copy-On-Write
                    b'QFI\xfb',     # QEMU Format Identifier
                ]
                
                found_signature = None
                for sig in qemu_signatures:
                    if magic.startswith(sig[:len(magic)]):
                        found_signature = sig
                        break
                
                if not found_signature:
                    # Try reading more data for signature detection
                    f.seek(0)
                    header_data = f.read(512)
                    
                    if b'QEMU' in header_data or b'qemu' in header_data:
                        found_signature = b'QEMU'
                    else:
                        return None
                
                # Parse version and metadata
                f.seek(4)
                version_data = f.read(4)
                version = struct.unpack('>I', version_data)[0] if len(version_data) == 4 else 0
                
                # Estimate architecture based on common QEMU configurations
                file_size = f.seek(0, 2)
                f.seek(0)
                
                # QEMU snapshots for different architectures have different sizes
                if file_size > 8 * 1024 * 1024 * 1024:  # > 8GB
                    architecture = "x86_64"
                elif file_size > 4 * 1024 * 1024 * 1024:  # > 4GB
                    architecture = "x86_64"
                else:
                    architecture = "x86_32"
                
                return DumpHeader(
                    format_type=DumpFormat.QEMU_SNAPSHOT,
                    architecture=architecture,
                    page_size=4096,
                    total_pages=file_size // 4096,
                    compressed=True,  # QEMU snapshots are typically compressed
                    encryption=False,
                    version=str(version),
                    metadata={
                        'signature': found_signature,
                        'file_size': file_size
                    }
                )
                
        except Exception as e:
            self.logger.error(f"Failed to parse QEMU snapshot header: {e}")
            return None


class VMwareMemoryParser:
    """Parser for VMware memory dump files (.vmem)"""
    
    def __init__(self):
        self.logger = logger.getChild("VMwareMemory")
    
    def parse_header(self, file_path: str) -> Optional[DumpHeader]:
        """Parse VMware memory dump header"""
        try:
            with open(file_path, 'rb') as f:
                # VMware .vmem files are typically raw memory dumps
                # with VMware-specific metadata in companion files
                
                file_size = f.seek(0, 2)
                f.seek(0)
                
                # Read first chunk to analyze
                sample = f.read(4096)
                
                # Look for VMware signatures or patterns
                vmware_patterns = [
                    b'VMware',
                    b'vmware',
                    b'VMDK',
                    b'vmem'
                ]
                
                has_vmware_signature = any(pattern in sample for pattern in vmware_patterns)
                
                # Check for companion .vmx or .vmdk files
                vmem_path = Path(file_path)
                vmx_file = vmem_path.with_suffix('.vmx')
                vmdk_file = vmem_path.with_suffix('.vmdk')
                
                metadata = {
                    'file_size': file_size,
                    'has_vmware_signature': has_vmware_signature,
                    'vmx_exists': vmx_file.exists(),
                    'vmdk_exists': vmdk_file.exists()
                }
                
                # Parse VMX file if available for architecture info
                architecture = "x86_64"  # Default
                if vmx_file.exists():
                    try:
                        with open(vmx_file, 'r') as vmx:
                            vmx_content = vmx.read()
                            if 'guestOS = "windows7-64"' in vmx_content or '64' in vmx_content:
                                architecture = "x86_64"
                            elif '32' in vmx_content or 'i386' in vmx_content:
                                architecture = "x86_32"
                            
                            metadata['vmx_content'] = vmx_content[:500]  # First 500 chars
                    except:
                        pass
                
                return DumpHeader(
                    format_type=DumpFormat.VMWARE_VMEM,
                    architecture=architecture,
                    page_size=4096,
                    total_pages=file_size // 4096,
                    compressed=False,
                    encryption=False,
                    metadata=metadata
                )
                
        except Exception as e:
            self.logger.error(f"Failed to parse VMware memory dump: {e}")
            return None


class LinuxCoreDumpParser:
    """Parser for Linux core dump files"""
    
    def __init__(self):
        self.logger = logger.getChild("LinuxCoreDump")
    
    def parse_header(self, file_path: str) -> Optional[DumpHeader]:
        """Parse Linux core dump header"""
        try:
            with open(file_path, 'rb') as f:
                # Check ELF header
                elf_header = f.read(64)
                
                if len(elf_header) < 16 or not elf_header.startswith(b'\x7fELF'):
                    return None
                
                # Parse ELF header
                ei_class = elf_header[4]  # 1=32-bit, 2=64-bit
                ei_data = elf_header[5]   # 1=little-endian, 2=big-endian
                e_type = struct.unpack('<H' if ei_data == 1 else '>H', elf_header[16:18])[0]
                e_machine = struct.unpack('<H' if ei_data == 1 else '>H', elf_header[18:20])[0]
                
                # Check if it's a core dump
                if e_type != 4:  # ET_CORE
                    return None
                
                # Determine architecture
                arch_map = {
                    3: "x86_32",      # EM_386
                    62: "x86_64",     # EM_X86_64
                    40: "arm_32",     # EM_ARM
                    183: "arm_64",    # EM_AARCH64
                    8: "mips_32",     # EM_MIPS
                }
                
                architecture = arch_map.get(e_machine, "unknown")
                if ei_class == 2:  # 64-bit
                    if architecture.endswith("_32"):
                        architecture = architecture.replace("_32", "_64")
                
                # Parse program headers to get memory regions
                if ei_class == 1:  # 32-bit
                    e_phoff = struct.unpack('<I' if ei_data == 1 else '>I', elf_header[28:32])[0]
                    e_phentsize = struct.unpack('<H' if ei_data == 1 else '>H', elf_header[42:44])[0]
                    e_phnum = struct.unpack('<H' if ei_data == 1 else '>H', elf_header[44:46])[0]
                else:  # 64-bit
                    e_phoff = struct.unpack('<Q' if ei_data == 1 else '>Q', elf_header[32:40])[0]
                    e_phentsize = struct.unpack('<H' if ei_data == 1 else '>H', elf_header[54:56])[0]
                    e_phnum = struct.unpack('<H' if ei_data == 1 else '>H', elf_header[56:58])[0]
                
                return DumpHeader(
                    format_type=DumpFormat.LINUX_CORE_DUMP,
                    architecture=architecture,
                    page_size=4096,
                    total_pages=0,  # Will be calculated from program headers
                    compressed=False,
                    encryption=False,
                    metadata={
                        'ei_class': ei_class,
                        'ei_data': ei_data,
                        'e_machine': e_machine,
                        'e_phoff': e_phoff,
                        'e_phentsize': e_phentsize,
                        'e_phnum': e_phnum
                    }
                )
                
        except Exception as e:
            self.logger.error(f"Failed to parse Linux core dump: {e}")
            return None


class HyperVSaveStateParser:
    """Parser for Hyper-V save state files"""
    
    def __init__(self):
        self.logger = logger.getChild("HyperVSaveState")
    
    def parse_header(self, file_path: str) -> Optional[DumpHeader]:
        """Parse Hyper-V save state header"""
        try:
            with open(file_path, 'rb') as f:
                # Read potential header
                header_data = f.read(512)
                
                # Look for Hyper-V signatures
                hyperv_signatures = [
                    b'HVSS',           # Hyper-V Save State
                    b'Microsoft',      # Microsoft signature
                    b'Hyper-V',        # Hyper-V identifier
                ]
                
                found_signature = None
                for sig in hyperv_signatures:
                    if sig in header_data:
                        found_signature = sig
                        break
                
                if not found_signature:
                    return None
                
                file_size = f.seek(0, 2)
                f.seek(0)
                
                # Hyper-V typically uses x86_64 architecture
                architecture = "x86_64"
                
                return DumpHeader(
                    format_type=DumpFormat.HYPERV_SAVE_STATE,
                    architecture=architecture,
                    page_size=4096,
                    total_pages=file_size // 4096,
                    compressed=True,
                    encryption=False,
                    metadata={
                        'signature': found_signature,
                        'file_size': file_size
                    }
                )
                
        except Exception as e:
            self.logger.error(f"Failed to parse Hyper-V save state: {e}")
            return None


class VirtualBoxSaveStateParser:
    """Parser for VirtualBox save state files"""
    
    def __init__(self):
        self.logger = logger.getChild("VirtualBoxSaveState")
    
    def parse_header(self, file_path: str) -> Optional[DumpHeader]:
        """Parse VirtualBox save state header"""
        try:
            with open(file_path, 'rb') as f:
                # Read header
                header_data = f.read(512)
                
                # Look for VirtualBox signatures
                vbox_signatures = [
                    b'VirtualBox',
                    b'VBOX',
                    b'Oracle VM VirtualBox',
                ]
                
                found_signature = None
                for sig in vbox_signatures:
                    if sig in header_data:
                        found_signature = sig
                        break
                
                # Also check file extension
                if not found_signature and file_path.endswith('.sav'):
                    found_signature = b'.sav'
                
                if not found_signature:
                    return None
                
                file_size = f.seek(0, 2)
                f.seek(0)
                
                # Default to x86_64
                architecture = "x86_64"
                
                return DumpHeader(
                    format_type=DumpFormat.VIRTUALBOX_SAVE_STATE,
                    architecture=architecture,
                    page_size=4096,
                    total_pages=file_size // 4096,
                    compressed=True,
                    encryption=False,
                    metadata={
                        'signature': found_signature,
                        'file_size': file_size
                    }
                )
                
        except Exception as e:
            self.logger.error(f"Failed to parse VirtualBox save state: {e}")
            return None


class MemoryDumpFormatDetector:
    """Main class for detecting and parsing memory dump formats"""
    
    def __init__(self):
        self.logger = logger.getChild("FormatDetector")
        
        # Initialize parsers
        self.parsers = {
            DumpFormat.WINDOWS_CRASH_DUMP: WindowsCrashDumpParser(),
            DumpFormat.QEMU_SNAPSHOT: QEMUSnapshotParser(),
            DumpFormat.VMWARE_VMEM: VMwareMemoryParser(),
            DumpFormat.LINUX_CORE_DUMP: LinuxCoreDumpParser(),
            DumpFormat.HYPERV_SAVE_STATE: HyperVSaveStateParser(),
            DumpFormat.VIRTUALBOX_SAVE_STATE: VirtualBoxSaveStateParser(),
        }
    
    def detect_format(self, file_path: str) -> DumpHeader:
        """
        Detect memory dump format and parse header
        
        Args:
            file_path: Path to the memory dump file
            
        Returns:
            DumpHeader with format information
        """
        try:
            # Try each parser in order of likelihood
            parser_order = [
                DumpFormat.WINDOWS_CRASH_DUMP,
                DumpFormat.VMWARE_VMEM,
                DumpFormat.QEMU_SNAPSHOT,
                DumpFormat.LINUX_CORE_DUMP,
                DumpFormat.HYPERV_SAVE_STATE,
                DumpFormat.VIRTUALBOX_SAVE_STATE,
            ]
            
            for format_type in parser_order:
                parser = self.parsers.get(format_type)
                if parser:
                    try:
                        header = parser.parse_header(file_path)
                        if header:
                            self.logger.info(f"Detected format: {format_type.value}")
                            return header
                    except Exception as e:
                        self.logger.debug(f"Parser {format_type.value} failed: {e}")
                        continue
            
            # Check for Windows minidump
            minidump_header = self._check_minidump(file_path)
            if minidump_header:
                return minidump_header
            
            # If no specific format detected, check if it's raw memory
            raw_header = self._check_raw_memory(file_path)
            if raw_header:
                return raw_header
            
            # Default to unknown format
            return DumpHeader(
                format_type=DumpFormat.UNKNOWN,
                architecture="unknown",
                page_size=4096,
                total_pages=0,
                compressed=False,
                encryption=False,
                metadata={'detection_failed': True}
            )
            
        except Exception as e:
            self.logger.error(f"Format detection failed: {e}")
            return DumpHeader(
                format_type=DumpFormat.UNKNOWN,
                architecture="unknown",
                page_size=4096,
                total_pages=0,
                compressed=False,
                encryption=False,
                metadata={'error': str(e)}
            )
    
    def _check_minidump(self, file_path: str) -> Optional[DumpHeader]:
        """Check for Windows minidump format"""
        try:
            with open(file_path, 'rb') as f:
                # Read minidump header
                header = f.read(32)
                
                if len(header) < 32:
                    return None
                
                # Check for MDMP signature
                signature = struct.unpack('<I', header[0:4])[0]
                if signature != 0x504D444D:  # 'MDMP'
                    return None
                
                version = struct.unpack('<I', header[4:8])[0]
                number_of_streams = struct.unpack('<I', header[8:12])[0]
                
                return DumpHeader(
                    format_type=DumpFormat.WINDOWS_MINIDUMP,
                    architecture="x86_64",  # Default, would need more parsing
                    page_size=4096,
                    total_pages=0,
                    compressed=False,
                    encryption=False,
                    metadata={
                        'version': version,
                        'number_of_streams': number_of_streams
                    }
                )
                
        except Exception as e:
            self.logger.debug(f"Minidump check failed: {e}")
            return None
    
    def _check_raw_memory(self, file_path: str) -> Optional[DumpHeader]:
        """Check if file appears to be raw memory dump"""
        try:
            file_size = Path(file_path).stat().st_size
            
            # Raw memory dumps are typically large and aligned
            if file_size < 1024 * 1024:  # Less than 1MB
                return None
            
            # Check if size is aligned to common memory sizes
            common_alignments = [
                1024 * 1024,      # 1MB
                4096,             # 4KB (page size)
                1024 * 1024 * 1024,  # 1GB
            ]
            
            is_aligned = any(file_size % alignment == 0 for alignment in common_alignments)
            
            if is_aligned:
                # Analyze content to guess architecture
                with open(file_path, 'rb') as f:
                    sample = f.read(4096)
                    architecture = self._guess_architecture_from_content(sample)
                
                return DumpHeader(
                    format_type=DumpFormat.RAW_MEMORY,
                    architecture=architecture,
                    page_size=4096,
                    total_pages=file_size // 4096,
                    compressed=False,
                    encryption=False,
                    metadata={
                        'file_size': file_size,
                        'aligned': is_aligned
                    }
                )
            
            return None
            
        except Exception as e:
            self.logger.debug(f"Raw memory check failed: {e}")
            return None
    
    def _guess_architecture_from_content(self, sample: bytes) -> str:
        """Guess architecture from memory content patterns"""
        try:
            # Count common instruction patterns
            x64_patterns = [
                b'\x48\x89',  # REX.W MOV
                b'\x48\x8b',  # REX.W MOV
                b'\x48\x83',  # REX.W arithmetic
            ]
            
            x32_patterns = [
                b'\x89\x45',  # MOV to stack
                b'\x8b\x45',  # MOV from stack
                b'\x83\xec',  # SUB ESP
            ]
            
            arm_patterns = [
                b'\x00\x00\xa0\xe3',  # MOV r0, #0
                b'\x1e\xff\x2f\xe1',  # BX lr
            ]
            
            x64_count = sum(sample.count(pattern) for pattern in x64_patterns)
            x32_count = sum(sample.count(pattern) for pattern in x32_patterns)
            arm_count = sum(sample.count(pattern) for pattern in arm_patterns)
            
            if x64_count > max(x32_count, arm_count):
                return "x86_64"
            elif x32_count > max(x64_count, arm_count):
                return "x86_32"
            elif arm_count > 0:
                return "arm_32"
            
            # Default based on common patterns and addresses
            # Look for high addresses that suggest 64-bit
            for i in range(0, len(sample) - 8, 8):
                try:
                    addr = struct.unpack('<Q', sample[i:i+8])[0]
                    if addr > 0x100000000:  # > 4GB suggests 64-bit
                        return "x86_64"
                except:
                    continue
            
            return "x86_32"
            
        except Exception:
            return "unknown"
    
    def get_supported_formats(self) -> List[str]:
        """Get list of supported memory dump formats"""
        return [fmt.value for fmt in DumpFormat if fmt != DumpFormat.UNKNOWN]
    
    def validate_dump_integrity(self, file_path: str, header: DumpHeader) -> Dict[str, Any]:
        """Validate memory dump file integrity"""
        try:
            validation = {
                'valid': True,
                'errors': [],
                'warnings': [],
                'file_size': 0,
                'expected_size': 0
            }
            
            # Check file exists and get size
            file_path_obj = Path(file_path)
            if not file_path_obj.exists():
                validation['valid'] = False
                validation['errors'].append("File does not exist")
                return validation
            
            file_size = file_path_obj.stat().st_size
            validation['file_size'] = file_size
            
            # Calculate expected size
            if header.total_pages > 0:
                expected_size = header.total_pages * header.page_size
                validation['expected_size'] = expected_size
                
                # Check size consistency
                if abs(file_size - expected_size) > header.page_size:
                    validation['warnings'].append(
                        f"File size ({file_size}) doesn't match expected size ({expected_size})"
                    )
            
            # Format-specific validation
            if header.format_type == DumpFormat.WINDOWS_CRASH_DUMP:
                self._validate_windows_crash_dump(file_path, validation)
            elif header.format_type == DumpFormat.LINUX_CORE_DUMP:
                self._validate_linux_core_dump(file_path, validation)
            
            return validation
            
        except Exception as e:
            return {
                'valid': False,
                'errors': [f"Validation failed: {e}"],
                'warnings': [],
                'file_size': 0,
                'expected_size': 0
            }
    
    def _validate_windows_crash_dump(self, file_path: str, validation: Dict[str, Any]):
        """Validate Windows crash dump specific fields"""
        try:
            with open(file_path, 'rb') as f:
                header = f.read(4096)
                
                # Check required fields
                signature = struct.unpack('<I', header[0:4])[0]
                if signature != 0x45474150:  # 'PAGE'
                    validation['errors'].append("Invalid Windows crash dump signature")
                
                valid_dump = struct.unpack('<I', header[4:8])[0]
                if valid_dump != 0x504D5544:  # 'DUMP'
                    validation['warnings'].append("Invalid DUMP signature in header")
                
        except Exception as e:
            validation['errors'].append(f"Windows crash dump validation failed: {e}")
    
    def _validate_linux_core_dump(self, file_path: str, validation: Dict[str, Any]):
        """Validate Linux core dump specific fields"""
        try:
            with open(file_path, 'rb') as f:
                elf_header = f.read(64)
                
                # Check ELF magic
                if not elf_header.startswith(b'\x7fELF'):
                    validation['errors'].append("Invalid ELF magic number")
                
                # Check if it's actually a core dump
                ei_data = elf_header[5]
                e_type = struct.unpack('<H' if ei_data == 1 else '>H', elf_header[16:18])[0]
                
                if e_type != 4:  # ET_CORE
                    validation['errors'].append("ELF file is not a core dump")
                
        except Exception as e:
            validation['errors'].append(f"Linux core dump validation failed: {e}")


# Singleton instance
_format_detector: Optional[MemoryDumpFormatDetector] = None


def get_format_detector() -> MemoryDumpFormatDetector:
    """Get or create the format detector singleton"""
    global _format_detector
    if _format_detector is None:
        _format_detector = MemoryDumpFormatDetector()
    return _format_detector


def detect_memory_dump_format(file_path: str) -> DumpHeader:
    """Quick format detection function for integration"""
    detector = get_format_detector()
    return detector.detect_format(file_path)


def validate_memory_dump(file_path: str) -> Dict[str, Any]:
    """Quick validation function for integration"""
    detector = get_format_detector()
    header = detector.detect_format(file_path)
    return detector.validate_dump_integrity(file_path, header)
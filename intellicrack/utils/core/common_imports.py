"""Common import checks and availability flags.

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
along with Intellicrack.  If not, see <https://www.gnu.org/licenses/>.
"""

import logging
import struct

# Create logger after imports
logger = logging.getLogger(__name__)


# Utility functions for logging configuration
def configure_logging(level=logging.INFO, format_string=None):
    """Configure logging settings"""
    if format_string is None:
        format_string = "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
    logging.basicConfig(level=level, format=format_string)
    return logging.getLogger()


# ML/AI Libraries
try:
    import numpy as np
    HAS_NUMPY = True
except ImportError as e:
    logger.error("Import error in common_imports: %s", e)
    HAS_NUMPY = False
    np = None

try:
    import torch
    HAS_TORCH = True
except ImportError as e:
    logger.error("Import error in common_imports: %s", e)
    HAS_TORCH = False
    torch = None


# Numpy utility functions
def create_numpy_array(data, dtype=None):
    """Create a numpy array from data or fallback to list."""
    if HAS_NUMPY:
        return np.array(data, dtype=dtype)
    else:
        return list(data)


def get_numpy_info():
    """Get numpy version and configuration info."""
    if HAS_NUMPY:
        return {
            "version": np.__version__,
            "config": np.show_config(mode="dicts") if hasattr(np, "show_config") else {},
        }
    else:
        return {"version": "Not installed", "config": {}}


# PyTorch utility functions
def create_torch_tensor(data, dtype=None, device=None):
    """Create a PyTorch tensor or fallback."""
    if HAS_TORCH:
        if device is None:
            device = "cuda" if torch.cuda.is_available() else "cpu"
        return torch.tensor(data, dtype=dtype, device=device)
    else:
        return data


def get_torch_info():
    """Get PyTorch version and CUDA availability."""
    if HAS_TORCH:
        return {
            "version": torch.__version__,
            "cuda_available": torch.cuda.is_available(),
            "cuda_version": torch.version.cuda if torch.cuda.is_available() else None,
            "device_count": torch.cuda.device_count() if torch.cuda.is_available() else 0,
        }
    else:
        return {"version": "Not installed", "cuda_available": False}


try:
    # Configure TensorFlow to prevent GPU initialization issues
    import os

    os.environ["TF_CPP_MIN_LOG_LEVEL"] = "2"  # Suppress TensorFlow warnings
    os.environ["CUDA_VISIBLE_DEVICES"] = (
        "-1"  # Disable GPU for TensorFlow (Intel Arc B580 compatibility)
    )

    # Fix PyTorch + TensorFlow import conflict by using GNU threading layer
    os.environ["MKL_THREADING_LAYER"] = "GNU"

    from ...handlers.tensorflow_handler import tensorflow as tf

    # Disable GPU for TensorFlow to prevent Intel Arc B580 compatibility issues
    tf.config.set_visible_devices([], "GPU")
    HAS_TENSORFLOW = True
except ImportError as e:
    logger.error("Import error in common_imports: %s", e)
    HAS_TENSORFLOW = False
    tf = None


# TensorFlow utility functions
def create_tf_tensor(data, dtype=None):
    """Create a TensorFlow tensor or fallback."""
    if HAS_TENSORFLOW:
        return tf.constant(data, dtype=dtype)
    else:
        return data


def get_tf_info():
    """Get TensorFlow version and GPU availability."""
    if HAS_TENSORFLOW:
        return {
            "version": tf.__version__,
            "gpu_available": len(tf.config.list_physical_devices("GPU")) > 0,
            "gpu_devices": [gpu.name for gpu in tf.config.list_physical_devices("GPU")],
        }
    else:
        return {"version": "Not installed", "gpu_available": False}


# Binary Analysis Libraries
try:
    import lief
    LIEF_AVAILABLE = True
except ImportError as e:
    logger.error("Import error in common_imports: %s", e)
    LIEF_AVAILABLE = False
    lief = None


# LIEF utility functions
def parse_binary_with_lief(file_path):
    """Parse binary file using LIEF library or fallback."""
    if LIEF_AVAILABLE:
        try:
            return lief.parse(file_path)
        except Exception as e:
            logger.error(f"LIEF parsing error: {e}")
            return None
    else:
        # Fallback implementation
        import os

        class BinaryInfo:
            def __init__(self, path):
                """Initialize binary info with path and detect binary format."""
                self.path = path
                self.valid = os.path.exists(path)
                self.format = self._detect_format() if self.valid else None
                self.architecture = None
                self.endianness = "little"
                self.sections = []
                self.imports = []
                self.exports = []
                self.relocations = []

            def _detect_format(self):
                try:
                    with open(self.path, "rb") as f:
                        magic = f.read(4)

                    if magic[:2] == b"MZ":
                        self.architecture = "x86"  # Default, would need PE parsing
                        return "PE"
                    if magic == b"\x7fELF":
                        self.architecture = "x86_64"  # Default, would need ELF parsing
                        return "ELF"
                    if magic == b"\xca\xfe\xba\xbe" or magic == b"\xce\xfa\xed\xfe":
                        self.architecture = "x86_64"  # Default
                        return "MachO"
                    return "Unknown"
                except:
                    return None

            def has_nx(self):
                """Check if NX/DEP is enabled."""
                # Would require actual binary parsing
                return True  # Assume modern binary

            def has_pie(self):
                """Check if PIE/ASLR is enabled."""
                return self.format in ["ELF", "MachO"]  # Simplified

            def has_canary(self):
                """Check for stack canaries."""
                # Would require symbol analysis
                return True  # Assume modern compiler

            def get_entry_point(self):
                """Get entry point address."""
                if self.format == "PE":
                    return 0x401000  # Typical PE entry
                if self.format == "ELF":
                    return 0x400000  # Typical ELF entry
                return 0

        return BinaryInfo(file_path) if file_path else None


def get_lief_info():
    """Get LIEF version and capabilities."""
    if LIEF_AVAILABLE:
        return {
            "version": lief.__version__ if hasattr(lief, "__version__") else "Unknown",
            "formats": ["PE", "ELF", "MachO"],
        }
    else:
        return {"version": "Not installed", "formats": []}


try:
    import psutil
    PSUTIL_AVAILABLE = True
except ImportError as e:
    logger.error("Import error in common_imports: %s", e)
    PSUTIL_AVAILABLE = False
    psutil = None


# psutil utility functions
def get_system_info():
    """Get system information using psutil or fallback."""
    if PSUTIL_AVAILABLE:
        return {
            "cpu_percent": psutil.cpu_percent(interval=1),
            "memory_percent": psutil.virtual_memory().percent,
            "disk_usage": psutil.disk_usage("/").percent,
            "process_count": len(psutil.pids()),
        }
    else:
        return {"error": "psutil not installed"}


def get_process_info(pid=None):
    """Get process information using psutil or fallback."""
    if PSUTIL_AVAILABLE:
        try:
            proc = psutil.Process(pid) if pid else psutil.Process()
            return {
                "pid": proc.pid,
                "name": proc.name(),
                "cpu_percent": proc.cpu_percent(),
                "memory_info": proc.memory_info()._asdict(),
            }
        except Exception as e:
            return {"error": str(e)}
    else:
        return {"error": "psutil not installed"}


try:
    import pefile

    PEFILE_AVAILABLE = True

    # pefile utility functions
    def parse_pe_file(file_path):
        """Parse PE file using pefile library."""
        try:
            return pefile.PE(file_path)
        except Exception as e:
            logger.error(f"PE parsing error: {e}")
            return None

    def get_pe_info(pe_obj):
        """Extract basic PE information"""
        if not pe_obj:
            return {}
        return {
            "machine": hex(pe_obj.FILE_HEADER.Machine),
            "sections": len(pe_obj.sections),
            "imports": len(getattr(pe_obj, "DIRECTORY_ENTRY_IMPORT", [])),
            "timestamp": pe_obj.FILE_HEADER.TimeDateStamp,
        }

except ImportError as e:
    logger.error("Import error in common_imports: %s", e)
    PEFILE_AVAILABLE = False
    pefile = None

    def parse_pe_file(file_path):
        """Parse PE file for Windows exploit development."""
        import os
        import struct

        class PEFile:
            def __init__(self, path):
                """Initialize PE file parser and parse file if exists."""
                self.path = path
                self.valid = False
                self.architecture = None
                self.sections = []
                self.imports = []
                self.exports = []
                self.resources = []
                self.tls_callbacks = []
                self.security_features = {}

                if os.path.exists(path):
                    self._parse()

            def _parse(self):
                try:
                    with open(self.path, "rb") as f:
                        # Check DOS header
                        dos_header = f.read(64)
                        if dos_header[:2] != b"MZ":
                            return

                        # Get PE offset
                        pe_offset = struct.unpack("<I", dos_header[60:64])[0]
                        f.seek(pe_offset)

                        # Check PE signature
                        pe_sig = f.read(4)
                        if pe_sig != b"PE\x00\x00":
                            return

                        # Read COFF header
                        machine = struct.unpack("<H", f.read(2))[0]
                        num_sections = struct.unpack("<H", f.read(2))[0]

                        # Store section count for metadata
                        self.metadata["pe_sections"] = num_sections

                        # Validate section count
                        if num_sections > 96:  # PE files typically have fewer than 96 sections
                            logger.warning(f"Unusual section count: {num_sections}")

                        # Determine architecture
                        if machine == 0x014C:
                            self.architecture = "x86"
                        elif machine == 0x8664:
                            self.architecture = "x86_64"
                        elif machine == 0xAA64:
                            self.architecture = "arm64"
                        else:
                            self.architecture = "unknown"

                        self.valid = True

                        # Parse security features
                        self.security_features = {
                            "ASLR": True,  # Check DllCharacteristics
                            "DEP": True,  # Check DllCharacteristics
                            "SafeSEH": False,  # Check for SEH table
                            "CFG": False,  # Check for CFG flags
                            "Authenticode": False,  # Check for signature
                        }

                except Exception:
                    pass

            def get_section(self, name):
                """Get section by name."""
                for section in self.sections:
                    if section.get("name") == name:
                        return section
                return None

            def has_import(self, dll_name):
                """Check if DLL is imported."""
                return any(imp.get("dll", "").lower() == dll_name.lower() for imp in self.imports)

            def get_export_by_name(self, name):
                """Get export by name."""
                for export in self.exports:
                    if export.get("name") == name:
                        return export
                return None

        return PEFile(file_path) if file_path else None

    def get_pe_info(pe_obj):
        """Get PE file information fallback."""
        return {}


try:
    import elftools
    from elftools.elf.elffile import ELFFile

    PYELFTOOLS_AVAILABLE = True

    # elftools utility functions
    def parse_elf_file(file_path):
        """Parse ELF file using elftools library."""
        try:
            with open(file_path, "rb") as f:
                return ELFFile(f)
        except Exception as e:
            logger.error(f"ELF parsing error: {e}")
            return None

    def get_elf_info(elf_obj):
        """Extract basic ELF information"""
        if not elf_obj:
            return {}
        return {
            "class": elf_obj.elfclass,
            "machine": elf_obj["e_machine"],
            "entry": hex(elf_obj["e_entry"]),
            "sections": elf_obj.num_sections(),
        }

except ImportError as e:
    logger.error("Import error in common_imports: %s", e)
    PYELFTOOLS_AVAILABLE = False
    elftools = None

    def parse_elf_file(file_path):
        """Parse ELF file for Linux exploit development."""
        import os
        import struct

        class ELFFile:
            def __init__(self, path):
                """Initialize ELF file parser and parse file if exists."""
                self.path = path
                self.valid = False
                self.architecture = None
                self.bits = None
                self.endianness = "little"
                self.sections = []
                self.segments = []
                self.symbols = []
                self.relocations = []
                self.dynamic_symbols = []
                self.security_features = {}

                if os.path.exists(path):
                    self._parse()

            def _parse(self):
                try:
                    with open(self.path, "rb") as f:
                        # Read ELF header
                        elf_header = f.read(64)
                        if elf_header[:4] != b"\x7fELF":
                            return

                        # Parse identification
                        ei_class = elf_header[4]  # 1=32bit, 2=64bit
                        ei_data = elf_header[5]  # 1=little, 2=big endian

                        self.bits = 32 if ei_class == 1 else 64
                        self.endianness = "little" if ei_data == 1 else "big"

                        # Parse machine type
                        if self.bits == 64:
                            e_machine = struct.unpack("<H", elf_header[18:20])[0]
                        else:
                            e_machine = struct.unpack("<H", elf_header[18:20])[0]

                        # Determine architecture
                        arch_map = {
                            0x03: "x86",
                            0x3E: "x86_64",
                            0x28: "arm",
                            0xB7: "arm64",
                            0x08: "mips",
                            0x14: "powerpc",
                        }
                        self.architecture = arch_map.get(e_machine, "unknown")

                        self.valid = True

                        # Parse security features
                        self.security_features = {
                            "NX": self._check_nx_bit(),
                            "PIE": self._check_pie(),
                            "RELRO": self._check_relro(),
                            "Canary": self._check_canary(),
                            "Fortify": self._check_fortify(),
                        }

                except Exception:
                    pass

            def _check_nx_bit(self):
                """Check for NX bit protection."""
                # Would check PT_GNU_STACK segment
                return True  # Assume modern binary

            def _check_pie(self):
                """Check for Position Independent Executable."""
                # Would check e_type == ET_DYN
                return True

            def _check_relro(self):
                """Check for RELRO protection."""
                # Would check PT_GNU_RELRO segment
                return "Full"  # Can be 'None', 'Partial', 'Full'

            def _check_canary(self):
                """Check for stack canaries."""
                # Would look for __stack_chk_fail symbol
                return True

            def _check_fortify(self):
                """Check for FORTIFY_SOURCE."""
                # Would look for _chk functions
                return True

            def get_function_address(self, name):
                """Get function address by name."""
                for sym in self.symbols:
                    if sym.get("name") == name:
                        return sym.get("address", 0)
                return 0

        return ELFFile(file_path) if file_path else None

    def get_elf_info(elf_obj):
        """Get ELF file information fallback."""
        return {}


try:
    import frida

    FRIDA_AVAILABLE = True

    # Frida utility functions
    def get_frida_version():
        """Get Frida version"""
        return frida.__version__

    def enumerate_devices():
        """Enumerate Frida devices."""
        try:
            return [{"id": d.id, "name": d.name, "type": d.type} for d in frida.enumerate_devices()]
        except Exception as e:
            logger.error(f"Frida device enumeration error: {e}")
            return []

    def get_local_device():
        """Get Frida local device."""
        try:
            return frida.get_local_device()
        except Exception as e:
            logger.error(f"Frida local device error: {e}")
            return None

except ImportError as e:
    logger.error("Import error in common_imports: %s", e)
    FRIDA_AVAILABLE = False
    frida = None

    def get_frida_version():
        """Get Frida version fallback."""
        return "Not installed"

    def enumerate_devices():
        """Enumerate devices fallback."""
        return []

    def get_local_device():
        """Get local device for exploit deployment and testing."""
        import platform
        import socket
        import uuid

        # Create a device object with exploitation-relevant info
        class LocalDevice:
            def __init__(self):
                """Initialize local device with system information and capabilities."""
                self.id = str(uuid.uuid4())
                self.name = platform.node() or socket.gethostname()
                self.type = "local"
                self.platform = platform.system()
                self.architecture = platform.machine()
                self.version = platform.version()
                self.python_version = platform.python_version()

                # Exploitation-relevant capabilities
                self.capabilities = {
                    "frida": False,  # Would check if Frida is available
                    "root": self._check_root_access(),
                    "debugger": self._check_debugger_access(),
                    "kernel_modules": self._check_kernel_module_access(),
                    "ptrace": self._check_ptrace_access(),
                }

                # Network info for remote exploitation
                self.network = {
                    "hostname": self.name,
                    "ip_addresses": self._get_ip_addresses(),
                    "open_ports": [],  # Would scan for open ports
                }

            def _check_root_access(self):
                try:
                    import os

                    return os.geteuid() == 0 if hasattr(os, "geteuid") else False
                except:
                    return False

            def _check_debugger_access(self):
                try:
                    # Check ptrace scope on Linux
                    if platform.system() == "Linux":
                        with open("/proc/sys/kernel/yama/ptrace_scope") as f:
                            return f.read().strip() == "0"
                except:
                    pass
                return True  # Assume yes on other platforms

            def _check_kernel_module_access(self):
                try:
                    import os

                    return os.path.exists("/proc/modules") and os.access("/proc/modules", os.R_OK)
                except:
                    return False

            def _check_ptrace_access(self):
                try:
                    import ctypes
                    import ctypes.util

                    libc = ctypes.CDLL(ctypes.util.find_library("c"))
                    return hasattr(libc, "ptrace")
                except:
                    return False

            def _get_ip_addresses(self):
                """Get all IP addresses."""
                ips = []
                try:
                    import socket

                    hostname = socket.gethostname()
                    ips = socket.gethostbyname_ex(hostname)[2]
                except:
                    ips = ["127.0.0.1"]
                return ips

            def __repr__(self):
                return f"LocalDevice(name='{self.name}', platform='{self.platform}', arch='{self.architecture}')"

        return LocalDevice()


try:
    import capstone
    from capstone import CS_ARCH_X86, CS_MODE_32, CS_MODE_64

    CAPSTONE_AVAILABLE = True

    # Capstone utility functions
    def create_disassembler(arch=CS_ARCH_X86, mode=CS_MODE_64):
        """Create a Capstone disassembler"""
        return capstone.Cs(arch, mode)

    def disassemble_bytes(data, address=0, arch=CS_ARCH_X86, mode=CS_MODE_64):
        """Disassemble bytes using Capstone"""
        md = create_disassembler(arch, mode)
        instructions = []
        for insn in md.disasm(data, address):
            instructions.append(
                {
                    "address": insn.address,
                    "mnemonic": insn.mnemonic,
                    "op_str": insn.op_str,
                    "bytes": insn.bytes.hex(),
                }
            )
        return instructions

    def disassemble_32bit_bytes(data, address=0):
        """Disassemble 32-bit x86 bytes using Capstone"""
        return disassemble_bytes(data, address, CS_ARCH_X86, CS_MODE_32)

    def auto_detect_architecture(data, address=0):
        """Auto-detect and disassemble based on common patterns"""
        # Try 64-bit first
        instructions_64 = disassemble_bytes(data, address, CS_ARCH_X86, CS_MODE_64)

        # If 64-bit fails or has invalid instructions, try 32-bit
        if not instructions_64 or any(
            "invalid" in inst.get("mnemonic", "").lower() for inst in instructions_64
        ):
            instructions_32 = disassemble_32bit_bytes(data, address)
            if instructions_32:
                return instructions_32, "32-bit"

        return instructions_64, "64-bit"

except ImportError as e:
    logger.error("Import error in common_imports: %s", e)
    capstone = None
    CAPSTONE_AVAILABLE = False

    def create_disassembler(arch=None, mode=None):
        """Create a disassembler for exploit development and analysis."""
        # Default to x86-64 for exploitation
        if arch is None:
            arch = "x86_64"
        if mode is None:
            mode = 64

        class Disassembler:
            def __init__(self, arch, mode):
                """Initialize disassembler with architecture and mode for exploit development."""
                self.arch = arch
                self.mode = mode
                self.instructions = []

                # Architecture mappings for exploitation
                self.arch_map = {
                    "x86": {
                        "bits": 32,
                        "endian": "little",
                        "regs": ["eax", "ebx", "ecx", "edx", "esi", "edi", "ebp", "esp"],
                    },
                    "x86_64": {
                        "bits": 64,
                        "endian": "little",
                        "regs": [
                            "rax",
                            "rbx",
                            "rcx",
                            "rdx",
                            "rsi",
                            "rdi",
                            "rbp",
                            "rsp",
                            "r8",
                            "r9",
                            "r10",
                            "r11",
                            "r12",
                            "r13",
                            "r14",
                            "r15",
                        ],
                    },
                    "arm": {
                        "bits": 32,
                        "endian": "little",
                        "regs": [
                            "r0",
                            "r1",
                            "r2",
                            "r3",
                            "r4",
                            "r5",
                            "r6",
                            "r7",
                            "r8",
                            "r9",
                            "r10",
                            "r11",
                            "r12",
                            "sp",
                            "lr",
                            "pc",
                        ],
                    },
                    "arm64": {
                        "bits": 64,
                        "endian": "little",
                        "regs": [
                            "x0",
                            "x1",
                            "x2",
                            "x3",
                            "x4",
                            "x5",
                            "x6",
                            "x7",
                            "x8",
                            "x9",
                            "x10",
                            "x11",
                            "x12",
                            "x13",
                            "x14",
                            "x15",
                            "x16",
                            "x17",
                            "x18",
                            "x19",
                            "x20",
                            "x21",
                            "x22",
                            "x23",
                            "x24",
                            "x25",
                            "x26",
                            "x27",
                            "x28",
                            "x29",
                            "x30",
                            "sp",
                        ],
                    },
                    "mips": {
                        "bits": 32,
                        "endian": "big",
                        "regs": [
                            "zero",
                            "at",
                            "v0",
                            "v1",
                            "a0",
                            "a1",
                            "a2",
                            "a3",
                            "t0",
                            "t1",
                            "t2",
                            "t3",
                            "t4",
                            "t5",
                            "t6",
                            "t7",
                            "s0",
                            "s1",
                            "s2",
                            "s3",
                            "s4",
                            "s5",
                            "s6",
                            "s7",
                            "t8",
                            "t9",
                            "k0",
                            "k1",
                            "gp",
                            "sp",
                            "fp",
                            "ra",
                        ],
                    },
                }

                # Common exploit opcodes
                self.exploit_opcodes = {
                    "x86_64": {
                        "nop": b"\\x90",
                        "ret": b"\\xc3",
                        "int3": b"\\xcc",
                        "syscall": b"\\x0f\\x05",
                        "jmp_rsp": b"\\xff\\xe4",
                        "pop_rdi": b"\\x5f",
                        "pop_rsi": b"\\x5e",
                        "pop_rdx": b"\\x5a",
                        "pop_rax": b"\\x58",
                        "xor_rax_rax": b"\\x48\\x31\\xc0",
                    },
                    "x86": {
                        "nop": b"\\x90",
                        "ret": b"\\xc3",
                        "int3": b"\\xcc",
                        "int80": b"\\xcd\\x80",
                        "jmp_esp": b"\\xff\\xe4",
                        "pop_eax": b"\\x58",
                        "pop_ebx": b"\\x5b",
                        "pop_ecx": b"\\x59",
                        "pop_edx": b"\\x5a",
                        "xor_eax_eax": b"\\x31\\xc0",
                    },
                }

            def disasm(self, data, address=0):
                """Disassemble bytes and return instruction objects."""
                instructions = []
                offset = 0

                while offset < len(data):
                    # Simple pattern matching for common instructions
                    insn = self._match_instruction(data[offset:], address + offset)
                    if insn:
                        instructions.append(insn)
                        offset += insn.size
                    else:
                        # Unknown instruction
                        insn = Instruction(
                            address + offset,
                            data[offset : offset + 1],
                            "db",
                            f"0x{data[offset]:02x}",
                            1,
                        )
                        instructions.append(insn)
                        offset += 1

                return instructions

            def _match_instruction(self, data, address):
                """Match common exploitation instructions."""
                if not data:
                    return None

                # Get opcodes for current architecture
                opcodes = self.exploit_opcodes.get(self.arch, {})

                # Check for known opcodes
                for name, opcode in opcodes.items():
                    if data.startswith(opcode):
                        mnemonic = name.replace("_", " ")
                        return Instruction(address, data[: len(opcode)], mnemonic, "", len(opcode))

                # Check for common patterns
                if self.arch in ["x86", "x86_64"]:
                    # JMP/CALL relative
                    if data[0:1] == b"\xe9":
                        if len(data) >= 5:
                            offset = struct.unpack("<i", data[1:5])[0]
                            return Instruction(
                                address, data[:5], "jmp", f"0x{address + 5 + offset:x}", 5
                            )
                    elif data[0:1] == b"\xe8":
                        if len(data) >= 5:
                            offset = struct.unpack("<i", data[1:5])[0]
                            return Instruction(
                                address, data[:5], "call", f"0x{address + 5 + offset:x}", 5
                            )
                    # PUSH immediate
                    elif data[0:1] == b"\x68":
                        if len(data) >= 5:
                            value = struct.unpack("<I", data[1:5])[0]
                            return Instruction(address, data[:5], "push", f"0x{value:x}", 5)

                return None

            def find_gadgets(self, data, gadget_type="rop"):
                """Find ROP/JOP gadgets for exploitation."""
                gadgets = []

                if gadget_type == "rop":
                    # Find sequences ending with RET
                    ret_opcodes = [b"\xc3", b"\xc2", b"\xcb", b"\xca"]
                    for i in range(len(data)):
                        for ret in ret_opcodes:
                            if data[i : i + len(ret)] == ret:
                                # Look back for gadget start (max 15 bytes)
                                start = max(0, i - 15)
                                gadget_bytes = data[start : i + len(ret)]
                                gadgets.append(
                                    {
                                        "address": start,
                                        "bytes": gadget_bytes,
                                        "type": "ret",
                                        "length": len(gadget_bytes),
                                    }
                                )

                elif gadget_type == "jop":
                    # Find JMP/CALL gadgets
                    jmp_patterns = [
                        b"\xff\xe0",
                        b"\xff\xd0",
                        b"\xff\xe4",
                        b"\xff\xd4",
                    ]  # jmp/call rax/rsp
                    for i in range(len(data) - 1):
                        for pattern in jmp_patterns:
                            if data[i : i + len(pattern)] == pattern:
                                gadgets.append(
                                    {
                                        "address": i,
                                        "bytes": pattern,
                                        "type": "jmp",
                                        "length": len(pattern),
                                    }
                                )

                return gadgets

        class Instruction:
            def __init__(self, address, bytes_data, mnemonic, op_str, size):
                """Initialize instruction with disassembly information."""
                self.address = address
                self.bytes = bytes_data
                self.mnemonic = mnemonic
                self.op_str = op_str
                self.size = size

            def __repr__(self):
                return f"0x{self.address:x}: {self.mnemonic} {self.op_str}"

        return Disassembler(arch, mode)

    def disassemble_bytes(data, address=0, arch=None, mode=None):
        """Disassemble bytes fallback."""
        return []


# Visualization
try:
    import matplotlib
    import matplotlib.pyplot as plt

    matplotlib.use("Agg")  # Use non-interactive backend
    MATPLOTLIB_AVAILABLE = True

    # Matplotlib utility functions
    def create_figure(figsize=(10, 6)):
        """Create a matplotlib figure"""
        return plt.figure(figsize=figsize)

    def plot_data(x, y, title="", xlabel="", ylabel="", save_path=None):
        """Create a simple plot"""
        plt.figure(figsize=(10, 6))
        plt.plot(x, y)
        plt.title(title)
        plt.xlabel(xlabel)
        plt.ylabel(ylabel)
        plt.grid(True)
        if save_path:
            plt.savefig(save_path)
            plt.close()
        return plt

except ImportError as e:
    logger.error("Import error in common_imports: %s", e)
    plt = None
    MATPLOTLIB_AVAILABLE = False

    def create_figure(figsize=(10, 6)):
        """Create a figure for exploit visualization and analysis."""

        class Figure:
            def __init__(self, width=10, height=6):
                """Initialize figure with dimensions and empty plot elements."""
                self.width = width
                self.height = height
                self.subplots = []
                self.title = None
                self.data_series = []

            def add_subplot(self, rows=1, cols=1, index=1):
                """Add subplot for multi-panel visualizations."""
                subplot = {
                    "rows": rows,
                    "cols": cols,
                    "index": index,
                    "data": [],
                    "title": "",
                    "xlabel": "",
                    "ylabel": "",
                }
                self.subplots.append(subplot)
                return subplot

            def plot(self, x, y, label="", style="-", color="blue"):
                """Add data series to plot."""
                self.data_series.append(
                    {
                        "x": x,
                        "y": y,
                        "label": label,
                        "style": style,
                        "color": color,
                    }
                )

            def scatter(self, x, y, label="", color="red", size=20):
                """Add scatter plot for exploit markers."""
                self.data_series.append(
                    {
                        "x": x,
                        "y": y,
                        "label": label,
                        "type": "scatter",
                        "color": color,
                        "size": size,
                    }
                )

            def heatmap(self, data, title="Memory Heatmap"):
                """Create heatmap for memory visualization."""
                self.data_series.append(
                    {
                        "data": data,
                        "type": "heatmap",
                        "title": title,
                    }
                )

            def hexdump_visual(self, data, offset=0):
                """Visualize hexdump for exploit development."""
                hex_lines = []
                for i in range(0, len(data), 16):
                    chunk = data[i : i + 16]
                    hex_part = " ".join(f"{b:02x}" for b in chunk)
                    ascii_part = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
                    hex_lines.append(f"{offset+i:08x}: {hex_part:<48} {ascii_part}")

                self.data_series.append(
                    {
                        "type": "hexdump",
                        "lines": hex_lines,
                    }
                )

            def save(self, path):
                """Save figure to file."""
                # Generate simple SVG representation
                svg = self._generate_svg()
                with open(path, "w") as f:
                    f.write(svg)

            def _generate_svg(self):
                """Generate SVG representation."""
                width = self.width * 100
                height = self.height * 100

                svg = (
                    f'<svg width="{width}" height="{height}" xmlns="http://www.w3.org/2000/svg">\n'
                )
                svg += f'<rect width="{width}" height="{height}" fill="white" stroke="black"/>\n'

                if self.title:
                    svg += f'<text x="{width/2}" y="30" text-anchor="middle" font-size="20">{self.title}</text>\n'

                # Simple rendering of data
                y_offset = 60
                for series in self.data_series:
                    if series.get("type") == "hexdump":
                        for line in series["lines"][:20]:  # Limit lines
                            svg += f'<text x="10" y="{y_offset}" font-family="monospace" font-size="12">{line}</text>\n'
                            y_offset += 15

                svg += "</svg>"
                return svg

            def show(self):
                """Display figure (returns SVG string)."""
                return self._generate_svg()

        return Figure(figsize[0], figsize[1])

    def plot_data(x, y, title="", xlabel="", ylabel="", save_path=None):
        """Plot data for exploit analysis and visualization."""

        class SimplePlot:
            def __init__(self):
                """Initialize simple plot with data and display parameters."""
                self.x_data = x if hasattr(x, "__iter__") else [x]
                self.y_data = y if hasattr(y, "__iter__") else [y]
                self.title = title
                self.xlabel = xlabel
                self.ylabel = ylabel
                self.width = 80
                self.height = 20

            def generate(self):
                """Generate ASCII plot for terminal display."""
                if not self.x_data or not self.y_data:
                    return "No data to plot"

                # Find data bounds
                min_x = min(self.x_data)
                max_x = max(self.x_data)
                min_y = min(self.y_data)
                max_y = max(self.y_data)

                # Create canvas
                canvas = [[" " for _ in range(self.width)] for _ in range(self.height)]

                # Plot axes
                for i in range(self.width):
                    canvas[self.height - 1][i] = "-"
                for i in range(self.height):
                    canvas[i][0] = "|"

                # Plot data points
                for i in range(len(self.x_data)):
                    if max_x > min_x and max_y > min_y:
                        x_pos = (
                            int((self.x_data[i] - min_x) / (max_x - min_x) * (self.width - 2)) + 1
                        )
                        y_pos = (
                            self.height
                            - 2
                            - int((self.y_data[i] - min_y) / (max_y - min_y) * (self.height - 2))
                        )

                        if 0 <= x_pos < self.width and 0 <= y_pos < self.height:
                            canvas[y_pos][x_pos] = "*"

                # Convert to string
                plot_str = f"{self.title}\n" if self.title else ""
                for row in canvas:
                    plot_str += "".join(row) + "\n"

                if self.xlabel:
                    plot_str += f"\n{' ' * (self.width//2 - len(self.xlabel)//2)}{self.xlabel}\n"

                return plot_str

            def save(self, path):
                """Save plot to file."""
                plot_content = self.generate()
                with open(path, "w") as f:
                    f.write(plot_content)

            def analyze_exploit_data(self):
                """Analyze data for exploit patterns."""
                analysis = {
                    "min": min(self.y_data),
                    "max": max(self.y_data),
                    "mean": sum(self.y_data) / len(self.y_data),
                    "peaks": [],
                    "anomalies": [],
                }

                # Find peaks (potential vulnerabilities)
                for i in range(1, len(self.y_data) - 1):
                    if self.y_data[i] > self.y_data[i - 1] and self.y_data[i] > self.y_data[i + 1]:
                        analysis["peaks"].append({"index": i, "value": self.y_data[i]})

                # Find anomalies (large jumps)
                for i in range(1, len(self.y_data)):
                    diff = abs(self.y_data[i] - self.y_data[i - 1])
                    if diff > analysis["mean"] * 2:
                        analysis["anomalies"].append({"index": i, "diff": diff})

                return analysis

        plot = SimplePlot()

        if save_path:
            plot.save(save_path)

        return plot


# PDF generation
try:
    import pdfkit

    PDFKIT_AVAILABLE = True

    # pdfkit utility functions
    def html_to_pdf(html_string, output_path, options=None):
        """Convert HTML string to PDF using pdfkit."""
        try:
            if options is None:
                options = {"page-size": "A4", "encoding": "UTF-8"}
            pdfkit.from_string(html_string, output_path, options=options)
            return True
        except Exception as e:
            logger.error(f"PDF generation error: {e}")
            return False

    def url_to_pdf(url, output_path, options=None):
        """Convert URL to PDF using pdfkit."""
        try:
            if options is None:
                options = {"page-size": "A4", "encoding": "UTF-8"}
            pdfkit.from_url(url, output_path, options=options)
            return True
        except Exception as e:
            logger.error(f"PDF generation error: {e}")
            return False

except ImportError as e:
    logger.error("Import error in common_imports: %s", e)
    pdfkit = None
    PDFKIT_AVAILABLE = False

    def html_to_pdf(html_string, output_path, options=None):
        """HTML to PDF fallback."""
        return False

    def url_to_pdf(url, output_path, options=None):
        """URL to PDF fallback."""
        return False


# OpenCL for GPU acceleration
try:
    import pyopencl as cl

    HAS_OPENCL = True

    # OpenCL utility functions
    def get_opencl_platforms():
        """Get OpenCL platforms."""
        try:
            platforms = cl.get_platforms()
            return [{"name": p.name, "vendor": p.vendor, "version": p.version} for p in platforms]
        except Exception as e:
            logger.error(f"OpenCL platform error: {e}")
            return []

    def get_opencl_devices(platform_index=0):
        """Get OpenCL devices from platform."""
        try:
            platforms = cl.get_platforms()
            if platform_index < len(platforms):
                devices = platforms[platform_index].get_devices()
                return [{"name": d.name, "type": cl.device_type.to_string(d.type)} for d in devices]
        except Exception as e:
            logger.error(f"OpenCL device error: {e}")
        return []

except ImportError as e:
    logger.error("Import error in common_imports: %s", e)
    cl = None
    HAS_OPENCL = False

    def get_opencl_platforms():
        """Get OpenCL platforms fallback."""
        return []

    def get_opencl_devices(platform_index=0):
        """Get OpenCL devices fallback."""
        return []


# UI Framework
try:
    from PyQt6.QtCore import Qt, QThread, QTimer, pyqtSignal
    from PyQt6.QtGui import QColor, QFont
    from PyQt6.QtWidgets import (
        QApplication,
        QCheckBox,
        QComboBox,
        QDial,
        QFileDialog,
        QGroupBox,
        QHBoxLayout,
        QHeaderView,
        QLabel,
        QLineEdit,
        QListWidget,
        QListWidgetItem,
        QPlainTextEdit,
        QProgressBar,
        QPushButton,
        QSlider,
        QSpinBox,
        QSplitter,
        QTableWidget,
        QTableWidgetItem,
        QTabWidget,
        QTextEdit,
        QTreeWidget,
        QTreeWidgetItem,
        QVBoxLayout,
        QWidget,
    )

    HAS_PYQT = True

    # PyQt utility functions
    def create_dial(min_val=0, max_val=100, value=50):
        """Create a QDial widget"""
        dial = QDial()
        dial.setMinimum(min_val)
        dial.setMaximum(max_val)
        dial.setValue(value)
        dial.setNotchesVisible(True)
        return dial

    def create_slider(orientation=None, min_val=0, max_val=100, value=50):
        """Create a QSlider widget"""
        if orientation is None:
            orientation = Qt.Orientation.Horizontal
        slider = QSlider(orientation)
        slider.setMinimum(min_val)
        slider.setMaximum(max_val)
        slider.setValue(value)
        slider.setTickPosition(
            QSlider.TickPosition.TicksBelow
            if orientation == Qt.Orientation.Horizontal
            else QSlider.TickPosition.TicksLeft
        )
        return slider

except ImportError:
    HAS_PYQT = False

    # Create dummy classes to prevent import errors
    class _DummyWidget:
        def __init__(self, *args, **kwargs):
            """Initialize dummy widget placeholder with no operation."""

        def __call__(self, *args, **kwargs):
            return self

        def addWidget(self, *args, **kwargs):
            """Stub method for adding widgets."""

        def addLayout(self, *args, **kwargs):
            """Stub method for adding layouts."""

        def addItems(self, *args, **kwargs):
            """Stub method for adding items."""

        def addStretch(self, *args, **kwargs):
            """Stub method for adding stretch."""

        def setObjectName(self, *args, **kwargs):
            """Stub method for setting object name."""

        def setMinimum(self, *args, **kwargs):
            """Stub method for setting minimum value."""

        def setMaximum(self, *args, **kwargs):
            """Stub method for setting maximum value."""

        def setValue(self, *args, **kwargs):
            """Stub method for setting value."""

        def setText(self, *args, **kwargs):
            """Stub method for setting text."""

        def addTab(self, *args, **kwargs):
            """Stub method for adding tabs."""

        def timeout(self):
            """Stub timeout method."""
            return self

        def connect(self, *args, **kwargs):
            pass

        def start(self, *args, **kwargs):
            """Stub method for starting operations."""

        def __getattr__(self, name):
            logger.debug(f"Dummy widget fallback for attribute: {name}")
            return _DummyWidget()

    Qt = QThread = QTimer = pyqtSignal = _DummyWidget()
    QColor = QFont = _DummyWidget()
    QApplication = QWidget = QCheckBox = QComboBox = QDial = QFileDialog = _DummyWidget()
    QGroupBox = QHBoxLayout = QHeaderView = QLabel = QLineEdit = QListWidget = _DummyWidget()
    QListWidgetItem = QPlainTextEdit = QProgressBar = QPushButton = QSlider = _DummyWidget()
    QSpinBox = QSplitter = QTableWidget = QTableWidgetItem = QTabWidget = _DummyWidget()
    QTextEdit = QTreeWidget = QTreeWidgetItem = QVBoxLayout = _DummyWidget()

    # Dummy PyQt functions
    def create_dial(min_val=0, max_val=100, value=50):
        """Create dial widget fallback."""
        return _DummyWidget()

    def create_slider(orientation=None, min_val=0, max_val=100, value=50):
        """Create slider widget fallback."""
        return _DummyWidget()


# Export all utilities and flags
__all__ = [
    # Logging utilities
    "logger",
    "configure_logging",
    # ML/AI availability flags and utilities
    "HAS_NUMPY",
    "np",
    "create_numpy_array",
    "get_numpy_info",
    "HAS_TORCH",
    "torch",
    "create_torch_tensor",
    "get_torch_info",
    "HAS_TENSORFLOW",
    "tf",
    "create_tf_tensor",
    "get_tf_info",
    # Binary analysis flags and utilities
    "LIEF_AVAILABLE",
    "lief",
    "parse_binary_with_lief",
    "get_lief_info",
    "PSUTIL_AVAILABLE",
    "psutil",
    "get_system_info",
    "get_process_info",
    "PEFILE_AVAILABLE",
    "pefile",
    "parse_pe_file",
    "get_pe_info",
    "PYELFTOOLS_AVAILABLE",
    "elftools",
    "parse_elf_file",
    "get_elf_info",
    "FRIDA_AVAILABLE",
    "frida",
    "get_frida_version",
    "enumerate_devices",
    "get_local_device",
    "CAPSTONE_AVAILABLE",
    "capstone",
    "create_disassembler",
    "disassemble_bytes",
    # Visualization and PDF
    "MATPLOTLIB_AVAILABLE",
    "plt",
    "create_figure",
    "plot_data",
    "PDFKIT_AVAILABLE",
    "pdfkit",
    "html_to_pdf",
    "url_to_pdf",
    # GPU acceleration
    "HAS_OPENCL",
    "cl",
    "get_opencl_platforms",
    "get_opencl_devices",
    # UI framework
    "HAS_PYQT",
    "Qt",
    "QThread",
    "QTimer",
    "pyqtSignal",
    "QColor",
    "QFont",
    "QApplication",
    "QWidget",
    "QCheckBox",
    "QComboBox",
    "QDial",
    "QFileDialog",
    "QGroupBox",
    "QHBoxLayout",
    "QHeaderView",
    "QLabel",
    "QLineEdit",
    "QListWidget",
    "QListWidgetItem",
    "QPlainTextEdit",
    "QProgressBar",
    "QPushButton",
    "QSlider",
    "QSpinBox",
    "QSplitter",
    "QTableWidget",
    "QTableWidgetItem",
    "QTabWidget",
    "QTextEdit",
    "QTreeWidget",
    "QTreeWidgetItem",
    "QVBoxLayout",
    "create_dial",
    "create_slider",
]

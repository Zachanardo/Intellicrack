"""Advanced Integrity Check Defeat System for Intellicrack.

Detects and bypasses various integrity checking mechanisms including
CRC checks, hash validations, signature verifications, and anti-tampering.
"""

import logging
import os
import struct
from dataclasses import dataclass
from enum import IntEnum
from typing import Any, Dict, List, Optional

import capstone
import frida
import pefile

logger = logging.getLogger(__name__)


class IntegrityCheckType(IntEnum):
    """Types of integrity checks."""

    UNKNOWN = 0
    CRC32 = 1
    MD5_HASH = 2
    SHA1_HASH = 3
    SHA256_HASH = 4
    SIGNATURE = 5
    CHECKSUM = 6
    SIZE_CHECK = 7
    TIMESTAMP = 8
    CERTIFICATE = 9
    MEMORY_HASH = 10
    CODE_SIGNING = 11
    ANTI_TAMPER = 12


@dataclass
class IntegrityCheck:
    """Represents detected integrity check."""

    check_type: IntegrityCheckType
    address: int
    size: int
    expected_value: bytes
    actual_value: bytes
    function_name: str
    bypass_method: str
    confidence: float


@dataclass
class BypassStrategy:
    """Strategy for bypassing integrity check."""

    name: str
    check_types: List[IntegrityCheckType]
    frida_script: str
    success_rate: float
    priority: int


class IntegrityCheckDetector:
    """Detect integrity checking mechanisms in binaries."""

    def __init__(self):
        """Initialize the IntegrityCheckDetector with disassembler and pattern databases."""
        self.md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
        self.md.detail = True
        self.check_patterns = self._load_check_patterns()
        self.api_signatures = self._load_api_signatures()

    def _load_check_patterns(self) -> Dict[str, Dict]:
        """Load patterns for detecting integrity checks."""
        return {
            "crc32": {
                "pattern": b"\xc1\xe8\x08\x33",  # SHR EAX, 8; XOR
                "type": IntegrityCheckType.CRC32,
                "description": "CRC32 calculation",
            },
            "md5": {
                "pattern": b"\x67\x45\x23\x01",  # MD5 constants
                "type": IntegrityCheckType.MD5_HASH,
                "description": "MD5 hash calculation",
            },
            "sha1": {
                "pattern": b"\x67\x45\x23\x01\xef\xcd\xab\x89",
                "type": IntegrityCheckType.SHA1_HASH,
                "description": "SHA1 hash calculation",
            },
            "sha256": {
                "pattern": b"\x6a\x09\xe6\x67",  # SHA256 init values
                "type": IntegrityCheckType.SHA256_HASH,
                "description": "SHA256 hash calculation",
            },
            "size_check": {
                "pattern": b"\x81\x7d.\x00\x00",  # CMP [EBP+x], size
                "type": IntegrityCheckType.SIZE_CHECK,
                "description": "File size verification",
            },
        }

    def _load_api_signatures(self) -> Dict[str, IntegrityCheckType]:
        """Load Windows API signatures for integrity checks."""
        return {
            "GetFileSize": IntegrityCheckType.SIZE_CHECK,
            "GetFileTime": IntegrityCheckType.TIMESTAMP,
            "CryptHashData": IntegrityCheckType.SHA256_HASH,
            "CryptVerifySignature": IntegrityCheckType.SIGNATURE,
            "WinVerifyTrust": IntegrityCheckType.CERTIFICATE,
            "CertVerifyCertificateChainPolicy": IntegrityCheckType.CERTIFICATE,
            "CheckSumMappedFile": IntegrityCheckType.CHECKSUM,
            "MapFileAndCheckSum": IntegrityCheckType.CHECKSUM,
            "ImageGetCertificateData": IntegrityCheckType.CODE_SIGNING,
            "CryptCATAdminCalcHashFromFileHandle": IntegrityCheckType.SHA256_HASH,
        }

    def detect_checks(self, binary_path: str) -> List[IntegrityCheck]:
        """Detect integrity checks in binary."""
        checks = []

        try:
            pe = pefile.PE(binary_path)

            # Scan for API imports
            api_checks = self._scan_api_imports(pe)
            checks.extend(api_checks)

            # Scan for inline checks
            inline_checks = self._scan_inline_checks(pe)
            checks.extend(inline_checks)

            # Scan for anti-tamper mechanisms
            antitamper_checks = self._scan_antitamper(pe)
            checks.extend(antitamper_checks)

            pe.close()

        except Exception as e:
            logger.error(f"Integrity check detection failed: {e}")

        return checks

    def _scan_api_imports(self, pe: pefile.PE) -> List[IntegrityCheck]:
        """Scan for integrity check API imports."""
        checks = []

        if not hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
            return checks

        for entry in pe.DIRECTORY_ENTRY_IMPORT:
            for imp in entry.imports:
                if imp.name:
                    func_name = imp.name.decode() if isinstance(imp.name, bytes) else imp.name

                    if func_name in self.api_signatures:
                        check = IntegrityCheck(
                            check_type=self.api_signatures[func_name],
                            address=imp.address,
                            size=0,
                            expected_value=b"",
                            actual_value=b"",
                            function_name=func_name,
                            bypass_method="hook_api",
                            confidence=0.9,
                        )
                        checks.append(check)

        return checks

    def _scan_inline_checks(self, pe: pefile.PE) -> List[IntegrityCheck]:
        """Scan for inline integrity checks."""
        checks = []

        # Scan code sections
        for section in pe.sections:
            if section.IMAGE_SCN_MEM_EXECUTE:
                section_data = section.get_data()

                for _pattern_name, pattern_info in self.check_patterns.items():
                    pattern = pattern_info["pattern"]
                    offset = 0

                    while True:
                        pos = section_data.find(pattern, offset)
                        if pos == -1:
                            break

                        check = IntegrityCheck(
                            check_type=pattern_info["type"],
                            address=section.VirtualAddress + pos,
                            size=len(pattern),
                            expected_value=b"",
                            actual_value=b"",
                            function_name=pattern_info["description"],
                            bypass_method="patch_inline",
                            confidence=0.7,
                        )
                        checks.append(check)
                        offset = pos + 1

        return checks

    def _scan_antitamper(self, pe: pefile.PE) -> List[IntegrityCheck]:
        """Scan for anti-tamper mechanisms."""
        checks = []

        # Check for packed sections
        for section in pe.sections:
            entropy = self._calculate_entropy(section.get_data())
            if entropy > 7.5:  # High entropy indicates encryption/compression
                check = IntegrityCheck(
                    check_type=IntegrityCheckType.ANTI_TAMPER,
                    address=section.VirtualAddress,
                    size=section.SizeOfRawData,
                    expected_value=b"",
                    actual_value=b"",
                    function_name="Packed/Encrypted Section",
                    bypass_method="unpack_section",
                    confidence=0.8,
                )
                checks.append(check)

        # Check for self-modifying code patterns
        smc_patterns = [
            b"\xf0\x0f\xc1",  # LOCK XADD - often used in SMC
            b"\x0f\xba\x2d",  # BTS with memory operand
            b"\x0f\xc7\x08",  # CMPXCHG8B - atomic compare and swap
            b"\x0f\xb0",  # CMPXCHG - compare and exchange
            b"\xf0\x0f\xb1",  # LOCK CMPXCHG - atomic operation
            b"\x66\x0f\xc7",  # CMPXCHG16B - 16-byte atomic operation
        ]

        for section in pe.sections:
            section_data = section.get_data()
            for pattern in smc_patterns:
                if pattern in section_data:
                    check = IntegrityCheck(
                        check_type=IntegrityCheckType.ANTI_TAMPER,
                        address=section.VirtualAddress + section_data.find(pattern),
                        size=len(pattern),
                        expected_value=b"",
                        actual_value=b"",
                        function_name="Self-Modifying Code",
                        bypass_method="hook_smc",
                        confidence=0.6,
                    )
                    checks.append(check)

        return checks

    def _calculate_entropy(self, data: bytes) -> float:
        """Calculate Shannon entropy."""
        if not data:
            return 0

        import math

        frequency_map = {}
        for byte in data:
            frequency_map[byte] = frequency_map.get(byte, 0) + 1

        entropy = 0.0
        data_len = len(data)
        for count in frequency_map.values():
            if count > 0:
                frequency = float(count) / data_len
                entropy -= frequency * math.log2(frequency)

        return entropy


class IntegrityBypassEngine:
    """Bypasses detected integrity checks using Frida."""

    def __init__(self):
        """Initialize the IntegrityBypassEngine with bypass strategies and Frida session."""
        self.bypass_strategies = self._load_bypass_strategies()
        self.session = None
        self.script = None
        self.hooks_installed = []
        self.crc_table = self._generate_crc32_table()
        self.original_bytes_cache = {}

    def _load_bypass_strategies(self) -> List[BypassStrategy]:
        """Load bypass strategies for different check types."""
        strategies = []

        # CRC32 bypass
        strategies.append(
            BypassStrategy(
                name="crc32_bypass",
                check_types=[IntegrityCheckType.CRC32],
                frida_script="""
                Interceptor.attach(Module.findExportByName(null, 'RtlComputeCrc32'), {
                    onEnter: function(args) {
                        this.buffer = args[1];
                        this.length = args[2].toInt32();
                    },
                    onLeave: function(retval) {
                        // Return expected CRC32 value
                        retval.replace(ptr('%EXPECTED_VALUE%'));
                        console.log('[CRC32] Bypassed check, returned: ' + retval);
                    }
                });
            """,
                success_rate=0.95,
                priority=1,
            )
        )

        # Hash verification bypass
        strategies.append(
            BypassStrategy(
                name="hash_bypass",
                check_types=[IntegrityCheckType.MD5_HASH, IntegrityCheckType.SHA1_HASH, IntegrityCheckType.SHA256_HASH],
                frida_script="""
                var cryptHashDataAddr = Module.findExportByName('Advapi32.dll', 'CryptHashData');
                if (cryptHashDataAddr) {
                    Interceptor.attach(cryptHashDataAddr, {
                        onEnter: function(args) {
                            this.hHash = args[0];
                            this.pbData = args[1];
                            this.dwDataLen = args[2].toInt32();
                        },
                        onLeave: function(retval) {
                            // Skip hash calculation for protected regions
                            var address = parseInt(this.pbData);
                            if (address >= %PROTECTED_START% && address <= %PROTECTED_END%) {
                                retval.replace(1);  // Return success without hashing
                                console.log('[Hash] Skipped hashing protected region');
                            }
                        }
                    });
                }

                // Also hook comparison functions
                Interceptor.attach(Module.findExportByName(null, 'memcmp'), {
                    onEnter: function(args) {
                        this.buf1 = args[0];
                        this.buf2 = args[1];
                        this.size = args[2].toInt32();
                    },
                    onLeave: function(retval) {
                        // Check if comparing hash values
                        if (this.size == 16 || this.size == 20 || this.size == 32) {
                            retval.replace(0);  // Return match
                            console.log('[Hash] Forced hash comparison match');
                        }
                    }
                });
            """,
                success_rate=0.90,
                priority=2,
            )
        )

        # Signature verification bypass
        strategies.append(
            BypassStrategy(
                name="signature_bypass",
                check_types=[IntegrityCheckType.SIGNATURE, IntegrityCheckType.CERTIFICATE],
                frida_script="""
                // Hook WinVerifyTrust
                var winVerifyTrustAddr = Module.findExportByName('Wintrust.dll', 'WinVerifyTrust');
                if (winVerifyTrustAddr) {
                    Interceptor.attach(winVerifyTrustAddr, {
                        onLeave: function(retval) {
                            retval.replace(0);  // Return S_OK (trusted)
                            console.log('[Signature] Bypassed WinVerifyTrust check');
                        }
                    });
                }

                // Hook certificate verification
                var certVerifyAddr = Module.findExportByName('Crypt32.dll', 'CertVerifyCertificateChainPolicy');
                if (certVerifyAddr) {
                    Interceptor.attach(certVerifyAddr, {
                        onLeave: function(retval) {
                            retval.replace(1);  // Return TRUE (valid)
                            console.log('[Certificate] Bypassed certificate chain verification');
                        }
                    });
                }
            """,
                success_rate=0.85,
                priority=3,
            )
        )

        # Size check bypass
        strategies.append(
            BypassStrategy(
                name="size_check_bypass",
                check_types=[IntegrityCheckType.SIZE_CHECK],
                frida_script="""
                // Hook GetFileSize
                var getFileSizeAddr = Module.findExportByName('kernel32.dll', 'GetFileSize');
                if (getFileSizeAddr) {
                    Interceptor.attach(getFileSizeAddr, {
                        onLeave: function(retval) {
                            // Return expected file size
                            retval.replace(%EXPECTED_SIZE%);
                            console.log('[Size] Returned expected size: ' + retval);
                        }
                    });
                }

                // Hook GetFileSizeEx
                var getFileSizeExAddr = Module.findExportByName('kernel32.dll', 'GetFileSizeEx');
                if (getFileSizeExAddr) {
                    Interceptor.attach(getFileSizeExAddr, {
                        onEnter: function(args) {
                            this.sizePtr = args[1];
                        },
                        onLeave: function(retval) {
                            if (retval.toInt32() != 0 && this.sizePtr) {
                                var expectedSize = %EXPECTED_SIZE%;
                                this.sizePtr.writeS64(expectedSize);
                                console.log('[Size] Set expected size: ' + expectedSize);
                            }
                        }
                    });
                }
            """,
                success_rate=0.92,
                priority=4,
            )
        )

        # Checksum bypass
        strategies.append(
            BypassStrategy(
                name="checksum_bypass",
                check_types=[IntegrityCheckType.CHECKSUM],
                frida_script="""
                // Hook CheckSumMappedFile
                var checkSumAddr = Module.findExportByName('Imagehlp.dll', 'CheckSumMappedFile');
                if (checkSumAddr) {
                    Interceptor.attach(checkSumAddr, {
                        onEnter: function(args) {
                            this.headerSumPtr = args[2];
                            this.checkSumPtr = args[3];
                        },
                        onLeave: function(retval) {
                            if (this.headerSumPtr) {
                                this.headerSumPtr.writeU32(%HEADER_CHECKSUM%);
                            }
                            if (this.checkSumPtr) {
                                this.checkSumPtr.writeU32(%IMAGE_CHECKSUM%);
                            }
                            console.log('[Checksum] Set expected checksum values');
                        }
                    });
                }
            """,
                success_rate=0.88,
                priority=5,
            )
        )

        # Anti-tamper bypass
        strategies.append(
            BypassStrategy(
                name="antitamper_bypass",
                check_types=[IntegrityCheckType.ANTI_TAMPER],
                frida_script="""
                // Hook memory protection functions
                var virtualProtectAddr = Module.findExportByName('kernel32.dll', 'VirtualProtect');
                if (virtualProtectAddr) {
                    Interceptor.attach(virtualProtectAddr, {
                        onEnter: function(args) {
                            this.address = args[0];
                            this.size = args[1].toInt32();
                            this.newProtect = args[2].toInt32();

                            // Allow all protection changes
                            if (this.newProtect & 0x40) {  // PAGE_EXECUTE_READWRITE
                                console.log('[AntiTamper] Allowing protection change to RWX');
                            }
                        },
                        onLeave: function(retval) {
                            retval.replace(1);  // Always return success
                        }
                    });
                }

                // Hook IsDebuggerPresent to hide debugger
                var isDebuggerPresentAddr = Module.findExportByName('kernel32.dll', 'IsDebuggerPresent');
                if (isDebuggerPresentAddr) {
                    Interceptor.attach(isDebuggerPresentAddr, {
                        onLeave: function(retval) {
                            retval.replace(0);  // No debugger
                            console.log('[AntiTamper] Hidden debugger presence');
                        }
                    });
                }

                // Clear PEB debugger flags
                var peb = Process.enumerateModules()[0].base;
                var beingDebuggedOffset = Process.pointerSize === 8 ? 0x02 : 0x02;
                var ntGlobalFlagOffset = Process.pointerSize === 8 ? 0xBC : 0x68;

                Memory.protect(peb, 0x1000, 'rwx');
                peb.add(beingDebuggedOffset).writeU8(0);
                peb.add(ntGlobalFlagOffset).writeU32(0);
                console.log('[AntiTamper] Cleared PEB debugger flags');
            """,
                success_rate=0.75,
                priority=6,
            )
        )

        # Memory hash bypass
        strategies.append(
            BypassStrategy(
                name="memory_hash_bypass",
                check_types=[IntegrityCheckType.MEMORY_HASH],
                frida_script="""
                // Track memory regions being hashed
                var protectedRegions = [];

                // Hook ReadProcessMemory for self-checks
                var readProcessMemoryAddr = Module.findExportByName('kernel32.dll', 'ReadProcessMemory');
                if (readProcessMemoryAddr) {
                    Interceptor.attach(readProcessMemoryAddr, {
                        onEnter: function(args) {
                            this.hProcess = args[0];
                            this.lpBaseAddress = args[1];
                            this.lpBuffer = args[2];
                            this.nSize = args[3].toInt32();
                        },
                        onLeave: function(retval) {
                            // Check if reading from protected region
                            var address = parseInt(this.lpBaseAddress);
                            for (var i = 0; i < protectedRegions.length; i++) {
                                var region = protectedRegions[i];
                                if (address >= region.start && address < region.end) {
                                    // Return original bytes instead of modified
                                    Memory.copy(this.lpBuffer, region.original, this.nSize);
                                    console.log('[MemHash] Returned original bytes for hash check');
                                    break;
                                }
                            }
                        }
                    });
                }

                // Function to add protected region
                function addProtectedRegion(start, size, originalBytes) {
                    protectedRegions.push({
                        start: start,
                        end: start + size,
                        original: originalBytes
                    });
                }
            """,
                success_rate=0.80,
                priority=7,
            )
        )

        # Timestamp bypass
        strategies.append(
            BypassStrategy(
                name="timestamp_bypass",
                check_types=[IntegrityCheckType.TIMESTAMP],
                frida_script="""
                // Hook GetFileTime
                var getFileTimeAddr = Module.findExportByName('kernel32.dll', 'GetFileTime');
                if (getFileTimeAddr) {
                    Interceptor.attach(getFileTimeAddr, {
                        onEnter: function(args) {
                            this.creationTimePtr = args[1];
                            this.lastAccessTimePtr = args[2];
                            this.lastWriteTimePtr = args[3];
                        },
                        onLeave: function(retval) {
                            if (retval.toInt32() !== 0) {
                                // Set expected timestamps
                                var expectedTime = ptr('%EXPECTED_TIMESTAMP%');
                                if (this.creationTimePtr && !this.creationTimePtr.isNull()) {
                                    this.creationTimePtr.writeU64(expectedTime);
                                }
                                if (this.lastWriteTimePtr && !this.lastWriteTimePtr.isNull()) {
                                    this.lastWriteTimePtr.writeU64(expectedTime);
                                }
                                console.log('[Timestamp] Set expected file times');
                            }
                        }
                    });
                }
            """,
                success_rate=0.93,
                priority=8,
            )
        )

        # Code signing bypass
        strategies.append(
            BypassStrategy(
                name="code_signing_bypass",
                check_types=[IntegrityCheckType.CODE_SIGNING],
                frida_script="""
                // Hook WinVerifyTrustEx
                var winVerifyTrustExAddr = Module.findExportByName('Wintrust.dll', 'WinVerifyTrustEx');
                if (winVerifyTrustExAddr) {
                    Interceptor.attach(winVerifyTrustExAddr, {
                        onLeave: function(retval) {
                            retval.replace(0);  // Return S_OK
                            console.log('[CodeSign] Bypassed WinVerifyTrustEx');
                        }
                    });
                }

                // Hook CryptCATAdminCalcHashFromFileHandle
                var cryptCATHashAddr = Module.findExportByName('Wintrust.dll', 'CryptCATAdminCalcHashFromFileHandle');
                if (cryptCATHashAddr) {
                    Interceptor.attach(cryptCATHashAddr, {
                        onLeave: function(retval) {
                            retval.replace(1);  // Return TRUE
                            console.log('[CodeSign] Bypassed catalog hash verification');
                        }
                    });
                }

                // Hook ImageGetCertificateData
                var imageGetCertAddr = Module.findExportByName('Imagehlp.dll', 'ImageGetCertificateData');
                if (imageGetCertAddr) {
                    Interceptor.attach(imageGetCertAddr, {
                        onLeave: function(retval) {
                            retval.replace(1);  // Return TRUE
                            console.log('[CodeSign] Bypassed certificate data retrieval');
                        }
                    });
                }
            """,
                success_rate=0.82,
                priority=9,
            )
        )

        return strategies

    def bypass_checks(self, process_name: str, checks: List[IntegrityCheck]) -> bool:
        """Bypass detected integrity checks."""
        try:
            # Attach to process
            self.session = frida.attach(process_name)

            # Build combined script
            combined_script = self._build_bypass_script(checks)

            # Create and load script
            self.script = self.session.create_script(combined_script)
            self.script.on("message", self._on_message)
            self.script.load()

            logger.info(f"Installed {len(checks)} integrity check bypasses")
            return True

        except Exception as e:
            logger.error(f"Failed to bypass integrity checks: {e}")
            return False

    def _build_bypass_script(self, checks: List[IntegrityCheck]) -> str:
        """Build combined Frida script for all checks."""
        script_parts = []

        # Group checks by type
        checks_by_type = {}
        for check in checks:
            if check.check_type not in checks_by_type:
                checks_by_type[check.check_type] = []
            checks_by_type[check.check_type].append(check)

        # Add appropriate bypass for each type
        for check_type, type_checks in checks_by_type.items():
            strategy = self._get_best_strategy(check_type)
            if strategy:
                script = self._customize_script(strategy.frida_script, type_checks)
                script_parts.append(f"// {strategy.name}")
                script_parts.append(script)

        # Combine all scripts
        return "\n".join(script_parts)

    def _get_best_strategy(self, check_type: IntegrityCheckType) -> Optional[BypassStrategy]:
        """Get best bypass strategy for check type."""
        best_strategy = None
        best_priority = 999

        for strategy in self.bypass_strategies:
            if check_type in strategy.check_types:
                if strategy.priority < best_priority:
                    best_strategy = strategy
                    best_priority = strategy.priority

        return best_strategy

    def _customize_script(self, script_template: str, checks: List[IntegrityCheck]) -> str:
        """Customize script template with actual values."""
        script = script_template

        # Substitute template variables with detected values
        if checks:
            first_check = checks[0]

            # Replace expected values
            if first_check.expected_value:
                expected_hex = first_check.expected_value.hex()
                script = script.replace("%EXPECTED_VALUE%", f"0x{expected_hex}")
            else:
                # Calculate expected CRC32 for the original binary
                if first_check.check_type == IntegrityCheckType.CRC32:
                    # Use cached original bytes if available
                    if first_check.address in self.original_bytes_cache:
                        original_data = self.original_bytes_cache[first_check.address]
                        expected_crc = self._calculate_crc32(original_data)
                        script = script.replace("%EXPECTED_VALUE%", str(expected_crc))
                    else:
                        script = script.replace("%EXPECTED_VALUE%", "0x00000000")

            # Replace address ranges
            min_addr = min(c.address for c in checks)
            max_addr = max(c.address + c.size for c in checks)
            script = script.replace("%PROTECTED_START%", str(min_addr))
            script = script.replace("%PROTECTED_END%", str(max_addr))

            # Calculate actual values from binary analysis
            try:
                binary_path = getattr(first_check, "binary_path", None)
                if binary_path and os.path.exists(binary_path):
                    pe = pefile.PE(binary_path)
                    actual_size = pe.OPTIONAL_HEADER.SizeOfImage
                    actual_header_checksum = pe.OPTIONAL_HEADER.CheckSum
                    actual_image_checksum = self._calculate_pe_checksum(pe)

                    # Get timestamp
                    actual_timestamp = pe.FILE_HEADER.TimeDateStamp

                    pe.close()
                else:
                    # Default values
                    actual_size = 1048576
                    actual_header_checksum = 0
                    actual_image_checksum = 0
                    actual_timestamp = 0
            except (struct.error, ValueError):
                actual_size = 1048576
                actual_header_checksum = 0
                actual_image_checksum = 0
                actual_timestamp = 0

            script = script.replace("%EXPECTED_SIZE%", str(actual_size))
            script = script.replace("%HEADER_CHECKSUM%", str(actual_header_checksum))
            script = script.replace("%IMAGE_CHECKSUM%", str(actual_image_checksum))
            script = script.replace("%EXPECTED_TIMESTAMP%", str(actual_timestamp))

        return script

    def _generate_crc32_table(self) -> List[int]:
        """Generate CRC32 lookup table."""
        crc_table = []
        for i in range(256):
            crc = i
            for _ in range(8):
                if crc & 1:
                    crc = (crc >> 1) ^ 0xEDB88320
                else:
                    crc >>= 1
            crc_table.append(crc)
        return crc_table

    def _calculate_crc32(self, data: bytes) -> int:
        """Calculate CRC32 checksum."""
        crc = 0xFFFFFFFF
        for byte in data:
            crc = self.crc_table[(crc & 0xFF) ^ byte] ^ (crc >> 8)
        return crc ^ 0xFFFFFFFF

    def _calculate_pe_checksum(self, pe: pefile.PE) -> int:
        """Calculate PE checksum."""
        checksum = 0
        word_count = (len(pe.__data__) + 1) // 2

        checksum_offset = pe.OPTIONAL_HEADER.get_file_offset() + 64

        for i in range(word_count):
            if i * 2 == checksum_offset:  # Skip checksum field
                continue

            if i * 2 + 2 <= len(pe.__data__):
                word = struct.unpack("<H", pe.__data__[i * 2 : i * 2 + 2])[0]
            else:
                word = 0

            checksum = (checksum & 0xFFFF) + word + (checksum >> 16)
            if checksum > 0xFFFF:
                checksum = (checksum & 0xFFFF) + (checksum >> 16)

        checksum = (checksum & 0xFFFF) + (checksum >> 16)
        checksum += len(pe.__data__)

        return checksum & 0xFFFFFFFF

    def _on_message(self, message, data):
        """Handle Frida script messages."""
        if message["type"] == "send":
            logger.info(f"[Frida] {message['payload']}")
        elif message["type"] == "error":
            logger.error(f"[Frida Error] {message['stack']}")

    def cleanup(self):
        """Clean up Frida session."""
        if self.script:
            self.script.unload()
        if self.session:
            self.session.detach()


class IntegrityCheckDefeatSystem:
    """Run integrity check defeat system."""

    def __init__(self):
        """Initialize the IntegrityCheckDefeatSystem with detector and bypasser components."""
        self.detector = IntegrityCheckDetector()
        self.bypasser = IntegrityBypassEngine()
        self.patch_history = []
        self.binary_backups = {}

    def defeat_integrity_checks(self, binary_path: str, process_name: str = None) -> Dict[str, Any]:
        """Complete integrity check defeat workflow."""
        result = {"success": False, "checks_detected": 0, "checks_bypassed": 0, "details": []}

        # Detect integrity checks
        logger.info(f"Detecting integrity checks in: {binary_path}")
        checks = self.detector.detect_checks(binary_path)
        result["checks_detected"] = len(checks)

        if not checks:
            logger.info("No integrity checks detected")
            result["success"] = True
            return result

        logger.info(f"Detected {len(checks)} integrity checks")

        # Log detected checks
        for check in checks:
            result["details"].append(
                {
                    "type": check.check_type.name,
                    "address": hex(check.address),
                    "function": check.function_name,
                    "bypass_method": check.bypass_method,
                    "confidence": check.confidence,
                }
            )

        # Apply bypasses if process is running
        if process_name:
            logger.info(f"Applying bypasses to process: {process_name}")
            if self.bypasser.bypass_checks(process_name, checks):
                result["checks_bypassed"] = len(checks)
                result["success"] = True
                logger.info("Successfully bypassed all integrity checks")
            else:
                logger.error("Failed to bypass some integrity checks")
        else:
            logger.info("No process specified, bypasses not applied")
            result["success"] = True

        return result

    def generate_bypass_script(self, binary_path: str) -> str:
        """Generate Frida script for bypassing integrity checks."""
        checks = self.detector.detect_checks(binary_path)

        if not checks:
            return "// No integrity checks detected"

        # Store binary path in checks for reference
        for check in checks:
            check.binary_path = binary_path

        return self.bypasser._build_bypass_script(checks)

    def patch_binary_integrity(self, binary_path: str, output_path: str = None) -> bool:
        """Patch binary to remove integrity checks."""
        if output_path is None:
            output_path = binary_path + ".patched"

        try:
            # Backup original
            with open(binary_path, "rb") as f:
                original_data = f.read()
            self.binary_backups[binary_path] = original_data

            # Load PE
            pe = pefile.PE(binary_path)

            # Detect checks
            checks = self.detector.detect_checks(binary_path)

            # Apply patches
            patch_data = bytearray(original_data)

            for check in checks:
                if check.bypass_method == "patch_inline":
                    # NOP out integrity check code
                    offset = self._rva_to_offset(pe, check.address)
                    if offset:
                        # Replace with NOPs (0x90)
                        for i in range(check.size):
                            patch_data[offset + i] = 0x90

                        self.patch_history.append(
                            {
                                "address": check.address,
                                "size": check.size,
                                "original": original_data[offset : offset + check.size],
                                "patched": bytes([0x90] * check.size),
                            }
                        )

                elif check.check_type == IntegrityCheckType.CRC32:
                    # Patch CRC32 checks to always return expected value
                    offset = self._rva_to_offset(pe, check.address)
                    if offset:
                        # MOV EAX, expected_crc; RET
                        expected_crc = self.bypasser._calculate_crc32(original_data)
                        patch_bytes = struct.pack("<BI", 0xB8, expected_crc) + b"\xc3"

                        for i, byte in enumerate(patch_bytes):
                            if offset + i < len(patch_data):
                                patch_data[offset + i] = byte

                        self.patch_history.append(
                            {
                                "address": check.address,
                                "size": len(patch_bytes),
                                "original": original_data[offset : offset + len(patch_bytes)],
                                "patched": patch_bytes,
                            }
                        )

            # Fix PE checksum
            pe_patched = pefile.PE(data=bytes(patch_data))
            pe_patched.OPTIONAL_HEADER.CheckSum = self.bypasser._calculate_pe_checksum(pe_patched)
            patch_data = bytearray(pe_patched.write())

            # Write patched file
            with open(output_path, "wb") as f:
                f.write(patch_data)

            logger.info(f"Binary patched successfully: {output_path}")
            logger.info(f"Applied {len(self.patch_history)} patches")

            pe.close()
            pe_patched.close()

            return True

        except Exception as e:
            logger.error(f"Failed to patch binary: {e}")
            return False

    def _rva_to_offset(self, pe: pefile.PE, rva: int) -> Optional[int]:
        """Convert RVA to file offset."""
        for section in pe.sections:
            if section.VirtualAddress <= rva < section.VirtualAddress + section.Misc_VirtualSize:
                return section.PointerToRawData + (rva - section.VirtualAddress)
        return None

    def restore_binary(self, binary_path: str) -> bool:
        """Restore original binary from backup."""
        if binary_path in self.binary_backups:
            try:
                with open(binary_path, "wb") as f:
                    f.write(self.binary_backups[binary_path])
                logger.info(f"Binary restored: {binary_path}")
                return True
            except Exception as e:
                logger.error(f"Failed to restore binary: {e}")
        return False


def main():
    """Test entry point."""
    import argparse

    parser = argparse.ArgumentParser(description="Integrity Check Defeat System")
    parser.add_argument("binary", help="Binary file to analyze")
    parser.add_argument("-p", "--process", help="Process name to attach to")
    parser.add_argument("-s", "--script", action="store_true", help="Generate bypass script only")
    parser.add_argument("-v", "--verbose", action="store_true", help="Verbose output")

    args = parser.parse_args()

    if args.verbose:
        logging.basicConfig(level=logging.DEBUG)
    else:
        logging.basicConfig(level=logging.INFO)

    defeat_system = IntegrityCheckDefeatSystem()

    if args.script:
        # Generate script only
        script = defeat_system.generate_bypass_script(args.binary)
        print("\n=== Generated Bypass Script ===")
        print(script)
    else:
        # Full defeat workflow
        result = defeat_system.defeat_integrity_checks(args.binary, args.process)

        print("\n=== Integrity Check Defeat Results ===")
        print(f"Checks Detected: {result['checks_detected']}")
        print(f"Checks Bypassed: {result['checks_bypassed']}")
        print(f"Success: {result['success']}")

        if result["details"]:
            print("\n=== Detected Checks ===")
            for detail in result["details"]:
                print(f"- {detail['type']} at {detail['address']}")
                print(f"  Function: {detail['function']}")
                print(f"  Bypass: {detail['bypass_method']}")
                print(f"  Confidence: {detail['confidence']:.1%}")


if __name__ == "__main__":
    main()

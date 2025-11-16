"""Arxan TransformIT Bypass Module for Intellicrack.

Implements sophisticated bypass techniques for Arxan-protected binaries including
anti-tampering defeat, integrity check neutralization, RASP bypass, and license
validation removal.

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

import logging
import struct
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

try:
    import capstone

    CAPSTONE_AVAILABLE = True
except ImportError:
    CAPSTONE_AVAILABLE = False
    capstone = None

try:
    import frida

    FRIDA_AVAILABLE = True
except ImportError:
    FRIDA_AVAILABLE = False
    frida = None

try:
    import keystone

    KEYSTONE_AVAILABLE = True
except ImportError:
    KEYSTONE_AVAILABLE = False
    keystone = None

try:
    import lief

    LIEF_AVAILABLE = True
except ImportError:
    LIEF_AVAILABLE = False
    lief = None

try:
    import pefile

    PEFILE_AVAILABLE = True
except ImportError:
    PEFILE_AVAILABLE = False
    pefile = None

from intellicrack.core.analysis.arxan_analyzer import (
    ArxanAnalyzer,
    LicenseValidationRoutine,
    RASPMechanism,
    TamperCheckLocation,
)
from intellicrack.core.protection_detection.arxan_detector import ArxanDetector

logger = logging.getLogger(__name__)


@dataclass
class BypassPatch:
    """Binary patch for bypassing protection."""

    address: int
    original_bytes: bytes
    patched_bytes: bytes
    patch_type: str
    description: str


@dataclass
class ArxanBypassResult:
    """Result of Arxan bypass operation."""

    success: bool
    patches_applied: list[BypassPatch] = field(default_factory=list)
    runtime_hooks_installed: int = 0
    license_checks_bypassed: int = 0
    integrity_checks_neutralized: int = 0
    rasp_mechanisms_defeated: int = 0
    frida_script: str = ""
    patched_binary_path: str = ""
    metadata: dict[str, Any] = field(default_factory=dict)


class ArxanBypass:
    """Bypasses Arxan TransformIT protection mechanisms."""

    NOP_OPCODE = b"\x90"
    RET_OPCODE = b"\xc3"
    XOR_EAX_EAX = b"\x33\xc0"
    MOV_EAX_1 = b"\xb8\x01\x00\x00\x00"
    JMP_SHORT_0 = b"\xeb\x00"

    def __init__(self) -> None:
        """Initialize ArxanBypass with analyzer and assemblers."""
        self.logger = logging.getLogger(__name__)
        self.detector = ArxanDetector()
        self.analyzer = ArxanAnalyzer()

        if KEYSTONE_AVAILABLE:
            self.ks_32 = keystone.Ks(keystone.KS_ARCH_X86, keystone.KS_MODE_32)
            self.ks_64 = keystone.Ks(keystone.KS_ARCH_X86, keystone.KS_MODE_64)
        else:
            self.ks_32 = None
            self.ks_64 = None
            self.logger.warning("Keystone not available - assembly features disabled")

        if CAPSTONE_AVAILABLE:
            self.md_32 = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
            self.md_32.detail = True
            self.md_64 = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
            self.md_64.detail = True
        else:
            self.md_32 = None
            self.md_64 = None
            self.logger.warning("Capstone not available - disassembly features disabled")

        self.frida_session = None
        self.frida_script = None

    def bypass(
        self,
        binary_path: str | Path,
        output_path: str | Path | None = None,
        runtime_bypass: bool = False,
        process_name: str | None = None,
    ) -> ArxanBypassResult:
        """Bypass Arxan protection.

        Args:
            binary_path: Path to protected binary
            output_path: Path for patched binary (None = auto-generate)
            runtime_bypass: Enable Frida runtime bypass
            process_name: Process name for Frida attachment

        Returns:
            ArxanBypassResult with bypass details

        """
        binary_path = Path(binary_path)

        if not binary_path.exists():
            error_msg = f"Binary not found: {binary_path}"
            logger.error(error_msg)
            raise FileNotFoundError(error_msg)

        if output_path is None:
            output_path = binary_path.with_suffix(".arxan_bypassed" + binary_path.suffix)
        else:
            output_path = Path(output_path)

        self.logger.info(f"Starting Arxan bypass: {binary_path}")

        detection_result = self.detector.detect(binary_path)

        if not detection_result.is_protected:
            self.logger.warning("Binary does not appear to be Arxan-protected")

        analysis_result = self.analyzer.analyze(binary_path)

        result = ArxanBypassResult(
            success=False,
            metadata={
                "arxan_version": detection_result.version.value,
                "confidence": detection_result.confidence,
            },
        )

        with open(binary_path, "rb") as f:
            binary_data = bytearray(f.read())

        patches = []

        self._bypass_tamper_checks(binary_data, analysis_result.tamper_checks, patches)
        self._bypass_integrity_checks(binary_data, analysis_result.integrity_checks, patches)
        self._bypass_license_validation(binary_data, analysis_result.license_routines, patches)
        self._neutralize_rasp(binary_data, analysis_result.rasp_mechanisms, patches)
        self._decrypt_strings(binary_data, analysis_result.encrypted_strings, patches)

        try:
            if binary_path.suffix.lower() in [".exe", ".dll", ".sys"] and PEFILE_AVAILABLE:
                pe = pefile.PE(data=bytes(binary_data))

                for patch in patches:
                    file_offset = self._rva_to_offset(pe, patch.address)
                    if file_offset is not None:
                        for i, byte in enumerate(patch.patched_bytes):
                            if file_offset + i < len(binary_data):
                                binary_data[file_offset + i] = byte

                new_checksum = self._calculate_pe_checksum(bytes(binary_data))
                pe.OPTIONAL_HEADER.CheckSum = new_checksum

                with open(output_path, "wb") as f:
                    f.write(binary_data)

                pe_final = pefile.PE(str(output_path))
                pe_final.OPTIONAL_HEADER.CheckSum = new_checksum

                with open(output_path, "wb") as f:
                    f.write(pe_final.write())

                pe_final.close()
                pe.close()

            else:
                for patch in patches:
                    for i, byte in enumerate(patch.patched_bytes):
                        if patch.address + i < len(binary_data):
                            binary_data[patch.address + i] = byte

                with open(output_path, "wb") as f:
                    f.write(binary_data)

        except Exception as e:
            self.logger.error(f"Binary patching failed: {e}")
            result.success = False
            return result

        result.patches_applied = patches
        result.patched_binary_path = str(output_path)
        result.license_checks_bypassed = len([p for p in patches if p.patch_type == "license_bypass"])
        result.integrity_checks_neutralized = len([p for p in patches if p.patch_type == "integrity_bypass"])
        result.rasp_mechanisms_defeated = len([p for p in patches if p.patch_type == "rasp_bypass"])

        self.logger.info(f"Applied {len(patches)} patches to binary")
        self.logger.info(f"Patched binary saved: {output_path}")

        if runtime_bypass and process_name:
            if not FRIDA_AVAILABLE:
                self.logger.warning("Frida not available - runtime bypass disabled")
            else:
                frida_script = self._generate_frida_bypass_script(analysis_result)
                result.frida_script = frida_script

                try:
                    self.frida_session = frida.attach(process_name)
                    self.frida_script = self.frida_session.create_script(frida_script)
                    self.frida_script.on("message", self._on_frida_message)
                    self.frida_script.load()

                    result.runtime_hooks_installed = frida_script.count("Interceptor.attach")
                    self.logger.info(f"Installed {result.runtime_hooks_installed} Frida hooks")

                except Exception as e:
                    self.logger.error(f"Frida runtime bypass failed: {e}")

        result.success = True
        return result

    def _bypass_tamper_checks(
        self,
        binary_data: bytearray,
        tamper_checks: list[TamperCheckLocation],
        patches: list[BypassPatch],
    ) -> None:
        """Bypass anti-tampering checks."""
        for check in tamper_checks:
            if check.algorithm == "crc32" or check.algorithm in ["md5", "sha256"]:
                patch_bytes = self.MOV_EAX_1 + self.RET_OPCODE
            else:
                patch_bytes = self.NOP_OPCODE * min(check.size, 20)

            if check.address < len(binary_data):
                original_bytes = binary_data[check.address : check.address + len(patch_bytes)]

                patch = BypassPatch(
                    address=check.address,
                    original_bytes=bytes(original_bytes),
                    patched_bytes=patch_bytes,
                    patch_type="tamper_bypass",
                    description=f"Bypass {check.algorithm} tamper check",
                )
                patches.append(patch)

                self.logger.debug(f"Patching tamper check at 0x{check.address:x}: {check.algorithm}")

    def _bypass_integrity_checks(
        self,
        binary_data: bytearray,
        integrity_checks: list,
        patches: list[BypassPatch],
    ) -> None:
        """Neutralize integrity check mechanisms."""
        for check in integrity_checks:
            if check.hash_algorithm == "CRC32":
                patch_bytes = b"\xb8\x00\x00\x00\x00\xc3"
            elif check.hash_algorithm in ["SHA1", "SHA256", "MD5"]:
                patch_bytes = b"\xb8\x01\x00\x00\x00\xc3"
            else:
                patch_bytes = self.NOP_OPCODE * 6

            if check.address < len(binary_data):
                original_bytes = binary_data[check.address : check.address + len(patch_bytes)]

                patch = BypassPatch(
                    address=check.address,
                    original_bytes=bytes(original_bytes),
                    patched_bytes=patch_bytes,
                    patch_type="integrity_bypass",
                    description=f"Neutralize {check.hash_algorithm} integrity check",
                )
                patches.append(patch)

                self.logger.debug(f"Patching integrity check at 0x{check.address:x}: {check.hash_algorithm}")

    def _bypass_license_validation(
        self,
        binary_data: bytearray,
        license_routines: list[LicenseValidationRoutine],
        patches: list[BypassPatch],
    ) -> None:
        """Bypass license validation routines."""
        for routine in license_routines:
            if routine.validation_type in {"rsa_validation", "aes_license"}:
                patch_bytes = b"\xb8\x01\x00\x00\x00\xc3"
            elif routine.validation_type == "serial_check":
                patch_bytes = b"\x33\xc0\x40\xc3"
            else:
                patch_bytes = b"\xb8\x01\x00\x00\x00\xc3"

            if routine.address < len(binary_data):
                original_bytes = binary_data[routine.address : routine.address + len(patch_bytes)]

                patch = BypassPatch(
                    address=routine.address,
                    original_bytes=bytes(original_bytes),
                    patched_bytes=patch_bytes,
                    patch_type="license_bypass",
                    description=f"Bypass {routine.validation_type} license check",
                )
                patches.append(patch)

                self.logger.debug(f"Patching license validation at 0x{routine.address:x}: {routine.validation_type}")

    def _neutralize_rasp(
        self,
        binary_data: bytearray,
        rasp_mechanisms: list[RASPMechanism],
        patches: list[BypassPatch],
    ) -> None:
        """Defeat RASP mechanisms."""
        for rasp in rasp_mechanisms:
            if rasp.mechanism_type == "anti_debug":
                patch_bytes = b"\x33\xc0\xc3"
            elif rasp.mechanism_type == "anti_frida":
                patch_bytes = self.NOP_OPCODE * 10
            elif rasp.mechanism_type == "anti_hook":
                patch_bytes = b"\xb8\x01\x00\x00\x00\xc3"
            elif rasp.mechanism_type == "exception_handler":
                patch_bytes = self.NOP_OPCODE * 8
            else:
                patch_bytes = self.NOP_OPCODE * 6

            if rasp.address < len(binary_data):
                original_bytes = binary_data[rasp.address : rasp.address + len(patch_bytes)]

                patch = BypassPatch(
                    address=rasp.address,
                    original_bytes=bytes(original_bytes),
                    patched_bytes=patch_bytes,
                    patch_type="rasp_bypass",
                    description=f"Defeat {rasp.mechanism_type} RASP",
                )
                patches.append(patch)

                self.logger.debug(f"Patching RASP mechanism at 0x{rasp.address:x}: {rasp.mechanism_type}")

    def _decrypt_strings(
        self,
        binary_data: bytearray,
        encrypted_regions: list[tuple[int, int]],
        patches: list[BypassPatch],
    ) -> None:
        """Decrypt encrypted strings (where possible)."""
        for address, length in encrypted_regions[:10]:
            if address + length > len(binary_data):
                continue

            encrypted_data = binary_data[address : address + length]

            for xor_key in range(1, 256):
                decrypted = bytes(b ^ xor_key for b in encrypted_data)

                printable_ratio = sum(1 for b in decrypted if 32 <= b < 127) / len(decrypted)

                if printable_ratio > 0.7:
                    patch = BypassPatch(
                        address=address,
                        original_bytes=bytes(encrypted_data),
                        patched_bytes=decrypted,
                        patch_type="string_decryption",
                        description=f"Decrypt XOR-{xor_key} encrypted string",
                    )
                    patches.append(patch)

                    self.logger.debug(f"Decrypting string at 0x{address:x} with XOR key {xor_key}")
                    break

    def _generate_frida_bypass_script(self, analysis_result: object) -> str:
        """Generate Frida script for runtime bypass.

        Args:
            analysis_result: Analysis result containing license routines and protection details.

        Returns:
            Frida JavaScript code for runtime protection bypass.

        """
        script_parts = [
            "console.log('[Arxan Bypass] Initializing runtime hooks...');",
            "",
        ]

        script_parts.extend(
            [
                "// Anti-debugging bypass",
                "var isDebuggerPresent = Module.findExportByName('kernel32.dll', 'IsDebuggerPresent');",
                "if (isDebuggerPresent) {",
                "    Interceptor.replace(isDebuggerPresent, new NativeCallback(function() {",
                "        return 0;",
                "    }, 'int', []));",
                "    console.log('[Arxan] Bypassed IsDebuggerPresent');",
                "}",
                "",
                "var checkRemoteDebugger = Module.findExportByName('kernel32.dll', 'CheckRemoteDebuggerPresent');",
                "if (checkRemoteDebugger) {",
                "    Interceptor.attach(checkRemoteDebugger, {",
                "        onEnter: function(args) {",
                "            this.pbDebuggerPresent = args[1];",
                "        },",
                "        onLeave: function(retval) {",
                "            if (this.pbDebuggerPresent) {",
                "                this.pbDebuggerPresent.writeU8(0);",
                "            }",
                "            retval.replace(1);",
                "        }",
                "    });",
                "    console.log('[Arxan] Bypassed CheckRemoteDebuggerPresent');",
                "}",
                "",
                "var ntQueryInfo = Module.findExportByName('ntdll.dll', 'NtQueryInformationProcess');",
                "if (ntQueryInfo) {",
                "    Interceptor.attach(ntQueryInfo, {",
                "        onEnter: function(args) {",
                "            this.infoClass = args[1].toInt32();",
                "            this.info = args[2];",
                "        },",
                "        onLeave: function(retval) {",
                "            if (this.infoClass === 7 || this.infoClass === 30 || this.infoClass === 31) {",
                "                if (this.info) {",
                "                    this.info.writePointer(ptr(0));",
                "                }",
                "                retval.replace(0);",
                "            }",
                "        }",
                "    });",
                "    console.log('[Arxan] Bypassed NtQueryInformationProcess');",
                "}",
                "",
            ],
        )

        script_parts.extend(
            [
                "// Integrity check bypass",
                "var cryptHashData = Module.findExportByName('Advapi32.dll', 'CryptHashData');",
                "if (cryptHashData) {",
                "    Interceptor.replace(cryptHashData, new NativeCallback(function(hHash, pbData, dwDataLen, dwFlags) {",
                "        return 1;",
                "    }, 'int', ['pointer', 'pointer', 'uint', 'uint']));",
                "    console.log('[Arxan] Bypassed CryptHashData');",
                "}",
                "",
                "var cryptVerifySig = Module.findExportByName('Advapi32.dll', 'CryptVerifySignature');",
                "if (cryptVerifySig) {",
                "    Interceptor.replace(cryptVerifySig, new NativeCallback(function() {",
                "        return 1;",
                "    }, 'int', ['pointer', 'pointer', 'uint', 'pointer', 'pointer', 'uint']));",
                "    console.log('[Arxan] Bypassed CryptVerifySignature');",
                "}",
                "",
            ],
        )

        for routine in analysis_result.license_routines[:5]:
            script_parts.extend(
                [
                    f"// License validation bypass at 0x{routine.address:x}",
                    f"var licenseFunc{routine.address:x} = ptr('0x{routine.address:x}');",
                    f"if (licenseFunc{routine.address:x}) {{",
                    "    try {",
                    f"        Interceptor.replace(licenseFunc{routine.address:x}, new NativeCallback(function() {{",
                    f"            console.log('[Arxan] Bypassed license check at 0x{routine.address:x}');",
                    "            return 1;",
                    "        }, 'int', []));",
                    "    } catch(e) {",
                    f"        console.log('[Arxan] Could not hook license function at 0x{routine.address:x}: ' + e);",
                    "    }",
                    "}",
                    "",
                ],
            )

        script_parts.extend(
            [
                "// Memory protection bypass",
                "var virtualProtect = Module.findExportByName('kernel32.dll', 'VirtualProtect');",
                "if (virtualProtect) {",
                "    Interceptor.attach(virtualProtect, {",
                "        onLeave: function(retval) {",
                "            retval.replace(1);",
                "        }",
                "    });",
                "    console.log('[Arxan] Hooked VirtualProtect');",
                "}",
                "",
                "console.log('[Arxan Bypass] All runtime hooks installed');",
            ],
        )

        return "\n".join(script_parts)

    def _rva_to_offset(self, pe: pefile.PE, rva: int) -> int | None:
        """Convert RVA to file offset."""
        for section in pe.sections:
            if section.VirtualAddress <= rva < section.VirtualAddress + section.Misc_VirtualSize:
                return section.PointerToRawData + (rva - section.VirtualAddress)
        return None

    def _calculate_pe_checksum(self, binary_data: bytes) -> int:
        """Calculate PE checksum."""
        checksum = 0

        for i in range(0, len(binary_data), 4):
            if i + 4 <= len(binary_data):
                dword = struct.unpack("<I", binary_data[i : i + 4])[0]
            elif i + 2 <= len(binary_data):
                dword = struct.unpack("<H", binary_data[i : i + 2])[0]
            else:
                dword = binary_data[i]

            checksum = (checksum + dword) & 0xFFFFFFFF
            checksum = (checksum & 0xFFFF) + (checksum >> 16)

        checksum = (checksum & 0xFFFF) + (checksum >> 16)
        checksum += len(binary_data)

        return checksum & 0xFFFFFFFF

    def _on_frida_message(self, message: dict[str, object], data: object) -> None:
        """Handle Frida script messages.

        Args:
            message: Dictionary containing Frida message type and payload.
            data: Binary data associated with the message.

        """
        if message["type"] == "send":
            self.logger.info(f"[Frida] {message['payload']}")
        elif message["type"] == "error":
            self.logger.error(f"[Frida Error] {message.get('stack', message)}")

    def cleanup(self) -> None:
        """Clean up Frida session."""
        if self.frida_script:
            try:
                self.frida_script.unload()
            except Exception as e:
                self.logger.debug(f"Failed to unload Frida script: {e}")

        if self.frida_session:
            try:
                self.frida_session.detach()
            except Exception as e:
                self.logger.debug(f"Failed to detach Frida session: {e}")


def main() -> None:
    """Test entry point for Arxan bypass."""
    import argparse
    import json

    parser = argparse.ArgumentParser(description="Arxan TransformIT Bypass")
    parser.add_argument("binary", help="Binary file to bypass")
    parser.add_argument("-o", "--output", help="Output path for patched binary")
    parser.add_argument("-r", "--runtime", action="store_true", help="Enable runtime bypass")
    parser.add_argument("-p", "--process", help="Process name for Frida attachment")
    parser.add_argument("-v", "--verbose", action="store_true", help="Verbose output")
    parser.add_argument("-j", "--json", action="store_true", help="JSON output")

    args = parser.parse_args()

    if args.verbose:
        logging.basicConfig(level=logging.DEBUG)
    else:
        logging.basicConfig(level=logging.INFO)

    bypass = ArxanBypass()

    try:
        result = bypass.bypass(
            args.binary,
            args.output,
            runtime_bypass=args.runtime,
            process_name=args.process,
        )

        if args.json:
            output = {
                "success": result.success,
                "patches_applied": len(result.patches_applied),
                "license_checks_bypassed": result.license_checks_bypassed,
                "integrity_checks_neutralized": result.integrity_checks_neutralized,
                "rasp_mechanisms_defeated": result.rasp_mechanisms_defeated,
                "runtime_hooks_installed": result.runtime_hooks_installed,
                "patched_binary": result.patched_binary_path,
            }
            print(json.dumps(output, indent=2))
        else:
            print("\n=== Arxan Bypass Results ===")
            print(f"Success: {result.success}")
            print(f"Patches Applied: {len(result.patches_applied)}")
            print(f"License Checks Bypassed: {result.license_checks_bypassed}")
            print(f"Integrity Checks Neutralized: {result.integrity_checks_neutralized}")
            print(f"RASP Mechanisms Defeated: {result.rasp_mechanisms_defeated}")

            if result.runtime_hooks_installed > 0:
                print(f"Runtime Hooks Installed: {result.runtime_hooks_installed}")

            if result.patched_binary_path:
                print(f"\nPatched Binary: {result.patched_binary_path}")

            if result.patches_applied:
                print(f"\n=== Applied Patches ({len(result.patches_applied)}) ===")
                for patch in result.patches_applied[:10]:
                    print(f"  - 0x{patch.address:x}: {patch.description}")

    except Exception as e:
        logger.error(f"Bypass failed: {e}")
        logger.error(e)
        raise


if __name__ == "__main__":
    main()

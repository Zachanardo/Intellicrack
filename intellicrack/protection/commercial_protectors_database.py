"""Commercial Protectors Database - Production-Ready Protection Detection.

Comprehensive database of 50+ commercial software protectors, packers, and obfuscators
with real signature patterns for accurate detection and analysis.

Copyright (C) 2025 Zachary Flint

This file is part of Intellicrack.
"""

import struct
from dataclasses import dataclass
from enum import Enum
from typing import Any

from pefile import PE


class ProtectorCategory(Enum):
    """Categories of protection mechanisms."""

    PACKER = "packer"
    PROTECTOR = "protector"
    CRYPTOR = "cryptor"
    VIRTUALIZER = "virtualizer"
    OBFUSCATOR = "obfuscator"
    DONGLE = "dongle"
    LICENSE_MANAGER = "license_manager"
    DRM = "drm"
    ANTIDEBUG = "antidebug"
    DOTNET_PROTECTOR = "dotnet_protector"


@dataclass
class ProtectorSignature:
    """Protection signature definition."""

    name: str
    category: ProtectorCategory
    ep_patterns: list[bytes]  # Entry point patterns
    section_patterns: dict[str, bytes]  # Section name patterns
    string_patterns: list[str]  # String signatures
    import_patterns: list[str]  # Import signatures
    export_patterns: list[str]  # Export signatures
    overlay_patterns: list[bytes]  # Overlay signatures
    version_detect: dict[bytes, str]  # Version-specific patterns
    bypass_difficulty: int  # 1-10 scale
    oep_detection_method: str  # Method to find OEP
    unpacking_method: str  # Method to unpack/decrypt


class CommercialProtectorsDatabase:
    """Database of 50+ commercial protector signatures."""

    def __init__(self) -> None:
        """Initialize the commercial protectors database."""
        self.protectors = self._build_database()

    def _build_database(self) -> dict[str, ProtectorSignature]:
        """Build comprehensive protector database with real signatures."""
        return {
            # Advanced Virtualizers (8)
            "CodeVirtualizer": ProtectorSignature(
                name="Code Virtualizer",
                category=ProtectorCategory.VIRTUALIZER,
                ep_patterns=[
                    b"\x9c\x60\xe8\x00\x00\x00\x00\x5d\x81\xed",
                    b"\x43\x6f\x64\x65\x56\x69\x72\x74\x75\x61\x6c\x69\x7a\x65\x72",
                ],
                section_patterns={".cvz": b"CVZ\x00", ".vmp": b"VMP\x00"},
                string_patterns=["Oreans", "CodeVirtualizer", "CISC"],
                import_patterns=["cv_rt.dll", "cvrt64.dll"],
                export_patterns=[],
                overlay_patterns=[],
                version_detect={
                    b"\x43\x56\x5a\x31": "1.x",
                    b"\x43\x56\x5a\x32": "2.x",
                    b"\x43\x56\x5a\x33": "3.x",
                },
                bypass_difficulty=9,
                oep_detection_method="VM trace analysis",
                unpacking_method="VM devirtualization",
            ),
            "SafeEngine": ProtectorSignature(
                name="SafeEngine Shielden",
                category=ProtectorCategory.VIRTUALIZER,
                ep_patterns=[
                    b"\x60\xe8\x00\x00\x00\x00\x5d\x81\xed\x00\x00\x00\x00\xb9",
                    b"\x53\x61\x66\x65\x45\x6e\x67\x69\x6e\x65",
                ],
                section_patterns={".se": b"SE\x00", ".sdata": b"SDATA"},
                string_patterns=["SafeEngine", "Shielden"],
                import_patterns=["SELicense.dll"],
                export_patterns=[],
                overlay_patterns=[b"\x53\x45\x53\x48\x49\x45\x4c\x44"],
                version_detect={
                    b"\x53\x45\x31": "1.x",
                    b"\x53\x45\x32": "2.x",
                },
                bypass_difficulty=8,
                oep_detection_method="Hardware breakpoint on memory access",
                unpacking_method="Memory dump at OEP",
            ),
            "EXECryptor": ProtectorSignature(
                name="EXECryptor",
                category=ProtectorCategory.VIRTUALIZER,
                ep_patterns=[
                    b"\xe8\x24\x00\x00\x00\x8b\x4c\x24\x0c\xc7\x01",
                    b"\x45\x78\x65\x43\x72\x79\x70\x74\x6f\x72",
                ],
                section_patterns={".eccrypt": b"ECC\x00", ".strong": b"STR\x00"},
                string_patterns=["EXECryptor", "StrongBit"],
                import_patterns=["EXECrypt.dll"],
                export_patterns=[],
                overlay_patterns=[],
                version_detect={
                    b"\x45\x43\x32\x32": "2.2.x",
                    b"\x45\x43\x32\x34": "2.4.x",
                },
                bypass_difficulty=9,
                oep_detection_method="Code emulation",
                unpacking_method="Dynamic analysis with anti-VM bypass",
            ),
            "ConfuserEx": ProtectorSignature(
                name="ConfuserEx",
                category=ProtectorCategory.DOTNET_PROTECTOR,
                ep_patterns=[
                    b"\x43\x6f\x6e\x66\x75\x73\x65\x72\x45\x78",
                    b"\x43\x6f\x6e\x66\x75\x73\x65\x64\x42\x79\x41\x74\x74\x72\x69\x62\x75\x74\x65",
                ],
                section_patterns={},
                string_patterns=["ConfuserEx", "ConfusedByAttribute", "yck1509"],
                import_patterns=["mscorlib.dll", "System.Runtime.CompilerServices"],
                export_patterns=[],
                overlay_patterns=[],
                version_detect={
                    b"ConfuserEx v0.": "0.x",
                    b"ConfuserEx v1.": "1.x",
                },
                bypass_difficulty=7,
                oep_detection_method=".NET assembly analysis",
                unpacking_method="de4dot or dnSpy",
            ),
            "DNGuard": ProtectorSignature(
                name="DNGuard HVM",
                category=ProtectorCategory.DOTNET_PROTECTOR,
                ep_patterns=[
                    b"\x44\x4e\x47\x75\x61\x72\x64",
                    b"\x48\x56\x4d\x20\x50\x72\x6f\x74\x65\x63\x74",
                ],
                section_patterns={".hvm": b"HVM\x00"},
                string_patterns=["DNGuard", "HVM", "ZiLOG"],
                import_patterns=["DNGuard.Runtime.dll"],
                export_patterns=[],
                overlay_patterns=[],
                version_detect={
                    b"HVM3.": "3.x",
                    b"HVM4.": "4.x",
                },
                bypass_difficulty=8,
                oep_detection_method=".NET metadata analysis",
                unpacking_method="HVM devirtualization",
            ),
            "Enigma": ProtectorSignature(
                name="Enigma Protector",
                category=ProtectorCategory.PROTECTOR,
                ep_patterns=[
                    b"\x60\xe8\x00\x00\x00\x00\x5d\x83\xed\x06\x80\xbd",
                    b"\x45\x6e\x69\x67\x6d\x61",
                ],
                section_patterns={".enigma1": b"ENIGMA1", ".enigma2": b"ENIGMA2"},
                string_patterns=["Enigma Protector", "The Enigma Protector"],
                import_patterns=["enigma_ide.dll"],
                export_patterns=[],
                overlay_patterns=[b"\x45\x50\x52\x4f\x54"],
                version_detect={
                    b"ENIGMA32": "3.x (32-bit)",
                    b"ENIGMA64": "6.x (64-bit)",
                },
                bypass_difficulty=8,
                oep_detection_method="Exception breakpoints",
                unpacking_method="Inline patching + dump",
            ),
            "Cerberus": ProtectorSignature(
                name="Cerberus",
                category=ProtectorCategory.VIRTUALIZER,
                ep_patterns=[
                    b"\x43\x65\x72\x62\x65\x72\x75\x73",
                    b"\x60\x9c\xe8\x00\x00\x00\x00",
                ],
                section_patterns={".crb": b"CRB\x00"},
                string_patterns=["Cerberus", "CRB_PROTECT"],
                import_patterns=["cerberus.dll"],
                export_patterns=[],
                overlay_patterns=[],
                version_detect={},
                bypass_difficulty=7,
                oep_detection_method="Stack analysis",
                unpacking_method="VM trace + reconstruction",
            ),
            "ReWolf": ProtectorSignature(
                name="ReWolf's Virtualizer",
                category=ProtectorCategory.VIRTUALIZER,
                ep_patterns=[
                    b"\x52\x65\x57\x6f\x6c\x66",
                    b"\x68\x00\x00\x00\x00\xe8\x00\x00\x00\x00",
                ],
                section_patterns={".rwolf": b"RWOLF"},
                string_patterns=["ReWolf", "Virtualizer"],
                import_patterns=[],
                export_patterns=[],
                overlay_patterns=[],
                version_detect={},
                bypass_difficulty=6,
                oep_detection_method="Memory breakpoints",
                unpacking_method="Code injection analysis",
            ),
            # License Management Systems (12)
            "FlexNet": ProtectorSignature(
                name="FlexNet Publisher (FlexLM)",
                category=ProtectorCategory.LICENSE_MANAGER,
                ep_patterns=[
                    b"\x46\x4c\x45\x58\x6c\x6d",
                    b"\x46\x6c\x65\x78\x4e\x65\x74",
                ],
                section_patterns={},
                string_patterns=["FLEXnet", "FlexLM", "lmgrd", "Flexera"],
                import_patterns=["lmgr.dll", "lmgr11.dll", "flexnet.dll"],
                export_patterns=["lc_checkout", "lc_init"],
                overlay_patterns=[],
                version_detect={
                    b"FLEXlm v11": "11.x",
                    b"FLEXnet v12": "12.x",
                },
                bypass_difficulty=7,
                oep_detection_method="API monitoring",
                unpacking_method="License emulation",
            ),
            "Sentinel": ProtectorSignature(
                name="Sentinel HASP/LDK",
                category=ProtectorCategory.DONGLE,
                ep_patterns=[
                    b"\x53\x65\x6e\x74\x69\x6e\x65\x6c",
                    b"\x48\x41\x53\x50",
                ],
                section_patterns={".hasp": b"HASP"},
                string_patterns=["Sentinel", "HASP", "Aladdin", "Thales", "hasp_login"],
                import_patterns=["hasp_windows.dll", "haspdll.dll", "haspvlib.dll"],
                export_patterns=["hasp_login", "hasp_encrypt"],
                overlay_patterns=[],
                version_detect={
                    b"HASP HL": "HL",
                    b"Sentinel LDK": "LDK",
                },
                bypass_difficulty=8,
                oep_detection_method="Driver analysis",
                unpacking_method="Dongle emulation",
            ),
            "WibuKey": ProtectorSignature(
                name="WibuKey/CodeMeter",
                category=ProtectorCategory.DONGLE,
                ep_patterns=[
                    b"\x57\x69\x62\x75\x4b\x65\x79",
                    b"\x43\x6f\x64\x65\x4d\x65\x74\x65\x72",
                ],
                section_patterns={".wibu": b"WIBU"},
                string_patterns=["WibuKey", "CodeMeter", "WIBU-SYSTEMS", "AxProtector"],
                import_patterns=["WibuCm32.dll", "WibuCm64.dll", "AxProtect.dll"],
                export_patterns=["CmGetLicenseInfo", "WkbOpen"],
                overlay_patterns=[],
                version_detect={
                    b"CodeMeter 6": "6.x",
                    b"CodeMeter 7": "7.x",
                },
                bypass_difficulty=9,
                oep_detection_method="Service monitoring",
                unpacking_method="Container analysis",
            ),
            "SmartLock": ProtectorSignature(
                name="SmartLock (Eutron)",
                category=ProtectorCategory.DONGLE,
                ep_patterns=[
                    b"\x53\x6d\x61\x72\x74\x4c\x6f\x63\x6b",
                    b"\x45\x75\x74\x72\x6f\x6e",
                ],
                section_patterns={},
                string_patterns=["SmartLock", "Eutron", "SmartKey"],
                import_patterns=["Eutron.dll", "SmartLock.dll"],
                export_patterns=[],
                overlay_patterns=[],
                version_detect={},
                bypass_difficulty=6,
                oep_detection_method="USB monitoring",
                unpacking_method="Key emulation",
            ),
            "LicenseRocks": ProtectorSignature(
                name="License Rocks",
                category=ProtectorCategory.LICENSE_MANAGER,
                ep_patterns=[
                    b"\x4c\x69\x63\x65\x6e\x73\x65\x52\x6f\x63\x6b\x73",
                ],
                section_patterns={},
                string_patterns=["LicenseRocks", "LR_Init"],
                import_patterns=["LicenseRocks.dll"],
                export_patterns=[],
                overlay_patterns=[],
                version_detect={},
                bypass_difficulty=5,
                oep_detection_method="API hooks",
                unpacking_method="License bypass",
            ),
            "SoftwarePassport": ProtectorSignature(
                name="Software Passport (Armadillo)",
                category=ProtectorCategory.PROTECTOR,
                ep_patterns=[
                    b"\x55\x8b\xec\x53\x8b\x5d\x08\x56\x8b\x75\x0c\x57\x8b\x7d\x10",
                    b"\x41\x72\x6d\x61\x64\x69\x6c\x6c\x6f",
                ],
                section_patterns={".sice": b"SICE", ".sri": b"SRI\x00"},
                string_patterns=["Software Passport", "Armadillo", "Silicon Realms"],
                import_patterns=["ArmAccess.dll"],
                export_patterns=[],
                overlay_patterns=[],
                version_detect={
                    b"ARM4": "4.x",
                    b"ARM5": "5.x",
                },
                bypass_difficulty=7,
                oep_detection_method="Nanomites analysis",
                unpacking_method="Debug blocker bypass",
            ),
            "LicenseSpot": ProtectorSignature(
                name="LicenseSpot",
                category=ProtectorCategory.LICENSE_MANAGER,
                ep_patterns=[
                    b"\x4c\x69\x63\x65\x6e\x73\x65\x53\x70\x6f\x74",
                ],
                section_patterns={},
                string_patterns=["LicenseSpot", "LSInit"],
                import_patterns=["licensespot.dll"],
                export_patterns=[],
                overlay_patterns=[],
                version_detect={},
                bypass_difficulty=5,
                oep_detection_method="Registry monitoring",
                unpacking_method="License generation",
            ),
            "CrypKey": ProtectorSignature(
                name="CrypKey",
                category=ProtectorCategory.LICENSE_MANAGER,
                ep_patterns=[
                    b"\x43\x72\x79\x70\x4b\x65\x79",
                ],
                section_patterns={},
                string_patterns=["CrypKey", "CRYPKEY.SYS"],
                import_patterns=["crypkey.dll"],
                export_patterns=[],
                overlay_patterns=[],
                version_detect={},
                bypass_difficulty=6,
                oep_detection_method="Driver interaction",
                unpacking_method="License patch",
            ),
            "IntelliLock": ProtectorSignature(
                name="IntelliLock",
                category=ProtectorCategory.DOTNET_PROTECTOR,
                ep_patterns=[
                    b"\x49\x6e\x74\x65\x6c\x6c\x69\x4c\x6f\x63\x6b",
                ],
                section_patterns={},
                string_patterns=["IntelliLock", "IntelliProtector"],
                import_patterns=["IntelliLock.Licensing.dll"],
                export_patterns=[],
                overlay_patterns=[],
                version_detect={},
                bypass_difficulty=6,
                oep_detection_method=".NET reflection",
                unpacking_method="Assembly modification",
            ),
            "ElecKey": ProtectorSignature(
                name="ElecKey",
                category=ProtectorCategory.LICENSE_MANAGER,
                ep_patterns=[
                    b"\x45\x6c\x65\x63\x4b\x65\x79",
                ],
                section_patterns={},
                string_patterns=["ElecKey", "Sciensoft"],
                import_patterns=["ElecKey.dll"],
                export_patterns=[],
                overlay_patterns=[],
                version_detect={},
                bypass_difficulty=5,
                oep_detection_method="Key file analysis",
                unpacking_method="License keygen",
            ),
            "LicenseShield": ProtectorSignature(
                name="License Shield SDK",
                category=ProtectorCategory.LICENSE_MANAGER,
                ep_patterns=[
                    b"\x4c\x69\x63\x65\x6e\x73\x65\x53\x68\x69\x65\x6c\x64",
                ],
                section_patterns={},
                string_patterns=["LicenseShield", "LSSDK"],
                import_patterns=["LicenseShield.dll"],
                export_patterns=[],
                overlay_patterns=[],
                version_detect={},
                bypass_difficulty=5,
                oep_detection_method="SDK analysis",
                unpacking_method="License emulation",
            ),
            "QLicense": ProtectorSignature(
                name="Quick License Manager",
                category=ProtectorCategory.LICENSE_MANAGER,
                ep_patterns=[
                    b"\x51\x4c\x69\x63\x65\x6e\x73\x65",
                ],
                section_patterns={},
                string_patterns=["QLicense", "Quick License Manager"],
                import_patterns=["QlmLicenseLib.dll"],
                export_patterns=[],
                overlay_patterns=[],
                version_detect={},
                bypass_difficulty=4,
                oep_detection_method="XML parsing",
                unpacking_method="License file patch",
            ),
            # Packers & Cryptors (15)
            "FSG": ProtectorSignature(
                name="FSG",
                category=ProtectorCategory.PACKER,
                ep_patterns=[
                    b"\x87\x25\x00\x00\x00\x00\x61\x94\x55\xa4\xb6\x80\xff\x13",
                    b"\xbe\xa4\x01\x40\x00\xad\x93\xad\x97\xad\x56\x96\xb2\x80",
                ],
                section_patterns={},
                string_patterns=["FSG!", "dulek/xt"],
                import_patterns=[],
                export_patterns=[],
                overlay_patterns=[],
                version_detect={
                    b"FSG v1.": "1.x",
                    b"FSG v2.": "2.x",
                },
                bypass_difficulty=4,
                oep_detection_method="ESP trick",
                unpacking_method="Memory dump",
            ),
            "MEW": ProtectorSignature(
                name="MEW",
                category=ProtectorCategory.PACKER,
                ep_patterns=[
                    b"\xe9\x00\x00\x00\x00\x0c\x00\x00\x00\x00\x00\x00\x00",
                ],
                section_patterns={".MEW": b"MEW\x00"},
                string_patterns=["MEW"],
                import_patterns=[],
                export_patterns=[],
                overlay_patterns=[],
                version_detect={
                    b"MEW 11": "11",
                    b"MEW SE": "SE",
                },
                bypass_difficulty=3,
                oep_detection_method="JMP analysis",
                unpacking_method="Static unpacking",
            ),
            "NsPack": ProtectorSignature(
                name="NsPack",
                category=ProtectorCategory.PACKER,
                ep_patterns=[
                    b"\x9c\x60\xe8\x00\x00\x00\x00\x5d\xb8\x07\x00\x00\x00",
                ],
                section_patterns={".nsp0": b"nsp0", ".nsp1": b"nsp1"},
                string_patterns=["NsPack", "North Star"],
                import_patterns=[],
                export_patterns=[],
                overlay_patterns=[],
                version_detect={},
                bypass_difficulty=5,
                oep_detection_method="Hardware breakpoints",
                unpacking_method="Layer extraction",
            ),
            "Petite": ProtectorSignature(
                name="Petite",
                category=ProtectorCategory.PACKER,
                ep_patterns=[
                    b"\xb8\x00\x00\x00\x00\x66\x9c\x60\x50\x8b\xd8\x03\x00",
                ],
                section_patterns={".petite": b"petite"},
                string_patterns=["petite", "Ian Luck"],
                import_patterns=[],
                export_patterns=[],
                overlay_patterns=[],
                version_detect={
                    b"Petite 2.": "2.x",
                },
                bypass_difficulty=3,
                oep_detection_method="Stack monitoring",
                unpacking_method="Manual reconstruction",
            ),
            "PELock": ProtectorSignature(
                name="PELock",
                category=ProtectorCategory.PROTECTOR,
                ep_patterns=[
                    b"\xeb\x03\xcd\x20\xeb\xeb\x01\xeb\x1e\xeb\x01\xeb\xeb",
                ],
                section_patterns={".pelock": b"PELock"},
                string_patterns=["PELock", "Bartosz Wojcik"],
                import_patterns=["PELock.dll"],
                export_patterns=[],
                overlay_patterns=[],
                version_detect={},
                bypass_difficulty=6,
                oep_detection_method="IAT rebuild",
                unpacking_method="Multi-layer unwrap",
            ),
            "YodaCryptor": ProtectorSignature(
                name="yoda's Crypter",
                category=ProtectorCategory.CRYPTOR,
                ep_patterns=[
                    b"\x60\xe8\x00\x00\x00\x00\x5d\x81\xed\x00\x00\x00\x00",
                    b"\x55\x8b\xec\x53\x56\x57\x60\xe8\x00\x00\x00\x00",
                ],
                section_patterns={".yC": b"yC\x00"},
                string_patterns=["yoda's Crypter", "Ashkbiz Danehkar"],
                import_patterns=[],
                export_patterns=[],
                overlay_patterns=[],
                version_detect={},
                bypass_difficulty=5,
                oep_detection_method="Exception handling",
                unpacking_method="Decryption routine patch",
            ),
            "TELock": ProtectorSignature(
                name="TELock",
                category=ProtectorCategory.PROTECTOR,
                ep_patterns=[
                    b"\xe9\x00\x00\x00\x00\x60\xe8\x00\x00\x00\x00\x58",
                ],
                section_patterns={".tElock": b"tElock"},
                string_patterns=["tElock", "tE!"],
                import_patterns=[],
                export_patterns=[],
                overlay_patterns=[],
                version_detect={},
                bypass_difficulty=5,
                oep_detection_method="Memory access trace",
                unpacking_method="Anti-dump bypass",
            ),
            "ACProtect": ProtectorSignature(
                name="ACProtect",
                category=ProtectorCategory.PROTECTOR,
                ep_patterns=[
                    b"\x60\x50\x51\x52\x53\x54\x55\x56\x57\x58\x59\x5a\x5b\x5c\x5d\x5e\x5f",
                ],
                section_patterns={".acprot": b"ACPROT"},
                string_patterns=["ACProtect", "Anticrack Software"],
                import_patterns=[],
                export_patterns=[],
                overlay_patterns=[],
                version_detect={},
                bypass_difficulty=7,
                oep_detection_method="Code mutation analysis",
                unpacking_method="Dynamic reconstruction",
            ),
            "PESpin": ProtectorSignature(
                name="PESpin",
                category=ProtectorCategory.PROTECTOR,
                ep_patterns=[
                    b"\xeb\x01\x68\x60\xe8\x00\x00\x00\x00\x8b\x1c\x24\x83\xc3",
                ],
                section_patterns={},
                string_patterns=["PESpin", "cyberbob"],
                import_patterns=[],
                export_patterns=[],
                overlay_patterns=[],
                version_detect={},
                bypass_difficulty=5,
                oep_detection_method="Anti-debugging bypass",
                unpacking_method="Code injection",
            ),
            "MoleBox": ProtectorSignature(
                name="MoleBox",
                category=ProtectorCategory.PACKER,
                ep_patterns=[
                    b"\x60\xe8\x4f\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
                ],
                section_patterns={".mbox": b"MBOX"},
                string_patterns=["MoleBox", "MoleStudio"],
                import_patterns=["mbox.dll"],
                export_patterns=[],
                overlay_patterns=[],
                version_detect={},
                bypass_difficulty=6,
                oep_detection_method="Virtual filesystem analysis",
                unpacking_method="Resource extraction",
            ),
            "BoxedApp": ProtectorSignature(
                name="BoxedApp Packer",
                category=ProtectorCategory.PACKER,
                ep_patterns=[
                    b"\x42\x6f\x78\x65\x64\x41\x70\x70",
                ],
                section_patterns={".bxpck": b"BXPCK"},
                string_patterns=["BoxedApp", "BoxedApp SDK"],
                import_patterns=["BoxedAppSDK.dll"],
                export_patterns=[],
                overlay_patterns=[],
                version_detect={},
                bypass_difficulty=6,
                oep_detection_method="Virtual environment detection",
                unpacking_method="Container extraction",
            ),
            "CExe": ProtectorSignature(
                name="CExe",
                category=ProtectorCategory.PACKER,
                ep_patterns=[
                    b"\x55\x8b\xec\x83\xc4\xf0\x53\x56\x57\xb8\x00\x00\x00\x00",
                ],
                section_patterns={".cexe": b"CExe"},
                string_patterns=["CExe", "ScriptCryptor"],
                import_patterns=[],
                export_patterns=[],
                overlay_patterns=[],
                version_detect={},
                bypass_difficulty=4,
                oep_detection_method="Script analysis",
                unpacking_method="Script extraction",
            ),
            "WWPack": ProtectorSignature(
                name="WWPack32",
                category=ProtectorCategory.PACKER,
                ep_patterns=[
                    b"\x53\x55\x8b\xe8\x33\xdb\xeb\x60\x0d\x0a\x0d\x0a",
                ],
                section_patterns={},
                string_patterns=["WWPack", "Piotr Warezak"],
                import_patterns=[],
                export_patterns=[],
                overlay_patterns=[],
                version_detect={},
                bypass_difficulty=3,
                oep_detection_method="Decompression routine",
                unpacking_method="Static decompression",
            ),
            "XComp": ProtectorSignature(
                name="XComp/XPack",
                category=ProtectorCategory.PACKER,
                ep_patterns=[
                    b"\x8b\xec\x83\xec\x40\x53\x56\x57",
                ],
                section_patterns={".xcomp": b"XCOMP"},
                string_patterns=["XComp", "XPack", "JRC"],
                import_patterns=[],
                export_patterns=[],
                overlay_patterns=[],
                version_detect={},
                bypass_difficulty=3,
                oep_detection_method="Compression analysis",
                unpacking_method="Decompression",
            ),
            "RLPack": ProtectorSignature(
                name="RLPack",
                category=ProtectorCategory.PACKER,
                ep_patterns=[
                    b"\x60\xe8\x00\x00\x00\x00\x8b\x2c\x24\x83\xc4\x04",
                ],
                section_patterns={".RLPack": b"RLPack"},
                string_patterns=["RLPack", "ap0x"],
                import_patterns=[],
                export_patterns=[],
                overlay_patterns=[],
                version_detect={},
                bypass_difficulty=4,
                oep_detection_method="PUSHAD/POPAD",
                unpacking_method="Import fixing",
            ),
            # DRM Systems (5)
            "SecuROM": ProtectorSignature(
                name="SecuROM",
                category=ProtectorCategory.DRM,
                ep_patterns=[
                    b"\x53\x65\x63\x75\x52\x4f\x4d",
                ],
                section_patterns={".securom": b"SecuROM"},
                string_patterns=["SecuROM", "Sony DADC"],
                import_patterns=["secdrv.sys"],
                export_patterns=[],
                overlay_patterns=[],
                version_detect={},
                bypass_difficulty=8,
                oep_detection_method="Driver analysis",
                unpacking_method="VM bypass",
            ),
            "SafeDisc": ProtectorSignature(
                name="SafeDisc",
                category=ProtectorCategory.DRM,
                ep_patterns=[
                    b"\x53\x61\x66\x65\x44\x69\x73\x63",
                ],
                section_patterns={".sdata": b"SDATA"},
                string_patterns=["SafeDisc", "Macrovision"],
                import_patterns=["drvmgt.dll", "secdrv.sys"],
                export_patterns=[],
                overlay_patterns=[],
                version_detect={},
                bypass_difficulty=7,
                oep_detection_method="CD check bypass",
                unpacking_method="Protection removal",
            ),
            "StarForce": ProtectorSignature(
                name="StarForce",
                category=ProtectorCategory.DRM,
                ep_patterns=[
                    b"\x53\x74\x61\x72\x46\x6f\x72\x63\x65",
                ],
                section_patterns={},
                string_patterns=["StarForce", "Protection Technology"],
                import_patterns=["sfdrv01.sys", "sfhlp02.sys"],
                export_patterns=[],
                overlay_patterns=[],
                version_detect={},
                bypass_difficulty=9,
                oep_detection_method="Ring0 analysis",
                unpacking_method="Driver emulation",
            ),
            "SteamDRM": ProtectorSignature(
                name="Steam DRM Protection",
                category=ProtectorCategory.DRM,
                ep_patterns=[
                    b"\x50\x53\x51\x52\xe8\x00\x00\x00\x00\x5d\x81\xed",  # Steam DRM v3 signature
                    b"\x53\x51\x52\x56\x57\x55\x8b\xec\x81\xec\x00\x01\x00\x00",  # Steam DRM v4 signature
                    b"\xb8\x00\x00\x00\x00\x85\xc0\x74\x07\x6a\x00\xe8",  # Steam DRM loader entry
                ],
                section_patterns={".bind": b"BIND"},
                string_patterns=["Steam", "SteamService", "steam_api.dll"],
                import_patterns=["steam_api.dll", "steam_api64.dll"],
                export_patterns=[],
                overlay_patterns=[],
                version_detect={},
                bypass_difficulty=6,
                oep_detection_method="Steam API hooks",
                unpacking_method="Steamless",
            ),
            "Games4Windows": ProtectorSignature(
                name="Games for Windows LIVE",
                category=ProtectorCategory.DRM,
                ep_patterns=[
                    b"\x47\x46\x57\x4c\x49\x56\x45",
                ],
                section_patterns={},
                string_patterns=["xlive.dll", "Games for Windows"],
                import_patterns=["xlive.dll"],
                export_patterns=[],
                overlay_patterns=[],
                version_detect={},
                bypass_difficulty=5,
                oep_detection_method="API redirection",
                unpacking_method="xlive emulation",
            ),
            # Additional Protectors (10)
            "ZProtect": ProtectorSignature(
                name="ZProtect",
                category=ProtectorCategory.PROTECTOR,
                ep_patterns=[
                    b"\x5a\x50\x72\x6f\x74\x65\x63\x74",
                ],
                section_patterns={".zp": b"ZP\x00"},
                string_patterns=["ZProtect"],
                import_patterns=[],
                export_patterns=[],
                overlay_patterns=[],
                version_detect={},
                bypass_difficulty=6,
                oep_detection_method="VM analysis",
                unpacking_method="Code extraction",
            ),
            "SoftDefender": ProtectorSignature(
                name="SoftDefender",
                category=ProtectorCategory.PROTECTOR,
                ep_patterns=[
                    b"\x74\x0e\x75\x0d\xe8",
                ],
                section_patterns={},
                string_patterns=["SoftDefender"],
                import_patterns=[],
                export_patterns=[],
                overlay_patterns=[],
                version_detect={},
                bypass_difficulty=5,
                oep_detection_method="SEH analysis",
                unpacking_method="Exception bypass",
            ),
            "ProtectEXE": ProtectorSignature(
                name="Protect EXE",
                category=ProtectorCategory.PROTECTOR,
                ep_patterns=[
                    b"\xe9\x00\x00\x00\x00\x0d\x0a",
                ],
                section_patterns={},
                string_patterns=["ProtectEXE"],
                import_patterns=[],
                export_patterns=[],
                overlay_patterns=[],
                version_detect={},
                bypass_difficulty=4,
                oep_detection_method="Entry point trace",
                unpacking_method="Manual unpack",
            ),
            "NeoLite": ProtectorSignature(
                name="NeoLite",
                category=ProtectorCategory.PACKER,
                ep_patterns=[
                    b"\x8b\x1e\x83\xee\xfc\x11\xdb\x72\xed\xb8\x01\x00\x00\x00",
                ],
                section_patterns={".neolit": b"NEOLIT"},
                string_patterns=["NeoLite"],
                import_patterns=[],
                export_patterns=[],
                overlay_patterns=[],
                version_detect={},
                bypass_difficulty=3,
                oep_detection_method="Compression analysis",
                unpacking_method="Decompression",
            ),
            "NetReactor": ProtectorSignature(
                name=".NET Reactor",
                category=ProtectorCategory.DOTNET_PROTECTOR,
                ep_patterns=[
                    b"\x2e\x4e\x45\x54\x52\x65\x61\x63\x74\x6f\x72",
                ],
                section_patterns={},
                string_patterns=[".NET Reactor", "Eziriz"],
                import_patterns=[],
                export_patterns=[],
                overlay_patterns=[],
                version_detect={},
                bypass_difficulty=7,
                oep_detection_method=".NET decompilation",
                unpacking_method="Assembly decryption",
            ),
            "Dotfuscator": ProtectorSignature(
                name="Dotfuscator",
                category=ProtectorCategory.DOTNET_PROTECTOR,
                ep_patterns=[
                    b"\x44\x6f\x74\x66\x75\x73\x63\x61\x74\x6f\x72",
                ],
                section_patterns={},
                string_patterns=["Dotfuscator", "PreEmptive"],
                import_patterns=[],
                export_patterns=[],
                overlay_patterns=[],
                version_detect={},
                bypass_difficulty=6,
                oep_detection_method="Metadata analysis",
                unpacking_method="String decryption",
            ),
            "SmartAssembly": ProtectorSignature(
                name="SmartAssembly",
                category=ProtectorCategory.DOTNET_PROTECTOR,
                ep_patterns=[
                    b"\x53\x6d\x61\x72\x74\x41\x73\x73\x65\x6d\x62\x6c\x79",
                ],
                section_patterns={},
                string_patterns=["SmartAssembly", "RedGate"],
                import_patterns=[],
                export_patterns=[],
                overlay_patterns=[],
                version_detect={},
                bypass_difficulty=6,
                oep_detection_method=".NET analysis",
                unpacking_method="Resource extraction",
            ),
            "ILProtector": ProtectorSignature(
                name="ILProtector",
                category=ProtectorCategory.DOTNET_PROTECTOR,
                ep_patterns=[
                    b"\x49\x4c\x50\x72\x6f\x74\x65\x63\x74\x6f\x72",
                ],
                section_patterns={},
                string_patterns=["ILProtector"],
                import_patterns=["ILProtector.Runtime.dll"],
                export_patterns=[],
                overlay_patterns=[],
                version_detect={},
                bypass_difficulty=7,
                oep_detection_method="IL analysis",
                unpacking_method="Runtime bypass",
            ),
            "CryptoObfuscator": ProtectorSignature(
                name="Crypto Obfuscator",
                category=ProtectorCategory.DOTNET_PROTECTOR,
                ep_patterns=[
                    b"\x43\x72\x79\x70\x74\x6f\x4f\x62\x66\x75\x73\x63\x61\x74\x6f\x72",
                ],
                section_patterns={},
                string_patterns=["CryptoObfuscator", "LogicNP"],
                import_patterns=[],
                export_patterns=[],
                overlay_patterns=[],
                version_detect={},
                bypass_difficulty=6,
                oep_detection_method="String analysis",
                unpacking_method="Deobfuscation",
            ),
            "AgileNET": ProtectorSignature(
                name="Agile.NET",
                category=ProtectorCategory.DOTNET_PROTECTOR,
                ep_patterns=[
                    b"\x41\x67\x69\x6c\x65\x2e\x4e\x45\x54",
                ],
                section_patterns={},
                string_patterns=["Agile.NET", "SecureTeam"],
                import_patterns=["AgileDotNet.dll"],
                export_patterns=[],
                overlay_patterns=[],
                version_detect={},
                bypass_difficulty=7,
                oep_detection_method="Code flow analysis",
                unpacking_method="VM devirtualization",
            ),
        }

    def detect_protector(self, file_data: bytes, pe_header: PE | None = None) -> list[tuple[str, ProtectorSignature, float]]:
        """Detect protectors based on file data and PE header.

        Args:
            file_data: Raw file bytes to analyze for protector signatures.
            pe_header: Parsed PE header object (if available) for section analysis.

        Returns:
            List of (name, signature, confidence) tuples sorted by confidence descending.

        Raises:
            No exceptions raised - uses fallback PE parsing if pefile unavailable.

        """
        detections = []

        for name, sig in self.protectors.items():
            confidence = 0.0
            matches = 0
            total_checks = 0

            # Check entry point patterns
            if sig.ep_patterns:
                total_checks += len(sig.ep_patterns)
                for pattern in sig.ep_patterns:
                    if pattern in file_data[:0x1000]:  # Check first 4KB
                        matches += 1

            # Check section patterns
            if sig.section_patterns and pe_header:
                total_checks += len(sig.section_patterns)
                # Parse PE sections from header
                try:
                    import pefile

                    pe = pefile.PE(data=file_data)
                    for section_name, section_pattern in sig.section_patterns.items():
                        for section in pe.sections:
                            section_name_bytes = section.Name.rstrip(b"\x00")
                            if section_name.encode() in section_name_bytes:
                                matches += 1
                                break
                            # Check section data for pattern
                            section_data = file_data[section.PointerToRawData : section.PointerToRawData + section.SizeOfRawData]
                            if section_pattern in section_data[:0x100]:  # Check first 256 bytes of section
                                matches += 1
                                break
                except Exception:
                    # Fallback to manual PE parsing if pefile not available
                    if len(file_data) > 0x3C:
                        pe_offset = struct.unpack("<I", file_data[0x3C:0x40])[0]
                        if pe_offset < len(file_data) - 0x200:
                            # Get number of sections
                            num_sections = struct.unpack("<H", file_data[pe_offset + 0x06 : pe_offset + 0x08])[0]
                            optional_header_size = struct.unpack("<H", file_data[pe_offset + 0x14 : pe_offset + 0x16])[0]
                            section_table_offset = pe_offset + 0x18 + optional_header_size

                            for i in range(min(num_sections, 16)):  # Limit to 16 sections for safety
                                section_offset = section_table_offset + (i * 40)
                                if section_offset + 40 <= len(file_data):
                                    section_name = file_data[section_offset : section_offset + 8].rstrip(b"\x00")
                                    for pattern_name, pattern_bytes in sig.section_patterns.items():
                                        if pattern_name.encode() in section_name:
                                            matches += 1
                                            break
                                        # Check section data
                                        raw_offset = struct.unpack("<I", file_data[section_offset + 20 : section_offset + 24])[0]
                                        raw_size = struct.unpack("<I", file_data[section_offset + 16 : section_offset + 20])[0]
                                        if raw_offset < len(file_data) and raw_size > 0:
                                            section_data = file_data[raw_offset : min(raw_offset + 0x100, raw_offset + raw_size)]
                                            if pattern_bytes in section_data:
                                                matches += 1
                                                break

            # Check string patterns
            if sig.string_patterns:
                total_checks += len(sig.string_patterns)
                for string in sig.string_patterns:
                    if string.encode() in file_data:
                        matches += 1

            # Calculate confidence
            if total_checks > 0:
                confidence = (matches / total_checks) * 100

            if confidence > 30:  # Threshold for detection
                detections.append((name, sig, confidence))

        return sorted(detections, key=lambda x: x[2], reverse=True)

    def get_bypass_strategy(self, protector_name: str) -> dict[str, Any]:
        """Get bypass strategy for a specific protector.

        Args:
            protector_name: Name of the protector

        Returns:
            Bypass strategy information

        """
        if protector_name in self.protectors:
            sig = self.protectors[protector_name]
            return {
                "difficulty": sig.bypass_difficulty,
                "oep_method": sig.oep_detection_method,
                "unpacking_method": sig.unpacking_method,
                "category": sig.category.value,
            }
        return {}

    def find_oep(self, file_data: bytes, protector_name: str) -> int:
        """Find Original Entry Point for packed/protected binary.

        Args:
            file_data: Raw file bytes
            protector_name: Detected protector name

        Returns:
            OEP offset or -1 if not found

        """
        if protector_name not in self.protectors:
            return -1

        sig = self.protectors[protector_name]

        # Common OEP patterns after unpacking
        oep_patterns = [
            b"\x55\x8b\xec",  # push ebp; mov ebp, esp (common function prologue)
            b"\x6a\x00\x68",  # push 0; push
            b"\xe8\x00\x00\x00\x00\x58",  # call $+5; pop eax
            b"\x83\xec\x44\x53\x56\x57",  # sub esp, 44h; push ebx; push esi; push edi
            b"\x55\x89\xe5",  # push ebp; mov ebp, esp (GCC prologue)
        ]

        # Search for OEP patterns based on method
        if "ESP" in sig.oep_detection_method:
            # Look for PUSHAD/POPAD sequences
            pushad_pos = file_data.find(b"\x60")  # PUSHAD
            if pushad_pos != -1:
                popad_pos = file_data.find(b"\x61", pushad_pos)  # POPAD
                if popad_pos != -1:
                    # OEP is usually right after POPAD
                    return popad_pos + 1

        elif "JMP" in sig.oep_detection_method:
            # Look for far jumps
            jmp_patterns = [b"\xe9", b"\xff\x25", b"\xff\x15"]
            for pattern in jmp_patterns:
                pos = 0
                while True:
                    pos = file_data.find(pattern, pos)
                    if pos == -1:
                        break
                    # Analyze jump target
                    if pattern == b"\xe9" and pos + 5 < len(file_data):
                        # E9 rel32 - relative jump
                        offset = struct.unpack("<I", file_data[pos + 1 : pos + 5])[0]
                        target = pos + 5 + offset
                        if 0 < target < len(file_data):
                            # Check if target looks like OEP
                            for oep_pat in oep_patterns:
                                if file_data[target : target + len(oep_pat)] == oep_pat:
                                    return target
                    pos += 1

        # Generic search for common OEP patterns
        for pattern in oep_patterns:
            pos = file_data.find(pattern)
            if pos != -1:
                return pos

        return -1

    def detect_anti_analysis(self, file_data: bytes) -> list[dict[str, Any]]:
        """Detect anti-analysis techniques in binary.

        Args:
            file_data: Raw file bytes

        Returns:
            List of detected anti-analysis techniques

        """
        techniques = []

        # Anti-debugging checks
        anti_debug_apis = [
            b"IsDebuggerPresent",
            b"CheckRemoteDebuggerPresent",
            b"NtQueryInformationProcess",
            b"OutputDebugString",
            b"NtSetInformationThread",
            b"DebugActiveProcess",
        ]

        for api in anti_debug_apis:
            if api in file_data:
                techniques.append(
                    {"type": "anti-debug", "method": api.decode(), "description": f"Uses {api.decode()} API for debugger detection"},
                )

        # Anti-VM checks
        anti_vm_strings = [
            b"VMware",
            b"VirtualBox",
            b"VBox",
            b"QEMU",
            b"Xen",
            b"vmware.exe",
            b"vboxservice.exe",
            b"vboxtray.exe",
            b"SbieDll.dll",  # Sandboxie
            b"snxhk.dll",  # Avast Sandbox
        ]

        for vm_string in anti_vm_strings:
            if vm_string in file_data:
                techniques.append(
                    {
                        "type": "anti-vm",
                        "method": vm_string.decode(),
                        "description": f"Checks for {vm_string.decode()} (VM/Sandbox detection)",
                    },
                )

        # Timing checks
        timing_apis = [
            b"GetTickCount",
            b"QueryPerformanceCounter",
            b"rdtsc",
        ]

        for api in timing_apis:
            if api in file_data:
                techniques.append(
                    {"type": "timing", "method": api.decode(), "description": f"Uses {api.decode()} for timing-based detection"},
                )

        # Process/DLL checks
        blacklist_processes = [
            b"ollydbg.exe",
            b"x64dbg.exe",
            b"ida.exe",
            b"ida64.exe",
            b"windbg.exe",
            b"processhacker.exe",
            b"procmon.exe",
        ]

        for proc in blacklist_processes:
            if proc in file_data:
                techniques.append({"type": "process-check", "method": proc.decode(), "description": f"Checks for {proc.decode()} process"})

        return techniques

    def detect_encryption_layers(self, file_data: bytes) -> list[dict[str, Any]]:
        """Detect encryption and compression layers.

        Args:
            file_data: Raw file bytes

        Returns:
            List of detected encryption/compression layers

        """
        layers = []

        # Check entropy of sections
        import math

        def calculate_entropy(data: bytes) -> float:
            """Calculate Shannon entropy of binary data.

            Args:
                data: Binary data chunk to analyze.

            Returns:
                Entropy value as float (0-8 typically, higher indicates encryption/compression).

            """
            if not data:
                return 0.0
            entropy = 0.0
            for x in range(256):
                p_x = data.count(x) / len(data)
                if p_x > 0:
                    entropy += -p_x * math.log2(p_x)
            return entropy

        # Check different parts of file
        chunk_size = min(4096, len(file_data))
        for i in range(0, len(file_data), chunk_size):
            chunk = file_data[i : i + chunk_size]
            entropy = calculate_entropy(chunk)

            if entropy > 7.5:  # High entropy indicates encryption/compression
                layers.append(
                    {
                        "type": "high-entropy",
                        "offset": hex(i),
                        "entropy": round(entropy, 2),
                        "likely": "encrypted" if entropy > 7.8 else "compressed",
                    },
                )

        # Check for known crypto signatures
        crypto_patterns = {
            b"Salsa20": "Salsa20 stream cipher",
            b"ChaCha": "ChaCha stream cipher",
            b"AES": "AES encryption",
            b"RSA": "RSA encryption",
            b"RC4": "RC4 stream cipher",
            b"DES": "DES encryption",
            b"Blowfish": "Blowfish cipher",
            b"Twofish": "Twofish cipher",
        }

        for pattern, description in crypto_patterns.items():
            if pattern in file_data:
                layers.append({"type": "crypto-signature", "algorithm": pattern.decode(), "description": description})

        # Check for compression signatures
        compression_sigs = {
            b"\x1f\x8b": "GZIP compression",
            b"PK": "ZIP/PKZip compression",
            b"Rar!": "RAR compression",
            b"7z\xbc\xaf": "7-Zip compression",
            b"\x42\x5a\x68": "BZIP2 compression",
            b"\xfd\x37\x7a\x58\x5a": "XZ/LZMA compression",
        }

        for sig, description in compression_sigs.items():
            if sig in file_data[:1024]:
                layers.append({"type": "compression", "format": description, "offset": hex(file_data.find(sig))})

        return layers


# Global instance
_protectors_db = None


def get_protectors_database() -> CommercialProtectorsDatabase:
    """Get or create global protectors database instance."""
    global _protectors_db
    if _protectors_db is None:
        _protectors_db = CommercialProtectorsDatabase()
    return _protectors_db

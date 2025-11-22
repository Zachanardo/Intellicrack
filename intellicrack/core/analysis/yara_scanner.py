"""YARA Rule Scanner - Production Implementation.

Copyright (C) 2025 Zachary Flint

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

from __future__ import annotations

import json
import logging
import os
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import TYPE_CHECKING, Any

import yara


if TYPE_CHECKING:
    from collections.abc import Callable

logger = logging.getLogger(__name__)


class RuleCategory(Enum):
    """Categories of YARA rules."""

    PACKER = "packer"
    PROTECTOR = "protector"
    CRYPTO = "crypto"
    LICENSE = "license"
    MALWARE = "malware"
    COMPILER = "compiler"
    ANTI_DEBUG = "anti_debug"
    ANTI_VM = "anti_vm"
    OBFUSCATION = "obfuscation"
    CUSTOM = "custom"


@dataclass
class YaraMatch:
    """Represents a YARA rule match."""

    rule_name: str
    category: RuleCategory
    offset: int
    matched_strings: list[tuple[int, str, bytes]]
    tags: list[str]
    meta: dict[str, Any]
    confidence: float


@dataclass
class ProtectionSignature:
    """Signature for a protection scheme."""

    name: str
    version: str | None
    category: str
    signatures: list[bytes]
    entry_point_pattern: bytes | None
    section_characteristics: dict[str, Any] | None
    imports: list[str] | None


class YaraScanner:
    """YARA-based signature scanner for binary analysis."""

    # Built-in protection signatures
    PROTECTION_SIGNATURES = {
        "VMProtect": ProtectionSignature(
            name="VMProtect",
            version=None,
            category="protector",
            signatures=[
                b"\x56\x4d\x50\x72\x6f\x74\x65\x63\x74",  # "VMProtect"
                b"\x2e\x76\x6d\x70\x30",  # ".vmp0"
                b"\x2e\x76\x6d\x70\x31",  # ".vmp1"
                b"\x2e\x76\x6d\x70\x32",  # ".vmp2"
            ],
            entry_point_pattern=b"\x68\x00\x00\x00\x00\xe8",
            section_characteristics={"name": ".vmp", "flags": 0xE0000020},
            imports=None,
        ),
        "Themida": ProtectionSignature(
            name="Themida",
            version=None,
            category="protector",
            signatures=[
                b"\x54\x68\x65\x6d\x69\x64\x61",  # "Themida"
                b"\x2e\x74\x68\x65\x6d\x69\x64\x61",  # ".themida"
                b"\xb8\x00\x00\x00\x00\x60\x0b\xc0\x74\x58",
            ],
            entry_point_pattern=b"\xb8\x00\x00\x00\x00\x60\x0b\xc0",
            section_characteristics=None,
            imports=["SecureEngineSDK.dll"],
        ),
        "ASProtect": ProtectionSignature(
            name="ASProtect",
            version=None,
            category="protector",
            signatures=[
                b"\x41\x53\x50\x72\x6f\x74\x65\x63\x74",  # "ASProtect"
                b"\x2e\x61\x73\x70\x72",  # ".aspr"
                b"\x60\xe8\x03\x00\x00\x00\xe9\xeb\x04",
            ],
            entry_point_pattern=b"\x60\xe8\x03\x00\x00\x00",
            section_characteristics={"name": ".aspack", "flags": 0xE0000020},
            imports=None,
        ),
        "Denuvo": ProtectionSignature(
            name="Denuvo",
            version=None,
            category="protector",
            signatures=[
                b"\x44\x65\x6e\x75\x76\x6f",  # "Denuvo"
                b"\x2e\x64\x65\x6e\x75",  # ".denu"
                b"\x48\x8d\x05\x00\x00\x00\x00\x48\x89\x45",
            ],
            entry_point_pattern=None,
            section_characteristics=None,
            imports=["denuvo32.dll", "denuvo64.dll"],
        ),
        "UPX": ProtectionSignature(
            name="UPX",
            version=None,
            category="packer",
            signatures=[
                b"\x55\x50\x58\x21",  # "UPX!"
                b"\x55\x50\x58\x30",  # "UPX0"
                b"\x55\x50\x58\x31",  # "UPX1"
                b"\x55\x50\x58\x32",  # "UPX2"
            ],
            entry_point_pattern=b"\x60\xbe\x00\x00\x00\x00\x8d\xbe",
            section_characteristics={"name": "UPX", "flags": 0xE0000080},
            imports=None,
        ),
    }

    def __init__(self, rules_dir: Path | None = None) -> None:
        """Initialize YARA scanner.

        Args:
            rules_dir: Directory containing YARA rule files

        """
        import threading

        self.rules_dir = rules_dir or Path(__file__).parent / "yara_rules"
        self.compiled_rules: dict[RuleCategory, yara.Rules] = {}
        self.custom_rules: dict[str, yara.Rules] = {}

        # Initialize thread-safe components
        self._matches: list[YaraMatch] = []
        self._match_lock = threading.Lock()
        self._scan_progress_lock = threading.Lock()
        self._scan_progress: dict[str, Any] = {
            "status": "idle",
            "scanned": 0,
            "total": 0,
            "matches": 0,
            "current_region": None,
        }

        # Initialize rule categories
        self._rule_categories: dict[str, RuleCategory] = {}

        # Initialize execution log with max size limit
        self._execution_log: list[dict[str, Any]] = []
        self._execution_log_max_size = 10000  # Max entries before rotation
        self._execution_log_lock = threading.Lock()

        self._load_builtin_rules()
        if self.rules_dir.exists():
            self._load_custom_rules()

    def _load_builtin_rules(self) -> None:
        """Load built-in YARA rules."""
        # Create built-in rules for each category
        builtin_rules = {
            RuleCategory.PACKER: self._create_packer_rules(),
            RuleCategory.PROTECTOR: self._create_protector_rules(),
            RuleCategory.CRYPTO: self._create_crypto_rules(),
            RuleCategory.LICENSE: self._create_license_rules(),
            RuleCategory.ANTI_DEBUG: self._create_antidebug_rules(),
            RuleCategory.COMPILER: self._create_compiler_rules(),
        }

        for category, rule_source in builtin_rules.items():
            try:
                self.compiled_rules[category] = yara.compile(source=rule_source)
                logger.info(f"Loaded built-in rules for {category.value}")
            except Exception as e:
                logger.error(f"Failed to compile {category.value} rules: {e}")

    def _create_packer_rules(self) -> str:
        """Create YARA rules for packer detection."""
        return """
rule UPX_Packer {
    meta:
        description = "Detects UPX packed executables"
        category = "packer"
        confidence = 90
    strings:
        $upx1 = "UPX!"
        $upx2 = "UPX0"
        $upx3 = "UPX1"
        $upx4 = "UPX2"
        $ep1 = { 60 BE ?? ?? ?? ?? 8D BE ?? ?? ?? ?? }
        $ep2 = { 80 7C 24 08 01 0F 85 ?? ?? ?? ?? 60 BE }
    condition:
        uint16(0) == 0x5A4D and
        (any of ($upx*) or any of ($ep*))
}

rule ASPack_Packer {
    meta:
        description = "Detects ASPack packed executables"
        category = "packer"
        confidence = 85
    strings:
        $aspack1 = "ASPack"
        $aspack2 = ".aspack"
        $ep = { 60 E8 ?? ?? ?? ?? 5D 81 ED ?? ?? ?? ?? }
    condition:
        uint16(0) == 0x5A4D and
        (any of ($aspack*) or $ep)
}

rule PECompact_Packer {
    meta:
        description = "Detects PECompact packed executables"
        category = "packer"
        confidence = 85
    strings:
        $pec1 = "PECompact"
        $pec2 = "PEC2"
        $ep = { B8 ?? ?? ?? ?? 50 64 FF 35 00 00 00 00 }
    condition:
        uint16(0) == 0x5A4D and
        (any of ($pec*) or $ep)
}
"""

    def _create_protector_rules(self) -> str:
        """Create YARA rules for protector detection."""
        return """
rule VMProtect_Protector {
    meta:
        description = "Detects VMProtect protected executables"
        category = "protector"
        confidence = 95
    strings:
        $vmp1 = "VMProtect"
        $vmp2 = ".vmp0"
        $vmp3 = ".vmp1"
        $vmp4 = ".vmp2"
        $ep = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? }
        $sig = { 9C 60 68 00 00 00 00 8B 74 24 28 }
    condition:
        uint16(0) == 0x5A4D and
        (2 of ($vmp*) or ($ep and $sig))
}

rule Themida_Protector {
    meta:
        description = "Detects Themida protected executables"
        category = "protector"
        confidence = 95
    strings:
        $themida1 = "Themida"
        $themida2 = ".themida"
        $themida3 = "SecureEngineSDK.dll"
        $ep = { B8 00 00 00 00 60 0B C0 74 58 }
        $sig = { 8B C5 8B D4 60 E8 00 00 00 00 }
    condition:
        uint16(0) == 0x5A4D and
        (any of ($themida*) or $ep or $sig)
}

rule Denuvo_Protector {
    meta:
        description = "Detects Denuvo protected executables"
        category = "protector"
        confidence = 90
    strings:
        $denuvo1 = "Denuvo"
        $denuvo2 = "denuvo32.dll"
        $denuvo3 = "denuvo64.dll"
        $sig1 = { 48 8D 05 ?? ?? ?? ?? 48 89 45 }
        $sig2 = { 48 89 5C 24 08 48 89 74 24 10 }
    condition:
        uint16(0) == 0x5A4D and
        (any of ($denuvo*) or all of ($sig*))
}

rule ASProtect_Protector {
    meta:
        description = "Detects ASProtect protected executables"
        category = "protector"
        confidence = 90
    strings:
        $asp1 = "ASProtect"
        $asp2 = ".aspr"
        $asp3 = ".adata"
        $ep = { 60 E8 03 00 00 00 E9 EB 04 }
        $sig = { 68 01 ?? ?? ?? C3 AA }
    condition:
        uint16(0) == 0x5A4D and
        (2 of ($asp*) or $ep or $sig)
}
"""

    def _create_crypto_rules(self) -> str:
        """Create YARA rules for cryptographic algorithm detection."""
        return """
rule AES_Constants {
    meta:
        description = "Detects AES encryption constants"
        category = "crypto"
        confidence = 85
    strings:
        $sbox = { 63 7C 77 7B F2 6B 6F C5 30 01 67 2B FE D7 AB 76 }
        $rcon = { 01 00 00 00 02 00 00 00 04 00 00 00 08 00 00 00 }
        $td0 = { A5 63 63 C6 84 7C 7C F8 }
    condition:
        any of them
}

rule RSA_Operations {
    meta:
        description = "Detects RSA cryptographic operations"
        category = "crypto"
        confidence = 80
    strings:
        $bignum1 = "BN_mod_exp"
        $bignum2 = "BN_mod_mul"
        $rsa1 = "RSA_public_encrypt"
        $rsa2 = "RSA_private_decrypt"
        $padding = { 00 01 FF FF FF FF FF FF }
    condition:
        2 of them
}

rule SHA256_Constants {
    meta:
        description = "Detects SHA-256 hash constants"
        category = "crypto"
        confidence = 85
    strings:
        $k1 = { 67 E6 09 6A 85 AE 67 BB 72 F3 6E 3C 3A F5 4F A5 }
        $h1 = { 6A 09 E6 67 BB 67 AE 85 3C 6E F3 72 A5 4F F5 3A }
        $init = { 67 45 23 01 EF CD AB 89 98 BA DC FE 10 32 54 76 }
    condition:
        any of them
}

rule MD5_Constants {
    meta:
        description = "Detects MD5 hash constants"
        category = "crypto"
        confidence = 85
    strings:
        $init = { 01 23 45 67 89 AB CD EF FE DC BA 98 76 54 32 10 }
        $sin1 = { 78 A4 6A D7 56 B7 C7 E8 }
        $sin2 = { DB 70 20 24 EE CE BD C1 }
    condition:
        any of them
}
"""

    def _create_license_rules(self) -> str:
        """Create YARA rules for license validation detection."""
        return """
rule License_Check_Patterns {
    meta:
        description = "Detects license validation routines"
        category = "license"
        confidence = 75
    strings:
        $lic1 = "Invalid license" nocase
        $lic2 = "License expired" nocase
        $lic3 = "Trial period" nocase
        $lic4 = "Product key" nocase
        $lic5 = "Serial number" nocase
        $lic6 = "Activation code" nocase
        $check1 = "CheckLicense"
        $check2 = "ValidateLicense"
        $check3 = "VerifyLicense"
    condition:
        2 of them
}

rule Serial_Number_Validation {
    meta:
        description = "Detects serial number validation patterns"
        category = "license"
        confidence = 85
    strings:
        // Common serial formats
        $serial1 = /[A-Z0-9]{4}-[A-Z0-9]{4}-[A-Z0-9]{4}-[A-Z0-9]{4}/
        $serial2 = /\\d{4}-\\d{4}-\\d{4}-\\d{4}/
        $serial3 = /[A-F0-9]{8}-[A-F0-9]{8}/

        // Validation functions
        $func1 = "ValidateSerial"
        $func2 = "CheckSerialNumber"
        $func3 = "VerifyProductKey"
        $func4 = "IsValidLicense"

        // Common checks
        $check1 = { 83 F8 10 }  // CMP EAX, 16 (length check)
        $check2 = { 83 F8 14 }  // CMP EAX, 20
        $check3 = { 83 F8 18 }  // CMP EAX, 24

        // Checksum validation
        $crc1 = { 81 F1 ?? ?? ?? ?? }  // XOR ECX, IMMED (CRC)
        $crc2 = { C1 C0 0D }  // ROL EAX, 13 (common in serial algos)

    condition:
        (any of ($serial*) and any of ($func*)) or
        (2 of ($check*) and any of ($crc*))
}

rule Trial_Expiration_Check {
    meta:
        description = "Detects trial expiration checking mechanisms"
        category = "license"
        confidence = 88
    strings:
        // Time strings
        $time1 = "trial expired" nocase
        $time2 = "days remaining" nocase
        $time3 = "evaluation period" nocase
        $time4 = "trial version" nocase
        $time5 = "%d days left"

        // Date/Time APIs
        $api1 = "GetSystemTime"
        $api2 = "GetLocalTime"
        $api3 = "SystemTimeToFileTime"
        $api4 = "CompareFileTime"
        $api5 = "GetTickCount"

        // Registry keys for trial tracking
        $reg1 = "SOFTWARE\\Trial"
        $reg2 = "InstallDate"
        $reg3 = "FirstRun"
        $reg4 = "TrialDays"

        // Time comparison patterns
        $cmp1 = { 3D ?? ?? ?? ?? 7? }  // CMP EAX, time; Jcc
        $cmp2 = { 81 3D ?? ?? ?? ?? ?? ?? ?? ?? 7? }  // CMP [mem], time; Jcc

        // 30-day trial check (2592000 seconds)
        $trial30 = { 00 7F 27 00 }  // 2592000 in little-endian
        $trial14 = { 80 2D 12 00 }  // 1209600 (14 days)
        $trial7  = { C0 54 06 00 }  // 604800 (7 days)

    condition:
        (2 of ($time*) and 2 of ($api*)) or
        (any of ($reg*) and any of ($cmp*)) or
        any of ($trial*)
}

rule Hardware_ID_Check {
    meta:
        description = "Detects hardware ID based licensing"
        category = "license"
        confidence = 82
    strings:
        // Hardware queries
        $hw1 = "GetVolumeInformation"
        $hw2 = "GetSystemInfo"
        $hw3 = "GetComputerName"
        $hw4 = "GetAdaptersInfo"
        $hw5 = "DeviceIoControl"

        // WMI queries for hardware
        $wmi1 = "Win32_Processor"
        $wmi2 = "Win32_BaseBoard"
        $wmi3 = "Win32_BIOS"
        $wmi4 = "Win32_DiskDrive"
        $wmi5 = "Win32_NetworkAdapter"

        // CPUID instruction
        $cpuid = { 0F A2 }  // CPUID

        // MAC address patterns
        $mac1 = { 00 [1] ?? ?? ?? ?? }  // MAC OUI pattern
        $mac2 = "PhysicalAddress"

        // Disk serial
        $disk1 = "IOCTL_STORAGE_QUERY_PROPERTY"
        $disk2 = { 2C EC 00 00 }  // IOCTL code

        // Machine GUID
        $guid1 = "MachineGuid"
        $guid2 = "SOFTWARE\\Microsoft\\Cryptography"

    condition:
        (3 of ($hw*) or 2 of ($wmi*)) or
        ($cpuid and any of ($mac*)) or
        (any of ($disk*) and any of ($guid*))
}

rule Activation_Server_Communication {
    meta:
        description = "Detects online activation server patterns"
        category = "license"
        confidence = 80
    strings:
        // URLs and endpoints
        $url1 = /https?:\\/\\/[^\\s]*\\/activate/
        $url2 = /https?:\\/\\/[^\\s]*\\/license/
        $url3 = /https?:\\/\\/[^\\s]*\\/validate/
        $url4 = /https?:\\/\\/[^\\s]*\\/auth/

        // API endpoints
        $api1 = "/api/activate"
        $api2 = "/api/verify"
        $api3 = "/licensing/check"
        $api4 = "/product/register"

        // HTTP methods
        $http1 = "POST /activate"
        $http2 = "GET /license"
        $http3 = "Content-Type: application/json"

        // Activation strings
        $act1 = "ActivationCode"
        $act2 = "ProductActivation"
        $act3 = "OnlineActivation"
        $act4 = "ActivationResponse"

        // Network APIs
        $net1 = "InternetConnect"
        $net2 = "HttpSendRequest"
        $net3 = "WinHttpOpen"
        $net4 = "URLDownloadToFile"

    condition:
        (any of ($url*) and any of ($act*)) or
        (2 of ($api*) and any of ($net*)) or
        (any of ($http*) and 2 of ($act*))
}

rule License_File_Patterns {
    meta:
        description = "Detects license file operations"
        category = "license"
        confidence = 85
    strings:
        // License file extensions
        $ext1 = ".lic" nocase
        $ext2 = ".license" nocase
        $ext3 = ".key" nocase
        $ext4 = ".dat" nocase
        $ext5 = ".reg" nocase

        // License file paths
        $path1 = "license.dat"
        $path2 = "license.key"
        $path3 = "product.lic"
        $path4 = "registration.key"

        // XML license tags
        $xml1 = "<License>"
        $xml2 = "<ProductKey>"
        $xml3 = "<ExpirationDate>"
        $xml4 = "<SerialNumber>"

        // JSON license fields
        $json1 = "\"license\":"
        $json2 = "\"serial\":"
        $json3 = "\"expiry\":"
        $json4 = "\"product_key\":"

        // File operations
        $file1 = "ReadLicenseFile"
        $file2 = "WriteLicenseFile"
        $file3 = "ValidateLicenseFile"

    condition:
        (2 of ($ext*) or 2 of ($path*)) or
        (2 of ($xml*) or 2 of ($json*)) or
        any of ($file*)
}

rule Registration_Key_Algorithm {
    meta:
        description = "Detects registration key generation/validation algorithms"
        category = "license"
        confidence = 87
    strings:
        // Common key generation patterns
        $keygen1 = { 69 ?? ?? ?? ?? ?? }  // IMUL reg, CONSTANT (key gen)
        $keygen2 = { C1 ?? 05 }  // SHL/SHR by 5 (common in keygens)
        $keygen3 = { 81 F? ?? ?? ?? ?? }  // XOR with constant

        // Blacklist check
        $blacklist1 = "FCFFFFFF"  // Common blacklisted serial
        $blacklist2 = "00000000"
        $blacklist3 = "12345678"

        // Key validation loops
        $loop1 = { 8A ?? ?? 3C 2D 74 ?? }  // Check for hyphen
        $loop2 = { 80 3? 2D 75 ?? }  // CMP byte, '-'

        // Base encoding
        $b64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
        $b32 = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"

        // Key format strings
        $fmt1 = "%04X-%04X-%04X-%04X"
        $fmt2 = "%08X-%08X"
        $fmt3 = "%s-%s-%s-%s"

    condition:
        (2 of ($keygen*) and any of ($loop*)) or
        (any of ($blacklist*) and any of ($fmt*)) or
        (any of ($b64, $b32) and 2 of ($keygen*))
}

rule Crypto_Signature_Validation {
    meta:
        description = "Detects cryptographic signature validation in licensing"
        category = "license"
        confidence = 90
    strings:
        // RSA operations
        $rsa1 = "RSA_public_decrypt"
        $rsa2 = "RSA_verify"
        $rsa3 = "RSA_public_key"
        $rsa4 = { 00 01 00 01 }  // RSA exponent 65537

        // ECDSA
        $ecc1 = "ECDSA_verify"
        $ecc2 = "EC_KEY_new"
        $ecc3 = "EC_POINT_"

        // Hash functions for signing
        $hash1 = "SHA256_Init"
        $hash2 = "SHA1_Update"
        $hash3 = "MD5_Final"

        // Public key embedded
        $pubkey1 = "-----BEGIN PUBLIC KEY-----"
        $pubkey2 = "-----BEGIN RSA PUBLIC KEY-----"
        $pubkey3 = { 30 82 ?? ?? 30 }  // ASN.1 public key structure

        // Signature verification
        $verify1 = "VerifySignature"
        $verify2 = "ValidateSignature"
        $verify3 = "CheckSignature"

        // Windows CryptoAPI
        $capi1 = "CryptVerifySignature"
        $capi2 = "CryptImportPublicKeyInfo"
        $capi3 = "CryptHashData"

    condition:
        (any of ($rsa*) or any of ($ecc*)) and
        (any of ($hash*) or any of ($verify*)) or
        (any of ($pubkey*) and any of ($capi*))
}

rule FlexLM_License {
    meta:
        description = "Detects FlexLM license manager"
        category = "license"
        confidence = 90
    strings:
        $flex1 = "FLEXlm"
        $flex2 = "lmgrd"
        $flex3 = "FLEXLM_DIAGNOSTICS"
        $flex4 = "vendor daemon"
        $api1 = "lc_checkout"
        $api2 = "lc_checkin"
        $api3 = "lc_cryptstr"
        $api4 = "lc_init"
        $api5 = "lc_get_attr"
    condition:
        3 of them
}

rule Sentinel_HASP {
    meta:
        description = "Detects Sentinel HASP license protection"
        category = "license"
        confidence = 90
    strings:
        $hasp1 = "hasp_login"
        $hasp2 = "hasp_logout"
        $hasp3 = "hasp_encrypt"
        $hasp4 = "HASP HL"
        $hasp5 = "Sentinel HASP"
        $hasp6 = "hasp_get_sessioninfo"
        $hasp7 = "hasp_update"
    condition:
        3 of them
}

rule CodeMeter_License {
    meta:
        description = "Detects CodeMeter license protection"
        category = "license"
        confidence = 90
    strings:
        $cm1 = "CodeMeter"
        $cm2 = "CmStick"
        $cm3 = "WibuCm"
        $cm4 = "CmActLicense"
        $api1 = "CmGetLicenseInfo"
        $api2 = "CmCheckLicense"
        $api3 = "CmGetBoxes"
        $api4 = "CmAccess"
    condition:
        3 of them
}

rule iLok_License {
    meta:
        description = "Detects iLok license protection"
        category = "license"
        confidence = 88
    strings:
        $ilok1 = "iLok"
        $ilok2 = "PACE Anti-Piracy"
        $ilok3 = "eden.sys"
        $ilok4 = "iLokClientLib"
        $api1 = "iLokGetLicense"
        $api2 = "iLokAuthorize"
    condition:
        2 of them
}

rule SafeNet_Sentinel {
    meta:
        description = "Detects SafeNet Sentinel protection"
        category = "license"
        confidence = 87
    strings:
        $sn1 = "Sentinel SuperPro"
        $sn2 = "Rainbow Technologies"
        $sn3 = "spnsrvnt.exe"
        $sn4 = "rnbosent.dll"
        $api1 = "RNBOsproFindFirstUnit"
        $api2 = "RNBOsproRead"
    condition:
        2 of them
}
"""

    def _create_antidebug_rules(self) -> str:
        """Create YARA rules for anti-debugging detection."""
        return """
rule AntiDebug_IsDebuggerPresent {
    meta:
        description = "Detects IsDebuggerPresent anti-debug"
        category = "anti_debug"
        confidence = 95
    strings:
        $api1 = "IsDebuggerPresent"
        $api2 = "CheckRemoteDebuggerPresent"
        $api3 = "NtQueryInformationProcess"
        $peb = { 64 A1 30 00 00 00 0F B6 40 02 }
        $flag = { 64 8B 05 30 00 00 00 8B 40 68 }
    condition:
        any of them
}

rule AntiDebug_Timing {
    meta:
        description = "Detects timing-based anti-debug"
        category = "anti_debug"
        confidence = 80
    strings:
        $time1 = "GetTickCount"
        $time2 = "QueryPerformanceCounter"
        $time3 = "rdtsc"
        $cpuid = { 0F A2 }
        $rdtsc = { 0F 31 }
    condition:
        2 of them
}

rule AntiDebug_Exception {
    meta:
        description = "Detects exception-based anti-debug"
        category = "anti_debug"
        confidence = 85
    strings:
        $seh = "SetUnhandledExceptionFilter"
        $veh = "AddVectoredExceptionHandler"
        $int3 = { CC }
        $int2d = { CD 2D }
        $icebp = { F1 }
    condition:
        ($seh or $veh) and any of ($int*)
}
"""

    def _create_compiler_rules(self) -> str:
        """Create YARA rules for compiler detection."""
        return """
rule MSVC_Compiler {
    meta:
        description = "Detects Microsoft Visual C++ compiler"
        category = "compiler"
        confidence = 90
    strings:
        $msvc1 = "Microsoft Visual C++"
        $msvc2 = "MSVCR"
        $msvc3 = "MSVCP"
        $rich = "Rich"
    condition:
        uint16(0) == 0x5A4D and
        (2 of ($msvc*) or $rich)
}

rule GCC_Compiler {
    meta:
        description = "Detects GCC compiler"
        category = "compiler"
        confidence = 85
    strings:
        $gcc1 = "GCC:"
        $gcc2 = "GNU C"
        $gcc3 = "gcc version"
        $mingw = "MinGW"
    condition:
        any of them
}

rule Delphi_Compiler {
    meta:
        description = "Detects Delphi/Borland compiler"
        category = "compiler"
        confidence = 90
    strings:
        $delphi1 = "Borland"
        $delphi2 = "Delphi"
        $delphi3 = "CodeGear"
        $tls = { 00 00 00 00 00 00 00 00 00 00 00 00 34 ?? ?? ?? }
    condition:
        uint16(0) == 0x5A4D and
        (2 of ($delphi*) or $tls)
}
"""

    def _load_custom_rules(self) -> None:
        """Load custom YARA rules from directory."""
        for rule_file in self.rules_dir.glob("*.yar"):
            try:
                rules = yara.compile(filepath=str(rule_file))
                self.custom_rules[rule_file.stem] = rules
                logger.info(f"Loaded custom rule: {rule_file.stem}")
            except Exception as e:
                logger.error(f"Failed to load rule {rule_file}: {e}")

    def scan_file(
        self, file_path: Path, categories: list[RuleCategory] | None = None
    ) -> list[YaraMatch]:
        """Scan a file with YARA rules.

        Args:
            file_path: Path to file to scan
            categories: Categories to scan (None = all)

        Returns:
            List of YARA matches

        """
        matches = []

        # Determine which rules to use
        if categories:
            rules_to_scan = {
                cat: self.compiled_rules[cat] for cat in categories if cat in self.compiled_rules
            }
        else:
            rules_to_scan = self.compiled_rules

        # Scan with each rule set
        for category, rules in rules_to_scan.items():
            try:
                yara_matches = rules.match(str(file_path))

                for match in yara_matches:
                    yara_match = YaraMatch(
                        rule_name=match.rule,
                        category=category,
                        offset=match.strings[0][0] if match.strings else 0,
                        matched_strings=[(s[0], s[1], s[2]) for s in match.strings],
                        tags=match.tags,
                        meta=match.meta,
                        confidence=float(match.meta.get("confidence", 50)),
                    )
                    matches.append(yara_match)

            except Exception as e:
                logger.error(f"Failed to scan with {category.value} rules: {e}")

        # Scan with custom rules
        for rule_name, rules in self.custom_rules.items():
            try:
                yara_matches = rules.match(str(file_path))

                for match in yara_matches:
                    yara_match = YaraMatch(
                        rule_name=match.rule,
                        category=RuleCategory.CUSTOM,
                        offset=match.strings[0][0] if match.strings else 0,
                        matched_strings=[(s[0], s[1], s[2]) for s in match.strings],
                        tags=match.tags,
                        meta=match.meta,
                        confidence=float(match.meta.get("confidence", 50)),
                    )
                    matches.append(yara_match)

            except Exception as e:
                logger.error(f"Failed to scan with custom rule {rule_name}: {e}")

        return matches

    def scan_memory(
        self, pid: int, categories: list[RuleCategory] | None = None
    ) -> list[YaraMatch]:
        """Scan process memory with YARA rules.

        Args:
            pid: Process ID to scan
            categories: Categories to scan (None = all)

        Returns:
            List of YARA matches

        """
        matches = []

        # Determine which rules to use
        if categories:
            rules_to_scan = {
                cat: self.compiled_rules[cat] for cat in categories if cat in self.compiled_rules
            }
        else:
            rules_to_scan = self.compiled_rules

        # Scan process memory
        for category, rules in rules_to_scan.items():
            try:
                yara_matches = rules.match(pid=pid)

                for match in yara_matches:
                    yara_match = YaraMatch(
                        rule_name=match.rule,
                        category=category,
                        offset=match.strings[0][0] if match.strings else 0,
                        matched_strings=[(s[0], s[1], s[2]) for s in match.strings],
                        tags=match.tags,
                        meta=match.meta,
                        confidence=float(match.meta.get("confidence", 50)),
                    )
                    matches.append(yara_match)

            except Exception as e:
                logger.error(f"Failed to scan process {pid} with {category.value} rules: {e}")

        return matches

    def detect_protections(self, file_path: Path) -> dict[str, Any]:
        """Detect protection schemes in a binary.

        Args:
            file_path: Path to binary file

        Returns:
            Dictionary of detected protections

        """
        protections = {
            "packers": [],
            "protectors": [],
            "crypto": [],
            "license": [],
            "anti_debug": [],
            "compiler": None,
        }

        # Scan with protection-related categories
        matches = self.scan_file(
            file_path,
            categories=[
                RuleCategory.PACKER,
                RuleCategory.PROTECTOR,
                RuleCategory.CRYPTO,
                RuleCategory.LICENSE,
                RuleCategory.ANTI_DEBUG,
                RuleCategory.COMPILER,
            ],
        )

        # Organize matches by category
        for match in matches:
            if match.category == RuleCategory.PACKER:
                protections["packers"].append(
                    {
                        "name": match.rule_name,
                        "confidence": match.confidence,
                        "offset": match.offset,
                    }
                )
            elif match.category == RuleCategory.PROTECTOR:
                protections["protectors"].append(
                    {
                        "name": match.rule_name,
                        "confidence": match.confidence,
                        "offset": match.offset,
                    }
                )
            elif match.category == RuleCategory.CRYPTO:
                protections["crypto"].append(
                    {
                        "algorithm": match.rule_name,
                        "confidence": match.confidence,
                        "offset": match.offset,
                    }
                )
            elif match.category == RuleCategory.LICENSE:
                protections["license"].append(
                    {
                        "type": match.rule_name,
                        "confidence": match.confidence,
                        "offset": match.offset,
                    }
                )
            elif match.category == RuleCategory.ANTI_DEBUG:
                protections["anti_debug"].append(
                    {
                        "technique": match.rule_name,
                        "confidence": match.confidence,
                        "offset": match.offset,
                    }
                )
            elif match.category == RuleCategory.COMPILER:
                if (
                    protections["compiler"] is None
                    or match.confidence > protections["compiler"]["confidence"]
                ):
                    protections["compiler"] = {
                        "name": match.rule_name,
                        "confidence": match.confidence,
                    }

        # Also check with signature-based detection
        sig_detections = self._detect_by_signatures(file_path)
        protections["signature_based"] = sig_detections

        return protections

    def _detect_by_signatures(self, file_path: Path) -> list[dict[str, Any]]:
        """Detect protections using byte signatures.

        Args:
            file_path: Path to binary file

        Returns:
            List of detected protections

        """
        detections = []

        try:
            with open(file_path, "rb") as f:
                # Read first 64KB for signature scanning
                data = f.read(65536)

                for name, signature in self.PROTECTION_SIGNATURES.items():
                    detected = False
                    confidence = 0

                    # Check byte signatures
                    for sig_bytes in signature.signatures:
                        if sig_bytes in data:
                            detected = True
                            confidence += 30
                            break

                    # Check entry point pattern
                    if signature.entry_point_pattern:
                        # Read entry point area
                        f.seek(0)
                        header = f.read(1024)
                        if signature.entry_point_pattern in header:
                            detected = True
                            confidence += 40

                    if detected:
                        detections.append(
                            {
                                "name": name,
                                "category": signature.category,
                                "confidence": min(confidence, 95),
                            }
                        )

        except Exception as e:
            logger.error(f"Failed to perform signature-based detection: {e}")

        return detections

    def create_custom_rule(
        self, rule_name: str, rule_content: str, category: RuleCategory = RuleCategory.CUSTOM
    ) -> bool:
        """Create and compile a custom YARA rule.

        Args:
            rule_name: Name for the rule
            rule_content: YARA rule content
            category: Category for the rule

        Returns:
            True if successful

        """
        try:
            # Compile rule to verify syntax
            rules = yara.compile(source=rule_content)

            # Save to file
            rule_file = self.rules_dir / f"{rule_name}.yar"
            self.rules_dir.mkdir(parents=True, exist_ok=True)

            with open(rule_file, "w") as f:
                f.write(rule_content)

            # Store compiled rule
            self.custom_rules[rule_name] = rules

            logger.info(f"Created custom rule: {rule_name}")
            return True

        except Exception as e:
            logger.error(f"Failed to create custom rule: {e}")
            return False

    def compile_rules(self, incremental: bool = False, timeout: int = 30) -> bool:
        """Compile all loaded rules with performance optimization."""
        import hashlib
        import time

        try:
            # Generate hash of current rules for caching
            rules_hash = hashlib.sha256(
                "".join(sorted(self.builtin_rules.values())).encode()
            ).hexdigest()

            # Check if rules haven't changed (use cached compilation)
            if hasattr(self, "_rules_hash") and self._rules_hash == rules_hash:
                logger.debug("Rules unchanged, using cached compilation")
                return True

            # Combine all rules with error handling for individual rule failures
            valid_rules = []
            failed_rules = []

            for name, content in self.builtin_rules.items():
                try:
                    # Validate individual rule
                    yara.compile(source=content)
                    valid_rules.append(content)
                except Exception as e:
                    logger.warning(f"Rule '{name}' failed validation: {e}")
                    failed_rules.append(name)
                    if not incremental:
                        raise

            if not valid_rules:
                logger.error("No valid rules to compile")
                return False

            # Compile with timeout for large rule sets
            start_time = time.time()
            all_rules = "\n\n".join(valid_rules)

            # Add performance hints
            if len(valid_rules) > 100:
                # For large rule sets, compile with includes to reduce memory
                self.compiled_rules = yara.compile(
                    source=all_rules, includes=True, error_on_warning=False
                )
            else:
                self.compiled_rules = yara.compile(source=all_rules)

            compile_time = time.time() - start_time
            logger.info(f"Compiled {len(valid_rules)} rules in {compile_time:.2f}s")

            # Remove failed rules from builtin_rules if incremental
            if incremental and failed_rules:
                for name in failed_rules:
                    del self.builtin_rules[name]
                logger.info(f"Removed {len(failed_rules)} invalid rules")

            # Cache the hash
            self._rules_hash = rules_hash
            return True

        except yara.TimeoutError:
            logger.error(f"Rule compilation timeout after {timeout}s")
            return False
        except Exception as e:
            logger.error(f"Failed to compile rules: {e}")
            return False

    def add_rule(
        self,
        rule_name: str,
        rule_content: str,
        category: RuleCategory = RuleCategory.LICENSE,
        validate_syntax: bool = True,
    ) -> bool:
        """Add a new YARA rule with validation and categorization."""
        import re

        try:
            # Sanitize rule name
            safe_name = re.sub(r"[^a-zA-Z0-9_]", "_", rule_name)

            # Check for duplicate
            if safe_name in self.builtin_rules:
                logger.warning(f"Rule '{safe_name}' already exists, updating...")

            # Validate rule syntax if requested
            if validate_syntax:
                try:
                    test_compiled = yara.compile(source=rule_content)
                    # Test the rule on empty data to ensure it doesn't crash
                    test_compiled.match(data=b"test")
                except yara.SyntaxError as e:
                    logger.error(f"Rule syntax error: {e}")
                    return False
                except Exception as e:
                    logger.error(f"Rule validation error: {e}")
                    return False

            # Add metadata to rule if not present
            if "meta:" not in rule_content:
                # Insert metadata after rule name
                lines = rule_content.split("\n")
                for i, line in enumerate(lines):
                    if "{" in line:
                        lines.insert(
                            i + 1,
                            f'    meta:\n        category = "{category.value}"\n        added_date = "{os.environ.get("DATE", "")}"',
                        )
                        break
                rule_content = "\n".join(lines)

            # Store rule with category tracking
            self.builtin_rules[safe_name] = rule_content
            self._rule_categories[safe_name] = category

            # Incremental compilation for performance
            return self.compile_rules(incremental=True)

        except Exception as e:
            logger.error(f"Failed to add rule {rule_name}: {e}")
            return False

    def remove_rule(self, rule_name: str, check_dependencies: bool = True) -> bool:
        """Remove a YARA rule with dependency checking."""
        if rule_name not in self.builtin_rules:
            logger.warning(f"Rule '{rule_name}' not found")
            return False

        try:
            # Check if other rules depend on this one
            if check_dependencies:
                for name, content in self.builtin_rules.items():
                    if name != rule_name and rule_name in content:
                        logger.warning(f"Rule '{name}' may depend on '{rule_name}'")
                        # Continue anyway but log the warning

            # Remove rule and its category
            del self.builtin_rules[rule_name]
            if hasattr(self, "_rule_categories") and rule_name in self._rule_categories:
                del self._rule_categories[rule_name]

            # Recompile remaining rules
            return self.compile_rules()

        except Exception as e:
            logger.error(f"Failed to remove rule {rule_name}: {e}")
            return False

    def scan_process(
        self,
        pid: int,
        categories: list[RuleCategory] | None = None,
        scan_dlls: bool = True,
        scan_heap: bool = True,
    ) -> list[YaraMatch]:
        """Scan a running process memory with advanced options."""
        import ctypes
        from ctypes import wintypes

        import psutil

        matches = []

        try:
            # Verify process exists
            if not psutil.pid_exists(pid):
                logger.error(f"Process {pid} does not exist")
                return matches

            # Get process info
            try:
                process = psutil.Process(pid)
                process_name = process.name()
            except (psutil.NoSuchProcess, psutil.AccessDenied) as e:
                logger.error(f"Cannot access process {pid}: {e}")
                return matches

            # Open process with required permissions
            PROCESS_VM_READ = 0x0010
            PROCESS_QUERY_INFORMATION = 0x0400

            kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
            if process_handle := kernel32.OpenProcess(
                PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, False, pid
            ):
                # Enhanced scanning with handle
                logger.info(f"Enhanced scanning of process {pid} with handle")

                class MEMORY_BASIC_INFORMATION(ctypes.Structure):  # noqa: N801
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
                MEM_COMMIT = 0x1000
                PAGE_EXECUTE_READWRITE = 0x40

                while address < 0x7FFFFFFF0000:
                    result = kernel32.VirtualQueryEx(
                        process_handle,
                        ctypes.c_void_p(address),
                        ctypes.byref(mbi),
                        ctypes.sizeof(mbi),
                    )

                    if not result:
                        break

                    # Scan committed memory with appropriate permissions
                    if mbi.State == MEM_COMMIT and (
                        scan_heap or mbi.Protect in [PAGE_EXECUTE_READWRITE]
                    ):
                        # Read memory region
                        buffer = ctypes.create_string_buffer(mbi.RegionSize)
                        bytes_read = ctypes.c_size_t()

                        if kernel32.ReadProcessMemory(
                            process_handle,
                            mbi.BaseAddress,
                            buffer,
                            mbi.RegionSize,
                            ctypes.byref(bytes_read),
                        ):
                            # Scan this memory region
                            region_matches = self._scan_memory_region(
                                buffer.raw[: bytes_read.value], mbi.BaseAddress, categories
                            )
                            matches.extend(region_matches)

                    address = mbi.BaseAddress + mbi.RegionSize

                kernel32.CloseHandle(process_handle)

            else:
                # Try using YARA's built-in process scanning
                logger.info(f"Using YARA built-in scanning for process {pid}")
                try:
                    # Filter rules by category
                    compiled = (
                        yara.compile(source=filtered_rules)
                        if categories
                        and (
                            filtered_rules := self._filter_rules_by_category(
                                categories
                            )
                        )
                        else self.compiled_rules
                    )
                    # Scan process
                    yara_matches = compiled.match(pid=pid)

                    for match in yara_matches:
                        matches.append(
                            YaraMatch(
                                rule_name=match.rule,
                                category=self._get_rule_category(match.rule),
                                matched_data=f"Process: {process_name} (PID: {pid})",
                                metadata={
                                    "pid": pid,
                                    "process_name": process_name,
                                    "strings": [(s.offset, s.matched_data) for s in match.strings],
                                },
                            ),
                        )

                except Exception as e:
                    logger.error(f"YARA process scan failed: {e}")
            # Store matches
            with self._match_lock:
                self._matches.extend(matches)

            logger.info(f"Found {len(matches)} matches in process {pid}")
            return matches

        except Exception as e:
            logger.error(f"Process scanning error: {e}")
            return matches

    def generate_rule(
        self,
        name: str,
        strings: list[str],
        condition: str = "any of them",
        add_wildcards: bool = True,
        add_case_variations: bool = True,
    ) -> str:
        """Generate sophisticated YARA rules for licensing protection detection."""
        import re

        # Sanitize rule name
        safe_name = re.sub(r"[^a-zA-Z0-9_]", "_", name)

        rule_content = f"rule {safe_name} {{\n"
        rule_content += "    meta:\n"
        rule_content += f'        description = "Auto-generated rule for {name}"\n'
        rule_content += '        category = "license"\n'
        rule_content += "    strings:\n"

        string_vars = []

        for i, s in enumerate(strings):
            var_name = f"s{i}"

            if s.startswith("/") and s.endswith("/"):
                # Regex pattern - validate it
                try:
                    re.compile(s[1:-1])
                    rule_content += f"        ${var_name} = {s}\n"
                    string_vars.append(f"${var_name}")
                except re.error as e:
                    logger.warning(f"Invalid regex pattern: {s} - {e}")
                    continue

            elif s.startswith("{") and s.endswith("}"):
                # Hex pattern - add wildcards for flexibility
                hex_pattern = s
                if add_wildcards:
                    # Convert some bytes to wildcards for variation matching
                    hex_bytes = hex_pattern[1:-1].strip().split()
                    if len(hex_bytes) > 4:
                        # Make every 3rd byte a wildcard
                        for j in range(2, len(hex_bytes), 3):
                            if hex_bytes[j] != "??":
                                hex_bytes[j] = "??"
                        hex_pattern = "{ " + " ".join(hex_bytes) + " }"

                rule_content += f"        ${var_name} = {hex_pattern}\n"
                string_vars.append(f"${var_name}")

            else:
                # String literal - add variations
                base_var = f"${var_name}"

                # Add base string
                rule_content += f'        {base_var} = "{s}"\n'
                string_vars.append(base_var)

                if add_case_variations:
                    # Add case-insensitive version
                    rule_content += f'        {base_var}_nocase = "{s}" nocase\n'
                    string_vars.append(f"{base_var}_nocase")

                    # Add wide string version (Unicode)
                    rule_content += f'        {base_var}_wide = "{s}" wide\n'
                    string_vars.append(f"{base_var}_wide")

                    # Add ASCII version
                    rule_content += f'        {base_var}_ascii = "{s}" ascii\n'
                    string_vars.append(f"{base_var}_ascii")

                # Add common obfuscation patterns
                if "license" in s.lower() or "serial" in s.lower() or "key" in s.lower():
                    # Add hex-encoded version
                    hex_encoded = " ".join([f"{ord(c):02X}" for c in s])
                    rule_content += f"        ${var_name}_hex = {{ {hex_encoded} }}\n"
                    string_vars.append(f"${var_name}_hex")

                    # Add base64 pattern
                    import base64

                    b64_encoded = base64.b64encode(s.encode()).decode()
                    rule_content += f'        ${var_name}_b64 = "{b64_encoded}"\n'
                    string_vars.append(f"${var_name}_b64")

        # Generate sophisticated conditions
        if condition == "any of them":
            condition = f"any of ({', '.join(string_vars)})"
        elif condition == "all of them":
            condition = f"all of ({', '.join(string_vars)})"
        elif condition.startswith("custom:"):
            # Parse custom condition
            condition = condition[7:]
        else:
            # Add advanced conditions for license detection
            conditions = []

            # Check for at least 2 strings
            if len(string_vars) > 2:
                conditions.append(f"2 of ({', '.join(string_vars)})")

            # Add filesize constraint for efficiency
            conditions.append("filesize < 50MB")

            # Combine conditions
            condition = " and ".join(conditions) if conditions else "any of them"

        rule_content += f"    condition:\n        {condition}\n}}"

        return rule_content

    def get_matches(self) -> list[YaraMatch]:
        """Get all stored matches (thread-safe)."""
        with self._match_lock:
            return list(self._matches)  # Return copy to prevent external modification

    def clear_matches(self) -> None:
        """Clear stored matches (thread-safe)."""
        with self._match_lock:
            self._matches = []
            logger.debug("Cleared all stored matches")

    def _scan_memory_region(
        self, data: bytes, base_address: int, categories: list[RuleCategory] | None
    ) -> list[YaraMatch]:
        """Scan a memory region with filtered rules."""
        matches = []

        try:
            # Filter rules by category if specified
            if categories and (
                filtered_rules := self._filter_rules_by_category(categories)
            ):
                compiled = yara.compile(source=filtered_rules)
            else:
                compiled = self.compiled_rules
            # Scan memory region
            yara_matches = compiled.match(data=data)

            matches.extend(
                YaraMatch(
                    rule_name=match.rule,
                    category=self._get_rule_category(match.rule),
                    matched_data=f"Memory at 0x{base_address:X}",
                    metadata={
                        "base_address": base_address,
                        "strings": [
                            (s.offset + base_address, s.matched_data)
                            for s in match.strings
                        ],
                    },
                )
                for match in yara_matches
            )
        except Exception as e:
            logger.error(f"Memory region scan error: {e}")

        return matches

    def _filter_rules_by_category(self, categories: list[RuleCategory]) -> str:
        """Filter rules by category."""
        filtered = []
        for name, content in self.builtin_rules.items():
            if name in self._rule_categories and self._rule_categories[name] in categories:
                filtered.append(content)

        return "\n\n".join(filtered)

    def _get_rule_category(self, rule_name: str) -> RuleCategory:
        """Get category for a rule."""
        if rule_name in self._rule_categories:
            return self._rule_categories[rule_name]
        return RuleCategory.CUSTOM

    def export_detections(self, detections: dict[str, Any], output_path: Path) -> None:
        """Export detection results to file.

        Args:
            detections: Detection results
            output_path: Path to save results

        """
        import time

        export_data = {
            "timestamp": time.time(),
            "detections": detections,
            "statistics": {
                "total_packers": len(detections.get("packers", [])),
                "total_protectors": len(detections.get("protectors", [])),
                "total_crypto": len(detections.get("crypto", [])),
                "total_license": len(detections.get("license", [])),
                "total_anti_debug": len(detections.get("anti_debug", [])),
            },
        }

        with open(output_path, "w") as f:
            json.dump(export_data, f, indent=2)

        logger.info(f"Exported detections to {output_path}")

    def scan_process_with_analyzer(
        self,
        license_analyzer: object,
        categories: list[RuleCategory] | None = None,
        scan_dlls: bool = True,
        scan_heap: bool = True,
        use_cache: bool = True,
        progress_callback: Callable[[int, int, str], None] | None = None,
    ) -> list[YaraMatch]:
        """Scan process memory using LicenseAnalyzer for enhanced memory access.

        Args:
            license_analyzer: Connected LicenseAnalyzer instance
            categories: Categories to scan (None = all)
            scan_dlls: Whether to scan loaded DLLs
            scan_heap: Whether to scan heap memory
            use_cache: Whether to use match caching
            progress_callback: Callback function for progress updates

        Returns:
            List of YARA matches

        """
        if not license_analyzer.process_handle:
            logger.error("LicenseAnalyzer not attached to process")
            return []

        matches = []
        scanned_regions = 0
        total_regions = 0

        try:
            # Enumerate memory regions using LicenseAnalyzer
            memory_regions = license_analyzer.enumerate_memory_regions()
            total_regions = len(memory_regions)

            if progress_callback:
                progress_callback(0, total_regions, "Starting YARA scan...")

            # Filter regions based on scan preferences
            filtered_regions = []
            for region in memory_regions:
                # Skip uncommitted memory
                if region["state"] != 0x1000:  # MEM_COMMIT
                    continue

                # Skip guard pages
                if region["protect"] & 0x100:  # PAGE_GUARD
                    continue

                # Apply DLL filtering
                if not scan_dlls and self._is_dll_region(license_analyzer, region):
                    continue

                # Apply heap filtering
                if not scan_heap and self._is_heap_region(license_analyzer, region):
                    continue

                filtered_regions.append(region)

            # Prepare YARA rules
            if categories:
                rules_to_scan = {
                    cat: self.compiled_rules[cat]
                    for cat in categories
                    if cat in self.compiled_rules
                }
            else:
                rules_to_scan = self.compiled_rules

            # Scan each filtered region
            for region in filtered_regions:
                try:
                    # Read memory region using LicenseAnalyzer
                    memory_data = license_analyzer.read_process_memory(
                        region["base_address"], region["size"]
                    )
                    if not memory_data:
                        continue

                    # Check cache if enabled
                    if use_cache and hasattr(self, "_match_cache"):
                        cache_key = self._generate_cache_key(memory_data, categories)
                        if cache_key in self._match_cache:
                            cached_matches = self._match_cache[cache_key]
                            matches.extend(cached_matches)
                            scanned_regions += 1
                            if progress_callback:
                                progress_callback(
                                    scanned_regions,
                                    total_regions,
                                    f"Scanning region 0x{region['base_address']:X} (cached)",
                                )
                            continue

                    # Scan with each rule set
                    region_matches = []
                    for category, rules in rules_to_scan.items():
                        try:
                            yara_matches = rules.match(data=memory_data)

                            for match in yara_matches:
                                yara_match = YaraMatch(
                                    rule_name=match.rule,
                                    category=category,
                                    offset=region["base_address"] + match.strings[0][0]
                                    if match.strings
                                    else region["base_address"],
                                    matched_strings=[(s[0], s[1], s[2]) for s in match.strings],
                                    tags=match.tags,
                                    meta=match.meta,
                                    confidence=float(match.meta.get("confidence", 50)),
                                )
                                region_matches.append(yara_match)
                                matches.append(yara_match)

                        except Exception as e:
                            logger.error(f"Failed to scan region with {category.value} rules: {e}")

                    # Cache results if enabled
                    if use_cache:
                        if not hasattr(self, "_match_cache"):
                            self._match_cache = {}
                        cache_key = self._generate_cache_key(memory_data, categories)
                        self._match_cache[cache_key] = region_matches

                    scanned_regions += 1
                    if progress_callback:
                        progress_callback(
                            scanned_regions,
                            total_regions,
                            f"Scanned region 0x{region['base_address']:X}",
                        )

                except Exception as e:
                    logger.error(f"Failed to scan region at 0x{region['base_address']:X}: {e}")
                    scanned_regions += 1

            # Also scan with custom rules
            for rule_name, rules in self.custom_rules.items():
                for region in filtered_regions:
                    try:
                        memory_data = license_analyzer.read_process_memory(
                            region["base_address"], region["size"]
                        )
                        if not memory_data:
                            continue

                        yara_matches = rules.match(data=memory_data)

                        for match in yara_matches:
                            yara_match = YaraMatch(
                                rule_name=match.rule,
                                category=RuleCategory.CUSTOM,
                                offset=region["base_address"] + match.strings[0][0]
                                if match.strings
                                else region["base_address"],
                                matched_strings=[(s[0], s[1], s[2]) for s in match.strings],
                                tags=match.tags,
                                meta=match.meta,
                                confidence=float(match.meta.get("confidence", 50)),
                            )
                            matches.append(yara_match)

                    except Exception as e:
                        logger.error(f"Failed to scan with custom rule {rule_name}: {e}")

            if progress_callback:
                progress_callback(
                    total_regions, total_regions, f"Scan complete - found {len(matches)} matches"
                )

            logger.info(f"YARA scan complete: {len(matches)} matches in {scanned_regions} regions")
            return matches

        except Exception as e:
            logger.error(f"Process scanning error: {e}")
            return matches

    def _is_dll_region(self, license_analyzer: object, region: dict[str, Any]) -> bool:
        """Check if memory region belongs to a DLL."""
        try:
            # Check if region has IMAGE characteristics
            if region.get("type") == 0x1000000:  # MEM_IMAGE
                return True

            # Check against known module ranges
            if hasattr(license_analyzer, "enumerate_modules"):
                modules = license_analyzer.enumerate_modules()
                for module in modules:
                    if module["base"] <= region["base_address"] < module["base"] + module["size"]:
                        return True

        except Exception as e:
            logger.debug(f"Module region comparison failed: {e}")

        return False

    def _is_heap_region(self, license_analyzer: object, region: dict[str, Any]) -> bool:
        """Check if memory region belongs to heap."""
        try:
            # Check for typical heap characteristics
            if region.get("protect") in [0x04, 0x08] and region.get("type") == 0x20000:
                return True

        except Exception as e:
            logger.debug(f"Heap region analysis failed: {e}")

        return False

    def _generate_cache_key(self, data: bytes, categories: list[RuleCategory] | None) -> str:
        """Generate cache key for match results."""
        import hashlib

        # Create hash of data and categories
        data_hash = hashlib.sha256(data[:1024] if len(data) > 1024 else data).hexdigest()[:16]
        cat_str = ",".join([c.value for c in categories]) if categories else "all"
        return f"{data_hash}_{cat_str}"

    def scan_memory_concurrent(
        self,
        pid: int,
        categories: list[RuleCategory] | None = None,
        max_workers: int = 4,
        chunk_size: int = 1024 * 1024,
    ) -> list[YaraMatch]:
        """Perform concurrent YARA scanning of process memory.

        Args:
            pid: Process ID to scan
            categories: Categories to scan
            max_workers: Maximum concurrent workers
            chunk_size: Size of memory chunks to scan

        Returns:
            List of YARA matches

        """
        from concurrent.futures import ThreadPoolExecutor, as_completed

        matches = []

        try:
            # Get memory regions
            from intellicrack.core.process_manipulation import LicenseAnalyzer

            analyzer = LicenseAnalyzer()
            if not analyzer.attach_to_process(pid):
                logger.error(f"Failed to attach to process {pid}")
                return matches

            memory_regions = analyzer.enumerate_memory_regions()

            # Prepare scanning tasks
            def scan_region_chunk(region_info: dict[str, Any]) -> list[YaraMatch]:
                region_matches: list[YaraMatch] = []
                try:
                    base_addr = region_info["base_address"]
                    size = region_info["size"]

                    # Read memory
                    memory_data = analyzer.read_process_memory(base_addr, size)
                    if not memory_data:
                        return region_matches

                    # Scan with rules
                    if categories:
                        rules_to_scan = {
                            cat: self.compiled_rules[cat]
                            for cat in categories
                            if cat in self.compiled_rules
                        }
                    else:
                        rules_to_scan = self.compiled_rules

                    for category, rules in rules_to_scan.items():
                        yara_matches = rules.match(data=memory_data)

                        for match in yara_matches:
                            yara_match = YaraMatch(
                                rule_name=match.rule,
                                category=category,
                                offset=base_addr + match.strings[0][0]
                                if match.strings
                                else base_addr,
                                matched_strings=[(s[0], s[1], s[2]) for s in match.strings],
                                tags=match.tags,
                                meta=match.meta,
                                confidence=float(match.meta.get("confidence", 50)),
                            )
                            region_matches.append(yara_match)

                except Exception as e:
                    logger.error(f"Error scanning region: {e}")

                return region_matches

            # Execute concurrent scanning
            with ThreadPoolExecutor(max_workers=max_workers) as executor:
                # Submit scanning tasks
                future_to_region = {
                    executor.submit(scan_region_chunk, region): region
                    for region in memory_regions
                    if region["state"] == 0x1000
                }

                # Collect results
                for future in as_completed(future_to_region):
                    region = future_to_region[future]
                    try:
                        region_matches = future.result(timeout=30)
                        matches.extend(region_matches)
                    except Exception as e:
                        logger.error(
                            f"Scanning failed for region 0x{region['base_address']:X}: {e}"
                        )

            analyzer.detach_from_process()
            logger.info(f"Concurrent scan found {len(matches)} matches")
            return matches

        except Exception as e:
            logger.error(f"Concurrent scanning error: {e}")
            return matches

    def add_memory_filter(
        self,
        include_executable: bool = True,
        include_writable: bool = True,
        include_readonly: bool = False,
        min_size: int = 0,
        max_size: int = 0,
    ) -> object:
        """Create a memory region filter for YARA scanning.

        Args:
            include_executable: Include executable regions
            include_writable: Include writable regions
            include_readonly: Include read-only regions
            min_size: Minimum region size
            max_size: Maximum region size (0 = no limit)

        Returns:
            MemoryFilter instance

        """

        class MemoryFilter:
            def __init__(self, scanner: YaraScanner) -> None:
                self.scanner = scanner
                self.include_executable = include_executable
                self.include_writable = include_writable
                self.include_readonly = include_readonly
                self.min_size = min_size
                self.max_size = max_size

            def apply(self, regions: list[dict[str, Any]]) -> list[dict[str, Any]]:
                """Apply filter to memory regions."""
                filtered = []
                for region in regions:
                    # Check protection flags
                    protect = region.get("protect", 0)

                    # Check executable
                    if self.include_executable and not (protect & 0xF0):  # Any execute flag
                        continue

                    # Check writable
                    if self.include_writable and not (protect & 0x06):  # READWRITE or WRITECOPY
                        continue

                    # Check readonly
                    if self.include_readonly and not (protect & 0x02):  # READONLY
                        continue

                    # Check size constraints
                    size = region.get("size", 0)
                    if self.min_size > 0 and size < self.min_size:
                        continue
                    if self.max_size > 0 and size > self.max_size:
                        continue

                    filtered.append(region)

                return filtered

        if not hasattr(self, "_memory_filters"):
            self._memory_filters = []

        filter_instance = MemoryFilter(self)
        self._memory_filters.append(filter_instance)
        return filter_instance

    def get_scan_progress(self) -> dict[str, Any]:
        """Get current scanning progress information.

        Returns:
            Dictionary with progress details

        """
        with self._scan_progress_lock:
            return dict(self._scan_progress)

    def set_scan_progress_callback(self, callback: Callable[[int, int, str], None]) -> None:
        """Set callback for scan progress updates.

        Args:
            callback: Function(current, total, status_msg) to call

        """
        self._progress_callback = callback

    def enable_match_caching(self, max_cache_size: int = 100, ttl_seconds: int = 300) -> None:
        """Enable caching of YARA match results.

        Args:
            max_cache_size: Maximum number of cached results
            ttl_seconds: Time to live for cache entries

        """
        from collections import OrderedDict

        self._match_cache = OrderedDict()
        self._cache_max_size = max_cache_size
        self._cache_ttl = ttl_seconds
        self._cache_timestamps = {}

        logger.info(f"Match caching enabled: max_size={max_cache_size}, ttl={ttl_seconds}s")

    def clear_match_cache(self) -> None:
        """Clear the match result cache."""
        if hasattr(self, "_match_cache"):
            self._match_cache.clear()
            self._cache_timestamps.clear()
            logger.info("Match cache cleared")

    def optimize_rules_for_memory(self, memory_size: int) -> bool:
        """Optimize YARA rules for scanning large memory spaces.

        Args:
            memory_size: Expected memory size to scan

        Returns:
            True if optimization successful

        """
        try:
            # Adjust rule compilation based on memory size
            if memory_size > 1024 * 1024 * 1024:  # > 1GB
                # Use fast matching mode for large memory
                logger.info("Optimizing rules for large memory scanning")

                # Recompile rules with optimization flags
                optimized_rules = {}
                for category, _ in self.compiled_rules.items():
                    if rule_source := self._get_rule_source(category):
                        # Compile with fast matching
                        optimized_rules[category] = yara.compile(
                            source=rule_source, fast_matching=True
                        )

                self.compiled_rules = optimized_rules
                logger.info("Rules optimized for large memory scanning")
                return True

            return True

        except Exception as e:
            logger.error(f"Failed to optimize rules: {e}")
            return False

    def _get_rule_source(self, category: RuleCategory) -> str | None:
        """Get source code for rule category."""
        source_methods = {
            RuleCategory.PACKER: self._create_packer_rules,
            RuleCategory.PROTECTOR: self._create_protector_rules,
            RuleCategory.CRYPTO: self._create_crypto_rules,
            RuleCategory.LICENSE: self._create_license_rules,
            RuleCategory.ANTI_DEBUG: self._create_antidebug_rules,
            RuleCategory.COMPILER: self._create_compiler_rules,
        }

        return source_methods[category]() if category in source_methods else None

    def convert_pattern_to_yara(
        self,
        pattern: bytes,
        name: str = "auto_pattern",
        add_wildcards: bool = True,
        context_bytes: int = 16,
    ) -> str:
        """Convert binary pattern to YARA rule.

        Args:
            pattern: Binary pattern to convert
            name: Rule name
            add_wildcards: Whether to add wildcards for flexibility
            context_bytes: Bytes of context to include

        Returns:
            YARA rule string

        """
        import re

        safe_name = re.sub(r"[^a-zA-Z0-9_]", "_", name)

        # Convert bytes to hex string
        hex_pattern = " ".join([f"{b:02X}" for b in pattern])

        # Add wildcards for flexibility if requested
        if add_wildcards and len(pattern) > 8:
            hex_bytes = hex_pattern.split()
            # Make every 4th byte a wildcard for flexibility
            for i in range(3, len(hex_bytes), 4):
                if i < len(hex_bytes) - 2:  # Keep last bytes intact
                    hex_bytes[i] = "??"
            hex_pattern = " ".join(hex_bytes)

        # Generate rule
        rule = f"""rule {safe_name} {{
    meta:
        description = "Auto-generated from binary pattern"
        category = "pattern"
        pattern_length = {len(pattern)}
        context_bytes = {context_bytes}
    strings:
        $pattern = {{ {hex_pattern} }}"""

        # Add variations
        if len(pattern) <= 32:
            # For short patterns, add ASCII and wide versions
            try:
                ascii_str = pattern.decode("ascii", errors="ignore")
                if ascii_str and len(ascii_str) > 3:
                    rule += f'\n        $ascii = "{ascii_str}"'
                    rule += f'\n        $wide = "{ascii_str}" wide'
            except (ValueError, OSError):
                pass

        # Add condition
        rule += """
    condition:
        any of them
}"""

        return rule

    def extract_strings_automatic(
        self,
        data: bytes,
        min_length: int = 4,
        encoding: str = "auto",
        filter_common: bool = True,
        extract_urls: bool = True,
        extract_paths: bool = True,
    ) -> list[str]:
        """Automatically extract interesting strings from binary data.

        Args:
            data: Binary data to analyze
            min_length: Minimum string length
            encoding: String encoding (auto, ascii, utf16le, utf16be)
            filter_common: Filter out common strings
            extract_urls: Extract URL patterns
            extract_paths: Extract file path patterns

        Returns:
            List of extracted strings

        """
        import re

        extracted = set()

        # Common strings to filter
        common_strings = {
            "This",
            "The",
            "Microsoft",
            "Windows",
            "System",
            "Program",
            "File",
            "Error",
            "Warning",
            "Information",
        }

        def is_interesting(s: str) -> bool:
            """Check if string is interesting for rule generation."""
            if len(s) < min_length:
                return False
            if filter_common and s in common_strings:
                return False
            # Check for license-related keywords
            license_keywords = [
                "license",
                "serial",
                "key",
                "activation",
                "trial",
                "expired",
                "register",
                "crack",
                "patch",
                "keygen",
            ]
            for keyword in license_keywords:
                if keyword.lower() in s.lower():
                    return True
            # Check for high entropy (encrypted/packed)
            return True if len(set(s)) / len(s) > 0.7 else len(s) >= min_length * 2

        # Extract ASCII strings
        if encoding in {"auto", "ascii"}:
            ascii_pattern = rb"[\x20-\x7E]{%d,}" % min_length
            for match in re.finditer(ascii_pattern, data):
                s = match.group().decode("ascii", errors="ignore")
                if is_interesting(s):
                    extracted.add(s)

        # Extract UTF-16LE strings (common in Windows)
        if encoding in {"auto", "utf16le"}:
            utf16_pattern = rb"(?:[\x20-\x7E]\x00){%d,}" % min_length
            for match in re.finditer(utf16_pattern, data):
                try:
                    s = match.group().decode("utf-16le", errors="ignore")
                    if is_interesting(s):
                        extracted.add(s)
                except (TypeError, ValueError):
                    pass

        # Extract UTF-16BE strings
        if encoding in {"auto", "utf16be"}:
            utf16be_pattern = rb"(?:\x00[\x20-\x7E]){%d,}" % min_length
            for match in re.finditer(utf16be_pattern, data):
                try:
                    s = match.group().decode("utf-16be", errors="ignore")
                    if is_interesting(s):
                        extracted.add(s)
                except (TypeError, ValueError):
                    pass

        # Extract URLs
        if extract_urls:
            url_pattern = rb"https?://[\x21-\x7E]+"
            for match in re.finditer(url_pattern, data):
                url = match.group().decode("ascii", errors="ignore")
                extracted.add(url)

        # Extract file paths
        if extract_paths:
            # Windows paths
            win_path_pattern = rb"[A-Za-z]:\\[\x20-\x7E]{3,}"
            for match in re.finditer(win_path_pattern, data):
                path = match.group().decode("ascii", errors="ignore")
                extracted.add(path)

            # Registry paths
            reg_pattern = rb"(?:HKEY_[A-Z_]+|HKLM|HKCU|HKCR)\\[\x20-\x7E]{3,}"
            for match in re.finditer(reg_pattern, data):
                reg = match.group().decode("ascii", errors="ignore")
                extracted.add(reg)

        return sorted(extracted)

    def generate_hex_patterns(
        self, data: bytes, pattern_size: int = 16, step: int = 1, unique_only: bool = True
    ) -> list[str]:
        """Generate hex patterns from binary data.

        Args:
            data: Binary data to process
            pattern_size: Size of each pattern
            step: Step size for sliding window
            unique_only: Return only unique patterns

        Returns:
            List of hex pattern strings

        """
        patterns = []
        seen = set() if unique_only else None

        for i in range(0, len(data) - pattern_size + 1, step):
            chunk = data[i : i + pattern_size]
            hex_pattern = " ".join([f"{b:02X}" for b in chunk])

            if unique_only:
                if hex_pattern not in seen:
                    seen.add(hex_pattern)
                    patterns.append(hex_pattern)
            else:
                patterns.append(hex_pattern)

        return patterns

    def generate_condition(
        self,
        num_strings: int,
        rule_type: str = "license",
        add_filesize: bool = True,
        add_pe_check: bool = True,
        min_matches: int = 2,
    ) -> str:
        """Generate YARA rule condition based on rule type.

        Args:
            num_strings: Number of strings in the rule
            rule_type: Type of rule (license, packer, protector, etc.)
            add_filesize: Add filesize constraint
            add_pe_check: Add PE file check
            min_matches: Minimum string matches required

        Returns:
            Condition string

        """
        conditions = []

        # Add PE check if requested
        if add_pe_check:
            conditions.append("uint16(0) == 0x5A4D")

        # Add filesize constraint based on type
        if add_filesize:
            size_limits = {
                "license": "filesize < 50MB",
                "packer": "filesize < 100MB",
                "protector": "filesize < 200MB",
                "crypto": "filesize < 10MB",
                "anti_debug": "filesize < 100MB",
            }
            if rule_type in size_limits:
                conditions.append(size_limits[rule_type])

        # Add string matching condition
        if num_strings == 1:
            conditions.append("all of them")
        elif num_strings <= 3:
            conditions.append("any of them")
        else:
            # For many strings, require minimum matches
            conditions.append(f"{min_matches} of them")

        # Special conditions for specific types
        if rule_type == "crypto":
            # For crypto, require multiple matches
            if num_strings > 2:
                conditions.append(f"({min(3, num_strings)} of them)")

        elif rule_type == "license":
            # For license rules, also check for specific sections
            conditions.append("(any of them)")

        elif rule_type == "packer":
            # For packers, check entry point
            conditions.append("($pattern at entrypoint or any of them)")

        # Combine conditions
        if len(conditions) == 1:
            return conditions[0]
        if len(conditions) == 2:
            return f"{conditions[0]} and {conditions[1]}"
        # Group PE and size checks
        base_checks = " and ".join(conditions[:2]) if len(conditions) > 2 else conditions[0]
        string_checks = " or ".join(conditions[2:]) if len(conditions) > 2 else conditions[1]
        return f"{base_checks} and ({string_checks})"

    def extract_metadata(self, file_path: Path) -> dict[str, Any]:
        """Extract metadata from binary for rule generation.

        Args:
            file_path: Path to binary file

        Returns:
            Dictionary of metadata

        """
        import hashlib

        import pefile

        metadata = {
            "file_name": file_path.name,
            "file_size": file_path.stat().st_size,
            "md5": "",
            "sha256": "",
            "imphash": "",
            "compile_time": None,
            "pdb_path": None,
            "original_filename": None,
            "company_name": None,
            "product_name": None,
            "file_version": None,
            "sections": [],
            "imports": [],
            "exports": [],
        }

        # Calculate hashes
        with open(file_path, "rb") as f:
            data = f.read()
            # For YARA scanning we calculate SHA256; MD5 is deprecated for security reasons
            metadata["sha256"] = hashlib.sha256(data).hexdigest()

        # Extract PE metadata
        try:
            pe = pefile.PE(str(file_path))

            # Get imphash
            metadata["imphash"] = pe.get_imphash()

            # Get compile time
            if hasattr(pe, "FILE_HEADER"):
                metadata["compile_time"] = pe.FILE_HEADER.TimeDateStamp

            # Get PDB path
            if hasattr(pe, "DIRECTORY_ENTRY_DEBUG"):
                for debug in pe.DIRECTORY_ENTRY_DEBUG:
                    if hasattr(debug.entry, "PdbFileName"):
                        metadata["pdb_path"] = debug.entry.PdbFileName.decode(
                            "utf-8", errors="ignore"
                        )
                        break

            # Get version info
            if hasattr(pe, "VS_VERSIONINFO") and hasattr(pe, "FileInfo"):
                for file_info in pe.FileInfo:
                    if hasattr(file_info, "StringTable"):
                        for st in file_info.StringTable:
                            for k, v in st.entries.items():
                                if k == b"OriginalFilename":
                                    metadata["original_filename"] = v.decode(
                                        "utf-8", errors="ignore"
                                    )
                                elif k == b"CompanyName":
                                    metadata["company_name"] = v.decode(
                                        "utf-8", errors="ignore"
                                    )
                                elif k == b"ProductName":
                                    metadata["product_name"] = v.decode(
                                        "utf-8", errors="ignore"
                                    )
                                elif k == b"FileVersion":
                                    metadata["file_version"] = v.decode(
                                        "utf-8", errors="ignore"
                                    )

            # Get sections
            for section in pe.sections:
                metadata["sections"].append(
                    {
                        "name": section.Name.decode("utf-8", errors="ignore").rstrip("\x00"),
                        "virtual_size": section.Misc_VirtualSize,
                        "raw_size": section.SizeOfRawData,
                        "entropy": section.get_entropy(),
                    },
                )

            # Get imports
            if hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
                for entry in pe.DIRECTORY_ENTRY_IMPORT:
                    dll_name = entry.dll.decode("utf-8", errors="ignore")
                    metadata["imports"].append(dll_name)

            # Get exports
            if hasattr(pe, "DIRECTORY_ENTRY_EXPORT"):
                for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
                    if exp.name:
                        metadata["exports"].append(exp.name.decode("utf-8", errors="ignore"))

            pe.close()

        except Exception as e:
            logger.error(f"Failed to extract PE metadata: {e}")

        return metadata

    def optimize_rule(
        self, rule_content: str, remove_redundant: bool = True, simplify_conditions: bool = True
    ) -> str:
        """Optimize YARA rule for better performance.

        Args:
            rule_content: Original rule content
            remove_redundant: Remove redundant strings
            simplify_conditions: Simplify complex conditions

        Returns:
            Optimized rule content

        """
        import re

        optimized = rule_content

        if remove_redundant:
            # Remove duplicate strings
            lines = optimized.split("\n")
            seen_strings = set()
            new_lines = []

            for line in lines:
                if "$" in line and "=" in line:
                    if match := re.match(r"\s*(\$\w+)\s*=\s*(.+)", line):
                        match.group(1)
                        value = match.group(2).strip()
                        if value not in seen_strings:
                            seen_strings.add(value)
                            new_lines.append(line)
                    else:
                        new_lines.append(line)
                else:
                    new_lines.append(line)

            optimized = "\n".join(new_lines)

        if simplify_conditions:
            # Simplify redundant conditions
            optimized = re.sub(r"any of them and any of them", "any of them", optimized)
            optimized = re.sub(r"all of them and all of them", "all of them", optimized)
            optimized = re.sub(r"\(([^)]+)\) and \1", r"\1", optimized)

        return optimized

    def validate_rule_syntax(self, rule_content: str) -> tuple[bool, str | None]:
        """Validate YARA rule syntax.

        Args:
            rule_content: Rule content to validate

        Returns:
            Tuple of (is_valid, error_message)

        """
        try:
            # Try to compile the rule
            yara.compile(source=rule_content)
            return True, None
        except yara.SyntaxError as e:
            return False, str(e)
        except Exception as e:
            return False, f"Validation error: {e}"

    def generate_rule_from_sample(
        self,
        file_path: Path,
        rule_name: str = "auto_generated",
        category: RuleCategory = RuleCategory.LICENSE,
        advanced_analysis: bool = True,
    ) -> str:
        """Generate comprehensive YARA rule from sample file.

        Args:
            file_path: Path to sample file
            rule_name: Name for the rule
            category: Rule category
            advanced_analysis: Perform advanced analysis

        Returns:
            Generated YARA rule

        """
        import re

        safe_name = re.sub(r"[^a-zA-Z0-9_]", "_", rule_name)

        # Read file
        with open(file_path, "rb") as f:
            data = f.read()

        # Extract metadata
        metadata = self.extract_metadata(file_path) if advanced_analysis else {}

        # Extract strings
        strings = self.extract_strings_automatic(
            data, min_length=6, extract_urls=True, extract_paths=True
        )

        # Generate hex patterns from interesting sections
        hex_patterns = []
        if advanced_analysis and len(data) > 1024:
            entry_patterns = self.generate_hex_patterns(data[:512], pattern_size=16, step=16)
            hex_patterns.extend(entry_patterns[:3])  # Take first 3 patterns

        # Build rule
        rule = f"""rule {safe_name} {{
    meta:
        description = "Auto-generated rule from {file_path.name}"
        category = "{category.value}"
        file_size = {metadata.get("file_size", len(data))}"""

        if metadata.get("md5"):
            rule += f'\n        md5 = "{metadata["md5"]}"'
        if metadata.get("sha256"):
            rule += f'\n        sha256 = "{metadata["sha256"]}"'
        if metadata.get("compile_time"):
            rule += f"\n        compile_time = {metadata['compile_time']}"

        rule += "\n    strings:"

        # Add extracted strings
        for i, s in enumerate(strings[:20]):  # Limit to 20 strings
            # Escape special characters
            escaped = s.replace("\\", "\\\\").replace('"', '\\"')
            rule += f'\n        $str{i} = "{escaped}"'
            # Add nocase for interesting strings
            if any(keyword in s.lower() for keyword in ["license", "trial", "serial", "key"]):
                rule += " nocase"

        # Add hex patterns
        for i, pattern in enumerate(hex_patterns[:5]):  # Limit to 5 patterns
            rule += f"\n        $hex{i} = {{ {pattern} }}"

        # Add specific patterns based on category
        if category == RuleCategory.LICENSE:
            rule += '\n        $lic1 = "Invalid license" nocase'
            rule += '\n        $lic2 = "License expired" nocase'
            rule += '\n        $lic3 = "Trial period" nocase'

        elif category == RuleCategory.PACKER:
            # Add section name checks
            if metadata.get("sections"):
                for section in metadata["sections"]:
                    if section["entropy"] > 7.0:  # High entropy section
                        rule += f'\n        $packed_section = "{section["name"]}"'

        # Generate condition
        num_strings = len(strings[:20]) + len(hex_patterns[:5])
        condition = self.generate_condition(num_strings, category.value, add_pe_check=True)

        rule += f"\n    condition:\n        {condition}\n}}"

        # Optimize and validate
        rule = self.optimize_rule(rule)
        is_valid, error = self.validate_rule_syntax(rule)

        if not is_valid:
            logger.error(f"Generated rule has syntax error: {error}")
            # Return simplified version
            return f"""rule {safe_name} {{
    meta:
        description = "Simplified auto-generated rule"
        category = "{category.value}"
    strings:
        $a = "{file_path.name}"
    condition:
        $a
}}"""

        return rule

    def initialize_patch_database(self) -> None:
        """Initialize the patch suggestion database with known bypass patterns."""
        self.patch_database = {
            # License validation bypasses
            "License_Check_Patterns": [
                {
                    "match_pattern": "Invalid license",
                    "patch_type": "string_replace",
                    "original": b"Invalid license",
                    "replacement": b"Valid license\x00\x00",
                    "confidence": 0.85,
                    "description": "Replace invalid license message with valid",
                },
                {
                    "match_pattern": "License expired",
                    "patch_type": "nop_sequence",
                    "target_instruction": "jz",
                    "confidence": 0.90,
                    "description": "NOP out license expiry check jump",
                },
                {
                    "match_pattern": "Trial period",
                    "patch_type": "conditional_jump",
                    "original": b"\x74",  # JZ
                    "replacement": b"\x75",  # JNZ
                    "confidence": 0.88,
                    "description": "Invert trial period check",
                },
            ],
            # VMProtect bypasses
            "VMProtect_Protector": [
                {
                    "match_pattern": ".vmp0",
                    "patch_type": "section_decrypt",
                    "algorithm": "vmprotect_v3",
                    "confidence": 0.75,
                    "description": "Decrypt VMProtect virtualized section",
                },
                {
                    "match_pattern": "VMProtect",
                    "patch_type": "anti_debug_bypass",
                    "method": "peb_patch",
                    "confidence": 0.82,
                    "description": "Bypass VMProtect debugger detection",
                },
            ],
            # Themida bypasses
            "Themida_Protector": [
                {
                    "match_pattern": "SecureEngineSDK.dll",
                    "patch_type": "dll_hijack",
                    "target_dll": "SecureEngineSDK.dll",
                    "confidence": 0.70,
                    "description": "Hijack Themida SDK library",
                },
                {
                    "match_pattern": ".themida",
                    "patch_type": "iat_hook",
                    "target_api": "GetSystemTime",
                    "confidence": 0.78,
                    "description": "Hook time-based checks",
                },
            ],
            # FlexLM bypasses
            "FlexLM_License": [
                {
                    "match_pattern": "lc_checkout",
                    "patch_type": "api_hook",
                    "target_api": "lc_checkout",
                    "return_value": 0,
                    "confidence": 0.92,
                    "description": "Hook FlexLM checkout to always succeed",
                },
                {
                    "match_pattern": "vendor daemon",
                    "patch_type": "process_patch",
                    "target_process": "lmgrd.exe",
                    "confidence": 0.65,
                    "description": "Patch FlexLM daemon process",
                },
            ],
            # Sentinel HASP bypasses
            "Sentinel_HASP": [
                {
                    "match_pattern": "hasp_login",
                    "patch_type": "api_hook",
                    "target_api": "hasp_login",
                    "return_value": 0,  # HASP_STATUS_OK
                    "confidence": 0.89,
                    "description": "Hook HASP login to return success",
                },
                {
                    "match_pattern": "hasp_encrypt",
                    "patch_type": "function_bypass",
                    "method": "return_input",
                    "confidence": 0.76,
                    "description": "Bypass HASP encryption",
                },
            ],
            # Anti-debugging bypasses
            "AntiDebug_IsDebuggerPresent": [
                {
                    "match_pattern": "IsDebuggerPresent",
                    "patch_type": "api_hook",
                    "target_api": "IsDebuggerPresent",
                    "return_value": 0,
                    "confidence": 0.95,
                    "description": "Hook IsDebuggerPresent to return false",
                },
                {
                    "match_pattern": "CheckRemoteDebuggerPresent",
                    "patch_type": "api_hook",
                    "target_api": "CheckRemoteDebuggerPresent",
                    "return_value": 0,
                    "confidence": 0.93,
                    "description": "Hook CheckRemoteDebuggerPresent",
                },
            ],
            # Timing attack bypasses
            "AntiDebug_Timing": [
                {
                    "match_pattern": "rdtsc",
                    "patch_type": "instruction_patch",
                    "original": b"\x0f\x31",  # RDTSC
                    "replacement": b"\x31\xc0",  # XOR EAX,EAX
                    "confidence": 0.80,
                    "description": "Replace RDTSC with constant value",
                },
                {
                    "match_pattern": "QueryPerformanceCounter",
                    "patch_type": "api_hook",
                    "target_api": "QueryPerformanceCounter",
                    "method": "constant_value",
                    "confidence": 0.85,
                    "description": "Return constant performance counter",
                },
            ],
        }

        # Initialize patch statistics
        self.patch_statistics = {
            "total_suggestions": 0,
            "successful_patches": 0,
            "failed_patches": 0,
            "confidence_threshold": 0.70,
        }

        logger.info("Patch database initialized with %d rule patterns", len(self.patch_database))

    def get_patch_suggestions(
        self, matches: list[YaraMatch], min_confidence: float = 0.70
    ) -> list[dict[str, Any]]:
        """Get patch suggestions based on YARA matches.

        Args:
            matches: List of YARA matches
            min_confidence: Minimum confidence threshold

        Returns:
            List of patch suggestions

        """
        if not hasattr(self, "patch_database"):
            self.initialize_patch_database()

        suggestions = []
        seen_patches = set()

        for match in matches:
            # Look up patches for this rule
            if match.rule_name in self.patch_database:
                rule_patches = self.patch_database[match.rule_name]

                for patch in rule_patches:
                    # Check confidence threshold
                    if patch["confidence"] < min_confidence:
                        continue

                    # Create unique patch identifier
                    patch_id = f"{patch['patch_type']}_{patch.get('target_api', '')}_{patch.get('target_instruction', '')}"

                    if patch_id not in seen_patches:
                        seen_patches.add(patch_id)

                        suggestion = {
                            "rule_name": match.rule_name,
                            "match_offset": match.offset,
                            "patch_type": patch["patch_type"],
                            "confidence": patch["confidence"],
                            "description": patch["description"],
                            "patch_data": self._generate_patch_data(patch, match),
                            "risk_level": self._assess_patch_risk(patch),
                            "complexity": self._assess_patch_complexity(patch),
                            "category": match.category.value,
                        }

                        suggestions.append(suggestion)

        # Sort by confidence
        suggestions.sort(key=lambda x: x["confidence"], reverse=True)

        self.patch_statistics["total_suggestions"] += len(suggestions)

        return suggestions

    def _generate_patch_data(self, patch: dict[str, Any], match: YaraMatch) -> dict[str, Any]:
        """Generate actual patch data based on patch type.

        Args:
            patch: Patch template
            match: YARA match information

        Returns:
            Patch data dictionary

        """
        patch_data = {"type": patch["patch_type"], "offset": match.offset}

        if patch["patch_type"] == "string_replace":
            patch_data["original"] = patch["original"]
            patch_data["replacement"] = patch["replacement"]

        elif patch["patch_type"] == "nop_sequence":
            # Calculate NOP length based on instruction
            patch_data["length"] = len(patch.get("original", b"\x74\x00"))
            patch_data["nop_bytes"] = b"\x90" * patch_data["length"]

        elif patch["patch_type"] == "conditional_jump":
            patch_data["original"] = patch["original"]
            patch_data["replacement"] = patch["replacement"]

        elif patch["patch_type"] == "api_hook":
            patch_data["api_name"] = patch["target_api"]
            patch_data["return_value"] = patch.get("return_value", 0)
            patch_data["hook_code"] = self._generate_hook_code(
                patch["target_api"], patch.get("return_value", 0)
            )

        elif patch["patch_type"] == "dll_hijack":
            patch_data["target_dll"] = patch["target_dll"]
            patch_data["proxy_dll"] = self._generate_proxy_dll_code(patch["target_dll"])

        elif patch["patch_type"] == "iat_hook":
            patch_data["target_api"] = patch["target_api"]
            patch_data["hook_method"] = "iat_patch"

        elif patch["patch_type"] == "instruction_patch":
            patch_data["original"] = patch["original"]
            patch_data["replacement"] = patch["replacement"]

        return patch_data

    def _generate_hook_code(self, api_name: str, return_value: int) -> bytes:
        """Generate hook code for API redirection.

        Args:
            api_name: Name of API to hook
            return_value: Value to return

        Returns:
            Hook shellcode

        """
        # x86 hook that returns specified value
        # MOV EAX, return_value
        # RET
        if return_value == 0:
            return b"\x31\xc0\xc3"  # XOR EAX,EAX; RET
        # MOV EAX, imm32; RET
        return b"\xb8" + return_value.to_bytes(4, "little") + b"\xc3"

    def _generate_proxy_dll_code(self, dll_name: str) -> str:
        """Generate proxy DLL code template.

        Args:
            dll_name: Name of DLL to proxy

        Returns:
            Proxy DLL source code

        """
        return f"""// Proxy DLL for {dll_name}
#include <windows.h>

extern "C" {{
    // Export forwarding to original DLL
    #pragma comment(linker, "/export:DllMain=original_{dll_name}.DllMain")

    BOOL APIENTRY DllMain(HMODULE hModule, DWORD dwReason, LPVOID lpReserved) {{
        if (dwReason == DLL_PROCESS_ATTACH) {{
            // Bypass license checks here
            return TRUE;
        }}
        return TRUE;
    }}
}}"""

    def _assess_patch_risk(self, patch: dict[str, Any]) -> str:
        """Assess risk level of a patch.

        Args:
            patch: Patch information

        Returns:
            Risk level (low, medium, high)

        """
        high_risk_types = ["dll_hijack", "process_patch", "section_decrypt"]
        medium_risk_types = ["api_hook", "iat_hook", "function_bypass"]
        if patch["patch_type"] in high_risk_types:
            return "high"
        if patch["patch_type"] in medium_risk_types:
            return "medium"
        low_risk_types = ["string_replace", "nop_sequence", "conditional_jump"]

        return "low" if patch["patch_type"] in low_risk_types else "unknown"

    def _assess_patch_complexity(self, patch: dict[str, Any]) -> str:
        """Assess complexity of applying a patch.

        Args:
            patch: Patch information

        Returns:
            Complexity level (simple, moderate, complex)

        """
        simple_types = ["string_replace", "nop_sequence", "conditional_jump"]
        moderate_types = ["api_hook", "instruction_patch"]
        if patch["patch_type"] in simple_types:
            return "simple"
        if patch["patch_type"] in moderate_types:
            return "moderate"
        complex_types = ["dll_hijack", "iat_hook", "section_decrypt", "process_patch"]

        return "complex" if patch["patch_type"] in complex_types else "unknown"

    def recommend_patch_sequence(
        self, suggestions: list[dict[str, Any]], target_success_rate: float = 0.80
    ) -> list[dict[str, Any]]:
        """Recommend optimal patch sequence based on confidence and dependencies.

        Args:
            suggestions: List of patch suggestions
            target_success_rate: Target cumulative success rate

        Returns:
            Ordered list of patches to apply

        """
        # Group patches by category
        categorized = {}
        for patch in suggestions:
            category = patch["category"]
            if category not in categorized:
                categorized[category] = []
            categorized[category].append(patch)

        # Build dependency graph
        dependencies = {
            "anti_debug": [],  # Apply first
            "protector": ["anti_debug"],  # After anti-debug
            "license": ["protector", "anti_debug"],  # After protections removed
            "packer": ["anti_debug"],  # After anti-debug
            "crypto": ["protector"],  # After protector
        }

        # Order patches based on dependencies
        ordered = []
        processed = set()

        def add_category_patches(category: str) -> None:
            if category in processed:
                return
            processed.add(category)

            # Process dependencies first
            if category in dependencies:
                for dep in dependencies[category]:
                    if dep in categorized:
                        add_category_patches(dep)

            # Add patches from this category
            if category in categorized:
                # Sort by confidence within category
                category_patches = sorted(
                    categorized[category], key=lambda x: x["confidence"], reverse=True
                )

                # Add until we reach target success rate
                cumulative_confidence = 1.0
                for patch in category_patches:
                    cumulative_confidence *= 1 - patch["confidence"]
                    ordered.append(patch)

                    if 1 - cumulative_confidence >= target_success_rate:
                        break

        # Process all categories
        for category in ["anti_debug", "protector", "packer", "crypto", "license"]:
            add_category_patches(category)

        return ordered

    def validate_patch(self, patch_data: dict[str, Any], target_file: Path) -> tuple[bool, str]:
        """Validate if a patch can be safely applied.

        Args:
            patch_data: Patch information
            target_file: File to patch

        Returns:
            Tuple of (is_valid, error_message)

        """
        try:
            with open(target_file, "rb") as f:
                f.seek(patch_data["offset"])
                current_bytes = f.read(len(patch_data.get("original", b"")))

            # Check if current bytes match expected
            if "original" in patch_data and current_bytes != patch_data["original"]:
                return False, "Original bytes don't match"

            # Check if patch size is valid
            if "replacement" in patch_data and len(patch_data["replacement"]) > len(patch_data["original"]):
                return False, "Replacement larger than original"

            return True, ""

        except Exception as e:
            return False, str(e)

    def apply_patch(
        self, patch_data: dict[str, Any], target_file: Path, backup: bool = True
    ) -> bool:
        """Apply a patch to target file.

        Args:
            patch_data: Patch information
            target_file: File to patch
            backup: Create backup before patching

        Returns:
            True if successful

        """
        import shutil

        try:
            # Create backup if requested
            if backup:
                backup_path = target_file.with_suffix(f"{target_file.suffix}.bak")
                shutil.copy2(target_file, backup_path)
                logger.info(f"Created backup: {backup_path}")

            # Apply patch based on type
            if patch_data["type"] in ["string_replace", "conditional_jump", "instruction_patch"]:
                with open(target_file, "r+b") as f:
                    f.seek(patch_data["offset"])
                    f.write(patch_data["replacement"])

            elif patch_data["type"] == "nop_sequence":
                with open(target_file, "r+b") as f:
                    f.seek(patch_data["offset"])
                    f.write(patch_data["nop_bytes"])

            else:
                logger.warning(
                    f"Patch type {patch_data['type']} requires additional implementation"
                )
                return False

            self.patch_statistics["successful_patches"] += 1
            logger.info(f"Successfully applied patch at offset 0x{patch_data['offset']:X}")
            return True

        except Exception as e:
            self.patch_statistics["failed_patches"] += 1
            logger.error(f"Failed to apply patch: {e}")
            return False

    def rollback_patch(self, target_file: Path) -> bool:
        """Rollback patch by restoring backup.

        Args:
            target_file: Patched file

        Returns:
            True if successful

        """
        import shutil

        backup_path = target_file.with_suffix(f"{target_file.suffix}.bak")

        if not backup_path.exists():
            logger.error("No backup file found")
            return False

        try:
            shutil.copy2(backup_path, target_file)
            logger.info("Patch rolled back successfully")
            return True
        except Exception as e:
            logger.error(f"Failed to rollback patch: {e}")
            return False

    def track_patch_effectiveness(self, patch_id: str, success: bool, notes: str = "") -> None:
        """Track effectiveness of applied patches.

        Args:
            patch_id: Unique patch identifier
            success: Whether patch was successful
            notes: Additional notes

        """
        if not hasattr(self, "_patch_history"):
            self._patch_history = []

        import time

        self._patch_history.append(
            {"patch_id": patch_id, "timestamp": time.time(), "success": success, "notes": notes}
        )

        # Update statistics
        if success:
            self.patch_statistics["successful_patches"] += 1
        else:
            self.patch_statistics["failed_patches"] += 1

    def get_patch_metrics(self) -> dict[str, Any]:
        """Get patch effectiveness metrics.

        Returns:
            Dictionary of metrics

        """
        if not hasattr(self, "_patch_history"):
            return {"success_rate": 0, "total_patches": 0}

        total = len(self._patch_history)
        successful = sum(bool(p["success"])
                     for p in self._patch_history)

        return {
            "success_rate": successful / total if total > 0 else 0,
            "total_patches": total,
            "successful": successful,
            "failed": total - successful,
            "statistics": self.patch_statistics,
        }

    def connect_to_debugger(self, debugger_instance: object) -> None:
        """Connect YaraScanner to a debugger instance for breakpoint integration.

        Args:
            debugger_instance: LicenseDebugger or compatible debugger instance

        """
        self.debugger = debugger_instance
        self.breakpoint_mapping = {}
        logger.info("Connected to debugger for breakpoint integration")

    def set_breakpoints_from_matches(
        self,
        matches: list[YaraMatch],
        auto_enable: bool = True,
        conditional: bool = False,
    ) -> list[dict[str, Any]]:
        """Set breakpoints at YARA match locations.

        Args:
            matches: List of YARA matches
            auto_enable: Automatically enable breakpoints
            conditional: Create conditional breakpoints

        Returns:
            List of created breakpoints

        """
        if not hasattr(self, "debugger") or not self.debugger:
            logger.error("No debugger connected. Use connect_to_debugger() first")
            return []

        breakpoints = []

        for match in matches:
            # Determine breakpoint type based on match category
            bp_type = self._determine_breakpoint_type(match)

            # Generate conditional expression if needed
            condition = None
            if conditional:
                condition = self._generate_breakpoint_condition(match)

            # Create breakpoint data
            bp_data = {
                "address": match.offset,
                "type": bp_type,
                "enabled": auto_enable,
                "condition": condition,
                "description": f"YARA: {match.rule_name}",
                "match_data": {
                    "rule": match.rule_name,
                    "category": match.category.value,
                    "confidence": match.confidence,
                },
                "actions": self._generate_breakpoint_actions(match),
            }

            # Set breakpoint using debugger
            try:
                if bp_type == "hardware":
                    # Use hardware breakpoint for critical matches
                    bp_id = self.debugger.set_hardware_breakpoint(
                        match.offset, condition=condition or "exec", size=1
                    )
                else:
                    # Use software breakpoint
                    bp_id = self.debugger.set_breakpoint(match.offset)

                if bp_id:
                    bp_data["id"] = bp_id
                    breakpoints.append(bp_data)
                    self.breakpoint_mapping[bp_id] = match

                    logger.info(f"Set breakpoint at 0x{match.offset:X} for {match.rule_name}")

            except Exception as e:
                logger.error(f"Failed to set breakpoint for {match.rule_name}: {e}")

        return breakpoints

    def _determine_breakpoint_type(self, match: YaraMatch) -> str:
        """Determine appropriate breakpoint type based on match.

        Args:
            match: YARA match information

        Returns:
            Breakpoint type (hardware, software, memory)

        """
        # Use hardware breakpoints for critical licensing checks
        hardware_categories = [RuleCategory.LICENSE, RuleCategory.CRYPTO]
        hardware_rules = [
            "License_Check_Patterns",
            "Serial_Number_Validation",
            "Trial_Expiration_Check",
            "Crypto_Signature_Validation",
        ]

        if match.category in hardware_categories or match.rule_name in hardware_rules:
            return "hardware"

        # Use memory breakpoints for data access
        memory_rules = ["Hardware_ID_Check", "License_File_Patterns"]
        return "memory" if match.rule_name in memory_rules else "software"

    def _generate_breakpoint_condition(self, match: YaraMatch) -> str:
        """Generate conditional breakpoint expression.

        Args:
            match: YARA match information

        Returns:
            Condition expression string

        """
        conditions = []

        # License-specific conditions
        if match.category == RuleCategory.LICENSE:
            if "serial" in match.rule_name.lower():
                # Break when serial validation function is called with specific pattern
                conditions.append("EAX != 0")  # Non-zero serial check

            elif "trial" in match.rule_name.lower():
                # Break when time check indicates expiration
                conditions.append("EAX > 0x1E")  # More than 30 days

            elif "activation" in match.rule_name.lower():
                # Break on activation server communication
                conditions.append("ECX == 0x50")  # POST request

        # Anti-debug conditions
        elif match.category == RuleCategory.ANTI_DEBUG:
            if "IsDebuggerPresent" in match.rule_name:
                conditions.append("EAX == 1")  # Debugger detected

            elif "Timing" in match.rule_name:
                # Break on timing discrepancies
                conditions.append("EDX - EAX > 0x1000")  # Large time delta

        # Protector conditions
        elif match.category == RuleCategory.PROTECTOR:
            if "VMProtect" in match.rule_name:
                conditions.append("ESP & 0xFFF == 0")  # Stack alignment check

            elif "Themida" in match.rule_name:
                conditions.append("[ESP] == 0x00400000")  # Image base check

        return " && ".join(conditions) if conditions else ""

    def _generate_breakpoint_actions(self, match: YaraMatch) -> list[dict[str, str]]:
        """Generate actions to perform when breakpoint is hit.

        Args:
            match: YARA match information

        Returns:
            List of actions

        """
        actions = [{"type": "log", "message": f"Hit {match.rule_name} at {{EIP}}"}]

        # Category-specific actions
        if match.category == RuleCategory.LICENSE:
            actions.extend(
                (
                    {
                        "type": "dump_registers",
                        "registers": ["EAX", "EBX", "ECX", "EDX"],
                    },
                    {"type": "dump_stack", "size": 32},
                )
            )
            if "serial" in match.rule_name.lower():
                # Capture serial number from memory
                actions.append({"type": "dump_memory", "address": "ECX", "size": 32})

        elif match.category == RuleCategory.ANTI_DEBUG:
            actions.extend(
                (
                    {"type": "modify_register", "register": "EAX", "value": 0},
                    {"type": "skip_instruction"},
                )
            )
        elif match.category == RuleCategory.CRYPTO:
            # Capture crypto keys
            actions.append({"type": "dump_memory", "address": "ESI", "size": 256})

        return actions

    def enable_match_tracing(self, matches: list[YaraMatch], trace_depth: int = 10) -> None:
        """Enable instruction tracing at match locations.

        Args:
            matches: List of YARA matches
            trace_depth: Number of instructions to trace

        """
        if not hasattr(self, "debugger") or not self.debugger:
            logger.error("No debugger connected")
            return

        for match in matches:
            try:
                # Set trace point
                self.debugger.trace_thread_execution(
                    start_address=match.offset,
                    num_instructions=trace_depth,
                    log_registers=True,
                    log_memory_access=True,
                )

                logger.info(f"Enabled tracing at 0x{match.offset:X} for {match.rule_name}")

            except Exception as e:
                logger.error(f"Failed to enable tracing for {match.rule_name}: {e}")

    def log_match_execution(self, match: YaraMatch, context: dict[str, Any]) -> None:
        """Log execution context when YARA match location is reached.

        Args:
            match: YARA match that triggered
            context: Execution context (registers, stack, etc.)

        """
        import json
        import time

        log_entry = {
            "timestamp": time.time(),
            "rule_name": match.rule_name,
            "category": match.category.value,
            "offset": match.offset,
            "context": {
                "registers": context.get("registers", {}),
                "stack_top": context.get("stack", [])[:8],
                "instruction": context.get("instruction", ""),
            },
        }

        with self._execution_log_lock:
            # Check if log has reached maximum size
            if len(self._execution_log) >= self._execution_log_max_size:
                # Rotate log by removing oldest entries (keep last 75% of max size)
                keep_count = int(self._execution_log_max_size * 0.75)
                self._execution_log = self._execution_log[-keep_count:]
                logger.debug(f"Execution log rotated, kept {keep_count} most recent entries")

            self._execution_log.append(log_entry)

        # Also write to debug log
        logger.debug(f"Match execution: {json.dumps(log_entry, indent=2)}")

    def set_match_triggered_action(
        self, rule_name: str, action_callback: Callable[[YaraMatch, dict[str, Any]], object]
    ) -> None:
        """Set a callback to execute when specific rule matches are hit.

        Args:
            rule_name: Name of YARA rule
            action_callback: Function to call when match is hit

        """
        if not hasattr(self, "_match_actions"):
            self._match_actions = {}

        self._match_actions[rule_name] = action_callback
        logger.info(f"Registered action for rule: {rule_name}")

    def trigger_match_action(self, match: YaraMatch, context: dict[str, Any]) -> object | None:
        """Trigger registered action for a match.

        Args:
            match: YARA match that triggered
            context: Execution context

        Returns:
            Action result

        """
        if not hasattr(self, "_match_actions"):
            return None

        if match.rule_name in self._match_actions:
            try:
                callback = self._match_actions[match.rule_name]
                result = callback(match, context)
                logger.info(f"Executed action for {match.rule_name}")
                return result
            except Exception as e:
                logger.error(f"Failed to execute action for {match.rule_name}: {e}")
                return None

        return None

    def correlate_matches(
        self, matches: list[YaraMatch], time_window: float = 1.0
    ) -> list[dict[str, Any]]:
        """Correlate YARA matches to identify related detections.

        Args:
            matches: List of YARA matches
            time_window: Time window for correlation (seconds)

        Returns:
            List of correlated match groups

        """
        # Group matches by time proximity
        correlations = []
        processed = set()

        for i, match1 in enumerate(matches):
            if i in processed:
                continue

            group = {"primary": match1, "related": [], "correlation_type": None}

            for j, match2 in enumerate(matches[i + 1 :], start=i + 1):
                if j in processed:
                    continue

                if correlation := self._check_match_correlation(match1, match2):
                    group["related"].append(match2)
                    group["correlation_type"] = correlation
                    processed.add(j)

            if group["related"]:
                processed.add(i)
                correlations.append(group)

        # Analyze correlation patterns
        patterns = self._analyze_correlation_patterns(correlations)

        return {"correlations": correlations, "patterns": patterns}

    def _check_match_correlation(self, match1: YaraMatch, match2: YaraMatch) -> str | None:
        """Check if two matches are correlated.

        Args:
            match1: First YARA match
            match2: Second YARA match

        Returns:
            Correlation type or None

        """
        # Check offset proximity
        offset_delta = abs(match1.offset - match2.offset)
        if offset_delta < 0x1000:  # Within 4KB
            return "proximity"

        # Check category correlation
        category_correlations = {
            (RuleCategory.LICENSE, RuleCategory.CRYPTO): "license_crypto",
            (RuleCategory.ANTI_DEBUG, RuleCategory.PROTECTOR): "protection_chain",
            (RuleCategory.PACKER, RuleCategory.PROTECTOR): "multi_layer",
        }

        cat_pair = (match1.category, match2.category)
        if cat_pair in category_correlations:
            return category_correlations[cat_pair]

        # Check rule name patterns
        if "serial" in match1.rule_name.lower() and "validation" in match2.rule_name.lower():
            return "serial_validation"

        if "trial" in match1.rule_name.lower() and "expir" in match2.rule_name.lower():
            return "trial_check"

        return None

    def _analyze_correlation_patterns(self, correlations: list[dict[str, Any]]) -> dict[str, Any]:
        """Analyze patterns in correlated matches.

        Args:
            correlations: List of correlation groups

        Returns:
            Pattern analysis results

        """
        # Count protection layers
        protection_categories = {
            RuleCategory.PACKER,
            RuleCategory.PROTECTOR,
            RuleCategory.ANTI_DEBUG,
        }
        protection_count = sum(bool(group["primary"].category in protection_categories
                                       or any(m.category in protection_categories for m in group["related"]))
                           for group in correlations)
        patterns = {
            "licensing_scheme": None,
            "complexity": "low",
            "protection_layers": protection_count,
        }
        # Identify licensing scheme
        license_indicators = {
            "flexlm": ["FlexLM", "lc_checkout"],
            "hasp": ["HASP", "hasp_login"],
            "custom": ["Serial_Number", "Trial_"],
        }

        for scheme, indicators in license_indicators.items():
            for group in correlations:
                all_matches = [group["primary"]] + group["related"]
                if any(any(ind in m.rule_name for ind in indicators) for m in all_matches):
                    patterns["licensing_scheme"] = scheme
                    break

        # Assess complexity
        if protection_count > 2:
            patterns["complexity"] = "high"
        elif protection_count > 0:
            patterns["complexity"] = "medium"

        return patterns

    def generate_breakpoint_script(self, matches: list[YaraMatch], script_type: str = "gdb") -> str:
        """Generate debugger script for setting breakpoints.

        Args:
            matches: List of YARA matches
            script_type: Type of script (gdb, windbg, x64dbg)

        Returns:
            Script content

        """
        script = []

        if script_type == "gdb":
            script.extend(("# GDB Breakpoint Script", "# Generated from YARA matches"))
            script.append("")

            for match in matches:
                # Set breakpoint
                script.append(f"# Rule: {match.rule_name}")
                script.append(f"break *0x{match.offset:X}")

                if condition := self._generate_breakpoint_condition(match):
                    script.append(f"condition $bpnum {condition}")

                script.append("commands")
                script.append(f'printf "Hit {match.rule_name} at %p\\n", $pc')
                script.append("info registers")
                script.append("x/8xw $esp")
                script.append("continue")
                script.append("end")
                script.append("")

        elif script_type == "windbg":
            script.append("$$ WinDbg Breakpoint Script")
            script.append("$$ Generated from YARA matches")
            script.append("")

            for match in matches:
                script.append(f"$$ Rule: {match.rule_name}")
                script.append(f"bp 0x{match.offset:X}")

                if condition := self._generate_breakpoint_condition(match):
                    # Convert to WinDbg syntax
                    condition = condition.replace("EAX", "@eax").replace("&&", "and")
                    script.append(f'bp 0x{match.offset:X} "{condition}"')

                script.append("")

        elif script_type == "x64dbg":
            script.append("// x64dbg Script")
            script.append("// Generated from YARA matches")
            script.append("")

            for match in matches:
                script.append(f"// Rule: {match.rule_name}")
                script.append(f"bp 0x{match.offset:X}")
                script.append(f'log "Hit {match.rule_name}"')
                script.append("")

        return "\n".join(script)

    def export_breakpoint_config(
        self, breakpoints: list[dict[str, Any]], output_path: Path
    ) -> None:
        """Export breakpoint configuration to file.

        Args:
            breakpoints: List of breakpoint data
            output_path: Path to save configuration

        """
        import json

        config = {
            "version": "1.0",
            "timestamp": output_path.parent.stat().st_mtime if output_path.parent.exists() else 0,
            "breakpoints": breakpoints,
            "statistics": {
                "total": len(breakpoints),
                "hardware": sum(bool(bp["type"] == "hardware")
                            for bp in breakpoints),
            },
        }

        with open(output_path, "w") as f:
            json.dump(config, f, indent=2)

        logger.info(f"Exported {len(breakpoints)} breakpoints to {output_path}")

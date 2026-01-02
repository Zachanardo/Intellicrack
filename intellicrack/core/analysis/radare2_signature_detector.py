#!/usr/bin/env python3
"""Radare2 Signature-Based Detection System.

Production-ready implementation for:
- YARA rule integration
- ClamAV signature support
- Custom signature language
- Protection scheme fingerprinting
- Compiler detection
- Library version identification
"""

import hashlib
import json
import logging
import re
import subprocess
import tempfile
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Any

import r2pipe
import yara


logger = logging.getLogger(__name__)


class SignatureType(Enum):
    """Types of signatures that can be detected."""

    YARA = "yara"
    CLAMAV = "clamav"
    CUSTOM = "custom"
    PROTECTION = "protection"
    COMPILER = "compiler"
    LIBRARY = "library"
    MALWARE = "malware"
    PACKER = "packer"
    CRYPTO = "crypto"


@dataclass
class SignatureMatch:
    """Information about a signature match."""

    signature_type: SignatureType
    name: str
    offset: int
    size: int
    confidence: float
    metadata: dict[str, Any]
    raw_match: Any | None = None


@dataclass
class CompilerInfo:
    """Compiler detection information."""

    compiler: str
    version: str
    optimization_level: str
    architecture: str
    metadata: dict[str, Any]


@dataclass
class LibraryInfo:
    """Library version information."""

    name: str
    version: str
    functions: list[str]
    imports: list[str]
    metadata: dict[str, Any]


class Radare2SignatureDetector:
    """Advanced signature-based detection using Radare2."""

    def __init__(self, binary_path: str) -> None:
        """Initialize the Radare2SignatureDetector with a binary file path.

        Args:
            binary_path: Path to the binary file to analyze.

        Returns:
            None.

        Raises:
            No exceptions raised by this method.
        """
        self.binary_path = binary_path
        self.r2: Any = None
        self.matches: list[SignatureMatch] = []
        self.yara_rules: list[yara.Rules] = []
        self.custom_signatures: dict[str, bytes] = {}
        self.file_hash = self._calculate_file_hash()

    def _calculate_file_hash(self) -> dict[str, str | int]:
        """Calculate various hashes of the binary.

        Computes SHA256 and SHA512 hashes of the binary file and returns file
        size along with the hashes.

        Returns:
            Dictionary containing SHA256, SHA512 hashes and file size in bytes.

        Raises:
            OSError: If the binary file cannot be read.
            IOError: If an I/O error occurs while reading the file.
        """
        hashes: dict[str, str | int] = {}
        with open(self.binary_path, "rb") as f:
            data = f.read()
            hashes["sha256"] = hashlib.sha256(data).hexdigest()
            hashes["sha512"] = hashlib.sha512(data).hexdigest()
            hashes["size"] = len(data)
        return hashes

    def open(self) -> bool:
        """Open binary in Radare2.

        Initializes r2pipe session with the binary file and performs initial
        analysis using the "aaa" command.

        Returns:
            True if binary was successfully opened, False otherwise.

        Raises:
            Exception: Caught and logged if binary opening fails, returns False
                in such cases.
        """
        try:
            self.r2 = r2pipe.open(self.binary_path)
            self.r2.cmd("aaa")  # Analyze
            logger.info("Opened %s for signature detection", self.binary_path)
            return True
        except Exception as e:
            logger.exception("Failed to open binary: %s", e)
            return False

    def load_yara_rules(self, rules_path: str) -> bool:
        """Load YARA rules from file or directory.

        Loads YARA rule files from a single file or from all rule files in a
        directory. Supports .yar and .yara file extensions.

        Args:
            rules_path: Path to YARA rule file or directory containing rules.

        Returns:
            True if at least one rule was loaded successfully, False otherwise.

        Raises:
            Exception: Caught and logged if rule loading fails, returns False
                in such cases.
        """
        try:
            path = Path(rules_path)

            if path.is_file():
                # Single rule file
                rules = yara.compile(filepath=str(path))
                self.yara_rules.append(rules)
                logger.info("Loaded YARA rules from %s", path)

            elif path.is_dir():
                # Directory of rule files
                for rule_file in path.glob("*.yar*"):
                    try:
                        rules = yara.compile(filepath=str(rule_file))
                        self.yara_rules.append(rules)
                        logger.info("Loaded YARA rules from %s", rule_file)
                    except Exception as e:
                        logger.warning("Failed to load %s: %s", rule_file, e)

            return len(self.yara_rules) > 0

        except Exception as e:
            logger.exception("Failed to load YARA rules: %s", e)
            return False

    def create_default_yara_rules(self) -> str:
        """Create comprehensive default YARA rules for common protections.

        Generates built-in YARA rule definitions for detecting common protections,
        packers, compilers, and licensing mechanisms including VMProtect, Themida,
        ASProtect, UPX, Armadillo, and various license managers.

        Returns:
            YARA rule definitions as string containing signatures for
            protection schemes, packers, compilers, and licensing mechanisms.

        Raises:
            No exceptions raised by this method.
        """
        return """
rule VMProtect_Signature {
    meta:
        description = "VMProtect packer/protector"
        author = "Intellicrack"
    strings:
        $vmp1 = ".vmp0" ascii
        $vmp2 = ".vmp1" ascii
        $vmp3 = ".vmp2" ascii
        $vmp4 = "VMProtect" ascii wide
        $vmp5 = { E8 ?? ?? ?? ?? 8B ?? ?? ?? ?? ?? 89 ?? ?? ?? ?? ?? E9 }
    condition:
        uint16(0) == 0x5A4D and (any of ($vmp*))
}

rule Themida_Signature {
    meta:
        description = "Themida/WinLicense protector"
        author = "Intellicrack"
    strings:
        $themida1 = "Themida" ascii wide
        $themida2 = ".themida" ascii
        $themida3 = "SecureEngine" ascii
        $themida4 = { B8 ?? ?? ?? ?? 60 0B C0 74 68 }
        $themida5 = { 55 8B EC 83 C4 D8 53 56 57 8B 45 }
    condition:
        uint16(0) == 0x5A4D and (any of ($themida*))
}

rule ASProtect_Signature {
    meta:
        description = "ASProtect packer"
        author = "Intellicrack"
    strings:
        $asp1 = "ASProtect" ascii wide
        $asp2 = ".aspr" ascii
        $asp3 = ".adata" ascii
        $asp4 = { 60 E8 03 00 00 00 E9 EB 04 5D 45 55 C3 E8 01 }
        $asp5 = { 68 01 ?? ?? ?? C1 ?? ?? ?? ?? ?? ?? ?? ?? ?? E8 }
    condition:
        uint16(0) == 0x5A4D and (any of ($asp*))
}

rule UPX_Packer {
    meta:
        description = "UPX executable packer"
        author = "Intellicrack"
    strings:
        $upx1 = "UPX!" ascii
        $upx2 = "UPX0" ascii
        $upx3 = "UPX1" ascii
        $upx4 = "UPX2" ascii
        $upx5 = { 55 50 58 21 ?? ?? ?? ?? 55 50 58 }
    condition:
        uint16(0) == 0x5A4D and (any of ($upx*))
}

rule Armadillo_Protector {
    meta:
        description = "Armadillo protector"
        author = "Intellicrack"
    strings:
        $arm1 = "Armadillo" ascii wide
        $arm2 = "arma.dll" ascii
        $arm3 = "ArmAccess.dll" ascii
        $arm4 = { 60 E8 00 00 00 00 5D 50 51 EB 0F }
        $arm5 = { 55 8B EC 6A FF 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 64 A1 }
    condition:
        uint16(0) == 0x5A4D and (any of ($arm*))
}

rule Enigma_Protector {
    meta:
        description = "Enigma Protector"
        author = "Intellicrack"
    strings:
        $enigma1 = "Enigma protector" ascii wide
        $enigma2 = ".enigma1" ascii
        $enigma3 = ".enigma2" ascii
        $enigma4 = { 60 E8 00 00 00 00 5D 83 ED 06 81 }
        $enigma5 = { 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 }
    condition:
        uint16(0) == 0x5A4D and (any of ($enigma*))
}

rule MPRESS_Packer {
    meta:
        description = "MPRESS packer"
        author = "Intellicrack"
    strings:
        $mpress1 = "MPRESS" ascii
        $mpress2 = ".MPRESS1" ascii
        $mpress3 = ".MPRESS2" ascii
        $mpress4 = { 60 E9 ?? ?? ?? ?? 52 50 52 45 53 53 }
    condition:
        uint16(0) == 0x5A4D and (any of ($mpress*))
}

rule PECompact_Packer {
    meta:
        description = "PECompact packer"
        author = "Intellicrack"
    strings:
        $pec1 = "PECompact" ascii
        $pec2 = "PEC2" ascii
        $pec3 = { B8 ?? ?? ?? ?? 50 64 FF 35 00 00 00 00 }
        $pec4 = { 33 C0 8B C8 8B D0 }
    condition:
        uint16(0) == 0x5A4D and (any of ($pec*))
}

rule ASPack_Packer {
    meta:
        description = "ASPack packer"
        author = "Intellicrack"
    strings:
        $aspack1 = "ASPack" ascii
        $aspack2 = ".aspack" ascii
        $aspack3 = { 60 E8 ?? ?? ?? ?? 5D 81 ED ?? ?? ?? ?? B8 ?? ?? ?? ?? 03 C5 }
        $aspack4 = { 60 EB 0A 5D EB 02 FF 25 45 FF E5 E8 }
    condition:
        uint16(0) == 0x5A4D and (any of ($aspack*))
}

rule Obsidium_Protector {
    meta:
        description = "Obsidium protector"
        author = "Intellicrack"
    strings:
        $obs1 = "Obsidium" ascii wide
        $obs2 = "obsidium.dll" ascii
        $obs3 = { EB 02 ?? ?? E8 ?? 00 00 00 }
        $obs4 = { 50 51 52 53 54 55 56 57 }
    condition:
        uint16(0) == 0x5A4D and (any of ($obs*))
}

rule NsPack_Packer {
    meta:
        description = "NsPack packer"
        author = "Intellicrack"
    strings:
        $nsp1 = "nsp0" ascii
        $nsp2 = "nsp1" ascii
        $nsp3 = "nsp2" ascii
        $nsp4 = { 9C 60 E8 00 00 00 00 5D 83 ED 07 8D }
    condition:
        uint16(0) == 0x5A4D and (any of ($nsp*))
}

rule PELock_Protector {
    meta:
        description = "PELock protector"
        author = "Intellicrack"
    strings:
        $pel1 = "PELock" ascii wide
        $pel2 = "PELOCK" ascii
        $pel3 = { EB 03 CD 20 EB EB 01 EB 1E EB 01 EB EB 02 CD 20 }
    condition:
        uint16(0) == 0x5A4D and (any of ($pel*))
}

rule ExeCryptor_Protector {
    meta:
        description = "ExeCryptor protector"
        author = "Intellicrack"
    strings:
        $exe1 = "ExeCryptor" ascii wide
        $exe2 = "EXECryptor" ascii
        $exe3 = { E8 24 00 00 00 8B 4C 24 0C C7 01 17 00 01 00 C7 81 }
        $exe4 = { A4 AF AA 1E 1F 46 4F 5F 5F 7C 7C 77 }
    condition:
        uint16(0) == 0x5A4D and (any of ($exe*))
}

rule Petite_Packer {
    meta:
        description = "Petite packer"
        author = "Intellicrack"
    strings:
        $petite1 = "petite" ascii
        $petite2 = ".petite" ascii
        $petite3 = { B8 ?? ?? ?? ?? 6A ?? 68 ?? ?? ?? ?? 64 FF 35 }
    condition:
        uint16(0) == 0x5A4D and (any of ($petite*))
}

rule RLPack_Packer {
    meta:
        description = "RLPack packer"
        author = "Intellicrack"
    strings:
        $rlp1 = "RLPack" ascii
        $rlp2 = ".RLPack" ascii
        $rlp3 = { 60 E8 00 00 00 00 8B 2C 24 83 C4 04 }
        $rlp4 = { 80 7C 24 08 01 0F 85 ?? ?? ?? ?? 60 E8 00 00 00 00 }
    condition:
        uint16(0) == 0x5A4D and (any of ($rlp*))
}

rule TELock_Protector {
    meta:
        description = "TELock protector"
        author = "Intellicrack"
    strings:
        $tel1 = "TELock" ascii
        $tel2 = ".tel0" ascii
        $tel3 = { E8 00 00 00 00 60 E8 00 00 00 00 58 }
    condition:
        uint16(0) == 0x5A4D and (any of ($tel*))
}

rule yoda_Protector {
    meta:
        description = "yoda's Protector"
        author = "Intellicrack"
    strings:
        $yoda1 = "yoda's Protector" ascii
        $yoda2 = ".yP" ascii
        $yoda3 = { 55 8B EC 53 56 57 60 E8 00 00 00 00 5D 81 ED }
    condition:
        uint16(0) == 0x5A4D and (any of ($yoda*))
}

rule FlexLM_License {
    meta:
        description = "FlexLM license manager"
        author = "Intellicrack"
    strings:
        $flex1 = "FLEXlm" ascii wide
        $flex2 = "lmgrd" ascii
        $flex3 = "license.dat" ascii
        $flex4 = "VENDOR_LICENSE_FILE" ascii
        $flex5 = { 46 4C 45 58 6C 6D }
    condition:
        any of ($flex*)
}

rule Sentinel_HASP {
    meta:
        description = "Sentinel HASP protection"
        author = "Intellicrack"
    strings:
        $hasp1 = "hasp" ascii wide nocase
        $hasp2 = "hardlock" ascii wide nocase
        $hasp3 = "Sentinel" ascii wide
        $hasp4 = "hasplms" ascii
    condition:
        any of ($hasp*)
}

rule CodeMeter_Protection {
    meta:
        description = "CodeMeter protection"
        author = "Intellicrack"
    strings:
        $cm1 = "CodeMeter" ascii wide
        $cm2 = "WibuCm" ascii
        $cm3 = "CmDongle" ascii
        $cm4 = { 57 69 62 75 43 6D }
    condition:
        any of ($cm*)
}

rule Microsoft_VisualStudio_Compiler {
    meta:
        description = "Microsoft Visual Studio compiled binary"
        author = "Intellicrack"
    strings:
        $msvc1 = "Microsoft Visual" ascii wide
        $msvc2 = "MSVC" ascii
        $msvc3 = { 52 69 63 68 ?? ?? ?? ?? 00 00 00 00 00 00 00 00 50 45 }
        $runtime1 = "msvcrt.dll" ascii
        $runtime2 = "msvcp" ascii
    condition:
        uint16(0) == 0x5A4D and (any of ($msvc*) or all of ($runtime*))
}

rule GCC_Compiler {
    meta:
        description = "GCC compiled binary"
        author = "Intellicrack"
    strings:
        $gcc1 = "GCC:" ascii
        $gcc2 = "GNU C" ascii
        $gcc3 = "mingw" ascii nocase
        $gcc4 = "__gcc" ascii
        $gcc5 = "__GNUC__" ascii
    condition:
        any of ($gcc*)
}

rule Clang_Compiler {
    meta:
        description = "Clang/LLVM compiled binary"
        author = "Intellicrack"
    strings:
        $clang1 = "clang" ascii
        $clang2 = "LLVM" ascii
        $clang3 = "__clang__" ascii
        $clang4 = "Apple LLVM" ascii
    condition:
        any of ($clang*)
}

rule Borland_Delphi_Compiler {
    meta:
        description = "Borland Delphi compiled binary"
        author = "Intellicrack"
    strings:
        $delphi1 = "Borland" ascii wide
        $delphi2 = "Delphi" ascii wide
        $delphi3 = "SOFTWARE\\Borland\\Delphi" ascii wide
        $delphi4 = { 50 45 00 00 4C 01 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 0B 01 }
        $forms = "TForm" ascii
    condition:
        uint16(0) == 0x5A4D and (any of ($delphi*) or $forms)
}

rule OpenSSL_Library {
    meta:
        description = "OpenSSL cryptographic library"
        author = "Intellicrack"
    strings:
        $ssl1 = "OpenSSL" ascii wide
        $ssl2 = "SSLeay" ascii
        $ssl3 = "libssl" ascii
        $ssl4 = "libcrypto" ascii
        $ssl5 = { 53 53 4C 65 61 79 }
    condition:
        any of ($ssl*)
}

rule CryptoAPI_Usage {
    meta:
        description = "Windows CryptoAPI usage"
        author = "Intellicrack"
    strings:
        $crypt1 = "CryptAcquireContext" ascii
        $crypt2 = "CryptCreateHash" ascii
        $crypt3 = "CryptEncrypt" ascii
        $crypt4 = "CryptDecrypt" ascii
        $crypt5 = "advapi32.dll" ascii
    condition:
        $crypt5 and (2 of ($crypt1, $crypt2, $crypt3, $crypt4))
}
"""

    def scan_with_yara(self) -> list[SignatureMatch]:
        """Scan binary with loaded YARA rules.

        Scans the binary file using all loaded YARA rule sets. If no rules are
        loaded, creates and uses default rules for common protections, packers,
        and compilers. Adds all matches to the internal match list.

        Returns:
            List of SignatureMatch objects containing YARA rule matches found
            in the binary file.

        Raises:
            Exception: Caught and logged if YARA scanning fails, returns empty
                list in such cases.
        """
        matches = []

        try:
            # If no rules loaded, create defaults
            if not self.yara_rules:
                default_rules = self.create_default_yara_rules()
                with tempfile.NamedTemporaryFile(mode="w", suffix=".yar", delete=False) as f:
                    f.write(default_rules)
                    temp_path = f.name

                rules = yara.compile(filepath=temp_path)
                self.yara_rules.append(rules)
                Path(temp_path).unlink()

            # Scan with each rule set
            for rules in self.yara_rules:
                yara_matches = rules.match(self.binary_path)

                for match in yara_matches:
                    for string_match in match.strings:
                        sig_match = SignatureMatch(
                            signature_type=SignatureType.YARA,
                            name=match.rule,
                            offset=string_match[0],
                            size=len(string_match[2]),
                            confidence=1.0,
                            metadata={
                                "namespace": match.namespace,
                                "tags": match.tags,
                                "meta": match.meta,
                                "string_id": string_match[1],
                            },
                            raw_match=match,
                        )
                        matches.append(sig_match)
                        logger.info("YARA match: %s at offset %s", match.rule, hex(string_match[0]))

        except Exception as e:
            logger.exception("YARA scanning failed: %s", e)

        self.matches.extend(matches)
        return matches

    def scan_with_clamav(self) -> list[SignatureMatch]:
        """Scan binary with ClamAV.

        Executes ClamAV antivirus scanner on the binary file to detect known
        malware and threat signatures. Requires clamscan to be installed and
        available in the system PATH. Adds all detected matches to the
        internal match list.

        Returns:
            List of SignatureMatch objects containing ClamAV detections. Returns
            empty list if ClamAV is not installed or scanning fails.

        Raises:
            FileNotFoundError: Caught if clamscan is not found, logs debug
                message and returns empty list.
            Exception: Caught and logged if ClamAV scanning fails, returns
                empty list in such cases.
        """
        matches = []

        try:
            # Check if clamscan is available
            result = subprocess.run(["clamscan", "--version"], capture_output=True, text=True)

            if result.returncode == 0:
                # Run ClamAV scan
                # Validate binary_path to prevent command injection
                binary_path_clean = str(self.binary_path).replace(";", "").replace("|", "").replace("&", "")
                result = subprocess.run(
                    ["clamscan", "--no-summary", "--infected", binary_path_clean],
                    capture_output=True,
                    text=True,
                    shell=False,
                )

                # Parse output
                for line in result.stdout.split("\n"):
                    if "FOUND" in line:
                        parts = line.split(":")
                        if len(parts) >= 2:
                            threat_name = parts[1].strip().replace(" FOUND", "")

                            file_size = self.file_hash["size"]
                            if not isinstance(file_size, int):
                                file_size = 0
                            sig_match = SignatureMatch(
                                signature_type=SignatureType.CLAMAV,
                                name=threat_name,
                                offset=0,
                                size=file_size,
                                confidence=0.95,
                                metadata={"scanner": "ClamAV", "file_path": self.binary_path},
                            )
                            matches.append(sig_match)
                            logger.info("ClamAV detection: %s", threat_name)

        except FileNotFoundError:
            logger.debug("ClamAV not installed, skipping ClamAV scan")
        except Exception as e:
            logger.exception("ClamAV scanning failed: %s", e)

        self.matches.extend(matches)
        return matches

    def create_custom_signatures(self) -> None:
        """Create custom binary signatures.

        Populates the custom_signatures dictionary with byte patterns for
        protection schemes, license checks, trial mechanisms, hardware IDs,
        anti-debug techniques, and cryptographic algorithms. Includes signatures
        for VMProtect, Themida, licensing validation functions, trial period
        checks, hardware identification routines, and crypto operations.

        Returns:
            None. Directly modifies self.custom_signatures dictionary.

        Raises:
            No exceptions raised by this method.
        """
        # Common protection signatures
        self.custom_signatures = {
            # VMProtect signatures
            "VMProtect_1": b"\x8b\x45\x00\x8b\x00\x8b\x4d\x00\x8b\x09\x89\x45\x00\x89\x4d",
            "VMProtect_2": b"\x9c\x60\xe8\x00\x00\x00\x00\x5d\x81\xed",
            "VMProtect_3": b"\x68\x00\x00\x00\x00\xe8\x00\x00\x00\x00\x58\x05",
            # Themida signatures
            "Themida_1": b"\xb8\x00\x00\x00\x00\x60\x0b\xc0\x74\x68",
            "Themida_2": b"\x8b\xc5\x8b\xd5\x60\x89\xc5\x89\xd5",
            "Themida_3": b"\xe8\x00\x00\x00\x00\x58\x05\x00\x00\x00\x00\x8b\x30\x03\xf0",
            # License check patterns
            "License_Check_1": b"IsLicenseValid",
            "License_Check_2": b"CheckLicense",
            "License_Check_3": b"VerifyLicense",
            "License_Check_4": b"ValidateLicense",
            "License_Check_5": b"GetLicenseInfo",
            # Trial check patterns
            "Trial_Check_1": b"IsTrialExpired",
            "Trial_Check_2": b"CheckTrialPeriod",
            "Trial_Check_3": b"GetTrialDays",
            "Trial_Check_4": b"trial_days_left",
            # Hardware ID patterns
            "HWID_1": b"GetVolumeSerialNumber",
            "HWID_2": b"GetAdaptersInfo",
            "HWID_3": b"HARDWARE\\DESCRIPTION\\System",
            "HWID_4": b"MachineGuid",
            # Anti-debug patterns
            "AntiDebug_1": b"\x64\xa1\x30\x00\x00\x00",  # fs:[30h] PEB access
            "AntiDebug_2": b"\x64\xa1\x18\x00\x00\x00",  # fs:[18h] TEB access
            "AntiDebug_3": b"\x31\xc0\x64\x8b\x70\x30",  # xor eax, eax; mov esi, fs:[eax+30h]
            # Crypto patterns
            "Crypto_AES": b"AES",
            "Crypto_RSA": b"RSA",
            "Crypto_SHA": b"SHA",
            "Crypto_MD5": b"MD5",
        }

    def scan_custom_signatures(self) -> list[SignatureMatch]:
        """Scan with custom signatures.

        Scans the binary file for all custom signature patterns. Creates default
        signatures if none are already loaded. Searches for each pattern in the
        binary and records all matches with offset, size, and metadata. Adds
        all matches to the internal match list.

        Returns:
            List of SignatureMatch objects containing custom signature matches
            found in the binary file.

        Raises:
            Exception: Caught and logged if custom signature scanning fails,
                returns empty list in such cases.
        """
        matches = []

        if not self.custom_signatures:
            self.create_custom_signatures()

        try:
            # Read binary file
            with open(self.binary_path, "rb") as f:
                data = f.read()

            # Search for each signature
            for sig_name, sig_bytes in self.custom_signatures.items():
                offset = 0
                while True:
                    pos = data.find(sig_bytes, offset)
                    if pos == -1:
                        break

                    sig_match = SignatureMatch(
                        signature_type=SignatureType.CUSTOM,
                        name=sig_name,
                        offset=pos,
                        size=len(sig_bytes),
                        confidence=0.85,
                        metadata={"pattern": sig_bytes.hex()},
                    )
                    matches.append(sig_match)
                    logger.info("Custom signature match: %s at offset %s", sig_name, hex(pos))

                    offset = pos + 1

        except Exception as e:
            logger.exception("Custom signature scanning failed: %s", e)

        self.matches.extend(matches)
        return matches

    def detect_protection_schemes(self) -> list[SignatureMatch]:
        """Detect protection schemes using Radare2 analysis.

        Analyzes the binary using Radare2 to identify protection schemes and
        anti-analysis techniques. Checks for high entropy sections, TLS callbacks,
        and imports of protection-related APIs like debugger detection and
        virtual protection functions. Adds all detected protections to the
        internal match list.

        Returns:
            List of SignatureMatch objects containing detected protection
            schemes, anti-analysis APIs, and other protection indicators.
            Returns empty list if r2 is None or analysis fails.

        Raises:
            Exception: Caught and logged if protection scheme detection fails,
                returns empty list in such cases.
        """
        matches: list[SignatureMatch] = []

        if self.r2 is None:
            return matches

        try:
            sections = self.r2.cmdj("iSj")
            if not isinstance(sections, list):
                return matches
            for section in sections:
                entropy = self._calculate_entropy(section)

                if entropy > 7.5:
                    sig_match = SignatureMatch(
                        signature_type=SignatureType.PROTECTION,
                        name=f"High Entropy Section ({section['name']})",
                        offset=section["vaddr"],
                        size=section["size"],
                        confidence=0.8,
                        metadata={
                            "section": section["name"],
                            "entropy": entropy,
                            "permissions": section["perm"],
                        },
                    )
                    matches.append(sig_match)

            if tls := self.r2.cmdj("itj"):
                sig_match = SignatureMatch(
                    signature_type=SignatureType.PROTECTION,
                    name="TLS Callbacks Present",
                    offset=0,
                    size=0,
                    confidence=0.75,
                    metadata={"tls_entries": len(tls)},
                )
                matches.append(sig_match)

            # Check imports for protection-related APIs
            imports = self.r2.cmdj("iij")
            protection_apis = [
                "IsDebuggerPresent",
                "CheckRemoteDebuggerPresent",
                "NtQueryInformationProcess",
                "GetTickCount",
                "QueryPerformanceCounter",
                "CreateToolhelp32Snapshot",
                "VirtualProtect",
                "VirtualAlloc",
            ]

            if found_apis := [imp["name"] for imp in imports if any(api in imp.get("name", "") for api in protection_apis)]:
                sig_match = SignatureMatch(
                    signature_type=SignatureType.PROTECTION,
                    name="Anti-Analysis APIs",
                    offset=0,
                    size=0,
                    confidence=0.7,
                    metadata={"apis": found_apis},
                )
                matches.append(sig_match)

        except Exception as e:
            logger.exception("Protection scheme detection failed: %s", e)

        self.matches.extend(matches)
        return matches

    def _calculate_entropy(self, section: dict[str, Any]) -> float:
        """Calculate entropy of a section.

        Calculates the Shannon entropy of a binary section using radare2 to
        extract the section data. Returns 0.0 if r2 is not initialized or if
        data cannot be retrieved.

        Args:
            section: Binary section information with vaddr and size keys.

        Returns:
            Entropy value in bits. Returns 0.0 if r2 is None or error occurs.

        Raises:
            Exception: Caught internally if entropy calculation fails, returns
                0.0 in such cases.
        """
        if self.r2 is None:
            return 0.0

        try:
            data = self.r2.cmdj(f"pxj {section['size']} @ {section['vaddr']}")
            if not data:
                return 0.0

            byte_counts: dict[int, int] = {}
            for byte in data:
                byte_counts[byte] = byte_counts.get(byte, 0) + 1

            entropy = 0.0
            total = len(data)

            for count in byte_counts.values():
                if count > 0:
                    probability = count / total
                    entropy -= probability * ((probability and probability * 2.0) or 0)

            return entropy * 3.32193  # Convert to bits

        except Exception:
            return 0.0

    def detect_compiler(self) -> CompilerInfo | None:
        """Detect compiler and version.

        Analyzes the binary using Radare2 to detect the compiler used to build
        it. Searches for compiler signatures in strings, MSVC runtime libraries,
        and disassembly patterns. Estimates optimization level based on code
        patterns like NOP instruction density and function call frequency.

        Returns:
            CompilerInfo object containing compiler name, version, optimization
            level, and architecture. Returns None if r2 is None or detection
            fails.

        Raises:
            Exception: Caught and logged if compiler detection fails, returns
                None in such cases.
        """
        if self.r2 is None:
            return None

        try:
            info = self.r2.cmdj("ij")
            imports = self.r2.cmdj("iij")
            self.r2.cmdj("iSj")
            strings = self.r2.cmdj("izj")

            if not isinstance(info, dict) or not isinstance(imports, list) or not isinstance(strings, list):
                return None

            compiler = "Unknown"
            version = "Unknown"
            optimization = "Unknown"

            # Check strings for compiler signatures
            compiler_strings = {
                "Microsoft Visual": "MSVC",
                "GCC:": "GCC",
                "clang": "Clang",
                "Borland": "Borland",
                "Watcom": "Watcom",
                "Intel(R) C++": "Intel C++",
                "Free Pascal": "Free Pascal",
                "Go build": "Go",
                "rustc": "Rust",
            }

            for s in strings:
                text = s.get("string", "")
                for sig, comp in compiler_strings.items():
                    if sig in text:
                        compiler = comp
                        if version_match := re.search(r"(\d+\.\d+(?:\.\d+)?)", text):
                            version = version_match[1]
                        break

            # Check for MSVC runtime libraries
            msvc_versions = {
                "msvcr70.dll": "MSVC 7.0 (2002)",
                "msvcr71.dll": "MSVC 7.1 (2003)",
                "msvcr80.dll": "MSVC 8.0 (2005)",
                "msvcr90.dll": "MSVC 9.0 (2008)",
                "msvcr100.dll": "MSVC 10.0 (2010)",
                "msvcr110.dll": "MSVC 11.0 (2012)",
                "msvcr120.dll": "MSVC 12.0 (2013)",
                "msvcr140.dll": "MSVC 14.0+ (2015+)",
                "ucrtbase.dll": "MSVC 14.0+ (Universal CRT)",
            }

            for imp in imports:
                dll_name = imp.get("libname", "").lower()
                if dll_name in msvc_versions:
                    compiler = "MSVC"
                    version = msvc_versions[dll_name]
                    break

            # Detect optimization level based on code patterns
            disasm = self.r2.cmd("pd 100 @ entry0")

            # Simple heuristics for optimization
            if "nop" in disasm.lower():
                nop_count = disasm.lower().count("nop")
                if nop_count > 10:
                    optimization = "Debug/O0"
                elif nop_count > 5:
                    optimization = "O1"
                else:
                    optimization = "O2/O3"
            # Check for function inlining and loop unrolling
            elif disasm.count("call") < 5:
                optimization = "O3/Aggressive"
            else:
                optimization = "O2/Standard"

            return CompilerInfo(
                compiler=compiler,
                version=version,
                optimization_level=optimization,
                architecture=info["bin"]["arch"],
                metadata={
                    "bits": info["bin"]["bits"],
                    "endian": info["bin"]["endian"],
                    "os": info["bin"]["os"],
                },
            )

        except Exception as e:
            logger.exception("Compiler detection failed: %s", e)
            return None

    def detect_libraries(self) -> list[LibraryInfo]:
        """Detect library versions.

        Analyzes imported functions and strings in the binary to detect libraries
        and their versions. Extracts imported function names from each library
        and searches for version information in binary strings. Includes detection
        of common libraries like OpenSSL, zlib, libpng, Qt, and Boost.

        Returns:
            List of LibraryInfo objects containing detected libraries, their
            versions, and imported function information. Returns empty list if
            r2 is None or detection fails.

        Raises:
            Exception: Caught and logged if library detection fails, returns
                empty list in such cases.
        """
        libraries: list[LibraryInfo] = []

        if self.r2 is None:
            return libraries

        try:
            imports = self.r2.cmdj("iij")
            strings = self.r2.cmdj("izj")

            if not isinstance(imports, list) or not isinstance(strings, list):
                return libraries

            lib_imports: dict[str, list[str]] = {}
            for imp in imports:
                if not isinstance(imp, dict):
                    continue
                libname = imp.get("libname", "unknown")
                if libname not in lib_imports:
                    lib_imports[libname] = []
                lib_imports[libname].append(imp.get("name", ""))

            # Analyze each library
            for libname, functions in lib_imports.items():
                version = "Unknown"

                # Try to find version in strings
                for s in strings:
                    text = s.get("string", "")
                    if libname.replace(".dll", "").replace(".so", "") in text.lower():
                        if version_match := re.search(r"(\d+\.\d+(?:\.\d+)?)", text):
                            version = version_match[1]
                            break

                lib_info = LibraryInfo(
                    name=libname,
                    version=version,
                    functions=functions[:20],  # Limit to first 20 functions
                    imports=[],
                    metadata={"function_count": len(functions)},
                )
                libraries.append(lib_info)

            # Detect specific libraries from strings
            library_patterns = {
                "OpenSSL": r"OpenSSL\s+(\d+\.\d+\.\d+)",
                "zlib": r"zlib\s+(\d+\.\d+\.\d+)",
                "libpng": r"libpng\s+(\d+\.\d+\.\d+)",
                "libjpeg": r"libjpeg\s+(\d+)",
                "Qt": r"Qt\s+(\d+\.\d+\.\d+)",
                "Boost": r"boost[/_](\d+[._]\d+[._]\d+)",
                "Python": r"Python\s+(\d+\.\d+(?:\.\d+)?)",
            }

            for s in strings:
                text = s.get("string", "")
                for lib_name, pattern in library_patterns.items():
                    if match := re.search(pattern, text, re.IGNORECASE):
                        lib_info = LibraryInfo(
                            name=lib_name,
                            version=match[1],
                            functions=[],
                            imports=[],
                            metadata={"detected_from": "strings"},
                        )
                        libraries.append(lib_info)

        except Exception as e:
            logger.exception("Library detection failed: %s", e)

        return libraries

    def generate_report(self) -> str:
        """Generate comprehensive detection report.

        Compiles all detected signatures, compiler information, and library
        details into a formatted text report. Includes binary hashes, signature
        matches grouped by type, detected compiler and optimization level,
        identified libraries, and protection detection summary.

        Returns:
            Formatted string containing signature matches, compiler info,
            detected libraries, and overall protection analysis summary.

        Raises:
            No exceptions raised by this method.
        """
        report = [
            "=" * 60,
            "SIGNATURE DETECTION REPORT",
            "=" * 60,
            f"Binary: {self.binary_path}",
            f"SHA256: {self.file_hash['sha256']}",
            f"SHA512: {self.file_hash['sha512']}",
            f"Size: {self.file_hash['size']} bytes",
            "",
        ]
        by_type: dict[SignatureType, list[SignatureMatch]] = {}
        for match in self.matches:
            if match.signature_type not in by_type:
                by_type[match.signature_type] = []
            by_type[match.signature_type].append(match)

        for sig_type, matches in by_type.items():
            report.extend((
                f"\n{sig_type.value.upper()} SIGNATURES ({len(matches)} matches)",
                "-" * 40,
            ))
            unique_sigs: dict[str, list[SignatureMatch]] = {}
            for match in matches:
                if match.name not in unique_sigs:
                    unique_sigs[match.name] = []
                unique_sigs[match.name].append(match)

            for sig_name, sig_matches in unique_sigs.items():
                report.extend((
                    f"  {sig_name}",
                    f"    Matches: {len(sig_matches)}",
                    f"    Confidence: {sig_matches[0].confidence:.0%}",
                ))
                # Show first few offsets
                offsets = [hex(m.offset) for m in sig_matches[:5]]
                if len(sig_matches) > 5:
                    offsets.append(f"... and {len(sig_matches) - 5} more")
                report.extend((f"    Offsets: {', '.join(offsets)}", ""))
        if compiler_info := self.detect_compiler():
            report.extend(("\nCOMPILER INFORMATION", "-" * 40))
            report.extend((
                f"  Compiler: {compiler_info.compiler}",
                f"  Version: {compiler_info.version}",
            ))
            report.extend((
                f"  Optimization: {compiler_info.optimization_level}",
                f"  Architecture: {compiler_info.architecture}",
            ))
            report.append("")

        if libraries := self.detect_libraries():
            report.append("\nDETECTED LIBRARIES")
            report.append("-" * 40)
            for lib in libraries[:10]:  # Limit to first 10
                report.append(f"  {lib.name}")
                report.append(f"    Version: {lib.version}")
                report.append(f"    Functions: {lib.metadata.get('function_count', len(lib.functions))}")
            if len(libraries) > 10:
                report.append(f"  ... and {len(libraries) - 10} more libraries")
            report.append("")

        report.extend((
            "\nSUMMARY",
            "-" * 40,
            f"Total Signatures Matched: {len(self.matches)}",
        ))
        if protection_matches := [
            m for m in self.matches if "protect" in m.name.lower() or "pack" in m.name.lower() or "crypt" in m.name.lower()
        ]:
            report.append("Protection/Packer Detected: YES")
            report.append(f"Protection Types: {', '.join({m.name for m in protection_matches})}")
        else:
            report.append("Protection/Packer Detected: NO")

        return "\n".join(report)

    def export_signatures(self, output_file: str, format: str = "json") -> bool:
        """Export detected signatures to file.

        Exports all detected signature matches to a file in the specified format.
        JSON format includes binary hashes, match details, and metadata. CSV
        format contains a header row and one row per signature match.

        Args:
            output_file: Path to output file for signature export.
            format: Export format, either "json" or "csv". Defaults to "json".

        Returns:
            True if export was successful, False otherwise.

        Raises:
            Exception: Caught and logged if export fails, returns False in such
                cases.
        """
        try:
            if format == "json":
                data: dict[str, Any] = {"binary": self.binary_path, "hashes": self.file_hash, "matches": []}
                matches_list: list[dict[str, Any]] = []

                for match in self.matches:
                    matches_list.append({
                        "type": match.signature_type.value,
                        "name": match.name,
                        "offset": match.offset,
                        "size": match.size,
                        "confidence": match.confidence,
                        "metadata": match.metadata,
                    })
                data["matches"] = matches_list

                with open(output_file, "w") as f:
                    json.dump(data, f, indent=2)

            elif format == "csv":
                import csv

                with open(output_file, "w", newline="") as f:
                    writer = csv.writer(f)
                    writer.writerow(["Type", "Name", "Offset", "Size", "Confidence"])

                    for match in self.matches:
                        writer.writerow([
                            match.signature_type.value,
                            match.name,
                            hex(match.offset),
                            match.size,
                            f"{match.confidence:.0%}",
                        ])

            logger.info("Exported %s signatures to %s", len(self.matches), output_file)
            return True

        except Exception as e:
            logger.exception("Failed to export signatures: %s", e)
            return False

    def close(self) -> None:
        """Close Radare2 session.

        Properly closes the r2pipe connection and releases resources. Sets
        internal r2 reference to None after closing.

        Returns:
            None.

        Raises:
            No exceptions raised by this method.
        """
        if self.r2:
            self.r2.quit()
            self.r2 = None


def main() -> None:
    """Demonstrate usage of signature detector.

    Command-line interface for signature detection supporting YARA rules,
    ClamAV integration, custom signatures, and protection scheme analysis.
    Results can be exported to JSON or CSV format.

    Returns:
        None.

    Raises:
        SystemExit: Raised by argparse if command-line arguments are invalid.
    """
    import argparse

    parser = argparse.ArgumentParser(description="Radare2 Signature-Based Detection")
    parser.add_argument("binary", help="Binary file to analyze")
    parser.add_argument("-y", "--yara", help="YARA rules file or directory")
    parser.add_argument("-c", "--clamav", action="store_true", help="Enable ClamAV scanning")
    parser.add_argument("-o", "--output", help="Output file for signatures")
    parser.add_argument("-f", "--format", choices=["json", "csv"], default="json", help="Output format")

    args = parser.parse_args()

    # Configure logging
    logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")

    # Create detector
    detector = Radare2SignatureDetector(args.binary)

    if not detector.open():
        return

    try:
        # Load YARA rules if provided
        if args.yara:
            detector.load_yara_rules(args.yara)

        logger.info("Starting signature detection...")

        detector.scan_with_yara()
        if args.clamav:
            detector.scan_with_clamav()
        detector.scan_custom_signatures()
        detector.detect_protection_schemes()

        # Generate report
        report = detector.generate_report()
        print(report)

        # Export if requested
        if args.output:
            detector.export_signatures(args.output, args.format)

    finally:
        detector.close()


if __name__ == "__main__":
    main()

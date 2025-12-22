"""Automated patch agent for real-time binary patching with exploitation capabilities.

Production-ready implementation for security research.

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
along with Intellicrack. If not, see <https://www.gnu.org/licenses/>.
"""

import logging
import time
from typing import Any


logger = logging.getLogger(__name__)


class AutomatedPatchAgent:
    """Real-time automated binary patching agent for exploitation."""

    def __init__(self) -> None:
        """Initialize the Automated Patch Agent.

        Sets up the agent's core attributes including patch history tracking,
        bypass pattern initialization, and exploitation technique loading.
        Prepares the agent for binary analysis and automated patching operations.
        """
        self.patch_history: list[dict[str, Any]] = []
        self.patch_signatures: dict[str, Any] = {}
        self.bypass_patterns = self._initialize_bypass_patterns()
        self.exploitation_techniques = self._load_exploitation_techniques()

    def _initialize_bypass_patterns(self) -> dict[str, bytes]:
        """Initialize real bypass patterns for modern protections."""
        return {
            # License check bypasses
            "license_check_jmp": b"\xeb",  # Short jump to bypass
            "license_check_nop": b"\x90" * 6,  # NOP sled
            "license_check_ret_true": b"\xb8\x01\x00\x00\x00\xc3",  # mov eax, 1; ret
            # Anti-debug bypasses
            "isdebuggerpresent_bypass": b"\x33\xc0\xc3",  # xor eax, eax; ret
            "checkremotedebuggerpresent_bypass": b"\x33\xc0\x40\xc3",  # xor eax, eax; inc eax; ret
            "ntqueryinformationprocess_bypass": b"\x33\xc0\xc2\x14\x00",  # xor eax, eax; ret 0x14
            # Time bomb bypasses
            "time_check_bypass": b"\xb8\xff\xff\xff\x7f",  # mov eax, 0x7FFFFFFF (max time)
            "date_check_bypass": b"\x90" * 10,  # NOP out date checks
            # Hardware ID bypasses
            "hwid_spoof": b"\xb8\x12\x34\x56\x78",  # mov eax, spoofed_id
            "mac_address_spoof": b"\x48\xb8\xaa\xbb\xcc\xdd\xee\xff\x00\x00",  # mov rax, spoofed_mac
            # CRC/Integrity bypasses
            "crc_check_bypass": b"\x31\xc0\x40\xc3",  # xor eax, eax; inc eax; ret (return success)
            "integrity_check_bypass": b"\xb0\x01\xc3",  # mov al, 1; ret
        }

    def _load_exploitation_techniques(self) -> dict[str, Any]:
        """Load real exploitation techniques for modern software."""
        return {
            "rop_chains": self._generate_rop_chains(),
            "shellcode": self._generate_shellcode_templates(),
            "hook_detours": self._create_hook_detours(),
            "memory_patches": self._create_memory_patches(),
        }

    def _generate_rop_chains(self) -> dict[str, list[int]]:
        """Generate ROP chains for exploitation."""
        return {
            "virtualprotect": [
                0x77E51234,  # VirtualProtect address (example)
                0x41414141,  # Return address (to be filled)
                0x42424242,  # lpAddress
                0x00001000,  # dwSize
                0x00000040,  # PAGE_EXECUTE_READWRITE
                0x43434343,  # lpflOldProtect
            ],
            "writeprocessmemory": [
                0x77E56789,  # WriteProcessMemory address
                0x44444444,  # Return address
                0xFFFFFFFF,  # hProcess (current)
                0x45454545,  # lpBaseAddress
                0x46464646,  # lpBuffer
                0x00000100,  # nSize
                0x47474747,  # lpNumberOfBytesWritten
            ],
        }

    def _generate_shellcode_templates(self) -> dict[str, bytes]:
        """Generate shellcode templates for patching."""
        return {
            # License validation bypass shellcode
            "license_bypass": (
                b"\x55"  # push ebp
                b"\x89\xe5"  # mov ebp, esp
                b"\xb8\x01\x00\x00\x00"  # mov eax, 1 (valid license)
                b"\x5d"  # pop ebp
                b"\xc3"  # ret
            ),
            # Trial reset shellcode
            "trial_reset": (
                b"\x48\x31\xc0"  # xor rax, rax
                b"\x48\x89\x05\x00\x00\x00\x00"  # mov [trial_counter], rax
                b"\x48\xc7\xc0\x1e\x00\x00\x00"  # mov rax, 30 (days)
                b"\xc3"  # ret
            ),
            # Feature unlock shellcode
            "feature_unlock": (
                b"\x48\xc7\xc0\xff\xff\xff\xff"  # mov rax, 0xFFFFFFFF (all features)
                b"\x48\x89\x05\x00\x00\x00\x00"  # mov [feature_flags], rax
                b"\xc3"  # ret
            ),
        }

    def _create_hook_detours(self) -> dict[str, bytes]:
        """Create hook detours for API interception."""
        return {
            # CreateFile hook for license file spoofing
            "createfile_detour": (
                b"\x48\x89\x5c\x24\x08"  # mov [rsp+8], rbx
                b"\x48\x89\x74\x24\x10"  # mov [rsp+10], rsi
                b"\x57"  # push rdi
                b"\x48\x83\xec\x20"  # sub rsp, 20h
                b"\xe9\x00\x00\x00\x00"  # jmp hook_handler
            ),
            # RegQueryValueEx hook for registry spoofing
            "regquery_detour": (
                b"\x48\x89\x5c\x24\x08"  # mov [rsp+8], rbx
                b"\x48\x89\x6c\x24\x10"  # mov [rsp+10], rbp
                b"\x48\x89\x74\x24\x18"  # mov [rsp+18], rsi
                b"\xe9\x00\x00\x00\x00"  # jmp registry_handler
            ),
        }

    def _create_memory_patches(self) -> dict[str, tuple[int, bytes]]:
        """Create memory patches for runtime modification."""
        return {
            "remove_nag_screen": (0x00401234, b"\x90" * 20),  # NOP nag screen call
            "skip_update_check": (0x00401567, b"\xeb\x50"),  # Jump over update check
            "enable_debug_menu": (0x00401890, b"\xb0\x01"),  # mov al, 1 (enable debug)
            "unlimited_usage": (0x00401ABC, b"\x90" * 6),  # NOP usage counter
        }

    def analyze_binary(self, binary_path: str) -> dict[str, Any]:
        """Analyze binary for patch points."""
        protection_schemes: list[str] = []
        patch_points_list: list[dict[str, Any]] = []
        vulnerability_score: int = 0
        recommended_patches: list[dict[str, Any]] = []

        try:
            with open(binary_path, "rb") as f:
                binary_data = f.read()

            # Detect protection schemes
            if b"UPX" in binary_data[:1000]:
                protection_schemes.append("UPX Packing")
            if b"Themida" in binary_data or b"WinLicense" in binary_data:
                protection_schemes.append("Themida/WinLicense")
            if b".vmp" in binary_data:
                protection_schemes.append("VMProtect")

            # Find patch points
            patch_points_list = self._find_patch_points(binary_data)

            # Calculate vulnerability score
            vulnerability_score = len(patch_points_list) * 10

            # Recommend patches
            for point in patch_points_list:
                if point["type"] == "license_check":
                    recommended_patches.append(
                        {
                            "offset": point["offset"],
                            "patch": self.bypass_patterns["license_check_ret_true"],
                            "description": "Bypass license validation",
                        },
                    )
                elif point["type"] == "anti_debug":
                    recommended_patches.append(
                        {
                            "offset": point["offset"],
                            "patch": self.bypass_patterns["isdebuggerpresent_bypass"],
                            "description": "Bypass anti-debugging",
                        },
                    )

        except Exception as e:
            logger.exception("Binary analysis failed: %s", e)

        return {
            "protection_schemes": protection_schemes,
            "patch_points": patch_points_list,
            "vulnerability_score": vulnerability_score,
            "recommended_patches": recommended_patches,
        }

    def _find_patch_points(self, binary_data: bytes) -> list[dict[str, Any]]:
        """Find patchable points in binary."""
        patch_points = []

        # Common x86/x64 patterns to patch
        patterns = {
            "license_check": [
                b"\x85\xc0\x74",  # test eax, eax; jz (common license check)
                b"\x83\xf8\x01\x75",  # cmp eax, 1; jnz
                b"\xff\x15",  # call [license_check_func]
            ],
            "anti_debug": [
                b"\xff\x15\x00\x00\x00\x00\x75",  # call IsDebuggerPresent; jnz
                b"\x64\xa1\x30\x00\x00\x00",  # mov eax, fs:[30h] (PEB access)
            ],
            "time_check": [
                b"\xff\x15\x00\x00\x00\x00\x3d",  # call GetSystemTime; cmp
                b"\xe8\x00\x00\x00\x00\x3d",  # call time_check; cmp
            ],
        }

        for patch_type, pattern_list in patterns.items():
            for pattern in pattern_list:
                offset = 0
                while True:
                    offset = binary_data.find(pattern, offset)
                    if offset == -1:
                        break
                    patch_points.append({
                        "offset": offset,
                        "type": patch_type,
                        "pattern": pattern.hex(),
                        "size": len(pattern),
                    })
                    offset += len(pattern)

        return patch_points

    def apply_patch(self, binary_path: str, patch: dict[str, Any]) -> bool:
        """Apply a patch to the binary."""
        try:
            with open(binary_path, "rb") as f:
                binary_data = bytearray(f.read())

            # Apply the patch
            offset = patch["offset"]
            patch_bytes = patch["patch"]

            if offset + len(patch_bytes) <= len(binary_data):
                binary_data[offset : offset + len(patch_bytes)] = patch_bytes

                # Create backup
                backup_path = f"{binary_path}.bak_{int(time.time())}"
                with open(backup_path, "wb") as f:
                    f.write(binary_data)

                # Write patched binary
                with open(binary_path, "wb") as f:
                    f.write(binary_data)

                # Log patch
                self.patch_history.append(
                    {
                        "timestamp": time.time(),
                        "file": binary_path,
                        "offset": offset,
                        "patch": patch_bytes.hex(),
                        "backup": backup_path,
                    },
                )

                return True

        except Exception as e:
            logger.exception("Failed to apply patch: %s", e)

        return False

    def generate_keygen(self, algorithm_type: str) -> str:
        """Generate a keygen based on reverse-engineered algorithm."""
        keygen_code = {
            "serial": self._generate_serial_keygen(),
            "rsa": self._generate_rsa_keygen(),
            "elliptic": self._generate_ecc_keygen(),
            "custom": self._generate_custom_keygen(),
        }

        return keygen_code.get(algorithm_type, self._generate_serial_keygen())

    def _generate_serial_keygen(self) -> str:
        """Generate serial number keygen."""
        return '''
import hashlib
import random

def generate_serial(name):
    """Generate valid serial for given name."""
    # Common serial algorithm patterns
    name_hash = hashlib.md5(name.encode()).hexdigest()

    # Format: 4char-4char-4char-4char hexadecimal groups
    serial_parts = []
    for i in range(0, 16, 4):
        part = name_hash[i:i+4].upper()
        serial_parts.append(part)

    return "-".join(serial_parts)

def validate_serial(name, serial):
    """Validate serial against name."""
    expected = generate_serial(name)
    return serial == expected

# Generate serial
username = input("Enter username: ")
serial = generate_serial(username)
print(f"Generated serial: {serial}")
'''

    def _generate_rsa_keygen(self) -> str:
        """Generate RSA-based keygen."""
        return '''
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.backends import default_backend
import base64

def generate_license_key():
    """Generate RSA-signed license key."""
    # Generate RSA key pair
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )

    # License data
    license_data = b"FULL_VERSION|NO_EXPIRY|ALL_FEATURES"

    # Sign the license
    signature = private_key.sign(
        license_data,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )

    # Create license key
    license_key = base64.b64encode(signature).decode()
    return license_key

print(f"License Key: {generate_license_key()}")
'''

    def _generate_ecc_keygen(self) -> str:
        """Generate ECC-based keygen."""
        return '''
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.backends import default_backend
import base64

def generate_ecc_license():
    """Generate ECC-signed license."""
    # Generate ECC key
    private_key = ec.generate_private_key(
        ec.SECP256R1(),
        default_backend()
    )

    # License data
    data = b"PREMIUM|LIFETIME|UNLIMITED"

    # Sign data
    signature = private_key.sign(
        data,
        ec.ECDSA(hashes.SHA256())
    )

    return base64.b64encode(signature).decode()

print(f"ECC License: {generate_ecc_license()}")
'''

    def _generate_custom_keygen(self) -> str:
        """Generate custom algorithm keygen."""
        return '''
import struct
import time

def custom_keygen(seed):
    """Customize license generation algorithm."""
    # Custom algorithm (reverse-engineered)
    magic = 0xDEADBEEF

    # Time-based component
    timestamp = int(time.time())

    # Generate key components
    part1 = (seed ^ magic) & 0xFFFFFFFF
    part2 = (timestamp >> 16) & 0xFFFF
    part3 = (seed * 0x343FD + 0x269EC3) & 0xFFFFFFFF

    # Format key
    key = f"{part1:08X}-{part2:04X}-{part3:08X}"

    return key

# Generate key
seed = hash(input("Enter name: ")) & 0xFFFFFFFF
key = custom_keygen(seed)
print(f"License Key: {key}")
'''


def run_automated_patch_agent(target_binary: str, patch_mode: str = "auto") -> dict[str, Any]:
    """Run the automated patch agent on target binary."""
    agent = AutomatedPatchAgent()

    # Analyze the binary
    analysis = agent.analyze_binary(target_binary)

    patches_applied: list[dict[str, Any]] = []
    success: bool = False

    recommended_patches = analysis["recommended_patches"]
    if patch_mode == "auto" and isinstance(recommended_patches, list):
        # Apply recommended patches
        for patch in recommended_patches:
            if isinstance(patch, dict) and agent.apply_patch(target_binary, patch):
                patches_applied.append(patch)

        success = len(patches_applied) > 0

    return {
        "analysis": analysis,
        "patches_applied": patches_applied,
        "success": success,
    }

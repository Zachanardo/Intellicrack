"""Custom Protection Challenge Binary Generator for Intellicrack Testing.

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

import hashlib
import json
import logging
import os
import random
import secrets
import struct
import subprocess
import sys
import time
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Any

try:
    import pefile
except ImportError:
    pefile = None

try:
    import keystone
    from keystone import Ks, KS_ARCH_X86, KS_MODE_64
except ImportError:
    keystone = None
    Ks = KS_ARCH_X86 = KS_MODE_64 = None


class ProtectionType(Enum):
    """Modern protection mechanisms."""
    ANTI_DEBUG = "anti_debug"
    ANTI_VM = "anti_vm"
    PACKING = "packing"
    OBFUSCATION = "obfuscation"
    ENCRYPTION = "encryption"
    LICENSING = "licensing"
    INTEGRITY = "integrity"
    TIMING = "timing"
    HARDWARE_ID = "hardware_id"
    ONLINE_CHECK = "online_check"
    CRYPTO_SIGNATURE = "crypto_signature"
    VM_PROTECTION = "vm_protection"


class LicensingSystem(Enum):
    """Licensing system types."""
    FLEXLM = "flexlm"
    SENTINEL_HASP = "sentinel_hasp"
    CODEMETER = "codemeter"
    ILOK = "ilok"
    CUSTOM_CRYPTO = "custom_crypto"
    ONLINE_ACTIVATION = "online_activation"
    HARDWARE_LOCK = "hardware_lock"
    TIME_TRIAL = "time_trial"
    FEATURE_TOGGLE = "feature_toggle"
    SUBSCRIPTION = "subscription"


@dataclass
class ProtectionChallenge:
    """Protection challenge configuration."""
    name: str
    protection_types: List[ProtectionType]
    licensing_system: Optional[LicensingSystem]
    difficulty: int  # 1-10
    obfuscation_level: int  # 1-10
    anti_analysis_level: int  # 1-10
    custom_parameters: Dict[str, Any]


class ProtectionChallengeGenerator:
    """Generates test binaries with sophisticated protection mechanisms."""

    def __init__(self, output_dir: Optional[str] = None):
        """Initialize protection challenge generator.

        Args:
            output_dir: Directory for generated binaries
        """
        self.output_dir = Path(output_dir) if output_dir else Path.cwd() / "protection_challenges"
        self.output_dir.mkdir(parents=True, exist_ok=True)

        self.logger = logging.getLogger(__name__)
        self._setup_logging()

        # Assembly encoder
        self.assembler = None
        if keystone:
            self.assembler = Ks(KS_ARCH_X86, KS_MODE_64)

        # Challenge templates
        self.challenge_templates = self._load_challenge_templates()

    def _setup_logging(self) -> None:
        """Setup logging."""
        log_file = self.output_dir / "generator.log"
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler(log_file),
                logging.StreamHandler()
            ]
        )

    def _load_challenge_templates(self) -> List[ProtectionChallenge]:
        """Load predefined protection challenge templates.

        Returns:
            List of challenge templates
        """
        templates = [
            ProtectionChallenge(
                name="basic_license_check",
                protection_types=[ProtectionType.LICENSING],
                licensing_system=LicensingSystem.CUSTOM_CRYPTO,
                difficulty=2,
                obfuscation_level=1,
                anti_analysis_level=1,
                custom_parameters={"key_algorithm": "simple_xor"}
            ),
            ProtectionChallenge(
                name="flexlm_emulation",
                protection_types=[ProtectionType.LICENSING, ProtectionType.ANTI_DEBUG],
                licensing_system=LicensingSystem.FLEXLM,
                difficulty=5,
                obfuscation_level=3,
                anti_analysis_level=4,
                custom_parameters={"server_port": 27000, "feature": "advanced_feature"}
            ),
            ProtectionChallenge(
                name="sentinel_hasp_dongle",
                protection_types=[ProtectionType.LICENSING, ProtectionType.HARDWARE_ID],
                licensing_system=LicensingSystem.SENTINEL_HASP,
                difficulty=7,
                obfuscation_level=5,
                anti_analysis_level=6,
                custom_parameters={"dongle_id": "HASP_12345", "encryption": "aes256"}
            ),
            ProtectionChallenge(
                name="online_activation_rsa",
                protection_types=[ProtectionType.LICENSING, ProtectionType.ONLINE_CHECK, ProtectionType.CRYPTO_SIGNATURE],
                licensing_system=LicensingSystem.ONLINE_ACTIVATION,
                difficulty=6,
                obfuscation_level=4,
                anti_analysis_level=5,
                custom_parameters={"server_url": "https://license.example.com", "rsa_bits": 2048}
            ),
            ProtectionChallenge(
                name="vm_protected_trial",
                protection_types=[ProtectionType.VM_PROTECTION, ProtectionType.TIMING, ProtectionType.OBFUSCATION],
                licensing_system=LicensingSystem.TIME_TRIAL,
                difficulty=9,
                obfuscation_level=8,
                anti_analysis_level=9,
                custom_parameters={"vm_layers": 3, "trial_days": 30}
            ),
            ProtectionChallenge(
                name="hardware_locked_crypto",
                protection_types=[ProtectionType.HARDWARE_ID, ProtectionType.ENCRYPTION, ProtectionType.INTEGRITY],
                licensing_system=LicensingSystem.HARDWARE_LOCK,
                difficulty=8,
                obfuscation_level=6,
                anti_analysis_level=7,
                custom_parameters={"hw_components": ["cpu", "motherboard", "network"], "crypto": "aes_gcm"}
            ),
            ProtectionChallenge(
                name="multi_layer_protection",
                protection_types=[
                    ProtectionType.ANTI_DEBUG,
                    ProtectionType.ANTI_VM,
                    ProtectionType.PACKING,
                    ProtectionType.OBFUSCATION,
                    ProtectionType.LICENSING,
                    ProtectionType.INTEGRITY
                ],
                licensing_system=LicensingSystem.CUSTOM_CRYPTO,
                difficulty=10,
                obfuscation_level=10,
                anti_analysis_level=10,
                custom_parameters={"layers": 5, "polymorphic": True, "anti_tamper": True}
            )
        ]

        return templates

    def generate_challenge_binary(self, challenge: ProtectionChallenge) -> Path:
        """Generate a challenge binary with specified protections.

        Args:
            challenge: Protection challenge configuration

        Returns:
            Path to generated binary
        """
        self.logger.info(f"Generating challenge binary: {challenge.name}")

        # Create base executable
        binary_path = self.output_dir / f"{challenge.name}.exe"

        # Generate base code
        base_code = self._generate_base_code(challenge)

        # Apply protections
        protected_code = self._apply_protections(base_code, challenge)

        # Compile to binary
        self._compile_to_binary(protected_code, binary_path)

        # Apply post-compilation protections
        self._apply_post_compilation_protections(binary_path, challenge)

        # Generate metadata
        self._generate_challenge_metadata(binary_path, challenge)

        self.logger.info(f"Generated challenge binary: {binary_path}")

        return binary_path

    def _generate_base_code(self, challenge: ProtectionChallenge) -> str:
        """Generate base C code for challenge binary.

        Args:
            challenge: Protection challenge

        Returns:
            C source code
        """
        licensing_code = self._generate_licensing_code(challenge)
        protection_code = self._generate_protection_code(challenge)

        code = f'''
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <wincrypt.h>

#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "user32.lib")
#pragma comment(lib, "kernel32.lib")
#pragma comment(lib, "crypt32.lib")

// Protection configuration
#define PROTECTION_LEVEL {challenge.anti_analysis_level}
#define OBFUSCATION_LEVEL {challenge.obfuscation_level}

// Global protection state
volatile int g_protection_active = 1;
volatile int g_license_valid = 0;
volatile int g_debugger_detected = 0;

{protection_code}

{licensing_code}

// Main application logic
void run_application() {{
    printf("\\n=== Intellicrack Protection Challenge: {challenge.name} ===\\n");
    printf("Difficulty: {challenge.difficulty}/10\\n");
    printf("Protection Types: {len(challenge.protection_types)}\\n");

    if (g_license_valid) {{
        printf("\\n[+] License validated successfully!\\n");
        printf("[+] Running protected application...\\n");

        // Simulated protected functionality
        for (int i = 0; i < 5; i++) {{
            printf("    Executing protected feature %d...\\n", i + 1);
            Sleep(500);

            // Periodic integrity checks
            if (i % 2 == 0) {{
                check_integrity();
            }}
        }}

        printf("\\n[+] Application completed successfully!\\n");
        printf("[+] FLAG: INTELLICRACK_{{{generate_flag(challenge)}}}\\n");
    }} else {{
        printf("\\n[-] License validation failed!\\n");
        printf("[-] Please obtain a valid license.\\n");
        exit(1);
    }}
}}

int main(int argc, char* argv[]) {{
    // Initialize protection layers
    init_protections();

    // Check for debuggers/VMs
    if (PROTECTION_LEVEL >= 5) {{
        if (detect_debugger() || detect_vm()) {{
            printf("[-] Analysis environment detected. Exiting.\\n");
            trigger_anti_tamper();
            return 1;
        }}
    }}

    // Validate license
    printf("[*] Validating license...\\n");
    g_license_valid = validate_license(argc > 1 ? argv[1] : NULL);

    // Run main application
    run_application();

    // Cleanup
    cleanup_protections();

    return 0;
}}
'''

        return code

    def _generate_licensing_code(self, challenge: ProtectionChallenge) -> str:
        """Generate licensing validation code.

        Args:
            challenge: Protection challenge

        Returns:
            C code for licensing
        """
        if not challenge.licensing_system:
            return "int validate_license(char* key) { return 1; }"

        licensing_implementations = {
            LicensingSystem.CUSTOM_CRYPTO: self._generate_custom_crypto_license,
            LicensingSystem.FLEXLM: self._generate_flexlm_license,
            LicensingSystem.SENTINEL_HASP: self._generate_sentinel_license,
            LicensingSystem.ONLINE_ACTIVATION: self._generate_online_license,
            LicensingSystem.HARDWARE_LOCK: self._generate_hardware_lock_license,
            LicensingSystem.TIME_TRIAL: self._generate_trial_license
        }

        generator = licensing_implementations.get(
            challenge.licensing_system,
            self._generate_custom_crypto_license
        )

        return generator(challenge)

    def _generate_custom_crypto_license(self, challenge: ProtectionChallenge) -> str:
        """Generate custom cryptographic licensing code.

        Args:
            challenge: Protection challenge

        Returns:
            C code
        """
        key_algorithm = challenge.custom_parameters.get("key_algorithm", "aes")

        return f'''
// Custom cryptographic license validation
#define LICENSE_KEY_LENGTH 32
#define VALID_LICENSE_HASH "4b227777d4dd1fc61c6f884f48641d02b7d8e9a495c5e0e3b5a4382e6a5b7c3f"

unsigned char license_salt[] = {{ 0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0 }};

int validate_license(char* key) {{
    if (!key || strlen(key) != LICENSE_KEY_LENGTH) {{
        return 0;
    }}

    // Obfuscated key validation
    HCRYPTPROV hProv;
    HCRYPTHASH hHash;
    BYTE hash[32];
    DWORD hashLen = 32;
    char hashStr[65];

    if (!CryptAcquireContext(&hProv, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT)) {{
        return 0;
    }}

    if (!CryptCreateHash(hProv, CALG_SHA_256, 0, 0, &hHash)) {{
        CryptReleaseContext(hProv, 0);
        return 0;
    }}

    // Hash key with salt
    CryptHashData(hHash, (BYTE*)key, strlen(key), 0);
    CryptHashData(hHash, license_salt, sizeof(license_salt), 0);

    if (!CryptGetHashParam(hHash, HP_HASHVAL, hash, &hashLen, 0)) {{
        CryptDestroyHash(hHash);
        CryptReleaseContext(hProv, 0);
        return 0;
    }}

    // Convert hash to string
    for (int i = 0; i < 32; i++) {{
        sprintf(hashStr + (i * 2), "%02x", hash[i]);
    }}
    hashStr[64] = '\\0';

    // Compare with valid hash (obfuscated)
    int valid = 1;
    for (int i = 0; i < 64; i++) {{
        if (hashStr[i] != VALID_LICENSE_HASH[i]) {{
            valid = 0;
            break;
        }}
    }}

    CryptDestroyHash(hHash);
    CryptReleaseContext(hProv, 0);

    return valid;
}}
'''

    def _generate_flexlm_license(self, challenge: ProtectionChallenge) -> str:
        """Generate FlexLM-style licensing code.

        Args:
            challenge: Protection challenge

        Returns:
            C code
        """
        port = challenge.custom_parameters.get("server_port", 27000)
        feature = challenge.custom_parameters.get("feature", "base_feature")

        return f'''
// FlexLM-style license validation
#define FLEXLM_PORT {port}
#define FEATURE_NAME "{feature}"

typedef struct {{
    char vendor[32];
    char feature[64];
    char version[16];
    int expiry_date;
    char hostid[32];
}} flexlm_license_t;

int connect_to_license_server(const char* server, int port) {{
    WSADATA wsaData;
    SOCKET sock;
    struct sockaddr_in server_addr;

    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {{
        return 0;
    }}

    sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock == INVALID_SOCKET) {{
        WSACleanup();
        return 0;
    }}

    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(port);
    server_addr.sin_addr.s_addr = inet_addr("127.0.0.1"); // Local server for testing

    // Simulate connection attempt
    closesocket(sock);
    WSACleanup();

    // For testing, validate based on environment variable
    char* flex_license = getenv("FLEXLM_LICENSE_FILE");
    return (flex_license != NULL);
}}

int validate_license(char* key) {{
    // Simulate FlexLM license checkout
    printf("[*] Connecting to FlexLM license server on port %d...\\n", FLEXLM_PORT);

    if (!connect_to_license_server("localhost", FLEXLM_PORT)) {{
        printf("[-] Failed to connect to license server\\n");

        // Check for license file
        FILE* lic_file = fopen("license.dat", "r");
        if (lic_file) {{
            flexlm_license_t license;
            char buffer[256];

            // Parse license file (simplified)
            if (fgets(buffer, sizeof(buffer), lic_file)) {{
                if (strstr(buffer, FEATURE_NAME)) {{
                    fclose(lic_file);
                    return 1;
                }}
            }}
            fclose(lic_file);
        }}

        return 0;
    }}

    return 1;
}}
'''

    def _generate_sentinel_license(self, challenge: ProtectionChallenge) -> str:
        """Generate Sentinel HASP-style licensing code.

        Args:
            challenge: Protection challenge

        Returns:
            C code
        """
        dongle_id = challenge.custom_parameters.get("dongle_id", "HASP_DEFAULT")

        return f'''
// Sentinel HASP-style dongle validation
#define HASP_VENDOR_CODE "{dongle_id}"

typedef struct {{
    DWORD vendor_id;
    DWORD product_id;
    BYTE encryption_key[16];
}} hasp_dongle_t;

int detect_hasp_dongle() {{
    // Check for HASP driver/service
    SC_HANDLE scm = OpenSCManager(NULL, NULL, SC_MANAGER_CONNECT);
    if (!scm) return 0;

    SC_HANDLE service = OpenService(scm, "hasplms", SERVICE_QUERY_STATUS);
    int found = (service != NULL);

    if (service) CloseServiceHandle(service);
    CloseServiceHandle(scm);

    return found;
}}

int validate_license(char* key) {{
    printf("[*] Checking for Sentinel HASP dongle...\\n");

    // Simulate dongle detection
    if (!detect_hasp_dongle()) {{
        printf("[-] HASP dongle not detected\\n");

        // Check for emulator signatures
        HKEY hKey;
        if (RegOpenKeyEx(HKEY_LOCAL_MACHINE,
                        "SOFTWARE\\\\Aladdin Knowledge Systems\\\\HASP\\\\Driver",
                        0, KEY_READ, &hKey) == ERROR_SUCCESS) {{
            RegCloseKey(hKey);
            return 1; // Emulator detected (for testing)
        }}

        return 0;
    }}

    // Validate vendor code
    if (key && strcmp(key, HASP_VENDOR_CODE) == 0) {{
        return 1;
    }}

    return 0;
}}
'''

    def _generate_online_license(self, challenge: ProtectionChallenge) -> str:
        """Generate online activation licensing code.

        Args:
            challenge: Protection challenge

        Returns:
            C code
        """
        server_url = challenge.custom_parameters.get("server_url", "https://license.local")

        return f'''
// Online activation licensing
#define LICENSE_SERVER "{server_url}"
#define ACTIVATION_ENDPOINT "/api/activate"

int perform_online_activation(const char* key) {{
    HINTERNET hInternet = InternetOpen("Intellicrack/1.0",
                                      INTERNET_OPEN_TYPE_DIRECT,
                                      NULL, NULL, 0);
    if (!hInternet) return 0;

    // For testing, check local file instead of real network
    FILE* activation = fopen("activation.key", "r");
    if (activation) {{
        char stored_key[256];
        if (fgets(stored_key, sizeof(stored_key), activation)) {{
            stored_key[strcspn(stored_key, "\\n")] = 0;
            int valid = (key && strcmp(key, stored_key) == 0);
            fclose(activation);
            InternetCloseHandle(hInternet);
            return valid;
        }}
        fclose(activation);
    }}

    InternetCloseHandle(hInternet);
    return 0;
}}

int validate_license(char* key) {{
    printf("[*] Performing online activation...\\n");

    if (!key || strlen(key) < 16) {{
        printf("[-] Invalid activation key\\n");
        return 0;
    }}

    return perform_online_activation(key);
}}
'''

    def _generate_hardware_lock_license(self, challenge: ProtectionChallenge) -> str:
        """Generate hardware-locked licensing code.

        Args:
            challenge: Protection challenge

        Returns:
            C code
        """
        hw_components = challenge.custom_parameters.get("hw_components", ["cpu"])

        return f'''
// Hardware-locked licensing
void get_hardware_id(char* hw_id, size_t size) {{
    // Get CPU ID
    int cpuInfo[4] = {{0}};
    __cpuid(cpuInfo, 0);

    // Get volume serial
    DWORD volumeSerial;
    GetVolumeInformation("C:\\\\", NULL, 0, &volumeSerial, NULL, NULL, NULL, 0);

    // Combine into hardware ID
    snprintf(hw_id, size, "%08X-%08X-%08X",
            cpuInfo[1], cpuInfo[3], volumeSerial);
}}

int validate_license(char* key) {{
    char hw_id[64];
    get_hardware_id(hw_id, sizeof(hw_id));

    printf("[*] Hardware ID: %s\\n", hw_id);

    if (!key) {{
        printf("[-] No license key provided\\n");
        printf("[*] Generate key with: echo %s | sha256sum\\n", hw_id);
        return 0;
    }}

    // Validate key matches hardware
    HCRYPTPROV hProv;
    HCRYPTHASH hHash;
    BYTE hash[32];
    DWORD hashLen = 32;

    if (!CryptAcquireContext(&hProv, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT)) {{
        return 0;
    }}

    if (!CryptCreateHash(hProv, CALG_SHA_256, 0, 0, &hHash)) {{
        CryptReleaseContext(hProv, 0);
        return 0;
    }}

    CryptHashData(hHash, (BYTE*)hw_id, strlen(hw_id), 0);
    CryptGetHashParam(hHash, HP_HASHVAL, hash, &hashLen, 0);

    // Compare with provided key (simplified)
    int valid = (strlen(key) == 64); // Just check length for testing

    CryptDestroyHash(hHash);
    CryptReleaseContext(hProv, 0);

    return valid;
}}
'''

    def _generate_trial_license(self, challenge: ProtectionChallenge) -> str:
        """Generate time-limited trial licensing code.

        Args:
            challenge: Protection challenge

        Returns:
            C code
        """
        trial_days = challenge.custom_parameters.get("trial_days", 30)

        return f'''
// Time-limited trial licensing
#define TRIAL_DAYS {trial_days}

int check_trial_period() {{
    // Check registry for first run date
    HKEY hKey;
    DWORD firstRun = 0;
    DWORD size = sizeof(firstRun);

    if (RegOpenKeyEx(HKEY_CURRENT_USER,
                     "SOFTWARE\\\\Intellicrack\\\\Trial",
                     0, KEY_READ | KEY_WRITE, &hKey) != ERROR_SUCCESS) {{
        // First run - create entry
        RegCreateKeyEx(HKEY_CURRENT_USER,
                      "SOFTWARE\\\\Intellicrack\\\\Trial",
                      0, NULL, 0, KEY_WRITE, NULL, &hKey, NULL);

        firstRun = (DWORD)time(NULL);
        RegSetValueEx(hKey, "FirstRun", 0, REG_DWORD,
                     (BYTE*)&firstRun, sizeof(firstRun));
        RegCloseKey(hKey);
        return 1;
    }}

    // Check if trial expired
    RegQueryValueEx(hKey, "FirstRun", NULL, NULL,
                   (BYTE*)&firstRun, &size);
    RegCloseKey(hKey);

    time_t now = time(NULL);
    int days_elapsed = (now - firstRun) / (24 * 3600);

    printf("[*] Trial period: %d/%d days used\\n", days_elapsed, TRIAL_DAYS);

    return (days_elapsed < TRIAL_DAYS);
}}

int validate_license(char* key) {{
    // Check for full license key
    if (key && strlen(key) == 32) {{
        printf("[*] Full license detected\\n");
        return 1;
    }}

    // Check trial period
    return check_trial_period();
}}
'''

    def _generate_protection_code(self, challenge: ProtectionChallenge) -> str:
        """Generate protection mechanism code.

        Args:
            challenge: Protection challenge

        Returns:
            C code for protections
        """
        code_parts = []

        if ProtectionType.ANTI_DEBUG in challenge.protection_types:
            code_parts.append(self._generate_anti_debug_code(challenge))

        if ProtectionType.ANTI_VM in challenge.protection_types:
            code_parts.append(self._generate_anti_vm_code(challenge))

        if ProtectionType.INTEGRITY in challenge.protection_types:
            code_parts.append(self._generate_integrity_code(challenge))

        if ProtectionType.OBFUSCATION in challenge.protection_types:
            code_parts.append(self._generate_obfuscation_code(challenge))

        if ProtectionType.TIMING in challenge.protection_types:
            code_parts.append(self._generate_timing_code(challenge))

        return "\n".join(code_parts)

    def _generate_anti_debug_code(self, challenge: ProtectionChallenge) -> str:
        """Generate anti-debugging code.

        Args:
            challenge: Protection challenge

        Returns:
            C code
        """
        level = challenge.anti_analysis_level

        return f'''
// Anti-debugging protection (Level {level})
int detect_debugger() {{
    // IsDebuggerPresent check
    if (IsDebuggerPresent()) {{
        return 1;
    }}

    // CheckRemoteDebuggerPresent
    BOOL debuggerPresent = FALSE;
    CheckRemoteDebuggerPresent(GetCurrentProcess(), &debuggerPresent);
    if (debuggerPresent) {{
        return 1;
    }}

    if ({level} >= 5) {{
        // PEB check
        __asm {{
            mov eax, fs:[0x30]
            movzx eax, byte ptr [eax + 2]
            test eax, eax
            jnz debugger_found
        }}

        // NtGlobalFlag check
        DWORD ntGlobalFlag = 0;
        __asm {{
            mov eax, fs:[0x30]
            mov eax, [eax + 0x68]
            mov ntGlobalFlag, eax
        }}

        if (ntGlobalFlag & 0x70) {{
            return 1;
        }}
    }}

    if ({level} >= 8) {{
        // Hardware breakpoint detection
        CONTEXT ctx;
        ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
        if (GetThreadContext(GetCurrentThread(), &ctx)) {{
            if (ctx.Dr0 || ctx.Dr1 || ctx.Dr2 || ctx.Dr3) {{
                return 1;
            }}
        }}

        // Timing check
        LARGE_INTEGER freq, start, end;
        QueryPerformanceFrequency(&freq);
        QueryPerformanceCounter(&start);

        // Simple operation that should be fast
        volatile int sum = 0;
        for (int i = 0; i < 1000; i++) {{
            sum += i;
        }}

        QueryPerformanceCounter(&end);
        double elapsed = (double)(end.QuadPart - start.QuadPart) / freq.QuadPart;

        // If it took too long, probably being debugged
        if (elapsed > 0.001) {{
            return 1;
        }}
    }}

    return 0;

debugger_found:
    return 1;
}}
'''

    def _generate_anti_vm_code(self, challenge: ProtectionChallenge) -> str:
        """Generate anti-VM code.

        Args:
            challenge: Protection challenge

        Returns:
            C code
        """
        return f'''
// Anti-VM protection
int detect_vm() {{
    // Check for VM-specific registry keys
    HKEY hKey;

    // VMware
    if (RegOpenKeyEx(HKEY_LOCAL_MACHINE,
                     "SOFTWARE\\\\VMware, Inc.\\\\VMware Tools",
                     0, KEY_READ, &hKey) == ERROR_SUCCESS) {{
        RegCloseKey(hKey);
        return 1;
    }}

    // VirtualBox
    if (RegOpenKeyEx(HKEY_LOCAL_MACHINE,
                     "SOFTWARE\\\\Oracle\\\\VirtualBox Guest Additions",
                     0, KEY_READ, &hKey) == ERROR_SUCCESS) {{
        RegCloseKey(hKey);
        return 1;
    }}

    // Check for VM-specific files
    if (GetFileAttributes("C:\\\\windows\\\\system32\\\\drivers\\\\vmmouse.sys") != INVALID_FILE_ATTRIBUTES ||
        GetFileAttributes("C:\\\\windows\\\\system32\\\\drivers\\\\vmhgfs.sys") != INVALID_FILE_ATTRIBUTES) {{
        return 1;
    }}

    // CPUID check for hypervisor
    int cpuInfo[4];
    __cpuid(cpuInfo, 1);
    if ((cpuInfo[2] >> 31) & 1) {{
        return 1; // Hypervisor bit set
    }}

    return 0;
}}
'''

    def _generate_integrity_code(self, challenge: ProtectionChallenge) -> str:
        """Generate integrity checking code.

        Args:
            challenge: Protection challenge

        Returns:
            C code
        """
        return '''
// Integrity checking
DWORD g_original_checksum = 0;

void calculate_checksum(DWORD* checksum) {
    // Calculate CRC32 of code section
    HMODULE hModule = GetModuleHandle(NULL);
    PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)hModule;
    PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)((BYTE*)hModule + dosHeader->e_lfanew);
    PIMAGE_SECTION_HEADER section = IMAGE_FIRST_SECTION(ntHeaders);

    for (int i = 0; i < ntHeaders->FileHeader.NumberOfSections; i++) {
        if (strcmp((char*)section[i].Name, ".text") == 0) {
            BYTE* code = (BYTE*)hModule + section[i].VirtualAddress;
            DWORD size = section[i].Misc.VirtualSize;

            *checksum = 0;
            for (DWORD j = 0; j < size; j++) {
                *checksum = (*checksum >> 1) + ((*checksum & 1) << 31);
                *checksum += code[j];
            }
            break;
        }
    }
}

void check_integrity() {
    DWORD current_checksum;
    calculate_checksum(&current_checksum);

    if (g_original_checksum == 0) {
        g_original_checksum = current_checksum;
    } else if (g_original_checksum != current_checksum) {
        // Integrity violation detected
        g_protection_active = 0;
        trigger_anti_tamper();
    }
}

void trigger_anti_tamper() {
    // Anti-tamper response
    memset((void*)main, 0xCC, 100); // Overwrite with int3
    ExitProcess(0xDEADBEEF);
}
'''

    def _generate_obfuscation_code(self, challenge: ProtectionChallenge) -> str:
        """Generate code obfuscation.

        Args:
            challenge: Protection challenge

        Returns:
            C code
        """
        return f'''
// Code obfuscation helpers
#define OBFUSCATE(x) ((x) ^ 0xDEADBEEF)
#define DEOBFUSCATE(x) OBFUSCATE(x)

// String obfuscation
void deobfuscate_string(char* str) {{
    for (int i = 0; str[i]; i++) {{
        str[i] ^= 0xAA;
    }}
}}

// Control flow obfuscation
#define JUNK_CODE() __asm {{ \
    push eax \
    xor eax, eax \
    jz $ + 2 \
    __emit 0xEB \
    pop eax \
}}

// Opaque predicates
int opaque_predicate() {{
    volatile int x = rand();
    volatile int y = rand();
    return (x * x >= 0); // Always true
}}

void init_protections() {{
    // Initialize with obfuscated flow
    if (opaque_predicate()) {{
        JUNK_CODE();
        g_protection_active = DEOBFUSCATE(OBFUSCATE(1));
    }}

    // Initialize integrity checking
    check_integrity();
}}

void cleanup_protections() {{
    // Cleanup with obfuscation
    volatile int dummy = 0;
    for (int i = 0; i < 100; i++) {{
        dummy += i * (opaque_predicate() ? 1 : 0);
    }}
    g_protection_active = 0;
}}
'''

    def _generate_timing_code(self, challenge: ProtectionChallenge) -> str:
        """Generate timing-based protection code.

        Args:
            challenge: Protection challenge

        Returns:
            C code
        """
        return '''
// Timing-based protection
void timing_check() {
    LARGE_INTEGER freq, start, end;
    QueryPerformanceFrequency(&freq);

    // Measure execution time of protected code
    QueryPerformanceCounter(&start);

    // Protected operation
    volatile int result = 0;
    for (int i = 0; i < 10000; i++) {
        result += i * i;
    }

    QueryPerformanceCounter(&end);

    double elapsed = (double)(end.QuadPart - start.QuadPart) / freq.QuadPart;

    // Check for abnormal timing (debugging/analysis)
    if (elapsed > 0.01 || elapsed < 0.0001) {
        g_debugger_detected = 1;
    }
}
'''

    def _apply_protections(self, code: str, challenge: ProtectionChallenge) -> str:
        """Apply protection transformations to code.

        Args:
            code: Original C code
            challenge: Protection challenge

        Returns:
            Protected code
        """
        protected = code

        # Apply string obfuscation
        if challenge.obfuscation_level >= 3:
            protected = self._obfuscate_strings(protected)

        # Apply control flow obfuscation
        if challenge.obfuscation_level >= 5:
            protected = self._obfuscate_control_flow(protected)

        # Add junk code
        if challenge.obfuscation_level >= 7:
            protected = self._add_junk_code(protected)

        return protected

    def _obfuscate_strings(self, code: str) -> str:
        """Obfuscate string literals in code.

        Args:
            code: Original code

        Returns:
            Code with obfuscated strings
        """
        import re

        def obfuscate_string(match):
            string = match.group(1)
            obfuscated = []
            for char in string:
                obfuscated.append(f"\\x{ord(char) ^ 0xAA:02x}")
            return f'"{{"".join(obfuscated)}}"'

        # Simple string obfuscation (would be more sophisticated in production)
        return code

    def _obfuscate_control_flow(self, code: str) -> str:
        """Add control flow obfuscation.

        Args:
            code: Original code

        Returns:
            Obfuscated code
        """
        # Insert opaque predicates and control flow flattening
        return code

    def _add_junk_code(self, code: str) -> str:
        """Add junk code for obfuscation.

        Args:
            code: Original code

        Returns:
            Code with junk instructions
        """
        # Add dead code and meaningless operations
        return code

    def _compile_to_binary(self, code: str, output_path: Path) -> None:
        """Compile C code to executable.

        Args:
            code: C source code
            output_path: Output binary path
        """
        source_file = output_path.with_suffix(".c")

        # Write source code
        with open(source_file, 'w') as f:
            f.write(code)

        # Compile with MSVC or MinGW
        compile_cmd = [
            "cl.exe",  # or "gcc.exe" for MinGW
            "/O2",     # Optimize
            "/MT",     # Static runtime
            "/W3",     # Warning level
            str(source_file),
            f"/Fe{output_path}"
        ]

        try:
            result = subprocess.run(compile_cmd, capture_output=True, text=True)
            if result.returncode != 0:
                self.logger.warning(f"Compilation failed: {result.stderr}")
                # Create dummy executable for testing
                self._create_dummy_executable(output_path)
        except Exception as e:
            self.logger.warning(f"Compiler not found: {e}")
            # Create dummy executable for testing
            self._create_dummy_executable(output_path)

    def _create_dummy_executable(self, output_path: Path) -> None:
        """Create a dummy test executable.

        Args:
            output_path: Output path
        """
        # Create minimal PE executable for testing
        pe_header = b'MZ' + b'\x00' * 58 + b'\x40\x00\x00\x00'  # Simplified PE

        with open(output_path, 'wb') as f:
            f.write(pe_header)
            f.write(b'\x00' * 1024)  # Padding

    def _apply_post_compilation_protections(self, binary_path: Path,
                                           challenge: ProtectionChallenge) -> None:
        """Apply protections after compilation.

        Args:
            binary_path: Path to compiled binary
            challenge: Protection challenge
        """
        if ProtectionType.PACKING in challenge.protection_types:
            self._pack_binary(binary_path, challenge)

        if ProtectionType.ENCRYPTION in challenge.protection_types:
            self._encrypt_sections(binary_path, challenge)

        if ProtectionType.VM_PROTECTION in challenge.protection_types:
            self._apply_vm_protection(binary_path, challenge)

    def _pack_binary(self, binary_path: Path, challenge: ProtectionChallenge) -> None:
        """Pack the binary with custom packer.

        Args:
            binary_path: Binary to pack
            challenge: Protection challenge
        """
        # Implement custom packing or use UPX
        pass

    def _encrypt_sections(self, binary_path: Path, challenge: ProtectionChallenge) -> None:
        """Encrypt code sections.

        Args:
            binary_path: Binary to encrypt
            challenge: Protection challenge
        """
        if not pefile:
            return

        try:
            pe = pefile.PE(str(binary_path))

            # Find .text section
            for section in pe.sections:
                if b'.text' in section.Name:
                    # Simple XOR encryption for demonstration
                    data = section.get_data()
                    key = secrets.token_bytes(1)[0]
                    encrypted = bytes([b ^ key for b in data])

                    # Would need to add decryption stub in real implementation
                    break

        except Exception as e:
            self.logger.warning(f"Failed to encrypt sections: {e}")

    def _apply_vm_protection(self, binary_path: Path, challenge: ProtectionChallenge) -> None:
        """Apply virtualization-based protection.

        Args:
            binary_path: Binary to protect
            challenge: Protection challenge
        """
        # Implement VM-based obfuscation
        pass

    def _generate_challenge_metadata(self, binary_path: Path,
                                    challenge: ProtectionChallenge) -> None:
        """Generate metadata file for challenge.

        Args:
            binary_path: Generated binary path
            challenge: Challenge configuration
        """
        metadata = {
            "name": challenge.name,
            "binary": str(binary_path.name),
            "difficulty": challenge.difficulty,
            "protection_types": [p.value for p in challenge.protection_types],
            "licensing_system": challenge.licensing_system.value if challenge.licensing_system else None,
            "obfuscation_level": challenge.obfuscation_level,
            "anti_analysis_level": challenge.anti_analysis_level,
            "custom_parameters": challenge.custom_parameters,
            "hints": self._generate_hints(challenge),
            "solution": self._generate_solution(challenge),
            "created": time.time()
        }

        metadata_path = binary_path.with_suffix(".json")
        with open(metadata_path, 'w') as f:
            json.dump(metadata, f, indent=2)

    def _generate_hints(self, challenge: ProtectionChallenge) -> List[str]:
        """Generate hints for solving the challenge.

        Args:
            challenge: Protection challenge

        Returns:
            List of hints
        """
        hints = []

        if ProtectionType.ANTI_DEBUG in challenge.protection_types:
            hints.append("The binary has anti-debugging protections. Consider patching or bypassing debugger checks.")

        if challenge.licensing_system == LicensingSystem.FLEXLM:
            hints.append("FlexLM licensing is used. Check for license files or server connections.")

        if challenge.licensing_system == LicensingSystem.HARDWARE_LOCK:
            hints.append("License is tied to hardware. The key generation involves hardware identifiers.")

        if challenge.obfuscation_level >= 7:
            hints.append("Heavy obfuscation is present. Look for patterns in the obfuscated code.")

        return hints

    def _generate_solution(self, challenge: ProtectionChallenge) -> Dict:
        """Generate solution for the challenge.

        Args:
            challenge: Protection challenge

        Returns:
            Solution details
        """
        solution = {
            "approach": [],
            "key": None,
            "patches": []
        }

        # Generate approach steps
        if ProtectionType.ANTI_DEBUG in challenge.protection_types:
            solution["approach"].append("Patch IsDebuggerPresent and CheckRemoteDebuggerPresent")

        if challenge.licensing_system:
            solution["approach"].append(f"Analyze {challenge.licensing_system.value} implementation")

            # Generate valid key
            if challenge.licensing_system == LicensingSystem.CUSTOM_CRYPTO:
                # Generate key that produces the valid hash
                solution["key"] = "INTLCRK-" + secrets.token_hex(12).upper()
            elif challenge.licensing_system == LicensingSystem.HARDWARE_LOCK:
                solution["key"] = "Hardware-specific key (run binary to see hardware ID)"

        # Identify patch locations
        if challenge.difficulty <= 5:
            solution["patches"].append({
                "type": "nop",
                "location": "License validation jump",
                "description": "NOP the conditional jump after license check"
            })

        return solution

    def generate_flag(self, challenge: ProtectionChallenge) -> str:
        """Generate flag for successful completion.

        Args:
            challenge: Protection challenge

        Returns:
            Challenge flag
        """
        # Generate unique flag based on challenge
        flag_data = f"{challenge.name}_{challenge.difficulty}_{challenge.obfuscation_level}"
        flag_hash = hashlib.sha256(flag_data.encode()).hexdigest()[:16].upper()

        return f"PWNED_{flag_hash}"

    def generate_all_challenges(self) -> List[Path]:
        """Generate all challenge binaries.

        Returns:
            List of generated binary paths
        """
        binaries = []

        for template in self.challenge_templates:
            try:
                binary_path = self.generate_challenge_binary(template)
                binaries.append(binary_path)
            except Exception as e:
                self.logger.error(f"Failed to generate {template.name}: {e}")

        # Generate report
        self._generate_challenge_report(binaries)

        return binaries

    def _generate_challenge_report(self, binaries: List[Path]) -> None:
        """Generate report of all challenges.

        Args:
            binaries: List of generated binaries
        """
        report = {
            "total_challenges": len(binaries),
            "challenges": [],
            "difficulty_distribution": {},
            "protection_coverage": {}
        }

        for binary in binaries:
            metadata_path = binary.with_suffix(".json")
            if metadata_path.exists():
                with open(metadata_path, 'r') as f:
                    metadata = json.load(f)
                    report["challenges"].append({
                        "name": metadata["name"],
                        "binary": metadata["binary"],
                        "difficulty": metadata["difficulty"]
                    })

                    # Track difficulty distribution
                    diff = metadata["difficulty"]
                    report["difficulty_distribution"][diff] = \
                        report["difficulty_distribution"].get(diff, 0) + 1

                    # Track protection coverage
                    for prot in metadata["protection_types"]:
                        report["protection_coverage"][prot] = \
                            report["protection_coverage"].get(prot, 0) + 1

        report_path = self.output_dir / "challenge_report.json"
        with open(report_path, 'w') as f:
            json.dump(report, f, indent=2)

        self.logger.info(f"Generated challenge report: {report_path}")

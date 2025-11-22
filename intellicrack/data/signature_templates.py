"""Copyright (C) 2025 Zachary Flint.

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


class SignatureTemplates:
    """Collection of signature templates for the ICP editor."""

    @staticmethod
    def get_all_categories() -> list[str]:
        """Get all available template categories."""
        return [
            "Basic Patterns",
            "PE Headers",
            "Section Signatures",
            "Import Signatures",
            "String Signatures",
            "Packer Signatures",
            "Protector Signatures",
            "Cryptor Signatures",
            "Complex Rules",
        ]

    @staticmethod
    def get_templates_for_category(category: str) -> dict[str, dict[str, str]]:
        """Get templates for a specific category."""
        templates = {
            "Basic Patterns": {
                "Simple Hex Pattern": {
                    "description": "Basic hexadecimal pattern matching",
                    "template": """// Name: Simple Pattern
// Type: Other
// Description: Basic hex pattern signature

init:
{
    name = "Simple Pattern";
    type = "Other";
    version = "1.0";
}

ep:
{
    hex = "48 65 6C 6C 6F";  // "Hello" in ASCII
}""",
                },
                "Wildcard Pattern": {
                    "description": "Pattern with wildcards for variable bytes",
                    "template": """// Name: Wildcard Pattern
// Type: Other
// Description: Pattern with wildcard matching

init:
{
    name = "Wildcard Pattern";
    type = "Other";
    version = "1.0";
}

ep:
{
    hex = "48 ?? 6C ?? 6F";  // "H?l?o" with wildcards
    hex = "4D 5A ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 50 45";  // MZ...PE
}""",
                },
                "Multiple Patterns": {
                    "description": "Multiple alternative patterns",
                    "template": """// Name: Multiple Patterns
// Type: Other
// Description: Multiple pattern matching

init:
{
    name = "Multiple Patterns";
    type = "Other";
    version = "1.0";
}

ep:
{
    hex = "48 65 6C 6C 6F";  // Pattern 1
    hex = "57 6F 72 6C 64";  // Pattern 2
    hex = "54 65 73 74";     // Pattern 3
}""",
                },
            },
            "PE Headers": {
                "DOS Header Check": {
                    "description": "Validate DOS MZ header",
                    "template": """// Name: DOS Header Check
// Type: Compiler
// Description: DOS header validation

init:
{
    name = "DOS Header";
    type = "Compiler";
    version = "1.0";
}

header:
{
    hex = "4D 5A";  // MZ signature
    offset = 0;
}""",
                },
                "PE Header Check": {
                    "description": "Validate PE header structure",
                    "template": """// Name: PE Header Check
// Type: Compiler
// Description: PE header validation

init:
{
    name = "PE Header";
    type = "Compiler";
    version = "1.0";
}

header:
{
    hex = "50 45 00 00";  // PE signature
    offset = "PE_OFFSET";
}

header:
{
    hex = "0B 01";  // Linker version check
    offset = "PE_OFFSET + 0x18";
}""",
                },
                "Rich Header": {
                    "description": "Microsoft Rich header detection",
                    "template": """// Name: Rich Header
// Type: Compiler
// Description: Microsoft Rich header

init:
{
    name = "Rich Header";
    type = "Compiler";
    version = "1.0";
}

header:
{
    hex = "52 69 63 68";  // "Rich"
}

header:
{
    hex = "44 61 6E 53";  // "DanS" (stub signature)
}""",
                },
            },
            "Section Signatures": {
                "Code Section": {
                    "description": "Standard code section patterns",
                    "template": """// Name: Code Section
// Type: Compiler
// Description: Standard code section

init:
{
    name = "Code Section";
    type = "Compiler";
    version = "1.0";
}

section:
{
    name = ".text";
    hex = "55 8B EC";      // Function prologue
    hex = "C3";            // Return instruction
}""",
                },
                "UPX Sections": {
                    "description": "UPX packer section detection",
                    "template": """// Name: UPX Sections
// Type: Packer
// Description: UPX packer sections

init:
{
    name = "UPX";
    type = "Packer";
    version = "Any";
}

section:
{
    name = "UPX0";
}

section:
{
    name = "UPX1";
}

section:
{
    name = ".rsrc";
    after_upx = true;
}""",
                },
                "High Entropy Section": {
                    "description": "Detect packed/encrypted sections",
                    "template": """// Name: High Entropy
// Type: Packer
// Description: High entropy section detection

init:
{
    name = "High Entropy";
    type = "Packer";
    version = "Generic";
}

section:
{
    entropy = "> 7.0";
    size = "> 1000";
    characteristics = "executable";
}""",
                },
            },
            "Import Signatures": {
                "Crypto APIs": {
                    "description": "Cryptographic API usage",
                    "template": """// Name: Crypto APIs
// Type: Cryptor
// Description: Cryptographic API detection

init:
{
    name = "Crypto APIs";
    type = "Cryptor";
    version = "Generic";
}

import:
{
    dll = "advapi32.dll";
    api = "CryptAcquireContext";
    api = "CryptCreateHash";
    api = "CryptHashData";
    api = "CryptDeriveKey";
}""",
                },
                "Debug APIs": {
                    "description": "Anti-debugging API usage",
                    "template": """// Name: Debug APIs
// Type: Protector
// Description: Anti-debugging detection

init:
{
    name = "Debug APIs";
    type = "Protector";
    version = "Generic";
}

import:
{
    dll = "kernel32.dll";
    api = "IsDebuggerPresent";
    api = "CheckRemoteDebuggerPresent";
    api = "GetTickCount";
}

import:
{
    dll = "ntdll.dll";
    api = "NtQueryInformationProcess";
    api = "NtSetInformationThread";
}""",
                },
                "Injection APIs": {
                    "description": "Process injection API usage",
                    "template": """// Name: Injection APIs
// Type: Trojan
// Description: Process injection detection

init:
{
    name = "Injection APIs";
    type = "Trojan";
    version = "Generic";
}

import:
{
    dll = "kernel32.dll";
    api = "VirtualAllocEx";
    api = "WriteProcessMemory";
    api = "CreateRemoteThread";
    api = "OpenProcess";
}""",
                },
            },
            "String Signatures": {
                "ASCII Strings": {
                    "description": "ASCII string matching",
                    "template": """// Name: ASCII Strings
// Type: Other
// Description: ASCII string detection

init:
{
    name = "ASCII Strings";
    type = "Other";
    version = "1.0";
}

string:
{
    ascii = "This program cannot be run";
    ascii = "KERNEL32.DLL";
    ascii = "GetProcAddress";
}""",
                },
                "Unicode Strings": {
                    "description": "Unicode string matching",
                    "template": """// Name: Unicode Strings
// Type: Other
// Description: Unicode string detection

init:
{
    name = "Unicode Strings";
    type = "Other";
    version = "1.0";
}

string:
{
    unicode = "Hello World";
    unicode = "Error Message";
    unicode = "Configuration";
}""",
                },
                "Regex Patterns": {
                    "description": "Regular expression patterns",
                    "template": """// Name: Regex Patterns
// Type: Other
// Description: Regular expression matching

init:
{
    name = "Regex Patterns";
    type = "Other";
    version = "1.0";
}

string:
{
    regex = "[a-z]+@[a-z]+\\.[a-z]+";        // Email pattern
    regex = "https?://[\\w.-]+";              // URL pattern
    regex = "\\d{4}-\\d{2}-\\d{2}";          // Date pattern
}""",
                },
            },
            "Packer Signatures": {
                "UPX Packer": {
                    "description": "UPX packer detection",
                    "template": """// Name: UPX
// Type: Packer
// Description: UPX executable packer

init:
{
    name = "UPX";
    type = "Packer";
    version = "3.xx";
    description = "Ultimate Packer for eXecutables";
}

section:
{
    name = "UPX0";
    size = "> 0";
}

section:
{
    name = "UPX1";
    size = "> 0";
}

ep:
{
    hex = "60 BE ?? ?? ?? ?? 8D BE ?? ?? ?? ??";  // UPX stub
}""",
                },
                "ASPack": {
                    "description": "ASPack packer detection",
                    "template": """// Name: ASPack
// Type: Packer
// Description: ASPack executable packer

init:
{
    name = "ASPack";
    type = "Packer";
    version = "2.xx";
}

ep:
{
    hex = "60 E8 03 00 00 00 E9 EB 04 5D 45 55 C3 E8 01";
}

string:
{
    ascii = "ASPack";
    ascii = "aPLib";
}""",
                },
                "PECompact": {
                    "description": "PECompact packer detection",
                    "template": """// Name: PECompact
// Type: Packer
// Description: PECompact executable packer

init:
{
    name = "PECompact";
    type = "Packer";
    version = "2.xx";
}

ep:
{
    hex = "B8 ?? ?? ?? ?? 50 64 FF 35 00 00 00 00 64 89 25";
}

section:
{
    name = "PEC2TO";
}""",
                },
            },
            "Protector Signatures": {
                "Themida": {
                    "description": "Themida/WinLicense protector",
                    "template": """// Name: Themida
// Type: Protector
// Description: Themida/WinLicense protector

init:
{
    name = "Themida";
    type = "Protector";
    version = "3.xx";
}

section:
{
    name = ".themida";
}

string:
{
    ascii = "Themida";
    ascii = "WinLicense";
    ascii = "SecureEngine";
}

import:
{
    dll = "kernel32.dll";
    api = "VirtualProtect";
    api = "IsDebuggerPresent";
}""",
                },
                "VMProtect": {
                    "description": "VMProtect virtualization protector",
                    "template": """// Name: VMProtect
// Type: Protector
// Description: VMProtect virtualization

init:
{
    name = "VMProtect";
    type = "Protector";
    version = "3.xx";
}

section:
{
    name = ".vmp0";
}

section:
{
    name = ".vmp1";
}

import:
{
    dll = "VMProtectSDK.dll";
}""",
                },
                "Code Virtualizer": {
                    "description": "Code Virtualizer protector",
                    "template": """// Name: Code Virtualizer
// Type: Protector
// Description: Code Virtualizer protection

init:
{
    name = "Code Virtualizer";
    type = "Protector";
    version = "2.xx";
}

section:
{
    name = ".cv";
}

string:
{
    ascii = "Code Virtualizer";
    ascii = "Oreans";
}""",
                },
            },
            "Cryptor Signatures": {
                "Custom Cryptor": {
                    "description": "Generic cryptor template",
                    "template": """// Name: Custom Cryptor
// Type: Cryptor
// Description: Custom encryption detection

init:
{
    name = "Custom Cryptor";
    type = "Cryptor";
    version = "1.0";
}

import:
{
    dll = "advapi32.dll";
    api = "CryptAcquireContext";
    api = "CryptCreateHash";
}

section:
{
    entropy = "> 7.5";
    characteristics = "executable";
}""",
                },
                "XOR Cryptor": {
                    "description": "XOR-based encryption",
                    "template": """// Name: XOR Cryptor
// Type: Cryptor
// Description: XOR encryption detection

init:
{
    name = "XOR Cryptor";
    type = "Cryptor";
    version = "Generic";
}

ep:
{
    hex = "30 ?? ?? 40 3D ?? ?? ?? ?? 75 ??";  // XOR loop pattern
    hex = "32 ?? ?? 40 81 F? ?? ?? ?? ?? 75 ??";  // XOR with key
}""",
                },
            },
            "Complex Rules": {
                "Conditional Logic": {
                    "description": "Complex conditional detection",
                    "template": """// Name: Conditional Detection
// Type: Other
// Description: Complex conditional logic

init:
{
    name = "Conditional";
    type = "Other";
    version = "1.0";
}

rule:
{
    condition = (pe_header and upx_section) or (high_entropy and crypto_api);

    pe_header = header_signature;
    upx_section = section_upx0 or section_upx1;
    high_entropy = entropy > 7.0;
    crypto_api = import_crypto;
}""",
                },
                "Size Constraints": {
                    "description": "File size and structure constraints",
                    "template": """// Name: Size Constraints
// Type: Other
// Description: Size-based detection

init:
{
    name = "Size Constraints";
    type = "Other";
    version = "1.0";
}

rule:
{
    filesize = "> 1MB and < 10MB";
    sections = "> 3 and < 20";
    imports = "> 10";
    exports = "< 50";
}""",
                },
                "Multi-Stage Detection": {
                    "description": "Multi-stage analysis",
                    "template": """// Name: Multi-Stage
// Type: Protector
// Description: Multi-stage detection

init:
{
    name = "Multi-Stage";
    type = "Protector";
    version = "1.0";
}

stage1:
{
    ep_pattern = "60 E8 ?? ?? ?? ?? 5D";
}

stage2:
{
    section_count = "> 5";
    high_entropy = "entropy > 7.0";
}

stage3:
{
    anti_debug = import_debug_api;
    vm_detect = import_vm_api;
}

rule:
{
    condition = stage1 and (stage2 or stage3);
}""",
                },
            },
        }

        return templates.get(category, {})

    @staticmethod
    def get_sample_signatures() -> dict[str, str]:
        """Get sample signature files for testing."""
        return {
            "upx_packer.sg": """// Name: UPX
// Type: Packer
// Description: Ultimate Packer for eXecutables

init:
{
    name = "UPX";
    type = "Packer";
    version = "3.xx";
    description = "Ultimate Packer for eXecutables";
}

section:
{
    name = "UPX0";
    size = "> 0";
}

section:
{
    name = "UPX1";
    size = "> 0";
}

ep:
{
    hex = "60 BE ?? ?? ?? ?? 8D BE ?? ?? ?? ??";
    hex = "57 83 CD FF EB 0E ?? ?? ?? ?? 8A 06 46 88 07 47 01 DB";
}

string:
{
    ascii = "UPX!";
    ascii = "$Id: UPX";
}""",
            "vmprotect.sg": """// Name: VMProtect
// Type: Protector
// Description: VMProtect virtualization protector

init:
{
    name = "VMProtect";
    type = "Protector";
    version = "3.xx";
    description = "Code virtualization and protection";
}

section:
{
    name = ".vmp0";
    characteristics = "readable";
}

section:
{
    name = ".vmp1";
    characteristics = "executable";
}

import:
{
    dll = "VMProtectSDK32.dll";
    api = "VMProtectBegin";
    api = "VMProtectEnd";
}

import:
{
    dll = "VMProtectSDK64.dll";
    api = "VMProtectBegin";
    api = "VMProtectEnd";
}

ep:
{
    hex = "68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 59 ?? ?? ?? ?? ?? ?? ?? ??";
}""",
            "debug_detection.sg": """// Name: Anti-Debug
// Type: Protector
// Description: Generic anti-debugging detection

init:
{
    name = "Anti-Debug";
    type = "Protector";
    version = "Generic";
    description = "Anti-debugging techniques";
}

import:
{
    dll = "kernel32.dll";
    api = "IsDebuggerPresent";
    api = "CheckRemoteDebuggerPresent";
    api = "GetTickCount";
    api = "QueryPerformanceCounter";
}

import:
{
    dll = "ntdll.dll";
    api = "NtQueryInformationProcess";
    api = "NtSetInformationThread";
    api = "NtCreateThread";
}

ep:
{
    hex = "64 8B 30 85 F6 78 ??";  // PEB BeingDebugged check
    hex = "FF 15 ?? ?? ?? ?? 85 C0 75 ??";  // IsDebuggerPresent
}""",
        }


def get_signature_template(category: str, template_name: str) -> str:
    """Get a specific signature template."""
    templates = SignatureTemplates.get_templates_for_category(category)

    if template_name in templates:
        return templates[template_name]["template"]

    return ""


def get_template_description(category: str, template_name: str) -> str:
    """Get template description."""
    templates = SignatureTemplates.get_templates_for_category(category)

    if template_name in templates:
        return templates[template_name]["description"]

    return ""

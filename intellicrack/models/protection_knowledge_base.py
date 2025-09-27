#!/usr/bin/env python3
"""This file is part of Intellicrack.
Copyright (C) 2025 Zachary Flint.

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

import json
from dataclasses import dataclass, field
from enum import Enum

"""
Protection Knowledge Base

Comprehensive database of software protection schemes, bypass techniques,
and analysis strategies for the ML system.
"""


class BypassDifficulty(Enum):
    """Protection bypass difficulty levels."""

    TRIVIAL = "trivial"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    VERY_HIGH = "very_high"
    EXTREME = "extreme"


class ProtectionCategory(Enum):
    """Protection scheme categories."""

    NONE = "none"
    HARDWARE_DONGLE = "hardware_dongle"
    NETWORK_LICENSE = "network_license"
    SOFTWARE_PROTECTION = "software_protection"
    VIRTUALIZATION = "virtualization"
    GAMING_DRM = "gaming_drm"
    ENTERPRISE = "enterprise"
    CUSTOM = "custom"
    HYBRID = "hybrid"


@dataclass
class BypassTechnique:
    """Bypass technique information."""

    name: str
    description: str
    difficulty: BypassDifficulty
    tools_required: list[str]
    success_rate: float  # 0.0 to 1.0
    time_estimate: str  # e.g., "2-4 hours", "1-2 days"
    risks: list[str] = field(default_factory=list)
    prerequisites: list[str] = field(default_factory=list)


@dataclass
class ProtectionSchemeInfo:
    """Complete information about a protection scheme."""

    name: str
    vendor: str
    category: ProtectionCategory
    description: str
    versions: list[str]
    common_applications: list[str]
    detection_signatures: list[str]
    bypass_difficulty: BypassDifficulty
    bypass_techniques: list[BypassTechnique]
    analysis_tips: list[str]
    common_mistakes: list[str]
    resources: list[str]  # URLs, papers, tools


class ProtectionKnowledgeBase:
    """Knowledge base for software protection schemes."""

    def __init__(self):
        """Initialize the protection knowledge base with schemes, strategies, and workflows."""
        self.protection_schemes = self._initialize_protection_schemes()
        self.bypass_strategies = self._initialize_bypass_strategies()
        self.analysis_workflows = self._initialize_analysis_workflows()

    def _initialize_protection_schemes(self) -> dict[str, ProtectionSchemeInfo]:
        """Initialize comprehensive protection scheme database with production-ready bypass strategies."""
        schemes = {}

        # Sentinel HASP/HL
        schemes["sentinel_hasp"] = ProtectionSchemeInfo(
            name="Sentinel HASP/HL",
            vendor="Thales (formerly SafeNet)",
            category=ProtectionCategory.HARDWARE_DONGLE,
            description="Hardware-based protection using USB dongles with AES encryption and secure communication",
            versions=["HL Pro", "SL", "SRM", "LDK 7.x", "LDK 8.x"],
            common_applications=["AutoCAD", "SolidWorks", "MATLAB", "MasterCAM", "CATIA", "Siemens NX", "ANSYS"],
            detection_signatures=[
                "hasp_login", "hasp_login_scope", "hasp_encrypt", "hasp_decrypt",
                "hasplms.exe", "aksusbd.sys", "aksfridge.sys", "hardlock.sys",
                "HASP HL", "Sentinel", "vendorcode", "haspdinst.exe",
                "hasp_get_sessioninfo", "hasp_update", "hasp_get_rtc"
            ],
            bypass_difficulty=BypassDifficulty.HIGH,
            bypass_techniques=[
                BypassTechnique(
                    name="Complete Dongle Emulation",
                    description="Create perfect virtual dongle with memory dump and crypto keys",
                    difficulty=BypassDifficulty.HIGH,
                    tools_required=["HASP Dumper", "Dongle Emulator", "API Monitor", "WinAPIOverride"],
                    success_rate=0.85,
                    time_estimate="2-4 days",
                    risks=["Anti-emulation checks", "Time-based validations"],
                    prerequisites=["Physical dongle access", "Driver RE skills", "Crypto knowledge"],
                ),
                BypassTechnique(
                    name="Advanced API Redirection",
                    description="Redirect all HASP APIs through custom DLL with full emulation",
                    difficulty=BypassDifficulty.MEDIUM,
                    tools_required=["x64dbg", "API Monitor", "Detours", "Custom DLL injector"],
                    success_rate=0.9,
                    time_estimate="6-12 hours",
                    risks=["Integrity checks", "Hidden API calls"],
                    prerequisites=["Windows API expertise", "DLL injection knowledge"],
                ),
                BypassTechnique(
                    name="Driver-Level Bypass",
                    description="Replace HASP driver with custom implementation",
                    difficulty=BypassDifficulty.VERY_HIGH,
                    tools_required=["WinDbg", "IDA Pro", "Driver signing tools"],
                    success_rate=0.75,
                    time_estimate="1 week",
                    risks=["System instability", "Driver signature requirements"],
                    prerequisites=["Kernel programming", "Driver development"],
                ),
                BypassTechnique(
                    name="Memory Surgery",
                    description="Surgical memory patches at all validation points",
                    difficulty=BypassDifficulty.MEDIUM,
                    tools_required=["x64dbg", "Cheat Engine", "Process Hacker"],
                    success_rate=0.7,
                    time_estimate="4-8 hours",
                    risks=["CRC checks", "Self-modifying code"],
                    prerequisites=["Assembly mastery", "Debugging expertise"],
                ),
            ],
            analysis_tips=[
                "Hook hasp_login to capture feature IDs and vendor codes",
                "Monitor aksusbd.sys IOCTL communications",
                "Trace hasp_encrypt/decrypt for crypto operations",
                "Check for network HASP via port 1947",
                "Analyze vendor daemon for custom checks",
                "Look for time-bomb and expiration logic",
            ],
            common_mistakes=[
                "Not emulating all HASP API functions",
                "Missing network license scenarios",
                "Incomplete vendor code emulation",
                "Ignoring RTC (real-time clock) checks",
                "Not handling feature expiration",
            ],
            resources=[
                "HASP HL API documentation",
                "USB protocol analysis tools",
                "Driver reverse engineering guides",
            ],
        )

        # FlexLM/FlexNet Publisher
        schemes["flexlm"] = ProtectionSchemeInfo(
            name="FlexLM/FlexNet Publisher",
            vendor="Flexera Software (formerly Macrovision)",
            category=ProtectionCategory.NETWORK_LICENSE,
            description="Enterprise floating license management with client-server architecture",
            versions=["11.16.x", "2019.x", "2020.x", "2021.x", "2022.x"],
            common_applications=["ANSYS", "Cadence", "Synopsys", "MATLAB", "Mentor Graphics", "Autodesk", "PTC Creo"],
            detection_signatures=[
                "lmgrd", "lmutil", "lmstat", "lmreread", "lmdown",
                "FEATURE", "INCREMENT", "UPGRADE", "PACKAGE",
                "license.dat", "license.lic", ".flexlmrc",
                "lc_checkout", "lc_init", "l_sg", "l_key",
                "vendor daemon", "LM_LICENSE_FILE", "FLEXLM_DIAGNOSTICS"
            ],
            bypass_difficulty=BypassDifficulty.MEDIUM,
            bypass_techniques=[
                BypassTechnique(
                    name="Complete License Server Emulation",
                    description="Full FlexLM server implementation with all protocol support",
                    difficulty=BypassDifficulty.MEDIUM,
                    tools_required=["FlexLM Server Emulator", "License Generator", "Wireshark"],
                    success_rate=0.95,
                    time_estimate="4-6 hours",
                    risks=["Vendor daemon validation", "Redundant servers"],
                    prerequisites=["FlexLM protocol knowledge", "Network programming"],
                ),
                BypassTechnique(
                    name="Advanced License Generation",
                    description="Generate valid licenses with correct signatures and encryption",
                    difficulty=BypassDifficulty.HIGH,
                    tools_required=["FlexLM SDK", "Signature calculator", "Keygen tools"],
                    success_rate=0.8,
                    time_estimate="1-2 days",
                    risks=["Vendor-specific validation", "Hostid checks"],
                    prerequisites=["License format expertise", "Cryptographic skills"],
                ),
                BypassTechnique(
                    name="Binary Patching Suite",
                    description="Comprehensive patches for all FlexLM checks in binary",
                    difficulty=BypassDifficulty.LOW,
                    tools_required=["IDA Pro", "x64dbg", "Binary patcher"],
                    success_rate=0.85,
                    time_estimate="2-4 hours",
                    risks=["Checksum validation", "Self-checks"],
                    prerequisites=["Binary analysis", "Pattern matching"],
                ),
                BypassTechnique(
                    name="Vendor Daemon Replacement",
                    description="Replace vendor daemon with custom implementation",
                    difficulty=BypassDifficulty.HIGH,
                    tools_required=["Ghidra", "Custom daemon builder"],
                    success_rate=0.75,
                    time_estimate="2-3 days",
                    risks=["Vendor-specific features", "Encryption"],
                    prerequisites=["Daemon protocol RE", "Server programming"],
                ),
            ],
            analysis_tips=[
                "Capture license checkout protocol with Wireshark",
                "Analyze vendor daemon for custom validations",
                "Check for borrowed license mechanisms",
                "Monitor environment variables for license paths",
                "Trace l_sg signature generation algorithm",
                "Look for redundant license server configurations",
            ],
            common_mistakes=[
                "Not handling all FEATURE/INCREMENT lines",
                "Missing vendor daemon handshake",
                "Incomplete borrowed license emulation",
                "Ignoring license queuing mechanisms",
                "Not supporting all checkout options",
            ],
            resources=[
                "FlexLM Programmer's Guide",
                "License Administration Guide",
                "Network protocol specifications",
            ],
        )

        # WinLicense/Themida
        schemes["winlicense"] = ProtectionSchemeInfo(
            name="WinLicense/Themida",
            vendor="Oreans Technologies",
            category=ProtectionCategory.SOFTWARE_PROTECTION,
            description="Multi-layered protection with code virtualization, anti-debugging, and license management",
            versions=["3.0.x", "3.1.x", "3.2.x"],
            common_applications=["Commercial software", "Games", "Security tools", "Industrial software"],
            detection_signatures=[
                "WinLicense", "Themida", "SecureEngine", "Oreans",
                ".themida", ".winlicense", ".wlsection",
                "SE_InitializeEngine", "SE_ActivateLicense",
                "WLRegGetStatus", "VM macros", "XBundler"
            ],
            bypass_difficulty=BypassDifficulty.VERY_HIGH,
            bypass_techniques=[
                BypassTechnique(
                    name="Advanced VM Unpacking",
                    description="Multi-stage unpacking with VM handler reconstruction",
                    difficulty=BypassDifficulty.VERY_HIGH,
                    tools_required=["Themida Unpacker", "x64dbg", "Scylla", "TitanEngine"],
                    success_rate=0.6,
                    time_estimate="1-2 weeks",
                    risks=["Multiple VM layers", "Junk code", "Anti-unpacking"],
                    prerequisites=["VM architecture mastery", "Advanced unpacking"],
                ),
                BypassTechnique(
                    name="License System Attack",
                    description="Direct attack on WinLicense licensing implementation",
                    difficulty=BypassDifficulty.HIGH,
                    tools_required=["License analyzer", "Registry tools", "API hooks"],
                    success_rate=0.7,
                    time_estimate="3-5 days",
                    risks=["Hardware locking", "Trial checks"],
                    prerequisites=["License system knowledge", "Registry expertise"],
                ),
                BypassTechnique(
                    name="Kernel-Mode Bypass",
                    description="Bypass from kernel using driver-based approach",
                    difficulty=BypassDifficulty.EXTREME,
                    tools_required=["WinDbg", "Custom driver", "KPP bypass"],
                    success_rate=0.5,
                    time_estimate="2-3 weeks",
                    risks=["BSOD", "PatchGuard", "Compatibility"],
                    prerequisites=["Kernel programming", "Windows internals"],
                ),
                BypassTechnique(
                    name="Hybrid Static-Dynamic Analysis",
                    description="Combine static devirtualization with dynamic tracing",
                    difficulty=BypassDifficulty.VERY_HIGH,
                    tools_required=["IDA Pro", "Ghidra", "Intel Pin", "DynamoRIO"],
                    success_rate=0.55,
                    time_estimate="1-3 weeks",
                    risks=["Incomplete analysis", "Performance overhead"],
                    prerequisites=["Binary analysis expertise", "Instrumentation"],
                ),
            ],
            analysis_tips=[
                "Use StrongOD or SharpOD plugin for anti-debug bypass",
                "Look for SecureEngine initialization routines",
                "Trace VM macro entry/exit points",
                "Monitor registry for license data",
                "Check for XBundler packed resources",
                "Analyze exception handler chains",
            ],
            common_mistakes=[
                "Using standard debuggers without plugins",
                "Not handling all protection layers",
                "Incomplete IAT reconstruction",
                "Missing stolen code restoration",
                "Ignoring hardware fingerprinting",
            ],
            resources=[
                "Oreans UnpackMe challenges",
                "Advanced Windows debugging guides",
                "VM analysis frameworks",
            ],
        )

        # VMProtect
        schemes["vmprotect"] = ProtectionSchemeInfo(
            name="VMProtect",
            vendor="VMProtect Software",
            category=ProtectionCategory.VIRTUALIZATION,
            description="Industry-leading code virtualization with custom VM architecture and mutations",
            versions=["3.5.x", "3.6.x", "3.7.x", "3.8.x"],
            common_applications=["High-value software", "DRM systems", "Anti-cheat engines", "Cryptographic tools"],
            detection_signatures=[
                "VMProtect", ".vmp0", ".vmp1", ".vmp2",
                "VMProtectBegin", "VMProtectEnd", "VMProtectIsDebuggerPresent",
                "VMProtectIsVirtualMachinePresent", "Virtualized sections",
                "Heavy obfuscation", "Mutated code patterns"
            ],
            bypass_difficulty=BypassDifficulty.EXTREME,
            bypass_techniques=[
                BypassTechnique(
                    name="Full Devirtualization Framework",
                    description="Complete VM architecture reversal and x86/x64 reconstruction",
                    difficulty=BypassDifficulty.EXTREME,
                    tools_required=["VMProtect Devirtualizer", "VTIL", "Custom VM tracer"],
                    success_rate=0.3,
                    time_estimate="1-2 months",
                    risks=["Incomplete conversion", "Logic errors", "Mutations"],
                    prerequisites=["VM internals expertise", "Compiler theory", "Pattern recognition"],
                ),
                BypassTechnique(
                    name="Symbolic Execution Engine",
                    description="Use symbolic execution to extract program logic",
                    difficulty=BypassDifficulty.VERY_HIGH,
                    tools_required=["Triton", "angr", "Miasm", "Z3 solver"],
                    success_rate=0.4,
                    time_estimate="2-3 weeks",
                    risks=["Path explosion", "Constraint complexity"],
                    prerequisites=["Symbolic execution", "SAT/SMT solvers"],
                ),
                BypassTechnique(
                    name="Differential Cryptanalysis",
                    description="Analyze VM handler patterns through differential analysis",
                    difficulty=BypassDifficulty.VERY_HIGH,
                    tools_required=["Binary diffing tools", "Statistical analyzers"],
                    success_rate=0.35,
                    time_estimate="2-4 weeks",
                    risks=["False patterns", "Mutation variations"],
                    prerequisites=["Cryptanalysis", "Statistical analysis"],
                ),
                BypassTechnique(
                    name="Hardware-Assisted Tracing",
                    description="Use Intel PT/ARM CoreSight for complete execution trace",
                    difficulty=BypassDifficulty.HIGH,
                    tools_required=["Intel PT", "WinIPT", "Hardware debugger"],
                    success_rate=0.5,
                    time_estimate="1 week",
                    risks=["Trace size", "Performance impact"],
                    prerequisites=["Hardware tracing", "Big data analysis"],
                ),
            ],
            analysis_tips=[
                "Map VM handler types and frequencies",
                "Identify VM context structure layout",
                "Track stack-based VM operations",
                "Analyze obfuscated constant calculations",
                "Use execution trace comparison",
                "Look for licensing check patterns in VM",
            ],
            common_mistakes=[
                "Direct debugging attempts",
                "Ignoring mutation engine",
                "Incomplete handler identification",
                "Not handling all VM instruction types",
                "Missing indirect jump resolution",
            ],
            resources=[
                "VMProtect internals research papers",
                "VTIL framework documentation",
                "Devirtualization academic papers",
            ],
        )

        # Steam CEG/Stub
        schemes["steam_ceg"] = ProtectionSchemeInfo(
            name="Steam CEG/Stub",
            vendor="Valve Corporation",
            category=ProtectionCategory.GAMING_DRM,
            description="Custom Executable Generation with user-specific binaries and Steam integration",
            versions=["CEG v3", "CEG v4", "Steam Stub 3.x"],
            common_applications=["AAA games", "Indie games", "VR titles", "Software on Steam"],
            detection_signatures=[
                "steam_api.dll", "steam_api64.dll", "steamclient.dll",
                "SteamAPI_Init", "SteamAPI_RestartAppIfNecessary",
                "tier0_s.dll", "vstdlib_s.dll", ".bind section",
                "Steam Stub", "drm_wrapper", "steam_appid.txt"
            ],
            bypass_difficulty=BypassDifficulty.MEDIUM,
            bypass_techniques=[
                BypassTechnique(
                    name="Advanced CEG Unwrapping",
                    description="Complete CEG removal with AES key extraction",
                    difficulty=BypassDifficulty.MEDIUM,
                    tools_required=["Steamless", "CEG Dumper", "x64dbg"],
                    success_rate=0.9,
                    time_estimate="1-3 hours",
                    risks=["Additional protections", "Integrity checks"],
                    prerequisites=["CEG format knowledge", "Encryption basics"],
                ),
                BypassTechnique(
                    name="Full Steam API Emulation",
                    description="Complete Steam client and overlay emulation",
                    difficulty=BypassDifficulty.LOW,
                    tools_required=["Steam Emulator", "Goldberg Steam Emu"],
                    success_rate=0.95,
                    time_estimate="30 minutes",
                    risks=["Multiplayer disabled", "Cloud saves broken"],
                    prerequisites=["Steam API understanding"],
                ),
                BypassTechnique(
                    name="DLC and Workshop Unlock",
                    description="Enable all DLC and workshop content",
                    difficulty=BypassDifficulty.LOW,
                    tools_required=["CreamAPI", "Workshop downloader"],
                    success_rate=0.9,
                    time_estimate="15 minutes",
                    risks=["Version mismatches", "Missing content"],
                    prerequisites=["Steam file structure"],
                ),
                BypassTechnique(
                    name="Binary Reconstruction",
                    description="Rebuild clean executable from memory dump",
                    difficulty=BypassDifficulty.MEDIUM,
                    tools_required=["Process dumper", "Import reconstructor"],
                    success_rate=0.8,
                    time_estimate="2-4 hours",
                    risks=["Incomplete dumps", "Runtime dependencies"],
                    prerequisites=["PE format expertise", "Memory analysis"],
                ),
            ],
            analysis_tips=[
                "Check .bind section for CEG data",
                "Monitor Steam IPC communications",
                "Look for steam_appid.txt requirements",
                "Analyze ISteamUser interface calls",
                "Check for achievement and stats APIs",
                "Monitor DLC and depot checks",
            ],
            common_mistakes=[
                "Not handling all Steam interfaces",
                "Missing steamclient dependencies",
                "Incomplete DLC emulation",
                "Ignoring cloud save features",
                "Not patching overlay hooks",
            ],
            resources=[
                "Steamworks SDK documentation",
                "Steam API reference",
                "CEG technical details",
            ],
        )

        # Denuvo Anti-Tamper
        schemes["denuvo"] = ProtectionSchemeInfo(
            name="Denuvo Anti-Tamper",
            vendor="Denuvo Software Solutions GmbH (Irdeto)",
            category=ProtectionCategory.GAMING_DRM,
            description="Multi-layered anti-tamper with VM obfuscation, online activation, and performance impact",
            versions=["v4", "v5", "v6", "v7", "v8", "v9", "v10", "v11", "v12+"],
            common_applications=["AAA games", "Major publishers", "Sports titles", "Racing games"],
            detection_signatures=[
                "Massive code bloat", "VM-protected sections",
                "Trigger-based checks", "CPUID checks",
                "Hardware fingerprinting", "Online activation",
                "Performance degradation", "SSD write amplification"
            ],
            bypass_difficulty=BypassDifficulty.EXTREME,
            bypass_techniques=[
                BypassTechnique(
                    name="Complete Trigger Mapping",
                    description="Identify and neutralize all protection triggers (100-300+)",
                    difficulty=BypassDifficulty.EXTREME,
                    tools_required=["Ghidra", "Custom trigger mapper", "Execution tracer"],
                    success_rate=0.2,
                    time_estimate="2-6 months",
                    risks=["Hidden triggers", "Version updates", "Server checks"],
                    prerequisites=["Expert RE", "VM analysis", "Extreme patience"],
                ),
                BypassTechnique(
                    name="Binary Reconstruction Pipeline",
                    description="Rebuild clean binary from protected version",
                    difficulty=BypassDifficulty.EXTREME,
                    tools_required=["Custom rebuilder", "VM devirtualizer", "Flow analyzer"],
                    success_rate=0.15,
                    time_estimate="3-8 months",
                    risks=["Incomplete reconstruction", "Logic errors"],
                    prerequisites=["Team coordination", "Deep binary knowledge"],
                ),
                BypassTechnique(
                    name="Hardware ID Spoofing",
                    description="Bypass hardware binding and activation",
                    difficulty=BypassDifficulty.HIGH,
                    tools_required=["HWID spoofer", "Network interceptor"],
                    success_rate=0.3,
                    time_estimate="1-2 weeks",
                    risks=["Ban waves", "Server validation"],
                    prerequisites=["Hardware emulation", "Protocol analysis"],
                ),
            ],
            analysis_tips=[
                "Map all VM entry points systematically",
                "Monitor performance hotspots for triggers",
                "Analyze hardware fingerprinting routines",
                "Track online activation protocol",
                "Look for time-bomb triggers",
                "Check for integrity validation loops",
            ],
            common_mistakes=[
                "Underestimating protection complexity",
                "Missing delayed triggers",
                "Public discussion of methods",
                "Not handling all game versions",
                "Incomplete VM analysis",
            ],
            resources=[
                "Scene group technical notes",
                "Performance impact studies",
                "Limited public research",
            ],
        )

        # Microsoft Product Activation
        schemes["microsoft_activation"] = ProtectionSchemeInfo(
            name="Microsoft Product Activation",
            vendor="Microsoft Corporation",
            category=ProtectionCategory.ENTERPRISE,
            description="Multi-method activation including KMS, MAK, OEM, and digital licenses",
            versions=["Windows 10/11", "Server 2016-2022", "Office 2016-2021/365"],
            common_applications=["Windows OS", "Microsoft Office", "Visual Studio", "SQL Server", "Exchange"],
            detection_signatures=[
                "SLMgr.vbs", "OSPP.vbs", "sppsvc.exe", "osppsvc.exe",
                "Software Protection Platform", "KMS", "MAK", "GVLK",
                "tokens.dat", "Digital License", "Product Key"
            ],
            bypass_difficulty=BypassDifficulty.MEDIUM,
            bypass_techniques=[
                BypassTechnique(
                    name="Advanced KMS Emulation",
                    description="Full KMS v6 protocol implementation with all validation",
                    difficulty=BypassDifficulty.MEDIUM,
                    tools_required=["KMS Server Emulator", "vlmcsd", "py-kms"],
                    success_rate=0.95,
                    time_estimate="20 minutes",
                    risks=["Genuine validation failures", "Update detection"],
                    prerequisites=["KMS protocol knowledge", "Network setup"],
                ),
                BypassTechnique(
                    name="HWID/Digital License Generation",
                    description="Generate permanent digital license with HWID binding",
                    difficulty=BypassDifficulty.HIGH,
                    tools_required=["HWID generator", "License injector", "gatherosstate.exe"],
                    success_rate=0.8,
                    time_estimate="1-2 hours",
                    risks=["Hardware changes", "Cloud validation"],
                    prerequisites=["Licensing system internals", "HWID structure"],
                ),
                BypassTechnique(
                    name="Token Manipulation",
                    description="Direct modification of activation tokens and certificates",
                    difficulty=BypassDifficulty.HIGH,
                    tools_required=["Token backup/restore", "pkeyconfig", "Certificate tools"],
                    success_rate=0.7,
                    time_estimate="2-3 hours",
                    risks=["System corruption", "Validation loops"],
                    prerequisites=["Token structure", "SPP internals"],
                ),
                BypassTechnique(
                    name="OEM BIOS Injection",
                    description="Inject SLIC tables for OEM activation",
                    difficulty=BypassDifficulty.VERY_HIGH,
                    tools_required=["SLIC toolkit", "Bootloader modifier", "ACPI tools"],
                    success_rate=0.6,
                    time_estimate="3-4 hours",
                    risks=["Boot failures", "Secure Boot conflicts"],
                    prerequisites=["BIOS/UEFI knowledge", "SLIC structure"],
                ),
            ],
            analysis_tips=[
                "Monitor SPP service communications",
                "Check clipup.exe for license refresh",
                "Analyze tokens.dat structure",
                "Look for KMS client machine ID",
                "Check scheduled tasks for validation",
                "Monitor genuine validation URLs",
            ],
            common_mistakes=[
                "Not handling all activation methods",
                "Missing Office integration points",
                "Incomplete token restoration",
                "Ignoring cloud-based checks",
                "Not preserving HWID consistency",
            ],
            resources=[
                "Volume Activation Management Tool",
                "KMS client setup keys",
                "Activation troubleshooting guides",
            ],
        )

        # iLok/PACE
        schemes["ilok"] = ProtectionSchemeInfo(
            name="iLok/PACE Anti-Piracy",
            vendor="PACE Anti-Piracy Inc.",
            category=ProtectionCategory.HARDWARE_DONGLE,
            description="Hardware and software licensing for pro audio/video applications",
            versions=["iLok 2", "iLok 3", "PACE Eden", "iLok Cloud"],
            common_applications=["Pro Tools", "Cubase", "Logic Pro", "Adobe CC", "Waves plugins", "Native Instruments"],
            detection_signatures=[
                "iLok License Manager", "PACE License Support",
                "iLok.com", "eden.sys", "PACESupport.dll",
                "iLokHelper", "com.paceap", "iLok Cloud Session"
            ],
            bypass_difficulty=BypassDifficulty.HIGH,
            bypass_techniques=[
                BypassTechnique(
                    name="iLok Emulation System",
                    description="Complete iLok hardware and software emulation",
                    difficulty=BypassDifficulty.HIGH,
                    tools_required=["iLok Emulator", "License dumper", "USB emulator"],
                    success_rate=0.7,
                    time_estimate="3-5 days",
                    risks=["Cloud validation", "Machine authorization"],
                    prerequisites=["USB protocol", "PACE encryption"],
                ),
                BypassTechnique(
                    name="License Memory Injection",
                    description="Inject valid licenses directly into memory",
                    difficulty=BypassDifficulty.MEDIUM,
                    tools_required=["Memory injector", "License generator"],
                    success_rate=0.8,
                    time_estimate="4-8 hours",
                    risks=["Runtime checks", "License refresh"],
                    prerequisites=["Memory manipulation", "License format"],
                ),
            ],
            analysis_tips=[
                "Monitor PACE driver communications",
                "Analyze iLok License Manager traffic",
                "Check for machine authorization",
                "Look for cloud session tokens",
            ],
            common_mistakes=[
                "Not handling cloud licenses",
                "Missing machine authorization",
                "Incomplete USB emulation",
            ],
            resources=[
                "iLok License Manager documentation",
                "PACE SDK information",
            ],
        )

        # CodeMeter
        schemes["codemeter"] = ProtectionSchemeInfo(
            name="CodeMeter",
            vendor="Wibu-Systems AG",
            category=ProtectionCategory.HARDWARE_DONGLE,
            description="Comprehensive protection with hardware dongles and software activation",
            versions=["CodeMeter 7.x", "CodeMeter 8.x"],
            common_applications=["Siemens software", "Rockwell Automation", "CAD/CAM tools", "Industrial software"],
            detection_signatures=[
                "CodeMeter.exe", "CodeMeter Runtime Server",
                "WibuKey", "CmDongle", "codemeter.service",
                "WibuCm32.dll", "WibuCm64.dll", "CmActLicense"
            ],
            bypass_difficulty=BypassDifficulty.VERY_HIGH,
            bypass_techniques=[
                BypassTechnique(
                    name="CmDongle Emulation",
                    description="Emulate CodeMeter dongle with full functionality",
                    difficulty=BypassDifficulty.VERY_HIGH,
                    tools_required=["CmDongle Emulator", "Wibu dumper"],
                    success_rate=0.6,
                    time_estimate="1-2 weeks",
                    risks=["Firmware protection", "Secure chip"],
                    prerequisites=["Hardware RE", "Cryptography"],
                ),
                BypassTechnique(
                    name="Runtime Server Replacement",
                    description="Replace CodeMeter Runtime with custom server",
                    difficulty=BypassDifficulty.HIGH,
                    tools_required=["Custom runtime", "Protocol analyzer"],
                    success_rate=0.7,
                    time_estimate="3-5 days",
                    risks=["API changes", "Version detection"],
                    prerequisites=["Server development", "Protocol RE"],
                ),
            ],
            analysis_tips=[
                "Analyze CodeMeter API calls",
                "Monitor runtime server communications",
                "Check for CmContainer usage",
                "Look for AxProtector integration",
            ],
            common_mistakes=[
                "Underestimating hardware security",
                "Missing AxProtector layers",
                "Incomplete API emulation",
            ],
            resources=[
                "CodeMeter API documentation",
                "AxProtector information",
            ],
        )

        return schemes

    def _initialize_bypass_strategies(self) -> dict[str, list[str]]:
        """Initialize general bypass strategies by category."""
        return {
            "hardware_dongle": [
                "Dump dongle memory and emulate",
                "Hook and redirect API calls",
                "Patch validation checks",
                "Use network redirection for network dongles",
                "Analyze communication protocol",
            ],
            "network_license": [
                "Set up local license server",
                "Modify license files",
                "Redirect network traffic",
                "Patch timeout checks",
                "Emulate vendor daemon",
            ],
            "software_protection": [
                "Unpack/devirtualize protected code",
                "Bypass anti-debugging checks",
                "Reconstruct import table",
                "Patch license validation",
                "Generate valid keys",
            ],
            "gaming_drm": [
                "Remove DRM wrapper",
                "Emulate platform APIs",
                "Patch online checks",
                "Bypass integrity verification",
                "Use scene releases as reference",
            ],
            "time_based": [
                "Manipulate system time",
                "Patch time checks",
                "Extend trial period in storage",
                "Bypass date validation",
                "Reset trial data",
            ],
        }

    def _initialize_analysis_workflows(self) -> dict[str, list[str]]:
        """Initialize standard analysis workflows."""
        return {
            "initial_analysis": [
                "Identify file type and architecture",
                "Check for known packers/protectors",
                "Scan for protection signatures",
                "Analyze imports and exports",
                "Look for encrypted/compressed sections",
            ],
            "static_analysis": [
                "Disassemble with Ghidra",
                "Identify protection initialization",
                "Find license check functions",
                "Analyze string references",
                "Map out control flow",
            ],
            "dynamic_analysis": [
                "Run with API monitoring",
                "Trace system calls",
                "Monitor file/registry access",
                "Capture network traffic",
                "Debug with anti-anti-debug",
            ],
            "protection_removal": [
                "Identify protection entry points",
                "Bypass/remove protection layers",
                "Reconstruct original code",
                "Fix imports and relocations",
                "Test functionality",
            ],
            "validation": [
                "Verify all features work",
                "Check for hidden checks",
                "Test edge cases",
                "Monitor for callbacks",
                "Ensure stability",
            ],
        }

    def get_protection_info(self, protection_name: str) -> ProtectionSchemeInfo | None:
        """Get detailed information about a protection scheme."""
        # Normalize name
        normalized_name = protection_name.lower().replace(" ", "_").replace("/", "_")

        # Check exact match
        if normalized_name in self.protection_schemes:
            return self.protection_schemes[normalized_name]

        # Check partial matches
        for key, scheme in self.protection_schemes.items():
            if normalized_name in key or key in normalized_name:
                return scheme
            if protection_name.lower() in scheme.name.lower():
                return scheme

        return None

    def get_bypass_techniques(self, protection_name: str) -> list[BypassTechnique]:
        """Get bypass techniques for a specific protection."""
        info = self.get_protection_info(protection_name)
        if info:
            return info.bypass_techniques
        return []

    def get_analysis_workflow(self, workflow_type: str) -> list[str]:
        """Get a standard analysis workflow."""
        return self.analysis_workflows.get(workflow_type, [])

    def search_by_signature(self, signature: str) -> list[ProtectionSchemeInfo]:
        """Search for protections containing a specific signature."""
        results = []
        signature_lower = signature.lower()

        for scheme in self.protection_schemes.values():
            for sig in scheme.detection_signatures:
                if signature_lower in sig.lower():
                    results.append(scheme)
                    break

        return results

    def get_tools_for_protection(self, protection_name: str) -> list[str]:
        """Get all tools needed for bypassing a protection."""
        info = self.get_protection_info(protection_name)
        if not info:
            return []

        tools = set()
        for technique in info.bypass_techniques:
            tools.update(technique.tools_required)

        return sorted(list(tools))

    def estimate_bypass_time(self, protection_name: str, skill_level: str = "intermediate") -> str:
        """Estimate time to bypass a protection based on skill level."""
        info = self.get_protection_info(protection_name)
        if not info:
            return "Unknown"

        # Skill multipliers
        skill_multipliers = {
            "beginner": 3.0,
            "intermediate": 1.5,
            "advanced": 1.0,
            "expert": 0.7,
        }

        multiplier = skill_multipliers.get(skill_level, 1.5)

        # Get average time from techniques
        total_hours = 0
        count = 0

        for technique in info.bypass_techniques:
            time_str = technique.time_estimate
            # Parse time estimates (simplified)
            if "hour" in time_str:
                hours = 4  # Average of range
            elif "day" in time_str:
                hours = 24
            elif "week" in time_str:
                hours = 24 * 7
            elif "month" in time_str:
                hours = 24 * 30
            else:
                hours = 8

            total_hours += hours * technique.success_rate
            count += 1

        if count > 0:
            avg_hours = (total_hours / count) * multiplier

            if avg_hours < 24:
                return f"{int(avg_hours)} hours"
            if avg_hours < 168:
                return f"{int(avg_hours / 24)} days"
            if avg_hours < 720:
                return f"{int(avg_hours / 168)} weeks"
            return f"{int(avg_hours / 720)} months"

        return "Variable"

    def export_knowledge_base(self, output_path: str):
        """Export knowledge base to JSON."""
        data = {
            "protection_schemes": {},
            "bypass_strategies": self.bypass_strategies,
            "analysis_workflows": self.analysis_workflows,
        }

        # Convert dataclasses to dicts
        for name, scheme in self.protection_schemes.items():
            scheme_dict = {
                "name": scheme.name,
                "vendor": scheme.vendor,
                "category": scheme.category.value,
                "description": scheme.description,
                "versions": scheme.versions,
                "common_applications": scheme.common_applications,
                "detection_signatures": scheme.detection_signatures,
                "bypass_difficulty": scheme.bypass_difficulty.value,
                "analysis_tips": scheme.analysis_tips,
                "common_mistakes": scheme.common_mistakes,
                "resources": scheme.resources,
                "bypass_techniques": [],
            }

            for technique in scheme.bypass_techniques:
                technique_dict = {
                    "name": technique.name,
                    "description": technique.description,
                    "difficulty": technique.difficulty.value,
                    "tools_required": technique.tools_required,
                    "success_rate": technique.success_rate,
                    "time_estimate": technique.time_estimate,
                    "risks": technique.risks,
                    "prerequisites": technique.prerequisites,
                }
                scheme_dict["bypass_techniques"].append(technique_dict)

            data["protection_schemes"][name] = scheme_dict

        with open(output_path, "w") as f:
            json.dump(data, f, indent=2)


# Singleton instance
_knowledge_base = None


def get_protection_knowledge_base() -> ProtectionKnowledgeBase:
    """Get or create the protection knowledge base singleton."""
    global _knowledge_base
    if _knowledge_base is None:
        _knowledge_base = ProtectionKnowledgeBase()
    return _knowledge_base


if __name__ == "__main__":
    # Example usage
    kb = get_protection_knowledge_base()

    # Get info about Sentinel HASP
    hasp_info = kb.get_protection_info("Sentinel HASP")
    if hasp_info:
        print(f"Protection: {hasp_info.name}")
        print(f"Vendor: {hasp_info.vendor}")
        print(f"Difficulty: {hasp_info.bypass_difficulty.value}")
        print(f"Common in: {', '.join(hasp_info.common_applications[:3])}")

        print("\nBypass Techniques:")
        for technique in hasp_info.bypass_techniques:
            print(f"  - {technique.name}: {technique.description}")
            print(f"    Success Rate: {technique.success_rate:.0%}")
            print(f"    Time: {technique.time_estimate}")

    # Search by signature
    print("\n\nSearching for 'steam' signatures:")
    results = kb.search_by_signature("steam")
    for scheme in results:
        print(f"  - {scheme.name}: {scheme.description}")

    # Export knowledge base
    kb.export_knowledge_base("protection_knowledge_base.json")
    print("\nKnowledge base exported to protection_knowledge_base.json")

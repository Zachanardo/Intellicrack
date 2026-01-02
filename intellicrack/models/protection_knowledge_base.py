#!/usr/bin/env python3
"""Protection knowledge base for Intellicrack models.

This file is part of Intellicrack.
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
import logging
from dataclasses import dataclass, field
from enum import Enum
from typing import Any


logger: logging.Logger = logging.getLogger(__name__)


"""Protection Knowledge Base module.

Comprehensive database of software protection schemes, bypass techniques,
and analysis strategies for the ML system. Provides singleton access to
structured protection knowledge for security research and analysis.
"""


class BypassDifficulty(Enum):
    """Protection bypass difficulty levels.

    Enumeration of relative difficulty ratings for software protection bypass
    techniques, ranging from trivial (simple patches) to extreme (requires
    specialized expertise and advanced tools).
    """

    TRIVIAL = "trivial"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    VERY_HIGH = "very_high"
    EXTREME = "extreme"


class ProtectionCategory(Enum):
    """Protection scheme categories.

    Enumeration of software protection categories covering hardware-based
    (dongle), network-based (license servers), software-based (obfuscation),
    virtualization-based, gaming DRM, enterprise systems, custom implementations,
    and hybrid approaches combining multiple protection mechanisms.
    """

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
    """Bypass technique information.

    Represents a specific technique for bypassing a software protection scheme,
    including difficulty level, required tools, success rate, time estimate,
    and associated risks and prerequisites for execution.
    """

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
    """Complete information about a protection scheme.

    Comprehensive data structure containing all known information about a
    specific software protection scheme, including vendor details, detection
    methods, bypass techniques, analysis strategies, and security research
    resources for defeating the protection mechanism.
    """

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
    """Knowledge base for software protection schemes.

    Central repository containing comprehensive information about software
    protection mechanisms, bypass techniques, analysis strategies, and
    workflows for analyzing and defeating commercial licensing protections.
    """

    def __init__(self) -> None:
        """Initialize the protection knowledge base with schemes, strategies, and workflows.

        Initializes three core components:
        - protection_schemes: Database of software protection mechanisms
        - bypass_strategies: Generic bypass strategies by category
        - analysis_workflows: Standard analysis methodologies
        """
        self.protection_schemes: dict[str, ProtectionSchemeInfo] = (
            self._initialize_protection_schemes()
        )
        self.bypass_strategies: dict[str, list[str]] = (
            self._initialize_bypass_strategies()
        )
        self.analysis_workflows: dict[str, list[str]] = (
            self._initialize_analysis_workflows()
        )

    def _initialize_protection_schemes(self) -> dict[str, ProtectionSchemeInfo]:
        """Initialize comprehensive protection scheme database with production-ready bypass strategies.

        Creates the complete protection knowledge base containing detailed information
        about major software protection mechanisms including commercial protectors
        (Sentinel HASP, FlexLM, VMProtect, Denuvo, etc.), gaming DRM (Steam CEG),
        enterprise systems (Microsoft Activation), and emerging protection technologies.

        Returns:
            dict[str, ProtectionSchemeInfo]: Dictionary mapping protection names to
                their detailed information including bypass techniques, detection
                signatures, analysis tips, vendor information, and security
                research resources.
        """
        schemes = {
            "sentinel_hasp": ProtectionSchemeInfo(
                name="Sentinel HASP/HL",
                vendor="Thales (formerly SafeNet)",
                category=ProtectionCategory.HARDWARE_DONGLE,
                description="Hardware-based protection using USB dongles with AES encryption and secure communication",
                versions=["HL Pro", "SL", "SRM", "LDK 7.x", "LDK 8.x"],
                common_applications=[
                    "AutoCAD",
                    "SolidWorks",
                    "MATLAB",
                    "MasterCAM",
                    "CATIA",
                    "Siemens NX",
                    "ANSYS",
                ],
                detection_signatures=[
                    "hasp_login",
                    "hasp_login_scope",
                    "hasp_encrypt",
                    "hasp_decrypt",
                    "hasplms.exe",
                    "aksusbd.sys",
                    "aksfridge.sys",
                    "hardlock.sys",
                    "HASP HL",
                    "Sentinel",
                    "vendorcode",
                    "haspdinst.exe",
                    "hasp_get_sessioninfo",
                    "hasp_update",
                    "hasp_get_rtc",
                ],
                bypass_difficulty=BypassDifficulty.HIGH,
                bypass_techniques=[
                    BypassTechnique(
                        name="Complete Dongle Emulation",
                        description="Create perfect virtual dongle with memory dump and crypto keys",
                        difficulty=BypassDifficulty.HIGH,
                        tools_required=[
                            "HASP Dumper",
                            "Dongle Emulator",
                            "API Monitor",
                            "WinAPIOverride",
                        ],
                        success_rate=0.85,
                        time_estimate="2-4 days",
                        risks=["Anti-emulation checks", "Time-based validations"],
                        prerequisites=[
                            "Physical dongle access",
                            "Driver RE skills",
                            "Crypto knowledge",
                        ],
                    ),
                    BypassTechnique(
                        name="Advanced API Redirection",
                        description="Redirect all HASP APIs through custom DLL with full emulation",
                        difficulty=BypassDifficulty.MEDIUM,
                        tools_required=[
                            "x64dbg",
                            "API Monitor",
                            "Detours",
                            "Custom DLL injector",
                        ],
                        success_rate=0.9,
                        time_estimate="6-12 hours",
                        risks=["Integrity checks", "Hidden API calls"],
                        prerequisites=[
                            "Windows API expertise",
                            "DLL injection knowledge",
                        ],
                    ),
                    BypassTechnique(
                        name="Driver-Level Bypass",
                        description="Replace HASP driver with custom implementation",
                        difficulty=BypassDifficulty.VERY_HIGH,
                        tools_required=[
                            "WinDbg",
                            "IDA Pro",
                            "Driver signing tools",
                        ],
                        success_rate=0.75,
                        time_estimate="1 week",
                        risks=[
                            "System instability",
                            "Driver signature requirements",
                        ],
                        prerequisites=["Kernel programming", "Driver development"],
                    ),
                    BypassTechnique(
                        name="Memory Surgery",
                        description="Surgical memory patches at all validation points",
                        difficulty=BypassDifficulty.MEDIUM,
                        tools_required=[
                            "x64dbg",
                            "Cheat Engine",
                            "Process Hacker",
                        ],
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
        }

        # FlexLM/FlexNet Publisher
        schemes["flexlm"] = ProtectionSchemeInfo(
            name="FlexLM/FlexNet Publisher",
            vendor="Flexera Software (formerly Macrovision)",
            category=ProtectionCategory.NETWORK_LICENSE,
            description="Enterprise floating license management with client-server architecture",
            versions=["11.16.x", "2019.x", "2020.x", "2021.x", "2022.x"],
            common_applications=[
                "ANSYS",
                "Cadence",
                "Synopsys",
                "MATLAB",
                "Mentor Graphics",
                "Autodesk",
                "PTC Creo",
            ],
            detection_signatures=[
                "lmgrd",
                "lmutil",
                "lmstat",
                "lmreread",
                "lmdown",
                "FEATURE",
                "INCREMENT",
                "UPGRADE",
                "PACKAGE",
                "license.dat",
                "license.lic",
                ".flexlmrc",
                "lc_checkout",
                "lc_init",
                "l_sg",
                "l_key",
                "vendor daemon",
                "LM_LICENSE_FILE",
                "FLEXLM_DIAGNOSTICS",
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
            common_applications=[
                "Commercial software",
                "Games",
                "Security tools",
                "Industrial software",
            ],
            detection_signatures=[
                "WinLicense",
                "Themida",
                "SecureEngine",
                "Oreans",
                ".themida",
                ".winlicense",
                ".wlsection",
                "SE_InitializeEngine",
                "SE_ActivateLicense",
                "WLRegGetStatus",
                "VM macros",
                "XBundler",
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
            common_applications=[
                "High-value software",
                "DRM systems",
                "Anti-cheat engines",
                "Cryptographic tools",
            ],
            detection_signatures=[
                "VMProtect",
                ".vmp0",
                ".vmp1",
                ".vmp2",
                "VMProtectBegin",
                "VMProtectEnd",
                "VMProtectIsDebuggerPresent",
                "VMProtectIsVirtualMachinePresent",
                "Virtualized sections",
                "Heavy obfuscation",
                "Mutated code patterns",
            ],
            bypass_difficulty=BypassDifficulty.EXTREME,
            bypass_techniques=[
                BypassTechnique(
                    name="Full Devirtualization Framework",
                    description="Complete VM architecture reversal and x86/x64 reconstruction",
                    difficulty=BypassDifficulty.EXTREME,
                    tools_required=["VMPImportFixer", "NoVmp", "VTIL-Core", "VMPDump", "Scylla"],
                    success_rate=0.3,
                    time_estimate="1-2 months",
                    risks=["Incomplete conversion", "Logic errors", "Mutations"],
                    prerequisites=[
                        "VM internals expertise",
                        "Compiler theory",
                        "Pattern recognition",
                    ],
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

        # Steam CEG/DRM Wrapper Implementation
        schemes["steam_ceg"] = ProtectionSchemeInfo(
            name="Steam CEG/DRM Wrapper",
            vendor="Valve Corporation",
            category=ProtectionCategory.GAMING_DRM,
            description="Custom Executable Generation with user-specific binaries and Steam integration",
            versions=["CEG v3", "CEG v4", "Steam DRM Wrapper 3.x"],
            common_applications=["AAA games", "Indie games", "VR titles", "Software on Steam"],
            detection_signatures=[
                "steam_api.dll",
                "steam_api64.dll",
                "steamclient.dll",
                "SteamAPI_Init",
                "SteamAPI_RestartAppIfNecessary",
                "tier0_s.dll",
                "vstdlib_s.dll",
                ".bind section",
                "Steam DRM",
                "drm_wrapper",
                "steam_appid.txt",
            ],
            bypass_difficulty=BypassDifficulty.MEDIUM,
            bypass_techniques=[
                BypassTechnique(
                    name="Advanced CEG Unwrapping",
                    description="Complete CEG removal with AES key extraction",
                    difficulty=BypassDifficulty.MEDIUM,
                    tools_required=["Steamless_CLI", "Steamless_GUI", "CEGPolisher", "x64dbg"],
                    success_rate=0.9,
                    time_estimate="1-3 hours",
                    risks=["Additional protections", "Integrity checks"],
                    prerequisites=["CEG format knowledge", "Encryption basics"],
                ),
                BypassTechnique(
                    name="Full Steam API Emulation",
                    description="Complete Steam client and overlay emulation",
                    difficulty=BypassDifficulty.LOW,
                    tools_required=["GoldbergSteamEmu", "SmartSteamEmu", "ALI213Steam"],
                    success_rate=0.95,
                    time_estimate="30 minutes",
                    risks=["Multiplayer disabled", "Cloud saves broken"],
                    prerequisites=["Steam API understanding"],
                ),
                BypassTechnique(
                    name="DLC and Workshop Unlock",
                    description="Enable all DLC and workshop content",
                    difficulty=BypassDifficulty.LOW,
                    tools_required=[
                        "CreamAPI_4.5.0.0",
                        "SteamWorkshopDownloader",
                        "DepotDownloader",
                    ],
                    success_rate=0.9,
                    time_estimate="15 minutes",
                    risks=["Version mismatches", "Missing content"],
                    prerequisites=["Steam file structure"],
                ),
                BypassTechnique(
                    name="Binary Reconstruction",
                    description="Rebuild clean executable from memory dump",
                    difficulty=BypassDifficulty.MEDIUM,
                    tools_required=["PEDump", "Scylla_x64", "ImportREC", "LordPE"],
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
                "Massive code bloat",
                "VM-protected sections",
                "Trigger-based checks",
                "CPUID checks",
                "Hardware fingerprinting",
                "Online activation",
                "Performance degradation",
                "SSD write amplification",
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
            common_applications=[
                "Windows OS",
                "Microsoft Office",
                "Visual Studio",
                "SQL Server",
                "Exchange",
            ],
            detection_signatures=[
                "SLMgr.vbs",
                "OSPP.vbs",
                "sppsvc.exe",
                "osppsvc.exe",
                "Software Protection Platform",
                "KMS",
                "MAK",
                "GVLK",
                "tokens.dat",
                "Digital License",
                "Product Key",
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
            common_applications=[
                "Pro Tools",
                "Cubase",
                "Logic Pro",
                "Adobe CC",
                "Waves plugins",
                "Native Instruments",
            ],
            detection_signatures=[
                "iLok License Manager",
                "PACE License Support",
                "iLok.com",
                "eden.sys",
                "PACESupport.dll",
                "iLokHelper",
                "com.paceap",
                "iLok Cloud Session",
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
            common_applications=[
                "Siemens software",
                "Rockwell Automation",
                "CAD/CAM tools",
                "Industrial software",
            ],
            detection_signatures=[
                "CodeMeter.exe",
                "CodeMeter Runtime Server",
                "WibuKey",
                "CmDongle",
                "codemeter.service",
                "WibuCm32.dll",
                "WibuCm64.dll",
                "CmActLicense",
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

        # SecuROM
        schemes["securom"] = ProtectionSchemeInfo(
            name="SecuROM",
            vendor="Sony DADC",
            category=ProtectionCategory.SOFTWARE_PROTECTION,
            description="Disc-based copy protection with online activation and virtual machine obfuscation",
            versions=["SecuROM 7.x", "SecuROM 8.x", "SecuROM PA"],
            common_applications=[
                "Games (2005-2010 era)",
                "BioShock",
                "Mass Effect",
                "GTA IV",
                "Spore",
            ],
            detection_signatures=[
                "SecuROM",
                "paul.dll",
                "drm.data",
                "securom_marker",
                ".securom",
                "CmdLineExt.dll",
                "SecuROM_UserAccessService",
                "securom32.dll",
                "securom64.dll",
                "SECDRV.SYS",
            ],
            bypass_difficulty=BypassDifficulty.MEDIUM,
            bypass_techniques=[
                BypassTechnique(
                    name="SecuROM Removal Tool",
                    description="Complete removal of SecuROM protection layers including triggers",
                    difficulty=BypassDifficulty.MEDIUM,
                    tools_required=["SecuROM Unpacker", "Trigger Mapper", "Import Fixer"],
                    success_rate=0.85,
                    time_estimate="4-8 hours",
                    risks=["Trigger points", "Activation checks", "VM detection"],
                    prerequisites=["SecuROM version identification", "PE reconstruction"],
                ),
                BypassTechnique(
                    name="Activation Server Emulation",
                    description="Emulate SecuROM activation servers for offline play",
                    difficulty=BypassDifficulty.LOW,
                    tools_required=["SecuROM Activator", "Server Emulator"],
                    success_rate=0.9,
                    time_estimate="1-2 hours",
                    risks=["Hardware binding", "Revocation lists"],
                    prerequisites=["Network protocol knowledge"],
                ),
                BypassTechnique(
                    name="VM Code Extraction",
                    description="Extract and reconstruct virtualized code segments",
                    difficulty=BypassDifficulty.HIGH,
                    tools_required=["VM Analyzer", "Code Rebuilder", "IDA Pro"],
                    success_rate=0.75,
                    time_estimate="2-3 days",
                    risks=["Incomplete extraction", "Logic errors"],
                    prerequisites=["VM architecture understanding", "x86 assembly"],
                ),
            ],
            analysis_tips=[
                "Look for SecuROM launcher wrapper",
                "Check for disc check triggers at runtime",
                "Monitor registry for activation data",
                "Analyze VM entry points for protected functions",
                "Track hardware fingerprinting routines",
                "Check for multiple trigger layers",
            ],
            common_mistakes=[
                "Missing delayed activation triggers",
                "Incomplete VM code reconstruction",
                "Not removing all SecuROM services",
                "Ignoring online verification callbacks",
            ],
            resources=[
                "SecuROM version databases",
                "Trigger point documentation",
                "VM handler analysis guides",
            ],
        )

        # StarForce
        schemes["starforce"] = ProtectionSchemeInfo(
            name="StarForce",
            vendor="Protection Technology",
            category=ProtectionCategory.SOFTWARE_PROTECTION,
            description="Driver-level protection with anti-debugging, encryption, and disc checks",
            versions=["StarForce 3", "StarForce 4", "StarForce 5", "StarForce ProActive"],
            common_applications=[
                "Splinter Cell: Chaos Theory",
                "King Kong",
                "Trackmania",
                "X3: Reunion",
            ],
            detection_signatures=[
                "StarForce",
                "protect.dll",
                "protect.sys",
                "sfdrv01.sys",
                "sfdrvup.exe",
                "StarForce Helper",
                "prodrv06.sys",
                "StarForceA",
                "sfhlp02.sys",
                "Protection ID",
            ],
            bypass_difficulty=BypassDifficulty.HIGH,
            bypass_techniques=[
                BypassTechnique(
                    name="Driver-Level Neutralization",
                    description="Disable StarForce drivers and protection mechanisms at kernel level",
                    difficulty=BypassDifficulty.HIGH,
                    tools_required=["Driver Disabler", "Kernel Debugger", "WinDbg"],
                    success_rate=0.7,
                    time_estimate="1 week",
                    risks=["System instability", "BSOD", "Driver conflicts"],
                    prerequisites=["Kernel debugging", "Driver analysis"],
                ),
                BypassTechnique(
                    name="Protected Process Dumping",
                    description="Dump and rebuild protected executable from memory",
                    difficulty=BypassDifficulty.MEDIUM,
                    tools_required=["StarForce Dumper", "Process Monitor", "IAT Rebuilder"],
                    success_rate=0.75,
                    time_estimate="6-12 hours",
                    risks=["Anti-dump tricks", "Encrypted sections"],
                    prerequisites=["Memory forensics", "PE format"],
                ),
                BypassTechnique(
                    name="Optical Drive Emulation",
                    description="Perfect emulation of physical disc including weak sectors",
                    difficulty=BypassDifficulty.MEDIUM,
                    tools_required=["DAEMON Tools", "Alcohol 120%", "StarForce Nightmare"],
                    success_rate=0.8,
                    time_estimate="2-4 hours",
                    risks=["Blacklisting", "Version detection"],
                    prerequisites=["Disc image formats", "SCSI emulation"],
                ),
            ],
            analysis_tips=[
                "Disable StarForce drivers before analysis",
                "Monitor IOCTL communications with drivers",
                "Check for encrypted code sections",
                "Look for IDE/SCSI miniport hooks",
                "Analyze disc authentication protocol",
                "Track thread creation for anti-debug",
            ],
            common_mistakes=[
                "Running with active StarForce drivers",
                "Incomplete driver removal",
                "Missing weak sector emulation",
                "Not handling all protection versions",
            ],
            resources=[
                "StarForce driver analysis papers",
                "Optical drive emulation guides",
                "Protection removal tutorials",
            ],
        )

        # Arxan TransformIT
        schemes["arxan"] = ProtectionSchemeInfo(
            name="Arxan TransformIT/GuardIT",
            vendor="Arxan Technologies (now Digital.ai)",
            category=ProtectionCategory.SOFTWARE_PROTECTION,
            description="Advanced application protection with code obfuscation, anti-tamper, and white-box cryptography",
            versions=["TransformIT 5.x", "GuardIT 4.x", "EnsureIT"],
            common_applications=[
                "Financial apps",
                "Healthcare software",
                "Gaming",
                "Enterprise applications",
            ],
            detection_signatures=[
                "Arxan",
                "TransformIT",
                "GuardIT",
                "White-box crypto",
                "Control flow flattening",
                "Instruction substitution",
                "Anti-tamper checks",
                "Integrity guards",
                "Code mobility",
            ],
            bypass_difficulty=BypassDifficulty.VERY_HIGH,
            bypass_techniques=[
                BypassTechnique(
                    name="Advanced Deobfuscation Pipeline",
                    description="Multi-stage deobfuscation with pattern recognition and symbolic execution",
                    difficulty=BypassDifficulty.VERY_HIGH,
                    tools_required=["Tigress Killer", "OLLVM Deobfuscator", "Miasm", "Z3"],
                    success_rate=0.5,
                    time_estimate="2-4 weeks",
                    risks=["Incomplete deobfuscation", "False patterns", "Performance overhead"],
                    prerequisites=["Compiler theory", "Symbolic execution", "Pattern matching"],
                ),
                BypassTechnique(
                    name="White-Box Crypto Attack",
                    description="Extract keys from white-box cryptographic implementations",
                    difficulty=BypassDifficulty.EXTREME,
                    tools_required=["DFA tools", "SideChannelMarvels", "Tracer", "Custom scripts"],
                    success_rate=0.4,
                    time_estimate="3-6 weeks",
                    risks=["Key extraction failure", "Multiple key layers"],
                    prerequisites=["Cryptanalysis", "DFA attacks", "White-box theory"],
                ),
                BypassTechnique(
                    name="Guard Network Mapping",
                    description="Map and neutralize all integrity guard checkpoints",
                    difficulty=BypassDifficulty.HIGH,
                    tools_required=["Guard Mapper", "Cross-reference analyzer", "IDA Pro"],
                    success_rate=0.6,
                    time_estimate="1-2 weeks",
                    risks=["Hidden guards", "Cascading checks", "Time bombs"],
                    prerequisites=["Graph analysis", "Anti-tamper knowledge"],
                ),
            ],
            analysis_tips=[
                "Start with control flow recovery",
                "Map guard network before patching",
                "Look for white-box crypto implementations",
                "Identify obfuscation patterns systematically",
                "Check for code mobility and polymorphism",
                "Monitor for integrity check cascades",
            ],
            common_mistakes=[
                "Patching guards individually",
                "Ignoring white-box crypto layers",
                "Incomplete control flow recovery",
                "Missing time-delayed checks",
            ],
            resources=[
                "Arxan protection whitepapers",
                "Control flow deobfuscation research",
                "White-box cryptography attacks",
            ],
        )

        # Enigma Protector
        schemes["enigma"] = ProtectionSchemeInfo(
            name="Enigma Protector",
            vendor="The Enigma Protector Developers Team",
            category=ProtectionCategory.SOFTWARE_PROTECTION,
            description="Executable protector with virtualization, licensing, and anti-debugging features",
            versions=["6.x", "7.x"],
            common_applications=["Shareware", "Commercial tools", "Game trainers", "Utilities"],
            detection_signatures=[
                "Enigma",
                "enigma1",
                "enigma2",
                "enigma_ide.dll",
                ".enigma1",
                ".enigma2",
                "EP_RegHardwareID",
                "EP_RegistrationLoadKeyA",
                "EP_RegistrationSaveKeyA",
            ],
            bypass_difficulty=BypassDifficulty.MEDIUM,
            bypass_techniques=[
                BypassTechnique(
                    name="Enigma Unpacker Suite",
                    description="Complete unpacking with OEP finding and import reconstruction",
                    difficulty=BypassDifficulty.MEDIUM,
                    tools_required=["Enigma Unpacker", "OEP Finder", "ImportREC"],
                    success_rate=0.8,
                    time_estimate="3-6 hours",
                    risks=["VM protected sections", "Anti-dump"],
                    prerequisites=["Unpacking knowledge", "PE format"],
                ),
                BypassTechnique(
                    name="Registration System Bypass",
                    description="Bypass hardware-locked registration and licensing",
                    difficulty=BypassDifficulty.LOW,
                    tools_required=["Registration patcher", "HWID spoofer"],
                    success_rate=0.85,
                    time_estimate="1-2 hours",
                    risks=["Online verification", "Time checks"],
                    prerequisites=["Registration system knowledge"],
                ),
            ],
            analysis_tips=[
                "Look for Enigma sections in PE header",
                "Check registration API usage",
                "Monitor hardware ID generation",
                "Trace VM entry points",
                "Analyze anti-debugging tricks",
            ],
            common_mistakes=[
                "Not fixing all imports",
                "Missing VM protected code",
                "Incomplete registration bypass",
            ],
            resources=[
                "Enigma Protector documentation",
                "Unpacking tutorials",
            ],
        )

        # ASProtect/ASPack
        schemes["asprotect"] = ProtectionSchemeInfo(
            name="ASProtect/ASPack",
            vendor="Alexey Solodovnikov",
            category=ProtectionCategory.SOFTWARE_PROTECTION,
            description="Compression and protection with anti-debugging and CRC checking",
            versions=["ASProtect 2.x", "ASPack 2.x"],
            common_applications=["Shareware", "Cracking tools", "Small utilities"],
            detection_signatures=[
                "ASProtect",
                "ASPack",
                ".aspack",
                ".adata",
                ".aspr",
                "aspr_ide.dll",
                "ASProtect SKE",
                "CRC Check",
            ],
            bypass_difficulty=BypassDifficulty.LOW,
            bypass_techniques=[
                BypassTechnique(
                    name="Standard Unpacking",
                    description="Unpack and rebuild original executable",
                    difficulty=BypassDifficulty.LOW,
                    tools_required=["ASProtect Unpacker", "OllyDbg", "x64dbg"],
                    success_rate=0.9,
                    time_estimate="30-60 minutes",
                    risks=["CRC checks", "Stolen bytes"],
                    prerequisites=["Basic unpacking"],
                ),
                BypassTechnique(
                    name="SKE License Bypass",
                    description="Bypass ASProtect SKE registration system",
                    difficulty=BypassDifficulty.LOW,
                    tools_required=["SKE patcher", "Registry editor"],
                    success_rate=0.85,
                    time_estimate="15-30 minutes",
                    risks=["Hardware binding"],
                    prerequisites=["Registry knowledge"],
                ),
            ],
            analysis_tips=[
                "Find OEP with hardware breakpoints",
                "Dump at OEP and fix imports",
                "Check for CRC verification routines",
                "Look for stolen bytes at entry point",
            ],
            common_mistakes=[
                "Not restoring stolen bytes",
                "Missing CRC patches",
                "Incomplete IAT reconstruction",
            ],
            resources=[
                "ASProtect unpacking guides",
                "SKE documentation",
            ],
        )

        # Obsidium
        schemes["obsidium"] = ProtectionSchemeInfo(
            name="Obsidium",
            vendor="Obsidium Software",
            category=ProtectionCategory.SOFTWARE_PROTECTION,
            description="Software protection with strong encryption, anti-debugging, and licensing",
            versions=["1.6.x", "1.7.x"],
            common_applications=["Commercial software", "Games", "Professional tools"],
            detection_signatures=[
                "Obsidium",
                "obsidium.dll",
                ".obsidium",
                "Obsidium©",
                "OBSIDIUM_SECTION",
                "obsidium_vm",
            ],
            bypass_difficulty=BypassDifficulty.HIGH,
            bypass_techniques=[
                BypassTechnique(
                    name="Advanced Obsidium Unpacking",
                    description="Multi-layer unpacking with anti-debug bypass",
                    difficulty=BypassDifficulty.HIGH,
                    tools_required=["Obsidium Unpacker", "ScyllaHide", "TitanEngine"],
                    success_rate=0.65,
                    time_estimate="1-2 days",
                    risks=["VM protection", "Encrypted layers"],
                    prerequisites=["Advanced unpacking", "Anti-anti-debug"],
                ),
                BypassTechnique(
                    name="License Key Generation",
                    description="Generate valid license keys through cryptanalysis",
                    difficulty=BypassDifficulty.HIGH,
                    tools_required=["Key analyzer", "Crypto tools"],
                    success_rate=0.6,
                    time_estimate="2-3 days",
                    risks=["RSA protection", "Online validation"],
                    prerequisites=["Cryptography", "Key algorithms"],
                ),
            ],
            analysis_tips=[
                "Use anti-anti-debug plugins",
                "Look for multiple protection layers",
                "Analyze VM protected sections",
                "Check license validation routines",
                "Monitor API redirection",
            ],
            common_mistakes=[
                "Triggering anti-debug mechanisms",
                "Incomplete layer removal",
                "Missing VM code reconstruction",
            ],
            resources=[
                "Obsidium SDK documentation",
                "Advanced unpacking techniques",
            ],
        )

        # SoftwarePassport/Armadillo
        schemes["armadillo"] = ProtectionSchemeInfo(
            name="SoftwarePassport/Armadillo",
            vendor="Silicon Realms/Digital River",
            category=ProtectionCategory.SOFTWARE_PROTECTION,
            description="Professional protection with nanomites, code splicing, and strategic code mutation",
            versions=["8.x", "9.x"],
            common_applications=[
                "Professional software",
                "Engineering tools",
                "Security applications",
            ],
            detection_signatures=[
                "Armadillo",
                "SoftwarePassport",
                ".arm",
                ".data",
                "ArmAccess.dll",
                "nanomites",
                "CopyMem2",
                "Strategic Code Splicing",
            ],
            bypass_difficulty=BypassDifficulty.VERY_HIGH,
            bypass_techniques=[
                BypassTechnique(
                    name="Nanomite Processing",
                    description="Process and remove nanomite protection with CC restoration",
                    difficulty=BypassDifficulty.VERY_HIGH,
                    tools_required=["ArmInline", "Nanomite Processor", "IDA Pro"],
                    success_rate=0.6,
                    time_estimate="1-2 weeks",
                    risks=["Incomplete processing", "Logic errors"],
                    prerequisites=["Nanomite theory", "Debugging expertise"],
                ),
                BypassTechnique(
                    name="Code Splicing Reconstruction",
                    description="Rebuild code sections split by strategic code splicing",
                    difficulty=BypassDifficulty.HIGH,
                    tools_required=["Code rebuilder", "Memory analyzer"],
                    success_rate=0.65,
                    time_estimate="3-5 days",
                    risks=["Missing code fragments", "Incorrect reassembly"],
                    prerequisites=["Code flow analysis", "Memory forensics"],
                ),
                BypassTechnique(
                    name="Import Elimination Recovery",
                    description="Recover eliminated imports and API redirections",
                    difficulty=BypassDifficulty.MEDIUM,
                    tools_required=["Import reconstructor", "API tracer"],
                    success_rate=0.75,
                    time_estimate="4-8 hours",
                    risks=["Hidden imports", "Dynamic resolution"],
                    prerequisites=["IAT reconstruction", "API knowledge"],
                ),
            ],
            analysis_tips=[
                "Map all nanomite INT3 locations",
                "Trace parent-child debugging architecture",
                "Analyze code splicing points",
                "Look for import elimination",
                "Check for debugger detection loops",
                "Monitor inter-process communication",
            ],
            common_mistakes=[
                "Not processing all nanomites",
                "Incomplete code splicing recovery",
                "Missing child process handling",
                "Ignoring CopyMem2 protection",
            ],
            resources=[
                "Armadillo protection analysis papers",
                "Nanomite handling techniques",
                "Strategic code splicing documentation",
            ],
        )

        return schemes

    def _initialize_bypass_strategies(self) -> dict[str, list[str]]:
        """Initialize general bypass strategies by category.

        Creates a mapping of protection categories to generic bypass strategies
        that can be applied across multiple protections within each category.
        Provides high-level tactical approaches for defeating various classes
        of protection mechanisms.

        Returns:
            dict[str, list[str]]: Dictionary mapping protection categories
                (hardware_dongle, network_license, software_protection, etc.)
                to lists of bypass strategies applicable to each category.
        """
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
        """Initialize standard analysis workflows.

        Creates predefined analysis workflows for protecting software reverse
        engineering. Workflows provide step-by-step guidance covering initial
        analysis, static analysis, dynamic analysis, protection removal, and
        validation phases. Workflows reflect industry best practices and proven
        methodologies for security research.

        Returns:
            dict[str, list[str]]: Dictionary mapping workflow types
                (initial_analysis, static_analysis, dynamic_analysis,
                protection_removal, validation) to lists of workflow steps
                in recommended execution order.
        """
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
        """Get detailed information about a protection scheme.

        Searches for protection schemes by name, supporting both exact and
        partial matches through flexible normalization. Handles various input
        formats (spaces, slashes) for improved usability and consistency.

        Args:
            protection_name: The name of the protection scheme to retrieve.
                Examples: 'Sentinel HASP', 'FlexLM', 'VMProtect'.

        Returns:
            ProtectionSchemeInfo | None: Detailed protection scheme information
                including vendor, category, bypass techniques, analysis tips,
                and detection signatures if found. Returns None if no matching
                scheme exists in the knowledge base.
        """
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
        """Get bypass techniques for a specific protection.

        Retrieves all documented bypass techniques for a given protection scheme,
        including difficulty ratings, required tools, success rates, and time
        estimates for each technique.

        Args:
            protection_name: The name of the protection scheme to query.

        Returns:
            list[BypassTechnique]: List of bypass techniques for the protection,
                including details on difficulty, tools, success rates, and risks.
                Returns empty list if protection not found in knowledge base.
        """
        if info := self.get_protection_info(protection_name):
            return info.bypass_techniques
        return []

    def get_analysis_workflow(self, workflow_type: str) -> list[str]:
        """Get a standard analysis workflow.

        Retrieves a predefined analysis workflow for a specific type of protection
        analysis. Workflows provide step-by-step guidance for analyzing software
        protections using industry best practices.

        Args:
            workflow_type: The type of analysis workflow to retrieve. Common types
                include 'initial_analysis', 'static_analysis', 'dynamic_analysis',
                'protection_removal', and 'validation'.

        Returns:
            list[str]: List of workflow steps in recommended execution order.
                Returns empty list if workflow type not found in knowledge base.
        """
        return self.analysis_workflows.get(workflow_type, [])

    def search_by_signature(self, signature: str) -> list[ProtectionSchemeInfo]:
        """Search for protections containing a specific signature.

        Searches the knowledge base for protection schemes that include a specific
        detection signature. Useful for identifying protections based on detected
        strings, functions, files, or other observable markers.

        Args:
            signature: The detection signature to search for. Case-insensitive.
                Examples: 'hasp_login', 'steam_api.dll', 'VMProtect'.

        Returns:
            list[ProtectionSchemeInfo]: List of protection schemes containing the
                specified signature in their detection signatures list. Returns
                empty list if no matching signatures found.
        """
        results = []
        signature_lower = signature.lower()

        for scheme in self.protection_schemes.values():
            for sig in scheme.detection_signatures:
                if signature_lower in sig.lower():
                    results.append(scheme)
                    break

        return results

    def get_tools_for_protection(self, protection_name: str) -> list[str]:
        """Get all tools needed for bypassing a protection.

        Aggregates tools from all bypass techniques for a protection scheme,
        eliminating duplicates and returning a sorted, deduplicated list. Useful
        for planning security research or identifying tool requirements.

        Args:
            protection_name: The name of the protection scheme to analyze.

        Returns:
            list[str]: Sorted and deduplicated list of all tools required for
                bypassing the protection across all available techniques. Returns
                empty list if protection not found in knowledge base.
        """
        info = self.get_protection_info(protection_name)
        if not info:
            return []

        tools = set()
        for technique in info.bypass_techniques:
            tools.update(technique.tools_required)

        return sorted(tools)

    def estimate_bypass_time(self, protection_name: str, skill_level: str = "intermediate") -> str:
        """Estimate time to bypass a protection based on skill level.

        Calculates an estimated time to bypass by analyzing all available bypass
        techniques and applying a skill-level multiplier. Supports beginner to
        expert skill levels with proportional time adjustments based on expertise.

        Args:
            protection_name: The name of the protection scheme to estimate.
            skill_level: The expertise level as a string. Accepts 'beginner',
                'intermediate', 'advanced', or 'expert'. Defaults to 'intermediate'.

        Returns:
            str: Estimated time in human-readable format (hours, days, weeks,
                or months), or "Unknown" if protection not found, or "Variable"
                if no techniques exist.
        """
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
        total_hours = 0.0
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

    def export_knowledge_base(self, output_path: str) -> None:
        """Export knowledge base to JSON.

        Serializes the complete protection knowledge base including schemes,
        strategies, and workflows to a JSON file for external use, backup, or
        integration with other tools. Creates well-formatted, human-readable JSON.

        Args:
            output_path: The file path where the JSON export will be written.
                Must be a valid writable file path.

        Raises:
            IOError: If the output file cannot be written or the parent directory
                does not exist.
        """
        protection_schemes_dict: dict[str, dict[str, Any]] = {}

        data: dict[str, Any] = {
            "protection_schemes": protection_schemes_dict,
            "bypass_strategies": self.bypass_strategies,
            "analysis_workflows": self.analysis_workflows,
        }

        # Convert dataclasses to dicts
        for name, scheme in self.protection_schemes.items():
            bypass_techniques_list: list[dict[str, Any]] = []

            scheme_dict: dict[str, Any] = {
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
                "bypass_techniques": bypass_techniques_list,
            }

            for technique in scheme.bypass_techniques:
                technique_dict: dict[str, Any] = {
                    "name": technique.name,
                    "description": technique.description,
                    "difficulty": technique.difficulty.value,
                    "tools_required": technique.tools_required,
                    "success_rate": technique.success_rate,
                    "time_estimate": technique.time_estimate,
                    "risks": technique.risks,
                    "prerequisites": technique.prerequisites,
                }
                bypass_techniques_list.append(technique_dict)

            protection_schemes_dict[name] = scheme_dict

        with open(output_path, "w") as f:
            json.dump(data, f, indent=2)


# Singleton instance
_knowledge_base: ProtectionKnowledgeBase | None = None


def get_protection_knowledge_base() -> ProtectionKnowledgeBase:
    """Get or create the protection knowledge base singleton.

    Implements lazy initialization of the protection knowledge base using a
    global singleton pattern to ensure only one instance exists throughout the
    application lifetime. On first call, creates and caches the knowledge base.
    Subsequent calls return the cached instance.

    Returns:
        ProtectionKnowledgeBase: The singleton protection knowledge base
            instance containing all protection scheme information, bypass
            strategies, and analysis workflows.
    """
    global _knowledge_base
    if _knowledge_base is None:
        _knowledge_base = ProtectionKnowledgeBase()
    return _knowledge_base


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    kb = get_protection_knowledge_base()

    if hasp_info := kb.get_protection_info("Sentinel HASP"):
        logger.info("Protection: %s", hasp_info.name)
        logger.info("Vendor: %s", hasp_info.vendor)
        logger.info("Difficulty: %s", hasp_info.bypass_difficulty.value)
        logger.info("Common in: %s", ", ".join(hasp_info.common_applications[:3]))

        logger.info("Bypass Techniques:")
        for technique in hasp_info.bypass_techniques:
            logger.info("  - %s: %s", technique.name, technique.description)
            logger.info("    Success Rate: %.0f%%", technique.success_rate * 100)
            logger.info("    Time: %s", technique.time_estimate)

    logger.info("Searching for 'steam' signatures:")
    results = kb.search_by_signature("steam")
    for scheme in results:
        logger.info("  - %s: %s", scheme.name, scheme.description)

    kb.export_knowledge_base("protection_knowledge_base.json")
    logger.info("Knowledge base exported to protection_knowledge_base.json")

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
        """Initialize comprehensive protection scheme database."""
        schemes = {}

        # Sentinel HASP
        schemes["sentinel_hasp"] = ProtectionSchemeInfo(
            name="Sentinel HASP",
            vendor="Thales (formerly SafeNet)",
            category=ProtectionCategory.HARDWARE_DONGLE,
            description="Hardware-based protection using USB dongles with encrypted communication",
            versions=["HL", "SL", "SRM", "LDK"],
            common_applications=["AutoCAD", "SolidWorks", "MATLAB", "MasterCAM", "CATIA"],
            detection_signatures=[
                "hasp_login",
                "hasp_encrypt",
                "hasp_decrypt",
                "hasplms.exe",
                "aksusbd.sys",
                "HASP HL",
                "Sentinel",
            ],
            bypass_difficulty=BypassDifficulty.HIGH,
            bypass_techniques=[
                BypassTechnique(
                    name="Dongle Emulation",
                    description="Create virtual dongle using dumped data",
                    difficulty=BypassDifficulty.HIGH,
                    tools_required=["HASP Emulator", "Dongle Dumper", "API Monitor"],
                    success_rate=0.7,
                    time_estimate="1-3 days",
                    risks=["Detection by anti-emulation checks"],
                    prerequisites=["Physical access to dongle", "Driver analysis skills"],
                ),
                BypassTechnique(
                    name="API Hooking",
                    description="Hook HASP API calls and return expected values",
                    difficulty=BypassDifficulty.MEDIUM,
                    tools_required=["x64dbg", "API Monitor", "Detours"],
                    success_rate=0.8,
                    time_estimate="4-8 hours",
                    risks=["Integrity checks may detect hooks"],
                    prerequisites=["Understanding of Windows API hooking"],
                ),
                BypassTechnique(
                    name="Memory Patching",
                    description="Patch license checks in memory",
                    difficulty=BypassDifficulty.MEDIUM,
                    tools_required=["x64dbg", "Cheat Engine"],
                    success_rate=0.6,
                    time_estimate="2-6 hours",
                    risks=["CRC checks", "Anti-debugging"],
                    prerequisites=["Assembly knowledge", "Debugging skills"],
                ),
            ],
            analysis_tips=[
                "Monitor hasp_login calls to identify feature IDs",
                "Check for aksusbd.sys driver installation",
                "Look for encrypted HASP communication",
                "Analyze vendor daemon if present",
            ],
            common_mistakes=[
                "Not handling all HASP API functions",
                "Ignoring time-based checks",
                "Missing network HASP scenarios",
                "Incomplete dongle dumps",
            ],
            resources=[
                "https://www.thalesgroup.com/en/markets/digital-identity-and-security/software-monetization/sentinel-ldk",
                "HASP HL/SL API Reference",
                "Dongle emulation forums",
            ],
        )

        # FlexLM/FlexNet
        schemes["flexlm"] = ProtectionSchemeInfo(
            name="FlexLM/FlexNet Publisher",
            vendor="Flexera Software",
            category=ProtectionCategory.NETWORK_LICENSE,
            description="Network-based floating license management system",
            versions=["11.x", "2019.x", "2020.x", "2021.x"],
            common_applications=["ANSYS", "Cadence", "Synopsys", "MATLAB", "Mentor Graphics"],
            detection_signatures=[
                "lmgrd",
                "lmutil",
                "lmstat",
                "FEATURE",
                "INCREMENT",
                "license.dat",
                "license.lic",
                "flexnet",
            ],
            bypass_difficulty=BypassDifficulty.MEDIUM,
            bypass_techniques=[
                BypassTechnique(
                    name="License Server Emulation",
                    description="Create fake license server returning valid licenses",
                    difficulty=BypassDifficulty.MEDIUM,
                    tools_required=["FlexLM Emulator", "License Generator"],
                    success_rate=0.85,
                    time_estimate="4-8 hours",
                    risks=["Network detection", "Vendor daemon checks"],
                    prerequisites=["Understanding of FlexLM protocol"],
                ),
                BypassTechnique(
                    name="License File Manipulation",
                    description="Modify license.dat with extended features/dates",
                    difficulty=BypassDifficulty.LOW,
                    tools_required=["Text editor", "FlexLM tools"],
                    success_rate=0.7,
                    time_estimate="1-2 hours",
                    risks=["Signature verification failure"],
                    prerequisites=["License file format knowledge"],
                ),
                BypassTechnique(
                    name="System Time Manipulation",
                    description="Change system time to bypass expiration",
                    difficulty=BypassDifficulty.TRIVIAL,
                    tools_required=["RunAsDate", "Time Stopper"],
                    success_rate=0.5,
                    time_estimate="30 minutes",
                    risks=["Other software affected", "Online checks"],
                    prerequisites=["None"],
                ),
            ],
            analysis_tips=[
                "Locate license.dat or license.lic files",
                "Monitor lmgrd.exe process",
                "Check environment variables (LM_LICENSE_FILE)",
                "Analyze vendor daemon behavior",
            ],
            common_mistakes=[
                "Not handling vendor-specific daemons",
                "Ignoring redundant license servers",
                "Missing borrowed license scenarios",
                "Incomplete FEATURE line emulation",
            ],
            resources=[
                "https://www.flexera.com/products/software-monetization/flexnet-publisher",
                "FlexLM Programmers Guide",
                "License administration guides",
            ],
        )

        # WinLicense/Themida
        schemes["winlicense"] = ProtectionSchemeInfo(
            name="WinLicense/Themida",
            vendor="Oreans Technologies",
            category=ProtectionCategory.SOFTWARE_PROTECTION,
            description="Advanced software protection with code virtualization and anti-debugging",
            versions=["2.x", "3.x"],
            common_applications=["Commercial software", "Games", "Utilities"],
            detection_signatures=[
                "WinLicense",
                "Themida",
                "SecureEngine",
                "Oreans",
                ".themida",
                ".winlicense",
                "SE_InitializeEngine",
            ],
            bypass_difficulty=BypassDifficulty.VERY_HIGH,
            bypass_techniques=[
                BypassTechnique(
                    name="VM Unpacking",
                    description="Unpack virtualized code sections",
                    difficulty=BypassDifficulty.VERY_HIGH,
                    tools_required=["Themida Unpacker", "x64dbg", "Scylla"],
                    success_rate=0.4,
                    time_estimate="1-2 weeks",
                    risks=["Multiple layers", "Anti-unpacking tricks"],
                    prerequisites=["Advanced unpacking skills", "VM understanding"],
                ),
                BypassTechnique(
                    name="Hardware Breakpoint Bypass",
                    description="Use hardware breakpoints to trace execution",
                    difficulty=BypassDifficulty.HIGH,
                    tools_required=["x64dbg", "TitanEngine", "Custom scripts"],
                    success_rate=0.5,
                    time_estimate="2-5 days",
                    risks=["Detection and crashes", "False paths"],
                    prerequisites=["Low-level debugging", "Anti-anti-debug"],
                ),
                BypassTechnique(
                    name="License Key Bruteforce",
                    description="Bruteforce or keygen weak implementations",
                    difficulty=BypassDifficulty.HIGH,
                    tools_required=["Custom keygen", "GPU bruteforcer"],
                    success_rate=0.3,
                    time_estimate="Variable",
                    risks=["Time consuming", "Blacklisting"],
                    prerequisites=["Cryptanalysis", "Key algorithm RE"],
                ),
            ],
            analysis_tips=[
                "Expect multiple anti-debugging layers",
                "Look for virtualized entry points",
                "Check for encrypted sections",
                "Monitor exception handlers",
            ],
            common_mistakes=[
                "Using standard debuggers without plugins",
                "Not handling all anti-debug checks",
                "Ignoring VM obfuscation layers",
                "Incomplete IAT reconstruction",
            ],
            resources=[
                "https://www.oreans.com/winlicense.php",
                "Tuts4You Themida unpacking",
                "Advanced unpacking tutorials",
            ],
        )

        # VMProtect
        schemes["vmprotect"] = ProtectionSchemeInfo(
            name="VMProtect",
            vendor="VMProtect Software",
            category=ProtectionCategory.VIRTUALIZATION,
            description="Code virtualization with custom VM protecting critical code sections",
            versions=["3.x"],
            common_applications=["Commercial software", "Games", "Security tools"],
            detection_signatures=[
                "VMProtect",
                ".vmp",
                "VMProtectBegin",
                "VMProtectEnd",
                "vmp sections",
                "virtualized code patterns",
            ],
            bypass_difficulty=BypassDifficulty.EXTREME,
            bypass_techniques=[
                BypassTechnique(
                    name="Devirtualization",
                    description="Convert VM bytecode back to x86/x64",
                    difficulty=BypassDifficulty.EXTREME,
                    tools_required=["VMProtect Devirtualizer", "Ghidra", "Custom tools"],
                    success_rate=0.2,
                    time_estimate="2-4 weeks",
                    risks=["Incomplete devirtualization", "Errors"],
                    prerequisites=["VM architecture knowledge", "Compiler theory"],
                ),
                BypassTechnique(
                    name="Symbolic Execution",
                    description="Use symbolic execution to understand VM logic",
                    difficulty=BypassDifficulty.VERY_HIGH,
                    tools_required=["Triton", "angr", "KLEE"],
                    success_rate=0.3,
                    time_estimate="1-2 weeks",
                    risks=["Path explosion", "Constraints"],
                    prerequisites=["Symbolic execution expertise"],
                ),
                BypassTechnique(
                    name="Side Channel Analysis",
                    description="Analyze execution patterns and timing",
                    difficulty=BypassDifficulty.HIGH,
                    tools_required=["Intel VTune", "Custom profilers"],
                    success_rate=0.4,
                    time_estimate="1 week",
                    risks=["Limited information", "Noise"],
                    prerequisites=["Performance analysis skills"],
                ),
            ],
            analysis_tips=[
                "Identify VM entry/exit points",
                "Trace VM handlers systematically",
                "Look for VM context structure",
                "Analyze obfuscated constants",
            ],
            common_mistakes=[
                "Trying to debug VM directly",
                "Not understanding VM architecture",
                "Ignoring mutation engine",
                "Incomplete handler analysis",
            ],
            resources=[
                "https://vmpsoft.com",
                "VMProtect Analysis papers",
                "Devirtualization research",
            ],
        )

        # Steam CEG
        schemes["steam_ceg"] = ProtectionSchemeInfo(
            name="Steam CEG",
            vendor="Valve Corporation",
            category=ProtectionCategory.GAMING_DRM,
            description="Custom Executable Generation creating unique binaries per user",
            versions=["Current"],
            common_applications=["Steam games", "VR applications"],
            detection_signatures=[
                "steam_api.dll",
                "steam_api64.dll",
                "SteamAPI_Init",
                "steamclient.dll",
                "tier0_s.dll",
                "vstdlib_s.dll",
            ],
            bypass_difficulty=BypassDifficulty.MEDIUM,
            bypass_techniques=[
                BypassTechnique(
                    name="CEG Unwrapping",
                    description="Remove CEG layer to get original executable",
                    difficulty=BypassDifficulty.MEDIUM,
                    tools_required=["Steamless", "CEG Dumper"],
                    success_rate=0.8,
                    time_estimate="1-2 hours",
                    risks=["Version differences", "Additional protections"],
                    prerequisites=["Understanding of CEG structure"],
                ),
                BypassTechnique(
                    name="Steam Emulation",
                    description="Emulate Steam client and API responses",
                    difficulty=BypassDifficulty.LOW,
                    tools_required=["Steam Emulator", "API wrapper"],
                    success_rate=0.9,
                    time_estimate="30 minutes",
                    risks=["Online features broken"],
                    prerequisites=["Basic Steam API knowledge"],
                ),
                BypassTechnique(
                    name="Offline Patching",
                    description="Patch Steam checks for offline play",
                    difficulty=BypassDifficulty.LOW,
                    tools_required=["x64dbg", "Hex editor"],
                    success_rate=0.7,
                    time_estimate="1 hour",
                    risks=["Updates revert patches"],
                    prerequisites=["Basic patching skills"],
                ),
            ],
            analysis_tips=[
                "Check for steam_appid.txt",
                "Monitor Steam API calls",
                "Look for CEG stub sections",
                "Analyze steamclient.dll loading",
            ],
            common_mistakes=[
                "Not handling all Steam API functions",
                "Missing DLC checks",
                "Incomplete CEG removal",
                "Ignoring workshop content",
            ],
            resources=[
                "https://partner.steamgames.com/doc/features/drm",
                "Steamless GitHub repository",
                "Steam API documentation",
            ],
        )

        # Denuvo
        schemes["denuvo"] = ProtectionSchemeInfo(
            name="Denuvo Anti-Tamper",
            vendor="Denuvo Software Solutions GmbH",
            category=ProtectionCategory.GAMING_DRM,
            description="Anti-tamper technology with VM obfuscation and integrity checks",
            versions=["v4", "v5", "v6", "v7", "v8", "v9", "v10+"],
            common_applications=["AAA games", "Major game releases"],
            detection_signatures=[
                "denuvo",
                "uplay_r1_loader",
                "massive VM usage",
                "trigger-based checks",
                "performance impact",
            ],
            bypass_difficulty=BypassDifficulty.EXTREME,
            bypass_techniques=[
                BypassTechnique(
                    name="Trigger Analysis",
                    description="Identify and bypass all protection triggers",
                    difficulty=BypassDifficulty.EXTREME,
                    tools_required=["Ghidra", "x64dbg", "Custom VM analysis"],
                    success_rate=0.1,
                    time_estimate="1-6 months",
                    risks=["Constant updates", "Multiple triggers"],
                    prerequisites=["Expert RE skills", "VM analysis", "Patience"],
                ),
                BypassTechnique(
                    name="Binary Reconstruction",
                    description="Rebuild clean binary without Denuvo",
                    difficulty=BypassDifficulty.EXTREME,
                    tools_required=["Custom tools", "Disassemblers", "Rebuilders"],
                    success_rate=0.15,
                    time_estimate="2-8 months",
                    risks=["Incomplete reconstruction", "Bugs"],
                    prerequisites=["Deep binary knowledge", "Team effort"],
                ),
            ],
            analysis_tips=[
                "Expect 100+ triggers throughout code",
                "Look for performance bottlenecks",
                "Analyze VM handler patterns",
                "Check for online activation",
            ],
            common_mistakes=[
                "Underestimating complexity",
                "Missing hidden triggers",
                "Not handling all versions",
                "Public discussion of methods",
            ],
            resources=[
                "Limited public information",
                "Scene group NFOs",
                "Performance analysis papers",
            ],
        )

        # Microsoft Activation
        schemes["microsoft_activation"] = ProtectionSchemeInfo(
            name="Microsoft Activation Technologies",
            vendor="Microsoft Corporation",
            category=ProtectionCategory.ENTERPRISE,
            description="Windows and Office activation using KMS, MAK, and digital licenses",
            versions=["Windows 10/11", "Office 2019/2021/365"],
            common_applications=["Windows OS", "Microsoft Office", "Visual Studio"],
            detection_signatures=[
                "SLMgr",
                "OSPP.vbs",
                "sppsvc.exe",
                "Software Protection",
                "KMS",
                "MAK",
                "Digital License",
                "Product Key",
            ],
            bypass_difficulty=BypassDifficulty.MEDIUM,
            bypass_techniques=[
                BypassTechnique(
                    name="KMS Emulation",
                    description="Emulate Key Management Service locally",
                    difficulty=BypassDifficulty.MEDIUM,
                    tools_required=["KMS emulator", "vlmcsd"],
                    success_rate=0.9,
                    time_estimate="30 minutes",
                    risks=["Detection by genuine check", "Updates"],
                    prerequisites=["Understanding of KMS protocol"],
                ),
                BypassTechnique(
                    name="Digital License Manipulation",
                    description="Modify digital license storage",
                    difficulty=BypassDifficulty.HIGH,
                    tools_required=["Registry tools", "Token backup"],
                    success_rate=0.6,
                    time_estimate="1-2 hours",
                    risks=["System instability", "Validation failures"],
                    prerequisites=["Windows internals knowledge"],
                ),
                BypassTechnique(
                    name="MAK Exploitation",
                    description="Use leaked or generated MAK keys",
                    difficulty=BypassDifficulty.LOW,
                    tools_required=["Key databases", "Activation tools"],
                    success_rate=0.4,
                    time_estimate="15 minutes",
                    risks=["Key blacklisting", "Limited activations"],
                    prerequisites=["Access to keys"],
                ),
            ],
            analysis_tips=[
                "Check HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\SoftwareProtectionPlatform",
                "Monitor sppsvc.exe service",
                "Analyze tokens.dat",
                "Look for KMS client setup keys",
            ],
            common_mistakes=[
                "Not handling all activation methods",
                "Ignoring online validation",
                "Missing Office integration",
                "Incomplete token manipulation",
            ],
            resources=[
                "https://docs.microsoft.com/en-us/windows-server/get-started/activation-overview",
                "KMS client setup keys",
                "Volume activation guides",
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

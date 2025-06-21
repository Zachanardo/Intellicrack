"""
Frida Preset Configurations for Common Protected Software

This module contains pre-configured Frida settings for bypassing protections
in commonly protected software categories.
"""

# Preset configurations for various software types
FRIDA_PRESETS = {
    "Adobe Creative Cloud": {
        "description": "Comprehensive bypass for Adobe CC applications",
        "target": "Adobe Photoshop, Illustrator, Premiere Pro, After Effects",
        "scripts": [
            "adobe_bypass",
            "cloud_licensing_bypass",
            "time_bomb_defuser",
            "registry_monitor"
        ],
        "protections": ["LICENSE", "CLOUD", "TIME", "INTEGRITY"],
        "options": {
            "aggressive": True,
            "patch_checksums": True,
            "emulate_server": True,
            "hook_priority": "HIGH"
        },
        "hooks": [
            "advapi32.dll!RegQueryValueExW",
            "wininet.dll!InternetOpenUrlW",
            "kernel32.dll!GetSystemTime",
            "advapi32.dll!CryptHashData"
        ]
    },

    "Microsoft Office 365": {
        "description": "Bypass for Microsoft Office licensing and activation",
        "target": "Word, Excel, PowerPoint, Outlook",
        "scripts": [
            "cloud_licensing_bypass",
            "registry_monitor",
            "telemetry_blocker"
        ],
        "protections": ["LICENSE", "CLOUD", "HARDWARE"],
        "options": {
            "stealth_mode": True,
            "block_telemetry": True,
            "spoof_hardware": True
        },
        "hooks": [
            "sppc.dll!SLGetLicensingStatusInformation",
            "osppc.dll!OfficeGetLicensingStatus",
            "winhttp.dll!WinHttpOpen",
            "kernel32.dll!GetVolumeInformationW"
        ]
    },

    "Autodesk Products": {
        "description": "Bypass for AutoCAD, 3ds Max, Maya, Revit",
        "target": "Autodesk software suite",
        "scripts": [
            "cloud_licensing_bypass",
            "enhanced_hardware_spoofer",
            "time_bomb_defuser",
            "code_integrity_bypass"
        ],
        "protections": ["LICENSE", "HARDWARE", "TIME", "INTEGRITY"],
        "options": {
            "patch_license_check": True,
            "spoof_all_hardware": True,
            "freeze_time": True
        },
        "hooks": [
            "AdskLicensingSDK*.dll!*",
            "kernel32.dll!GetSystemTime",
            "iphlpapi.dll!GetAdaptersInfo",
            "advapi32.dll!CryptHashData"
        ]
    },

    "VMware Products": {
        "description": "Bypass for VMware Workstation and vSphere",
        "target": "VMware virtualization software",
        "scripts": [
            "registry_monitor",
            "time_bomb_defuser",
            "enhanced_hardware_spoofer"
        ],
        "protections": ["LICENSE", "TIME", "HARDWARE"],
        "options": {
            "patch_trial": True,
            "extend_evaluation": True,
            "hide_vm_detection": True
        },
        "hooks": [
            "vmware-vmx.exe!*License*",
            "kernel32.dll!GetSystemTime",
            "kernel32.dll!GetTickCount64"
        ]
    },

    "Anti-Virus Software": {
        "description": "Bypass for antivirus license checks",
        "target": "Various AV products",
        "scripts": [
            "anti_debugger",
            "virtualization_bypass",
            "memory_integrity_bypass",
            "kernel_mode_bypass"
        ],
        "protections": ["LICENSE", "ANTI_DEBUG", "KERNEL", "MEMORY"],
        "options": {
            "usermode_only": True,
            "avoid_kernel": True,
            "stealth_hooks": True
        },
        "hooks": [
            "kernel32.dll!IsDebuggerPresent",
            "ntdll.dll!NtQueryInformationProcess",
            "kernel32.dll!DeviceIoControl"
        ]
    },

    "Steam Games (CEG)": {
        "description": "Bypass Steam CEG (Custom Executable Generation)",
        "target": "Steam protected games",
        "scripts": [
            "code_integrity_bypass",
            "memory_integrity_bypass",
            "anti_debugger"
        ],
        "protections": ["DRM", "INTEGRITY", "ANTI_DEBUG"],
        "options": {
            "patch_steam_stub": True,
            "bypass_ceg": True,
            "hook_steam_api": True
        },
        "hooks": [
            "steam_api*.dll!*",
            "kernel32.dll!VirtualProtect",
            "ntdll.dll!NtProtectVirtualMemory"
        ]
    },

    "Denuvo Protected Games": {
        "description": "Advanced bypass for Denuvo anti-tamper",
        "target": "AAA games with Denuvo",
        "scripts": [
            "anti_debugger",
            "code_integrity_bypass",
            "memory_integrity_bypass",
            "virtualization_bypass"
        ],
        "protections": ["DRM", "ANTI_DEBUG", "ANTI_VM", "INTEGRITY"],
        "options": {
            "aggressive": True,
            "deep_hooks": True,
            "patch_vm_checks": True,
            "timing_bypass": True
        },
        "hooks": [
            "ntdll.dll!*",
            "kernel32.dll!QueryPerformanceCounter",
            "kernel32.dll!GetTickCount*",
            "user32.dll!GetAsyncKeyState"
        ]
    },

    "Enterprise Software": {
        "description": "Generic bypass for enterprise applications",
        "target": "SAP, Oracle, IBM software",
        "scripts": [
            "cloud_licensing_bypass",
            "enhanced_hardware_spoofer",
            "registry_monitor",
            "telemetry_blocker"
        ],
        "protections": ["LICENSE", "CLOUD", "HARDWARE", "TELEMETRY"],
        "options": {
            "enterprise_mode": True,
            "multi_user_spoof": True,
            "server_emulation": True
        },
        "hooks": [
            "winhttp.dll!*",
            "wininet.dll!*",
            "ws2_32.dll!*",
            "advapi32.dll!Reg*"
        ]
    },

    "FlexLM/FlexNet Licensed": {
        "description": "Bypass for FlexLM/FlexNet license manager",
        "target": "Engineering and scientific software",
        "scripts": [
            "cloud_licensing_bypass",
            "time_bomb_defuser",
            "enhanced_hardware_spoofer"
        ],
        "protections": ["LICENSE", "TIME", "HARDWARE"],
        "options": {
            "flexlm_mode": True,
            "emulate_license_server": True,
            "patch_hostid": True
        },
        "hooks": [
            "lmgr*.dll!*",
            "flexnet*.dll!*",
            "ws2_32.dll!connect",
            "kernel32.dll!GetVolumeInformation*"
        ]
    },

    "HASP/Sentinel Protected": {
        "description": "Bypass for HASP/Sentinel dongle protection",
        "target": "Industrial and specialized software",
        "scripts": [
            "enhanced_hardware_spoofer",
            "registry_monitor",
            "memory_integrity_bypass"
        ],
        "protections": ["HARDWARE", "LICENSE", "MEMORY"],
        "options": {
            "dongle_emulation": True,
            "hasp_mode": True,
            "memory_patch": True
        },
        "hooks": [
            "hasp*.dll!*",
            "sentinel*.dll!*",
            "kernel32.dll!DeviceIoControl",
            "setupapi.dll!*"
        ]
    },

    "Trial Software (Generic)": {
        "description": "Generic bypass for trial/evaluation software",
        "target": "Various trial versions",
        "scripts": [
            "time_bomb_defuser",
            "registry_monitor",
            "telemetry_blocker"
        ],
        "protections": ["TIME", "LICENSE", "TELEMETRY"],
        "options": {
            "reset_trial": True,
            "freeze_time": True,
            "clean_traces": True
        },
        "hooks": [
            "kernel32.dll!GetSystemTime*",
            "kernel32.dll!GetLocalTime",
            "advapi32.dll!RegSetValue*",
            "kernel32.dll!GetTickCount*"
        ]
    },

    "Development Tools": {
        "description": "Bypass for IDEs and development tools",
        "target": "JetBrains, Visual Studio extensions",
        "scripts": [
            "cloud_licensing_bypass",
            "registry_monitor",
            "time_bomb_defuser"
        ],
        "protections": ["LICENSE", "CLOUD", "TIME"],
        "options": {
            "dev_mode": True,
            "patch_eval": True,
            "unlock_features": True
        },
        "hooks": [
            "wininet.dll!*",
            "advapi32.dll!Reg*",
            "kernel32.dll!GetSystemTime"
        ]
    },

    "Media Production Software": {
        "description": "Bypass for audio/video production tools",
        "target": "DAWs, NLEs, plugins",
        "scripts": [
            "registry_monitor",
            "enhanced_hardware_spoofer",
            "code_integrity_bypass",
            "time_bomb_defuser"
        ],
        "protections": ["LICENSE", "HARDWARE", "TIME", "INTEGRITY"],
        "options": {
            "plugin_mode": True,
            "multi_instance": True,
            "auth_bypass": True
        },
        "hooks": [
            "kernel32.dll!GetVolumeInformation*",
            "advapi32.dll!Reg*",
            "kernel32.dll!CreateMutex*",
            "user32.dll!FindWindow*"
        ]
    },

    "Educational Software": {
        "description": "Bypass for educational and training software",
        "target": "E-learning platforms, simulators",
        "scripts": [
            "cloud_licensing_bypass",
            "time_bomb_defuser",
            "telemetry_blocker"
        ],
        "protections": ["LICENSE", "CLOUD", "TIME"],
        "options": {
            "educational_mode": True,
            "unlock_content": True,
            "bypass_drm": True
        },
        "hooks": [
            "wininet.dll!*",
            "winhttp.dll!*",
            "kernel32.dll!GetSystemTime*"
        ]
    },

    "Minimal Bypass": {
        "description": "Minimal bypass for testing purposes",
        "target": "Unknown/Generic software",
        "scripts": [
            "registry_monitor"
        ],
        "protections": ["LICENSE"],
        "options": {
            "safe_mode": True,
            "minimal_hooks": True,
            "log_only": True
        },
        "hooks": [
            "advapi32.dll!RegQueryValueEx*"
        ]
    },

    "Maximum Protection Bypass": {
        "description": "All available bypasses for heavily protected software",
        "target": "Unknown heavily protected software",
        "scripts": [
            "anti_debugger",
            "virtualization_bypass",
            "cloud_licensing_bypass",
            "code_integrity_bypass",
            "memory_integrity_bypass",
            "kernel_mode_bypass",
            "enhanced_hardware_spoofer",
            "time_bomb_defuser",
            "registry_monitor",
            "telemetry_blocker"
        ],
        "protections": ["ALL"],
        "options": {
            "aggressive": True,
            "all_bypasses": True,
            "deep_hooks": True,
            "stealth_mode": True
        },
        "hooks": [
            "*!*Debug*",
            "*!*License*",
            "*!*Protection*",
            "*!*Verify*",
            "*!*Check*"
        ]
    }
}

# Wizard configurations for automated bypass
WIZARD_CONFIGS = {
    "safe": {
        "name": "Safe Mode",
        "description": "Conservative approach with minimal risk",
        "detection_first": True,
        "max_scripts": 3,
        "priority": ["LICENSE", "TIME"],
        "exclude": ["KERNEL", "MEMORY"],
        "options": {
            "safe_mode": True,
            "minimal_hooks": True
        }
    },

    "balanced": {
        "name": "Balanced Mode",
        "description": "Good balance between effectiveness and safety",
        "detection_first": True,
        "max_scripts": 5,
        "priority": ["LICENSE", "CLOUD", "TIME", "HARDWARE"],
        "exclude": ["KERNEL"],
        "options": {
            "selective": True,
            "adaptive": True
        }
    },

    "aggressive": {
        "name": "Aggressive Mode",
        "description": "Maximum bypass capability",
        "detection_first": False,
        "max_scripts": 10,
        "priority": ["ALL"],
        "exclude": [],
        "options": {
            "aggressive": True,
            "all_bypasses": True,
            "deep_hooks": True
        }
    },

    "stealth": {
        "name": "Stealth Mode",
        "description": "Minimize detection by anti-cheat/anti-debug",
        "detection_first": True,
        "max_scripts": 4,
        "priority": ["LICENSE", "CLOUD"],
        "exclude": ["KERNEL", "ANTI_DEBUG"],
        "options": {
            "stealth_mode": True,
            "usermode_only": True,
            "indirect_hooks": True
        }
    },

    "analysis": {
        "name": "Analysis Only",
        "description": "Detect protections without bypassing",
        "detection_first": True,
        "max_scripts": 2,
        "priority": ["DETECTION"],
        "exclude": ["ALL_BYPASSES"],
        "options": {
            "log_only": True,
            "no_patches": True,
            "monitor_mode": True
        }
    }
}

# Quick templates for specific scenarios
QUICK_TEMPLATES = {
    "trial_reset": {
        "scripts": ["time_bomb_defuser", "registry_monitor"],
        "options": {"reset_trial": True, "freeze_time": True}
    },

    "hardware_spoof": {
        "scripts": ["enhanced_hardware_spoofer"],
        "options": {"spoof_all": True, "persistent": True}
    },

    "cloud_bypass": {
        "scripts": ["cloud_licensing_bypass", "telemetry_blocker"],
        "options": {"emulate_server": True, "block_telemetry": True}
    },

    "anti_debug_bypass": {
        "scripts": ["anti_debugger", "virtualization_bypass"],
        "options": {"aggressive": True, "patch_all": True}
    },

    "drm_bypass": {
        "scripts": ["code_integrity_bypass", "memory_integrity_bypass"],
        "options": {"patch_checks": True, "hook_crypto": True}
    }
}

def get_preset_by_software(software_name: str) -> dict:
    """Get preset configuration by software name (fuzzy matching)"""
    software_lower = software_name.lower()

    for preset_name, preset_config in FRIDA_PRESETS.items():
        if software_lower in preset_name.lower():
            return preset_config

        # Check target field
        if 'target' in preset_config:
            if software_lower in preset_config['target'].lower():
                return preset_config

    # Default to minimal bypass
    return FRIDA_PRESETS["Minimal Bypass"]

def get_wizard_config(mode: str = "balanced") -> dict:
    """Get wizard configuration by mode"""
    return WIZARD_CONFIGS.get(mode, WIZARD_CONFIGS["balanced"])

def get_scripts_for_protection(protection_type: str) -> list:
    """Get recommended scripts for a specific protection type"""
    script_map = {
        "LICENSE": ["cloud_licensing_bypass", "registry_monitor"],
        "CLOUD": ["cloud_licensing_bypass", "telemetry_blocker"],
        "TIME": ["time_bomb_defuser"],
        "HARDWARE": ["enhanced_hardware_spoofer"],
        "ANTI_DEBUG": ["anti_debugger"],
        "ANTI_VM": ["virtualization_bypass"],
        "INTEGRITY": ["code_integrity_bypass", "memory_integrity_bypass"],
        "KERNEL": ["kernel_mode_bypass"],
        "MEMORY": ["memory_integrity_bypass"],
        "DRM": ["drm_bypass", "code_integrity_bypass"]
    }

    return script_map.get(protection_type, [])

# Export configuration
__all__ = [
    'FRIDA_PRESETS',
    'WIZARD_CONFIGS',
    'QUICK_TEMPLATES',
    'get_preset_by_software',
    'get_wizard_config',
    'get_scripts_for_protection'
]

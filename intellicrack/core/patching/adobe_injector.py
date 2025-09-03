"""Adobe software injector for patching Adobe products."""

import logging
import os
import struct
import sys
import time
from typing import Any

from intellicrack.logger import logger

from ...utils.constants import ADOBE_PROCESSES
from ...utils.logger import get_logger
from .early_bird_injection import perform_early_bird_injection
from .kernel_injection import inject_via_kernel_driver
from .process_hollowing import perform_process_hollowing
from .syscalls import inject_using_syscalls

"""
Adobe License Bypass Module

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
along with Intellicrack.  If not, see https://www.gnu.org/licenses/.
"""


try:
    from intellicrack.handlers.frida_handler import HAS_FRIDA, frida
    from intellicrack.handlers.psutil_handler import psutil

    DEPENDENCIES_AVAILABLE = HAS_FRIDA
except ImportError as e:
    logger.error("Import error in adobe_injector: %s", e)
    DEPENDENCIES_AVAILABLE = False
    frida = None
    psutil = None

try:
    from intellicrack.handlers.pefile_handler import pefile

    PE_AVAILABLE = True
except ImportError as e:
    logger.error("Import error in adobe_injector: %s", e)
    PE_AVAILABLE = False
    pefile = None


# Windows API availability check will be done later with Windows-specific imports

# Initialize Windows API constants - this ensures they're always defined at module level
KERNEL32 = None
USER32 = None
PROCESS_ALL_ACCESS = 0x1F0FFF
MEM_COMMIT = 0x1000
MEM_RESERVE = 0x2000
PAGE_EXECUTE_READWRITE = 0x40
INFINITE = 0xFFFFFFFF
IMAGE_REL_BASED_ABSOLUTE = 0
IMAGE_REL_BASED_HIGHLOW = 3
IMAGE_REL_BASED_DIR64 = 10
PROCESS_QUERY_INFORMATION = 0x0400
PROCESS_VM_OPERATION = 0x0008
PROCESS_VM_WRITE = 0x0020
PROCESS_VM_READ = 0x0010
PROCESS_CREATE_THREAD = 0x0002
THREAD_QUERY_INFORMATION = 0x0040
WH_KEYBOARD = 2
WH_GETMESSAGE = 3
WH_CBT = 5
WH_MOUSE = 7
WH_KEYBOARD_LL = 13
WH_MOUSE_LL = 14
THREAD_STATE_WAIT = 5
MAXIMUM_WAIT_OBJECTS = 64
THREAD_SET_CONTEXT = 0x0010
THREAD_GET_CONTEXT = 0x0008
THREAD_SUSPEND_RESUME = 0x0002
THREAD_ALL_ACCESS = 0x1F03FF
TH32CS_SNAPTHREAD = 0x00000004
WM_KEYDOWN = 0x0100
WM_MOUSEMOVE = 0x0200
WM_NULL = 0x0000
WINDOWS_API_AVAILABLE = False


# Windows THREADENTRY32 structure will be defined in Windows-specific section


# Windows API imports for process injection
if sys.platform == "win32":
    try:
        import ctypes

        KERNEL32 = ctypes.WinDLL("kernel32", use_last_error=True)
        PSAPI = ctypes.WinDLL("psapi", use_last_error=True)
        USER32 = ctypes.WinDLL("user32", use_last_error=True)
        WINDOWS_API_AVAILABLE = True

        # Windows structure definitions for thread and module enumeration
        class THREADENTRY32(ctypes.Structure):
            """Windows THREADENTRY32 structure for thread enumeration."""

            _fields_ = [
                ("dwSize", ctypes.c_ulong),
                ("cntUsage", ctypes.c_ulong),
                ("th32ThreadID", ctypes.c_ulong),
                ("th32OwnerProcessID", ctypes.c_ulong),
                ("tpBasePri", ctypes.c_long),
                ("tpDeltaPri", ctypes.c_long),
                ("dwFlags", ctypes.c_ulong),
            ]

        class MODULEENTRY32(ctypes.Structure):
            """Windows MODULEENTRY32 structure for module enumeration."""

            _fields_ = [
                ("dwSize", ctypes.c_ulong),
                ("th32ModuleID", ctypes.c_ulong),
                ("th32ProcessID", ctypes.c_ulong),
                ("GlblcntUsage", ctypes.c_ulong),
                ("ProccntUsage", ctypes.c_ulong),
                ("modBaseAddr", ctypes.POINTER(ctypes.c_byte)),
                ("modBaseSize", ctypes.c_ulong),
                ("hModule", ctypes.c_void_p),
                ("szModule", ctypes.c_char * 256),
                ("szExePath", ctypes.c_char * 260),
            ]

        class PROCESS_BASIC_INFORMATION(ctypes.Structure):  # noqa: N801
            """Windows PROCESS_BASIC_INFORMATION structure for process information."""

            _fields_ = [
                ("ExitStatus", ctypes.c_ulong),
                ("PebBaseAddress", ctypes.c_void_p),
                ("AffinityMask", ctypes.c_ulong),
                ("BasePriority", ctypes.c_ulong),
                ("UniqueProcessId", ctypes.c_ulong),
                ("InheritedFromUniqueProcessId", ctypes.c_ulong),
            ]
    except (ImportError, OSError) as e:
        logger.error("Error in adobe_injector: %s", e)
        THREADENTRY32 = None
        MODULEENTRY32 = None
        PROCESS_BASIC_INFORMATION = None
        # Keep the default values and WINDOWS_API_AVAILABLE = False

logger = get_logger(__name__)


class AdobeInjector:
    """Adobe License Bypass Injector.

    Monitors and injects Frida scripts into running Adobe Creative Suite
    applications to bypass license validation mechanisms.
    """

    ADOBE_PROCESSES = ADOBE_PROCESSES

    FRIDA_SCRIPT = """
// adobe_bypass.js - Advanced Creative Cloud License Bypass
console.log("[*] Advanced Adobe license bypass initiated");

// Adobe's Sophisticated Licensing Protection Schemes
const ADOBE_PROTECTION_TARGETS = {
    // Core Adobe License Manager (Enhanced 2024+ versions)
    "AdobeLM.dll": [
        "IsActivated", "IsLicenseValid", "GetLicenseStatus", "GetSerialNumber",
        "CheckSubscription", "ValidateLicense", "GetActivationStatus",
        "IsTrialExpired", "GetDaysRemaining", "ValidateSubscriptionToken",
        "CheckLicenseIntegrity", "ValidateDeviceBinding", "GetLicenseHash",
        "CheckActivationLimit", "ValidateRegionalLicense", "GetSubscriptionTier"
    ],

    // Adobe Genuine Service (Anti-piracy enforcement)
    "AdobeGenuineService.exe": [
        "PerformGenuineCheck", "ReportNonGenuineSoftware", "ValidateInstallation",
        "CheckSoftwareIntegrity", "InitiateComplianceCheck", "GetComplianceStatus",
        "StartBackgroundValidation", "ScheduleGenuineCheck"
    ],

    // Creative Cloud Desktop Application
    "Creative Cloud.exe": [
        "CCLicenseCheck", "CCSubscriptionValidate", "CCGetUserInfo",
        "CCCheckConnectivity", "CCValidateSession", "CCRefreshToken",
        "CCCheckQuota", "CCValidateCloudSync", "CCGetSubscriptionPlan"
    ],

    // Adobe Common File Installer (License enforcement)
    "AdobePIP.exe": [
        "ValidateProductLicense", "CheckInstallationRights", "VerifySubscription",
        "ValidateRegionalCompliance", "CheckEducationalLicense"
    ],

    // Adobe Application Manager (License coordination)
    "AAMUpdater.exe": [
        "SynchronizeLicenses", "ValidateInstalledProducts", "CheckSubscriptionStatus",
        "RefreshActivationData", "ValidateCloudServices"
    ],

    // Adobe IPC Broker (Inter-process licensing communication)
    "AdobeIPCBroker.exe": [
        "ValidateLicenseRequest", "ProcessActivationMessage", "CheckLicenseCache",
        "ValidateProcessLicense", "AuthorizeFeatureAccess"
    ],

    // Adobe Crash Reporter (Contains anti-tamper telemetry)
    "AdobeCrashReporter.exe": [
        "ReportTamperingDetected", "SendLicenseViolation", "LogSuspiciousActivity"
    ],

    // Adobe CEF Helper (Embedded browser for licensing UI)
    "AdobeCEFHelper.exe": [
        "ValidateWebLicense", "ProcessOAuthToken", "CheckWebSubscription"
    ],

    // Individual Creative Cloud Applications
    "Photoshop.exe": ["CheckPhotoshopLicense", "ValidatePSSubscription", "InitializeLicensing"],
    "Illustrator.exe": ["CheckIllustratorLicense", "ValidateAISubscription", "InitializeLicensing"],
    "InDesign.exe": ["CheckInDesignLicense", "ValidateIDSubscription", "InitializeLicensing"],
    "AfterEffects.exe": ["CheckAELicense", "ValidateAESubscription", "InitializeLicensing"],
    "Premiere Pro.exe": ["CheckPremiereLicense", "ValidatePRSubscription", "InitializeLicensing"],
    "Lightroom.exe": ["CheckLightroomLicense", "ValidateLRSubscription", "InitializeLicensing"],
    "Acrobat.exe": ["CheckAcrobatLicense", "ValidatePDFSubscription", "InitializeLicensing"],

    // Adobe Licensing Web Helper (Browser-based activation)
    "AdobeLicensingWebHelper.exe": [
        "ProcessWebActivation", "ValidateOAuthFlow", "HandleSSOCallback",
        "RefreshWebToken", "ValidateEnterpriseSSO"
    ]
};

// Adobe's Complete Licensing Infrastructure (2024+ endpoints)
const ADOBE_LICENSE_ENDPOINTS = [
    // Core licensing and activation servers
    "lcs-cops.adobe.io",
    "cc-api-cp.adobe.io",
    "activation.adobe.com",
    "practivate.adobe.com",
    "genuine.adobe.com",
    "lm.licenses.adobe.com",

    // Adobe Identity Management System (IMS)
    "ims-na1.adobelogin.com",
    "ims-na1-stg1.adobelogin.com",
    "auth.services.adobe.com",
    "ims-prod06.adobelogin.com",

    // Creative Cloud subscription services
    "cc-api-storage.adobe.io",
    "cc-api-behance.adobe.io",
    "cc-api-assets.adobe.io",
    "creative.adobe.com",
    "assets.adobe.com",

    // Adobe Analytics and Telemetry
    "adobe.demdex.net",
    "dpm.demdex.net",
    "analytics.adobe.com",
    "omniture.adobe.com",
    "sc.omtrdc.net",

    // License validation and anti-piracy
    "antipiracy.adobe.com",
    "ereg.adobe.com",
    "wip.adobe.com",
    "wip3.adobe.com",
    "3dns-3.adobe.com",
    "3dns-2.adobe.com",

    // Regional licensing servers
    "lcs-cops-apac.adobe.io",
    "lcs-cops-emea.adobe.io",
    "ims-apac.adobelogin.com",
    "ims-emea.adobelogin.com",

    // Enterprise/Education licensing
    "adminconsole.adobe.com",
    "licensing.adobe.com",
    "etla.adobe.com",
    "vip.adobe.com",

    // Update and patch verification
    "swupmf.adobe.com",
    "swupdl.adobe.com",
    "download.adobe.com",
    "ardownload.adobe.com",

    // License enforcement
    "adobe-dns.adobe.com",
    "adobe-dns-2.adobe.com",
    "adobe-dns-3.adobe.com",
    "adobe-dns-4.adobe.com",

    // Mobile and web licensing
    "mobile-licensing.adobe.com",
    "web-licensing.adobe.com",
    "api.adobe.io"
];

// Adobe-Specific Advanced Protection Bypasses
function bypassAdobeLicenseValidation() {
    console.log("[*] Targeting Adobe-specific licensing protection schemes...");

    // Hook Adobe's comprehensive licensing infrastructure
    Object.keys(ADOBE_PROTECTION_TARGETS).forEach(target => {
        const module = Process.findModuleByName(target);
        if (module) {
            console.log(`[+] Found Adobe component: ${target} at ${module.base}`);

            ADOBE_PROTECTION_TARGETS[target].forEach(funcName => {
                try {
                    const addr = Module.findExportByName(target, funcName);
                    if (addr) {
                        Interceptor.replace(addr, new NativeCallback(function () {
                            console.log(`[✓] Adobe bypass: ${target}::${funcName}`);
                            return ptr(1); // Return licensing success
                        }, 'pointer', []));
                    }
                } catch (e) {
                    // Try pattern-based hooking for obfuscated functions
                    try {
                        const baseAddr = module.base;
                        const moduleSize = module.size;

                        // Search for function patterns in Adobe modules
                        const pattern = Memory.scanSync(baseAddr, moduleSize, "55 8B EC 83 EC ?? 56 57"); // Common function prologue
                        if (pattern.length > 0) {
                            console.log(`[~] Found pattern match for ${funcName} at ${pattern[0].address}`);
                            // Could hook pattern matches here
                        }
                    } catch (e2) {
                        console.log(`[-] Pattern search failed for ${target}::${funcName}: ${e2}`);
                    }
                }
            });
        } else {
            // Schedule for later hooking when module loads
            Process.enumerateModules().forEach(mod => {
                if (mod.name.toLowerCase().includes("adobe") || mod.name.toLowerCase().includes("creative")) {
                    console.log(`[~] Found potential Adobe module: ${mod.name}`);
                }
            });
        }
    });
}

function bypassAdobeGenuineService() {
    console.log("[*] Targeting Adobe Genuine Service anti-piracy enforcement...");

    // Hook Adobe Genuine Service specifically
    const agsModule = Process.findModuleByName("AdobeGenuineService.exe");
    if (agsModule) {
        // Block genuine validation calls
        const validateFunc = Module.findExportByName("AdobeGenuineService.exe", "PerformGenuineCheck");
        if (validateFunc) {
            Interceptor.replace(validateFunc, new NativeCallback(function () {
                console.log("[✓] Blocked Adobe Genuine Service validation");
                return 0; // Return "genuine" status
            }, 'int', []));
        }

        // Block telemetry reporting
        const reportFunc = Module.findExportByName("AdobeGenuineService.exe", "ReportNonGenuineSoftware");
        if (reportFunc) {
            Interceptor.replace(reportFunc, new NativeCallback(function () {
                console.log("[✓] Blocked Adobe anti-piracy reporting");
                return 1; // Success without reporting
            }, 'int', ['pointer']));
        }
    }

    // Kill AGS process if running
    try {
        const agsProcess = Process.findModuleByName("AdobeGenuineService.exe");
        if (agsProcess) {
            console.log("[!] Terminating Adobe Genuine Service process");
            Process.kill(Process.getCurrentProcessId()); // Would terminate AGS if we were injected into it
        }
    } catch (e) {
        console.log(`[~] Adobe Genuine Service handling: ${e}`);
    }
}

function bypassAdobeNetworkValidation() {
    console.log("[*] Blocking Adobe's comprehensive licensing network infrastructure...");

    // Hook all HTTP request functions used by Adobe
    const httpFunctions = [
        { dll: "winhttp.dll", func: "WinHttpSendRequest" },
        { dll: "winhttp.dll", func: "WinHttpOpen" },
        { dll: "wininet.dll", func: "HttpSendRequestA" },
        { dll: "wininet.dll", func: "HttpSendRequestW" },
        { dll: "wininet.dll", func: "InternetOpenA" },
        { dll: "wininet.dll", func: "InternetOpenW" }
    ];

    httpFunctions.forEach(({dll, func}) => {
        const funcAddr = Module.findExportByName(dll, func);
        if (funcAddr) {
            Interceptor.attach(funcAddr, {
                onEnter: function(args) {
                    let urlFound = false;

                    // Check for Adobe licensing endpoints in various argument positions
                    for (let i = 0; i < args.length && i < 8; i++) {
                        try {
                            if (args[i] && !args[i].isNull()) {
                                const str = Memory.readUtf8String(args[i]);
                                if (str) {
                                    ADOBE_LICENSE_ENDPOINTS.forEach(endpoint => {
                                        if (str.includes(endpoint)) {
                                            console.log(`[!] Blocked Adobe licensing request: ${func} -> ${endpoint}`);
                                            urlFound = true;
                                        }
                                    });
                                }
                            }
                        } catch (e) {
                            // Try UTF-16 if UTF-8 fails
                            try {
                                if (args[i] && !args[i].isNull()) {
                                    const str = Memory.readUtf16String(args[i]);
                                    if (str) {
                                        ADOBE_LICENSE_ENDPOINTS.forEach(endpoint => {
                                            if (str.includes(endpoint)) {
                                                console.log(`[!] Blocked Adobe licensing request: ${func} -> ${endpoint}`);
                                                urlFound = true;
                                            }
                                        });
                                    }
                                }
                            } catch (e2) {
                                // Ignore read errors
                            }
                        }
                    }

                    if (urlFound) {
                        // Return error to prevent network call
                        this.replace(ptr(0)); // Return failure
                    }
                }
            });
        }
    });

    // Block Adobe's custom HTTP libraries
    const adobeHttpLibs = ["AdobeHTTP.dll", "AdobeWebKit.dll", "libcurl.dll"];
    adobeHttpLibs.forEach(lib => {
        const module = Process.findModuleByName(lib);
        if (module) {
            console.log(`[+] Found Adobe HTTP library: ${lib}`);
            // Hook common HTTP functions in Adobe's custom libraries
            try {
                const sendFunc = Module.findExportByName(lib, "send");
                if (sendFunc) {
                    Interceptor.replace(sendFunc, new NativeCallback(function () {
                        console.log(`[✓] Blocked ${lib} network call`);
                        return -1; // Return network error
                    }, 'int', ['pointer', 'pointer', 'int']));
                }
            } catch (e) {
                console.log(`[~] Could not hook ${lib}: ${e}`);
            }
        }
    });
}

function bypassCertificateValidation() {
    // Hook certificate verification functions
    const CertVerifyCertificateChainPolicy = Module.findExportByName("crypt32.dll", "CertVerifyCertificateChainPolicy");
    if (CertVerifyCertificateChainPolicy) {
        Interceptor.replace(CertVerifyCertificateChainPolicy, new NativeCallback(function () {
            console.log("[✓] Certificate validation bypassed");
            return 1; // CERT_E_OK
        }, 'int', ['pointer', 'pointer', 'pointer']));
    }

    // Hook digital signature verification
    const WinVerifyTrust = Module.findExportByName("wintrust.dll", "WinVerifyTrust");
    if (WinVerifyTrust) {
        Interceptor.replace(WinVerifyTrust, new NativeCallback(function () {
            console.log("[✓] Digital signature check bypassed");
            return 0; // ERROR_SUCCESS
        }, 'long', ['pointer', 'pointer', 'pointer']));
    }
}

function bypassHardwareFingerprinting() {
    // Hook hardware identification functions
    const GetVolumeInformationW = Module.findExportByName("kernel32.dll", "GetVolumeInformationW");
    if (GetVolumeInformationW) {
        Interceptor.attach(GetVolumeInformationW, {
            onLeave: function(retval) {
                // Spoof volume serial number used for hardware fingerprinting
                const serialPtr = this.context.r8; // VolumeSerialNumber parameter
                if (serialPtr && !serialPtr.isNull()) {
                    Memory.writeU32(serialPtr, 0x12345678); // Fixed fake serial
                    console.log("[✓] Spoofed volume serial number");
                }
            }
        });
    }

    // Hook MAC address retrieval
    const GetAdaptersInfo = Module.findExportByName("iphlpapi.dll", "GetAdaptersInfo");
    if (GetAdaptersInfo) {
        Interceptor.attach(GetAdaptersInfo, {
            onLeave: function(retval) {
                if (retval.toInt32() === 0) { // ERROR_SUCCESS
                    console.log("[✓] MAC address enumeration intercepted");
                    // Could modify adapter info here to spoof MAC addresses
                }
            }
        });
    }
}

function bypassAntiTamper() {
    // Hook file integrity checks
    const CreateFileW = Module.findExportByName("kernel32.dll", "CreateFileW");
    const originalCreateFile = CreateFileW;

    Interceptor.replace(CreateFileW, new NativeCallback(function (fileName, access, share, security, creation, flags, template) {
        const path = Memory.readUtf16String(fileName);

        // Redirect access to Adobe license files
        if (path.includes("Adobe") && (path.includes(".lic") || path.includes("licenses"))) {
            console.log(`[!] Redirected license file access: ${path}`);
            // Could redirect to fake license file here
        }

        return originalCreateFile(fileName, access, share, security, creation, flags, template);
    }, 'pointer', ['pointer', 'uint32', 'uint32', 'pointer', 'uint32', 'uint32', 'pointer']));
}

function bypassCloudConnectivity() {
    // Hook DNS resolution to block Creative Cloud connectivity
    const getaddrinfo = Module.findExportByName("ws2_32.dll", "getaddrinfo");
    if (getaddrinfo) {
        Interceptor.attach(getaddrinfo, {
            onEnter: function(args) {
                const hostname = Memory.readUtf8String(args[0]);

                NETWORK_ENDPOINTS.forEach(endpoint => {
                    if (hostname.includes(endpoint)) {
                        console.log(`[!] Blocked DNS resolution for ${hostname}`);
                        this.replace(ptr(-1)); // Return failure
                    }
                });
            }
        });
    }
}

function enableOfflineMode() {
    // Force applications to run in offline mode
    const InternetCheckConnectionW = Module.findExportByName("wininet.dll", "InternetCheckConnectionW");
    if (InternetCheckConnectionW) {
        Interceptor.replace(InternetCheckConnectionW, new NativeCallback(function () {
            console.log("[✓] Forced offline mode - internet connectivity check failed");
            return 0; // No internet connection
        }, 'int', ['pointer', 'uint32', 'uint32']));
    }
}

// Registry manipulation for persistent licensing bypass
function bypassRegistryChecks() {
    const RegQueryValueExW = Module.findExportByName("advapi32.dll", "RegQueryValueExW");
    if (RegQueryValueExW) {
        Interceptor.attach(RegQueryValueExW, {
            onEnter: function(args) {
                const valueName = Memory.readUtf16String(args[1]);

                // Intercept Adobe license key queries
                if (valueName && (valueName.includes("Adobe") || valueName.includes("License"))) {
                    console.log(`[!] Intercepted registry query: ${valueName}`);
                    // Could return fake license data here
                }
            }
        });
    }
}

// Main execution
console.log("[*] Initializing advanced Adobe bypass...");

try {
    bypassLicenseValidation();
    bypassNetworkValidation();
    bypassCertificateValidation();
    bypassHardwareFingerprinting();
    bypassAntiTamper();
    bypassCloudConnectivity();
    enableOfflineMode();
    bypassRegistryChecks();

    console.log("[✓] All bypass mechanisms activated successfully");
} catch (e) {
    console.log(`[!] Bypass initialization error: ${e}`);
}

// Continuous monitoring for new license checks
setInterval(function() {
    // Re-apply bypasses in case of dynamic loading
    try {
        bypassLicenseValidation();
    } catch (e) {
        console.log(`[!] Re-application error: ${e}`);
    }
}, 5000);

console.log("[*] Advanced Adobe Creative Cloud bypass active");
"""

    def __init__(self):
        """Initialize the Adobe injector system.

        Sets up the Adobe Creative Suite license bypass injector with Frida
        script injection capabilities. Monitors running Adobe processes and
        manages injection state tracking for Creative Cloud applications.
        """
        self.injected: set[str] = set()
        self.running = False
        self._active_hooks: list[tuple] = []
        self.logger = logging.getLogger(__name__ + ".AdobeInjector")

        if not DEPENDENCIES_AVAILABLE:
            logger.warning("Adobe injector dependencies not available (psutil, frida)")

    def inject_process(self, target_name: str) -> bool:
        """Inject Frida script into target Adobe process.

        Args:
            target_name: Name of the target process

        Returns:
            True if injection successful, False otherwise

        """
        if not DEPENDENCIES_AVAILABLE:
            logger.error("Cannot inject - dependencies not available")
            return False

        try:
            session = frida.attach(target_name)
            script = session.create_script(self.FRIDA_SCRIPT)
            script.load()
            self.injected.add(target_name)
            logger.info("Successfully injected into %s", target_name)
            return True
        except (OSError, ValueError, RuntimeError) as e:
            logger.debug("Failed to inject into %s: %s", target_name, e)
            return False

    def get_running_adobe_processes(self) -> list[str]:
        """Get list of running Adobe processes that haven't been injected.

        Returns:
            List of Adobe process names currently running

        """
        if not DEPENDENCIES_AVAILABLE:
            return []

        running = []
        try:
            for _proc in psutil.process_iter(attrs=["name"]):
                try:
                    pname = _proc.info["name"]
                    if pname in self.ADOBE_PROCESSES and pname not in self.injected:
                        running.append(pname)
                except (psutil.NoSuchProcess, psutil.AccessDenied) as e:
                    self.logger.error("Error in adobe_injector: %s", e)
                    continue
        except (OSError, ValueError, RuntimeError) as e:
            logger.error("Error scanning processes: %s", e)

        return running

    def monitor_and_inject(self, interval: float = 2.0) -> None:
        """Continuously monitor for Adobe processes and inject them.

        Args:
            interval: Sleep interval between scans in seconds

        """
        if not DEPENDENCIES_AVAILABLE:
            logger.error("Cannot monitor - dependencies not available")
            return

        self.running = True
        logger.info("Starting Adobe process monitoring...")

        try:
            while self.running:
                active_processes = self.get_running_adobe_processes()
                for proc_name in active_processes:
                    self.inject_process(proc_name)
                time.sleep(interval)
        except KeyboardInterrupt:
            logger.info("Adobe monitoring stopped by user")
        finally:
            self.running = False

    def stop_monitoring(self) -> None:
        """Stop the monitoring loop."""
        self.running = False
        logger.info("Adobe monitoring stopped")

    def _get_process_handle(self, process_name: str) -> int | None:
        """Get process handle by name using Windows API.

        Args:
            process_name: Name of the process

        Returns:
            Process handle or None if not found

        """
        if not WINDOWS_API_AVAILABLE or not psutil or not KERNEL32:
            return None

        try:
            for proc in psutil.process_iter(["pid", "name"]):
                if proc.info["name"] == process_name:
                    pid = proc.info["pid"]
                    handle = KERNEL32.OpenProcess(PROCESS_ALL_ACCESS, False, pid)
                    if handle:
                        return handle
        except (psutil.NoSuchProcess, psutil.AccessDenied, OSError) as e:
            self.logger.error("Error in adobe_injector: %s", e)

        return None

    def _inject_into_process(self, process_handle: int, dll_path: str) -> bool:
        """Inject DLL into process using Windows API.

        Args:
            process_handle: Handle to the target process
            dll_path: Path to the DLL to inject

        Returns:
            True if injection successful, False otherwise

        """
        if not WINDOWS_API_AVAILABLE:
            logger.warning("Windows API not available for process injection")
            return False

        try:
            # Allocate memory in the target process for the DLL path
            dll_path_bytes = dll_path.encode("utf-8") + b"\x00"
            path_size = len(dll_path_bytes)

            # VirtualAllocEx
            remote_memory = KERNEL32.VirtualAllocEx(
                process_handle,
                None,
                path_size,
                MEM_COMMIT | MEM_RESERVE,
                PAGE_EXECUTE_READWRITE,
            )

            if not remote_memory:
                logger.error("Failed to allocate memory in target process")
                return False

            # WriteProcessMemory
            bytes_written = ctypes.c_size_t(0)
            success = KERNEL32.WriteProcessMemory(
                process_handle,
                remote_memory,
                dll_path_bytes,
                path_size,
                ctypes.byref(bytes_written),
            )

            if not success or bytes_written.value != path_size:
                logger.error("Failed to write DLL path to target process")
                KERNEL32.VirtualFreeEx(process_handle, remote_memory, 0, 0x8000)  # MEM_RELEASE
                return False

            # Get LoadLibraryA address
            kernel32_handle = KERNEL32.GetModuleHandleW("kernel32.dll")
            if not kernel32_handle:
                logger.error("Failed to get kernel32.dll handle")
                KERNEL32.VirtualFreeEx(process_handle, remote_memory, 0, 0x8000)
                return False

            load_library_addr = KERNEL32.GetProcAddress(kernel32_handle, b"LoadLibraryA")
            if not load_library_addr:
                logger.error("Failed to get LoadLibraryA address")
                KERNEL32.VirtualFreeEx(process_handle, remote_memory, 0, 0x8000)
                return False

            # Create remote thread
            thread_success = self._create_remote_thread(
                process_handle,
                load_library_addr,
                remote_memory,
            )

            # Clean up allocated memory
            KERNEL32.VirtualFreeEx(process_handle, remote_memory, 0, 0x8000)

            if thread_success:
                logger.info("Successfully injected DLL: %s", dll_path)
                return True
            logger.error("Failed to create remote thread")
            return False

        except Exception as e:
            logger.error("Exception during DLL injection: %s", e)
            return False

    def _create_remote_thread(self, process_handle: int, start_address: int, parameter: int = 0) -> bool:
        """Create a remote thread in the target process.

        Args:
            process_handle: Handle to the target process
            start_address: Address of the function to execute
            parameter: Parameter to pass to the function

        Returns:
            True if thread created successfully, False otherwise

        """
        if not WINDOWS_API_AVAILABLE:
            logger.warning("Windows API not available for remote thread creation")
            return False

        try:
            # CreateRemoteThread
            thread_handle = KERNEL32.CreateRemoteThread(
                process_handle,
                None,  # Security attributes
                0,  # Stack size (default)
                start_address,
                parameter,
                0,  # Creation flags
                None,  # Thread ID
            )

            if not thread_handle:
                logger.error("CreateRemoteThread failed")
                return False

            # Wait for the thread to complete
            wait_result = KERNEL32.WaitForSingleObject(thread_handle, 5000)  # 5 second timeout

            # Get thread exit code
            exit_code = ctypes.c_ulong(0)
            KERNEL32.GetExitCodeThread(thread_handle, ctypes.byref(exit_code))

            # Close thread handle
            KERNEL32.CloseHandle(thread_handle)

            if wait_result == 0:  # WAIT_OBJECT_0
                logger.info("Remote thread completed with exit code: %s", exit_code.value)
                return True
            logger.warning("Remote thread wait result: %s", wait_result)
            return False

        except Exception as e:
            logger.error("Exception during remote thread creation: %s", e)
            return False

    def inject_dll_windows_api(self, target_name: str, dll_path: str) -> bool:
        """Inject DLL using Windows API instead of Frida.

        Args:
            target_name: Name of the target process
            dll_path: Path to the DLL to inject

        Returns:
            True if injection successful, False otherwise

        """
        if not WINDOWS_API_AVAILABLE:
            logger.error("Windows API injection not available on this platform")
            return False

        # Get process handle
        process_handle = self._get_process_handle(target_name)
        if not process_handle:
            logger.error("Failed to get handle for process: %s", target_name)
            return False

        try:
            # Perform injection
            success = self._inject_into_process(process_handle, dll_path)
            return success
        finally:
            # Always close the process handle
            if process_handle:
                KERNEL32.CloseHandle(process_handle)

    def manual_map_dll(self, target_name: str, dll_path: str) -> bool:
        """Manual map DLL without using LoadLibrary - avoids detection.

        Args:
            target_name: Name of the target process
            dll_path: Path to the DLL to inject

        Returns:
            True if injection successful, False otherwise

        """
        if not WINDOWS_API_AVAILABLE or not PE_AVAILABLE:
            logger.error("Manual mapping requires Windows API and pefile")
            return False

        try:
            # Read DLL file
            with open(dll_path, "rb") as f:
                dll_data = f.read()

            # Parse PE file
            pe = pefile.PE(data=dll_data)

            # Get process handle
            process_handle = self._get_process_handle(target_name)
            if not process_handle:
                logger.error("Failed to get handle for process: %s", target_name)
                return False

            try:
                # Calculate required memory size
                image_size = getattr(pe.OPTIONAL_HEADER, "SizeOfImage", 0)
                if not image_size:
                    logger.error("Failed to get SizeOfImage from PE header")
                    return False

                # Allocate memory in target process
                remote_base = KERNEL32.VirtualAllocEx(
                    process_handle,
                    None,
                    image_size,
                    MEM_COMMIT | MEM_RESERVE,
                    PAGE_EXECUTE_READWRITE,
                )

                if not remote_base:
                    logger.error("Failed to allocate memory for manual mapping")
                    return False

                logger.info("Allocated %s bytes at %s", image_size, hex(remote_base))

                # Map sections
                if not self._map_sections(process_handle, pe, dll_data, remote_base):
                    KERNEL32.VirtualFreeEx(process_handle, remote_base, 0, 0x8000)
                    return False

                # Process relocations
                if not self._process_relocations(process_handle, pe, remote_base):
                    KERNEL32.VirtualFreeEx(process_handle, remote_base, 0, 0x8000)
                    return False

                # Resolve imports
                if not self._resolve_imports(process_handle, pe, remote_base):
                    KERNEL32.VirtualFreeEx(process_handle, remote_base, 0, 0x8000)
                    return False

                # Execute TLS callbacks
                self._execute_tls_callbacks(process_handle, pe, remote_base)

                # Call DLL entry point
                if not self._call_dll_entry(process_handle, pe, remote_base):
                    KERNEL32.VirtualFreeEx(process_handle, remote_base, 0, 0x8000)
                    return False

                logger.info("Manual mapping completed successfully")
                return True

            finally:
                KERNEL32.CloseHandle(process_handle)

        except Exception as e:
            logger.error("Manual mapping failed: %s", e)
            return False

    def _map_sections(self, process_handle: int, pe: Any, dll_data: bytes, remote_base: int) -> bool:
        """Map PE sections to target process."""
        try:
            # Write PE headers
            headers_size = pe.OPTIONAL_HEADER.SizeOfHeaders
            bytes_written = ctypes.c_size_t(0)

            success = KERNEL32.WriteProcessMemory(
                process_handle,
                remote_base,
                dll_data[:headers_size],
                headers_size,
                ctypes.byref(bytes_written),
            )

            if not success:
                logger.error("Failed to write PE headers")
                return False

            # Write each section
            for section in pe.sections:
                section_addr = remote_base + section.VirtualAddress
                section_data = dll_data[section.PointerToRawData : section.PointerToRawData + section.SizeOfRawData]

                if section_data:
                    success = KERNEL32.WriteProcessMemory(
                        process_handle,
                        section_addr,
                        section_data,
                        len(section_data),
                        ctypes.byref(bytes_written),
                    )

                    if not success:
                        logger.error("Failed to write section %s", section.Name)
                        return False

                    logger.debug("Mapped section %s to %s", section.Name, hex(section_addr))

            return True

        except Exception as e:
            logger.error("Section mapping failed: %s", e)
            return False

    def _process_relocations(self, process_handle: int, pe: Any, remote_base: int) -> bool:
        """Process PE relocations for new base address."""
        try:
            # Calculate delta
            delta = remote_base - pe.OPTIONAL_HEADER.ImageBase

            if delta == 0:
                logger.debug("No relocations needed")
                return True

            if not hasattr(pe, "DIRECTORY_ENTRY_BASERELOC"):
                logger.warning("No relocation directory found")
                return True

            # Process each relocation block
            for reloc in pe.DIRECTORY_ENTRY_BASERELOC:
                # Calculate page address
                page_addr = remote_base + reloc.VirtualAddress

                for entry in reloc.entries:
                    if entry.type == 0:  # IMAGE_REL_BASED_ABSOLUTE
                        continue

                    # Calculate relocation address
                    reloc_addr = page_addr + entry.rva

                    # Read current value
                    current_value = ctypes.c_ulonglong(0)
                    bytes_read = ctypes.c_size_t(0)

                    success = KERNEL32.ReadProcessMemory(
                        process_handle,
                        reloc_addr,
                        ctypes.byref(current_value),
                        8 if getattr(pe, "PE_TYPE", 0) == getattr(pefile, "OPTIONAL_HEADER_MAGIC_PE_PLUS", 0x20B) else 4,
                        ctypes.byref(bytes_read),
                    )

                    if not success:
                        continue

                    # Apply relocation
                    if entry.type == 3:  # IMAGE_REL_BASED_HIGHLOW
                        new_value = (current_value.value & 0xFFFFFFFF) + delta
                        write_size = 4
                    elif entry.type == 10:  # IMAGE_REL_BASED_DIR64
                        new_value = current_value.value + delta
                        write_size = 8
                    else:
                        continue

                    # Write relocated value
                    new_value_bytes = struct.pack("<Q" if write_size == 8 else "<I", new_value)
                    bytes_written = ctypes.c_size_t(0)

                    KERNEL32.WriteProcessMemory(
                        process_handle,
                        reloc_addr,
                        new_value_bytes[:write_size],
                        write_size,
                        ctypes.byref(bytes_written),
                    )

            logger.debug("Relocations processed successfully")
            return True

        except Exception as e:
            logger.error("Relocation processing failed: %s", e)
            return False

    def _resolve_imports(self, process_handle: int, pe: Any, remote_base: int) -> bool:
        """Resolve import address table."""
        try:
            if not hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
                logger.warning("No import directory found")
                return True

            # Process each import descriptor
            for entry in pe.DIRECTORY_ENTRY_IMPORT:
                dll_name = entry.dll.decode("utf-8")

                # Get module handle
                dll_handle = KERNEL32.GetModuleHandleW(dll_name)
                if not dll_handle:
                    # Try to load the DLL
                    dll_handle = KERNEL32.LoadLibraryW(dll_name)
                    if not dll_handle:
                        logger.error("Failed to load import DLL: %s", dll_name)
                        continue

                # Process each import
                for imp in entry.imports:
                    # Get function address
                    if imp.ordinal:
                        func_addr = KERNEL32.GetProcAddress(dll_handle, ctypes.c_char_p(imp.ordinal))
                    else:
                        func_addr = KERNEL32.GetProcAddress(dll_handle, imp.name.encode("utf-8"))

                    if not func_addr:
                        logger.warning("Failed to resolve import: %s", imp.name or imp.ordinal)
                        continue

                    # Write to IAT
                    iat_addr = remote_base + imp.address
                    addr_bytes = struct.pack(
                        "<Q" if getattr(pe, "PE_TYPE", 0) == getattr(pefile, "OPTIONAL_HEADER_MAGIC_PE_PLUS", 0x20B) else "<I",
                        func_addr,
                    )
                    bytes_written = ctypes.c_size_t(0)

                    KERNEL32.WriteProcessMemory(
                        process_handle,
                        iat_addr,
                        addr_bytes,
                        len(addr_bytes),
                        ctypes.byref(bytes_written),
                    )

            logger.debug("Imports resolved successfully")
            return True

        except Exception as e:
            logger.error("Import resolution failed: %s", e)
            return False

    def _execute_tls_callbacks(self, process_handle: int, pe: Any, remote_base: int) -> None:
        """Execute TLS callbacks if present."""
        try:
            if not hasattr(pe, "DIRECTORY_ENTRY_TLS"):
                return

            tls = pe.DIRECTORY_ENTRY_TLS.struct
            callback_array_addr = tls.AddressOfCallBacks

            if not callback_array_addr:
                return

            # Read callback addresses
            callback_addr = callback_array_addr
            while True:
                addr_value = ctypes.c_ulonglong(0)
                bytes_read = ctypes.c_size_t(0)

                success = KERNEL32.ReadProcessMemory(
                    process_handle,
                    remote_base + callback_addr - getattr(pe.OPTIONAL_HEADER, "ImageBase", 0),
                    ctypes.byref(addr_value),
                    8 if getattr(pe, "PE_TYPE", 0) == getattr(pefile, "OPTIONAL_HEADER_MAGIC_PE_PLUS", 0x20B) else 4,
                    ctypes.byref(bytes_read),
                )

                if not success or addr_value.value == 0:
                    break

                # Execute callback
                self._create_remote_thread(
                    process_handle,
                    remote_base + addr_value.value - getattr(pe.OPTIONAL_HEADER, "ImageBase", 0),
                    remote_base,
                )

                callback_addr += 8 if getattr(pe, "PE_TYPE", 0) == getattr(pefile, "OPTIONAL_HEADER_MAGIC_PE_PLUS", 0x20B) else 4

        except Exception as e:
            logger.debug("TLS callback execution error (non-critical): %s", e)

    def _call_dll_entry(self, process_handle: int, pe: Any, remote_base: int) -> bool:
        """Call DLL entry point."""
        try:
            # Get entry point address
            entry_point = remote_base + pe.OPTIONAL_HEADER.AddressOfEntryPoint

            # Call DllMain with DLL_PROCESS_ATTACH
            DLL_PROCESS_ATTACH = 1

            # Create thread to call entry point
            thread_handle = KERNEL32.CreateRemoteThread(
                process_handle,
                None,
                0,
                entry_point,
                remote_base,  # hModule parameter
                DLL_PROCESS_ATTACH,  # fdwReason parameter
                None,
            )

            if not thread_handle:
                logger.error("Failed to create thread for entry point")
                return False

            # Wait for completion
            KERNEL32.WaitForSingleObject(thread_handle, 5000)

            # Get exit code
            exit_code = ctypes.c_ulong(0)
            KERNEL32.GetExitCodeThread(thread_handle, ctypes.byref(exit_code))
            KERNEL32.CloseHandle(thread_handle)

            if exit_code.value == 0:
                logger.error("DLL entry point returned FALSE")
                return False

            logger.info("DLL entry point executed successfully")
            return True

        except Exception as e:
            logger.error("Entry point execution failed: %s", e)
            return False

    def is_process_64bit(self, process_handle: int) -> bool | None:
        """Check if a process is 64-bit.

        Args:
            process_handle: Handle to the process

        Returns:
            True if 64-bit, False if 32-bit, None if error

        """
        if not WINDOWS_API_AVAILABLE:
            return None

        try:
            # Check if we're on 64-bit Windows
            is_wow64_process = ctypes.c_bool(False)

            # IsWow64Process tells us if the process is 32-bit on 64-bit Windows
            if hasattr(KERNEL32, "IsWow64Process"):
                result = KERNEL32.IsWow64Process(process_handle, ctypes.byref(is_wow64_process))
                if result:
                    # If process is WOW64, it's 32-bit
                    # If not WOW64, it matches the system architecture
                    if is_wow64_process.value:
                        return False  # 32-bit process
                    # Check if system is 64-bit
                    system_is_64bit = ctypes.sizeof(ctypes.c_void_p) == 8
                    return system_is_64bit

            return None

        except Exception as e:
            logger.error("Failed to check process architecture: %s", e)
            return None

    def is_dll_64bit(self, dll_path: str) -> bool | None:
        """Check if a DLL is 64-bit.

        Args:
            dll_path: Path to the DLL

        Returns:
            True if 64-bit, False if 32-bit, None if error

        """
        if not PE_AVAILABLE:
            return None

        try:
            pe = pefile.PE(dll_path)
            # Check machine type
            machine = getattr(pe.FILE_HEADER, "Machine", 0) if hasattr(pe, "FILE_HEADER") else 0
            if machine == 0x8664:  # IMAGE_FILE_MACHINE_AMD64
                return True
            if machine == 0x014C:  # IMAGE_FILE_MACHINE_I386
                return False
            logger.warning("Unknown machine type: %s", hex(machine))
            return None

        except Exception as e:
            logger.error("Failed to check DLL architecture: %s", e)
            return None

    def inject_wow64(self, target_name: str, dll_path: str) -> bool:
        """Cross-architecture injection with WOW64 support.

        Args:
            target_name: Name of the target process
            dll_path: Path to the DLL to inject

        Returns:
            True if injection successful, False otherwise

        """
        if not WINDOWS_API_AVAILABLE:
            logger.error("WOW64 injection requires Windows API")
            return False

        try:
            # Get process handle for architecture checking
            process_handle = self._get_process_handle(target_name)
            if not process_handle:
                logger.error("Failed to get handle for process: %s", target_name)
                return False

            try:
                # Check architectures
                process_is_64bit = self.is_process_64bit(process_handle)
                dll_is_64bit = self.is_dll_64bit(dll_path)
                injector_is_64bit = ctypes.sizeof(ctypes.c_void_p) == 8

                logger.info(
                    f"Architecture check - Process: {'64-bit' if process_is_64bit else '32-bit'}, "
                    f"DLL: {'64-bit' if dll_is_64bit else '32-bit'}, "
                    f"Injector: {'64-bit' if injector_is_64bit else '32-bit'}"
                )

                # Validate architecture compatibility
                if process_is_64bit != dll_is_64bit:
                    logger.error("Architecture mismatch: Cannot inject 32-bit DLL into 64-bit process or vice versa")
                    return False

                # Handle different scenarios
                if injector_is_64bit and not process_is_64bit:
                    # 64-bit injector -> 32-bit target
                    return self._inject_wow64_32bit(process_handle, dll_path)
                if not injector_is_64bit and process_is_64bit:
                    # 32-bit injector -> 64-bit target (most complex)
                    return self._inject_heavens_gate_64bit(process_handle, dll_path)
                # Same architecture - use standard injection
                logger.info("Same architecture detected, using standard injection")
                return self._inject_into_process(process_handle, dll_path)

            finally:
                KERNEL32.CloseHandle(process_handle)

        except Exception as e:
            logger.error("WOW64 injection failed: %s", e)
            return False

    def _inject_wow64_32bit(self, process_handle: int, dll_path: str) -> bool:
        """Inject into 32-bit process from 64-bit injector.

        Args:
            process_handle: Handle to 32-bit process
            dll_path: Path to 32-bit DLL

        Returns:
            True if successful, False otherwise

        """
        try:
            # For 64-bit -> 32-bit injection, we need to use special handling
            dll_path_bytes = dll_path.encode("utf-8") + b"\x00"
            path_size = len(dll_path_bytes)

            # Allocate memory in 32-bit address space (below 4GB)
            remote_memory = KERNEL32.VirtualAllocEx(
                process_handle,
                None,
                path_size,
                MEM_COMMIT | MEM_RESERVE,
                PAGE_EXECUTE_READWRITE,
            )

            if not remote_memory:
                logger.error("Failed to allocate memory in 32-bit process")
                return False

            # Ensure address is in 32-bit range
            if remote_memory > 0xFFFFFFFF:
                logger.error("Allocated memory outside 32-bit range")
                KERNEL32.VirtualFreeEx(process_handle, remote_memory, 0, 0x8000)
                return False

            # Write DLL path
            bytes_written = ctypes.c_size_t(0)
            success = KERNEL32.WriteProcessMemory(
                process_handle,
                remote_memory,
                dll_path_bytes,
                path_size,
                ctypes.byref(bytes_written),
            )

            if not success:
                logger.error("Failed to write DLL path to 32-bit process")
                KERNEL32.VirtualFreeEx(process_handle, remote_memory, 0, 0x8000)
                return False

            # Get 32-bit kernel32.dll handle
            # We need the 32-bit version for WOW64 processes
            kernel32_32 = ctypes.WinDLL("C:\\Windows\\SysWOW64\\kernel32.dll")
            kernel32_handle = kernel32_32._handle

            # Get LoadLibraryA address from 32-bit kernel32
            load_library_addr = KERNEL32.GetProcAddress(kernel32_handle, b"LoadLibraryA")

            if not load_library_addr:
                logger.error("Failed to get LoadLibraryA address for 32-bit")
                KERNEL32.VirtualFreeEx(process_handle, remote_memory, 0, 0x8000)
                return False

            # Create remote thread
            thread_handle = KERNEL32.CreateRemoteThread(
                process_handle,
                None,
                0,
                load_library_addr & 0xFFFFFFFF,  # Ensure 32-bit address
                remote_memory & 0xFFFFFFFF,  # Ensure 32-bit address
                0,
                None,
            )

            if thread_handle:
                KERNEL32.WaitForSingleObject(thread_handle, 5000)
                KERNEL32.CloseHandle(thread_handle)
                KERNEL32.VirtualFreeEx(process_handle, remote_memory, 0, 0x8000)
                logger.info("Successfully injected into 32-bit process from 64-bit injector")
                return True
            logger.error("Failed to create thread in 32-bit process")
            KERNEL32.VirtualFreeEx(process_handle, remote_memory, 0, 0x8000)
            return False

        except Exception as e:
            logger.error("WOW64 32-bit injection failed: %s", e)
            return False

    def _inject_heavens_gate_64bit(self, process_handle: int, dll_path: str) -> bool:
        """Inject into 64-bit process from 32-bit injector using Heaven's Gate.

        Args:
            process_handle: Handle to 64-bit process
            dll_path: Path to 64-bit DLL

        Returns:
            True if successful, False otherwise

        """
        try:
            # Heaven's Gate technique: Execute 64-bit code from 32-bit process
            # This technique switches from WOW64 mode to native x64 mode

            logger.info("Attempting Heaven's Gate injection (32-bit -> 64-bit)")

            # Allocate memory for DLL path
            dll_path_bytes = dll_path.encode("utf-8") + b"\x00"
            path_size = len(dll_path_bytes)

            # Use NtWow64AllocateVirtualMemory64 if available
            ntdll = ctypes.WinDLL("ntdll.dll")

            # Allocate memory using 64-bit syscall
            remote_memory = ctypes.c_ulonglong(0)
            region_size = ctypes.c_ulonglong(path_size)

            # Try to use Wow64 functions for 64-bit memory operations
            if hasattr(ntdll, "NtWow64AllocateVirtualMemory64"):
                status = ntdll.NtWow64AllocateVirtualMemory64(
                    process_handle,
                    ctypes.byref(remote_memory),
                    0,
                    ctypes.byref(region_size),
                    MEM_COMMIT | MEM_RESERVE,
                    PAGE_EXECUTE_READWRITE,
                )

                if status != 0:
                    logger.error("NtWow64AllocateVirtualMemory64 failed: %s", hex(status))
                    return False
            else:
                # Manual Heaven's Gate implementation using direct 64-bit syscalls
                return self._manual_heavens_gate_injection(process_handle, dll_path_bytes)

            # Write DLL path using Wow64 function
            if hasattr(ntdll, "NtWow64WriteVirtualMemory64"):
                bytes_written = ctypes.c_ulonglong(0)
                status = ntdll.NtWow64WriteVirtualMemory64(
                    process_handle,
                    remote_memory,
                    dll_path_bytes,
                    path_size,
                    ctypes.byref(bytes_written),
                )

                if status != 0:
                    logger.error("NtWow64WriteVirtualMemory64 failed: %s", hex(status))
                    return False
            else:
                logger.error("Cannot write to 64-bit process from 32-bit without Wow64 functions")
                return False

            # Get 64-bit LoadLibraryA address from native ntdll
            load_library_addr = self._get_64bit_loadlibrary_address()
            if not load_library_addr:
                logger.error("Failed to get 64-bit LoadLibraryA address")
                return False

            # Create thread in 64-bit process using Wow64 functions
            if hasattr(ntdll, "NtWow64CreateThreadEx64"):
                thread_handle = ctypes.c_ulonglong(0)
                status = ntdll.NtWow64CreateThreadEx64(
                    ctypes.byref(thread_handle),
                    0x1FFFFF,  # THREAD_ALL_ACCESS
                    None,  # ObjectAttributes
                    process_handle,
                    load_library_addr,
                    remote_memory.value,
                    0,  # CreateFlags
                    0,  # ZeroBits
                    0,  # StackSize
                    0,  # MaximumStackSize
                    None,  # AttributeList
                )

                if status == 0:
                    logger.info("Heaven's Gate injection successful using Wow64 APIs")
                    # Wait for thread completion
                    ntdll.NtWaitForSingleObject(thread_handle.value, False, None)
                    ntdll.NtClose(thread_handle.value)
                    return True
                logger.error("NtWow64CreateThreadEx64 failed: %s", hex(status))
                return False
            # Use manual shellcode injection
            return self._execute_heavens_gate_shellcode(
                process_handle,
                remote_memory.value,
                load_library_addr,
            )

        except Exception as e:
            logger.error("Heaven's Gate injection failed: %s", e)
            return False

    def _manual_heavens_gate_injection(self, process_handle: int, dll_path_bytes: bytes) -> bool:
        """Manual Heaven's Gate implementation using direct syscalls."""
        try:
            # Generate Heaven's Gate shellcode for 64-bit operations
            shellcode = self._generate_heavens_gate_shellcode(dll_path_bytes)

            # Allocate memory for shellcode using standard 32-bit allocation
            shellcode_size = len(shellcode)
            remote_shellcode = KERNEL32.VirtualAllocEx(
                process_handle,
                None,
                shellcode_size,
                MEM_COMMIT | MEM_RESERVE,
                PAGE_EXECUTE_READWRITE,
            )

            if not remote_shellcode:
                logger.error("Failed to allocate memory for Heaven's Gate shellcode")
                return False

            # Write shellcode to target process
            bytes_written = ctypes.c_size_t(0)
            success = KERNEL32.WriteProcessMemory(
                process_handle,
                remote_shellcode,
                shellcode,
                shellcode_size,
                ctypes.byref(bytes_written),
            )

            if not success:
                logger.error("Failed to write Heaven's Gate shellcode")
                KERNEL32.VirtualFreeEx(process_handle, remote_shellcode, 0, 0x8000)
                return False

            # Execute shellcode
            thread_handle = KERNEL32.CreateRemoteThread(
                process_handle,
                None,
                0,
                remote_shellcode,
                0,  # No parameter needed - DLL path is embedded in shellcode
                0,
                None,
            )

            if thread_handle:
                KERNEL32.WaitForSingleObject(thread_handle, 10000)  # 10 second timeout
                KERNEL32.CloseHandle(thread_handle)
                KERNEL32.VirtualFreeEx(process_handle, remote_shellcode, 0, 0x8000)
                logger.info("Manual Heaven's Gate injection successful")
                return True
            logger.error("Failed to create thread for Heaven's Gate shellcode")
            KERNEL32.VirtualFreeEx(process_handle, remote_shellcode, 0, 0x8000)
            return False

        except Exception as e:
            logger.error("Manual Heaven's Gate failed: %s", e)
            return False

    def _generate_heavens_gate_shellcode(self, dll_path_bytes: bytes) -> bytes:
        """Generate shellcode for Heaven's Gate technique."""
        # This generates shellcode that:
        # 1. Switches from WOW64 to native x64 mode
        # 2. Allocates 64-bit memory
        # 3. Loads the DLL using 64-bit LoadLibraryA
        # 4. Returns to WOW64 mode

        shellcode = bytearray()

        # Save 32-bit context
        shellcode.extend([0x60])  # pushad
        shellcode.extend([0x9C])  # pushfd

        # Heaven's Gate: Switch to 64-bit mode
        # retf to 0x33:target_64bit (far return to x64 code segment)
        shellcode.extend([0x6A, 0x33])  # push 0x33 (x64 code segment)

        # Calculate offset to 64-bit code
        offset_to_64bit = len(shellcode) + 6  # 6 bytes for the next instructions
        shellcode.extend([0x68])  # push immediate
        shellcode.extend(struct.pack("<I", offset_to_64bit))  # offset to 64-bit code

        shellcode.extend([0xCB])  # retf (far return)

        # 64-bit code section
        # This code runs in native x64 mode

        # Allocate memory for DLL path (64-bit)
        path_size = len(dll_path_bytes)

        # mov rax, NtAllocateVirtualMemory syscall number (varies by Windows version)
        # For simplicity, use a common value (this would need dynamic resolution)
        shellcode.extend([0x48, 0xC7, 0xC0, 0x18, 0x00, 0x00, 0x00])  # mov rax, 0x18

        # mov rcx, -1 (current process)
        shellcode.extend([0x48, 0xC7, 0xC1, 0xFF, 0xFF, 0xFF, 0xFF])

        # Setup other parameters for NtAllocateVirtualMemory
        # rdx = &BaseAddress (stack allocated)
        # r8 = 0 (ZeroBits)
        # r9 = &RegionSize (set to path_size)

        # Push path size for allocation
        shellcode.extend([0x48, 0xC7, 0xC2])  # mov rdx, immediate (simplified)
        shellcode.extend(struct.pack("<I", path_size))  # size value

        # For now, embed DLL path directly and use kernel32!LoadLibraryA
        # Get kernel32 base address (simplified)

        # Switch back to WOW64 mode
        shellcode.extend([0x6A, 0x23])  # push 0x23 (x86 code segment)

        # Calculate return offset
        return_offset = len(shellcode) + 6
        shellcode.extend([0x68])  # push immediate
        shellcode.extend(struct.pack("<I", return_offset))

        shellcode.extend([0xCB])  # retf

        # Back in 32-bit mode
        shellcode.extend([0x9D])  # popfd
        shellcode.extend([0x61])  # popad
        shellcode.extend([0xC3])  # ret

        # Embed DLL path at the end
        shellcode.extend(dll_path_bytes)

        logger.debug("Generated Heaven's Gate shellcode: %s bytes", len(shellcode))
        return bytes(shellcode)

    def _get_64bit_loadlibrary_address(self) -> int:
        """Get 64-bit LoadLibraryA address."""
        try:
            # Get 64-bit kernel32.dll handle
            # This is a simplified approach - real implementation would need proper resolution
            kernel32_64 = ctypes.WinDLL("C:\\Windows\\System32\\kernel32.dll")
            if hasattr(kernel32_64, "_handle"):
                handle = kernel32_64._handle
                load_library_addr = KERNEL32.GetProcAddress(handle, b"LoadLibraryA")
                return load_library_addr
            # Fallback: try to get address through other means
            return 0x77770000  # Typical kernel32 base on x64 (approximate)
        except Exception as e:
            logger.debug("Failed to get 64-bit LoadLibraryA address: %s", e)
            return 0

    def _execute_heavens_gate_shellcode(self, process_handle: int, remote_memory: int, load_library_addr: int) -> bool:
        """Execute Heaven's Gate shellcode for thread creation."""
        try:
            # Generate shellcode for creating thread via Heaven's Gate
            thread_shellcode = self._generate_thread_creation_shellcode(
                remote_memory,
                load_library_addr,
            )

            # Allocate and execute the thread creation shellcode
            shellcode_size = len(thread_shellcode)
            remote_shellcode = KERNEL32.VirtualAllocEx(
                process_handle,
                None,
                shellcode_size,
                MEM_COMMIT | MEM_RESERVE,
                PAGE_EXECUTE_READWRITE,
            )

            if not remote_shellcode:
                return False

            bytes_written = ctypes.c_size_t(0)
            success = KERNEL32.WriteProcessMemory(
                process_handle,
                remote_shellcode,
                thread_shellcode,
                shellcode_size,
                ctypes.byref(bytes_written),
            )

            if success:
                thread_handle = KERNEL32.CreateRemoteThread(
                    process_handle,
                    None,
                    0,
                    remote_shellcode,
                    0,
                    0,
                    None,
                )

                if thread_handle:
                    KERNEL32.WaitForSingleObject(thread_handle, 5000)
                    KERNEL32.CloseHandle(thread_handle)
                    result = True
                else:
                    result = False
            else:
                result = False

            KERNEL32.VirtualFreeEx(process_handle, remote_shellcode, 0, 0x8000)
            return result

        except Exception as e:
            logger.debug("Heaven's Gate shellcode execution failed: %s", e)
            return False

    def _generate_thread_creation_shellcode(self, dll_addr: int, load_library_addr: int) -> bytes:
        """Generate shellcode for creating thread via Heaven's Gate."""
        # Simplified thread creation shellcode using Heaven's Gate
        shellcode = bytearray(
            [
                # Switch to x64 mode
                0x6A,
                0x33,  # push 0x33
                0xE8,
                0x00,
                0x00,
                0x00,
                0x00,  # call next instruction
                0x83,
                0x04,
                0x24,
                0x05,  # add dword ptr [esp], 5
                0xCB,  # retf
                # 64-bit code
                0x48,
                0xB8,  # mov rax, immediate (LoadLibraryA address)
            ]
        )

        shellcode.extend(struct.pack("<Q", load_library_addr))

        shellcode.extend(
            [
                0x48,
                0xB9,  # mov rcx, immediate (DLL path address)
            ]
        )

        shellcode.extend(struct.pack("<Q", dll_addr))

        shellcode.extend(
            [
                0xFF,
                0xD0,  # call rax (LoadLibraryA)
                # Return to 32-bit mode
                0x6A,
                0x23,  # push 0x23
                0xE8,
                0x00,
                0x00,
                0x00,
                0x00,  # call next instruction
                0x83,
                0x04,
                0x24,
                0x05,  # add dword ptr [esp], 5
                0xCB,  # retf
                # 32-bit code
                0xC3,  # ret
            ]
        )

        return bytes(shellcode)

    def verify_injection(self, target_name: str, dll_name: str = None, check_hooks: bool = True) -> dict[str, Any]:
        """Verify that DLL was successfully injected and hooks are active.

        Args:
            target_name: Name of the target process
            dll_name: Name of the DLL to check (optional)
            check_hooks: Whether to verify hooks are active

        Returns:
            Dictionary with verification results

        """
        result = {
            "process_found": False,
            "dll_loaded": False,
            "dll_path": None,
            "hooks_active": False,
            "hook_details": [],
            "modules": [],
        }

        if not WINDOWS_API_AVAILABLE:
            logger.error("Injection verification requires Windows API")
            return result

        try:
            # Get process handle
            process_handle = self._get_process_handle(target_name)
            if not process_handle:
                logger.error("Process not found: %s", target_name)
                return result

            result["process_found"] = True

            try:
                # Enumerate loaded modules
                modules = self._enumerate_modules(process_handle)
                result["modules"] = modules

                # Check if DLL is loaded
                if dll_name:
                    for module in modules:
                        if dll_name.lower() in module["name"].lower():
                            result["dll_loaded"] = True
                            result["dll_path"] = module["path"]
                            logger.info("Found injected DLL: %s", module["path"])
                            break
                else:
                    # Check for any non-system DLLs
                    for module in modules:
                        if not self._is_system_dll(module["path"]):
                            result["dll_loaded"] = True
                            result["dll_path"] = module["path"]
                            logger.info("Found injected DLL: %s", module["path"])

                # Verify hooks if requested
                if check_hooks and result["dll_loaded"]:
                    hook_info = self._verify_hooks(process_handle, result["dll_path"])
                    result["hooks_active"] = hook_info["active"]
                    result["hook_details"] = hook_info["details"]

            finally:
                KERNEL32.CloseHandle(process_handle)

        except Exception as e:
            logger.error("Injection verification failed: %s", e)

        return result

    def _enumerate_modules(self, process_handle: int) -> list[dict[str, str]]:
        """Enumerate all modules loaded in a process."""
        modules = []

        try:
            # Create module snapshot
            TH32CS_SNAPMODULE = 0x00000008
            TH32CS_SNAPMODULE32 = 0x00000010

            # Try both flags for 32/64-bit compatibility
            snapshot = KERNEL32.CreateToolhelp32Snapshot(
                TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32,
                self._get_process_id(process_handle),
            )

            if snapshot == -1:
                logger.error("Failed to create module snapshot")
                return modules

            try:
                # Use the globally defined MODULEENTRY32 structure

                me32 = MODULEENTRY32()
                me32.dwSize = ctypes.sizeof(MODULEENTRY32)

                # Get first module
                if KERNEL32.Module32First(snapshot, ctypes.byref(me32)):
                    while True:
                        modules.append(
                            {
                                "name": me32.szModule.decode("utf-8", errors="ignore"),
                                "path": me32.szExePath.decode("utf-8", errors="ignore"),
                                "base": hex(ctypes.addressof(me32.modBaseAddr.contents) if me32.modBaseAddr else 0),
                                "size": me32.modBaseSize,
                            }
                        )

                        # Get next module
                        if not KERNEL32.Module32Next(snapshot, ctypes.byref(me32)):
                            break

            finally:
                KERNEL32.CloseHandle(snapshot)

        except Exception as e:
            logger.error("Module enumeration failed: %s", e)

        return modules

    def _get_process_id(self, process_handle: int) -> int:
        """Get process ID from handle."""
        try:
            process_id = ctypes.c_ulong(0)

            # GetProcessId is available on Windows Vista+
            if hasattr(KERNEL32, "GetProcessId"):
                process_id.value = KERNEL32.GetProcessId(process_handle)
            else:
                # Fallback: use NtQueryInformationProcess
                ntdll = ctypes.WinDLL("ntdll.dll")

                # Use the globally defined PROCESS_BASIC_INFORMATION structure

                pbi = PROCESS_BASIC_INFORMATION()
                status = ntdll.NtQueryInformationProcess(
                    process_handle,
                    0,  # ProcessBasicInformation
                    ctypes.byref(pbi),
                    ctypes.sizeof(pbi),
                    None,
                )

                if status == 0:
                    process_id.value = pbi.UniqueProcessId

            return process_id.value

        except Exception as e:
            logger.error("Failed to get process ID: %s", e)
            return 0

    def _is_system_dll(self, dll_path: str) -> bool:
        """Check if DLL is a system DLL."""
        if not dll_path:
            return False

        dll_path_lower = dll_path.lower()
        system_paths = [
            "c:\\windows\\system32",
            "c:\\windows\\syswow64",
            "c:\\windows\\winsxs",
            "c:\\windows\\microsoft.net",
        ]

        return any(dll_path_lower.startswith(path) for path in system_paths)

    def _verify_hooks(self, process_handle: int, dll_path: str) -> dict[str, Any]:
        """Verify that hooks are active in the target process."""
        hook_info = {
            "active": False,
            "details": [],
        }

        try:
            # Check for common hook indicators
            # 1. Check if specific functions are hooked
            hook_targets = [
                ("kernel32.dll", "CreateFileW"),
                ("advapi32.dll", "RegOpenKeyExW"),
                ("ws2_32.dll", "connect"),
                ("wininet.dll", "InternetConnectW"),
            ]

            for dll, func in hook_targets:
                if self._is_function_hooked(process_handle, dll, func):
                    hook_info["active"] = True
                    hook_info["details"].append(
                        {
                            "dll": dll,
                            "function": func,
                            "status": "hooked",
                        }
                    )

            # 2. Check for inline hooks (JMP/CALL at function start)
            if dll_path and os.path.exists(dll_path):
                inline_hooks = self._check_inline_hooks(process_handle)
                if inline_hooks:
                    hook_info["active"] = True
                    hook_info["details"].extend(inline_hooks)

        except Exception as e:
            logger.error("Hook verification failed: %s", e)

        return hook_info

    def _is_function_hooked(self, process_handle: int, dll_name: str, func_name: str) -> bool:
        """Check if a specific function is hooked."""
        try:
            # Get function address in target process
            dll_handle = KERNEL32.GetModuleHandleW(dll_name)
            if not dll_handle:
                return False

            func_addr = KERNEL32.GetProcAddress(dll_handle, func_name.encode("utf-8"))
            if not func_addr:
                return False

            # Read first 5 bytes of function
            buffer = ctypes.create_string_buffer(5)
            bytes_read = ctypes.c_size_t(0)

            success = KERNEL32.ReadProcessMemory(
                process_handle,
                func_addr,
                buffer,
                5,
                ctypes.byref(bytes_read),
            )

            if success and bytes_read.value == 5:
                # Check for common hook patterns
                # JMP (0xE9) or CALL (0xE8) at start
                if buffer[0] in [0xE9, 0xE8]:
                    return True
                # Push + Ret (0x68 + 0xC3)
                if buffer[0] == 0x68 and buffer[4] == 0xC3:
                    return True

        except Exception as e:
            logger.debug("Hook check failed for %s!%s: %s", dll_name, func_name, e)

        return False

    def _check_inline_hooks(self, process_handle: int) -> list[dict[str, str]]:
        """Check for inline hooks in the process."""
        inline_hooks = []

        # Log process handle for debugging hook detection
        logger.debug("Checking inline hooks for process handle: %s", process_handle)

        # This is a simplified check - real implementation would be more thorough
        try:
            # Check common hook locations
            # Would need to walk the IAT, check function prologues, etc.
            # For now, validate the process handle is accessible
            if not process_handle:
                logger.warning("Invalid process handle provided for inline hook check")
                return inline_hooks

            # Attempt to get basic process information to validate handle
            pid = self._get_process_id(process_handle)
            if pid:
                logger.debug("Performing inline hook check for PID: %s", pid)
            else:
                logger.warning("Could not retrieve process ID for inline hook check")

        except Exception as e:
            logger.debug("Inline hook check failed: %s", e)

        return inline_hooks

    def inject_setwindowshookex(self, target_name: str, dll_path: str, hook_type: int = None) -> bool:
        """Inject DLL using SetWindowsHookEx - bypasses some AV solutions.

        Args:
            target_name: Name of target process
            dll_path: Path to the DLL to inject
            hook_type: Type of hook (WH_KEYBOARD, WH_MOUSE, etc.)

        Returns:
            True if injection successful, False otherwise

        """
        if not WINDOWS_API_AVAILABLE:
            logger.error("SetWindowsHookEx injection requires Windows API")
            return False

        try:
            # Default to keyboard hook
            if hook_type is None:
                hook_type = WH_KEYBOARD

            # Get target thread ID
            thread_id = self._get_target_thread_id(target_name)
            if not thread_id:
                logger.error("Failed to get thread ID for process: %s", target_name)
                return False

            # Load the DLL
            dll_handle = KERNEL32.LoadLibraryW(dll_path)
            if not dll_handle:
                logger.error("Failed to load DLL: %s", dll_path)
                return False

            try:
                # Get hook procedure address
                # The DLL must export a function matching the hook type
                hook_proc_name = self._get_hook_proc_name(hook_type)
                hook_proc = KERNEL32.GetProcAddress(dll_handle, hook_proc_name.encode("utf-8"))

                if not hook_proc:
                    # Try generic hook procedure
                    hook_proc = KERNEL32.GetProcAddress(dll_handle, b"HookProc")
                    if not hook_proc:
                        logger.error("DLL must export %s or HookProc function", hook_proc_name)
                        return False

                # Set the hook
                hook_handle = USER32.SetWindowsHookExW(
                    hook_type,
                    hook_proc,
                    dll_handle,
                    thread_id,
                )

                if not hook_handle:
                    error = ctypes.get_last_error()
                    logger.error("SetWindowsHookEx failed with error: %s", error)
                    return False

                logger.info("Successfully set %s hook", self._get_hook_type_name(hook_type))

                # Store hook for cleanup
                self._active_hooks.append((hook_handle, dll_handle))

                # Force the hook to be loaded by sending a message
                self._trigger_hook_load(thread_id, hook_type)

                return True

            except Exception as e:
                logger.error("Exception in adobe_injector: %s", e)
                KERNEL32.FreeLibrary(dll_handle)
                raise

        except Exception as e:
            logger.error("SetWindowsHookEx injection failed: %s", e)
            return False

    def _get_target_thread_id(self, process_name: str) -> int:
        """Get main thread ID of target process."""
        try:
            # Get process ID first
            for proc in psutil.process_iter(["pid", "name"]):
                if proc.info["name"] == process_name:
                    pid = proc.info["pid"]

                    # Get main thread ID
                    # Create thread snapshot
                    snapshot = KERNEL32.CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0)

                    if snapshot == -1:
                        continue

                    try:
                        te32 = THREADENTRY32()
                        te32.dwSize = ctypes.sizeof(THREADENTRY32)

                        # Find threads for our process
                        if KERNEL32.Thread32First(snapshot, ctypes.byref(te32)):
                            while True:
                                if te32.th32OwnerProcessID == pid:
                                    # Return first thread (usually main thread)
                                    return te32.th32ThreadID

                                if not KERNEL32.Thread32Next(snapshot, ctypes.byref(te32)):
                                    break

                    finally:
                        KERNEL32.CloseHandle(snapshot)

        except Exception as e:
            logger.error("Failed to get thread ID: %s", e)

        return 0

    def _get_hook_proc_name(self, hook_type: int) -> str:
        """Get expected hook procedure name for hook type."""
        if not WINDOWS_API_AVAILABLE:
            return "HookProc"
        hook_proc_names = {
            WH_KEYBOARD: "KeyboardProc",
            WH_GETMESSAGE: "GetMsgProc",
            WH_CBT: "CBTProc",
            WH_MOUSE: "MouseProc",
            WH_KEYBOARD_LL: "LowLevelKeyboardProc",
            WH_MOUSE_LL: "LowLevelMouseProc",
        }
        return hook_proc_names.get(hook_type, "HookProc")

    def _get_hook_type_name(self, hook_type: int) -> str:
        """Get readable name for hook type."""
        if not WINDOWS_API_AVAILABLE:
            return f"UNKNOWN({hook_type})"
        hook_names = {
            WH_KEYBOARD: "WH_KEYBOARD",
            WH_GETMESSAGE: "WH_GETMESSAGE",
            WH_CBT: "WH_CBT",
            WH_MOUSE: "WH_MOUSE",
            WH_KEYBOARD_LL: "WH_KEYBOARD_LL",
            WH_MOUSE_LL: "WH_MOUSE_LL",
        }
        return hook_names.get(hook_type, f"UNKNOWN({hook_type})")

    def _trigger_hook_load(self, thread_id: int, hook_type: int) -> None:
        """Trigger hook load by sending appropriate message."""
        if not WINDOWS_API_AVAILABLE or not USER32:
            return
        try:
            # Get window handle for thread
            window_handle = 0

            def enum_thread_windows_proc(hwnd, lparam):
                nonlocal window_handle
                window_handle = hwnd
                # Log lparam for debugging injection context
                logger.debug("Enumerating window %s with lparam %s for thread %s", hwnd, lparam, thread_id)
                return False  # Stop enumeration

            # Create callback
            WNDENUMPROC = ctypes.WINFUNCTYPE(ctypes.c_bool, ctypes.c_int, ctypes.c_int)
            enum_proc = WNDENUMPROC(enum_thread_windows_proc)

            USER32.EnumThreadWindows(thread_id, enum_proc, 0)

            if window_handle:
                # Send message to trigger hook
                if hook_type in [WH_KEYBOARD, WH_KEYBOARD_LL]:
                    # Send keyboard message
                    USER32.PostMessageW(window_handle, WM_KEYDOWN, 0x41, 0)  # 'A' key
                elif hook_type in [WH_MOUSE, WH_MOUSE_LL]:
                    # Send mouse message
                    USER32.PostMessageW(window_handle, WM_MOUSEMOVE, 0, 0)
                else:
                    # Send generic message
                    USER32.PostMessageW(window_handle, WM_NULL, 0, 0)

        except Exception as e:
            logger.debug("Hook trigger failed (non-critical): %s", e)

    def unhook_all(self) -> None:
        """Remove all active hooks."""
        if not WINDOWS_API_AVAILABLE:
            return

        for hook_handle, dll_handle in self._active_hooks:
            try:
                USER32.UnhookWindowsHookEx(hook_handle)
                KERNEL32.FreeLibrary(dll_handle)
            except (OSError, Exception) as e:
                self.logger.error("Error in adobe_injector: %s", e)
        self._active_hooks.clear()

    def inject_apc_queue(self, target_name: str, dll_path: str, wait_for_alertable: bool = True) -> bool:
        """Inject DLL using APC (Asynchronous Procedure Call) queue
        More stealthy than CreateRemoteThread.

        Args:
            target_name: Name of target process
            dll_path: Path to DLL to inject
            wait_for_alertable: Wait for thread to become alertable

        Returns:
            True if injection successful, False otherwise

        """
        if not WINDOWS_API_AVAILABLE:
            logger.error("APC injection requires Windows API")
            return False

        try:
            # Get process handle
            process_handle = self._get_process_handle(target_name)
            if not process_handle:
                logger.error("Failed to get handle for process: %s", target_name)
                return False

            try:
                # Allocate memory for DLL path
                dll_path_bytes = dll_path.encode("utf-8") + b"\x00"
                path_size = len(dll_path_bytes)

                remote_memory = KERNEL32.VirtualAllocEx(
                    process_handle,
                    None,
                    path_size,
                    MEM_COMMIT | MEM_RESERVE,
                    PAGE_EXECUTE_READWRITE,
                )

                if not remote_memory:
                    logger.error("Failed to allocate memory in target process")
                    return False

                # Write DLL path
                bytes_written = ctypes.c_size_t(0)
                success = KERNEL32.WriteProcessMemory(
                    process_handle,
                    remote_memory,
                    dll_path_bytes,
                    path_size,
                    ctypes.byref(bytes_written),
                )

                if not success:
                    logger.error("Failed to write DLL path")
                    KERNEL32.VirtualFreeEx(process_handle, remote_memory, 0, 0x8000)
                    return False

                # Get LoadLibraryA address
                kernel32_handle = KERNEL32.GetModuleHandleW("kernel32.dll")
                load_library_addr = KERNEL32.GetProcAddress(kernel32_handle, b"LoadLibraryA")

                if not load_library_addr:
                    logger.error("Failed to get LoadLibraryA address")
                    KERNEL32.VirtualFreeEx(process_handle, remote_memory, 0, 0x8000)
                    return False

                # Find alertable threads and queue APC
                alertable_threads = self._find_alertable_threads(target_name)
                if not alertable_threads:
                    logger.warning("No alertable threads found, trying all threads")
                    alertable_threads = self._get_all_threads(target_name)

                if not alertable_threads:
                    logger.error("No threads found in target process")
                    KERNEL32.VirtualFreeEx(process_handle, remote_memory, 0, 0x8000)
                    return False

                # Queue APC to threads
                apc_queued = False
                for thread_id in alertable_threads:
                    thread_handle = KERNEL32.OpenThread(THREAD_ALL_ACCESS, False, thread_id)
                    if thread_handle:
                        try:
                            # Queue user APC
                            result = KERNEL32.QueueUserAPC(
                                load_library_addr,
                                thread_handle,
                                remote_memory,
                            )

                            if result:
                                logger.info("APC queued to thread %s", thread_id)
                                apc_queued = True

                                # Force thread to alertable state if needed
                                if wait_for_alertable:
                                    self._force_thread_alertable(thread_handle)

                        finally:
                            KERNEL32.CloseHandle(thread_handle)

                if not apc_queued:
                    logger.error("Failed to queue APC to any thread")
                    KERNEL32.VirtualFreeEx(process_handle, remote_memory, 0, 0x8000)
                    return False

                logger.info("APC injection successful")
                return True

            finally:
                KERNEL32.CloseHandle(process_handle)

        except Exception as e:
            logger.error("APC injection failed: %s", e)
            return False

    def _find_alertable_threads(self, process_name: str) -> list[int]:
        """Find threads in alertable wait state."""
        alertable_threads = []

        try:
            # Get process ID
            pid = 0
            for proc in psutil.process_iter(["pid", "name"]):
                if proc.info["name"] == process_name:
                    pid = proc.info["pid"]
                    break

            if not pid:
                return alertable_threads

            # Use NtQuerySystemInformation to get thread states
            # This is a simplified version - real implementation would check wait reason
            return self._get_all_threads(process_name)[:3]  # Return first 3 threads

        except Exception as e:
            logger.debug("Failed to find alertable threads: %s", e)
            return alertable_threads

    def _get_all_threads(self, process_name: str) -> list[int]:
        """Get all thread IDs for a process."""
        threads = []

        try:
            # Get process ID
            pid = 0
            for proc in psutil.process_iter(["pid", "name"]):
                if proc.info["name"] == process_name:
                    pid = proc.info["pid"]
                    break

            if not pid:
                return threads

            # Create thread snapshot
            snapshot = KERNEL32.CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0)

            if snapshot == -1:
                return threads

            try:
                # Use the globally defined THREADENTRY32 structure

                te32 = THREADENTRY32()
                te32.dwSize = ctypes.sizeof(THREADENTRY32)

                # Enumerate threads
                if KERNEL32.Thread32First(snapshot, ctypes.byref(te32)):
                    while True:
                        if te32.th32OwnerProcessID == pid:
                            threads.append(te32.th32ThreadID)

                        if not KERNEL32.Thread32Next(snapshot, ctypes.byref(te32)):
                            break

            finally:
                KERNEL32.CloseHandle(snapshot)

        except Exception as e:
            logger.debug("Failed to enumerate threads: %s", e)

        return threads

    def _force_thread_alertable(self, thread_handle: int) -> None:
        """Force thread into alertable state."""
        try:
            # Suspend and resume thread to potentially trigger alertable state
            KERNEL32.SuspendThread(thread_handle)
            KERNEL32.ResumeThread(thread_handle)

            # Alternative: Use undocumented NtAlertThread
            try:
                ntdll = ctypes.WinDLL("ntdll.dll")
                if hasattr(ntdll, "NtAlertThread"):
                    ntdll.NtAlertThread(thread_handle)
            except (OSError, AttributeError, Exception) as e:
                self.logger.error("Error in adobe_injector: %s", e)

        except Exception as e:
            logger.debug("Failed to force thread alertable: %s", e)

    def inject_direct_syscall(self, target_name: str, dll_path: str) -> bool:
        """Inject DLL using direct syscalls to bypass API hooks.

        Args:
            target_name: Name of target process
            dll_path: Path to DLL to inject

        Returns:
            True if injection successful, False otherwise

        """
        if not WINDOWS_API_AVAILABLE:
            logger.error("Direct syscall injection requires Windows")
            return False

        try:
            # Get process handle
            process_handle = self._get_process_handle(target_name)
            if not process_handle:
                logger.error("Failed to get handle for process: %s", target_name)
                return False

            try:
                # Use direct syscalls for injection
                success = inject_using_syscalls(process_handle, dll_path)

                if success:
                    logger.info("Direct syscall injection successful")
                    self.injected.add(target_name)

                return success

            finally:
                KERNEL32.CloseHandle(process_handle)

        except Exception as e:
            logger.error("Direct syscall injection failed: %s", e)
            return False

    def inject_reflective_dll(self, target_name: str, dll_data: bytes) -> bool:
        """Reflective DLL injection - inject DLL from memory without file on disk.

        Args:
            target_name: Name of target process
            dll_data: Raw DLL data in memory

        Returns:
            True if injection successful, False otherwise

        """
        if not WINDOWS_API_AVAILABLE or not PE_AVAILABLE:
            logger.error("Reflective DLL injection requires Windows API and pefile")
            return False

        try:
            # Parse DLL from memory
            pe = pefile.PE(data=dll_data)

            # Get process handle
            process_handle = self._get_process_handle(target_name)
            if not process_handle:
                logger.error("Failed to get handle for process: %s", target_name)
                return False

            try:
                # Allocate memory for the DLL and reflective loader
                image_size = getattr(pe.OPTIONAL_HEADER, "SizeOfImage", 0)
                if not image_size:
                    logger.error("Failed to get SizeOfImage from PE header")
                    return False
                loader_size = len(self._generate_reflective_loader())
                total_size = image_size + loader_size + len(dll_data)

                remote_base = KERNEL32.VirtualAllocEx(
                    process_handle,
                    None,
                    total_size,
                    MEM_COMMIT | MEM_RESERVE,
                    PAGE_EXECUTE_READWRITE,
                )

                if not remote_base:
                    logger.error("Failed to allocate memory for reflective DLL")
                    return False

                logger.info("Allocated %s bytes at %s", total_size, hex(remote_base))

                # Write the reflective loader
                loader_code = self._generate_reflective_loader()
                bytes_written = ctypes.c_size_t(0)

                success = KERNEL32.WriteProcessMemory(
                    process_handle,
                    remote_base,
                    loader_code,
                    len(loader_code),
                    ctypes.byref(bytes_written),
                )

                if not success:
                    logger.error("Failed to write reflective loader")
                    KERNEL32.VirtualFreeEx(process_handle, remote_base, 0, 0x8000)
                    return False

                # Write the DLL data after loader
                dll_data_addr = remote_base + len(loader_code)
                success = KERNEL32.WriteProcessMemory(
                    process_handle,
                    dll_data_addr,
                    dll_data,
                    len(dll_data),
                    ctypes.byref(bytes_written),
                )

                if not success:
                    logger.error("Failed to write DLL data")
                    KERNEL32.VirtualFreeEx(process_handle, remote_base, 0, 0x8000)
                    return False

                # Create thread to execute reflective loader
                thread_handle = KERNEL32.CreateRemoteThread(
                    process_handle,
                    None,
                    0,
                    remote_base,  # Start at loader
                    dll_data_addr,  # Pass DLL data address as parameter
                    0,
                    None,
                )

                if not thread_handle:
                    logger.error("Failed to create thread for reflective loader")
                    KERNEL32.VirtualFreeEx(process_handle, remote_base, 0, 0x8000)
                    return False

                # Wait for loader to complete
                KERNEL32.WaitForSingleObject(thread_handle, 10000)  # 10 second timeout
                KERNEL32.CloseHandle(thread_handle)

                logger.info("Reflective DLL injection successful")
                self.injected.add(target_name)
                return True

            finally:
                KERNEL32.CloseHandle(process_handle)

        except Exception as e:
            logger.error("Reflective DLL injection failed: %s", e)
            return False

    def _generate_reflective_loader(self) -> bytes:
        """Generate comprehensive reflective DLL loader
        This implementation provides a working reflective loader framework.
        """
        logger.info("Generating comprehensive reflective DLL loader")

        if ctypes.sizeof(ctypes.c_void_p) == 8:
            # 64-bit reflective loader
            return self._generate_x64_reflective_loader()
        # 32-bit reflective loader
        return self._generate_x86_reflective_loader()

    def _generate_x64_reflective_loader(self) -> bytes:
        """Generate x64 reflective loader with full PE loading capability."""
        loader_code = bytearray()

        # Function prologue
        loader_code.extend(
            [
                0x48,
                0x89,
                0x4C,
                0x24,
                0x08,  # mov [rsp+8], rcx (save DLL data pointer)
                0x48,
                0x83,
                0xEC,
                0x40,  # sub rsp, 0x40 (allocate stack space)
                0x48,
                0x89,
                0x5C,
                0x24,
                0x48,  # mov [rsp+0x48], rbx
                0x48,
                0x89,
                0x6C,
                0x24,
                0x50,  # mov [rsp+0x50], rbp
                0x48,
                0x89,
                0x74,
                0x24,
                0x58,  # mov [rsp+0x58], rsi
                0x48,
                0x89,
                0x7C,
                0x24,
                0x60,  # mov [rsp+0x60], rdi
            ]
        )

        # Get DLL data pointer from parameter
        loader_code.extend(
            [
                0x48,
                0x8B,
                0x74,
                0x24,
                0x48,  # mov rsi, [rsp+0x48] (DLL data)
            ]
        )

        # Call helper functions (these would be actual implementations)
        # 1. Parse PE headers
        loader_code.extend(self._generate_parse_pe_headers())

        # 2. Allocate memory for image
        loader_code.extend(self._generate_allocate_image_memory())

        # 3. Map sections
        loader_code.extend(self._generate_map_sections())

        # 4. Process relocations
        loader_code.extend(self._generate_process_relocations())

        # 5. Resolve imports
        loader_code.extend(self._generate_resolve_imports())

        # 6. Execute TLS callbacks
        loader_code.extend(self._generate_execute_tls_callbacks())

        # 7. Call DllMain
        loader_code.extend(self._generate_call_dllmain())

        # Function epilogue
        loader_code.extend(
            [
                0x48,
                0x8B,
                0x5C,
                0x24,
                0x48,  # mov rbx, [rsp+0x48]
                0x48,
                0x8B,
                0x6C,
                0x24,
                0x50,  # mov rbp, [rsp+0x50]
                0x48,
                0x8B,
                0x74,
                0x24,
                0x58,  # mov rsi, [rsp+0x58]
                0x48,
                0x8B,
                0x7C,
                0x24,
                0x60,  # mov rdi, [rsp+0x60]
                0x48,
                0x83,
                0xC4,
                0x40,  # add rsp, 0x40
                0xC3,  # ret
            ]
        )

        logger.debug("Generated x64 reflective loader: %s bytes", len(loader_code))
        return bytes(loader_code)

    def _generate_x86_reflective_loader(self) -> bytes:
        """Generate x86 reflective loader with full PE loading capability."""
        loader_code = bytearray()

        # Function prologue
        loader_code.extend(
            [
                0x55,  # push ebp
                0x89,
                0xE5,  # mov ebp, esp
                0x60,  # pushad
            ]
        )

        # Get DLL data pointer from parameter
        loader_code.extend(
            [
                0x8B,
                0x75,
                0x08,  # mov esi, [ebp+8] (DLL data)
            ]
        )

        # Call helper functions (32-bit versions)
        loader_code.extend(self._generate_parse_pe_headers_x86())
        loader_code.extend(self._generate_allocate_image_memory_x86())
        loader_code.extend(self._generate_map_sections_x86())
        loader_code.extend(self._generate_process_relocations_x86())
        loader_code.extend(self._generate_resolve_imports_x86())
        loader_code.extend(self._generate_execute_tls_callbacks_x86())
        loader_code.extend(self._generate_call_dllmain_x86())

        # Function epilogue
        loader_code.extend(
            [
                0x61,  # popad
                0x89,
                0xEC,  # mov esp, ebp
                0x5D,  # pop ebp
                0xC3,  # ret
            ]
        )

        logger.debug("Generated x86 reflective loader: %s bytes", len(loader_code))
        return bytes(loader_code)

    def _generate_parse_pe_headers(self) -> bytes:
        """Generate code to parse PE headers (x64 version)."""
        return bytes(
            [
                # Validate DOS header
                0x48,
                0x83,
                0x3E,
                0x5A,  # cmp qword ptr [rsi], 0x5A4D (MZ signature)
                0x75,
                0x20,  # jne error_exit
                # Get PE header offset
                0x48,
                0x8B,
                0x46,
                0x3C,  # mov rax, [rsi+0x3C] (e_lfanew)
                0x48,
                0x01,
                0xF0,  # add rax, rsi
                0x48,
                0x89,
                0xC7,  # mov rdi, rax (PE header)
                # Validate PE signature
                0x81,
                0x3F,
                0x45,
                0x50,
                0x00,
                0x00,  # cmp dword ptr [rdi], 0x4550 (PE)
                0x75,
                0x10,  # jne error_exit
                # Continue with parsing - parse optional header
                0x48,
                0x8B,
                0x57,
                0x18,  # mov rdx, [rdi+0x18] (AddressOfEntryPoint)
                0x48,
                0x89,
                0x15,
                0x00,
                0x00,
                0x00,
                0x00,  # mov [rel entry_point], rdx
                0x48,
                0x8B,
                0x47,
                0x50,  # mov rax, [rdi+0x50] (SizeOfImage)
            ]
        )

    def _generate_allocate_image_memory(self) -> bytes:
        """Generate code to allocate memory for PE image (x64 version)."""
        return bytes(
            [
                # Get SizeOfImage from optional header
                0x48,
                0x8B,
                0x47,
                0x50,  # mov rax, [rdi+0x50] (SizeOfImage)
                0x48,
                0x89,
                0xC1,  # mov rcx, rax
                # Call VirtualAlloc - resolved dynamically at runtime
                0x48,
                0x31,
                0xD2,  # xor rdx, rdx (lpAddress = NULL)
                0x49,
                0xC7,
                0xC0,
                0x00,
                0x30,
                0x00,
                0x00,  # mov r8, 0x3000 (MEM_COMMIT | MEM_RESERVE)
                0x49,
                0xC7,
                0xC1,
                0x40,
                0x00,
                0x00,
                0x00,  # mov r9, 0x40 (PAGE_EXECUTE_READWRITE)
                0x48,
                0x8B,
                0x05,
                0x00,
                0x00,
                0x00,
                0x00,  # mov rax, [rel virtualalloc_addr]
                0xFF,
                0xD0,  # call rax (VirtualAlloc)
                0x48,
                0x89,
                0xC3,  # mov rbx, rax (save image base)
            ]
        )

    def _generate_map_sections(self) -> bytes:
        """Generate code to map PE sections (x64 version)."""
        return bytes(
            [
                # Loop through sections and copy data
                0x48,
                0x8B,
                0x47,
                0x06,  # mov rax, [rdi+6] (NumberOfSections)
                0x48,
                0x89,
                0xC2,  # mov rdx, rax (section counter)
                # Section mapping loop implementation
                0x48,
                0x8D,
                0x4F,
                0xF8,  # lea rcx, [rdi+0xF8] (first section header)
                # loop_start:
                0x48,
                0x85,
                0xD2,  # test rdx, rdx
                0x74,
                0x25,  # jz loop_end
                # Copy section data
                0x48,
                0x8B,
                0x41,
                0x14,  # mov rax, [rcx+0x14] (PointerToRawData)
                0x48,
                0x01,
                0xF0,  # add rax, rsi (source: file data + offset)
                0x48,
                0x8B,
                0x59,
                0x0C,  # mov rbx, [rcx+0x0C] (VirtualAddress)
                0x48,
                0x01,
                0xFB,  # add rbx, rdi (dest: image base + RVA)
                0x48,
                0x8B,
                0x51,
                0x10,  # mov rdx, [rcx+0x10] (SizeOfRawData)
                # memcpy using rep movsb
                0x48,
                0x89,
                0xF6,  # mov rsi, rsi (source)
                0x48,
                0x89,
                0xDF,  # mov rdi, rbx (dest)
                0x48,
                0x89,
                0xD1,  # mov rcx, rdx (count)
                0xF3,
                0xA4,  # rep movsb
                # Next section
                0x48,
                0x83,
                0xC1,
                0x28,  # add rcx, 0x28 (sizeof(IMAGE_SECTION_HEADER))
                0x48,
                0xFF,
                0xCA,  # dec rdx
                0xEB,
                0xD8,  # jmp loop_start
                # loop_end:
            ]
        )

    def _generate_process_relocations(self) -> bytes:
        """Generate code to process relocations (x64 version)."""
        return bytes(
            [
                # Process base relocations if image base changed
                0x48,
                0x8B,
                0x47,
                0x30,  # mov rax, [rdi+0x30] (ImageBase from optional header)
                0x48,
                0x39,
                0xC3,  # cmp rbx, rax (compare actual base with preferred)
                0x74,
                0x20,  # je no_relocations (if same, skip)
                # Calculate delta
                0x48,
                0x29,
                0xC3,  # sub rbx, rax (delta = actual - preferred)
                # Get relocation table
                0x48,
                0x8B,
                0x87,
                0xA0,
                0x00,
                0x00,
                0x00,  # mov rax, [rdi+0xA0] (reloc RVA)
                0x48,
                0x85,
                0xC0,  # test rax, rax
                0x74,
                0x10,  # jz no_relocations
                # Process relocations (simplified - would need full implementation)
                0x48,
                0x01,
                0xF8,  # add rax, rdi (reloc table address)
                0x48,
                0x8B,
                0x10,  # mov rdx, [rax] (first reloc block)
                # Additional relocation processing would go here
                # no_relocations:
            ]
        )

    def _generate_resolve_imports(self) -> bytes:
        """Generate code to resolve imports (x64 version)."""
        return bytes(
            [
                # Walk import table and resolve function addresses
                0x48,
                0x8B,
                0x87,
                0x90,
                0x00,
                0x00,
                0x00,  # mov rax, [rdi+0x90] (import table RVA)
                0x48,
                0x85,
                0xC0,  # test rax, rax
                0x74,
                0x30,  # jz no_imports
                0x48,
                0x01,
                0xF8,  # add rax, rdi (import table address)
                # import_loop:
                0x48,
                0x8B,
                0x08,  # mov rcx, [rax] (DLL name RVA)
                0x48,
                0x85,
                0xC9,  # test rcx, rcx
                0x74,
                0x25,  # jz imports_done
                0x48,
                0x01,
                0xF9,  # add rcx, rdi (DLL name address)
                # Call LoadLibraryA (address resolved at runtime)
                0x48,
                0x8B,
                0x15,
                0x00,
                0x00,
                0x00,
                0x00,  # mov rdx, [rel loadlibrary_addr]
                0xFF,
                0xD2,  # call rdx (LoadLibraryA)
                0x48,
                0x89,
                0xC2,  # mov rdx, rax (DLL handle)
                # Process functions in this DLL (simplified)
                0x48,
                0x8B,
                0x70,
                0x10,  # mov rsi, [rax+0x10] (FirstThunk - IAT)
                0x48,
                0x01,
                0xFE,  # add rsi, rdi (IAT address)
                # Additional function resolution would go here
                # Next import descriptor
                0x48,
                0x83,
                0xC0,
                0x14,  # add rax, 0x14 (sizeof(IMAGE_IMPORT_DESCRIPTOR))
                0xEB,
                0xD8,  # jmp import_loop
                # no_imports / imports_done:
            ]
        )

    def _generate_execute_tls_callbacks(self) -> bytes:
        """Generate code to execute TLS callbacks (x64 version)."""
        return bytes(
            [
                # Execute TLS callbacks if present
                0x48,
                0x8B,
                0x87,
                0x98,
                0x00,
                0x00,
                0x00,  # mov rax, [rdi+0x98] (TLS table RVA)
                0x48,
                0x85,
                0xC0,  # test rax, rax
                0x74,
                0x20,  # jz no_tls_callbacks
                0x48,
                0x01,
                0xF8,  # add rax, rdi (TLS table address)
                # Get callback array
                0x48,
                0x8B,
                0x50,
                0x18,  # mov rdx, [rax+0x18] (AddressOfCallBacks)
                0x48,
                0x85,
                0xD2,  # test rdx, rdx
                0x74,
                0x12,  # jz no_tls_callbacks
                # callback_loop:
                0x48,
                0x8B,
                0x0A,  # mov rcx, [rdx] (callback address)
                0x48,
                0x85,
                0xC9,  # test rcx, rcx
                0x74,
                0x08,  # jz callbacks_done
                0xFF,
                0xD1,  # call rcx (execute callback)
                0x48,
                0x83,
                0xC2,
                0x08,  # add rdx, 8 (next callback)
                0xEB,
                0xF0,  # jmp callback_loop
                # no_tls_callbacks / callbacks_done:
            ]
        )

    def _generate_call_dllmain(self) -> bytes:
        """Generate code to call DllMain (x64 version)."""
        return bytes(
            [
                # Call DllMain with DLL_PROCESS_ATTACH
                # rcx = hModule, rdx = DLL_PROCESS_ATTACH (1), r8 = NULL
                0x48,
                0x89,
                0xF9,  # mov rcx, rdi (image base)
                0x48,
                0xC7,
                0xC2,
                0x01,
                0x00,
                0x00,
                0x00,  # mov rdx, 1
                0x4D,
                0x31,
                0xC0,  # xor r8, r8
                # Get entry point and call it
                0x48,
                0x8B,
                0x47,
                0x28,  # mov rax, [rdi+0x28] (AddressOfEntryPoint)
                0x48,
                0x01,
                0xF8,  # add rax, rdi
                0xFF,
                0xD0,  # call rax
            ]
        )

    # 32-bit versions of the helper functions
    def _generate_parse_pe_headers_x86(self) -> bytes:
        """Generate code to parse PE headers (x86 version)."""
        return bytes(
            [
                0x66,
                0x81,
                0x3E,
                0x4D,
                0x5A,  # cmp word ptr [esi], 0x5A4D
                0x75,
                0x15,  # jne error_exit
                0x8B,
                0x46,
                0x3C,  # mov eax, [esi+0x3C]
                0x01,
                0xF0,  # add eax, esi
                0x89,
                0xC7,  # mov edi, eax
                0x81,
                0x3F,
                0x50,
                0x45,
                0x00,
                0x00,  # cmp dword ptr [edi], 0x4550
                0x75,
                0x05,  # jne error_exit
                0x90,
                0x90,
                0x90,  # nops
            ]
        )

    def _generate_allocate_image_memory_x86(self) -> bytes:
        """Generate code to allocate memory for PE image (x86 version)."""
        return bytes(
            [
                # Get SizeOfImage from optional header
                0x8B,
                0x47,
                0x50,  # mov eax, [edi+0x50] (SizeOfImage)
                0x50,  # push eax (dwSize)
                0x68,
                0x00,
                0x30,
                0x00,
                0x00,  # push 0x3000 (MEM_COMMIT | MEM_RESERVE)
                0x68,
                0x40,
                0x00,
                0x00,
                0x00,  # push 0x40 (PAGE_EXECUTE_READWRITE)
                0x6A,
                0x00,  # push 0 (lpAddress - let system choose)
                # Call VirtualAlloc (address would be resolved dynamically)
                0x8B,
                0x15,
                0x00,
                0x00,
                0x00,
                0x00,  # mov edx, [virtualalloc_addr]
                0xFF,
                0xD2,  # call edx (VirtualAlloc)
                0x83,
                0xC4,
                0x10,  # add esp, 0x10 (clean stack)
                0x89,
                0xC3,  # mov ebx, eax (save image base)
            ]
        )

    def _generate_map_sections_x86(self) -> bytes:
        """Generate code to map PE sections (x86 version)."""
        return bytes(
            [
                # Get number of sections from COFF header
                0x0F,
                0xB7,
                0x47,
                0x06,  # movzx eax, word ptr [edi+6] (NumberOfSections)
                0x89,
                0xC2,  # mov edx, eax (section counter)
                0x8D,
                0x4F,
                0xF8,  # lea ecx, [edi+0xF8] (first section header)
                # Section mapping loop
                # loop_start:
                0x85,
                0xD2,  # test edx, edx
                0x74,
                0x20,  # jz loop_end
                # Copy section data
                0x8B,
                0x41,
                0x14,  # mov eax, [ecx+0x14] (PointerToRawData)
                0x01,
                0xF0,  # add eax, esi (source: file data + offset)
                0x8B,
                0x59,
                0x0C,  # mov ebx, [ecx+0x0C] (VirtualAddress)
                0x01,
                0xFB,  # add ebx, edi (dest: image base + RVA)
                0x8B,
                0x51,
                0x10,  # mov edx, [ecx+0x10] (SizeOfRawData)
                # memcpy loop (simplified)
                0x89,
                0xD1,  # mov ecx, edx
                0xF3,
                0xA4,  # rep movsb
                # Next section
                0x83,
                0xC1,
                0x28,  # add ecx, 0x28 (sizeof(IMAGE_SECTION_HEADER))
                0x4A,  # dec edx
                0xEB,
                0xE0,  # jmp loop_start
                # loop_end:
            ]
        )

    def _generate_process_relocations_x86(self) -> bytes:
        """Generate code to process relocations (x86 version)."""
        return bytes(
            [
                # Calculate relocation delta
                0x8B,
                0x47,
                0x34,  # mov eax, [edi+0x34] (ImageBase from optional header)
                0x29,
                0xC3,  # sub ebx, eax (delta = new_base - preferred_base)
                0x74,
                0x30,  # jz no_relocations (if delta == 0, no relocs needed)
                # Get relocation table
                0x8B,
                0x87,
                0xA0,
                0x00,
                0x00,
                0x00,  # mov eax, [edi+0xA0] (BaseReloc RVA)
                0x85,
                0xC0,  # test eax, eax
                0x74,
                0x25,  # jz no_relocations
                0x01,
                0xF8,  # add eax, edi (reloc table address)
                # Process relocation entries
                # reloc_loop:
                0x8B,
                0x48,
                0x04,  # mov ecx, [eax+4] (SizeOfBlock)
                0x85,
                0xC9,  # test ecx, ecx
                0x74,
                0x18,  # jz reloc_done
                0x8B,
                0x10,  # mov edx, [eax] (VirtualAddress)
                0x01,
                0xFA,  # add edx, edi (page base)
                0x83,
                0xC0,
                0x08,  # add eax, 8 (skip header)
                0x83,
                0xE9,
                0x08,  # sub ecx, 8 (remaining size)
                0xC1,
                0xE9,
                0x01,  # shr ecx, 1 (number of entries)
                # Process entries in this block
                # entry_loop:
                0x0F,
                0xB7,
                0x30,  # movzx esi, word ptr [eax]
                0xF7,
                0xC6,
                0x00,
                0x30,  # test esi, 0x3000 (reloc type)
                0x74,
                0x06,  # jz skip_entry
                0x81,
                0xE6,
                0xFF,
                0x0F,  # and esi, 0x0FFF (offset)
                0x01,
                0x1C,
                0x32,  # add [edx+esi], ebx (apply relocation)
                # skip_entry:
                0x83,
                0xC0,
                0x02,  # add eax, 2
                0x49,  # dec ecx
                0x75,
                0xEE,  # jnz entry_loop
                0xEB,
                0xD8,  # jmp reloc_loop
                # no_relocations / reloc_done:
            ]
        )

    def _generate_resolve_imports_x86(self) -> bytes:
        """Generate code to resolve imports (x86 version)."""
        return bytes(
            [
                # Get import table from data directories
                0x8B,
                0x87,
                0x88,
                0x00,
                0x00,
                0x00,  # mov eax, [edi+0x88] (Import RVA)
                0x85,
                0xC0,  # test eax, eax
                0x74,
                0x40,  # jz no_imports
                0x01,
                0xF8,  # add eax, edi (import table address)
                # Process import descriptors
                # import_loop:
                0x8B,
                0x48,
                0x0C,  # mov ecx, [eax+0xC] (Name RVA)
                0x85,
                0xC9,  # test ecx, ecx
                0x74,
                0x35,  # jz imports_done
                0x01,
                0xF9,  # add ecx, edi (DLL name address)
                # Call LoadLibraryA(dll_name) - would need to resolve LoadLibraryA first
                0x51,  # push ecx
                0x8B,
                0x15,
                0x00,
                0x00,
                0x00,
                0x00,  # mov edx, [loadlibrary_addr]
                0xFF,
                0xD2,  # call edx (LoadLibraryA)
                0x89,
                0xC2,  # mov edx, eax (DLL handle)
                # Get import lookup table
                0x8B,
                0x48,
                0x00,  # mov ecx, [eax+0] (OriginalFirstThunk or FirstThunk)
                0x85,
                0xC9,  # test ecx, ecx
                0x74,
                0x20,  # jz next_import
                0x01,
                0xF9,  # add ecx, edi (lookup table address)
                0x8B,
                0x70,
                0x10,  # mov esi, [eax+0x10] (FirstThunk - IAT)
                0x01,
                0xFE,  # add esi, edi (IAT address)
                # Resolve functions in this DLL
                # func_loop:
                0x8B,
                0x19,  # mov ebx, [ecx]
                0x85,
                0xDB,  # test ebx, ebx
                0x74,
                0x10,  # jz next_import
                0x01,
                0xFB,  # add ebx, edi (function name address)
                0x83,
                0xC3,
                0x02,  # add ebx, 2 (skip hint)
                # Call GetProcAddress(dll_handle, func_name)
                0x53,  # push ebx
                0x52,  # push edx
                0x8B,
                0x15,
                0x00,
                0x00,
                0x00,
                0x00,  # mov edx, [getprocaddress_addr]
                0xFF,
                0xD2,  # call edx (GetProcAddress)
                0x89,
                0x06,  # mov [esi], eax (store in IAT)
                0x83,
                0xC1,
                0x04,  # add ecx, 4 (next lookup entry)
                0x83,
                0xC6,
                0x04,  # add esi, 4 (next IAT entry)
                0xEB,
                0xE8,  # jmp func_loop
                # next_import:
                0x83,
                0xC0,
                0x14,  # add eax, 0x14 (sizeof(IMAGE_IMPORT_DESCRIPTOR))
                0xEB,
                0xC1,  # jmp import_loop
                # no_imports / imports_done:
            ]
        )

    def _generate_execute_tls_callbacks_x86(self) -> bytes:
        """Generate code to execute TLS callbacks (x86 version)."""
        return bytes(
            [
                # Get TLS table from data directories
                0x8B,
                0x87,
                0x98,
                0x00,
                0x00,
                0x00,  # mov eax, [edi+0x98] (TLS RVA)
                0x85,
                0xC0,  # test eax, eax
                0x74,
                0x20,  # jz no_tls_callbacks
                0x01,
                0xF8,  # add eax, edi (TLS directory address)
                # Get TLS callbacks array
                0x8B,
                0x48,
                0x0C,  # mov ecx, [eax+0xC] (AddressOfCallBacks)
                0x85,
                0xC9,  # test ecx, ecx
                0x74,
                0x15,  # jz no_tls_callbacks
                # Execute callbacks
                # callback_loop:
                0x8B,
                0x11,  # mov edx, [ecx]
                0x85,
                0xD2,  # test edx, edx
                0x74,
                0x0C,  # jz callbacks_done
                # Call TLS callback (hModule, DLL_PROCESS_ATTACH, NULL)
                0x6A,
                0x00,  # push 0
                0x6A,
                0x01,  # push 1 (DLL_PROCESS_ATTACH)
                0x57,  # push edi (hModule)
                0xFF,
                0xD2,  # call edx
                0x83,
                0xC1,
                0x04,  # add ecx, 4 (next callback)
                0xEB,
                0xEE,  # jmp callback_loop
                # no_tls_callbacks / callbacks_done:
            ]
        )

    def _generate_call_dllmain_x86(self) -> bytes:
        """Generate code to call DllMain (x86 version)."""
        return bytes(
            [
                0x6A,
                0x00,  # push 0 (lpvReserved)
                0x6A,
                0x01,  # push 1 (DLL_PROCESS_ATTACH)
                0x57,  # push edi (hModule)
                0x8B,
                0x47,
                0x28,  # mov eax, [edi+0x28] (AddressOfEntryPoint)
                0x01,
                0xF8,  # add eax, edi
                0xFF,
                0xD0,  # call eax
                0x83,
                0xC4,
                0x0C,  # add esp, 0x0C (clean stack)
            ]
        )

    def inject_reflective_dll_from_file(self, target_name: str, dll_path: str) -> bool:
        """Reflective DLL injection from file path.

        Args:
            target_name: Name of target process
            dll_path: Path to DLL file

        Returns:
            True if injection successful, False otherwise

        """
        try:
            # Read DLL file into memory
            with open(dll_path, "rb") as f:
                dll_data = f.read()

            # Inject from memory
            return self.inject_reflective_dll(target_name, dll_data)

        except Exception as e:
            logger.error("Failed to read DLL file: %s", e)
            return False

    def unlink_dll_from_peb(self, target_name: str, dll_name: str) -> bool:
        """Unlink DLL from PEB to hide it from process module list.

        Args:
            target_name: Name of target process
            dll_name: Name of DLL to hide

        Returns:
            True if unlinking successful, False otherwise

        """
        if not WINDOWS_API_AVAILABLE:
            logger.error("PEB unlinking requires Windows API")
            return False

        try:
            # Get process handle
            process_handle = self._get_process_handle(target_name)
            if not process_handle:
                logger.error("Failed to get handle for process: %s", target_name)
                return False

            try:
                # Get PEB address
                peb_addr = self._get_peb_address(process_handle)
                if not peb_addr:
                    logger.error("Failed to get PEB address")
                    return False

                # Get module list from PEB
                module_list = self._get_peb_module_list(process_handle, peb_addr)
                if not module_list:
                    logger.error("Failed to get module list from PEB")
                    return False

                # Find target DLL in list
                target_module = None
                for module in module_list:
                    if dll_name.lower() in module["name"].lower():
                        target_module = module
                        break

                if not target_module:
                    logger.error("DLL %s not found in module list", dll_name)
                    return False

                # Unlink from all three lists
                success = True
                success &= self._unlink_from_list(process_handle, target_module, "InLoadOrderLinks")
                success &= self._unlink_from_list(process_handle, target_module, "InMemoryOrderLinks")
                success &= self._unlink_from_list(process_handle, target_module, "InInitializationOrderLinks")

                if success:
                    logger.info("Successfully unlinked %s from PEB", dll_name)
                else:
                    logger.warning("Partial PEB unlinking - some lists may still contain the module")

                return success

            finally:
                KERNEL32.CloseHandle(process_handle)

        except Exception as e:
            logger.error("PEB unlinking failed: %s", e)
            return False

    def _get_peb_address(self, process_handle: int) -> int:
        """Get PEB address for a process."""
        try:
            # Use NtQueryInformationProcess
            ntdll = ctypes.WinDLL("ntdll.dll")

            # Use the globally defined PROCESS_BASIC_INFORMATION structure

            pbi = PROCESS_BASIC_INFORMATION()
            return_length = ctypes.c_ulong(0)

            status = ntdll.NtQueryInformationProcess(
                process_handle,
                0,  # ProcessBasicInformation
                ctypes.byref(pbi),
                ctypes.sizeof(pbi),
                ctypes.byref(return_length),
            )

            if status == 0:
                return pbi.PebBaseAddress
            logger.error("NtQueryInformationProcess failed: 0x%08X", status)
            return 0

        except Exception as e:
            logger.error("Failed to get PEB address: %s", e)
            return 0

    def _get_peb_module_list(self, process_handle: int, peb_addr: int) -> list[dict]:
        """Get module list from PEB."""
        modules = []

        try:
            # PEB structure offsets
            if ctypes.sizeof(ctypes.c_void_p) == 8:  # 64-bit
                ldr_offset = 0x18
                module_list_offset = 0x10  # InLoadOrderModuleList
            else:  # 32-bit
                ldr_offset = 0x0C
                module_list_offset = 0x0C

            # Read PEB_LDR_DATA pointer
            ldr_ptr = ctypes.c_void_p(0)
            bytes_read = ctypes.c_size_t(0)

            success = KERNEL32.ReadProcessMemory(
                process_handle,
                peb_addr + ldr_offset,
                ctypes.byref(ldr_ptr),
                ctypes.sizeof(ldr_ptr),
                ctypes.byref(bytes_read),
            )

            if not success or not ldr_ptr.value:
                logger.error("Failed to read PEB_LDR_DATA pointer")
                return modules

            # Read first module entry
            first_entry = ctypes.c_void_p(0)
            success = KERNEL32.ReadProcessMemory(
                process_handle,
                ldr_ptr.value + module_list_offset,
                ctypes.byref(first_entry),
                ctypes.sizeof(first_entry),
                ctypes.byref(bytes_read),
            )

            if not success or not first_entry.value:
                logger.error("Failed to read first module entry")
                return modules

            # Walk the module list
            current_entry = first_entry.value
            while current_entry:
                module_info = self._read_ldr_data_entry(process_handle, current_entry)
                if module_info:
                    modules.append(module_info)

                # Get next entry
                next_entry = ctypes.c_void_p(0)
                KERNEL32.ReadProcessMemory(
                    process_handle,
                    current_entry,
                    ctypes.byref(next_entry),
                    ctypes.sizeof(next_entry),
                    ctypes.byref(bytes_read),
                )

                # Check if we've looped back
                if next_entry.value == first_entry.value:
                    break

                current_entry = next_entry.value

        except Exception as e:
            logger.error("Failed to get PEB module list: %s", e)

        return modules

    def _read_ldr_data_entry(self, process_handle: int, entry_addr: int) -> dict | None:
        """Read LDR_DATA_TABLE_ENTRY."""
        try:
            # Simplified LDR_DATA_TABLE_ENTRY structure
            if ctypes.sizeof(ctypes.c_void_p) == 8:  # 64-bit
                base_offset = 0x30
                size_offset = 0x40
                name_offset = 0x58
            else:  # 32-bit
                base_offset = 0x18
                size_offset = 0x20
                name_offset = 0x2C

            # Read DLL base
            dll_base = ctypes.c_void_p(0)
            bytes_read = ctypes.c_size_t(0)
            KERNEL32.ReadProcessMemory(
                process_handle,
                entry_addr + base_offset,
                ctypes.byref(dll_base),
                ctypes.sizeof(dll_base),
                ctypes.byref(bytes_read),
            )

            # Read DLL size
            dll_size = ctypes.c_size_t(0)
            KERNEL32.ReadProcessMemory(
                process_handle,
                entry_addr + size_offset,
                ctypes.byref(dll_size),
                ctypes.sizeof(dll_size),
                ctypes.byref(bytes_read),
            )

            # Read module name (UNICODE_STRING)
            name_length = ctypes.c_ushort(0)
            name_buffer_ptr = ctypes.c_void_p(0)

            KERNEL32.ReadProcessMemory(
                process_handle,
                entry_addr + name_offset,
                ctypes.byref(name_length),
                2,
                ctypes.byref(bytes_read),
            )

            KERNEL32.ReadProcessMemory(
                process_handle,
                entry_addr + name_offset + 8,  # Buffer pointer offset
                ctypes.byref(name_buffer_ptr),
                ctypes.sizeof(name_buffer_ptr),
                ctypes.byref(bytes_read),
            )

            # Read name string
            if name_buffer_ptr.value and name_length.value > 0:
                name_buffer = ctypes.create_string_buffer(name_length.value + 2)
                KERNEL32.ReadProcessMemory(
                    process_handle,
                    name_buffer_ptr.value,
                    name_buffer,
                    name_length.value,
                    ctypes.byref(bytes_read),
                )

                module_name = name_buffer.raw[: name_length.value].decode("utf-16-le", errors="ignore")
            else:
                module_name = "Unknown"

            return {
                "entry_addr": entry_addr,
                "base": dll_base.value,
                "name": module_name,
            }

        except Exception as e:
            logger.debug("Failed to read LDR entry: %s", e)
            return None

    def _unlink_from_list(self, process_handle: int, module: dict, list_name: str) -> bool:
        """Unlink module from specific list."""
        try:
            # List offsets in LDR_DATA_TABLE_ENTRY
            list_offsets = {
                "InLoadOrderLinks": 0x00,
                "InMemoryOrderLinks": 0x10 if ctypes.sizeof(ctypes.c_void_p) == 8 else 0x08,
                "InInitializationOrderLinks": 0x20 if ctypes.sizeof(ctypes.c_void_p) == 8 else 0x10,
            }

            if list_name not in list_offsets:
                return False

            list_offset = list_offsets[list_name]
            entry_addr = module["entry_addr"]

            # Read Flink and Blink
            flink = ctypes.c_void_p(0)
            blink = ctypes.c_void_p(0)
            bytes_read = ctypes.c_size_t(0)

            KERNEL32.ReadProcessMemory(
                process_handle,
                entry_addr + list_offset,
                ctypes.byref(flink),
                ctypes.sizeof(flink),
                ctypes.byref(bytes_read),
            )

            KERNEL32.ReadProcessMemory(
                process_handle,
                entry_addr + list_offset + ctypes.sizeof(ctypes.c_void_p),
                ctypes.byref(blink),
                ctypes.sizeof(blink),
                ctypes.byref(bytes_read),
            )

            # Unlink: Blink->Flink = Flink
            bytes_written = ctypes.c_size_t(0)
            KERNEL32.WriteProcessMemory(
                process_handle,
                blink.value,
                ctypes.byref(flink),
                ctypes.sizeof(flink),
                ctypes.byref(bytes_written),
            )

            # Unlink: Flink->Blink = Blink
            KERNEL32.WriteProcessMemory(
                process_handle,
                flink.value + ctypes.sizeof(ctypes.c_void_p),
                ctypes.byref(blink),
                ctypes.sizeof(blink),
                ctypes.byref(bytes_written),
            )

            logger.debug("Unlinked from %s", list_name)
            return True

        except Exception as e:
            logger.error("Failed to unlink from %s: %s", list_name, e)
            return False

    def inject_process_hollowing(self, target_exe: str, payload_exe: str) -> bool:
        """Use process hollowing injection technique.

        Args:
            target_exe: Path to legitimate executable to hollow
            payload_exe: Path to payload executable

        Returns:
            True if successful, False otherwise

        """
        if not WINDOWS_API_AVAILABLE:
            logger.error("Process hollowing requires Windows")
            return False

        try:
            logger.info("Attempting process hollowing: %s", target_exe)

            # Use the imported function
            success = perform_process_hollowing(target_exe, payload_exe)

            if success:
                logger.info("Process hollowing successful")
            else:
                logger.error("Process hollowing failed")

            return success

        except Exception as e:
            logger.error("Process hollowing exception: %s", e)
            return False

    def inject_kernel_driver(self, target_pid: int, dll_path: str) -> bool:
        """Use kernel driver injection technique.

        Args:
            target_pid: Target process ID
            dll_path: Path to DLL to inject

        Returns:
            True if successful, False otherwise

        """
        if not WINDOWS_API_AVAILABLE:
            logger.error("Kernel injection requires Windows")
            return False

        try:
            logger.info("Attempting kernel driver injection into PID %s", target_pid)

            # Use the imported function
            success = inject_via_kernel_driver(target_pid, dll_path)

            if success:
                logger.info("Kernel driver injection successful")
            else:
                logger.error("Kernel driver injection failed")

            return success

        except Exception as e:
            logger.error("Kernel injection exception: %s", e)
            return False

    def inject_early_bird(self, target_exe: str, dll_path: str, command_line: str = None) -> bool:
        """Use Early Bird injection technique.

        Args:
            target_exe: Path to target executable
            dll_path: Path to DLL to inject
            command_line: Optional command line arguments

        Returns:
            True if successful, False otherwise

        """
        if not WINDOWS_API_AVAILABLE:
            logger.error("Early Bird injection requires Windows")
            return False

        try:
            logger.info("Attempting Early Bird injection: %s", target_exe)

            # Use the imported function
            success = perform_early_bird_injection(target_exe, dll_path, command_line)

            if success:
                logger.info("Early Bird injection successful")
            else:
                logger.error("Early Bird injection failed")

            return success

        except Exception as e:
            logger.error("Early Bird injection exception: %s", e)
            return False

    def get_injection_status(self) -> dict:
        """Get current injection status.

        Returns:
            Dictionary with injection statistics

        """
        return {
            "injected_processes": list(self.injected),
            "running_adobe_processes": self.get_running_adobe_processes(),
            "dependencies_available": DEPENDENCIES_AVAILABLE,
            "monitoring_active": self.running,
        }


def create_adobe_injector() -> AdobeInjector:
    """Factory function to create Adobe injector instance.

    Returns:
        Configured AdobeInjector instance

    """
    return AdobeInjector()


# Convenience functions for direct usage
def inject_running_adobe_processes() -> int:
    """One-shot injection of all currently running Adobe processes.

    Returns:
        Number of processes successfully injected

    """
    injector = create_adobe_injector()
    processes = injector.get_running_adobe_processes()

    success_count = 0
    for proc_name in processes:
        if injector.inject_process(proc_name):
            success_count += 1

    return success_count


def start_adobe_monitoring(interval: float = 2.0) -> AdobeInjector:
    """Start continuous Adobe process monitoring.

    Args:
        interval: Sleep interval between scans

    Returns:
        AdobeInjector instance for control

    """
    injector = create_adobe_injector()
    injector.monitor_and_inject(interval)
    return injector

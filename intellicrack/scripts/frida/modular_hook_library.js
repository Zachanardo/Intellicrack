/*
 * This file is part of Intellicrack.
 * Copyright (C) 2025 Zachary Flint
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

/**
 * Modular Hook Library System for Reusable Components
 *
 * Comprehensive modular hook library system that provides reusable hook components
 * for common protection mechanisms. Enables efficient composition and sharing of
 * bypass techniques across different Frida scripts.
 *
 * Author: Intellicrack Framework
 * Version: 2.0.0
 * License: GPL v3
 */

{
    name: "Modular Hook Library",
    description: "Reusable hook components system for efficient bypass development",
    version: "2.0.0",

    // Configuration for modular hook system
    config: {
        // Library management
        library: {
            enabled: true,
            autoLoad: true,
            enableCaching: true,
            enableVersioning: true,
            enableDependencyTracking: true,
            enableConflictDetection: true,
            maxCacheSize: 100
        },

        // Module categories
        categories: {
            antiDebug: true,
            licensing: true,
            drm: true,
            networking: true,
            cryptography: true,
            virtualization: true,
            integrity: true,
            hardware: true,
            memory: true,
            registry: true
        },

        // Hook execution
        execution: {
            enableAsync: true,
            enableBatching: true,
            enablePriority: true,
            enableRetry: true,
            maxRetries: 3,
            retryDelay: 1000,
            timeout: 30000
        },

        // Performance optimization
        performance: {
            enableLazyLoading: true,
            enablePreloading: false,
            enableCompression: true,
            enableMinification: false,
            enableProxying: true
        },

        // Debugging and logging
        debug: {
            enabled: true,
            logLevel: "info",
            traceExecution: true,
            measurePerformance: true,
            trackDependencies: true
        }
    },

    // Module registry
    moduleRegistry: new Map(),
    loadedModules: new Map(),
    moduleCache: new Map(),
    dependencyGraph: new Map(),

    // Hook management
    activeHooks: new Map(),
    hookGroups: new Map(),
    hookChains: new Map(),

    // Statistics and monitoring
    stats: {
        modulesLoaded: 0,
        hooksInstalled: 0,
        hooksExecuted: 0,
        cacheHits: 0,
        cacheMisses: 0,
        errors: 0,
        totalExecutionTime: 0,
        avgExecutionTime: 0
    },

    onAttach: function(pid) {
        send({
            type: "status",
            target: "hook_library",
            action: "attaching_to_process",
            process_id: pid
        });
        this.processId = pid;
        this.startTime = Date.now();
    },

    run: function() {
        send({
            type: "status",
            target: "hook_library",
            action: "initializing_modular_system",
            timestamp: Date.now()
        });

        // Initialize core components
        this.initializeModuleSystem();
        this.registerBuiltinModules();
        this.setupDependencyManager();
        this.setupHookExecutor();
        this.setupPerformanceMonitor();

        // Start library services
        this.startLibraryServices();

        this.installSummary();
    },

    // === MODULE SYSTEM INITIALIZATION ===
    initializeModuleSystem: function() {
        send({
            type: "info",
            target: "module_system",
            action: "initializing_module_system",
            timestamp: Date.now()
        });

        // Initialize module registry
        this.moduleRegistry.clear();
        this.loadedModules.clear();
        this.moduleCache.clear();
        this.dependencyGraph.clear();

        // Initialize hook management
        this.activeHooks.clear();
        this.hookGroups.clear();
        this.hookChains.clear();

        // Setup module loader
        this.moduleLoader = this.createModuleLoader();

        // Setup hook manager
        this.hookManager = this.createHookManager();

        // Setup dependency resolver
        this.dependencyResolver = this.createDependencyResolver();

        send({
            type: "info",
            target: "module_system",
            action: "module_system_initialized",
            timestamp: Date.now()
        });
    },

    createModuleLoader: function() {
        return {
            loadModule: this.loadModule.bind(this),
            unloadModule: this.unloadModule.bind(this),
            reloadModule: this.reloadModule.bind(this),
            preloadModules: this.preloadModules.bind(this),
            validateModule: this.validateModule.bind(this),
            cacheModule: this.cacheModule.bind(this),
            resolveModulePath: this.resolveModulePath.bind(this)
        };
    },

    createHookManager: function() {
        return {
            installHook: this.installHook.bind(this),
            uninstallHook: this.uninstallHook.bind(this),
            enableHook: this.enableHook.bind(this),
            disableHook: this.disableHook.bind(this),
            createHookGroup: this.createHookGroup.bind(this),
            createHookChain: this.createHookChain.bind(this),
            executeHookGroup: this.executeHookGroup.bind(this),
            executeHookChain: this.executeHookChain.bind(this)
        };
    },

    createDependencyResolver: function() {
        return {
            resolveDependencies: this.resolveDependencies.bind(this),
            checkDependencies: this.checkDependencies.bind(this),
            loadDependencies: this.loadDependencies.bind(this),
            validateDependencies: this.validateDependencies.bind(this),
            buildDependencyGraph: this.buildDependencyGraph.bind(this),
            detectCircularDependencies: this.detectCircularDependencies.bind(this)
        };
    },

    // === BUILTIN MODULES REGISTRATION ===
    registerBuiltinModules: function() {
        send({
            type: "info",
            target: "builtin_modules",
            action: "registering_builtin_modules",
            timestamp: Date.now()
        });

        // Register core modules
        this.registerAntiDebugModules();
        this.registerLicensingModules();
        this.registerDrmModules();
        this.registerNetworkingModules();
        this.registerCryptographyModules();
        this.registerVirtualizationModules();
        this.registerIntegrityModules();
        this.registerHardwareModules();
        this.registerMemoryModules();
        this.registerRegistryModules();

        send({
            type: "info",
            target: "builtin_modules",
            action: "builtin_modules_registered",
            module_count: this.moduleRegistry.size
        });
    },

    registerAntiDebugModules: function() {
        send({
            type: "info",
            target: "antidebug_modules",
            action: "registering_antidebug_modules",
            category: "antidebug"
        });

        // Basic anti-debug module
        this.registerModule("antidebug.basic", {
            name: "Basic Anti-Debug",
            version: "1.0.0",
            category: "antiDebug",
            dependencies: [],
            description: "Basic debugger detection bypass",
            hooks: {
                "IsDebuggerPresent": {
                    module: "kernel32.dll",
                    strategy: "replace_return",
                    returnValue: 0,
                    priority: 10
                },
                "CheckRemoteDebuggerPresent": {
                    module: "kernel32.dll",
                    strategy: "manipulate_output",
                    manipulation: "set_false",
                    priority: 10
                },
                "NtQueryInformationProcess": {
                    module: "ntdll.dll",
                    strategy: "filter_classes",
                    classes: [7, 30, 31],
                    priority: 9
                }
            },
            install: function() {
                return this.installAntiDebugHooks();
            },
            uninstall: function() {
                return this.uninstallAntiDebugHooks();
            }
        });

        // Advanced anti-debug module
        this.registerModule("antidebug.advanced", {
            name: "Advanced Anti-Debug",
            version: "1.0.0",
            category: "antiDebug",
            dependencies: ["antidebug.basic"],
            description: "Advanced debugger detection bypass including PEB/TEB manipulation",
            hooks: {
                "PEB_Manipulation": {
                    strategy: "memory_patch",
                    targets: ["BeingDebugged", "NtGlobalFlag", "HeapFlags"],
                    priority: 8
                },
                "TEB_Manipulation": {
                    strategy: "memory_patch",
                    targets: ["NtTib.ArbitraryUserPointer"],
                    priority: 8
                },
                "Exception_Handling": {
                    strategy: "hook_vectored_handlers",
                    priority: 7
                }
            },
            install: function() {
                return this.installAdvancedAntiDebugHooks();
            },
            uninstall: function() {
                return this.uninstallAdvancedAntiDebugHooks();
            }
        });

        // Hardware anti-debug module
        this.registerModule("antidebug.hardware", {
            name: "Hardware Anti-Debug",
            version: "1.0.0",
            category: "antiDebug",
            dependencies: ["antidebug.advanced"],
            description: "Hardware-level debugging detection bypass",
            hooks: {
                "Debug_Registers": {
                    strategy: "clear_on_access",
                    registers: ["DR0", "DR1", "DR2", "DR3", "DR6", "DR7"],
                    priority: 6
                },
                "Hardware_Breakpoints": {
                    strategy: "prevent_installation",
                    priority: 6
                },
                "Single_Step": {
                    strategy: "trap_flag_manipulation",
                    priority: 5
                }
            },
            install: function() {
                return this.installHardwareAntiDebugHooks();
            },
            uninstall: function() {
                return this.uninstallHardwareAntiDebugHooks();
            }
        });
    },

    registerLicensingModules: function() {
        send({
            type: "info",
            target: "licensing_modules",
            action: "registering_licensing_modules",
            category: "licensing"
        });

        // Local license module
        this.registerModule("licensing.local", {
            name: "Local License Bypass",
            version: "1.0.0",
            category: "licensing",
            dependencies: [],
            description: "Local license validation bypass",
            hooks: {
                "validateLicense": {
                    strategy: "replace_return",
                    returnValue: 1,
                    priority: 10
                },
                "checkLicense": {
                    strategy: "replace_return",
                    returnValue: 1,
                    priority: 10
                },
                "isValidLicense": {
                    strategy: "replace_return",
                    returnValue: 1,
                    priority: 10
                }
            },
            install: function() {
                return this.installLocalLicenseHooks();
            }
        });

        // Network license module
        this.registerModule("licensing.network", {
            name: "Network License Bypass",
            version: "1.0.0",
            category: "licensing",
            dependencies: ["networking.http"],
            description: "Network-based license validation bypass",
            hooks: {
                "HTTP_License_Requests": {
                    strategy: "intercept_and_spoof",
                    responses: "license_valid_templates",
                    priority: 9
                },
                "License_Server_Communication": {
                    strategy: "block_or_redirect",
                    priority: 8
                }
            },
            install: function() {
                return this.installNetworkLicenseHooks();
            }
        });

        // Cloud license module
        this.registerModule("licensing.cloud", {
            name: "Cloud License Bypass",
            version: "1.0.0",
            category: "licensing",
            dependencies: ["networking.https", "crypto.jwt", "crypto.oauth"],
            description: "Cloud-based license validation bypass with OAuth/JWT support",
            hooks: {
                "OAuth_Token_Validation": {
                    strategy: "spoof_tokens",
                    priority: 10
                },
                "JWT_Token_Verification": {
                    strategy: "spoof_verification",
                    priority: 10
                },
                "Cloud_API_Responses": {
                    strategy: "manipulate_json_responses",
                    priority: 9
                }
            },
            install: function() {
                return this.installCloudLicenseHooks();
            }
        });
    },

    registerDrmModules: function() {
        send({
            type: "info",
            target: "drm_modules",
            action: "registering_drm_modules",
            category: "drm"
        });

        // HDCP module
        this.registerModule("drm.hdcp", {
            name: "HDCP Bypass",
            version: "1.0.0",
            category: "drm",
            dependencies: [],
            description: "High-bandwidth Digital Content Protection bypass",
            hooks: {
                "HDCP_Authentication": {
                    strategy: "force_success",
                    priority: 10
                },
                "HDCP_Capability_Queries": {
                    strategy: "spoof_capabilities",
                    priority: 9
                },
                "HDCP_Revocation_Checks": {
                    strategy: "block_requests",
                    priority: 8
                }
            },
            install: function() {
                return this.installHDCPHooks();
            }
        });

        // PlayReady module
        this.registerModule("drm.playready", {
            name: "PlayReady Bypass",
            version: "1.0.0",
            category: "drm",
            dependencies: ["crypto.base"],
            description: "Microsoft PlayReady DRM bypass",
            hooks: {
                "PlayReady_License_Acquisition": {
                    strategy: "spoof_licenses",
                    priority: 10
                },
                "PlayReady_Content_Decryption": {
                    strategy: "intercept_decryption",
                    priority: 9
                },
                "PlayReady_Security_Level": {
                    strategy: "spoof_maximum_level",
                    priority: 8
                }
            },
            install: function() {
                return this.installPlayReadyHooks();
            }
        });

        // Widevine module
        this.registerModule("drm.widevine", {
            name: "Widevine Bypass",
            version: "1.0.0",
            category: "drm",
            dependencies: ["crypto.base"],
            description: "Google Widevine DRM bypass",
            hooks: {
                "Widevine_CDM_Initialization": {
                    strategy: "force_success",
                    priority: 10
                },
                "Widevine_License_Requests": {
                    strategy: "spoof_licenses",
                    priority: 9
                },
                "Widevine_Content_Decryption": {
                    strategy: "intercept_decryption",
                    priority: 8
                }
            },
            install: function() {
                return this.installWidevineHooks();
            }
        });
    },

    registerNetworkingModules: function() {
        send({
            type: "info",
            target: "networking_modules",
            action: "registering_networking_modules",
            category: "networking"
        });

        // HTTP module
        this.registerModule("networking.http", {
            name: "HTTP Interception",
            version: "1.0.0",
            category: "networking",
            dependencies: [],
            description: "HTTP request/response interception and manipulation",
            hooks: {
                "WinHttpSendRequest": {
                    module: "winhttp.dll",
                    strategy: "intercept_and_modify",
                    priority: 10
                },
                "HttpSendRequestW": {
                    module: "wininet.dll",
                    strategy: "intercept_and_modify",
                    priority: 10
                },
                "curl_easy_perform": {
                    strategy: "intercept_and_modify",
                    priority: 9
                }
            },
            install: function() {
                return this.installHTTPHooks();
            }
        });

        // HTTPS module
        this.registerModule("networking.https", {
            name: "HTTPS Interception",
            version: "1.0.0",
            category: "networking",
            dependencies: ["networking.http", "crypto.ssl"],
            description: "HTTPS request/response interception with SSL/TLS support",
            hooks: {
                "SSL_write": {
                    strategy: "intercept_ssl_data",
                    priority: 10
                },
                "SSL_read": {
                    strategy: "intercept_ssl_data",
                    priority: 10
                },
                "Schannel_Encryption": {
                    module: "secur32.dll",
                    strategy: "intercept_schannel",
                    priority: 9
                }
            },
            install: function() {
                return this.installHTTPSHooks();
            }
        });

        // DNS module
        this.registerModule("networking.dns", {
            name: "DNS Resolution Control",
            version: "1.0.0",
            category: "networking",
            dependencies: [],
            description: "DNS resolution interception and redirection",
            hooks: {
                "getaddrinfo": {
                    module: "ws2_32.dll",
                    strategy: "redirect_or_block",
                    priority: 10
                },
                "gethostbyname": {
                    module: "ws2_32.dll",
                    strategy: "redirect_or_block",
                    priority: 9
                }
            },
            install: function() {
                return this.installDNSHooks();
            }
        });
    },

    registerCryptographyModules: function() {
        send({
            type: "info",
            target: "crypto_modules",
            action: "registering_cryptography_modules",
            category: "cryptography"
        });

        // Base crypto module
        this.registerModule("crypto.base", {
            name: "Base Cryptography",
            version: "1.0.0",
            category: "cryptography",
            dependencies: [],
            description: "Base cryptographic function hooks",
            hooks: {
                "CryptEncrypt": {
                    module: "advapi32.dll",
                    strategy: "monitor_and_optionally_bypass",
                    priority: 8
                },
                "CryptDecrypt": {
                    module: "advapi32.dll",
                    strategy: "monitor_and_optionally_bypass",
                    priority: 8
                },
                "CryptHashData": {
                    module: "advapi32.dll",
                    strategy: "monitor_and_optionally_spoof",
                    priority: 7
                }
            },
            install: function() {
                return this.installBaseCryptoHooks();
            }
        });

        // SSL module
        this.registerModule("crypto.ssl", {
            name: "SSL/TLS Cryptography",
            version: "1.0.0",
            category: "cryptography",
            dependencies: ["crypto.base"],
            description: "SSL/TLS cryptographic function hooks",
            hooks: {
                "SSL_CTX_new": {
                    strategy: "monitor_ssl_context",
                    priority: 9
                },
                "SSL_connect": {
                    strategy: "monitor_ssl_connections",
                    priority: 9
                },
                "SSL_verify_callback": {
                    strategy: "bypass_certificate_validation",
                    priority: 8
                }
            },
            install: function() {
                return this.installSSLHooks();
            }
        });

        // JWT module
        this.registerModule("crypto.jwt", {
            name: "JWT Token Handling",
            version: "1.0.0",
            category: "cryptography",
            dependencies: ["crypto.base"],
            description: "JSON Web Token manipulation and spoofing",
            hooks: {
                "jwt_decode": {
                    strategy: "spoof_payload",
                    priority: 10
                },
                "jwt_verify": {
                    strategy: "force_verification_success",
                    priority: 10
                },
                "base64_decode": {
                    strategy: "spoof_jwt_base64",
                    priority: 9
                }
            },
            install: function() {
                return this.installJWTHooks();
            }
        });

        // OAuth module
        this.registerModule("crypto.oauth", {
            name: "OAuth Token Handling",
            version: "1.0.0",
            category: "cryptography",
            dependencies: ["crypto.base"],
            description: "OAuth token manipulation and spoofing",
            hooks: {
                "generateToken": {
                    strategy: "spoof_token_generation",
                    priority: 10
                },
                "validateToken": {
                    strategy: "force_validation_success",
                    priority: 10
                },
                "refreshToken": {
                    strategy: "spoof_token_refresh",
                    priority: 9
                }
            },
            install: function() {
                return this.installOAuthHooks();
            }
        });
    },

    registerVirtualizationModules: function() {
        send({
            type: "info",
            target: "virtualization_modules",
            action: "registering_virtualization_modules",
            category: "virtualization"
        });

        // VMware detection bypass
        this.registerModule("virtualization.vmware", {
            name: "VMware Detection Bypass",
            version: "1.0.0",
            category: "virtualization",
            dependencies: ["hardware.base"],
            description: "VMware virtualization detection bypass",
            hooks: {
                "VMware_Backdoor": {
                    strategy: "spoof_physical_hardware",
                    priority: 10
                },
                "VMware_Registry_Keys": {
                    strategy: "hide_vm_indicators",
                    priority: 9
                },
                "VMware_Processes": {
                    strategy: "hide_vm_processes",
                    priority: 8
                }
            },
            install: function() {
                return this.installVMwareBypassHooks();
            }
        });

        // VirtualBox detection bypass
        this.registerModule("virtualization.virtualbox", {
            name: "VirtualBox Detection Bypass",
            version: "1.0.0",
            category: "virtualization",
            dependencies: ["hardware.base"],
            description: "VirtualBox virtualization detection bypass",
            hooks: {
                "VirtualBox_Guest_Additions": {
                    strategy: "hide_guest_additions",
                    priority: 10
                },
                "VirtualBox_Hardware_IDs": {
                    strategy: "spoof_hardware_ids",
                    priority: 9
                },
                "VirtualBox_Services": {
                    strategy: "hide_vbox_services",
                    priority: 8
                }
            },
            install: function() {
                return this.installVirtualBoxBypassHooks();
            }
        });
    },

    registerIntegrityModules: function() {
        send({
            type: "info",
            target: "integrity_modules",
            action: "registering_integrity_modules",
            category: "integrity"
        });

        // Code integrity module
        this.registerModule("integrity.code", {
            name: "Code Integrity Bypass",
            version: "1.0.0",
            category: "integrity",
            dependencies: ["crypto.base"],
            description: "Code integrity check bypass",
            hooks: {
                "PE_Checksum_Validation": {
                    strategy: "spoof_checksums",
                    priority: 10
                },
                "Digital_Signature_Verification": {
                    strategy: "bypass_signature_checks",
                    priority: 10
                },
                "Hash_Verification": {
                    strategy: "spoof_hash_values",
                    priority: 9
                }
            },
            install: function() {
                return this.installCodeIntegrityHooks();
            }
        });

        // Memory integrity module
        this.registerModule("integrity.memory", {
            name: "Memory Integrity Bypass",
            version: "1.0.0",
            category: "integrity",
            dependencies: ["memory.base"],
            description: "Memory integrity check bypass",
            hooks: {
                "Memory_Checksum_Validation": {
                    strategy: "spoof_memory_checksums",
                    priority: 10
                },
                "Stack_Canary_Checks": {
                    strategy: "bypass_stack_protection",
                    priority: 9
                },
                "Heap_Integrity_Checks": {
                    strategy: "bypass_heap_protection",
                    priority: 8
                }
            },
            install: function() {
                return this.installMemoryIntegrityHooks();
            }
        });
    },

    registerHardwareModules: function() {
        send({
            type: "info",
            target: "hardware_modules",
            action: "registering_hardware_modules",
            category: "hardware"
        });

        // Base hardware module
        this.registerModule("hardware.base", {
            name: "Base Hardware Spoofing",
            version: "1.0.0",
            category: "hardware",
            dependencies: [],
            description: "Base hardware information spoofing",
            hooks: {
                "GetSystemInfo": {
                    module: "kernel32.dll",
                    strategy: "spoof_system_info",
                    priority: 10
                },
                "IsProcessorFeaturePresent": {
                    module: "kernel32.dll",
                    strategy: "spoof_cpu_features",
                    priority: 9
                },
                "GetComputerName": {
                    module: "kernel32.dll",
                    strategy: "spoof_computer_name",
                    priority: 8
                }
            },
            install: function() {
                return this.installBaseHardwareHooks();
            }
        });

        // TPM module
        this.registerModule("hardware.tpm", {
            name: "TPM Bypass",
            version: "1.0.0",
            category: "hardware",
            dependencies: ["hardware.base"],
            description: "Trusted Platform Module bypass",
            hooks: {
                "Tbsi_Context_Create": {
                    module: "tbs.dll",
                    strategy: "spoof_tpm_operations",
                    priority: 10
                },
                "TpmCreateContext": {
                    strategy: "spoof_tpm_context",
                    priority: 9
                }
            },
            install: function() {
                return this.installTPMHooks();
            }
        });
    },

    registerMemoryModules: function() {
        send({
            type: "info",
            target: "memory_modules",
            action: "registering_memory_modules",
            category: "memory"
        });

        // Base memory module
        this.registerModule("memory.base", {
            name: "Base Memory Operations",
            version: "1.0.0",
            category: "memory",
            dependencies: [],
            description: "Base memory operation hooks",
            hooks: {
                "VirtualAlloc": {
                    module: "kernel32.dll",
                    strategy: "monitor_allocations",
                    priority: 8
                },
                "VirtualProtect": {
                    module: "kernel32.dll",
                    strategy: "monitor_protection_changes",
                    priority: 8
                },
                "ReadProcessMemory": {
                    module: "kernel32.dll",
                    strategy: "monitor_memory_reads",
                    priority: 7
                }
            },
            install: function() {
                return this.installBaseMemoryHooks();
            }
        });

        // Memory protection module
        this.registerModule("memory.protection", {
            name: "Memory Protection Bypass",
            version: "1.0.0",
            category: "memory",
            dependencies: ["memory.base"],
            description: "Memory protection mechanism bypass",
            hooks: {
                "PAGE_NOACCESS_Protection": {
                    strategy: "convert_to_readwrite",
                    priority: 9
                },
                "DEP_Protection": {
                    strategy: "bypass_dep",
                    priority: 9
                },
                "ASLR_Protection": {
                    strategy: "bypass_aslr",
                    priority: 8
                }
            },
            install: function() {
                return this.installMemoryProtectionHooks();
            }
        });
    },

    registerRegistryModules: function() {
        send({
            type: "info",
            target: "registry_modules",
            action: "registering_registry_modules",
            category: "registry"
        });

        // Registry access module
        this.registerModule("registry.access", {
            name: "Registry Access Control",
            version: "1.0.0",
            category: "registry",
            dependencies: [],
            description: "Registry access interception and control",
            hooks: {
                "RegOpenKeyExW": {
                    module: "advapi32.dll",
                    strategy: "monitor_and_redirect",
                    priority: 10
                },
                "RegQueryValueExW": {
                    module: "advapi32.dll",
                    strategy: "spoof_values",
                    priority: 10
                },
                "RegSetValueExW": {
                    module: "advapi32.dll",
                    strategy: "intercept_writes",
                    priority: 9
                }
            },
            install: function() {
                return this.installRegistryAccessHooks();
            }
        });

        // Registry spoofing module
        this.registerModule("registry.spoofing", {
            name: "Registry Value Spoofing",
            version: "1.0.0",
            category: "registry",
            dependencies: ["registry.access"],
            description: "Registry value spoofing for license/activation bypass",
            hooks: {
                "License_Registry_Keys": {
                    strategy: "spoof_license_values",
                    priority: 10
                },
                "Hardware_Registry_Keys": {
                    strategy: "spoof_hardware_values",
                    priority: 9
                },
                "Software_Registry_Keys": {
                    strategy: "spoof_software_values",
                    priority: 8
                }
            },
            install: function() {
                return this.installRegistrySpoofingHooks();
            }
        });
    },

    // === MODULE MANAGEMENT ===
    registerModule: function(moduleId, moduleDefinition) {
        if (this.moduleRegistry.has(moduleId)) {
            send({
                type: "warning",
                target: "hook_library",
                action: "module_overwrite",
                module_id: moduleId,
                message: "Module already registered, overwriting"
            });
        }

        // Validate module definition
        if (!this.validateModuleDefinition(moduleDefinition)) {
            send({
                type: "error",
                target: "hook_library",
                action: "invalid_module_definition",
                module_id: moduleId
            });
            return false;
        }

        // Add metadata
        moduleDefinition.id = moduleId;
        moduleDefinition.registeredAt = Date.now();
        moduleDefinition.status = "registered";

        this.moduleRegistry.set(moduleId, moduleDefinition);
        send({
            type: "success",
            target: "hook_library",
            action: "module_registered",
            module_id: moduleId
        });

        return true;
    },

    validateModuleDefinition: function(module) {
        // Required fields
        if (!module.name || !module.version || !module.category) {
            return false;
        }

        // Valid category
        if (!this.config.categories[module.category]) {
            return false;
        }

        // Dependencies should be array
        if (module.dependencies && !Array.isArray(module.dependencies)) {
            return false;
        }

        // Hooks should be object
        if (module.hooks && typeof module.hooks !== 'object') {
            return false;
        }

        return true;
    },

    loadModule: function(moduleId, options) {
        send({
            type: "info",
            target: "hook_library",
            action: "loading_module",
            module_id: moduleId
        });

        options = options || {};

        try {
            // Check if already loaded
            if (this.loadedModules.has(moduleId)) {
                send({
                    type: "info",
                    target: "hook_library",
                    action: "module_already_loaded",
                    module_id: moduleId
                });
                return this.loadedModules.get(moduleId);
            }

            // Get module definition
            var moduleDefinition = this.moduleRegistry.get(moduleId);
            if (!moduleDefinition) {
                throw new Error("Module not found: " + moduleId);
            }

            // Check cache first
            if (this.config.library.enableCaching && this.moduleCache.has(moduleId)) {
                var cachedModule = this.moduleCache.get(moduleId);
                this.loadedModules.set(moduleId, cachedModule);
                this.stats.cacheHits++;
                send({
                    type: "info",
                    target: "hook_library",
                    action: "module_loaded_from_cache",
                    module_id: moduleId
                });
                return cachedModule;
            }

            this.stats.cacheMisses++;

            // Load dependencies first
            if (moduleDefinition.dependencies && moduleDefinition.dependencies.length > 0) {
                for (var i = 0; i < moduleDefinition.dependencies.length; i++) {
                    var depId = moduleDefinition.dependencies[i];
                    this.loadModule(depId);
                }
            }

            // Create module instance
            var moduleInstance = this.createModuleInstance(moduleDefinition, options);

            // Install the module
            if (moduleInstance.install) {
                var installResult = moduleInstance.install();
                if (!installResult) {
                    throw new Error("Module installation failed: " + moduleId);
                }
            }

            // Cache the module
            if (this.config.library.enableCaching) {
                this.cacheModule(moduleId, moduleInstance);
            }

            // Track loaded module
            this.loadedModules.set(moduleId, moduleInstance);
            this.stats.modulesLoaded++;

            send({
                type: "success",
                target: "hook_library",
                action: "module_loaded_successfully",
                module_id: moduleId
            });
            return moduleInstance;

        } catch (e) {
            send({
                type: "error",
                target: "hook_library",
                action: "module_load_error",
                module_id: moduleId,
                error: e.message || e.toString()
            });
            this.stats.errors++;
            return null;
        }
    },

    createModuleInstance: function(moduleDefinition, options) {
        var instance = {
            id: moduleDefinition.id,
            name: moduleDefinition.name,
            version: moduleDefinition.version,
            category: moduleDefinition.category,
            dependencies: moduleDefinition.dependencies || [],
            hooks: moduleDefinition.hooks || {},
            status: "loaded",
            loadedAt: Date.now(),
            options: options,

            // Copy methods from definition
            install: moduleDefinition.install || function() { return true; },
            uninstall: moduleDefinition.uninstall || function() { return true; },
            enable: moduleDefinition.enable || function() { return true; },
            disable: moduleDefinition.disable || function() { return true; },

            // Add management methods
            getHooks: function() {
                return Object.keys(this.hooks);
            },

            isInstalled: function() {
                return this.status === "installed";
            },

            isEnabled: function() {
                return this.status === "enabled";
            }
        };

        return instance;
    },

    unloadModule: function(moduleId) {
        send({
            type: "info",
            target: "hook_library",
            action: "module_unloading",
            module_id: moduleId
        });

        try {
            var moduleInstance = this.loadedModules.get(moduleId);
            if (!moduleInstance) {
                send({
                    type: "warning",
                    target: "hook_library",
                    action: "module_not_loaded",
                    module_id: moduleId
                });
                return false;
            }

            // Uninstall hooks
            if (moduleInstance.uninstall) {
                moduleInstance.uninstall();
            }

            // Remove from loaded modules
            this.loadedModules.delete(moduleId);

            // Remove from cache
            this.moduleCache.delete(moduleId);

            send({
                type: "success",
                target: "hook_library",
                action: "module_unloaded",
                module_id: moduleId
            });
            return true;

        } catch (e) {
            send({
                type: "error",
                target: "hook_library",
                action: "module_unload_error",
                module_id: moduleId,
                error: e.message || e.toString()
            });
            this.stats.errors++;
            return false;
        }
    },

    reloadModule: function(moduleId) {
        send({
            type: "info",
            target: "hook_library",
            action: "module_reloading",
            module_id: moduleId
        });

        this.unloadModule(moduleId);
        return this.loadModule(moduleId);
    },

    cacheModule: function(moduleId, moduleInstance) {
        if (this.moduleCache.size >= this.config.library.maxCacheSize) {
            // Remove oldest entry
            var oldestKey = this.moduleCache.keys().next().value;
            this.moduleCache.delete(oldestKey);
        }

        this.moduleCache.set(moduleId, moduleInstance);
    },

    // === HOOK MANAGEMENT ===
    installHook: function(hookId, hookDefinition, moduleId) {
        send({
            type: "info",
            target: "hook_library",
            action: "hook_installing",
            hook_id: hookId
        });

        try {
            var hookInfo = {
                id: hookId,
                definition: hookDefinition,
                moduleId: moduleId,
                installedAt: Date.now(),
                status: "installed",
                callCount: 0,
                successCount: 0,
                errorCount: 0
            };

            // Install the actual Frida hook based on strategy
            var fridaHook = this.createFridaHook(hookDefinition);
            if (fridaHook) {
                hookInfo.fridaHook = fridaHook;
                this.activeHooks.set(hookId, hookInfo);
                this.stats.hooksInstalled++;

                send({
            type: "success",
            target: "hook_library",
            action: "hook_installed",
            hook_id: hookId
        });
                return true;
            }

            return false;

        } catch (e) {
            send({
                type: "error",
                target: "hook_library",
                action: "hook_install_error",
                hook_id: hookId,
                error: e.message || e.toString()
            });
            this.stats.errors++;
            return false;
        }
    },

    createFridaHook: function(hookDefinition) {
        var strategy = hookDefinition.strategy;
        var target = hookDefinition.target || hookDefinition.module;

        try {
            switch (strategy) {
                case "replace_return":
                    return this.createReplaceReturnHook(hookDefinition);

                case "intercept_and_modify":
                    return this.createInterceptModifyHook(hookDefinition);

                case "monitor_and_log":
                    return this.createMonitorLogHook(hookDefinition);

                case "spoof_values":
                    return this.createSpoofValuesHook(hookDefinition);

                case "block_requests":
                    return this.createBlockRequestsHook(hookDefinition);

                default:
                    send({
                        type: "warning",
                        target: "hook_library",
                        action: "unknown_hook_strategy",
                        strategy: strategy
                    });
                    return null;
            }
        } catch (e) {
            send({
                type: "error",
                target: "hook_library",
                action: "frida_hook_creation_error",
                error: e.message || e.toString()
            });
            return null;
        }
    },

    createReplaceReturnHook: function(hookDefinition) {
        var targetFunc = Module.findExportByName(hookDefinition.module, hookDefinition.target);
        if (!targetFunc) {
            send({
                type: "warning",
                target: "hook_library",
                action: "function_not_found",
                target_function: hookDefinition.target
            });
            return null;
        }

        return Interceptor.replace(targetFunc, new NativeCallback(function() {
            send({
                type: "info",
                target: "hook_library",
                action: "hook_executed",
                target_function: hookDefinition.target
            });
            return hookDefinition.returnValue || 0;
        }, 'int', []));
    },

    createInterceptModifyHook: function(hookDefinition) {
        var targetFunc = Module.findExportByName(hookDefinition.module, hookDefinition.target);
        if (!targetFunc) {
            return null;
        }

        return Interceptor.attach(targetFunc, {
            onEnter: function(args) {
                this.args = args;
                this.hookDef = hookDefinition;
            },

            onLeave: function(retval) {
                if (this.hookDef.modifyReturn) {
                    retval.replace(this.hookDef.modifyReturn);
                }
                send({
                    type: "bypass",
                    target: "hook_library",
                    action: "intercept_hook_executed",
                    target_function: this.hookDef.target
                });
            }
        });
    },

    createMonitorLogHook: function(hookDefinition) {
        var targetFunc = Module.findExportByName(hookDefinition.module, hookDefinition.target);
        if (!targetFunc) {
            return null;
        }

        return Interceptor.attach(targetFunc, {
            onEnter: function(args) {
                send({
                    type: "info",
                    target: "hook_library",
                    action: "monitor_function_called",
                    target_function: hookDefinition.target
                });
            }
        });
    },

    createSpoofValuesHook: function(hookDefinition) {
        var targetFunc = Module.findExportByName(hookDefinition.module, hookDefinition.target);
        if (!targetFunc) {
            return null;
        }

        return Interceptor.attach(targetFunc, {
            onLeave: function(retval) {
                if (hookDefinition.spoofedValues) {
                    // Apply spoofed values based on hook configuration
                    send({
                        type: "bypass",
                        target: "hook_library",
                        action: "values_spoofed",
                        target_function: hookDefinition.target
                    });
                }
            }
        });
    },

    createBlockRequestsHook: function(hookDefinition) {
        var targetFunc = Module.findExportByName(hookDefinition.module, hookDefinition.target);
        if (!targetFunc) {
            return null;
        }

        return Interceptor.attach(targetFunc, {
            onLeave: function(retval) {
                retval.replace(-1); // Block by returning error
                send({
                    type: "bypass",
                    target: "hook_library",
                    action: "request_blocked",
                    target_function: hookDefinition.target
                });
            }
        });
    },

    uninstallHook: function(hookId) {
        send({
            type: "info",
            target: "hook_library",
            action: "hook_uninstalling",
            hook_id: hookId
        });

        var hookInfo = this.activeHooks.get(hookId);
        if (!hookInfo) {
            send({
                type: "warning",
                target: "hook_library",
                action: "hook_not_found",
                hook_id: hookId
            });
            return false;
        }

        try {
            if (hookInfo.fridaHook) {
                // Frida hooks are automatically cleaned up when script is unloaded
                // For manual cleanup, we would need to store the hook reference
            }

            this.activeHooks.delete(hookId);
            send({
                type: "success",
                target: "hook_library",
                action: "hook_uninstalled",
                hook_id: hookId
            });
            return true;

        } catch (e) {
            send({
                type: "error",
                target: "hook_library",
                action: "hook_uninstall_error",
                hook_id: hookId,
                error: e.message || e.toString()
            });
            return false;
        }
    },

    // === HOOK GROUPS AND CHAINS ===
    createHookGroup: function(groupId, hookIds, options) {
        send({
            type: "info",
            target: "hook_library",
            action: "hook_group_creating",
            group_id: groupId
        });

        var group = {
            id: groupId,
            hooks: hookIds,
            options: options || {},
            createdAt: Date.now(),
            status: "created"
        };

        this.hookGroups.set(groupId, group);
        return group;
    },

    executeHookGroup: function(groupId) {
        send({
            type: "info",
            target: "hook_library",
            action: "hook_group_executing",
            group_id: groupId
        });

        var group = this.hookGroups.get(groupId);
        if (!group) {
            send({
                type: "warning",
                target: "hook_library",
                action: "hook_group_not_found",
                group_id: groupId
            });
            return false;
        }

        var results = [];
        for (var i = 0; i < group.hooks.length; i++) {
            var hookId = group.hooks[i];
            var hookInfo = this.activeHooks.get(hookId);

            if (hookInfo) {
                results.push({hookId: hookId, status: "executed"});
                hookInfo.callCount++;
                this.stats.hooksExecuted++;
            } else {
                results.push({hookId: hookId, status: "not_found"});
            }
        }

        return results;
    },

    createHookChain: function(chainId, hookIds, options) {
        send({
            type: "info",
            target: "hook_library",
            action: "hook_chain_creating",
            chain_id: chainId
        });

        var chain = {
            id: chainId,
            hooks: hookIds,
            options: options || {},
            createdAt: Date.now(),
            status: "created"
        };

        this.hookChains.set(chainId, chain);
        return chain;
    },

    executeHookChain: function(chainId) {
        send({
            type: "info",
            target: "hook_library",
            action: "hook_chain_executing",
            chain_id: chainId
        });

        var chain = this.hookChains.get(chainId);
        if (!chain) {
            send({
                type: "warning",
                target: "hook_library",
                action: "hook_chain_not_found",
                chain_id: chainId
            });
            return false;
        }

        // Execute hooks in sequence with dependency checking
        var results = [];
        for (var i = 0; i < chain.hooks.length; i++) {
            var hookId = chain.hooks[i];
            var hookInfo = this.activeHooks.get(hookId);

            if (hookInfo) {
                // Check if previous hooks succeeded (if required)
                if (chain.options.stopOnFailure && results.some(r => r.status === "failed")) {
                    results.push({hookId: hookId, status: "skipped"});
                    continue;
                }

                results.push({hookId: hookId, status: "executed"});
                hookInfo.callCount++;
                this.stats.hooksExecuted++;
            } else {
                results.push({hookId: hookId, status: "not_found"});
            }
        }

        return results;
    },

    // === DEPENDENCY MANAGEMENT ===
    setupDependencyManager: function() {
        send({
            type: "info",
            target: "dependency_manager",
            action: "setting_up_dependency_manager",
            component: "dependency_system"
        });

        if (this.config.library.enableDependencyTracking) {
            this.buildDependencyGraph();
        }
    },

    buildDependencyGraph: function() {
        send({
            type: "info",
            target: "dependency_manager",
            action: "building_dependency_graph",
            component: "dependency_graph"
        });

        this.dependencyGraph.clear();

        this.moduleRegistry.forEach((module, moduleId) => {
            if (module.dependencies && module.dependencies.length > 0) {
                this.dependencyGraph.set(moduleId, module.dependencies);
            }
        });

        // Check for circular dependencies
        if (this.detectCircularDependencies()) {
            send({
                type: "warning",
                target: "dependency_manager",
                action: "circular_dependencies_detected",
                component: "dependency_validation"
            });
        }
    },

    detectCircularDependencies: function() {
        var visited = new Set();
        var recursionStack = new Set();

        for (var moduleId of this.dependencyGraph.keys()) {
            if (this.hasCycle(moduleId, visited, recursionStack)) {
                return true;
            }
        }

        return false;
    },

    hasCycle: function(moduleId, visited, recursionStack) {
        if (recursionStack.has(moduleId)) {
            return true;
        }

        if (visited.has(moduleId)) {
            return false;
        }

        visited.add(moduleId);
        recursionStack.add(moduleId);

        var dependencies = this.dependencyGraph.get(moduleId) || [];
        for (var i = 0; i < dependencies.length; i++) {
            var dep = dependencies[i];
            if (this.hasCycle(dep, visited, recursionStack)) {
                return true;
            }
        }

        recursionStack.delete(moduleId);
        return false;
    },

    resolveDependencies: function(moduleId) {
        var resolved = [];
        var resolving = new Set();

        return this.resolveDependenciesRecursive(moduleId, resolved, resolving);
    },

    resolveDependenciesRecursive: function(moduleId, resolved, resolving) {
        if (resolving.has(moduleId)) {
            throw new Error("Circular dependency detected: " + moduleId);
        }

        if (resolved.indexOf(moduleId) !== -1) {
            return resolved;
        }

        resolving.add(moduleId);

        var module = this.moduleRegistry.get(moduleId);
        if (module && module.dependencies) {
            for (var i = 0; i < module.dependencies.length; i++) {
                var dep = module.dependencies[i];
                this.resolveDependenciesRecursive(dep, resolved, resolving);
            }
        }

        resolving.delete(moduleId);
        resolved.push(moduleId);

        return resolved;
    },

    // === HOOK EXECUTOR ===
    setupHookExecutor: function() {
        send({
            type: "info",
            target: "hook_executor",
            action: "setting_up_hook_executor",
            component: "execution_engine"
        });

        this.hookExecutor = {
            executeAsync: this.config.execution.enableAsync,
            batchExecution: this.config.execution.enableBatching,
            retryOnFailure: this.config.execution.enableRetry,
            maxRetries: this.config.execution.maxRetries,
            timeout: this.config.execution.timeout
        };
    },

    // === PERFORMANCE MONITORING ===
    setupPerformanceMonitor: function() {
        send({
            type: "info",
            target: "performance_monitor",
            action: "setting_up_performance_monitor",
            component: "monitoring_system"
        });

        if (this.config.debug.measurePerformance) {
            setInterval(() => {
                this.updatePerformanceMetrics();
            }, 30000); // Update every 30 seconds
        }
    },

    updatePerformanceMetrics: function() {
        var totalTime = 0;
        var totalExecutions = 0;

        this.activeHooks.forEach((hookInfo) => {
            totalExecutions += hookInfo.callCount;
            // totalTime would be calculated from actual hook execution times
        });

        if (totalExecutions > 0) {
            this.stats.totalExecutionTime = totalTime;
            this.stats.avgExecutionTime = totalTime / totalExecutions;
        }

        this.stats.hooksExecuted = totalExecutions;
    },

    // === LIBRARY SERVICES ===
    startLibraryServices: function() {
        send({
            type: "status",
            target: "library_services",
            action: "starting_library_services",
            component: "service_manager"
        });

        // Auto-load configured modules
        if (this.config.library.autoLoad) {
            this.autoLoadModules();
        }

        // Start conflict detection
        if (this.config.library.enableConflictDetection) {
            this.startConflictDetection();
        }

        // Start performance monitoring
        if (this.config.debug.measurePerformance) {
            this.startPerformanceMonitoring();
        }
    },

    autoLoadModules: function() {
        send({
            type: "info",
            target: "auto_loader",
            action: "auto_loading_modules",
            component: "module_loader"
        });

        // Load essential modules
        var essentialModules = [
            "antidebug.basic",
            "networking.http",
            "crypto.base",
            "hardware.base",
            "memory.base",
            "registry.access"
        ];

        for (var i = 0; i < essentialModules.length; i++) {
            var moduleId = essentialModules[i];
            if (this.moduleRegistry.has(moduleId)) {
                this.loadModule(moduleId);
            }
        }
    },

    startConflictDetection: function() {
        send({
            type: "info",
            target: "conflict_detection",
            action: "starting_conflict_detection",
            component: "conflict_detector"
        });

        // This would monitor for conflicting hooks
        // For now, just log that it's started
        send({
            type: "success",
            target: "conflict_detection",
            action: "conflict_detection_service_started",
            component: "conflict_detector"
        });
    },

    startPerformanceMonitoring: function() {
        send({
            type: "info",
            target: "performance_monitoring",
            action: "starting_performance_monitoring",
            component: "performance_monitor"
        });

        setInterval(() => {
            this.logPerformanceMetrics();
        }, 60000); // Log every minute
    },

    logPerformanceMetrics: function() {
        send({
            type: "info",
            target: "modular_hook_library",
            action: "performance_stats",
            modules_loaded: this.stats.modulesLoaded,
            hooks_installed: this.stats.hooksInstalled,
            hooks_executed: this.stats.hooksExecuted,
            cache_hits: this.stats.cacheHits,
            cache_misses: this.stats.cacheMisses
        });
    },

    // === API METHODS ===
    getModuleInfo: function(moduleId) {
        return this.moduleRegistry.get(moduleId);
    },

    getLoadedModules: function() {
        return Array.from(this.loadedModules.keys());
    },

    getActiveHooks: function() {
        return Array.from(this.activeHooks.keys());
    },

    getModulesByCategory: function(category) {
        var modules = [];
        this.moduleRegistry.forEach((module, moduleId) => {
            if (module.category === category) {
                modules.push(moduleId);
            }
        });
        return modules;
    },

    getStatistics: function() {
        return Object.assign({}, this.stats);
    },

    // === INSTALLATION SUMMARY ===
    installSummary: function() {
        setTimeout(() => {
            send({
                type: "status",
                target: "summary",
                action: "displaying_library_summary",
                section: "header"
            });

            var activeFeatures = [];

            if (this.config.library.enabled) {
                activeFeatures.push("Core Library System");
            }
            if (this.config.library.enableCaching) {
                activeFeatures.push("Module Caching");
            }
            if (this.config.library.enableDependencyTracking) {
                activeFeatures.push("Dependency Management");
            }
            if (this.config.execution.enableAsync) {
                activeFeatures.push("Async Execution");
            }
            if (this.config.execution.enableBatching) {
                activeFeatures.push("Hook Batching");
            }
            if (this.config.performance.enableLazyLoading) {
                activeFeatures.push("Lazy Loading");
            }

            for (var i = 0; i < activeFeatures.length; i++) {
                send({
                    type: "info",
                    target: "hook_library",
                    action: "active_feature_listed",
                    feature: activeFeatures[i]
                });
            }

            send({
                type: "info",
                target: "summary",
                action: "displaying_module_categories",
                section: "categories"
            });

            var categories = Object.keys(this.config.categories);
            for (var i = 0; i < categories.length; i++) {
                var category = categories[i];
                if (this.config.categories[category]) {
                    var moduleCount = this.getModulesByCategory(category).length;
                    send({
                        type: "info",
                        target: "hook_library",
                        action: "category_module_count",
                        category: category,
                        module_count: moduleCount
                    });
                }
            }

            send({
                type: "info",
                target: "modular_hook_library",
                action: "status_separator"
            });
            send({
                type: "info",
                target: "hook_library",
                action: "library_configuration_header"
            });
            send({
                type: "info",
                target: "hook_library",
                action: "config_auto_load",
                value: this.config.library.autoLoad
            });
            send({
                type: "info",
                target: "hook_library",
                action: "config_caching",
                value: this.config.library.enableCaching
            });
            send({
                type: "info",
                target: "hook_library",
                action: "config_cache_size",
                value: this.config.library.maxCacheSize
            });
            send({
                type: "info",
                target: "hook_library",
                action: "config_dependency_tracking",
                value: this.config.library.enableDependencyTracking
            });
            send({
                type: "info",
                target: "hook_library",
                action: "config_conflict_detection",
                value: this.config.library.enableConflictDetection
            });

            send({
                type: "info",
                target: "modular_hook_library",
                action: "status_separator"
            });
            send({
                type: "info",
                target: "modular_hook_library",
                action: "execution_settings_header"
            });
            send({
                type: "info",
                target: "modular_hook_library",
                action: "config_setting",
                setting: "async_execution",
                value: this.config.execution.enableAsync
            });
            send({
                type: "info",
                target: "modular_hook_library",
                action: "config_setting",
                setting: "hook_batching",
                value: this.config.execution.enableBatching
            });
            send({
                type: "info",
                target: "modular_hook_library",
                action: "config_setting",
                setting: "retry_on_failure",
                value: this.config.execution.enableRetry
            });
            send({
                type: "info",
                target: "modular_hook_library",
                action: "config_setting",
                setting: "max_retries",
                value: this.config.execution.maxRetries
            });
            send({
                type: "info",
                target: "modular_hook_library",
                action: "config_setting",
                setting: "timeout",
                value: this.config.execution.timeout + "ms"
            });

            send({
                type: "info",
                target: "modular_hook_library",
                action: "status_separator"
            });
            send({
                type: "info",
                target: "modular_hook_library",
                action: "runtime_statistics_header"
            });
            send({
                type: "info",
                target: "modular_hook_library",
                action: "runtime_statistic",
                metric: "registered_modules",
                value: this.moduleRegistry.size
            });
            send({
                type: "info",
                target: "modular_hook_library",
                action: "runtime_statistic",
                metric: "loaded_modules",
                value: this.stats.modulesLoaded
            });
            send({
                type: "info",
                target: "modular_hook_library",
                action: "runtime_statistic",
                metric: "installed_hooks",
                value: this.stats.hooksInstalled
            });
            send({
                type: "info",
                target: "modular_hook_library",
                action: "runtime_statistic",
                metric: "cache_hits",
                value: this.stats.cacheHits
            });
            send({
                type: "info",
                target: "modular_hook_library",
                action: "runtime_statistic",
                metric: "cache_misses",
                value: this.stats.cacheMisses
            });
            send({
                type: "info",
                target: "modular_hook_library",
                action: "runtime_statistic",
                metric: "cache_hit_rate",
                value: (this.stats.cacheHits / (this.stats.cacheHits + this.stats.cacheMisses) * 100).toFixed(1) + "%"
            });

            send({
                type: "info",
                target: "modular_hook_library",
                action: "status_separator"
            });
            send({
                type: "info",
                target: "modular_hook_library",
                action: "available_modules_header"
            });

            var modulesByCategory = {};
            this.moduleRegistry.forEach((module, moduleId) => {
                if (!modulesByCategory[module.category]) {
                    modulesByCategory[module.category] = [];
                }
                modulesByCategory[module.category].push(moduleId);
            });

            for (var category in modulesByCategory) {
                send({
                    type: "info",
                    target: "modular_hook_library",
                    action: "module_category",
                    category: category
                });
                var modules = modulesByCategory[category];
                for (var i = 0; i < modules.length; i++) {
                    var moduleId = modules[i];
                    var isLoaded = this.loadedModules.has(moduleId);
                    var status = isLoaded ? "loaded" : "available";
                    send({
                        type: "info",
                        target: "modular_hook_library",
                        action: "module_status",
                        module_id: moduleId,
                        status: status
                    });
                }
            }

            send({
                type: "info",
                target: "modular_hook_library",
                action: "status_separator"
            });
            send({
                type: "success",
                target: "modular_hook_library",
                action: "system_active"
            });
            send({
                type: "info",
                target: "modular_hook_library",
                action: "usage_instructions"
            });
        }, 100);
    }
}

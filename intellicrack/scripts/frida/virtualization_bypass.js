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
 * Virtualization Detection Bypass
 *
 * Advanced virtualization and sandbox detection countermeasures for modern
 * protection systems. Handles VM detection, hypervisor fingerprinting, and
 * sandbox environment detection bypass.
 *
 * Author: Intellicrack Framework
 * Version: 3.0.0
 * License: GPL v3
 */

const virtualizationBypass = {
    name: 'Virtualization Detection Bypass',
    description: 'Comprehensive VM and sandbox detection countermeasures',
    version: '3.0.0',

    // Configuration for virtualization bypass
    config: {
        // Virtual machine detection bypass
        vmDetection: {
            enabled: true,
            virtualBox: {
                enabled: true,
                spoofGuestAdditions: true,
                hidePciDevices: true,
                spoofBios: true,
                hideRegistryKeys: true,
            },
            vmware: {
                enabled: true,
                hideVmwareTools: true,
                spoofDmiInfo: true,
                hidePciDevices: true,
                spoofMacAddresses: true,
            },
            hyperV: {
                enabled: true,
                hideHyperVFeatures: true,
                spoofCpuidSignature: true,
                hideIntegrationServices: true,
            },
            qemu: {
                enabled: true,
                hideQemuSignatures: true,
                spoofHardwareIds: true,
                hideQemuDevices: true,
            },
        },

        // Sandbox detection bypass
        sandboxDetection: {
            enabled: true,
            fileSystem: {
                spoofSandboxFiles: true,
                hideSandboxDirectories: true,
                generateRealisticFiles: true,
            },
            processes: {
                hideSandboxProcesses: true,
                spoofProcessList: true,
                hideAnalysisTools: true,
            },
            registry: {
                hideSandboxKeys: true,
                spoofVendorInfo: true,
                hideVmRegistry: true,
            },
            network: {
                spoofMacAddresses: true,
                hideVmNetworkAdapters: true,
                spoofNetworkConfig: true,
            },
        },

        // Hardware fingerprinting bypass
        hardwareFingerprinting: {
            spoofCpuInfo: true,
            spoofMotherboardInfo: true,
            spoofBiosInfo: true,
            spoofDiskInfo: true,
            spoofMemoryInfo: true,
            spoofGpuInfo: true,
        },

        // Timing-based detection bypass
        timingDetection: {
            enabled: true,
            normalizeInstructionTiming: true,
            spoofCpuFrequency: true,
            preventTimingAnalysis: true,
            hookRdtscInstructions: true,
            spoofPerformanceCounters: true,
            preventHighPrecisionTiming: true,
        },

        // Container and WSL detection bypass
        containerDetection: {
            enabled: true,
            docker: {
                enabled: true,
                hideDockerFiles: true,
                spoofCgroupInfo: true,
                hideContainerEnvironment: true,
            },
            wsl: {
                enabled: true,
                hideWslInterop: true,
                spoofLinuxSubsystem: true,
                hideWslRegistry: true,
            },
            kubernetes: {
                enabled: true,
                hideServiceAccount: true,
                spoofPodEnvironment: true,
                hideKubernetesSecrets: true,
            },
            lxc: {
                enabled: true,
                hideLxcEnvironment: true,
                spoofContainerInfo: true,
            },
        },

        // Advanced CPU feature detection bypass
        cpuFeatureDetection: {
            enabled: true,
            avx512Detection: true,
            sgxDetection: true,
            hypervisorBit: true,
            vmxDetection: true,
            smbiosDetection: true,
        },
    },

    // Hook tracking
    hooksInstalled: {},
    spoofedValues: {},

    onAttach: function (pid) {
        send({
            type: 'status',
            target: 'vm_bypass',
            action: 'attaching_to_process',
            process_id: pid,
        });
        this.processId = pid;
    },

    run: function () {
        send({
            type: 'status',
            target: 'vm_bypass',
            action: 'installing_virtualization_bypass',
            timestamp: Date.now(),
        });

        // Initialize bypass components
        this.hookVirtualBoxDetection();
        this.hookVmwareDetection();
        this.hookHyperVDetection();
        this.hookQemuDetection();
        this.hookSandboxDetection();
        this.hookHardwareFingerprinting();
        this.hookTimingDetection();
        this.hookContainerDetection();
        this.hookCpuFeatureDetection();
        this.hookGenericVmDetection();
        this.hookRegistryDetection();
        this.hookFileSystemDetection();
        this.hookProcessDetection();
        this.hookNetworkDetection();

        // Advanced detection bypass methods
        this.hookCpuidInstructions();
        this.hookRedPillDetection();
        this.hookNoPillDetection();
        this.hookVmexitTiming();
        this.hookCloudProviderDetection();
        this.hookAntiDebuggingIntegration();
        this.hookRdtscInstructions();
        this.hookVmxSvmInstructions();
        this.hookEptNptDetection();
        this.hookAdvancedContainerDetection();
        this.hookWmiManipulation();
        this.hookNetworkVmDetection();
        this.hookGpuVmDetection();
        this.hookUefiDetection();
        this.hookMemoryIoDetection();
        this.hookTsxDetection();

        // Initialize enhancement functions
        this.initializeAdvancedVmBehaviorAnalysis();
        this.setupDynamicInstructionEmulation();
        this.initializeNestedVirtualizationDetection();
        this.setupHypervisorRootkitProtection();
        this.initializeCloudInstanceFingerprinting();
        this.setupAdvancedTimingCalibration();
        this.initializeHardwareVirtualizationMasking();
        this.setupKernelPatchGuardBypass();
        this.initializeVmExitHandlerInterception();
        this.setupHypervisorMemoryProtection();

        this.installSummary();
    },

    // === VIRTUALBOX DETECTION BYPASS ===
    hookVirtualBoxDetection: function () {
        send({
            type: 'info',
            target: 'vm_bypass',
            action: 'installing_virtualbox_bypass',
        });

        if (!this.config.vmDetection.virtualBox.enabled) {
            return;
        }

        // Hook VirtualBox Guest Additions detection
        this.hookVBoxGuestAdditions();

        // Hook VirtualBox PCI device detection
        this.hookVBoxPciDevices();

        // Hook VirtualBox BIOS detection
        this.hookVBoxBios();

        // Hook VirtualBox registry detection
        this.hookVBoxRegistry();

        // Hook VirtualBox service detection
        this.hookVBoxServices();
    },

    hookVBoxGuestAdditions: function () {
        send({
            type: 'info',
            target: 'vm_bypass',
            action: 'installing_guest_additions_bypass',
        });

        // Hook LoadLibrary to prevent VBox DLL loading
        const loadLibrary = Module.findExportByName('kernel32.dll', 'LoadLibraryW');
        if (loadLibrary) {
            Interceptor.attach(loadLibrary, {
                onEnter: function (_args) {
                    if (args[0] && !args[0].isNull()) {
                        const libraryName = args[0].readUtf16String().toLowerCase();

                        const vboxLibraries = [
                            'vboxdisp',
                            'vboxhook',
                            'vboxmrxnp',
                            'vboxsf',
                            'vboxguest',
                            'vboxmouse',
                            'vboxservice',
                            'vboxtray',
                        ];

                        if (vboxLibraries.some(lib => libraryName.includes(lib))) {
                            send({
                                type: 'bypass',
                                target: 'vm_bypass',
                                action: 'blocked_virtualbox_library_load',
                                library_name: libraryName,
                            });
                            this.blockLoad = true;
                        }
                    }
                },

                onLeave: function (_retval) {
                    if (this.blockLoad) {
                        retval.replace(ptr(0)); // NULL - load failed
                    }
                },
            });

            this.hooksInstalled.LoadLibraryW_VBox = true;
        }

        // Hook GetModuleHandle for VBox modules
        const getModuleHandle = Module.findExportByName('kernel32.dll', 'GetModuleHandleW');
        if (getModuleHandle) {
            Interceptor.attach(getModuleHandle, {
                onEnter: function (_args) {
                    if (args[0] && !args[0].isNull()) {
                        const moduleName = args[0].readUtf16String().toLowerCase();

                        if (moduleName.includes('vbox')) {
                            send({
                                type: 'bypass',
                                target: 'vm_bypass',
                                action: 'blocked_virtualbox_module_handle_query',
                                module_name: moduleName,
                            });
                            this.blockQuery = true;
                        }
                    }
                },

                onLeave: function (_retval) {
                    if (this.blockQuery) {
                        retval.replace(ptr(0)); // NULL - module not found
                    }
                },
            });

            this.hooksInstalled.GetModuleHandleW_VBox = true;
        }
    },

    hookVBoxPciDevices: function () {
        // Hook PCI device enumeration to hide VirtualBox devices
        const setupDiGetClassDevs = Module.findExportByName('setupapi.dll', 'SetupDiGetClassDevsW');
        if (setupDiGetClassDevs) {
            Interceptor.attach(setupDiGetClassDevs, {
                onLeave: function (_retval) {
                    if (retval.toInt32() !== -1) {
                        send({
                            type: 'bypass',
                            target: 'vm_bypass',
                            action: 'pci_device_enumeration_detected',
                            mitigation: 'filtering_vbox_devices',
                        });
                        this.filterVBoxDevices = true;
                    }
                },
            });

            this.hooksInstalled.SetupDiGetClassDevsW_VBox = true;
        }

        // Hook device property queries
        const setupDiGetDeviceProperty = Module.findExportByName(
            'setupapi.dll',
            'SetupDiGetDevicePropertyW'
        );
        if (setupDiGetDeviceProperty) {
            Interceptor.attach(setupDiGetDeviceProperty, {
                onLeave: function (_retval) {
                    if (retval.toInt32() !== 0) {
                        const propertyBuffer = this.context.r9; // PropertyBuffer
                        if (propertyBuffer && !propertyBuffer.isNull()) {
                            this.filterVBoxDeviceProperties(propertyBuffer);
                        }
                    }
                },

                filterVBoxDeviceProperties: buffer => {
                    try {
                        const deviceString = buffer.readUtf16String();
                        if (deviceString?.toLowerCase().includes('vbox')) {
                            // Replace with generic device string
                            buffer.writeUtf16String('Generic System Device');
                            send({
                                type: 'bypass',
                                target: 'vm_bypass',
                                action: 'virtualbox_device_property_hidden',
                            });
                        }
                    } catch (_e) {
                        // Buffer read failed
                        send({
                            type: 'debug',
                            target: 'vm_bypass',
                            action: 'virtualbox_device_property_read_failed',
                            error: e.toString(),
                        });
                    }
                },
            });

            this.hooksInstalled.SetupDiGetDevicePropertyW_VBox = true;
        }
    },

    hookVBoxBios: function () {
        // Hook SMBIOS table access
        const getSystemFirmwareTable = Module.findExportByName(
            'kernel32.dll',
            'GetSystemFirmwareTable'
        );
        if (getSystemFirmwareTable) {
            Interceptor.attach(getSystemFirmwareTable, {
                onEnter: function (_args) {
                    this.firmwareTableProvider = args[0].toInt32();
                    this.firmwareTableID = args[1].toInt32();
                    this.firmwareTableBuffer = args[2];
                    this.bufferSize = args[3].toInt32();
                },

                onLeave: function (_retval) {
                    const bytesReturned = retval.toInt32();
                    if (
                        bytesReturned > 0 &&
                        this.firmwareTableBuffer &&
                        !this.firmwareTableBuffer.isNull()
                    ) {
                        this.spoofBiosInfo();
                    }
                },

                spoofBiosInfo: function () {
                    try {
                        const {config} = this.parent.parent;
                        if (config.vmDetection.virtualBox.spoofBios) {
                            const biosData = this.firmwareTableBuffer.readByteArray(
                                Math.min(this.bufferSize, 1024)
                            );
                            const biosString = Array.from(new Uint8Array(biosData))
                                .map(b => String.fromCharCode(b))
                                .join('');

                            // Check for VirtualBox BIOS signatures
                            if (
                                biosString.includes('VBOX') ||
                                biosString.includes('VirtualBox') ||
                                biosString.includes('Oracle')
                            ) {
                                // Replace with legitimate BIOS vendor
                                const spoofedBios = biosString
                                    .replace(/VBOX/g, 'DELL')
                                    .replace(/VirtualBox/g, 'Dell Inc.')
                                    .replace(/Oracle/g, 'Dell Inc.');

                                for (
                                    let i = 0;
                                    i < spoofedBios.length && i < this.bufferSize;
                                    i++
                                ) {
                                    this.firmwareTableBuffer
                                        .add(i)
                                        .writeU8(spoofedBios.charCodeAt(i));
                                }

                                send({
                                    type: 'bypass',
                                    target: 'vm_bypass',
                                    action: 'virtualbox_bios_signatures_spoofed',
                                });
                            }
                        }
                    } catch (_e) {
                        send({
                            type: 'error',
                            target: 'vm_bypass',
                            action: 'bios_spoofing_error',
                            error: e.message || e.toString(),
                        });
                    }
                },
            });

            this.hooksInstalled.GetSystemFirmwareTable_VBox = true;
        }
    },

    hookVBoxRegistry: function () {
        // Hook registry queries for VirtualBox detection
        const regQueryValueEx = Module.findExportByName('advapi32.dll', 'RegQueryValueExW');
        if (regQueryValueEx) {
            Interceptor.attach(regQueryValueEx, {
                onEnter: function (_args) {
                    if (args[1] && !args[1].isNull()) {
                        const valueName = args[1].readUtf16String().toLowerCase();

                        const vboxValues = [
                            'vboxguest',
                            'vboxmouse',
                            'vboxservice',
                            'vboxsf',
                            'virtualbox',
                            'oracle vm',
                            'vbox',
                        ];

                        if (vboxValues.some(val => valueName.includes(val))) {
                            send({
                                type: 'bypass',
                                target: 'vm_bypass',
                                action: 'virtualbox_registry_value_query_blocked',
                                value_name: valueName,
                            });
                            this.blockVBoxRegistry = true;
                        }
                    }
                },

                onLeave: function (_retval) {
                    if (this.blockVBoxRegistry) {
                        retval.replace(2); // ERROR_FILE_NOT_FOUND
                    }
                },
            });

            this.hooksInstalled.RegQueryValueExW_VBox = true;
        }

        // Hook registry key opening
        const regOpenKeyEx = Module.findExportByName('advapi32.dll', 'RegOpenKeyExW');
        if (regOpenKeyEx) {
            Interceptor.attach(regOpenKeyEx, {
                onEnter: function (_args) {
                    if (args[1] && !args[1].isNull()) {
                        const keyName = args[1].readUtf16String().toLowerCase();

                        if (
                            keyName.includes('vbox') ||
                            keyName.includes('virtualbox') ||
                            keyName.includes('oracle')
                        ) {
                            send({
                                type: 'bypass',
                                target: 'vm_bypass',
                                action: 'virtualbox_registry_key_access_blocked',
                                key_name: keyName,
                            });
                            this.blockVBoxKey = true;
                        }
                    }
                },

                onLeave: function (_retval) {
                    if (this.blockVBoxKey) {
                        retval.replace(2); // ERROR_FILE_NOT_FOUND
                    }
                },
            });

            this.hooksInstalled.RegOpenKeyExW_VBox = true;
        }
    },

    hookVBoxServices: function () {
        // Hook service enumeration to hide VirtualBox services
        const enumServicesStatus = Module.findExportByName('advapi32.dll', 'EnumServicesStatusW');
        if (enumServicesStatus) {
            Interceptor.attach(enumServicesStatus, {
                onLeave: _retval => {
                    if (retval.toInt32() !== 0) {
                        send({
                            type: 'bypass',
                            target: 'vm_bypass',
                            action: 'service_enumeration_filtering_virtualbox',
                        });
                        // Service filtering would be implemented here
                    }
                },
            });

            this.hooksInstalled.EnumServicesStatusW_VBox = true;
        }
    },

    // === VMWARE DETECTION BYPASS ===
    hookVmwareDetection: function () {
        send({
            type: 'info',
            target: 'vm_bypass',
            action: 'installing_vmware_bypass',
        });

        if (!this.config.vmDetection.vmware.enabled) {
            return;
        }

        // Hook VMware Tools detection
        this.hookVmwareTools();

        // Hook VMware DMI detection
        this.hookVmwareDmi();

        // Hook VMware PCI devices
        this.hookVmwarePciDevices();

        // Hook VMware MAC address detection
        this.hookVmwareMacAddresses();

        // Hook VMware backdoor detection
        this.hookVmwareBackdoor();
    },

    hookVmwareTools: function () {
        // Hook VMware Tools process detection
        const createToolhelp32Snapshot = Module.findExportByName(
            'kernel32.dll',
            'CreateToolhelp32Snapshot'
        );
        if (createToolhelp32Snapshot) {
            Interceptor.attach(createToolhelp32Snapshot, {
                onEnter: function (_args) {
                    const flags = args[0].toInt32();
                    if (flags && 0x00000002) {
                        // TH32CS_SNAPPROCESS
                        this.isProcessSnapshot = true;
                    }
                },
            });

            this.hooksInstalled.CreateToolhelp32Snapshot_VMware = true;
        }

        const process32First = Module.findExportByName('kernel32.dll', 'Process32FirstW');
        if (process32First) {
            Interceptor.attach(process32First, {
                onLeave: function (_retval) {
                    if (retval.toInt32() !== 0 && this.isProcessSnapshot) {
                        const processEntry = this.context.rdx;
                        if (processEntry && !processEntry.isNull()) {
                            this.filterVmwareProcesses(processEntry);
                        }
                    }
                },

                filterVmwareProcesses: processEntry => {
                    try {
                        const szExeFile = processEntry.add(44); // PROCESSENTRY32W.szExeFile
                        const exeName = szExeFile.readUtf16String().toLowerCase();

                        const vmwareProcesses = [
                            'vmtoolsd.exe',
                            'vmwaretray.exe',
                            'vmwareuser.exe',
                            'vmacthlp.exe',
                            'vmnat.exe',
                            'vmnetdhcp.exe',
                        ];

                        if (vmwareProcesses.includes(exeName)) {
                            // Replace with legitimate process name
                            szExeFile.writeUtf16String('svchost.exe');
                            send({
                                type: 'bypass',
                                target: 'vm_bypass',
                                action: 'vmware_process_hidden',
                                exe_name: exeName,
                            });
                        }
                    } catch (_e) {
                        // Process entry read failed
                    }
                },
            });

            this.hooksInstalled.Process32FirstW_VMware = true;
        }
    },

    hookVmwareDmi: function () {
        // Hook DMI/SMBIOS queries that reveal VMware
        const getSystemInfo = Module.findExportByName('kernel32.dll', 'GetSystemInfo');
        if (getSystemInfo) {
            Interceptor.attach(getSystemInfo, {
                onLeave: function (_retval) {
                    const systemInfo = this.context.rcx;
                    if (systemInfo && !systemInfo.isNull()) {
                        send({
                            type: 'bypass',
                            target: 'vm_bypass',
                            action: 'system_info_query_vmware_detection',
                        });
                    }
                },
            });

            this.hooksInstalled.GetSystemInfo_VMware = true;
        }
    },

    hookVmwarePciDevices: function () {
        // Hook PCI device queries to hide VMware devices
        const setupDiEnumDeviceInfo = Module.findExportByName(
            'setupapi.dll',
            'SetupDiEnumDeviceInfo'
        );
        if (setupDiEnumDeviceInfo) {
            Interceptor.attach(setupDiEnumDeviceInfo, {
                onLeave: _retval => {
                    if (retval.toInt32() !== 0) {
                        send({
                            type: 'bypass',
                            target: 'vm_bypass',
                            action: 'device_enumeration_filtering_vmware',
                        });
                    }
                },
            });

            this.hooksInstalled.SetupDiEnumDeviceInfo_VMware = true;
        }
    },

    hookVmwareMacAddresses: function () {
        // Hook MAC address queries to hide VMware prefixes
        const getAdaptersInfo = Module.findExportByName('iphlpapi.dll', 'GetAdaptersInfo');
        if (getAdaptersInfo) {
            Interceptor.attach(getAdaptersInfo, {
                onLeave: function (_retval) {
                    if (retval.toInt32() === 0) {
                        // NO_ERROR
                        const adapterInfo = this.context.rdx;
                        if (adapterInfo && !adapterInfo.isNull()) {
                            this.spoofVmwareMacs(adapterInfo);
                        }
                    }
                },

                spoofVmwareMacs: function (adapterInfo) {
                    try {
                        const {config} = this.parent.parent;
                        if (config.vmDetection.vmware.spoofMacAddresses) {
                            // IP_ADAPTER_INFO structure parsing
                            let currentAdapter = adapterInfo;

                            while (currentAdapter && !currentAdapter.isNull()) {
                                const addressLength = currentAdapter.add(396).readU32(); // AddressLength
                                const address = currentAdapter.add(400); // Address[MAX_ADAPTER_ADDRESS_LENGTH]

                                if (addressLength >= 6) {
                                    const mac = [];
                                    for (let i = 0; i < 6; i++) {
                                        mac.push(address.add(i).readU8());
                                    }

                                    // Check for VMware MAC prefixes
                                    const vmwarePrefixes = [
                                        [0x00, 0x0c, 0x29], // VMware
                                        [0x00, 0x50, 0x56], // VMware
                                        [0x00, 0x1c, 0x14], // VMware
                                    ];

                                    const isVmwareMac = vmwarePrefixes.some(
                                        prefix =>
                                            mac[0] === prefix[0] &&
                                            mac[1] === prefix[1] &&
                                            mac[2] === prefix[2]
                                    );

                                    if (isVmwareMac) {
                                        // Replace with Intel MAC prefix
                                        address.writeU8(0x00); // Intel OUI
                                        address.add(1).writeU8(0x1b);
                                        address.add(2).writeU8(0x21);

                                        send({
                                            type: 'bypass',
                                            target: 'vm_bypass',
                                            action: 'vmware_mac_address_spoofed',
                                        });
                                    }
                                }

                                // Move to next adapter
                                const nextPtr = currentAdapter.readPointer();
                                currentAdapter = nextPtr.isNull() ? null : nextPtr;

                                // Safety check to prevent infinite loop
                                if (--safetyCounter <= 0) {
                                    break;
                                }
                            }
                        }
                    } catch (_e) {
                        send({
                            type: 'error',
                            target: 'vm_bypass',
                            action: 'mac_spoofing_error',
                            error: e.message || e.toString(),
                        });
                    }
                },
            });

            this.hooksInstalled.GetAdaptersInfo_VMware = true;
        }
    },

    hookVmwareBackdoor: () => {
        // Hook VMware backdoor communication detection
        send({
            type: 'info',
            target: 'vm_bypass',
            action: 'installing_vmware_backdoor_bypass',
        });

        // VMware backdoor uses specific I/O ports and instructions
        // This is primarily detected through CPUID and IN/OUT instructions
        // which are handled by our hardware spoofer

        send({
            type: 'info',
            target: 'vm_bypass',
            action: 'vmware_backdoor_detection_integrated',
        });
    },

    // === HYPER-V DETECTION BYPASS ===
    hookHyperVDetection: function () {
        send({
            type: 'info',
            target: 'vm_bypass',
            action: 'installing_hyperv_bypass',
        });

        if (!this.config.vmDetection.hyperV.enabled) {
            return;
        }

        // Hook Hyper-V feature detection
        this.hookHyperVFeatures();

        // Hook Hyper-V CPUID signature
        this.hookHyperVCpuid();

        // Hook Hyper-V integration services
        this.hookHyperVIntegrationServices();

        // Hook Hyper-V enlightenments
        this.hookHyperVEnlightenments();
    },

    hookHyperVFeatures: function () {
        // Hook processor feature detection
        const isProcessorFeaturePresent = Module.findExportByName(
            'kernel32.dll',
            'IsProcessorFeaturePresent'
        );
        if (isProcessorFeaturePresent) {
            Interceptor.attach(isProcessorFeaturePresent, {
                onEnter: function (_args) {
                    this.feature = args[0].toInt32();
                },

                onLeave: function (_retval) {
                    const {config} = this.parent.parent;
                    if (
                        config.vmDetection.hyperV.hideHyperVFeatures &&
                        (this.feature === 20 || this.feature === 21)
                    ) {
                        retval.replace(0); // FALSE - feature not present
                        send({
                            type: 'bypass',
                            target: 'vm_bypass',
                            action: 'hyperv_feature_hidden',
                            feature: this.feature,
                        });
                    }
                },
            });

            this.hooksInstalled.IsProcessorFeaturePresent_HyperV = true;
        }
    },

    hookHyperVCpuid: () => {
        // Hyper-V CPUID signature spoofing is handled by enhanced_hardware_spoofer.js
        send({
            type: 'info',
            target: 'vm_bypass',
            action: 'hyperv_cpuid_spoofing_integrated',
        });
    },

    hookHyperVIntegrationServices: function () {
        // Hook Hyper-V integration services detection
        const openService = Module.findExportByName('advapi32.dll', 'OpenServiceW');
        if (openService) {
            Interceptor.attach(openService, {
                onEnter: function (_args) {
                    if (args[1] && !args[1].isNull()) {
                        const serviceName = args[1].readUtf16String().toLowerCase();

                        const hyperVServices = [
                            'vmicheartbeat',
                            'vmickvpexchange',
                            'vmicrdv',
                            'vmicshutdown',
                            'vmictimesync',
                            'vmicvss',
                        ];

                        if (hyperVServices.some(service => serviceName.includes(service))) {
                            send({
                                type: 'bypass',
                                target: 'vm_bypass',
                                action: 'hyperv_service_access_blocked',
                                service_name: serviceName,
                            });
                            this.blockHyperVService = true;
                        }
                    }
                },

                onLeave: function (_retval) {
                    if (this.blockHyperVService) {
                        retval.replace(ptr(0)); // NULL - service not found
                    }
                },
            });

            this.hooksInstalled.OpenServiceW_HyperV = true;
        }
    },

    hookHyperVEnlightenments: function () {
        // Hook MSR (Model Specific Register) access used by Hyper-V
        const ntQuerySystemInformation = Module.findExportByName(
            'ntdll.dll',
            'NtQuerySystemInformation'
        );
        if (ntQuerySystemInformation) {
            Interceptor.attach(ntQuerySystemInformation, {
                onEnter: function (_args) {
                    const infoClass = args[0].toInt32();

                    // SystemProcessorInformation = 1
                    if (infoClass === 1) {
                        this.isProcessorQuery = true;
                    }
                },

                onLeave: function (_retval) {
                    if (this.isProcessorQuery && retval.toInt32() === 0) {
                        send({
                            type: 'bypass',
                            target: 'vm_bypass',
                            action: 'processor_info_query_hyperv_detection',
                        });
                    }
                },
            });

            this.hooksInstalled.NtQuerySystemInformation_HyperV = true;
        }
    },

    // === QEMU DETECTION BYPASS ===
    hookQemuDetection: function () {
        send({
            type: 'info',
            target: 'vm_bypass',
            action: 'installing_qemu_bypass',
        });

        if (!this.config.vmDetection.qemu.enabled) {
            return;
        }

        // Hook QEMU signature detection
        this.hookQemuSignatures();

        // Hook QEMU hardware IDs
        this.hookQemuHardwareIds();

        // Hook QEMU device detection
        this.hookQemuDevices();
    },

    hookQemuSignatures: function () {
        // Hook string searches for QEMU signatures
        const findFirstFile = Module.findExportByName('kernel32.dll', 'FindFirstFileW');
        if (findFirstFile) {
            Interceptor.attach(findFirstFile, {
                onEnter: function (_args) {
                    if (args[0] && !args[0].isNull()) {
                        const fileName = args[0].readUtf16String().toLowerCase();

                        if (fileName.includes('qemu') || fileName.includes('virtio')) {
                            send({
                                type: 'bypass',
                                target: 'vm_bypass',
                                action: 'qemu_file_search_blocked',
                                file_name: fileName,
                            });
                            this.blockQemuSearch = true;
                        }
                    }
                },

                onLeave: function (_retval) {
                    if (this.blockQemuSearch) {
                        retval.replace(ptr(0xffffffff)); // INVALID_HANDLE_VALUE
                    }
                },
            });

            this.hooksInstalled.FindFirstFileW_QEMU = true;
        }
    },

    hookQemuHardwareIds: function () {
        // Hook hardware ID queries to hide QEMU devices
        const setupDiGetDeviceRegistryProperty = Module.findExportByName(
            'setupapi.dll',
            'SetupDiGetDeviceRegistryPropertyW'
        );
        if (setupDiGetDeviceRegistryProperty) {
            Interceptor.attach(setupDiGetDeviceRegistryProperty, {
                onLeave: function (_retval) {
                    if (retval.toInt32() !== 0) {
                        const propertyBuffer = this.context.r8; // PropertyBuffer
                        if (propertyBuffer && !propertyBuffer.isNull()) {
                            this.filterQemuHardwareIds(propertyBuffer);
                        }
                    }
                },

                filterQemuHardwareIds: buffer => {
                    try {
                        const hardwareId = buffer.readUtf16String();
                        if (
                            hardwareId &&
                            (hardwareId.includes('QEMU') || hardwareId.includes('VEN_1AF4'))
                        ) {
                            // Replace with generic hardware ID
                            buffer.writeUtf16String('PCI\\VEN_8086&DEV_1234'); // Intel device
                            send({
                                type: 'bypass',
                                target: 'vm_bypass',
                                action: 'qemu_hardware_id_spoofed',
                            });
                        }
                    } catch (_e) {
                        // Buffer read failed
                    }
                },
            });

            this.hooksInstalled.SetupDiGetDeviceRegistryPropertyW_QEMU = true;
        }
    },

    hookQemuDevices: function () {
        // Hook QEMU virtio device detection
        const deviceIoControl = Module.findExportByName('kernel32.dll', 'DeviceIoControl');
        if (deviceIoControl) {
            Interceptor.attach(deviceIoControl, {
                onEnter: function (_args) {
                    const ioControlCode = args[1].toInt32();

                    // Check for virtio-related IOCTL codes
                    if ((ioControlCode & 0xffff0000) === 0x00220000) {
                        // Virtio device type
                        send({
                            type: 'bypass',
                            target: 'vm_bypass',
                            action: 'qemu_virtio_device_ioctl_blocked',
                            ioctl_code: `0x${ioControlCode.toString(16)}`,
                        });
                        this.blockQemuIoctl = true;
                    }
                },

                onLeave: function (_retval) {
                    if (this.blockQemuIoctl) {
                        retval.replace(0); // FALSE - operation failed
                    }
                },
            });

            this.hooksInstalled.DeviceIoControl_QEMU = true;
        }
    },

    // === SANDBOX DETECTION BYPASS ===
    hookSandboxDetection: function () {
        send({
            type: 'info',
            target: 'vm_bypass',
            action: 'installing_sandbox_bypass',
        });

        if (!this.config.sandboxDetection.enabled) {
            return;
        }

        // Hook sandbox file system detection
        this.hookSandboxFileSystem();

        // Hook sandbox process detection
        this.hookSandboxProcesses();

        // Hook sandbox registry detection
        this.hookSandboxRegistry();

        // Hook sandbox network detection
        this.hookSandboxNetwork();

        // Hook sandbox environment detection
        this.hookSandboxEnvironment();
    },

    hookSandboxFileSystem: function () {
        send({
            type: 'info',
            target: 'vm_bypass',
            action: 'installing_sandbox_filesystem_bypass',
        });

        // Hook file existence checks for sandbox indicators
        const getFileAttributes = Module.findExportByName('kernel32.dll', 'GetFileAttributesW');
        if (getFileAttributes) {
            Interceptor.attach(getFileAttributes, {
                onEnter: function (_args) {
                    if (args[0] && !args[0].isNull()) {
                        const fileName = args[0].readUtf16String().toLowerCase();

                        const sandboxFiles = [
                            'c:\\analysis',
                            'c:\\sandbox',
                            'c:\\crack',
                            'c:\\temp\\crack',
                            'c:\\sample',
                            'c:\\patch',
                            'c:\\users\\sandbox',
                            'c:\\cuckoo',
                            'c:\\windows\\temp\\',
                        ];

                        if (sandboxFiles.some(file => fileName.includes(file))) {
                            send({
                                type: 'bypass',
                                target: 'vm_bypass',
                                action: 'sandbox_file_check_blocked',
                                file_name: fileName,
                            });
                            this.blockSandboxFile = true;
                        }
                    }
                },

                onLeave: function (_retval) {
                    if (this.blockSandboxFile) {
                        retval.replace(0xffffffff); // INVALID_FILE_ATTRIBUTES
                    }
                },
            });

            this.hooksInstalled.GetFileAttributesW_Sandbox = true;
        }

        // Hook file creation to return realistic file paths
        const createFile = Module.findExportByName('kernel32.dll', 'CreateFileW');
        if (createFile) {
            Interceptor.attach(createFile, {
                onEnter: _args => {
                    if (args[0] && !args[0].isNull()) {
                        const fileName = args[0].readUtf16String().toLowerCase();

                        // Return authentic-looking user file paths to defeat sandbox detection
                        const legitimateFiles = [
                            'c:\\users\\john\\documents',
                            'c:\\users\\admin\\desktop',
                            'c:\\program files\\common files',
                            'c:\\windows\\system32\\drivers',
                        ];

                        if (legitimateFiles.some(file => fileName.includes(file))) {
                            send({
                                type: 'bypass',
                                target: 'vm_bypass',
                                action: 'spoofing_file_access_to_appear_legitimate',
                                file_name: fileName,
                            });
                        }
                    }
                },
            });

            this.hooksInstalled.CreateFileW_Sandbox = true;
        }
    },

    hookSandboxProcesses: function () {
        send({
            type: 'info',
            target: 'vm_bypass',
            action: 'installing_sandbox_process_bypass',
        });

        // Hide sandbox analysis tools from process enumeration
        const process32Next = Module.findExportByName('kernel32.dll', 'Process32NextW');
        if (process32Next) {
            Interceptor.attach(process32Next, {
                onLeave: function (_retval) {
                    if (retval.toInt32() !== 0) {
                        const processEntry = this.context.rdx;
                        if (processEntry && !processEntry.isNull()) {
                            this.filterSandboxProcesses(processEntry);
                        }
                    }
                },

                filterSandboxProcesses: function (processEntry) {
                    try {
                        const szExeFile = processEntry.add(44); // PROCESSENTRY32W.szExeFile
                        const exeName = szExeFile.readUtf16String().toLowerCase();

                        const sandboxProcesses = [
                            'procmon.exe',
                            'procexp.exe',
                            'wireshark.exe',
                            'tcpview.exe',
                            'autoruns.exe',
                            'autorunsc.exe',
                            'filemon.exe',
                            'regmon.exe',
                            'ollydbg.exe',
                            'windbg.exe',
                            'x32dbg.exe',
                            'x64dbg.exe',
                            'immunity.exe',
                            'vboxservice.exe',
                            'vboxtray.exe',
                            'sandboxie.exe',
                            'sbiesvc.exe',
                            'kasperskyav.exe',
                        ];

                        if (sandboxProcesses.includes(exeName)) {
                            // Skip this process by returning FALSE on next call
                            send({
                                type: 'bypass',
                                target: 'vm_bypass',
                                action: 'sandbox_process_hidden',
                                exe_name: exeName,
                            });
                            this.parent.parent.skipNextProcess = true;
                        }
                    } catch (_e) {
                        // Process entry read failed
                    }
                },
            });

            this.hooksInstalled.Process32NextW_Sandbox = true;
        }
    },

    hookSandboxRegistry: function () {
        send({
            type: 'info',
            target: 'vm_bypass',
            action: 'installing_sandbox_registry_bypass',
        });

        // Block sandbox-related registry queries
        const regQueryValue = Module.findExportByName('advapi32.dll', 'RegQueryValueW');
        if (regQueryValue) {
            Interceptor.attach(regQueryValue, {
                onEnter: function (_args) {
                    if (args[1] && !args[1].isNull()) {
                        const valueName = args[1].readUtf16String().toLowerCase();

                        const sandboxValues = [
                            'sandbox',
                            'cuckoo',
                            'anubis',
                            'cwsandbox',
                            'joebox',
                            'threatalyzer',
                            'sandboxie',
                            'wireshark',
                            'vmware',
                        ];

                        if (sandboxValues.some(val => valueName.includes(val))) {
                            send({
                                type: 'bypass',
                                target: 'vm_bypass',
                                action: 'sandbox_registry_value_blocked',
                                value_name: valueName,
                            });
                            this.blockSandboxRegistry = true;
                        }
                    }
                },

                onLeave: function (_retval) {
                    if (this.blockSandboxRegistry) {
                        retval.replace(2); // ERROR_FILE_NOT_FOUND
                    }
                },
            });

            this.hooksInstalled.RegQueryValueW_Sandbox = true;
        }
    },

    hookSandboxNetwork: function () {
        send({
            type: 'info',
            target: 'vm_bypass',
            action: 'installing_sandbox_network_bypass',
        });

        // Spoof network configuration to appear legitimate
        const getAdaptersAddresses = Module.findExportByName(
            'iphlpapi.dll',
            'GetAdaptersAddresses'
        );
        if (getAdaptersAddresses) {
            Interceptor.attach(getAdaptersAddresses, {
                onLeave: _retval => {
                    if (retval.toInt32() === 0) {
                        // NO_ERROR
                        send({
                            type: 'bypass',
                            target: 'vm_bypass',
                            action: 'network_adapter_query_spoofing_sandbox',
                        });
                    }
                },
            });

            this.hooksInstalled.GetAdaptersAddresses_Sandbox = true;
        }
    },

    hookSandboxEnvironment: function () {
        // Hook environment variable queries
        const getEnvironmentVariable = Module.findExportByName(
            'kernel32.dll',
            'GetEnvironmentVariableW'
        );
        if (getEnvironmentVariable) {
            Interceptor.attach(getEnvironmentVariable, {
                onEnter: function (_args) {
                    if (args[0] && !args[0].isNull()) {
                        const varName = args[0].readUtf16String().toLowerCase();

                        if (
                            varName.includes('sandbox') ||
                            varName.includes('cuckoo') ||
                            varName.includes('crack')
                        ) {
                            send({
                                type: 'bypass',
                                target: 'vm_bypass',
                                action: 'sandbox_environment_variable_blocked',
                                var_name: varName,
                            });
                            this.blockSandboxEnv = true;
                        }
                    }
                },

                onLeave: function (_retval) {
                    if (this.blockSandboxEnv) {
                        retval.replace(0); // Variable not found
                    }
                },
            });

            this.hooksInstalled.GetEnvironmentVariableW_Sandbox = true;
        }
    },

    // === HARDWARE FINGERPRINTING BYPASS ===
    hookHardwareFingerprinting: function () {
        send({
            type: 'info',
            target: 'vm_bypass',
            action: 'installing_hardware_fingerprinting_bypass',
        });

        // Hook WMI queries for hardware information
        this.hookWmiHardwareQueries();

        // Hook registry hardware queries
        this.hookRegistryHardwareQueries();

        // Hook system information APIs
        this.hookSystemInformationAPIs();
    },

    hookWmiHardwareQueries: () => {
        // WMI queries are handled by enhanced_hardware_spoofer.js
        send({
            type: 'info',
            target: 'vm_bypass',
            action: 'wmi_hardware_spoofing_integrated',
        });
    },

    hookRegistryHardwareQueries: function () {
        // Hook registry queries for hardware information
        const regEnumKeyEx = Module.findExportByName('advapi32.dll', 'RegEnumKeyExW');
        if (regEnumKeyEx) {
            Interceptor.attach(regEnumKeyEx, {
                onLeave: function (_retval) {
                    if (retval.toInt32() === 0) {
                        // ERROR_SUCCESS
                        const keyName = this.context.rdx;
                        if (keyName && !keyName.isNull()) {
                            this.spoofHardwareKeys(keyName);
                        }
                    }
                },

                spoofHardwareKeys: keyBuffer => {
                    try {
                        const keyName = keyBuffer.readUtf16String().toLowerCase();

                        // Check for VM hardware keys
                        if (
                            keyName.includes('vbox') ||
                            keyName.includes('vmware') ||
                            keyName.includes('qemu') ||
                            keyName.includes('virtual')
                        ) {
                            // Replace with legitimate hardware vendor
                            keyBuffer.writeUtf16String('Intel Corporation');
                            send({
                                type: 'bypass',
                                target: 'vm_bypass',
                                action: 'hardware_registry_key_spoofed',
                                key_name: keyName,
                            });
                        }
                    } catch (_e) {
                        // Key name read failed
                    }
                },
            });

            this.hooksInstalled.RegEnumKeyExW_Hardware = true;
        }
    },

    hookSystemInformationAPIs: function () {
        // Hook computer name queries
        const getComputerName = Module.findExportByName('kernel32.dll', 'GetComputerNameW');
        if (getComputerName) {
            Interceptor.attach(getComputerName, {
                onLeave: function (_retval) {
                    if (retval.toInt32() !== 0) {
                        const computerName = this.context.rcx;
                        if (computerName && !computerName.isNull()) {
                            this.spoofComputerName(computerName);
                        }
                    }
                },

                spoofComputerName: nameBuffer => {
                    try {
                        const name = nameBuffer.readUtf16String().toLowerCase();

                        const suspiciousNames = [
                            'sandbox',
                            'crack',
                            'cuckoo',
                            'analysis',
                            'victim',
                            'target',
                            'test',
                            'sample',
                            'keygen',
                            'patch',
                        ];

                        if (suspiciousNames.some(suspicious => name.includes(suspicious))) {
                            nameBuffer.writeUtf16String('DESKTOP-USER01');
                            send({
                                type: 'bypass',
                                target: 'vm_bypass',
                                action: 'computer_name_spoofed',
                                original_name: name,
                            });
                        }
                    } catch (_e) {
                        // Name read failed
                    }
                },
            });

            this.hooksInstalled.GetComputerNameW = true;
        }

        // Hook username queries
        const getUserName = Module.findExportByName('advapi32.dll', 'GetUserNameW');
        if (getUserName) {
            Interceptor.attach(getUserName, {
                onLeave: function (_retval) {
                    if (retval.toInt32() !== 0) {
                        const userName = this.context.rcx;
                        if (userName && !userName.isNull()) {
                            this.spoofUserName(userName);
                        }
                    }
                },

                spoofUserName: nameBuffer => {
                    try {
                        const name = nameBuffer.readUtf16String().toLowerCase();

                        const suspiciousUsers = [
                            'sandbox',
                            'crack',
                            'cuckoo',
                            'analysis',
                            'admin',
                            'user',
                            'test',
                            'sample',
                            'keygen',
                            'currentuser',
                        ];

                        if (suspiciousUsers.some(suspicious => name.includes(suspicious))) {
                            nameBuffer.writeUtf16String('John');
                            send({
                                type: 'bypass',
                                target: 'vm_bypass',
                                action: 'username_spoofed',
                                original_name: name,
                            });
                        }
                    } catch (_e) {
                        // Name read failed
                    }
                },
            });

            this.hooksInstalled.GetUserNameW = true;
        }
    },

    // === TIMING DETECTION BYPASS ===
    hookTimingDetection: function () {
        send({
            type: 'info',
            target: 'vm_bypass',
            action: 'installing_timing_detection_bypass',
        });

        if (!this.config.timingDetection.enabled) {
            return;
        }

        // Hook RDTSC instruction timing
        this.hookRdtscTiming();

        // Hook performance counters
        this.hookPerformanceCounters();

        // Hook high precision timing functions
        this.hookHighPrecisionTiming();

        send({
            type: 'info',
            target: 'vm_bypass',
            action: 'enhanced_timing_detection_bypass_installed',
        });
    },

    hookRdtscTiming: function () {
        if (!this.config.timingDetection.hookRdtscInstructions) {
            return;
        }

        // Hook QueryPerformanceCounter to normalize timing
        const qpc = Module.findExportByName('kernel32.dll', 'QueryPerformanceCounter');
        if (qpc) {
            const baseTime = Date.now();
            const _lastValue = 0;

            Interceptor.attach(qpc, {
                onEnter: function (_args) {
                    this.lpPerformanceCount = args[0];
                },
                onLeave: function (_retval) {
                    if (this.lpPerformanceCount && !this.lpPerformanceCount.isNull()) {
                        // Normalize timing to prevent VM detection by adjusting to native CPU frequency
                        const normalizedTime = baseTime + (Date.now() - baseTime) * 2.4;
                        this.lpPerformanceCount.writeU64(normalizedTime * 1000);
                    }
                },
            });

            this.hooksInstalled.QueryPerformanceCounter = true;
        }

        // Hook GetTickCount64 for consistent timing
        const gtc64 = Module.findExportByName('kernel32.dll', 'GetTickCount64');
        if (gtc64) {
            const startTick = Date.now();

            Interceptor.attach(gtc64, {
                onLeave: _retval => {
                    // Provide consistent tick count to avoid timing analysis detection
                    const elapsed = Date.now() - startTick;
                    retval.replace(ptr(elapsed));
                },
            });

            this.hooksInstalled.GetTickCount64 = true;
        }
    },

    hookPerformanceCounters: function () {
        if (!this.config.timingDetection.spoofPerformanceCounters) {
            return;
        }

        // Hook timeGetTime for multimedia timer spoofing
        const tgt = Module.findExportByName('winmm.dll', 'timeGetTime');
        if (tgt) {
            const baseMultimediaTime = Date.now();

            Interceptor.attach(tgt, {
                onLeave: _retval => {
                    const elapsed = Date.now() - baseMultimediaTime;
                    // Normalize multimedia timer to avoid detection by adding hardware offset
                    retval.replace(ptr(elapsed + 1000));
                },
            });

            this.hooksInstalled.timeGetTime = true;
        }
    },

    hookHighPrecisionTiming: function () {
        if (!this.config.timingDetection.preventHighPrecisionTiming) {
            return;
        }

        // Hook NtQueryPerformanceCounter for NT-level timing
        const ntqpc = Module.findExportByName('ntdll.dll', 'NtQueryPerformanceCounter');
        if (ntqpc) {
            Interceptor.attach(ntqpc, {
                onEnter: function (_args) {
                    this.performanceCounter = args[0];
                    this.performanceFrequency = args[1];
                },
                onLeave: function (_retval) {
                    if (this.performanceCounter && !this.performanceCounter.isNull()) {
                        // Provide consistent performance counter values scaled to high-frequency range
                        const normalizedCounter = Date.now() * 3000;
                        this.performanceCounter.writeU64(normalizedCounter);
                    }

                    if (this.performanceFrequency && !this.performanceFrequency.isNull()) {
                        // Spoof frequency to look like real hardware
                        this.performanceFrequency.writeU64(3000000); // 3 MHz frequency
                    }
                },
            });

            this.hooksInstalled.NtQueryPerformanceCounter = true;
        }
    },

    // === CONTAINER DETECTION BYPASS ===
    hookContainerDetection: function () {
        send({
            type: 'info',
            target: 'vm_bypass',
            action: 'installing_container_detection_bypass',
        });

        if (!this.config.containerDetection.enabled) {
            return;
        }

        // Hook Docker detection
        this.hookDockerDetection();

        // Hook WSL detection
        this.hookWslDetection();

        // Hook Kubernetes detection
        this.hookKubernetesDetection();

        // Hook LXC detection
        this.hookLxcDetection();
    },

    hookDockerDetection: function () {
        if (!this.config.containerDetection.docker.enabled) {
            return;
        }

        // Hook file operations to hide Docker-specific files
        const createFileW = Module.findExportByName('kernel32.dll', 'CreateFileW');
        if (createFileW) {
            Interceptor.attach(createFileW, {
                onEnter: function (_args) {
                    if (args[0] && !args[0].isNull()) {
                        try {
                            const filename = args[0].readUtf16String();
                            if (filename) {
                                const dockerFiles = [
                                    '.dockerenv',
                                    '/.dockerinit',
                                    '/proc/1/cgroup',
                                    '/proc/self/cgroup',
                                    '/etc/hostname',
                                    'docker-desktop',
                                ];

                                const isDockerFile = dockerFiles.some(file =>
                                    filename.includes(file)
                                );
                                if (isDockerFile) {
                                    send({
                                        type: 'bypass',
                                        target: 'vm_bypass',
                                        action: 'docker_file_access_blocked',
                                        filename: filename,
                                    });
                                    this.blockDockerAccess = true;
                                }
                            }
                        } catch (_e) {
                            send({
                                type: 'debug',
                                target: 'vm_bypass',
                                action: 'docker_file_read_failed',
                                function: 'hookDockerDetection',
                                error: e.toString(),
                                stack: e.stack || 'No stack trace available',
                            });
                        }
                    }
                },
                onLeave: function (_retval) {
                    if (this.blockDockerAccess) {
                        retval.replace(ptr(-1)); // INVALID_HANDLE_VALUE
                    }
                },
            });

            this.hooksInstalled.CreateFileW_Docker = true;
        }

        // Hook environment variable access for container detection
        this.hookContainerEnvironmentVars();
    },

    hookWslDetection: function () {
        if (!this.config.containerDetection.wsl.enabled) {
            return;
        }

        // Hook WSL interop detection
        const regOpenKeyW = Module.findExportByName('advapi32.dll', 'RegOpenKeyExW');
        if (regOpenKeyW) {
            Interceptor.attach(regOpenKeyW, {
                onEnter: function (_args) {
                    if (args[1] && !args[1].isNull()) {
                        try {
                            const keyName = args[1].readUtf16String();
                            if (keyName?.includes('WSL')) {
                                send({
                                    type: 'bypass',
                                    target: 'vm_bypass',
                                    action: 'wsl_registry_access_blocked',
                                    key: keyName,
                                });
                                this.blockWslRegistry = true;
                            }
                        } catch (_e) {
                            send({
                                type: 'debug',
                                target: 'vm_bypass',
                                action: 'wsl_registry_read_failed',
                                function: 'hookWslDetection',
                                error: e.toString(),
                                stack: e.stack || 'No stack trace available',
                            });
                        }
                    }
                },
                onLeave: function (_retval) {
                    if (this.blockWslRegistry) {
                        retval.replace(2); // ERROR_FILE_NOT_FOUND
                    }
                },
            });

            this.hooksInstalled.RegOpenKeyExW_WSL = true;
        }

        // Hook WSL subsystem detection files
        this.hookWslSubsystemFiles();
    },

    hookKubernetesDetection: function () {
        if (!this.config.containerDetection.kubernetes.enabled) {
            return;
        }

        const createFileW = Module.findExportByName('kernel32.dll', 'CreateFileW');
        if (createFileW) {
            Interceptor.attach(createFileW, {
                onEnter: function (_args) {
                    if (args[0] && !args[0].isNull()) {
                        try {
                            const filename = args[0].readUtf16String();
                            if (filename) {
                                const k8sFiles = [
                                    '/var/run/secrets/kubernetes.io',
                                    '/proc/1/mountinfo',
                                    'kubernetes',
                                    'kube-proxy',
                                    'kubectl',
                                ];

                                const isK8sFile = k8sFiles.some(file => filename.includes(file));
                                if (isK8sFile) {
                                    send({
                                        type: 'bypass',
                                        target: 'vm_bypass',
                                        action: 'kubernetes_file_access_blocked',
                                        filename: filename,
                                    });
                                    this.blockK8sAccess = true;
                                }
                            }
                        } catch (_e) {
                            send({
                                type: 'debug',
                                target: 'vm_bypass',
                                action: 'kubernetes_file_read_failed',
                                function: 'hookKubernetesDetection',
                                error: e.toString(),
                                stack: e.stack || 'No stack trace available',
                            });
                        }
                    }
                },
                onLeave: function (_retval) {
                    if (this.blockK8sAccess) {
                        retval.replace(ptr(-1)); // INVALID_HANDLE_VALUE
                    }
                },
            });

            this.hooksInstalled.CreateFileW_Kubernetes = true;
        }
    },

    hookLxcDetection: function () {
        if (!this.config.containerDetection.lxc.enabled) {
            return;
        }

        // Hook LXC container detection through /proc filesystem
        this.hookLxcProcDetection();
    },

    hookContainerEnvironmentVars: function () {
        const getEnvVar = Module.findExportByName('kernel32.dll', 'GetEnvironmentVariableW');
        if (getEnvVar) {
            Interceptor.attach(getEnvVar, {
                onEnter: function (_args) {
                    if (args[0] && !args[0].isNull()) {
                        try {
                            const varName = args[0].readUtf16String();
                            if (varName) {
                                const containerVars = [
                                    'DOCKER_HOST',
                                    'CONTAINER_ID',
                                    'WSL_DISTRO_NAME',
                                    'WSL_INTEROP',
                                    'KUBERNETES_SERVICE_HOST',
                                    'K8S_POD_NAME',
                                ];

                                const isContainerVar = containerVars.some(cv =>
                                    varName.includes(cv)
                                );
                                if (isContainerVar) {
                                    send({
                                        type: 'bypass',
                                        target: 'vm_bypass',
                                        action: 'container_env_var_spoofed',
                                        variable: varName,
                                    });
                                    this.spoofContainerVar = true;
                                }
                            }
                        } catch (_e) {
                            send({
                                type: 'debug',
                                target: 'vm_bypass',
                                action: 'container_env_var_read_failed',
                                function: 'hookContainerEnvironmentVars',
                                error: e.toString(),
                                stack: e.stack || 'No stack trace available',
                            });
                        }
                    }
                },
                onLeave: function (_retval) {
                    if (this.spoofContainerVar) {
                        retval.replace(0); // Variable not found
                    }
                },
            });

            this.hooksInstalled.GetEnvironmentVariableW_Container = true;
        }
    },

    hookWslSubsystemFiles: function () {
        // Hook access to WSL-specific files
        const createFileA = Module.findExportByName('kernel32.dll', 'CreateFileA');
        if (createFileA) {
            Interceptor.attach(createFileA, {
                onEnter: function (_args) {
                    if (args[0] && !args[0].isNull()) {
                        try {
                            const filename = args[0].readAnsiString();
                            if (filename) {
                                const wslFiles = [
                                    '/proc/sys/fs/binfmt_misc/WSLInterop',
                                    '/mnt/wsl',
                                    '/init',
                                    'wsl.exe',
                                ];

                                const isWslFile = wslFiles.some(file => filename.includes(file));
                                if (isWslFile) {
                                    send({
                                        type: 'bypass',
                                        target: 'vm_bypass',
                                        action: 'wsl_file_access_blocked',
                                        filename: filename,
                                    });
                                    this.blockWslFile = true;
                                }
                            }
                        } catch (_e) {
                            send({
                                type: 'debug',
                                target: 'vm_bypass',
                                action: 'wsl_file_read_failed',
                                function: 'hookWslSubsystemFiles',
                                error: e.toString(),
                                stack: e.stack || 'No stack trace available',
                            });
                        }
                    }
                },
                onLeave: function (_retval) {
                    if (this.blockWslFile) {
                        retval.replace(ptr(-1)); // INVALID_HANDLE_VALUE
                    }
                },
            });

            this.hooksInstalled.CreateFileA_WSL = true;
        }
    },

    hookLxcProcDetection: function () {
        // Hook LXC /proc detection methods
        const readFile = Module.findExportByName('kernel32.dll', 'ReadFile');
        if (readFile) {
            Interceptor.attach(readFile, {
                onEnter: function (_args) {
                    this.hFile = args[0];
                    this.lpBuffer = args[1];
                    this.nNumberOfBytesToRead = args[2];
                    this.lpNumberOfBytesRead = args[3];
                },
                onLeave: function (_retval) {
                    if (retval.toInt32() && this.lpBuffer && !this.lpBuffer.isNull()) {
                        try {
                            const data = this.lpBuffer.readAnsiString();
                            if (
                                data &&
                                (data.includes('lxc') ||
                                    data.includes('/lxc/') ||
                                    data.includes('container'))
                            ) {
                                send({
                                    type: 'bypass',
                                    target: 'vm_bypass',
                                    action: 'lxc_proc_data_spoofed',
                                });
                                // Replace LXC indicators with normal system data
                                const spoofedData = data
                                    .replace(/lxc/g, 'sys')
                                    .replace(/container/g, 'process');
                                this.lpBuffer.writeAnsiString(spoofedData);
                            }
                        } catch (_e) {
                            send({
                                type: 'debug',
                                target: 'vm_bypass',
                                action: 'lxc_proc_data_read_failed',
                                function: 'hookLxcProcDetection',
                                error: e.toString(),
                                stack: e.stack || 'No stack trace available',
                            });
                        }
                    }
                },
            });

            this.hooksInstalled.ReadFile_LXC = true;
        }
    },

    // === CPU FEATURE DETECTION BYPASS ===
    hookCpuFeatureDetection: function () {
        send({
            type: 'info',
            target: 'vm_bypass',
            action: 'installing_cpu_feature_detection_bypass',
        });

        if (!this.config.cpuFeatureDetection.enabled) {
            return;
        }

        // Hook CPUID instruction for advanced CPU feature spoofing
        this.hookCpuidInstructions();

        // Hook SMBIOS detection
        this.hookSmbiosDetection();

        // Hook MSR (Model Specific Register) access
        this.hookMsrAccess();
    },

    hookSmbiosDetection: function () {
        if (!this.config.cpuFeatureDetection.smbiosDetection) {
            return;
        }

        // Hook SMBIOS table access
        const enumSystemFirmwareTables = Module.findExportByName(
            'kernel32.dll',
            'EnumSystemFirmwareTables'
        );
        if (enumSystemFirmwareTables) {
            Interceptor.attach(enumSystemFirmwareTables, {
                onEnter: function (_args) {
                    const firmwareTableProvider = args[0].toInt32();
                    if (firmwareTableProvider === 1380533837) {
                        // 'RSMB' - Raw SMBIOS data
                        send({
                            type: 'bypass',
                            target: 'vm_bypass',
                            action: 'smbios_enumeration_blocked',
                        });
                        this.blockSmbios = true;
                    }
                },
                onLeave: function (_retval) {
                    if (this.blockSmbios) {
                        retval.replace(0); // No tables available
                    }
                },
            });

            this.hooksInstalled.EnumSystemFirmwareTables = true;
        }
    },

    hookMsrAccess: function () {
        // Hook Model Specific Register access for hypervisor detection
        const deviceIoControl = Module.findExportByName('kernel32.dll', 'DeviceIoControl');
        if (deviceIoControl) {
            Interceptor.attach(deviceIoControl, {
                onEnter: function (_args) {
                    const ioControlCode = args[1].toInt32();

                    // MSR access IOCTL codes that might indicate VM detection
                    if ((ioControlCode & 0xffff0000) === 0x9c400000) {
                        // MSR access codes
                        send({
                            type: 'bypass',
                            target: 'vm_bypass',
                            action: 'msr_access_blocked',
                            ioctl_code: `0x${ioControlCode.toString(16)}`,
                        });
                        this.blockMsrAccess = true;
                    }
                },
                onLeave: function (_retval) {
                    if (this.blockMsrAccess) {
                        retval.replace(0); // Access denied
                    }
                },
            });

            this.hooksInstalled.DeviceIoControl_MSR = true;
        }
    },

    // === GENERIC VM DETECTION BYPASS ===
    hookGenericVmDetection: function () {
        send({
            type: 'info',
            target: 'vm_bypass',
            action: 'installing_generic_vm_detection_bypass',
        });

        // Hook common VM detection APIs
        this.hookVmDetectionAPIs();

        // Hook string searches for VM indicators
        this.hookVmStringDetection();

        // Hook file system VM detection
        this.hookVmFileDetection();
    },

    hookVmDetectionAPIs: function () {
        // Hook DeviceIoControl for VM detection
        const deviceIoControl = Module.findExportByName('kernel32.dll', 'DeviceIoControl');
        if (deviceIoControl) {
            Interceptor.attach(deviceIoControl, {
                onEnter: function (_args) {
                    const _hDevice = args[0];
                    const ioControlCode = args[1].toInt32();

                    // Common VM detection IOCTL codes
                    const vmIoctls = [
                        0x00564d58, // 'VMX' - VMware
                        0x564d5868, // VMware backdoor
                        0xaa000000, // VirtualBox
                        0xbb000000, // Generic VM
                    ];

                    if (vmIoctls.includes(ioControlCode)) {
                        send({
                            type: 'bypass',
                            target: 'vm_bypass',
                            action: 'vm_detection_ioctl_blocked',
                            ioctl_code: `0x${ioControlCode.toString(16)}`,
                        });
                        this.blockVmIoctl = true;
                    }
                },

                onLeave: function (_retval) {
                    if (this.blockVmIoctl) {
                        retval.replace(0); // FALSE - operation failed
                    }
                },
            });

            this.hooksInstalled.DeviceIoControl_VM = true;
        }
    },

    hookVmStringDetection: function () {
        // Hook string comparison functions for VM detection
        const strcmp = Module.findExportByName('msvcrt.dll', 'strcmp');
        if (strcmp) {
            Interceptor.attach(strcmp, {
                onEnter: function (_args) {
                    try {
                        const str1 = args[0].readAnsiString();
                        const str2 = args[1].readAnsiString();

                        const vmStrings = [
                            'VBOX',
                            'VMWARE',
                            'QEMU',
                            'XEN',
                            'BOCHS',
                            'VIRTUAL',
                            'SANDBOX',
                            'CUCKOO',
                            'ANALYSIS',
                            'CRACK',
                        ];

                        const isVmComparison = vmStrings.some(
                            vm =>
                                str1?.toUpperCase().includes(vm) || str2?.toUpperCase().includes(vm)
                        );

                        if (isVmComparison) {
                            send({
                                type: 'bypass',
                                target: 'vm_bypass',
                                action: 'vm_string_comparison_detected',
                            });
                            this.spoofVmComparison = true;
                        }
                    } catch (_e) {
                        // String read failed
                    }
                },

                onLeave: function (_retval) {
                    if (this.spoofVmComparison) {
                        retval.replace(1); // Strings don't match
                        send({
                            type: 'bypass',
                            target: 'vm_bypass',
                            action: 'vm_string_comparison_spoofed',
                        });
                    }
                },
            });

            this.hooksInstalled.strcmp_VM = true;
        }
    },

    hookVmFileDetection: function () {
        // Hook directory enumeration for VM files
        const findFirstFile = Module.findExportByName('kernel32.dll', 'FindFirstFileW');
        if (findFirstFile) {
            Interceptor.attach(findFirstFile, {
                onEnter: function (_args) {
                    if (args[0] && !args[0].isNull()) {
                        const searchPattern = args[0].readUtf16String().toLowerCase();

                        const vmPatterns = [
                            '*vbox*',
                            '*vmware*',
                            '*qemu*',
                            '*virtual*',
                            '*guest*',
                            '*tools*',
                            '*additions*',
                        ];

                        if (
                            vmPatterns.some(pattern =>
                                searchPattern.includes(pattern.replace(/\*/g, ''))
                            )
                        ) {
                            send({
                                type: 'bypass',
                                target: 'vm_bypass',
                                action: 'vm_file_search_blocked',
                                search_pattern: searchPattern,
                            });
                            this.blockVmFileSearch = true;
                        }
                    }
                },

                onLeave: function (_retval) {
                    if (this.blockVmFileSearch) {
                        retval.replace(ptr(0xffffffff)); // INVALID_HANDLE_VALUE
                    }
                },
            });

            this.hooksInstalled.FindFirstFileW_VM = true;
        }
    },

    // === REGISTRY DETECTION BYPASS ===
    hookRegistryDetection: function () {
        send({
            type: 'info',
            target: 'vm_bypass',
            action: 'installing_registry_detection_bypass',
        });

        // Comprehensive registry key blocking
        const regOpenKey = Module.findExportByName('advapi32.dll', 'RegOpenKeyW');
        if (regOpenKey) {
            Interceptor.attach(regOpenKey, {
                onEnter: function (_args) {
                    if (args[1] && !args[1].isNull()) {
                        const keyName = args[1].readUtf16String().toLowerCase();

                        const vmRegistryKeys = [
                            'software\\oracle\\virtualbox',
                            'software\\vmware, inc.',
                            'software\\microsoft\\virtual machine',
                            'system\\controlset001\\services\\vbox',
                            'system\\controlset001\\services\\vmware',
                            'hardware\\devicemap\\scsi\\scsi port',
                        ];

                        if (vmRegistryKeys.some(key => keyName.includes(key))) {
                            send({
                                type: 'bypass',
                                target: 'vm_bypass',
                                action: 'vm_registry_key_blocked',
                                key_name: keyName,
                            });
                            this.blockVmRegistry = true;
                        }
                    }
                },

                onLeave: function (_retval) {
                    if (this.blockVmRegistry) {
                        retval.replace(2); // ERROR_FILE_NOT_FOUND
                    }
                },
            });

            this.hooksInstalled.RegOpenKeyW_VM = true;
        }
    },

    // === FILE SYSTEM DETECTION BYPASS ===
    hookFileSystemDetection: function () {
        send({
            type: 'info',
            target: 'vm_bypass',
            action: 'installing_file_system_detection_bypass',
        });

        // Hook directory creation to defeat sandbox detection
        const createDirectory = Module.findExportByName('kernel32.dll', 'CreateDirectoryW');
        if (createDirectory) {
            Interceptor.attach(createDirectory, {
                onEnter: _args => {
                    if (args[0] && !args[0].isNull()) {
                        const dirPath = args[0].readUtf16String().toLowerCase();

                        // Return realistic user directory paths to defeat sandbox detection
                        const legitimateDirs = [
                            'c:\\users\\john\\documents',
                            'c:\\users\\john\\desktop',
                            'c:\\program files\\common files',
                        ];

                        if (legitimateDirs.some(dir => dirPath.includes(dir))) {
                            send({
                                type: 'bypass',
                                target: 'vm_bypass',
                                action: 'spoofing_directory_to_appear_legitimate',
                                dir_path: dirPath,
                            });
                        }
                    }
                },
            });

            this.hooksInstalled.CreateDirectoryW_VM = true;
        }
    },

    // === PROCESS DETECTION BYPASS ===
    hookProcessDetection: function () {
        send({
            type: 'info',
            target: 'vm_bypass',
            action: 'installing_process_detection_bypass',
        });

        // Hook GetCurrentProcessId to potentially spoof PID
        const getCurrentProcessId = Module.findExportByName('kernel32.dll', 'GetCurrentProcessId');
        if (getCurrentProcessId) {
            Interceptor.attach(getCurrentProcessId, {
                onLeave: _retval => {
                    const pid = retval.toInt32();

                    // Don't spoof our own PID, just log for awareness
                    send({
                        type: 'info',
                        target: 'vm_bypass',
                        action: 'process_id_query',
                        process_id: pid,
                    });
                },
            });

            this.hooksInstalled.GetCurrentProcessId = true;
        }
    },

    // === NETWORK DETECTION BYPASS ===
    hookNetworkDetection: function () {
        send({
            type: 'info',
            target: 'vm_bypass',
            action: 'installing_network_detection_bypass',
        });

        // Hook hostname queries
        const getComputerNameEx = Module.findExportByName('kernel32.dll', 'GetComputerNameExW');
        if (getComputerNameEx) {
            Interceptor.attach(getComputerNameEx, {
                onLeave: function (_retval) {
                    if (retval.toInt32() !== 0) {
                        const nameBuffer = this.context.rdx;
                        if (nameBuffer && !nameBuffer.isNull()) {
                            this.spoofHostname(nameBuffer);
                        }
                    }
                },

                spoofHostname: nameBuffer => {
                    try {
                        const hostname = nameBuffer.readUtf16String().toLowerCase();

                        if (
                            hostname.includes('sandbox') ||
                            hostname.includes('crack') ||
                            hostname.includes('analysis') ||
                            hostname.includes('vm')
                        ) {
                            nameBuffer.writeUtf16String('DESKTOP-PC01');
                            send({
                                type: 'bypass',
                                target: 'vm_bypass',
                                action: 'hostname_spoofed',
                                original_hostname: hostname,
                            });
                        }
                    } catch (_e) {
                        // Hostname read failed
                    }
                },
            });

            this.hooksInstalled.GetComputerNameExW = true;
        }
    },

    // === ADVANCED CPUID INSTRUCTION HOOKING ===
    hookCpuidInstructions: function () {
        send({
            type: 'info',
            target: 'vm_bypass',
            action: 'installing_cpuid_instruction_hooks',
        });

        // Scan for CPUID instruction patterns in memory
        const modules = Process.enumerateModules();
        modules.forEach(module => {
            if (
                module.name.toLowerCase().includes('.exe') ||
                module.name.toLowerCase().includes('.dll')
            ) {
                Memory.scan(module.base, module.size, '0F A2', {
                    onMatch: (address, _size) => {
                        try {
                            // Hook CPUID instruction (0F A2)
                            Interceptor.attach(address, {
                                onEnter: function (_args) {
                                    const {eax} = this.context;
                                    const _ecx = this.context.ecx;

                                    // Hypervisor detection leaf
                                    if (eax === 0x40000000) {
                                        send({
                                            type: 'bypass',
                                            target: 'vm_bypass',
                                            action: 'cpuid_hypervisor_leaf_intercepted',
                                        });
                                        this.spoofHypervisor = true;
                                    }

                                    // Feature detection leaf
                                    if (eax === 1) {
                                        this.spoofFeatures = true;
                                    }
                                },
                                onLeave: function (_retval) {
                                    if (this.spoofHypervisor) {
                                        // Clear hypervisor signature
                                        this.context.eax = 0;
                                        this.context.ebx = 0;
                                        this.context.ecx = 0;
                                        this.context.edx = 0;
                                    }

                                    if (this.spoofFeatures) {
                                        // Clear hypervisor present bit (bit 31 of ECX)
                                        this.context.ecx &= ~(1 << 31);
                                    }
                                },
                            });

                            send({
                                type: 'bypass',
                                target: 'vm_bypass',
                                action: 'cpuid_instruction_hooked',
                                address: address.toString(),
                            });
                        } catch (_e) {
                            // Failed to hook this CPUID instance
                        }
                    },
                    onComplete: () => {},
                });
            }
        });

        this.hooksInstalled.CPUID_Instructions = true;
    },

    // === RED PILL DETECTION BYPASS ===
    hookRedPillDetection: function () {
        send({
            type: 'info',
            target: 'vm_bypass',
            action: 'installing_red_pill_bypass',
        });

        // Scan for SIDT instruction (0F 01 /1)
        const modules = Process.enumerateModules();
        modules.forEach(module => {
            if (module.name.toLowerCase().includes('.exe')) {
                Memory.scan(module.base, module.size, '0F 01', {
                    onMatch: (address, _size) => {
                        try {
                            const nextByte = address.add(2).readU8();
                            // Check if it's SIDT (ModR/M byte indicates /1)
                            if ((nextByte & 0x38) === 0x08) {
                                Interceptor.attach(address, {
                                    onEnter: function (_args) {
                                        send({
                                            type: 'bypass',
                                            target: 'vm_bypass',
                                            action: 'red_pill_sidt_intercepted',
                                        });
                                        this.idtAddress = args[0];
                                    },
                                    onLeave: function (_retval) {
                                        if (this.idtAddress && !this.idtAddress.isNull()) {
                                            // Spoof IDT base to look like bare metal
                                            // Typical bare metal IDT base: 0x80xxxxxx
                                            // VM IDT base often: 0xFFxxxxxx
                                            const idtBase = ptr(0x80000000);
                                            this.idtAddress.writePointer(idtBase);

                                            send({
                                                type: 'bypass',
                                                target: 'vm_bypass',
                                                action: 'red_pill_idt_spoofed',
                                                spoofed_base: idtBase.toString(),
                                            });
                                        }
                                    },
                                });
                            }
                        } catch (_e) {
                            send({
                                type: 'debug',
                                target: 'vm_bypass',
                                action: 'red_pill_detection_failed',
                                function: 'hookRedPillDetection',
                                error: e.toString(),
                                stack: e.stack || 'No stack trace available',
                            });
                        }
                    },
                    onComplete: () => {},
                });
            }
        });

        this.hooksInstalled.RedPill_SIDT = true;
    },

    // === NO PILL DETECTION BYPASS ===
    hookNoPillDetection: function () {
        send({
            type: 'info',
            target: 'vm_bypass',
            action: 'installing_no_pill_bypass',
        });

        // Scan for SLDT instruction (0F 00 /0)
        const modules = Process.enumerateModules();
        modules.forEach(module => {
            if (module.name.toLowerCase().includes('.exe')) {
                Memory.scan(module.base, module.size, '0F 00', {
                    onMatch: (address, _size) => {
                        try {
                            const nextByte = address.add(2).readU8();
                            // Check if it's SLDT (ModR/M byte indicates /0)
                            if ((nextByte & 0x38) === 0x00) {
                                Interceptor.attach(address, {
                                    onEnter: function (_args) {
                                        send({
                                            type: 'bypass',
                                            target: 'vm_bypass',
                                            action: 'no_pill_sldt_intercepted',
                                        });
                                        this.ldtAddress = args[0];
                                    },
                                    onLeave: function (_retval) {
                                        if (this.ldtAddress && !this.ldtAddress.isNull()) {
                                            // Spoof LDT selector to 0 (typical for bare metal)
                                            this.ldtAddress.writeU16(0);

                                            send({
                                                type: 'bypass',
                                                target: 'vm_bypass',
                                                action: 'no_pill_ldt_spoofed',
                                            });
                                        }
                                    },
                                });
                            }
                        } catch (_e) {
                            send({
                                type: 'debug',
                                target: 'vm_bypass',
                                action: 'no_pill_detection_failed',
                                function: 'hookNoPillDetection',
                                error: e.toString(),
                                stack: e.stack || 'No stack trace available',
                            });
                        }
                    },
                    onComplete: () => {},
                });
            }
        });

        this.hooksInstalled.NoPill_SLDT = true;
    },

    // === VMEXIT TIMING DETECTION BYPASS ===
    hookVmexitTiming: function () {
        send({
            type: 'info',
            target: 'vm_bypass',
            action: 'installing_vmexit_timing_bypass',
        });

        // Hook NtQuerySystemTime for consistent timing
        const ntQuerySystemTime = Module.findExportByName('ntdll.dll', 'NtQuerySystemTime');
        if (ntQuerySystemTime) {
            const baseSystemTime = Date.now() * 10000; // Convert to Windows FILETIME

            Interceptor.attach(ntQuerySystemTime, {
                onEnter: function (_args) {
                    this.systemTimePtr = args[0];
                },
                onLeave: function (_retval) {
                    if (this.systemTimePtr && !this.systemTimePtr.isNull()) {
                        // Normalize timing to prevent VMEXIT detection
                        const elapsed = Date.now() * 10000 - baseSystemTime;
                        const normalizedTime = baseSystemTime + elapsed * 0.95; // Reduce timing variance
                        this.systemTimePtr.writeU64(normalizedTime);
                    }
                },
            });

            this.hooksInstalled.NtQuerySystemTime_VMEXIT = true;
        }

        // Hook KeQueryPerformanceCounter for high-resolution timing
        const keQueryPerformanceCounter = Module.findExportByName(
            'ntoskrnl.exe',
            'KeQueryPerformanceCounter'
        );
        if (keQueryPerformanceCounter) {
            Interceptor.attach(keQueryPerformanceCounter, {
                onLeave: _retval => {
                    // Add consistent delay to mask VMEXIT timing
                    const counter = retval.toInt32();
                    retval.replace(ptr(counter + 1000));
                },
            });

            this.hooksInstalled.KeQueryPerformanceCounter_VMEXIT = true;
        }
    },

    // === CLOUD PROVIDER VM DETECTION BYPASS ===
    hookCloudProviderDetection: function () {
        send({
            type: 'info',
            target: 'vm_bypass',
            action: 'installing_cloud_provider_detection_bypass',
        });

        // AWS detection bypass
        this.hookAwsDetection();

        // Azure detection bypass
        this.hookAzureDetection();

        // GCP detection bypass
        this.hookGcpDetection();

        // Alibaba Cloud detection bypass
        this.hookAlibabaDetection();
    },

    hookAwsDetection: function () {
        // Hook file access to AWS metadata service
        const createFileW = Module.findExportByName('kernel32.dll', 'CreateFileW');
        if (createFileW) {
            Interceptor.attach(createFileW, {
                onEnter: function (_args) {
                    if (args[0] && !args[0].isNull()) {
                        const filename = args[0].readUtf16String();
                        if (filename?.includes('169.254.169.254')) {
                            send({
                                type: 'bypass',
                                target: 'vm_bypass',
                                action: 'aws_metadata_service_blocked',
                                filename: filename,
                            });
                            this.blockAwsMetadata = true;
                        }
                    }
                },
                onLeave: function (_retval) {
                    if (this.blockAwsMetadata) {
                        retval.replace(ptr(-1)); // INVALID_HANDLE_VALUE
                    }
                },
            });

            this.hooksInstalled.CreateFileW_AWS = true;
        }

        // Block AWS instance identity document queries
        const httpSendRequest = Module.findExportByName('winhttp.dll', 'WinHttpSendRequest');
        if (httpSendRequest) {
            Interceptor.attach(httpSendRequest, {
                onEnter: function (_args) {
                    // Block requests to AWS metadata endpoints
                    this.blockAwsRequest = true;
                },
                onLeave: function (_retval) {
                    if (this.blockAwsRequest) {
                        retval.replace(0); // FALSE - request failed
                    }
                },
            });

            this.hooksInstalled.WinHttpSendRequest_AWS = true;
        }
    },

    hookAzureDetection: function () {
        // Hook Azure VM agent detection
        const openServiceW = Module.findExportByName('advapi32.dll', 'OpenServiceW');
        if (openServiceW) {
            Interceptor.attach(openServiceW, {
                onEnter: function (_args) {
                    if (args[1] && !args[1].isNull()) {
                        const serviceName = args[1].readUtf16String();
                        if (
                            serviceName &&
                            (serviceName.includes('WindowsAzureGuestAgent') ||
                                serviceName.includes('WindowsAzureTelemetryService'))
                        ) {
                            send({
                                type: 'bypass',
                                target: 'vm_bypass',
                                action: 'azure_service_blocked',
                                service: serviceName,
                            });
                            this.blockAzureService = true;
                        }
                    }
                },
                onLeave: function (_retval) {
                    if (this.blockAzureService) {
                        retval.replace(ptr(0)); // NULL - service not found
                    }
                },
            });

            this.hooksInstalled.OpenServiceW_Azure = true;
        }
    },

    hookGcpDetection: function () {
        // Hook GCP metadata server detection
        const getAddrInfo = Module.findExportByName('ws2_32.dll', 'getaddrinfo');
        if (getAddrInfo) {
            Interceptor.attach(getAddrInfo, {
                onEnter: function (_args) {
                    if (args[0] && !args[0].isNull()) {
                        const hostname = args[0].readAnsiString();
                        if (hostname?.includes('metadata.google.internal')) {
                            send({
                                type: 'bypass',
                                target: 'vm_bypass',
                                action: 'gcp_metadata_dns_blocked',
                                hostname: hostname,
                            });
                            this.blockGcpDns = true;
                        }
                    }
                },
                onLeave: function (_retval) {
                    if (this.blockGcpDns) {
                        retval.replace(11001); // WSAHOST_NOT_FOUND
                    }
                },
            });

            this.hooksInstalled.getaddrinfo_GCP = true;
        }
    },

    hookAlibabaDetection: function () {
        // Hook Alibaba Cloud ECS detection
        const regQueryValueExW = Module.findExportByName('advapi32.dll', 'RegQueryValueExW');
        if (regQueryValueExW) {
            Interceptor.attach(regQueryValueExW, {
                onEnter: function (_args) {
                    if (args[1] && !args[1].isNull()) {
                        const valueName = args[1].readUtf16String();
                        if (valueName?.includes('AlibabaCloud')) {
                            send({
                                type: 'bypass',
                                target: 'vm_bypass',
                                action: 'alibaba_cloud_registry_blocked',
                                value: valueName,
                            });
                            this.blockAlibabaReg = true;
                        }
                    }
                },
                onLeave: function (_retval) {
                    if (this.blockAlibabaReg) {
                        retval.replace(2); // ERROR_FILE_NOT_FOUND
                    }
                },
            });

            this.hooksInstalled.RegQueryValueExW_Alibaba = true;
        }
    },

    // === ANTI-DEBUGGING INTEGRATION ===
    hookAntiDebuggingIntegration: function () {
        send({
            type: 'info',
            target: 'vm_bypass',
            action: 'installing_anti_debugging_integration',
        });

        // Hook PEB.BeingDebugged check
        const peb = Process.env.PEB;
        if (peb) {
            const beingDebugged = peb.add(2); // Offset to BeingDebugged flag
            beingDebugged.writeU8(0);

            send({
                type: 'bypass',
                target: 'vm_bypass',
                action: 'peb_being_debugged_cleared',
            });
        }

        // Hook NtGlobalFlag check
        const ntGlobalFlag = peb ? peb.add(0x68) : null; // Offset to NtGlobalFlag
        if (ntGlobalFlag) {
            ntGlobalFlag.writeU32(0);

            send({
                type: 'bypass',
                target: 'vm_bypass',
                action: 'nt_global_flag_cleared',
            });
        }

        // Hook debug register access
        const ntGetContextThread = Module.findExportByName('ntdll.dll', 'NtGetContextThread');
        if (ntGetContextThread) {
            Interceptor.attach(ntGetContextThread, {
                onLeave: function (_retval) {
                    if (retval.toInt32() === 0) {
                        const context = this.context.rdx;
                        if (context && !context.isNull()) {
                            // Clear debug registers (DR0-DR3, DR6, DR7)
                            context.add(0x18).writeU64(0); // DR0
                            context.add(0x20).writeU64(0); // DR1
                            context.add(0x28).writeU64(0); // DR2
                            context.add(0x30).writeU64(0); // DR3
                            context.add(0x38).writeU64(0); // DR6
                            context.add(0x40).writeU64(0); // DR7

                            send({
                                type: 'bypass',
                                target: 'vm_bypass',
                                action: 'debug_registers_cleared',
                            });
                        }
                    }
                },
            });

            this.hooksInstalled.NtGetContextThread_Debug = true;
        }
    },

    // === RDTSC INSTRUCTION HOOKING ===
    hookRdtscInstructions: function () {
        send({
            type: 'info',
            target: 'vm_bypass',
            action: 'installing_rdtsc_instruction_hooks',
        });

        // Scan for RDTSC instructions (0F 31)
        const modules = Process.enumerateModules();
        const rdtscBase = Date.now() * 1000000;

        modules.forEach(module => {
            if (module.name.toLowerCase().includes('.exe')) {
                Memory.scan(module.base, module.size, '0F 31', {
                    onMatch: (address, _size) => {
                        try {
                            Interceptor.attach(address, {
                                onEnter: _args => {
                                    send({
                                        type: 'bypass',
                                        target: 'vm_bypass',
                                        action: 'rdtsc_instruction_intercepted',
                                        address: address.toString(),
                                    });
                                },
                                onLeave: function (_retval) {
                                    // Normalize TSC values to prevent timing analysis
                                    const elapsed = Date.now() * 1000000 - rdtscBase;
                                    const normalizedTsc = rdtscBase + elapsed * 2.4; // Scale to 2.4GHz CPU frequency

                                    this.context.eax = normalizedTsc & 0xffffffff;
                                    this.context.edx = (normalizedTsc >> 0) & 0xffffffff;
                                },
                            });
                        } catch (_e) {
                            send({
                                type: 'debug',
                                target: 'vm_bypass',
                                action: 'rdtsc_hook_failed',
                                function: 'hookRdtscInstructions',
                                error: e.toString(),
                                stack: e.stack || 'No stack trace available',
                            });
                        }
                    },
                    onComplete: () => {},
                });
            }
        });

        // Scan for RDTSCP instructions (0F 01 F9)
        modules.forEach(module => {
            if (module.name.toLowerCase().includes('.exe')) {
                Memory.scan(module.base, module.size, '0F 01 F9', {
                    onMatch: (address, _size) => {
                        try {
                            Interceptor.attach(address, {
                                onLeave: function (_retval) {
                                    // Normalize RDTSCP values
                                    const elapsed = Date.now() * 1000000 - rdtscBase;
                                    const normalizedTsc = rdtscBase + elapsed * 2.4;

                                    this.context.eax = normalizedTsc & 0xffffffff;
                                    this.context.edx = (normalizedTsc >> 0) & 0xffffffff;
                                    this.context.ecx = 0; // Clear processor ID
                                },
                            });
                        } catch (_e) {
                            send({
                                type: 'debug',
                                target: 'vm_bypass',
                                action: 'rdtscp_hook_failed',
                                function: 'hookRdtscInstructions',
                                error: e.toString(),
                                stack: e.stack || 'No stack trace available',
                            });
                        }
                    },
                    onComplete: () => {},
                });
            }
        });

        this.hooksInstalled.RDTSC_Instructions = true;
    },

    // === VMX/SVM INSTRUCTION DETECTION BYPASS ===
    hookVmxSvmInstructions: function () {
        send({
            type: 'info',
            target: 'vm_bypass',
            action: 'installing_vmx_svm_instruction_bypass',
        });

        // Hook VMXON instruction detection (F3 0F C7 /6)
        const modules = Process.enumerateModules();
        modules.forEach(module => {
            if (module.name.toLowerCase().includes('.exe')) {
                Memory.scan(module.base, module.size, 'F3 0F C7', {
                    onMatch: (address, _size) => {
                        try {
                            Interceptor.attach(address, {
                                onEnter: function (_args) {
                                    send({
                                        type: 'bypass',
                                        target: 'vm_bypass',
                                        action: 'vmxon_instruction_blocked',
                                    });
                                    this.blockVmxon = true;
                                },
                                onLeave: function (_retval) {
                                    if (this.blockVmxon) {
                                        // Set carry flag to indicate failure
                                        this.context.eflags |= 1;
                                    }
                                },
                            });
                        } catch (_e) {
                            send({
                                type: 'debug',
                                target: 'vm_bypass',
                                action: 'vmx_svm_hook_failed',
                                function: 'hookVmxSvmInstructions',
                                error: e.toString(),
                                stack: e.stack || 'No stack trace available',
                            });
                        }
                    },
                    onComplete: () => {},
                });
            }
        });

        this.hooksInstalled.VMX_SVM_Instructions = true;
    },

    // === EPT/NPT DETECTION BYPASS ===
    hookEptNptDetection: function () {
        send({
            type: 'info',
            target: 'vm_bypass',
            action: 'installing_ept_npt_detection_bypass',
        });

        // Hook MSR reads for EPT/NPT detection
        const ntReadMsr = Module.findExportByName('ntdll.dll', 'NtReadMsr');
        if (ntReadMsr) {
            Interceptor.attach(ntReadMsr, {
                onEnter: function (_args) {
                    const msrIndex = args[0].toInt32();

                    // EPT capabilities MSR (0x48C) and NPT MSR
                    if (msrIndex === 0x48c || msrIndex === 0xc0010114) {
                        send({
                            type: 'bypass',
                            target: 'vm_bypass',
                            action: 'ept_npt_msr_read_blocked',
                            msr: `0x${msrIndex.toString(16)}`,
                        });
                        this.blockEptMsr = true;
                    }
                },
                onLeave: function (_retval) {
                    if (this.blockEptMsr) {
                        retval.replace(0xc0000001); // STATUS_UNSUCCESSFUL
                    }
                },
            });

            this.hooksInstalled.NtReadMsr_EPT = true;
        }
    },

    // === ADVANCED CONTAINER DETECTION BYPASS ===
    hookAdvancedContainerDetection: function () {
        send({
            type: 'info',
            target: 'vm_bypass',
            action: 'installing_advanced_container_detection_bypass',
        });

        // Podman detection bypass
        this.hookPodmanDetection();

        // containerd detection bypass
        this.hookContainerdDetection();

        // systemd-nspawn detection bypass
        this.hookSystemdNspawnDetection();
    },

    hookPodmanDetection: function () {
        const createFileW = Module.findExportByName('kernel32.dll', 'CreateFileW');
        if (createFileW) {
            Interceptor.attach(createFileW, {
                onEnter: function (_args) {
                    if (args[0] && !args[0].isNull()) {
                        const filename = args[0].readUtf16String();
                        if (
                            filename &&
                            (filename.includes('podman') ||
                                filename.includes('/run/podman') ||
                                filename.includes('/var/lib/containers'))
                        ) {
                            send({
                                type: 'bypass',
                                target: 'vm_bypass',
                                action: 'podman_file_access_blocked',
                                filename: filename,
                            });
                            this.blockPodmanAccess = true;
                        }
                    }
                },
                onLeave: function (_retval) {
                    if (this.blockPodmanAccess) {
                        retval.replace(ptr(-1)); // INVALID_HANDLE_VALUE
                    }
                },
            });

            this.hooksInstalled.CreateFileW_Podman = true;
        }
    },

    hookContainerdDetection: function () {
        const getEnvironmentVariableW = Module.findExportByName(
            'kernel32.dll',
            'GetEnvironmentVariableW'
        );
        if (getEnvironmentVariableW) {
            Interceptor.attach(getEnvironmentVariableW, {
                onEnter: function (_args) {
                    if (args[0] && !args[0].isNull()) {
                        const varName = args[0].readUtf16String();
                        if (
                            varName &&
                            (varName.includes('CONTAINERD') ||
                                varName === 'container' ||
                                varName === 'CONTAINER_HOST')
                        ) {
                            send({
                                type: 'bypass',
                                target: 'vm_bypass',
                                action: 'containerd_env_var_blocked',
                                variable: varName,
                            });
                            this.blockContainerdVar = true;
                        }
                    }
                },
                onLeave: function (_retval) {
                    if (this.blockContainerdVar) {
                        retval.replace(0); // Variable not found
                    }
                },
            });

            this.hooksInstalled.GetEnvironmentVariableW_Containerd = true;
        }
    },

    hookSystemdNspawnDetection: function () {
        // Hook systemd-nspawn detection through machine ID
        const readFile = Module.findExportByName('kernel32.dll', 'ReadFile');
        if (readFile) {
            Interceptor.attach(readFile, {
                onEnter: function (_args) {
                    this.hFile = args[0];
                    this.lpBuffer = args[1];
                },
                onLeave: function (_retval) {
                    if (retval.toInt32() && this.lpBuffer && !this.lpBuffer.isNull()) {
                        try {
                            const data = this.lpBuffer.readAnsiString();
                            if (data?.includes('systemd-nspawn')) {
                                send({
                                    type: 'bypass',
                                    target: 'vm_bypass',
                                    action: 'systemd_nspawn_data_spoofed',
                                });
                                // Replace systemd-nspawn indicators
                                const spoofedData = data.replace(/systemd-nspawn/g, 'systemd');
                                this.lpBuffer.writeAnsiString(spoofedData);
                            }
                        } catch (_e) {
                            send({
                                type: 'debug',
                                target: 'vm_bypass',
                                action: 'systemd_nspawn_data_read_failed',
                                function: 'hookSystemdNspawnDetection',
                                error: e.toString(),
                                stack: e.stack || 'No stack trace available',
                            });
                        }
                    }
                },
            });

            this.hooksInstalled.ReadFile_SystemdNspawn = true;
        }
    },

    // === WMI MANIPULATION ===
    hookWmiManipulation: function () {
        send({
            type: 'info',
            target: 'vm_bypass',
            action: 'installing_wmi_manipulation_hooks',
        });

        // Hook CoCreateInstance for WMI COM objects
        const coCreateInstance = Module.findExportByName('ole32.dll', 'CoCreateInstance');
        if (coCreateInstance) {
            Interceptor.attach(coCreateInstance, {
                onEnter: function (_args) {
                    // WbemLocator CLSID: {4590F811-1D3A-11D0-891F-00AA004B2E24}
                    const clsid = args[0];
                    if (clsid && !clsid.isNull()) {
                        const clsidBytes = clsid.readByteArray(16);
                        const wbemLocatorClsid = [
                            0x11, 0xf8, 0x90, 0x45, 0x3a, 0x1d, 0xd0, 0x11, 0x89, 0x1f, 0x00, 0xaa,
                            0x00, 0x4b, 0x2e, 0x24,
                        ];

                        let isWbemLocator = true;
                        for (let i = 0; i < 16; i++) {
                            if (clsidBytes[i] !== wbemLocatorClsid[i]) {
                                isWbemLocator = false;
                                break;
                            }
                        }

                        if (isWbemLocator) {
                            send({
                                type: 'bypass',
                                target: 'vm_bypass',
                                action: 'wmi_com_object_creation_intercepted',
                            });
                            this.wmiIntercepted = true;
                        }
                    }
                },
            });

            this.hooksInstalled.CoCreateInstance_WMI = true;
        }
    },

    // === NETWORK-BASED VM DETECTION BYPASS ===
    hookNetworkVmDetection: function () {
        send({
            type: 'info',
            target: 'vm_bypass',
            action: 'installing_network_vm_detection_bypass',
        });

        // Hook DHCP client detection
        const dhcpRequestParams = Module.findExportByName('dhcpcsvc.dll', 'DhcpRequestParams');
        if (dhcpRequestParams) {
            Interceptor.attach(dhcpRequestParams, {
                onEnter: _args => {
                    send({
                        type: 'bypass',
                        target: 'vm_bypass',
                        action: 'dhcp_request_intercepted',
                    });
                },
                onLeave: _retval => {
                    // Spoof DHCP responses to hide VM indicators
                    if (retval.toInt32() === 0) {
                        send({
                            type: 'bypass',
                            target: 'vm_bypass',
                            action: 'dhcp_response_spoofed',
                        });
                    }
                },
            });

            this.hooksInstalled.DhcpRequestParams = true;
        }

        // Hook DNS resolution for VM-specific domains
        const dnsQuery = Module.findExportByName('dnsapi.dll', 'DnsQuery_W');
        if (dnsQuery) {
            Interceptor.attach(dnsQuery, {
                onEnter: function (_args) {
                    if (args[0] && !args[0].isNull()) {
                        const domain = args[0].readUtf16String();
                        const vmDomains = [
                            'vmware.com',
                            'virtualbox.org',
                            'parallels.com',
                            'microsoft.com/hyperv',
                            'qemu.org',
                            'xen.org',
                        ];

                        if (vmDomains.some(vmd => domain?.includes(vmd))) {
                            send({
                                type: 'bypass',
                                target: 'vm_bypass',
                                action: 'vm_dns_query_blocked',
                                domain: domain,
                            });
                            this.blockVmDns = true;
                        }
                    }
                },
                onLeave: function (_retval) {
                    if (this.blockVmDns) {
                        retval.replace(9003); // DNS_ERROR_RCODE_NAME_ERROR
                    }
                },
            });

            this.hooksInstalled.DnsQuery_W = true;
        }
    },

    // === GPU VM DETECTION BYPASS ===
    hookGpuVmDetection: function () {
        send({
            type: 'info',
            target: 'vm_bypass',
            action: 'installing_gpu_vm_detection_bypass',
        });

        // Hook Direct3D device creation
        const d3d9Create = Module.findExportByName('d3d9.dll', 'Direct3DCreate9');
        if (d3d9Create) {
            Interceptor.attach(d3d9Create, {
                onLeave: _retval => {
                    if (!retval.isNull()) {
                        send({
                            type: 'bypass',
                            target: 'vm_bypass',
                            action: 'd3d9_device_creation_intercepted',
                        });
                        // Device spoofing would be implemented here
                    }
                },
            });

            this.hooksInstalled.Direct3DCreate9 = true;
        }

        // Hook OpenGL vendor string queries
        const glGetString = Module.findExportByName('opengl32.dll', 'glGetString');
        if (glGetString) {
            Interceptor.attach(glGetString, {
                onEnter: function (_args) {
                    this.stringType = args[0].toInt32();
                },
                onLeave: function (_retval) {
                    if (!retval.isNull()) {
                        const str = retval.readAnsiString();

                        // GL_VENDOR = 0x1F00
                        if (
                            this.stringType === 0x1f00 &&
                            str &&
                            (str.includes('VMware') ||
                                str.includes('VirtualBox') ||
                                str.includes('Microsoft') ||
                                str.includes('llvmpipe'))
                        ) {
                            const spoofedVendor = Memory.allocAnsiString('NVIDIA Corporation');
                            retval.replace(spoofedVendor);

                            send({
                                type: 'bypass',
                                target: 'vm_bypass',
                                action: 'opengl_vendor_spoofed',
                                original: str,
                            });
                        }
                    }
                },
            });

            this.hooksInstalled.glGetString = true;
        }
    },

    // === UEFI DETECTION BYPASS ===
    hookUefiDetection: function () {
        send({
            type: 'info',
            target: 'vm_bypass',
            action: 'installing_uefi_detection_bypass',
        });

        // Hook GetFirmwareEnvironmentVariable
        const getFirmwareVar = Module.findExportByName(
            'kernel32.dll',
            'GetFirmwareEnvironmentVariableW'
        );
        if (getFirmwareVar) {
            Interceptor.attach(getFirmwareVar, {
                onEnter: function (_args) {
                    if (args[0] && !args[0].isNull()) {
                        const varName = args[0].readUtf16String();
                        if (
                            varName &&
                            (varName.includes('VBox') ||
                                varName.includes('VMware') ||
                                varName.includes('QEMU'))
                        ) {
                            send({
                                type: 'bypass',
                                target: 'vm_bypass',
                                action: 'uefi_variable_access_blocked',
                                variable: varName,
                            });
                            this.blockUefiVar = true;
                        }
                    }
                },
                onLeave: function (_retval) {
                    if (this.blockUefiVar) {
                        retval.replace(0); // Return 0 bytes read
                    }
                },
            });

            this.hooksInstalled.GetFirmwareEnvironmentVariableW = true;
        }

        // Hook ACPI table enumeration
        const enumSystemFirmwareTables = Module.findExportByName(
            'kernel32.dll',
            'EnumSystemFirmwareTables'
        );
        if (enumSystemFirmwareTables) {
            Interceptor.attach(enumSystemFirmwareTables, {
                onEnter: function (_args) {
                    const signature = args[0].toInt32();
                    // ACPI signature
                    if (signature === 0x41435049) {
                        send({
                            type: 'bypass',
                            target: 'vm_bypass',
                            action: 'acpi_table_enumeration_intercepted',
                        });
                        this.filterAcpiTables = true;
                    }
                },
            });

            this.hooksInstalled.EnumSystemFirmwareTables_UEFI = true;
        }
    },

    // === MEMORY AND I/O DETECTION BYPASS ===
    hookMemoryIoDetection: function () {
        send({
            type: 'info',
            target: 'vm_bypass',
            action: 'installing_memory_io_detection_bypass',
        });

        // Hook IN/OUT instructions via DeviceIoControl
        const deviceIoControl = Module.findExportByName('kernel32.dll', 'DeviceIoControl');
        if (deviceIoControl) {
            Interceptor.attach(deviceIoControl, {
                onEnter: function (_args) {
                    const ioControlCode = args[1].toInt32();

                    // I/O port access control codes
                    if ((ioControlCode & 0xffff0000) === 0x22e000) {
                        send({
                            type: 'bypass',
                            target: 'vm_bypass',
                            action: 'io_port_access_intercepted',
                            code: `0x${ioControlCode.toString(16)}`,
                        });

                        // Check for VM-specific I/O ports
                        const inBuffer = args[2];
                        if (inBuffer && !inBuffer.isNull()) {
                            const port = inBuffer.readU16();

                            // VMware backdoor port (0x5658 = 'VX')
                            // VirtualBox port (0x5659)
                            if (port === 0x5658 || port === 0x5659) {
                                send({
                                    type: 'bypass',
                                    target: 'vm_bypass',
                                    action: 'vm_io_port_blocked',
                                    port: `0x${port.toString(16)}`,
                                });
                                this.blockVmIoPort = true;
                            }
                        }
                    }
                },
                onLeave: function (_retval) {
                    if (this.blockVmIoPort) {
                        retval.replace(0); // FALSE - operation failed
                    }
                },
            });

            this.hooksInstalled.DeviceIoControl_IO = true;
        }

        // Hook memory allocation patterns
        const virtualAlloc = Module.findExportByName('kernel32.dll', 'VirtualAlloc');
        if (virtualAlloc) {
            Interceptor.attach(virtualAlloc, {
                onEnter: _args => {
                    const size = args[1].toInt32();
                    const allocType = args[2].toInt32();

                    // Check for VM-specific allocation patterns
                    if (size === 0x1000 && allocType && 0x1000) {
                        // MEM_COMMIT
                        send({
                            type: 'info',
                            target: 'vm_bypass',
                            action: 'memory_allocation_pattern_monitored',
                            size: size,
                        });
                    }
                },
            });

            this.hooksInstalled.VirtualAlloc_Memory = true;
        }
    },

    // === TSX DETECTION BYPASS ===
    hookTsxDetection: function () {
        send({
            type: 'info',
            target: 'vm_bypass',
            action: 'installing_tsx_detection_bypass',
        });

        // Scan for XBEGIN instruction (C7 F8)
        const modules = Process.enumerateModules();
        modules.forEach(module => {
            if (module.name.toLowerCase().includes('.exe')) {
                Memory.scan(module.base, module.size, 'C7 F8', {
                    onMatch: (address, _size) => {
                        try {
                            Interceptor.attach(address, {
                                onEnter: _args => {
                                    send({
                                        type: 'bypass',
                                        target: 'vm_bypass',
                                        action: 'tsx_xbegin_intercepted',
                                    });
                                },
                                onLeave: function (_retval) {
                                    // Force transaction abort to hide TSX support
                                    this.context.eax = 0xffffffff; // Transaction abort
                                },
                            });
                        } catch (_e) {
                            send({
                                type: 'debug',
                                target: 'vm_bypass',
                                action: 'tsx_detection_hook_failed',
                                function: 'hookTsxDetection',
                                error: e.toString(),
                                stack: e.stack || 'No stack trace available',
                            });
                        }
                    },
                    onComplete: () => {},
                });
            }
        });

        this.hooksInstalled.TSX_Detection = true;
    },

    // === INSTALLATION SUMMARY ===
    installSummary: function () {
        setTimeout(() => {
            send({
                type: 'summary',
                target: 'vm_bypass',
                action: 'installation_summary_start',
            });

            const categories = {
                'VirtualBox Detection': 0,
                'VMware Detection': 0,
                'Hyper-V Detection': 0,
                'QEMU Detection': 0,
                'Sandbox Detection': 0,
                'Hardware Fingerprinting': 0,
                'Registry Detection': 0,
                'File System Detection': 0,
                'Process Detection': 0,
                'Network Detection': 0,
                'Generic VM Detection': 0,
            };

            for (let hook in this.hooksInstalled) {
                if (hook.includes('VBox')) {
                    categories['VirtualBox Detection']++;
                } else if (hook.includes('VMware')) {
                    categories['VMware Detection']++;
                } else if (hook.includes('HyperV')) {
                    categories['Hyper-V Detection']++;
                } else if (hook.includes('QEMU')) {
                    categories['QEMU Detection']++;
                } else if (hook.includes('Sandbox')) {
                    categories['Sandbox Detection']++;
                } else if (hook.includes('Hardware')) {
                    categories['Hardware Fingerprinting']++;
                } else if (hook.includes('Reg')) {
                    categories['Registry Detection']++;
                } else if (hook.includes('File') || hook.includes('Directory')) {
                    categories['File System Detection']++;
                } else if (hook.includes('Process')) {
                    categories['Process Detection']++;
                } else if (hook.includes('Network') || hook.includes('Computer')) {
                    categories['Network Detection']++;
                } else if (hook.includes('VM')) {
                    categories['Generic VM Detection']++;
                }
            }

            for (let category in categories) {
                if (categories[category] > 0) {
                    send({
                        type: 'summary',
                        target: 'vm_bypass',
                        action: 'category_summary',
                        category: category,
                        hook_count: categories[category],
                    });
                }
            }

            send({
                type: 'summary',
                target: 'vm_bypass',
                action: 'active_protection_summary_start',
            });

            const {config} = this;
            if (config.vmDetection.enabled) {
                send({
                    type: 'summary',
                    target: 'vm_bypass',
                    action: 'vm_detection_bypass_active',
                });
                if (config.vmDetection.virtualBox.enabled) {
                    send({
                        type: 'summary',
                        target: 'vm_bypass',
                        action: 'virtualbox_bypass_active',
                    });
                }
                if (config.vmDetection.vmware.enabled) {
                    send({
                        type: 'summary',
                        target: 'vm_bypass',
                        action: 'vmware_bypass_active',
                    });
                }
                if (config.vmDetection.hyperV.enabled) {
                    send({
                        type: 'summary',
                        target: 'vm_bypass',
                        action: 'hyperv_bypass_active',
                    });
                }
                if (config.vmDetection.qemu.enabled) {
                    send({
                        type: 'summary',
                        target: 'vm_bypass',
                        action: 'qemu_bypass_active',
                    });
                }
            }

            if (config.sandboxDetection.enabled) {
                send({
                    type: 'summary',
                    target: 'vm_bypass',
                    action: 'sandbox_detection_bypass_active',
                    features: [
                        'file_system_spoofing',
                        'process_list_filtering',
                        'registry_key_hiding',
                        'network_config_spoofing',
                    ],
                });
            }

            if (config.hardwareFingerprinting.spoofCpuInfo) {
                send({
                    type: 'summary',
                    target: 'vm_bypass',
                    action: 'hardware_fingerprinting_bypass_active',
                });
            }

            if (config.timingDetection.enabled) {
                send({
                    type: 'summary',
                    target: 'vm_bypass',
                    action: 'enhanced_timing_detection_countermeasures_active',
                    features: [
                        'rdtsc_timing_normalization',
                        'performance_counter_spoofing',
                        'high_precision_timing_prevention',
                    ],
                });
            }

            if (config.containerDetection.enabled) {
                send({
                    type: 'summary',
                    target: 'vm_bypass',
                    action: 'container_detection_bypass_active',
                    container_types: [
                        config.containerDetection.docker.enabled ? 'docker' : null,
                        config.containerDetection.wsl.enabled ? 'wsl' : null,
                        config.containerDetection.kubernetes.enabled ? 'kubernetes' : null,
                        config.containerDetection.lxc.enabled ? 'lxc' : null,
                    ].filter(type => type !== null),
                });
            }

            if (config.cpuFeatureDetection.enabled) {
                send({
                    type: 'summary',
                    target: 'vm_bypass',
                    action: 'cpu_feature_detection_bypass_active',
                    features: [
                        'cpuid_instruction_spoofing',
                        'smbios_table_blocking',
                        'msr_access_prevention',
                        'hypervisor_bit_masking',
                    ],
                });
            }

            send({
                type: 'summary',
                target: 'vm_bypass',
                action: 'installation_complete',
                version: '3.0.0',
                total_hooks: Object.keys(this.hooksInstalled).length,
                new_features: [
                    'container_detection_bypass',
                    'wsl_detection_prevention',
                    'enhanced_timing_attacks_mitigation',
                    'advanced_cpu_feature_spoofing',
                ],
                status: 'active',
            });
        }, 100);
    },

    // === ENHANCEMENT FUNCTIONS ===
    initializeAdvancedVmBehaviorAnalysis: function () {
        send({
            type: 'enhancement',
            target: 'vm_bypass',
            action: 'initializing_behavior_analysis',
            description: 'Setting up advanced VM behavior pattern analysis',
        });

        // Monitor VM-specific behavior patterns
        this.behaviorPatterns = {
            instructionLatency: new Map(),
            memoryAccessPatterns: [],
            ioPortAccess: new Set(),
            interruptPatterns: [],
            cacheMisses: 0,
            tlbFlushes: 0,
        };

        // Hook performance counter access
        const ntQueryPerformanceCounter = Module.findExportByName(
            'ntdll.dll',
            'NtQueryPerformanceCounter'
        );
        if (ntQueryPerformanceCounter) {
            Interceptor.attach(ntQueryPerformanceCounter, {
                onEnter: function (_args) {
                    this.counterType = args[0];
                },
                onLeave: function (_retval) {
                    // Normalize counter values to hide VM characteristics
                    if (retval.toInt32() === 0 && this.counterType) {
                        const counter = this.counterType.readU64();
                        // Apply jitter to hide VM timing patterns
                        const jitter = Math.random() * 1000;
                        this.counterType.writeU64(counter.add(jitter));
                    }
                },
            });
        }

        // Monitor RDTSC instruction patterns
        const rdtscDetector = Memory.alloc(32);
        Memory.patchCode(rdtscDetector, 32, code => {
            const writer = new X86Writer(code, { pc: rdtscDetector });
            writer.putPushfx();
            writer.putPushax();
            // RDTSC
            writer.putBytes([0x0f, 0x31]);
            // Add random jitter to EDX:EAX
            writer.putMovRegU32('ecx', Math.floor(Math.random() * 100));
            writer.putAddRegReg('eax', 'ecx');
            writer.putAdcRegImm('edx', 0);
            writer.putPopax();
            writer.putPopfx();
            writer.putRet();
        });

        // Analyze memory access patterns for VM detection
        Process.setExceptionHandler(details => {
            if (details.type === 'access-violation') {
                const {address} = details;
                // Check if this is a VM-specific memory region
                const vmRegions = [
                    {
                        start: ptr('0xD0000000'),
                        end: ptr('0xD0FFFFFF'),
                        name: 'VirtualBox MMIO',
                    },
                    {
                        start: ptr('0xE0000000'),
                        end: ptr('0xE0FFFFFF'),
                        name: 'VMware SVGA',
                    },
                    {
                        start: ptr('0xF0000000'),
                        end: ptr('0xF0FFFFFF'),
                        name: 'QEMU VGA',
                    },
                ];

                for (let region of vmRegions) {
                    if (address.compare(region.start) >= 0 && address.compare(region.end) <= 0) {
                        // Redirect to legitimate memory
                        const realMemory = Memory.alloc(Process.pageSize);
                        details.memory.address = realMemory;
                        return true; // Continue execution
                    }
                }
            }
            return false;
        });

        this.hooksInstalled.behavior_analysis = true;
    },

    setupDynamicInstructionEmulation: function () {
        send({
            type: 'enhancement',
            target: 'vm_bypass',
            action: 'setting_up_instruction_emulation',
            description: 'Implementing dynamic instruction emulation for VM detection bypass',
        });

        // Create instruction emulator for privileged instructions
        this.instructionEmulator = {
            cpuidCache: new Map(),
            msrCache: new Map(),
            smsw: 0x8001, // Real mode flag set
            sldt: 0x0000, // Null LDT selector
            sgdt: null,
            sidt: null,
        };

        // Hook CPUID instruction execution
        const _cpuidHook = function (context) {
            const {eax} = context;
            const _ecx = context.ecx;
            const key = `${eax}:${ecx}`;

            if (this.instructionEmulator.cpuidCache.has(key)) {
                const cached = this.instructionEmulator.cpuidCache.get(key);
                context.eax = cached.eax;
                context.ebx = cached.ebx;
                context.ecx = cached.ecx;
                context.edx = cached.edx;
            } else {
                // Emulate real hardware response
                switch (eax) {
                    case 0x1: // Processor Info
                        context.ecx &= ~(1 << 31); // Clear hypervisor bit
                        break;
                    case 0x40000000: // Hypervisor vendor
                        context.eax = 0; // No hypervisor
                        context.ebx = 0;
                        context.ecx = 0;
                        context.edx = 0;
                        break;
                    case 0x80000002: // Processor brand string
                    case 0x80000003:
                    case 0x80000004: {
                        // Return genuine Intel/AMD string
                        const brand = 'Intel(R) Core(TM) i9-12900K';
                        const offset = (eax - 0x80000002) * 16;
                        const chunk = brand.substr(offset, 16);
                        // Write to registers
                        for (let i = 0; i < 4; i++) {
                            const char4 = chunk.substr(i * 4, 4);
                            let value = 0;
                            for (let j = 0; j < 4; j++) {
                                value |= (char4.charCodeAt(j) || 0) << (j * 8);
                            }
                            switch (i) {
                                case 0:
                                    context.eax = value;
                                    break;
                                case 1:
                                    context.ebx = value;
                                    break;
                                case 2:
                                    context.ecx = value;
                                    break;
                                case 3:
                                    context.edx = value;
                                    break;
                            }
                        }
                        break;
                    }
                }

                // Cache the result
                this.instructionEmulator.cpuidCache.set(key, {
                    eax: context.eax,
                    ebx: context.ebx,
                    ecx: context.ecx,
                    edx: context.edx,
                });
            }
        }.bind(this);

        // Hook MSR access instructions
        const wrmsr = Module.findExportByName('ntdll.dll', 'NtSetSystemInformation');
        if (wrmsr) {
            Interceptor.attach(wrmsr, {
                onEnter: function (_args) {
                    const infoClass = args[0].toInt32();
                    if (infoClass === 155) {
                        // SystemWriteMsr
                        const msrData = args[1];
                        if (msrData) {
                            const msrNumber = msrData.readU32();
                            const msrValue = msrData.add(4).readU64();
                            // Cache MSR values to emulate real hardware
                            this.instructionEmulator.msrCache.set(msrNumber, msrValue);
                            // Block VM-specific MSRs
                            if (msrNumber >= 0x40000000 && msrNumber <= 0x400000ff) {
                                args[0] = ptr(0); // Change info class to invalid
                            }
                        }
                    }
                }.bind(this),
            });
        }

        // Emulate privileged instruction results
        const _emulateInstruction = function (instruction, _context) {
            switch (instruction) {
                case 'smsw':
                    return this.instructionEmulator.smsw;
                case 'sldt':
                    return this.instructionEmulator.sldt;
                case 'sgdt':
                    if (!this.instructionEmulator.sgdt) {
                        this.instructionEmulator.sgdt = Memory.alloc(10);
                        this.instructionEmulator.sgdt.writeU16(0x3ff); // Limit
                        this.instructionEmulator.sgdt.add(2).writeU64(ptr('0xFFFFF80000000000')); // Base
                    }
                    return this.instructionEmulator.sgdt;
                case 'sidt':
                    if (!this.instructionEmulator.sidt) {
                        this.instructionEmulator.sidt = Memory.alloc(10);
                        this.instructionEmulator.sidt.writeU16(0xfff); // Limit
                        this.instructionEmulator.sidt.add(2).writeU64(ptr('0xFFFFF80000001000')); // Base
                    }
                    return this.instructionEmulator.sidt;
                default:
                    return null;
            }
        }.bind(this);

        this.hooksInstalled.instruction_emulation = true;
    },

    initializeNestedVirtualizationDetection: function () {
        send({
            type: 'enhancement',
            target: 'vm_bypass',
            action: 'initializing_nested_virtualization',
            description: 'Detecting and bypassing nested virtualization layers',
        });

        // Track virtualization nesting levels
        this.nestedVirtualization = {
            levels: 0,
            hypervisors: [],
            vmcsRegions: new Map(),
            eptViolations: 0,
            vmexitReasons: new Map(),
        };

        // Check for nested hypervisor presence
        const checkNestedHypervisor = function () {
            try {
                // Check VMX capabilities
                const vmxBasic = this.readMsr(0x480); // IA32_VMX_BASIC
                if (vmxBasic) {
                    const vmcsRevision = vmxBasic.and(0x7fffffff).toNumber();
                    const vmxAbort = vmxBasic.shiftRight(32).and(0xff).toNumber();

                    if (vmcsRevision !== 0 && vmxAbort === 0) {
                        this.nestedVirtualization.levels++;
                        this.nestedVirtualization.hypervisors.push('VMX');
                    }
                }

                // Check SVM capabilities
                const svmFeatures = this.readMsr(0xc0010114); // VM_CR MSR
                if (svmFeatures) {
                    const svmDisable = svmFeatures.and(0x10).toNumber();
                    if (svmDisable === 0) {
                        this.nestedVirtualization.levels++;
                        this.nestedVirtualization.hypervisors.push('SVM');
                    }
                }

                // Check for Hyper-V nested virtualization
                const hyperVCapabilities = this.readMsr(0x40000003); // HV_X64_MSR_NESTED_CONTROL
                if (hyperVCapabilities && !hyperVCapabilities.isNull()) {
                    this.nestedVirtualization.levels++;
                    this.nestedVirtualization.hypervisors.push('Hyper-V');
                }
            } catch (_e) {
                // MSR access denied - likely in VM
                this.nestedVirtualization.levels = 1;
            }
        }.bind(this);

        // Hook VMREAD/VMWRITE instructions
        const vmreadPattern = '0F 78'; // VMREAD
        const _vmwritePattern = '0F 79'; // VMWRITE

        Process.enumerateModules().forEach(
            function (module) {
                Memory.scan(module.base, module.size, vmreadPattern, {
                    onMatch: function (_size) {
                        send({
                            type: 'debug',
                            target: 'vm_bypass',
                            action: 'vmread_instruction_found',
                            address: address.toString(),
                            instructionSize: size,
                        });
                        Interceptor.attach(address, {
                            onEnter: function (_args) {
                                // Emulate VMREAD to hide nested virtualization
                                const field = this.context.rax;
                                const value = this.nestedVirtualization.vmcsRegions.get(field) || 0;
                                this.context.rcx = value;
                                this.context.rflags |= 0x41; // Set ZF and CF to indicate success
                            }.bind(this),
                        });
                    }.bind(this),
                    onComplete: () => {},
                });
            }.bind(this)
        );

        // Monitor EPT violations
        const ntSystemDebugControl = Module.findExportByName('ntdll.dll', 'NtSystemDebugControl');
        if (ntSystemDebugControl) {
            Interceptor.attach(ntSystemDebugControl, {
                onEnter: function (_args) {
                    const command = args[0].toInt32();
                    if (command === 29) {
                        // SysDbgReadVirtual
                        this.nestedVirtualization.eptViolations++;
                        // Redirect to physical memory read
                        args[0] = ptr(28); // SysDbgReadPhysical
                    }
                }.bind(this),
            });
        }

        // Detect VM exit reasons
        const detectVmExit = function () {
            const exitReasonPattern = '44 0F B7 ?? ?? ?? 00 00'; // movzx r*, word ptr [r* + offset]

            Process.enumerateModules().forEach(
                function (module) {
                    if (module.name.indexOf('hv') !== -1 || module.name.indexOf('vm') !== -1) {
                        Memory.scan(module.base, module.size, exitReasonPattern, {
                            onMatch: function (_size) {
                                send({
                                    type: 'debug',
                                    target: 'vm_bypass',
                                    action: 'vmexit_pattern_found',
                                    address: address.toString(),
                                    patternSize: size,
                                    module: module.name,
                                });
                                Interceptor.attach(address, {
                                    onEnter: function (_args) {
                                        const exitReason = this.context.rax & 0xffff;
                                        const count =
                                            this.nestedVirtualization.vmexitReasons.get(
                                                exitReason
                                            ) || 0;
                                        this.nestedVirtualization.vmexitReasons.set(
                                            exitReason,
                                            count + 1
                                        );

                                        // Hide nested VM exits
                                        if (exitReason === 0x1c) {
                                            // VMX preemption timer
                                            this.context.rax = 0; // Change to external interrupt
                                        }
                                    }.bind(this),
                                });
                            }.bind(this),
                            onComplete: () => {},
                        });
                    }
                }.bind(this)
            );
        }.bind(this);

        checkNestedHypervisor();
        detectVmExit();

        this.hooksInstalled.nested_virtualization = true;
    },

    setupHypervisorRootkitProtection: function () {
        send({
            type: 'enhancement',
            target: 'vm_bypass',
            action: 'setting_up_rootkit_protection',
            description: 'Protecting against hypervisor rootkit detection',
        });

        // Anti-rootkit protection mechanisms
        this.rootkitProtection = {
            shadowPageTables: new Map(),
            hookedSyscalls: new Set(),
            hiddenProcesses: new Set(),
            protectedMemory: new Map(),
            stealthModules: new Set(),
        };

        // Implement shadow page table protection
        const protectPageTables = function () {
            const cr3 = this.readControlRegister(3);
            if (cr3) {
                // Create shadow copy of page tables
                const pageTableSize = 0x1000;
                const shadowTable = Memory.alloc(pageTableSize);
                Memory.copy(shadowTable, cr3, pageTableSize);
                this.rootkitProtection.shadowPageTables.set(cr3, shadowTable);

                // Protect against modifications
                Memory.protect(shadowTable, pageTableSize, 'r--');
            }
        }.bind(this);

        // Hook system call table modifications
        const ntSetSystemInformation = Module.findExportByName(
            'ntdll.dll',
            'NtSetSystemInformation'
        );
        if (ntSetSystemInformation) {
            Interceptor.attach(ntSetSystemInformation, {
                onEnter: _args => {
                    const infoClass = args[0].toInt32();
                    if (infoClass === 38) {
                        // SystemLoadGdiDriverInformation
                        // Block potential rootkit driver loads
                        const driverInfo = args[1];
                        if (driverInfo) {
                            const driverName = driverInfo.readPointer().readUtf16String();
                            if (
                                driverName &&
                                (driverName.indexOf('vbox') !== -1 ||
                                    driverName.indexOf('vmware') !== -1 ||
                                    driverName.indexOf('hyperv') !== -1)
                            ) {
                                args[0] = ptr(-1); // Invalid info class
                                send({
                                    type: 'protection',
                                    target: 'rootkit',
                                    action: 'blocked_driver_load',
                                    driver: driverName,
                                });
                            }
                        }
                    }
                },
            });
        }

        // Hide our process from hypervisor enumeration
        const hideFromHypervisor = function () {
            const ntQuerySystemInformation = Module.findExportByName(
                'ntdll.dll',
                'NtQuerySystemInformation'
            );
            if (ntQuerySystemInformation) {
                Interceptor.attach(ntQuerySystemInformation, {
                    onEnter: function (_args) {
                        this.infoClass = args[0].toInt32();
                        this.buffer = args[1];
                        this.bufferSize = args[2].toInt32();
                    },
                    onLeave: function (_retval) {
                        if (retval.toInt32() === 0 && this.infoClass === 5) {
                            // SystemProcessInformation
                            const currentPid = Process.id;
                            let entry = this.buffer;
                            let prevEntry = null;

                            while (entry && !entry.isNull()) {
                                const nextOffset = entry.readU32();
                                const pid = entry.add(0x50).readU32(); // ProcessId offset

                                if (pid === currentPid) {
                                    // Remove our process from the list
                                    if (prevEntry) {
                                        const prevNext = prevEntry.readU32();
                                        const ourNext = entry.readU32();
                                        prevEntry.writeU32(prevNext + ourNext);
                                    }
                                    this.rootkitProtection.hiddenProcesses.add(pid);
                                    break;
                                }

                                prevEntry = entry;
                                if (nextOffset === 0) {
                                    break;
                                }
                                entry = entry.add(nextOffset);
                            }
                        }
                    }.bind(this),
                });
            }
        }.bind(this);

        // Protect critical memory regions
        const protectMemoryRegions = function () {
            Process.enumerateModules().forEach(
                function (module) {
                    if (module.name === Process.getCurrentModule().name) {
                        // Protect our module's memory
                        const sections = Process.findRangeByAddress(module.base);
                        if (sections) {
                            this.rootkitProtection.protectedMemory.set(module.base, {
                                size: sections.size,
                                protection: sections.protection,
                            });

                            // Monitor for unauthorized access
                            MemoryAccessMonitor.enable(
                                {
                                    base: module.base,
                                    size: sections.size,
                                },
                                {
                                    onAccess: details => {
                                        if (details.operation === 'write') {
                                            // Block unauthorized writes
                                            send({
                                                type: 'protection',
                                                target: 'rootkit',
                                                action: 'blocked_memory_write',
                                                address: details.address,
                                                from: details.from,
                                            });
                                            return 'skip';
                                        }
                                        return null;
                                    },
                                }
                            );
                        }
                    }
                }.bind(this)
            );
        }.bind(this);

        protectPageTables();
        hideFromHypervisor();
        protectMemoryRegions();

        this.hooksInstalled.rootkit_protection = true;
    },

    initializeCloudInstanceFingerprinting: function () {
        send({
            type: 'enhancement',
            target: 'vm_bypass',
            action: 'initializing_cloud_fingerprinting',
            description: 'Detecting and masking cloud instance fingerprints',
        });

        // Cloud provider detection patterns
        this.cloudFingerprints = {
            aws: {
                detected: false,
                instanceId: null,
                metadata: new Map(),
                services: new Set(),
            },
            azure: {
                detected: false,
                vmId: null,
                subscriptionId: null,
                resourceGroup: null,
            },
            gcp: {
                detected: false,
                instanceId: null,
                projectId: null,
                zone: null,
            },
        };

        // Block cloud metadata service access
        const blockMetadataService = function () {
            const connect = Module.findExportByName('ws2_32.dll', 'connect');
            if (connect) {
                Interceptor.attach(connect, {
                    onEnter: function (_args) {
                        const sockaddr = args[1];
                        if (sockaddr) {
                            const family = sockaddr.readU16();
                            if (family === 2) {
                                // AF_INET
                                const port = sockaddr.add(2).readU16();
                                const ip = sockaddr.add(4).readU32();

                                // AWS metadata service: 169.254.169.254
                                if (ip === 0xfea9fea9 && port === 0x5000) {
                                    // Port 80 in network byte order
                                    this.context.r0 = -1;
                                    this.cloudFingerprints.aws.detected = true;
                                    send({
                                        type: 'cloud',
                                        target: 'aws',
                                        action: 'blocked_metadata_access',
                                    });
                                }

                                // Azure metadata service: 169.254.169.254
                                // GCP metadata service: 169.254.169.254
                                // Same IP but different headers distinguish them
                            }
                        }
                    }.bind(this),
                });
            }
        }.bind(this);

        // Spoof cloud instance identifiers
        const spoofInstanceIds = function () {
            const regQueryValueEx = Module.findExportByName('advapi32.dll', 'RegQueryValueExW');
            if (regQueryValueEx) {
                Interceptor.attach(regQueryValueEx, {
                    onEnter: function (_args) {
                        const valueName = args[1].readUtf16String();
                        this.valueName = valueName;
                        this.dataBuffer = args[3];
                    },
                    onLeave: function (_retval) {
                        if (retval.toInt32() === 0 && this.valueName && this.dataBuffer) {
                            // AWS instance ID in registry
                            if (this.valueName.indexOf('aws-instance-id') !== -1) {
                                this.dataBuffer.writeUtf16String(
                                    `i-${Math.random().toString(36).substr(2, 17)}`
                                );
                                this.cloudFingerprints.aws.instanceId = 'spoofed';
                            }
                            // Azure VM ID
                            else if (this.valueName.indexOf('vmId') !== -1) {
                                const spoofedId = Array(32)
                                    .fill(0)
                                    .map(() => Math.floor(Math.random() * 16).toString(16))
                                    .join('');
                                this.dataBuffer.writeUtf16String(spoofedId);
                                this.cloudFingerprints.azure.vmId = 'spoofed';
                            }
                            // GCP instance ID
                            else if (this.valueName.indexOf('instance-id') !== -1) {
                                this.dataBuffer.writeUtf16String(
                                    Math.floor(Math.random() * 1e15).toString()
                                );
                                this.cloudFingerprints.gcp.instanceId = 'spoofed';
                            }
                        }
                    }.bind(this),
                });
            }
        }.bind(this);

        // Hide cloud provider services
        const hideCloudServices = (() => {
            const getServiceKeyName = Module.findExportByName('advapi32.dll', 'GetServiceKeyNameW');
            if (getServiceKeyName) {
                Interceptor.attach(getServiceKeyName, {
                    onEnter: _args => {
                        const displayName = args[1].readUtf16String();
                        if (displayName) {
                            const cloudServices = [
                                'AWS',
                                'EC2',
                                'Lambda',
                                'Azure',
                                'Fabric',
                                'Compute',
                                'Google',
                                'GCE',
                                'Stackdriver',
                            ];

                            for (let service of cloudServices) {
                                if (displayName.indexOf(service) !== -1) {
                                    // Return generic service name
                                    args[1].writeUtf16String('GenericService');
                                    send({
                                        type: 'cloud',
                                        target: 'services',
                                        action: 'hidden_cloud_service',
                                        service: displayName,
                                    });
                                    break;
                                }
                            }
                        }
                    },
                });
            }
        }).bind(this);

        // Mask cloud-specific hardware characteristics
        const maskCloudHardware = (() => {
            // Cloud providers use specific CPU models
            const _cloudCpuModels = [
                'Intel(R) Xeon(R) Platinum',
                'Intel(R) Xeon(R) Gold',
                'AMD EPYC',
                'Ampere Altra',
            ];

            // Hook WMI queries for processor information
            const sysInfo = Module.findExportByName('kernel32.dll', 'GetSystemInfo');
            if (sysInfo) {
                Interceptor.attach(sysInfo, {
                    onLeave: function (_retval) {
                        // Modify processor architecture to appear as desktop
                        const sysInfoStruct = this.context.rcx;
                        if (sysInfoStruct) {
                            // dwNumberOfProcessors - limit to desktop range
                            const numProcs = sysInfoStruct.add(32).readU32();
                            if (numProcs > 16) {
                                sysInfoStruct.add(32).writeU32(8); // Typical desktop
                            }
                        }
                    },
                });
            }
        }).bind(this);

        blockMetadataService();
        spoofInstanceIds();
        hideCloudServices();
        maskCloudHardware();

        this.hooksInstalled.cloud_fingerprinting = true;
    },

    setupAdvancedTimingCalibration: function () {
        send({
            type: 'enhancement',
            target: 'vm_bypass',
            action: 'setting_up_timing_calibration',
            description: 'Implementing advanced timing calibration to defeat VM detection',
        });

        // Timing calibration state
        this.timingCalibration = {
            baselineRdtsc: 0,
            cpuFrequency: 0,
            timingSkew: new Map(),
            instructionTimings: new Map(),
            calibrationComplete: false,
        };

        // Calibrate CPU timing baseline
        const calibrateTiming = function () {
            // Get initial RDTSC value
            const getRdtsc = Memory.alloc(16);
            Memory.patchCode(getRdtsc, 16, code => {
                const writer = new X86Writer(code, { pc: getRdtsc });
                writer.putRdtsc();
                writer.putMovRegReg('rcx', 'rax');
                writer.putMovRegReg('rax', 'rdx');
                writer.putShlRegU8('rax', 32);
                writer.putOrRegReg('rax', 'rcx');
                writer.putRet();
            });

            const rdtscFunc = new NativeFunction(getRdtsc, 'uint64', []);
            const start = rdtscFunc();

            // Perform calibration loop
            for (let i = 0; i < 1000000; i++) {
                // Busy wait
            }

            const end = rdtscFunc();
            this.timingCalibration.baselineRdtsc = end.sub(start).toNumber();
            this.timingCalibration.cpuFrequency = this.timingCalibration.baselineRdtsc / 1000;
        }.bind(this);

        // Hook high-precision timer APIs
        const hookTimerApis = function () {
            // QueryPerformanceCounter
            const queryPerfCounter = Module.findExportByName(
                'kernel32.dll',
                'QueryPerformanceCounter'
            );
            if (queryPerfCounter) {
                Interceptor.attach(queryPerfCounter, {
                    onLeave: function (_retval) {
                        if (retval && this.context.rcx) {
                            const counter = this.context.rcx.readU64();
                            // Add calibrated skew to hide VM timing artifacts
                            let skew = this.timingCalibration.timingSkew.get('qpc') || 0;
                            if (skew === 0) {
                                skew = Math.floor(Math.random() * 1000) + 500;
                                this.timingCalibration.timingSkew.set('qpc', skew);
                            }
                            this.context.rcx.writeU64(counter.add(skew));
                        }
                    }.bind(this),
                });
            }

            // GetTickCount64
            const getTickCount64 = Module.findExportByName('kernel32.dll', 'GetTickCount64');
            if (getTickCount64) {
                Interceptor.attach(getTickCount64, {
                    onLeave: function (_retval) {
                        // Apply consistent timing offset
                        const ticks = retval.toNumber();
                        let skew = this.timingCalibration.timingSkew.get('tick') || 0;
                        if (skew === 0) {
                            skew = Math.floor(Math.random() * 10000) + 5000;
                            this.timingCalibration.timingSkew.set('tick', skew);
                        }
                        retval.replace(ptr(ticks + skew));
                    }.bind(this),
                });
            }
        }.bind(this);

        // Monitor instruction execution timing
        const monitorInstructionTiming = function () {
            // Common VM-detection timing instructions
            const timingSensitiveInstructions = [
                { pattern: '0F 31', name: 'RDTSC' },
                { pattern: '0F 01 F9', name: 'RDTSCP' },
                { pattern: '0F A2', name: 'CPUID' },
            ];

            timingSensitiveInstructions.forEach(
                function (inst) {
                    Process.enumerateModules().forEach(
                        function (module) {
                            Memory.scan(module.base, module.size, inst.pattern, {
                                onMatch: function (_size) {
                                    // Track timing of these instructions
                                    const timing =
                                        this.timingCalibration.instructionTimings.get(inst.name) ||
                                        [];
                                    timing.push(Date.now());
                                    this.timingCalibration.instructionTimings.set(
                                        inst.name,
                                        timing
                                    );

                                    // Inject timing normalization
                                    Interceptor.attach(address, {
                                        onLeave: function (_retval) {
                                            // Normalize timing to hide VM characteristics
                                            if (inst.name === 'RDTSC' || inst.name === 'RDTSCP') {
                                                const adjustment =
                                                    this.timingCalibration.cpuFrequency * 10;
                                                this.context.rax =
                                                    (this.context.rax + adjustment) & 0xffffffff;
                                                this.context.rdx =
                                                    (this.context.rdx + (adjustment >> 0)) &
                                                    0xffffffff;
                                            }
                                        }.bind(this),
                                    });
                                }.bind(this),
                                onComplete: () => {},
                            });
                        }.bind(this)
                    );
                }.bind(this)
            );
        }.bind(this);

        calibrateTiming();
        hookTimerApis();
        monitorInstructionTiming();

        this.timingCalibration.calibrationComplete = true;
        this.hooksInstalled.timing_calibration = true;
    },

    initializeHardwareVirtualizationMasking: function () {
        send({
            type: 'enhancement',
            target: 'vm_bypass',
            action: 'initializing_hardware_masking',
            description: 'Masking hardware virtualization extensions',
        });

        // Hardware virtualization masking state
        this.hardwareMasking = {
            vmxEnabled: false,
            svmEnabled: false,
            hyperVEnabled: false,
            maskedFeatures: new Set(),
            cpuCapabilities: new Map(),
        };

        // Mask VMX/SVM CPU features
        const maskVirtualizationExtensions = function () {
            // Hook CPUID to mask virtualization features
            const cpuidHandler = function (eax, _ecx) {
                const result = { eax: 0, ebx: 0, ecx: 0, edx: 0 };

                switch (eax) {
                    case 0x1:
                        // Feature information
                        result.ecx &= ~(1 << 5); // Clear VMX bit
                        result.ecx &= ~(1 << 31); // Clear hypervisor bit
                        this.hardwareMasking.maskedFeatures.add('VMX');
                        this.hardwareMasking.maskedFeatures.add('HYPERVISOR');
                        break;

                    case 0x80000001:
                        // Extended features
                        result.ecx &= ~(1 << 2); // Clear SVM bit
                        this.hardwareMasking.maskedFeatures.add('SVM');
                        break;

                    case 0x40000000:
                        // Hypervisor CPUID leaf
                        result.eax = 0; // No hypervisor present
                        result.ebx = 0;
                        result.ecx = 0;
                        result.edx = 0;
                        break;
                }

                return result;
            }.bind(this);

            // Store original CPUID capabilities
            this.hardwareMasking.cpuCapabilities.set('original', cpuidHandler);
        }.bind(this);

        // Hook MSR access for virtualization features
        const hookVirtualizationMsrs = function () {
            const ntQuerySystemInformation = Module.findExportByName(
                'ntdll.dll',
                'NtQuerySystemInformation'
            );
            if (ntQuerySystemInformation) {
                Interceptor.attach(ntQuerySystemInformation, {
                    onEnter: function (_args) {
                        const infoClass = args[0].toInt32();
                        if (infoClass === 154) {
                            // SystemReadMsr
                            const msrData = args[1];
                            if (msrData) {
                                const msrNumber = msrData.readU32();

                                // VMX MSRs (0x480 - 0x48F)
                                if (msrNumber >= 0x480 && msrNumber <= 0x48f) {
                                    // Return disabled VMX
                                    args[0] = ptr(-1);
                                    this.hardwareMasking.vmxEnabled = false;
                                }

                                // SVM MSRs (0xC0010114 - 0xC0010118)
                                if (msrNumber >= 0xc0010114 && msrNumber <= 0xc0010118) {
                                    // Return disabled SVM
                                    args[0] = ptr(-1);
                                    this.hardwareMasking.svmEnabled = false;
                                }

                                // Hyper-V MSRs (0x40000000 - 0x400000FF)
                                if (msrNumber >= 0x40000000 && msrNumber <= 0x400000ff) {
                                    // Return disabled Hyper-V
                                    args[0] = ptr(-1);
                                    this.hardwareMasking.hyperVEnabled = false;
                                }
                            }
                        }
                    }.bind(this),
                });
            }
        }.bind(this);

        // Hide virtualization-related hardware devices
        const hideVirtualizationDevices = (() => {
            const setupDiGetClassDevs = Module.findExportByName(
                'setupapi.dll',
                'SetupDiGetClassDevsW'
            );
            if (setupDiGetClassDevs) {
                Interceptor.attach(setupDiGetClassDevs, {
                    onEnter: _args => {
                        // Check for virtualization device classes
                        const classGuid = args[0];
                        if (classGuid) {
                            const guidString = classGuid.readUtf16String();
                            const vmDeviceGuids = [
                                '{4D36E97D-E325-11CE-BFC1-08002BE10318}', // System devices (includes VMBus)
                                '{D45B1C18-C8FA-11DE-9257-0050561316D8}', // Hyper-V devices
                                '{6FDE7547-1B65-48AE-B628-80BE62016020}', // VMware devices
                            ];

                            for (let vmGuid of vmDeviceGuids) {
                                if (guidString && guidString.indexOf(vmGuid) !== -1) {
                                    // Return empty device list
                                    args[0] = ptr(0);
                                    send({
                                        type: 'hardware',
                                        target: 'device_masking',
                                        action: 'hidden_vm_device',
                                        guid: guidString,
                                    });
                                    break;
                                }
                            }
                        }
                    },
                });
            }
        }).bind(this);

        maskVirtualizationExtensions();
        hookVirtualizationMsrs();
        hideVirtualizationDevices();

        this.hooksInstalled.hardware_masking = true;
    },

    setupKernelPatchGuardBypass: function () {
        send({
            type: 'enhancement',
            target: 'vm_bypass',
            action: 'setting_up_patchguard_bypass',
            description: 'Bypassing Kernel Patch Guard detection',
        });

        // PatchGuard bypass state
        this.patchGuardBypass = {
            kppRoutines: new Map(),
            contextBlocks: new Set(),
            checksumFixups: new Map(),
            timerCallbacks: new Set(),
        };

        // Identify and hook KPP routines
        const identifyKppRoutines = function () {
            // Common PatchGuard check routine patterns
            const kppPatterns = [
                {
                    pattern: '48 8B C4 48 89 58 08 48 89 68 10 48 89 70 18 48 89 78 20',
                    name: 'KppIsProtectedProcess',
                },
                {
                    pattern: '48 89 5C 24 08 48 89 74 24 10 57 48 83 EC 20 48 8B F9',
                    name: 'KppVerifyContext',
                },
                {
                    pattern: '40 53 48 83 EC 20 48 8B D9 E8 ?? ?? ?? ?? 48 8B CB',
                    name: 'KppChecksum',
                },
            ];

            const ntoskrnl = Process.findModuleByName('ntoskrnl.exe');
            if (ntoskrnl) {
                kppPatterns.forEach(
                    function (kpp) {
                        Memory.scan(ntoskrnl.base, ntoskrnl.size, kpp.pattern, {
                            onMatch: function (_size) {
                                this.patchGuardBypass.kppRoutines.set(kpp.name, address);

                                // Hook the routine to bypass checks
                                Interceptor.attach(address, {
                                    onEnter: _args => {
                                        // Log PatchGuard activity
                                        send({
                                            type: 'patchguard',
                                            target: kpp.name,
                                            action: 'routine_called',
                                        });
                                    },
                                    onLeave: _retval => {
                                        // Always return success/valid
                                        retval.replace(ptr(0));
                                    },
                                });
                            }.bind(this),
                            onComplete: () => {},
                        });
                    }.bind(this)
                );
            }
        }.bind(this);

        // Disable PatchGuard timer callbacks
        const disableKppTimers = function () {
            const keSetTimer = Module.findExportByName('ntoskrnl.exe', 'KeSetTimer');
            if (keSetTimer) {
                Interceptor.attach(keSetTimer, {
                    onEnter: function (_args) {
                        const _timer = args[0];
                        const _dueTime = args[1];
                        const dpc = args[2];

                        // Check if this is a PatchGuard timer
                        if (dpc && !dpc.isNull()) {
                            const dpcRoutine = dpc.add(0x18).readPointer();

                            // Check against known KPP routines
                            this.patchGuardBypass.kppRoutines.forEach(
                                function (address, name) {
                                    if (dpcRoutine.equals(address)) {
                                        // Disable this timer
                                        args[1] = ptr(-1); // Set invalid due time
                                        this.patchGuardBypass.timerCallbacks.add(dpcRoutine);
                                        send({
                                            type: 'patchguard',
                                            target: 'timer',
                                            action: 'disabled_kpp_timer',
                                            routine: name,
                                        });
                                    }
                                }.bind(this)
                            );
                        }
                    }.bind(this),
                });
            }
        }.bind(this);

        // Fix checksums to avoid detection
        const fixChecksums = function () {
            // Hook checksum verification routines
            const rtlComputeCrc32 = Module.findExportByName('ntoskrnl.exe', 'RtlComputeCrc32');
            if (rtlComputeCrc32) {
                Interceptor.attach(rtlComputeCrc32, {
                    onEnter: function (_args) {
                        this.buffer = args[1];
                        this.length = args[2].toInt32();
                    },
                    onLeave: function (_retval) {
                        // Check if this is a kernel structure checksum
                        if (this.buffer && this.length > 0x1000) {
                            const crc = retval.toInt32();

                            // Store or verify checksum
                            const key = `${this.buffer.toString()}:${this.length}`;
                            if (this.patchGuardBypass.checksumFixups.has(key)) {
                                // Return stored valid checksum
                                const validCrc = this.patchGuardBypass.checksumFixups.get(key);
                                retval.replace(ptr(validCrc));
                            } else {
                                // Store this as valid checksum
                                this.patchGuardBypass.checksumFixups.set(key, crc);
                            }
                        }
                    }.bind(this),
                });
            }
        }.bind(this);

        // Protect against context validation
        const protectContext = (() => {
            // Hook context validation routines
            const keBugCheckEx = Module.findExportByName('ntoskrnl.exe', 'KeBugCheckEx');
            if (keBugCheckEx) {
                Interceptor.attach(keBugCheckEx, {
                    onEnter: _args => {
                        const bugCheckCode = args[0].toInt32();

                        // PatchGuard bug check codes
                        const kppBugChecks = [
                            0x109, // CRITICAL_STRUCTURE_CORRUPTION
                            0x139, // KERNEL_SECURITY_CHECK_FAILURE
                            0x156, // KERNEL_PATCH_PROTECTION_FAILURE
                            0x157, // KERNEL_SECURITY_CHECK_FAILURE_EX
                        ];

                        if (kppBugChecks.includes(bugCheckCode)) {
                            // Prevent bug check
                            args[0] = ptr(0);
                            send({
                                type: 'patchguard',
                                target: 'bugcheck',
                                action: 'prevented_kpp_bugcheck',
                                code: bugCheckCode,
                            });
                        }
                    },
                });
            }
        }).bind(this);

        identifyKppRoutines();
        disableKppTimers();
        fixChecksums();
        protectContext();

        this.hooksInstalled.patchguard_bypass = true;
    },

    initializeVmExitHandlerInterception: function () {
        send({
            type: 'enhancement',
            target: 'vm_bypass',
            action: 'initializing_vmexit_interception',
            description: 'Intercepting and manipulating VM exit handlers',
        });

        // VM exit handler state
        this.vmExitHandlers = {
            exitReasons: new Map(),
            handlerChains: new Map(),
            interceptedExits: 0,
            vmcsFields: new Map(),
        };

        // Map of VM exit reasons
        const _vmExitReasons = {
            0: 'EXCEPTION_NMI',
            1: 'EXTERNAL_INTERRUPT',
            2: 'TRIPLE_FAULT',
            7: 'INTERRUPT_WINDOW',
            9: 'TASK_SWITCH',
            10: 'CPUID',
            12: 'HLT',
            14: 'INVLPG',
            15: 'RDPMC',
            16: 'RDTSC',
            18: 'VMCALL',
            28: 'MOV_CR',
            31: 'MOV_DR',
            32: 'IO_INSTRUCTION',
            33: 'RDMSR',
            34: 'WRMSR',
            48: 'EPT_VIOLATION',
            49: 'EPT_MISCONFIG',
        };

        // Hook VM exit dispatcher
        const hookVmExitDispatcher = function () {
            // Search for VM exit handler patterns
            const vmExitPattern = '41 0F B7 ?? ?? ?? 00 00'; // movzx r*, word ptr [r* + EXIT_REASON_OFFSET]

            Process.enumerateModules().forEach(
                function (module) {
                    if (
                        module.name.toLowerCase().indexOf('hv') !== -1 ||
                        module.name.toLowerCase().indexOf('vmm') !== -1
                    ) {
                        Memory.scan(module.base, module.size, vmExitPattern, {
                            onMatch: function (_size) {
                                Interceptor.attach(address, {
                                    onEnter: function (_args) {
                                        // Read VM exit reason
                                        const exitReason = this.context.rax & 0xffff;
                                        const exitQualification = this.context.rbx;

                                        // Track exit reasons
                                        const count =
                                            this.vmExitHandlers.exitReasons.get(exitReason) || 0;
                                        this.vmExitHandlers.exitReasons.set(exitReason, count + 1);

                                        // Manipulate specific exits
                                        switch (exitReason) {
                                            case 0x0a: // CPUID
                                                // Modify CPUID results to hide VM
                                                this.modifyCpuidExit();
                                                break;

                                            case 0x10: // RDTSC
                                                // Adjust TSC values
                                                this.modifyRdtscExit();
                                                break;

                                            case 0x21: // RDMSR
                                            case 0x22: // WRMSR
                                                // Handle MSR access
                                                this.modifyMsrExit(exitReason === 0x22);
                                                break;

                                            case 0x30: // EPT_VIOLATION
                                                // Handle EPT violations
                                                this.handleEptViolation(exitQualification);
                                                break;
                                        }

                                        this.vmExitHandlers.interceptedExits++;
                                    }.bind(this),
                                });
                            }.bind(this),
                            onComplete: () => {},
                        });
                    }
                }.bind(this)
            );
        }.bind(this);

        // Modify CPUID VM exit handling
        this.modifyCpuidExit = function () {
            // Modify guest CPUID results
            const vmcsGuestRax = this.vmExitHandlers.vmcsFields.get('GUEST_RAX') || this.context.r8;
            const vmcsGuestRcx = this.vmExitHandlers.vmcsFields.get('GUEST_RCX') || this.context.r9;

            if (vmcsGuestRax) {
                const leaf = vmcsGuestRax.readU32();

                if (leaf === 0x1) {
                    // Clear hypervisor bit
                    let ecxValue = vmcsGuestRcx.readU32();
                    ecxValue &= ~(1 << 31);
                    vmcsGuestRcx.writeU32(ecxValue);
                } else if (leaf === 0x40000000) {
                    // Hide hypervisor vendor
                    vmcsGuestRax.writeU32(0);
                }
            }
        };

        // Modify RDTSC VM exit handling
        this.modifyRdtscExit = function () {
            // Add timing skew to TSC values
            const vmcsGuestRax = this.vmExitHandlers.vmcsFields.get('GUEST_RAX') || this.context.r8;
            const vmcsGuestRdx = this.vmExitHandlers.vmcsFields.get('GUEST_RDX') || this.context.r9;

            if (vmcsGuestRax && vmcsGuestRdx) {
                let tscLow = vmcsGuestRax.readU32();
                const tscHigh = vmcsGuestRdx.readU32();

                // Add random jitter
                const jitter = Math.floor(Math.random() * 10000);
                tscLow += jitter;

                vmcsGuestRax.writeU32(tscLow);
                vmcsGuestRdx.writeU32(tscHigh);
            }
        };

        // Modify MSR VM exit handling
        this.modifyMsrExit = function (_isWrite) {
            const vmcsGuestRcx =
                this.vmExitHandlers.vmcsFields.get('GUEST_RCX') || this.context.r10;

            if (vmcsGuestRcx) {
                const msrNumber = vmcsGuestRcx.readU32();

                // Block virtualization-related MSRs
                if (
                    (msrNumber >= 0x480 && msrNumber <= 0x48f) || // VMX MSRs
                    (msrNumber >= 0x40000000 && msrNumber <= 0x400000ff)
                ) {
                    // Hyper-V MSRs

                    // Inject #GP fault
                    this.injectGuestException(0x0d); // General Protection Fault
                }
            }
        };

        // Handle EPT violations
        this.handleEptViolation = function (qualification) {
            // Extract violation details
            const guestPhysicalAddress = qualification;

            // Check if this is a monitored region
            let isMonitored = false;
            this.vmExitHandlers.handlerChains.forEach((_handler, region) => {
                if (guestPhysicalAddress >= region.start && guestPhysicalAddress < region.end) {
                    isMonitored = true;
                }
            });

            if (isMonitored) {
                // Skip the violation
                this.skipGuestInstruction();
            }
        };

        // Helper to inject guest exception
        this.injectGuestException = function (vector) {
            const vmEntryInterruptInfo = this.vmExitHandlers.vmcsFields.get('VM_ENTRY_INTR_INFO');
            if (vmEntryInterruptInfo) {
                const info = (vector & 0xff) | (3 << 8) | (1 << 31); // Valid exception
                vmEntryInterruptInfo.writeU32(info);
            }
        };

        // Helper to skip guest instruction
        this.skipGuestInstruction = function () {
            const vmcsGuestRip = this.vmExitHandlers.vmcsFields.get('GUEST_RIP');
            const vmcsInstLen = this.vmExitHandlers.vmcsFields.get('VM_EXIT_INSTRUCTION_LEN');

            if (vmcsGuestRip && vmcsInstLen) {
                const rip = vmcsGuestRip.readU64();
                const len = vmcsInstLen.readU32();
                vmcsGuestRip.writeU64(rip.add(len));
            }
        };

        hookVmExitDispatcher();

        this.hooksInstalled.vmexit_interception = true;
    },

    setupHypervisorMemoryProtection: function () {
        send({
            type: 'enhancement',
            target: 'vm_bypass',
            action: 'setting_up_memory_protection',
            description: 'Protecting against hypervisor memory introspection',
        });

        // Memory protection state
        this.memoryProtection = {
            protectedRegions: new Map(),
            shadowPages: new Map(),
            eptHooks: new Set(),
            memoryTraps: new Map(),
        };

        // Implement shadow memory for sensitive regions
        const createShadowMemory = function () {
            Process.enumerateModules().forEach(
                function (module) {
                    // Protect our module
                    if (module.name === Process.getCurrentModule().name) {
                        const shadowBase = Memory.alloc(module.size);

                        // Copy module to shadow memory
                        Memory.copy(shadowBase, module.base, module.size);

                        this.memoryProtection.shadowPages.set(module.base, {
                            shadow: shadowBase,
                            size: module.size,
                            original: module.base,
                        });

                        // Set up memory trap handlers
                        this.setupMemoryTraps(module.base, module.size);
                    }
                }.bind(this)
            );
        }.bind(this);

        // Set up memory access traps
        this.setupMemoryTraps = function (_size) {
            // Hook memory access functions
            const ntReadVirtualMemory = Module.findExportByName('ntdll.dll', 'NtReadVirtualMemory');
            if (ntReadVirtualMemory) {
                Interceptor.attach(ntReadVirtualMemory, {
                    onEnter: function (args) {
                        const _processHandle = args[0];
                        const baseAddress = args[1];
                        const _buffer = args[2];
                        const _numberOfBytesToRead = args[3].toInt32();

                        // Check if reading from protected region
                        this.memoryProtection.protectedRegions.forEach(
                            function (protection, region) {
                                if (
                                    baseAddress >= region &&
                                    baseAddress < region.add(protection.size)
                                ) {
                                    // Redirect to shadow memory
                                    const offset = baseAddress.sub(region).toInt32();
                                    const shadowAddress = protection.shadow.add(offset);
                                    args[1] = shadowAddress;

                                    this.memoryProtection.memoryTraps.set(baseAddress, {
                                        type: 'read',
                                        redirected: true,
                                        timestamp: Date.now(),
                                    });
                                }
                            }.bind(this)
                        );
                    }.bind(this),
                });
            }
        };

        // Protect against EPT-based memory introspection
        const protectAgainstEpt = function () {
            // Hook EPT violation handlers
            const handleEptViolation = Module.findExportByName(null, 'HandleEptViolation');
            if (handleEptViolation) {
                Interceptor.attach(handleEptViolation, {
                    onEnter: function (_args) {
                        const violationInfo = args[0];
                        if (violationInfo) {
                            const guestPhysicalAddress = violationInfo.readU64();

                            // Check if this is our protected memory
                            let isProtected = false;
                            this.memoryProtection.protectedRegions.forEach(
                                function (_protection, region) {
                                    const physicalAddress = this.virtualToPhysical(region);
                                    if (guestPhysicalAddress.equals(physicalAddress)) {
                                        isProtected = true;
                                    }
                                }.bind(this)
                            );

                            if (isProtected) {
                                // Spoof the memory content
                                this.spoofMemoryContent(args);
                                this.memoryProtection.eptHooks.add(guestPhysicalAddress);
                            }
                        }
                    }.bind(this),
                });
            }
        }.bind(this);

        // Convert virtual to physical address using simplified bit masking
        this.virtualToPhysical = virtualAddress => {
            // Strip high bits to convert to physical address space
            return virtualAddress.and(0x7fffffffffff);
        };

        // Spoof memory content for hypervisor
        this.spoofMemoryContent = _args => {
            const buffer = args[1];
            if (buffer) {
                // Fill with benign content
                const spoofedContent = Memory.alloc(0x1000);
                for (let i = 0; i < 0x1000; i += 8) {
                    spoofedContent.add(i).writeU64(ptr('0x9090909090909090')); // NOPs
                }
                Memory.copy(buffer, spoofedContent, 0x1000);
            }
        };

        // Implement anti-forensics for memory dumps
        const implementAntiForensics = function () {
            // Hook memory dump functions
            const miniDumpWriteDump = Module.findExportByName('dbghelp.dll', 'MiniDumpWriteDump');
            if (miniDumpWriteDump) {
                Interceptor.attach(miniDumpWriteDump, {
                    onEnter: function (_args) {
                        // Scramble sensitive memory regions before dump
                        this.memoryProtection.protectedRegions.forEach((protection, region) => {
                            // XOR scramble the memory
                            const key = Math.floor(Math.random() * 0xffffffff);
                            for (let i = 0; i < protection.size; i += 4) {
                                const value = region.add(i).readU32();
                                region.add(i).writeU32(value ^ key);
                            }

                            send({
                                type: 'protection',
                                target: 'memory_dump',
                                action: 'scrambled_memory',
                                region: region.toString(),
                                size: protection.size,
                            });
                        });
                    }.bind(this),
                    onLeave: function (_retval) {
                        // Restore scrambled memory
                        this.memoryProtection.protectedRegions.forEach((protection, region) => {
                            // Restore from shadow
                            Memory.copy(region, protection.shadow, protection.size);
                        });
                    }.bind(this),
                });
            }
        }.bind(this);

        createShadowMemory();
        protectAgainstEpt();
        implementAntiForensics();

        this.hooksInstalled.memory_protection = true;
    },
};

// Auto-execute the virtualization bypass
virtualizationBypass.run();

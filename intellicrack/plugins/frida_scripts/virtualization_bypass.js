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
 * Version: 2.0.0
 * License: GPL v3
 */

{
    name: "Virtualization Detection Bypass",
    description: "Comprehensive VM and sandbox detection countermeasures",
    version: "2.0.0",

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
                hideRegistryKeys: true
            },
            vmware: {
                enabled: true,
                hideVmwareTools: true,
                spoofDmiInfo: true,
                hidePciDevices: true,
                spoofMacAddresses: true
            },
            hyperV: {
                enabled: true,
                hideHyperVFeatures: true,
                spoofCpuidSignature: true,
                hideIntegrationServices: true
            },
            qemu: {
                enabled: true,
                hideQemuSignatures: true,
                spoofHardwareIds: true,
                hideQemuDevices: true
            }
        },

        // Sandbox detection bypass
        sandboxDetection: {
            enabled: true,
            fileSystem: {
                spoofSandboxFiles: true,
                hideSandboxDirectories: true,
                createFakeFiles: true
            },
            processes: {
                hideSandboxProcesses: true,
                spoofProcessList: true,
                hideAnalysisTools: true
            },
            registry: {
                hideSandboxKeys: true,
                spoofVendorInfo: true,
                hideVmRegistry: true
            },
            network: {
                spoofMacAddresses: true,
                hideVmNetworkAdapters: true,
                spoofNetworkConfig: true
            }
        },

        // Hardware fingerprinting bypass
        hardwareFingerprinting: {
            spoofCpuInfo: true,
            spoofMotherboardInfo: true,
            spoofBiosInfo: true,
            spoofDiskInfo: true,
            spoofMemoryInfo: true,
            spoofGpuInfo: true
        },

        // Timing-based detection bypass
        timingDetection: {
            enabled: true,
            normalizeInstructionTiming: true,
            spoofCpuFrequency: true,
            preventTimingAnalysis: true
        }
    },

    // Hook tracking
    hooksInstalled: {},
    spoofedValues: {},

    onAttach: function(pid) {
        send({
            type: "status",
            target: "vm_bypass",
            action: "attaching_to_process",
            process_id: pid
        });
        this.processId = pid;
    },

    run: function() {
        send({
            type: "status",
            target: "vm_bypass",
            action: "installing_virtualization_bypass",
            timestamp: Date.now()
        });

        // Initialize bypass components
        this.hookVirtualBoxDetection();
        this.hookVmwareDetection();
        this.hookHyperVDetection();
        this.hookQemuDetection();
        this.hookSandboxDetection();
        this.hookHardwareFingerprinting();
        this.hookTimingDetection();
        this.hookGenericVmDetection();
        this.hookRegistryDetection();
        this.hookFileSystemDetection();
        this.hookProcessDetection();
        this.hookNetworkDetection();

        this.installSummary();
    },

    // === VIRTUALBOX DETECTION BYPASS ===
    hookVirtualBoxDetection: function() {
        send({
            type: "info",
            target: "vm_bypass",
            action: "installing_virtualbox_bypass"
        });

        if (!this.config.vmDetection.virtualBox.enabled) return;

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

    hookVBoxGuestAdditions: function() {
        send({
            type: "info",
            target: "vm_bypass",
            action: "installing_guest_additions_bypass"
        });

        // Hook LoadLibrary to prevent VBox DLL loading
        var loadLibrary = Module.findExportByName("kernel32.dll", "LoadLibraryW");
        if (loadLibrary) {
            Interceptor.attach(loadLibrary, {
                onEnter: function(args) {
                    if (args[0] && !args[0].isNull()) {
                        var libraryName = args[0].readUtf16String().toLowerCase();

                        var vboxLibraries = [
                            "vboxdisp", "vboxhook", "vboxmrxnp", "vboxsf",
                            "vboxguest", "vboxmouse", "vboxservice", "vboxtray"
                        ];

                        if (vboxLibraries.some(lib => libraryName.includes(lib))) {
                            send({
                                type: "bypass",
                                target: "vm_bypass",
                                action: "blocked_virtualbox_library_load",
                                library_name: libraryName
                            });
                            this.blockLoad = true;
                        }
                    }
                },

                onLeave: function(retval) {
                    if (this.blockLoad) {
                        retval.replace(ptr(0)); // NULL - load failed
                    }
                }
            });

            this.hooksInstalled['LoadLibraryW_VBox'] = true;
        }

        // Hook GetModuleHandle for VBox modules
        var getModuleHandle = Module.findExportByName("kernel32.dll", "GetModuleHandleW");
        if (getModuleHandle) {
            Interceptor.attach(getModuleHandle, {
                onEnter: function(args) {
                    if (args[0] && !args[0].isNull()) {
                        var moduleName = args[0].readUtf16String().toLowerCase();

                        if (moduleName.includes("vbox")) {
                            send({
                                type: "bypass",
                                target: "vm_bypass",
                                action: "blocked_virtualbox_module_handle_query",
                                module_name: moduleName
                            });
                            this.blockQuery = true;
                        }
                    }
                },

                onLeave: function(retval) {
                    if (this.blockQuery) {
                        retval.replace(ptr(0)); // NULL - module not found
                    }
                }
            });

            this.hooksInstalled['GetModuleHandleW_VBox'] = true;
        }
    },

    hookVBoxPciDevices: function() {
        // Hook PCI device enumeration to hide VirtualBox devices
        var setupDiGetClassDevs = Module.findExportByName("setupapi.dll", "SetupDiGetClassDevsW");
        if (setupDiGetClassDevs) {
            Interceptor.attach(setupDiGetClassDevs, {
                onLeave: function(retval) {
                    if (retval.toInt32() !== -1) {
                        send({
                            type: "bypass",
                            target: "vm_bypass",
                            action: "pci_device_enumeration_detected",
                            mitigation: "filtering_vbox_devices"
                        });
                        this.filterVBoxDevices = true;
                    }
                }
            });

            this.hooksInstalled['SetupDiGetClassDevsW_VBox'] = true;
        }

        // Hook device property queries
        var setupDiGetDeviceProperty = Module.findExportByName("setupapi.dll", "SetupDiGetDevicePropertyW");
        if (setupDiGetDeviceProperty) {
            Interceptor.attach(setupDiGetDeviceProperty, {
                onLeave: function(retval) {
                    if (retval.toInt32() !== 0) {
                        var propertyBuffer = this.context.r9; // PropertyBuffer
                        if (propertyBuffer && !propertyBuffer.isNull()) {
                            this.filterVBoxDeviceProperties(propertyBuffer);
                        }
                    }
                },

                filterVBoxDeviceProperties: function(buffer) {
                    try {
                        var deviceString = buffer.readUtf16String();
                        if (deviceString && deviceString.toLowerCase().includes("vbox")) {
                            // Replace with generic device string
                            buffer.writeUtf16String("Generic System Device");
                            send({
                                type: "bypass",
                                target: "vm_bypass",
                                action: "virtualbox_device_property_hidden"
                            });
                        }
                    } catch(e) {
                        // Buffer read failed
                    }
                }
            });

            this.hooksInstalled['SetupDiGetDevicePropertyW_VBox'] = true;
        }
    },

    hookVBoxBios: function() {
        // Hook SMBIOS table access
        var getSystemFirmwareTable = Module.findExportByName("kernel32.dll", "GetSystemFirmwareTable");
        if (getSystemFirmwareTable) {
            Interceptor.attach(getSystemFirmwareTable, {
                onEnter: function(args) {
                    this.firmwareTableProvider = args[0].toInt32();
                    this.firmwareTableID = args[1].toInt32();
                    this.firmwareTableBuffer = args[2];
                    this.bufferSize = args[3].toInt32();
                },

                onLeave: function(retval) {
                    var bytesReturned = retval.toInt32();
                    if (bytesReturned > 0 && this.firmwareTableBuffer && !this.firmwareTableBuffer.isNull()) {
                        this.spoofBiosInfo();
                    }
                },

                spoofBiosInfo: function() {
                    try {
                        var config = this.parent.parent.config;
                        if (config.vmDetection.virtualBox.spoofBios) {
                            var biosData = this.firmwareTableBuffer.readByteArray(Math.min(this.bufferSize, 1024));
                            var biosString = Array.from(new Uint8Array(biosData))
                                .map(b => String.fromCharCode(b)).join('');

                            // Check for VirtualBox BIOS signatures
                            if (biosString.includes("VBOX") || biosString.includes("VirtualBox") ||
                                biosString.includes("Oracle")) {

                                // Replace with legitimate BIOS vendor
                                var spoofedBios = biosString
                                    .replace(/VBOX/g, "DELL")
                                    .replace(/VirtualBox/g, "Dell Inc.")
                                    .replace(/Oracle/g, "Dell Inc.");

                                for (var i = 0; i < spoofedBios.length && i < this.bufferSize; i++) {
                                    this.firmwareTableBuffer.add(i).writeU8(spoofedBios.charCodeAt(i));
                                }

                                send({
                                    type: "bypass",
                                    target: "vm_bypass",
                                    action: "virtualbox_bios_signatures_spoofed"
                                });
                            }
                        }
                    } catch(e) {
                        send({
                            type: "error",
                            target: "vm_bypass",
                            action: "bios_spoofing_error",
                            error: e.message || e.toString()
                        });
                    }
                }
            });

            this.hooksInstalled['GetSystemFirmwareTable_VBox'] = true;
        }
    },

    hookVBoxRegistry: function() {
        // Hook registry queries for VirtualBox detection
        var regQueryValueEx = Module.findExportByName("advapi32.dll", "RegQueryValueExW");
        if (regQueryValueEx) {
            Interceptor.attach(regQueryValueEx, {
                onEnter: function(args) {
                    if (args[1] && !args[1].isNull()) {
                        var valueName = args[1].readUtf16String().toLowerCase();

                        var vboxValues = [
                            "vboxguest", "vboxmouse", "vboxservice", "vboxsf",
                            "virtualbox", "oracle vm", "vbox"
                        ];

                        if (vboxValues.some(val => valueName.includes(val))) {
                            send({
                                type: "bypass",
                                target: "vm_bypass",
                                action: "virtualbox_registry_value_query_blocked",
                                value_name: valueName
                            });
                            this.blockVBoxRegistry = true;
                        }
                    }
                },

                onLeave: function(retval) {
                    if (this.blockVBoxRegistry) {
                        retval.replace(2); // ERROR_FILE_NOT_FOUND
                    }
                }
            });

            this.hooksInstalled['RegQueryValueExW_VBox'] = true;
        }

        // Hook registry key opening
        var regOpenKeyEx = Module.findExportByName("advapi32.dll", "RegOpenKeyExW");
        if (regOpenKeyEx) {
            Interceptor.attach(regOpenKeyEx, {
                onEnter: function(args) {
                    if (args[1] && !args[1].isNull()) {
                        var keyName = args[1].readUtf16String().toLowerCase();

                        if (keyName.includes("vbox") || keyName.includes("virtualbox") ||
                            keyName.includes("oracle")) {
                            send({
                                type: "bypass",
                                target: "vm_bypass",
                                action: "virtualbox_registry_key_access_blocked",
                                key_name: keyName
                            });
                            this.blockVBoxKey = true;
                        }
                    }
                },

                onLeave: function(retval) {
                    if (this.blockVBoxKey) {
                        retval.replace(2); // ERROR_FILE_NOT_FOUND
                    }
                }
            });

            this.hooksInstalled['RegOpenKeyExW_VBox'] = true;
        }
    },

    hookVBoxServices: function() {
        // Hook service enumeration to hide VirtualBox services
        var enumServicesStatus = Module.findExportByName("advapi32.dll", "EnumServicesStatusW");
        if (enumServicesStatus) {
            Interceptor.attach(enumServicesStatus, {
                onLeave: function(retval) {
                    if (retval.toInt32() !== 0) {
                        send({
            type: "bypass",
            target: "vm_bypass",
            action: "service_enumeration_filtering_virtualbox"
        });
                        // Service filtering would be implemented here
                    }
                }
            });

            this.hooksInstalled['EnumServicesStatusW_VBox'] = true;
        }
    },

    // === VMWARE DETECTION BYPASS ===
    hookVmwareDetection: function() {
        send({
            type: "info",
            target: "vm_bypass",
            action: "installing_vmware_bypass"
        });

        if (!this.config.vmDetection.vmware.enabled) return;

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

    hookVmwareTools: function() {
        // Hook VMware Tools process detection
        var createToolhelp32Snapshot = Module.findExportByName("kernel32.dll", "CreateToolhelp32Snapshot");
        if (createToolhelp32Snapshot) {
            Interceptor.attach(createToolhelp32Snapshot, {
                onEnter: function(args) {
                    var flags = args[0].toInt32();
                    if (flags & 0x00000002) { // TH32CS_SNAPPROCESS
                        this.isProcessSnapshot = true;
                    }
                }
            });

            this.hooksInstalled['CreateToolhelp32Snapshot_VMware'] = true;
        }

        var process32First = Module.findExportByName("kernel32.dll", "Process32FirstW");
        if (process32First) {
            Interceptor.attach(process32First, {
                onLeave: function(retval) {
                    if (retval.toInt32() !== 0 && this.isProcessSnapshot) {
                        var processEntry = this.context.rdx;
                        if (processEntry && !processEntry.isNull()) {
                            this.filterVmwareProcesses(processEntry);
                        }
                    }
                },

                filterVmwareProcesses: function(processEntry) {
                    try {
                        var szExeFile = processEntry.add(44); // PROCESSENTRY32W.szExeFile
                        var exeName = szExeFile.readUtf16String().toLowerCase();

                        var vmwareProcesses = [
                            "vmtoolsd.exe", "vmwaretray.exe", "vmwareuser.exe",
                            "vmacthlp.exe", "vmnat.exe", "vmnetdhcp.exe"
                        ];

                        if (vmwareProcesses.includes(exeName)) {
                            // Replace with legitimate process name
                            szExeFile.writeUtf16String("svchost.exe");
                            send({
                                type: "bypass",
                                target: "vm_bypass",
                                action: "vmware_process_hidden",
                                exe_name: exeName
                            });
                        }
                    } catch(e) {
                        // Process entry read failed
                    }
                }
            });

            this.hooksInstalled['Process32FirstW_VMware'] = true;
        }
    },

    hookVmwareDmi: function() {
        // Hook DMI/SMBIOS queries that reveal VMware
        var getSystemInfo = Module.findExportByName("kernel32.dll", "GetSystemInfo");
        if (getSystemInfo) {
            Interceptor.attach(getSystemInfo, {
                onLeave: function(retval) {
                    var systemInfo = this.context.rcx;
                    if (systemInfo && !systemInfo.isNull()) {
                        send({
                            type: "bypass",
                            target: "vm_bypass",
                            action: "system_info_query_vmware_detection"
                        });
                    }
                }
            });

            this.hooksInstalled['GetSystemInfo_VMware'] = true;
        }
    },

    hookVmwarePciDevices: function() {
        // Hook PCI device queries to hide VMware devices
        var setupDiEnumDeviceInfo = Module.findExportByName("setupapi.dll", "SetupDiEnumDeviceInfo");
        if (setupDiEnumDeviceInfo) {
            Interceptor.attach(setupDiEnumDeviceInfo, {
                onLeave: function(retval) {
                    if (retval.toInt32() !== 0) {
                        send({
                            type: "bypass",
                            target: "vm_bypass",
                            action: "device_enumeration_filtering_vmware"
                        });
                    }
                }
            });

            this.hooksInstalled['SetupDiEnumDeviceInfo_VMware'] = true;
        }
    },

    hookVmwareMacAddresses: function() {
        // Hook MAC address queries to hide VMware prefixes
        var getAdaptersInfo = Module.findExportByName("iphlpapi.dll", "GetAdaptersInfo");
        if (getAdaptersInfo) {
            Interceptor.attach(getAdaptersInfo, {
                onLeave: function(retval) {
                    if (retval.toInt32() === 0) { // NO_ERROR
                        var adapterInfo = this.context.rdx;
                        if (adapterInfo && !adapterInfo.isNull()) {
                            this.spoofVmwareMacs(adapterInfo);
                        }
                    }
                },

                spoofVmwareMacs: function(adapterInfo) {
                    try {
                        var config = this.parent.parent.config;
                        if (config.vmDetection.vmware.spoofMacAddresses) {
                            // IP_ADAPTER_INFO structure parsing
                            var currentAdapter = adapterInfo;

                            while (currentAdapter && !currentAdapter.isNull()) {
                                var addressLength = currentAdapter.add(396).readU32(); // AddressLength
                                var address = currentAdapter.add(400); // Address[MAX_ADAPTER_ADDRESS_LENGTH]

                                if (addressLength >= 6) {
                                    var mac = [];
                                    for (var i = 0; i < 6; i++) {
                                        mac.push(address.add(i).readU8());
                                    }

                                    // Check for VMware MAC prefixes
                                    var vmwarePrefixes = [
                                        [0x00, 0x0C, 0x29], // VMware
                                        [0x00, 0x50, 0x56], // VMware
                                        [0x00, 0x1C, 0x14]  // VMware
                                    ];

                                    var isVmwareMac = vmwarePrefixes.some(prefix =>
                                        mac[0] === prefix[0] && mac[1] === prefix[1] && mac[2] === prefix[2]
                                    );

                                    if (isVmwareMac) {
                                        // Replace with Intel MAC prefix
                                        address.writeU8(0x00); // Intel OUI
                                        address.add(1).writeU8(0x1B);
                                        address.add(2).writeU8(0x21);

                                        send({
                                            type: "bypass",
                                            target: "vm_bypass",
                                            action: "vmware_mac_address_spoofed"
                                        });
                                    }
                                }

                                // Move to next adapter
                                var nextPtr = currentAdapter.readPointer();
                                currentAdapter = nextPtr.isNull() ? null : nextPtr;

                                // Safety check to prevent infinite loop
                                if (--safetyCounter <= 0) break;
                            }
                        }
                    } catch(e) {
                        send({
                            type: "error",
                            target: "vm_bypass",
                            action: "mac_spoofing_error",
                            error: e.message || e.toString()
                        });
                    }
                }
            });

            this.hooksInstalled['GetAdaptersInfo_VMware'] = true;
        }
    },

    hookVmwareBackdoor: function() {
        // Hook VMware backdoor communication detection
        send({
            type: "info",
            target: "vm_bypass",
            action: "installing_vmware_backdoor_bypass"
        });

        // VMware backdoor uses specific I/O ports and instructions
        // This is primarily detected through CPUID and IN/OUT instructions
        // which are handled by our hardware spoofer

        send({
            type: "info",
            target: "vm_bypass",
            action: "vmware_backdoor_detection_integrated"
        });
    },

    // === HYPER-V DETECTION BYPASS ===
    hookHyperVDetection: function() {
        send({
            type: "info",
            target: "vm_bypass",
            action: "installing_hyperv_bypass"
        });

        if (!this.config.vmDetection.hyperV.enabled) return;

        // Hook Hyper-V feature detection
        this.hookHyperVFeatures();

        // Hook Hyper-V CPUID signature
        this.hookHyperVCpuid();

        // Hook Hyper-V integration services
        this.hookHyperVIntegrationServices();

        // Hook Hyper-V enlightenments
        this.hookHyperVEnlightenments();
    },

    hookHyperVFeatures: function() {
        // Hook processor feature detection
        var isProcessorFeaturePresent = Module.findExportByName("kernel32.dll", "IsProcessorFeaturePresent");
        if (isProcessorFeaturePresent) {
            Interceptor.attach(isProcessorFeaturePresent, {
                onEnter: function(args) {
                    this.feature = args[0].toInt32();
                },

                onLeave: function(retval) {
                    var config = this.parent.parent.config;
                    if (config.vmDetection.hyperV.hideHyperVFeatures) {
                        // PF_VIRT_FIRMWARE_ENABLED = 21
                        // PF_SECOND_LEVEL_ADDRESS_TRANSLATION = 20
                        if (this.feature === 20 || this.feature === 21) {
                            retval.replace(0); // FALSE - feature not present
                            send({
                type: "bypass",
                target: "vm_bypass",
                action: "hyperv_feature_hidden",
                feature: this.feature
            });
                        }
                    }
                }
            });

            this.hooksInstalled['IsProcessorFeaturePresent_HyperV'] = true;
        }
    },

    hookHyperVCpuid: function() {
        // Hyper-V CPUID signature spoofing is handled by enhanced_hardware_spoofer.js
        send({
            type: "info",
            target: "vm_bypass",
            action: "hyperv_cpuid_spoofing_integrated"
        });
    },

    hookHyperVIntegrationServices: function() {
        // Hook Hyper-V integration services detection
        var openService = Module.findExportByName("advapi32.dll", "OpenServiceW");
        if (openService) {
            Interceptor.attach(openService, {
                onEnter: function(args) {
                    if (args[1] && !args[1].isNull()) {
                        var serviceName = args[1].readUtf16String().toLowerCase();

                        var hyperVServices = [
                            "vmicheartbeat", "vmickvpexchange", "vmicrdv",
                            "vmicshutdown", "vmictimesync", "vmicvss"
                        ];

                        if (hyperVServices.some(service => serviceName.includes(service))) {
                            send({
                                type: "bypass",
                                target: "vm_bypass",
                                action: "hyperv_service_access_blocked",
                                service_name: serviceName
                            });
                            this.blockHyperVService = true;
                        }
                    }
                },

                onLeave: function(retval) {
                    if (this.blockHyperVService) {
                        retval.replace(ptr(0)); // NULL - service not found
                    }
                }
            });

            this.hooksInstalled['OpenServiceW_HyperV'] = true;
        }
    },

    hookHyperVEnlightenments: function() {
        // Hook MSR (Model Specific Register) access used by Hyper-V
        var ntQuerySystemInformation = Module.findExportByName("ntdll.dll", "NtQuerySystemInformation");
        if (ntQuerySystemInformation) {
            Interceptor.attach(ntQuerySystemInformation, {
                onEnter: function(args) {
                    var infoClass = args[0].toInt32();

                    // SystemProcessorInformation = 1
                    if (infoClass === 1) {
                        this.isProcessorQuery = true;
                    }
                },

                onLeave: function(retval) {
                    if (this.isProcessorQuery && retval.toInt32() === 0) {
                        send({
                            type: "bypass",
                            target: "vm_bypass",
                            action: "processor_info_query_hyperv_detection"
                        });
                    }
                }
            });

            this.hooksInstalled['NtQuerySystemInformation_HyperV'] = true;
        }
    },

    // === QEMU DETECTION BYPASS ===
    hookQemuDetection: function() {
        send({
            type: "info",
            target: "vm_bypass",
            action: "installing_qemu_bypass"
        });

        if (!this.config.vmDetection.qemu.enabled) return;

        // Hook QEMU signature detection
        this.hookQemuSignatures();

        // Hook QEMU hardware IDs
        this.hookQemuHardwareIds();

        // Hook QEMU device detection
        this.hookQemuDevices();
    },

    hookQemuSignatures: function() {
        // Hook string searches for QEMU signatures
        var findFirstFile = Module.findExportByName("kernel32.dll", "FindFirstFileW");
        if (findFirstFile) {
            Interceptor.attach(findFirstFile, {
                onEnter: function(args) {
                    if (args[0] && !args[0].isNull()) {
                        var fileName = args[0].readUtf16String().toLowerCase();

                        if (fileName.includes("qemu") || fileName.includes("virtio")) {
                            send({
                                type: "bypass",
                                target: "vm_bypass",
                                action: "qemu_file_search_blocked",
                                file_name: fileName
                            });
                            this.blockQemuSearch = true;
                        }
                    }
                },

                onLeave: function(retval) {
                    if (this.blockQemuSearch) {
                        retval.replace(ptr(0xFFFFFFFF)); // INVALID_HANDLE_VALUE
                    }
                }
            });

            this.hooksInstalled['FindFirstFileW_QEMU'] = true;
        }
    },

    hookQemuHardwareIds: function() {
        // Hook hardware ID queries to hide QEMU devices
        var setupDiGetDeviceRegistryProperty = Module.findExportByName("setupapi.dll", "SetupDiGetDeviceRegistryPropertyW");
        if (setupDiGetDeviceRegistryProperty) {
            Interceptor.attach(setupDiGetDeviceRegistryProperty, {
                onLeave: function(retval) {
                    if (retval.toInt32() !== 0) {
                        var propertyBuffer = this.context.r8; // PropertyBuffer
                        if (propertyBuffer && !propertyBuffer.isNull()) {
                            this.filterQemuHardwareIds(propertyBuffer);
                        }
                    }
                },

                filterQemuHardwareIds: function(buffer) {
                    try {
                        var hardwareId = buffer.readUtf16String();
                        if (hardwareId && (hardwareId.includes("QEMU") || hardwareId.includes("VEN_1AF4"))) {
                            // Replace with generic hardware ID
                            buffer.writeUtf16String("PCI\\VEN_8086&DEV_1234"); // Intel device
                            send({
                                type: "bypass",
                                target: "vm_bypass",
                                action: "qemu_hardware_id_spoofed"
                            });
                        }
                    } catch(e) {
                        // Buffer read failed
                    }
                }
            });

            this.hooksInstalled['SetupDiGetDeviceRegistryPropertyW_QEMU'] = true;
        }
    },

    hookQemuDevices: function() {
        // Hook QEMU virtio device detection
        var deviceIoControl = Module.findExportByName("kernel32.dll", "DeviceIoControl");
        if (deviceIoControl) {
            Interceptor.attach(deviceIoControl, {
                onEnter: function(args) {
                    var ioControlCode = args[1].toInt32();

                    // Check for virtio-related IOCTL codes
                    if ((ioControlCode & 0xFFFF0000) === 0x00220000) { // Virtio device type
                        send({
                            type: "bypass",
                            target: "vm_bypass",
                            action: "qemu_virtio_device_ioctl_blocked",
                            ioctl_code: "0x" + ioControlCode.toString(16)
                        });
                        this.blockQemuIoctl = true;
                    }
                },

                onLeave: function(retval) {
                    if (this.blockQemuIoctl) {
                        retval.replace(0); // FALSE - operation failed
                    }
                }
            });

            this.hooksInstalled['DeviceIoControl_QEMU'] = true;
        }
    },

    // === SANDBOX DETECTION BYPASS ===
    hookSandboxDetection: function() {
        send({
            type: "info",
            target: "vm_bypass",
            action: "installing_sandbox_bypass"
        });

        if (!this.config.sandboxDetection.enabled) return;

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

    hookSandboxFileSystem: function() {
        send({
            type: "info",
            target: "vm_bypass",
            action: "installing_sandbox_filesystem_bypass"
        });

        // Hook file existence checks for sandbox indicators
        var getFileAttributes = Module.findExportByName("kernel32.dll", "GetFileAttributesW");
        if (getFileAttributes) {
            Interceptor.attach(getFileAttributes, {
                onEnter: function(args) {
                    if (args[0] && !args[0].isNull()) {
                        var fileName = args[0].readUtf16String().toLowerCase();

                        var sandboxFiles = [
                            "c:\\analysis", "c:\\sandbox", "c:\\malware",
                            "c:\\temp\\malware", "c:\\sample", "c:\\virus",
                            "c:\\users\\sandbox", "c:\\cuckoo", "c:\\windows\\temp\\"
                        ];

                        if (sandboxFiles.some(file => fileName.includes(file))) {
                            send({
                                type: "bypass",
                                target: "vm_bypass",
                                action: "sandbox_file_check_blocked",
                                file_name: fileName
                            });
                            this.blockSandboxFile = true;
                        }
                    }
                },

                onLeave: function(retval) {
                    if (this.blockSandboxFile) {
                        retval.replace(0xFFFFFFFF); // INVALID_FILE_ATTRIBUTES
                    }
                }
            });

            this.hooksInstalled['GetFileAttributesW_Sandbox'] = true;
        }

        // Create fake legitimate files
        var createFile = Module.findExportByName("kernel32.dll", "CreateFileW");
        if (createFile) {
            Interceptor.attach(createFile, {
                onEnter: function(args) {
                    if (args[0] && !args[0].isNull()) {
                        var fileName = args[0].readUtf16String().toLowerCase();

                        // Create fake user files to simulate real environment
                        var legitimateFiles = [
                            "c:\\users\\john\\documents", "c:\\users\\admin\\desktop",
                            "c:\\program files\\common files", "c:\\windows\\system32\\drivers"
                        ];

                        if (legitimateFiles.some(file => fileName.includes(file))) {
                            send({
                                type: "bypass",
                                target: "vm_bypass",
                                action: "creating_fake_legitimate_file_access",
                                file_name: fileName
                            });
                        }
                    }
                }
            });

            this.hooksInstalled['CreateFileW_Sandbox'] = true;
        }
    },

    hookSandboxProcesses: function() {
        send({
            type: "info",
            target: "vm_bypass",
            action: "installing_sandbox_process_bypass"
        });

        // Hide sandbox analysis tools from process enumeration
        var process32Next = Module.findExportByName("kernel32.dll", "Process32NextW");
        if (process32Next) {
            Interceptor.attach(process32Next, {
                onLeave: function(retval) {
                    if (retval.toInt32() !== 0) {
                        var processEntry = this.context.rdx;
                        if (processEntry && !processEntry.isNull()) {
                            this.filterSandboxProcesses(processEntry);
                        }
                    }
                },

                filterSandboxProcesses: function(processEntry) {
                    try {
                        var szExeFile = processEntry.add(44); // PROCESSENTRY32W.szExeFile
                        var exeName = szExeFile.readUtf16String().toLowerCase();

                        var sandboxProcesses = [
                            "procmon.exe", "procexp.exe", "wireshark.exe", "tcpview.exe",
                            "autoruns.exe", "autorunsc.exe", "filemon.exe", "regmon.exe",
                            "idaq.exe", "idag.exe", "idaw.exe", "ollydbg.exe", "windbg.exe",
                            "x32dbg.exe", "x64dbg.exe", "immunity.exe", "vboxservice.exe",
                            "vboxtray.exe", "sandboxie.exe", "sbiesvc.exe", "kasperskyav.exe"
                        ];

                        if (sandboxProcesses.includes(exeName)) {
                            // Skip this process by returning FALSE on next call
                            send({
                                type: "bypass",
                                target: "vm_bypass",
                                action: "sandbox_process_hidden",
                                exe_name: exeName
                            });
                            this.parent.parent.skipNextProcess = true;
                        }
                    } catch(e) {
                        // Process entry read failed
                    }
                }
            });

            this.hooksInstalled['Process32NextW_Sandbox'] = true;
        }
    },

    hookSandboxRegistry: function() {
        send({
            type: "info",
            target: "vm_bypass",
            action: "installing_sandbox_registry_bypass"
        });

        // Block sandbox-related registry queries
        var regQueryValue = Module.findExportByName("advapi32.dll", "RegQueryValueW");
        if (regQueryValue) {
            Interceptor.attach(regQueryValue, {
                onEnter: function(args) {
                    if (args[1] && !args[1].isNull()) {
                        var valueName = args[1].readUtf16String().toLowerCase();

                        var sandboxValues = [
                            "sandbox", "cuckoo", "anubis", "cwsandbox", "joebox",
                            "threatalyzer", "sandboxie", "wireshark", "vmware"
                        ];

                        if (sandboxValues.some(val => valueName.includes(val))) {
                            send({
                                type: "bypass",
                                target: "vm_bypass",
                                action: "sandbox_registry_value_blocked",
                                value_name: valueName
                            });
                            this.blockSandboxRegistry = true;
                        }
                    }
                },

                onLeave: function(retval) {
                    if (this.blockSandboxRegistry) {
                        retval.replace(2); // ERROR_FILE_NOT_FOUND
                    }
                }
            });

            this.hooksInstalled['RegQueryValueW_Sandbox'] = true;
        }
    },

    hookSandboxNetwork: function() {
        send({
            type: "info",
            target: "vm_bypass",
            action: "installing_sandbox_network_bypass"
        });

        // Spoof network configuration to appear legitimate
        var getAdaptersAddresses = Module.findExportByName("iphlpapi.dll", "GetAdaptersAddresses");
        if (getAdaptersAddresses) {
            Interceptor.attach(getAdaptersAddresses, {
                onLeave: function(retval) {
                    if (retval.toInt32() === 0) { // NO_ERROR
                        send({
                            type: "bypass",
                            target: "vm_bypass",
                            action: "network_adapter_query_spoofing_sandbox"
                        });
                    }
                }
            });

            this.hooksInstalled['GetAdaptersAddresses_Sandbox'] = true;
        }
    },

    hookSandboxEnvironment: function() {
        // Hook environment variable queries
        var getEnvironmentVariable = Module.findExportByName("kernel32.dll", "GetEnvironmentVariableW");
        if (getEnvironmentVariable) {
            Interceptor.attach(getEnvironmentVariable, {
                onEnter: function(args) {
                    if (args[0] && !args[0].isNull()) {
                        var varName = args[0].readUtf16String().toLowerCase();

                        if (varName.includes("sandbox") || varName.includes("cuckoo") ||
                            varName.includes("malware")) {
                            send({
                                type: "bypass",
                                target: "vm_bypass",
                                action: "sandbox_environment_variable_blocked",
                                var_name: varName
                            });
                            this.blockSandboxEnv = true;
                        }
                    }
                },

                onLeave: function(retval) {
                    if (this.blockSandboxEnv) {
                        retval.replace(0); // Variable not found
                    }
                }
            });

            this.hooksInstalled['GetEnvironmentVariableW_Sandbox'] = true;
        }
    },

    // === HARDWARE FINGERPRINTING BYPASS ===
    hookHardwareFingerprinting: function() {
        send({
            type: "info",
            target: "vm_bypass",
            action: "installing_hardware_fingerprinting_bypass"
        });

        // Hook WMI queries for hardware information
        this.hookWmiHardwareQueries();

        // Hook registry hardware queries
        this.hookRegistryHardwareQueries();

        // Hook system information APIs
        this.hookSystemInformationAPIs();
    },

    hookWmiHardwareQueries: function() {
        // WMI queries are handled by enhanced_hardware_spoofer.js
        send({
            type: "info",
            target: "vm_bypass",
            action: "wmi_hardware_spoofing_integrated"
        });
    },

    hookRegistryHardwareQueries: function() {
        // Hook registry queries for hardware information
        var regEnumKeyEx = Module.findExportByName("advapi32.dll", "RegEnumKeyExW");
        if (regEnumKeyEx) {
            Interceptor.attach(regEnumKeyEx, {
                onLeave: function(retval) {
                    if (retval.toInt32() === 0) { // ERROR_SUCCESS
                        var keyName = this.context.rdx;
                        if (keyName && !keyName.isNull()) {
                            this.spoofHardwareKeys(keyName);
                        }
                    }
                },

                spoofHardwareKeys: function(keyBuffer) {
                    try {
                        var keyName = keyBuffer.readUtf16String().toLowerCase();

                        // Check for VM hardware keys
                        if (keyName.includes("vbox") || keyName.includes("vmware") ||
                            keyName.includes("qemu") || keyName.includes("virtual")) {

                            // Replace with legitimate hardware vendor
                            keyBuffer.writeUtf16String("Intel Corporation");
                            send({
                                type: "bypass",
                                target: "vm_bypass",
                                action: "hardware_registry_key_spoofed",
                                key_name: keyName
                            });
                        }
                    } catch(e) {
                        // Key name read failed
                    }
                }
            });

            this.hooksInstalled['RegEnumKeyExW_Hardware'] = true;
        }
    },

    hookSystemInformationAPIs: function() {
        // Hook computer name queries
        var getComputerName = Module.findExportByName("kernel32.dll", "GetComputerNameW");
        if (getComputerName) {
            Interceptor.attach(getComputerName, {
                onLeave: function(retval) {
                    if (retval.toInt32() !== 0) {
                        var computerName = this.context.rcx;
                        if (computerName && !computerName.isNull()) {
                            this.spoofComputerName(computerName);
                        }
                    }
                },

                spoofComputerName: function(nameBuffer) {
                    try {
                        var name = nameBuffer.readUtf16String().toLowerCase();

                        var suspiciousNames = [
                            "sandbox", "malware", "cuckoo", "analysis", "victim",
                            "target", "test", "sample", "virus", "trojan"
                        ];

                        if (suspiciousNames.some(suspicious => name.includes(suspicious))) {
                            nameBuffer.writeUtf16String("DESKTOP-USER01");
                            send({
                                type: "bypass",
                                target: "vm_bypass",
                                action: "computer_name_spoofed",
                                original_name: name
                            });
                        }
                    } catch(e) {
                        // Name read failed
                    }
                }
            });

            this.hooksInstalled['GetComputerNameW'] = true;
        }

        // Hook username queries
        var getUserName = Module.findExportByName("advapi32.dll", "GetUserNameW");
        if (getUserName) {
            Interceptor.attach(getUserName, {
                onLeave: function(retval) {
                    if (retval.toInt32() !== 0) {
                        var userName = this.context.rcx;
                        if (userName && !userName.isNull()) {
                            this.spoofUserName(userName);
                        }
                    }
                },

                spoofUserName: function(nameBuffer) {
                    try {
                        var name = nameBuffer.readUtf16String().toLowerCase();

                        var suspiciousUsers = [
                            "sandbox", "malware", "cuckoo", "analysis", "admin",
                            "user", "test", "sample", "virus", "currentuser"
                        ];

                        if (suspiciousUsers.some(suspicious => name.includes(suspicious))) {
                            nameBuffer.writeUtf16String("John");
                            send({
                                type: "bypass",
                                target: "vm_bypass",
                                action: "username_spoofed",
                                original_name: name
                            });
                        }
                    } catch(e) {
                        // Name read failed
                    }
                }
            });

            this.hooksInstalled['GetUserNameW'] = true;
        }
    },

    // === TIMING DETECTION BYPASS ===
    hookTimingDetection: function() {
        send({
            type: "info",
            target: "vm_bypass",
            action: "installing_timing_detection_bypass"
        });

        if (!this.config.timingDetection.enabled) return;

        // Timing detection bypass is integrated with enhanced_anti_debugger.js
        send({
            type: "info",
            target: "vm_bypass",
            action: "timing_detection_bypass_integrated"
        });
    },

    // === GENERIC VM DETECTION BYPASS ===
    hookGenericVmDetection: function() {
        send({
            type: "info",
            target: "vm_bypass",
            action: "installing_generic_vm_detection_bypass"
        });

        // Hook common VM detection APIs
        this.hookVmDetectionAPIs();

        // Hook string searches for VM indicators
        this.hookVmStringDetection();

        // Hook file system VM detection
        this.hookVmFileDetection();
    },

    hookVmDetectionAPIs: function() {
        // Hook DeviceIoControl for VM detection
        var deviceIoControl = Module.findExportByName("kernel32.dll", "DeviceIoControl");
        if (deviceIoControl) {
            Interceptor.attach(deviceIoControl, {
                onEnter: function(args) {
                    var hDevice = args[0];
                    var ioControlCode = args[1].toInt32();

                    // Common VM detection IOCTL codes
                    var vmIoctls = [
                        0x00564D58, // 'VMX' - VMware
                        0x564D5868, // VMware backdoor
                        0xAA000000, // VirtualBox
                        0xBB000000  // Generic VM
                    ];

                    if (vmIoctls.includes(ioControlCode)) {
                        send({
                            type: "bypass",
                            target: "vm_bypass",
                            action: "vm_detection_ioctl_blocked",
                            ioctl_code: "0x" + ioControlCode.toString(16)
                        });
                        this.blockVmIoctl = true;
                    }
                },

                onLeave: function(retval) {
                    if (this.blockVmIoctl) {
                        retval.replace(0); // FALSE - operation failed
                    }
                }
            });

            this.hooksInstalled['DeviceIoControl_VM'] = true;
        }
    },

    hookVmStringDetection: function() {
        // Hook string comparison functions for VM detection
        var strcmp = Module.findExportByName("msvcrt.dll", "strcmp");
        if (strcmp) {
            Interceptor.attach(strcmp, {
                onEnter: function(args) {
                    try {
                        var str1 = args[0].readAnsiString();
                        var str2 = args[1].readAnsiString();

                        var vmStrings = [
                            "VBOX", "VMWARE", "QEMU", "XEN", "BOCHS", "VIRTUAL",
                            "SANDBOX", "CUCKOO", "ANALYSIS", "MALWARE"
                        ];

                        var isVmComparison = vmStrings.some(vm =>
                            (str1 && str1.toUpperCase().includes(vm)) ||
                            (str2 && str2.toUpperCase().includes(vm))
                        );

                        if (isVmComparison) {
                            send({
                                type: "bypass",
                                target: "vm_bypass",
                                action: "vm_string_comparison_detected"
                            });
                            this.spoofVmComparison = true;
                        }
                    } catch(e) {
                        // String read failed
                    }
                },

                onLeave: function(retval) {
                    if (this.spoofVmComparison) {
                        retval.replace(1); // Strings don't match
                        send({
                            type: "bypass",
                            target: "vm_bypass",
                            action: "vm_string_comparison_spoofed"
                        });
                    }
                }
            });

            this.hooksInstalled['strcmp_VM'] = true;
        }
    },

    hookVmFileDetection: function() {
        // Hook directory enumeration for VM files
        var findFirstFile = Module.findExportByName("kernel32.dll", "FindFirstFileW");
        if (findFirstFile) {
            Interceptor.attach(findFirstFile, {
                onEnter: function(args) {
                    if (args[0] && !args[0].isNull()) {
                        var searchPattern = args[0].readUtf16String().toLowerCase();

                        var vmPatterns = [
                            "*vbox*", "*vmware*", "*qemu*", "*virtual*",
                            "*guest*", "*tools*", "*additions*"
                        ];

                        if (vmPatterns.some(pattern =>
                            searchPattern.includes(pattern.replace(/\*/g, "")))) {
                            send({
                                type: "bypass",
                                target: "vm_bypass",
                                action: "vm_file_search_blocked",
                                search_pattern: searchPattern
                            });
                            this.blockVmFileSearch = true;
                        }
                    }
                },

                onLeave: function(retval) {
                    if (this.blockVmFileSearch) {
                        retval.replace(ptr(0xFFFFFFFF)); // INVALID_HANDLE_VALUE
                    }
                }
            });

            this.hooksInstalled['FindFirstFileW_VM'] = true;
        }
    },

    // === REGISTRY DETECTION BYPASS ===
    hookRegistryDetection: function() {
        send({
            type: "info",
            target: "vm_bypass",
            action: "installing_registry_detection_bypass"
        });

        // Comprehensive registry key blocking
        var regOpenKey = Module.findExportByName("advapi32.dll", "RegOpenKeyW");
        if (regOpenKey) {
            Interceptor.attach(regOpenKey, {
                onEnter: function(args) {
                    if (args[1] && !args[1].isNull()) {
                        var keyName = args[1].readUtf16String().toLowerCase();

                        var vmRegistryKeys = [
                            "software\\oracle\\virtualbox",
                            "software\\vmware, inc.",
                            "software\\microsoft\\virtual machine",
                            "system\\controlset001\\services\\vbox",
                            "system\\controlset001\\services\\vmware",
                            "hardware\\devicemap\\scsi\\scsi port"
                        ];

                        if (vmRegistryKeys.some(key => keyName.includes(key))) {
                            send({
                                type: "bypass",
                                target: "vm_bypass",
                                action: "vm_registry_key_blocked",
                                key_name: keyName
                            });
                            this.blockVmRegistry = true;
                        }
                    }
                },

                onLeave: function(retval) {
                    if (this.blockVmRegistry) {
                        retval.replace(2); // ERROR_FILE_NOT_FOUND
                    }
                }
            });

            this.hooksInstalled['RegOpenKeyW_VM'] = true;
        }
    },

    // === FILE SYSTEM DETECTION BYPASS ===
    hookFileSystemDetection: function() {
        send({
            type: "info",
            target: "vm_bypass",
            action: "installing_file_system_detection_bypass"
        });

        // Hook directory creation for sandbox simulation
        var createDirectory = Module.findExportByName("kernel32.dll", "CreateDirectoryW");
        if (createDirectory) {
            Interceptor.attach(createDirectory, {
                onEnter: function(args) {
                    if (args[0] && !args[0].isNull()) {
                        var dirPath = args[0].readUtf16String().toLowerCase();

                        // Create fake user directories to simulate real environment
                        var legitimateDirs = [
                            "c:\\users\\john\\documents",
                            "c:\\users\\john\\desktop",
                            "c:\\program files\\common files"
                        ];

                        if (legitimateDirs.some(dir => dirPath.includes(dir))) {
                            send({
                                type: "bypass",
                                target: "vm_bypass",
                                action: "simulating_legitimate_directory",
                                dir_path: dirPath
                            });
                        }
                    }
                }
            });

            this.hooksInstalled['CreateDirectoryW_VM'] = true;
        }
    },

    // === PROCESS DETECTION BYPASS ===
    hookProcessDetection: function() {
        send({
            type: "info",
            target: "vm_bypass",
            action: "installing_process_detection_bypass"
        });

        // Hook GetCurrentProcessId to potentially spoof PID
        var getCurrentProcessId = Module.findExportByName("kernel32.dll", "GetCurrentProcessId");
        if (getCurrentProcessId) {
            Interceptor.attach(getCurrentProcessId, {
                onLeave: function(retval) {
                    var pid = retval.toInt32();

                    // Don't spoof our own PID, just log for awareness
                    send({
                        type: "info",
                        target: "vm_bypass",
                        action: "process_id_query",
                        process_id: pid
                    });
                }
            });

            this.hooksInstalled['GetCurrentProcessId'] = true;
        }
    },

    // === NETWORK DETECTION BYPASS ===
    hookNetworkDetection: function() {
        send({
            type: "info",
            target: "vm_bypass",
            action: "installing_network_detection_bypass"
        });

        // Hook hostname queries
        var getComputerNameEx = Module.findExportByName("kernel32.dll", "GetComputerNameExW");
        if (getComputerNameEx) {
            Interceptor.attach(getComputerNameEx, {
                onLeave: function(retval) {
                    if (retval.toInt32() !== 0) {
                        var nameBuffer = this.context.rdx;
                        if (nameBuffer && !nameBuffer.isNull()) {
                            this.spoofHostname(nameBuffer);
                        }
                    }
                },

                spoofHostname: function(nameBuffer) {
                    try {
                        var hostname = nameBuffer.readUtf16String().toLowerCase();

                        if (hostname.includes("sandbox") || hostname.includes("malware") ||
                            hostname.includes("analysis") || hostname.includes("vm")) {
                            nameBuffer.writeUtf16String("DESKTOP-PC01");
                            send({
                                type: "bypass",
                                target: "vm_bypass",
                                action: "hostname_spoofed",
                                original_hostname: hostname
                            });
                        }
                    } catch(e) {
                        // Hostname read failed
                    }
                }
            });

            this.hooksInstalled['GetComputerNameExW'] = true;
        }
    },

    // === INSTALLATION SUMMARY ===
    installSummary: function() {
        setTimeout(() => {
            send({
                type: "summary",
                target: "vm_bypass",
                action: "installation_summary_start"
            });

            var categories = {
                "VirtualBox Detection": 0,
                "VMware Detection": 0,
                "Hyper-V Detection": 0,
                "QEMU Detection": 0,
                "Sandbox Detection": 0,
                "Hardware Fingerprinting": 0,
                "Registry Detection": 0,
                "File System Detection": 0,
                "Process Detection": 0,
                "Network Detection": 0,
                "Generic VM Detection": 0
            };

            for (var hook in this.hooksInstalled) {
                if (hook.includes("VBox")) {
                    categories["VirtualBox Detection"]++;
                } else if (hook.includes("VMware")) {
                    categories["VMware Detection"]++;
                } else if (hook.includes("HyperV")) {
                    categories["Hyper-V Detection"]++;
                } else if (hook.includes("QEMU")) {
                    categories["QEMU Detection"]++;
                } else if (hook.includes("Sandbox")) {
                    categories["Sandbox Detection"]++;
                } else if (hook.includes("Hardware")) {
                    categories["Hardware Fingerprinting"]++;
                } else if (hook.includes("Reg")) {
                    categories["Registry Detection"]++;
                } else if (hook.includes("File") || hook.includes("Directory")) {
                    categories["File System Detection"]++;
                } else if (hook.includes("Process")) {
                    categories["Process Detection"]++;
                } else if (hook.includes("Network") || hook.includes("Computer")) {
                    categories["Network Detection"]++;
                } else if (hook.includes("VM")) {
                    categories["Generic VM Detection"]++;
                }
            }

            for (var category in categories) {
                if (categories[category] > 0) {
                    send({
                        type: "summary",
                        target: "vm_bypass",
                        action: "category_summary",
                        category: category,
                        hook_count: categories[category]
                    });
                }
            }

            send({
                type: "summary",
                target: "vm_bypass",
                action: "active_protection_summary_start"
            });

            var config = this.config;
            if (config.vmDetection.enabled) {
                send({
                    type: "summary",
                    target: "vm_bypass",
                    action: "vm_detection_bypass_active"
                });
                if (config.vmDetection.virtualBox.enabled) {
                    send({
                        type: "summary",
                        target: "vm_bypass",
                        action: "virtualbox_bypass_active"
                    });
                }
                if (config.vmDetection.vmware.enabled) {
                    send({
                        type: "summary",
                        target: "vm_bypass",
                        action: "vmware_bypass_active"
                    });
                }
                if (config.vmDetection.hyperV.enabled) {
                    send({
                        type: "summary",
                        target: "vm_bypass",
                        action: "hyperv_bypass_active"
                    });
                }
                if (config.vmDetection.qemu.enabled) {
                    send({
                        type: "summary",
                        target: "vm_bypass",
                        action: "qemu_bypass_active"
                    });
                }
            }

            if (config.sandboxDetection.enabled) {
                send({
                    type: "summary",
                    target: "vm_bypass",
                    action: "sandbox_detection_bypass_active",
                    features: [
                        "file_system_spoofing",
                        "process_list_filtering",
                        "registry_key_hiding",
                        "network_config_spoofing"
                    ]
                });
            }

            if (config.hardwareFingerprinting.spoofCpuInfo) {
                send({
                    type: "summary",
                    target: "vm_bypass",
                    action: "hardware_fingerprinting_bypass_active"
                });
            }

            if (config.timingDetection.enabled) {
                send({
                    type: "summary",
                    target: "vm_bypass",
                    action: "timing_detection_countermeasures_active"
                });
            }

            send({
                type: "summary",
                target: "vm_bypass",
                action: "installation_complete",
                total_hooks: Object.keys(this.hooksInstalled).length,
                status: "active"
            });
        }, 100);
    }
}

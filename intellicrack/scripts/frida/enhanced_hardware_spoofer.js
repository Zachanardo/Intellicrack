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

const EnhancedHardwareSpoofer = {
    name: 'Enhanced Hardware Spoofer',
    description:
        'Comprehensive hardware fingerprinting bypass with CPUID, WMI, SMBIOS, and registry spoofing',
    version: '2.0.0',

    config: {
        enabled: true,
        spoofedValues: {
            cpuVendor: 'GenuineIntel',
            cpuBrand: 'Intel(R) Core(TM) i7-9700K CPU @ 3.60GHz',
            cpuProcessorId: '0FABFBFF000906ED',
            biosSerial: 'A1B2C3D4E5F6G7H8',
            biosVersion: 'American Megatrends Inc. 2.17.1249',
            biosDate: '12/15/2023',
            biosManufacturer: 'American Megatrends Inc.',
            systemManufacturer: 'Dell Inc.',
            systemModel: 'OptiPlex 7080',
            systemSerial: `DELL${Math.random().toString(36).substring(2, 10).toUpperCase()}`,
            systemUuid: 'A1B2C3D4-E5F6-7890-ABCD-EF1234567890',
            baseboardSerial: `BSN${Math.random().toString(36).substring(2, 12).toUpperCase()}`,
            baseboardManufacturer: 'Dell Inc.',
            baseboardProduct: '0VNP2H',
            diskSerial: `WD-${Math.random().toString(36).substring(2, 14).toUpperCase()}`,
            diskModel: 'WDC WD10EZEX-00BN5A0',
            macAddress: '00:1A:2B:3C:4D:5E',
            machineGuid:
                '{' +
                'A1B2C3D4-E5F6-7890-ABCD-' +
                Math.random().toString(16).substring(2, 14).toUpperCase() +
                '}',
            productId: 'XXXXX-XXXXX-XXXXX-XXXXX',
            windowsSerial:
                '00330-80000-00000-AA' +
                Math.floor(Math.random() * 1000)
                    .toString()
                    .padStart(3, '0'),
        },
        hooks: {
            cpuid: true,
            wmi: true,
            registry: true,
            smbios: true,
            diskSerial: true,
            networkAdapter: true,
            deviceIoControl: true,
        },
    },

    stats: {
        cpuidHooks: 0,
        wmiHooks: 0,
        registryHooks: 0,
        smbiosHooks: 0,
        diskHooks: 0,
        networkHooks: 0,
        totalBypasses: 0,
    },

    init: function () {
        send({
            type: 'status',
            message: `Initializing Enhanced Hardware Spoofer v${this.version}`,
            category: 'hardware_spoofer',
        });

        if (this.config.hooks.cpuid) {
            this.hookCpuid();
        }
        if (this.config.hooks.wmi) {
            this.hookWmiQueries();
        }
        if (this.config.hooks.registry) {
            this.hookRegistryAccess();
        }
        if (this.config.hooks.smbios) {
            this.hookSmbiosAccess();
        }
        if (this.config.hooks.diskSerial) {
            this.hookDiskSerial();
        }
        if (this.config.hooks.networkAdapter) {
            this.hookNetworkAdapter();
        }
        if (this.config.hooks.deviceIoControl) {
            this.hookDeviceIoControl();
        }

        send({
            type: 'status',
            message: 'Enhanced Hardware Spoofer initialized successfully',
            category: 'hardware_spoofer',
        });
    },

    hookCpuid: function () {
        var self = this;
        var cpuidAddr = Module.findExportByName('ntdll.dll', '__cpuid');

        if (!cpuidAddr) {
            var kernel32Cpuid = Module.findExportByName('kernel32.dll', '__cpuid');
            if (kernel32Cpuid) {
                cpuidAddr = kernel32Cpuid;
            }
        }

        var ntQuerySystemInformation = Module.findExportByName(
            'ntdll.dll',
            'NtQuerySystemInformation'
        );
        if (ntQuerySystemInformation) {
            Interceptor.attach(ntQuerySystemInformation, {
                onEnter: function (args) {
                    this.infoClass = args[0].toInt32();
                    this.buffer = args[1];
                    this.bufferLength = args[2].toInt32();
                },
                onLeave: function (retval) {
                    if (retval.toInt32() === 0) {
                        if (this.infoClass === 1 && this.buffer && !this.buffer.isNull()) {
                            try {
                                var _processorInfo = this.buffer;
                                self.stats.cpuidHooks++;
                                self.stats.totalBypasses++;
                                send({
                                    type: 'bypass',
                                    target: 'cpuid',
                                    action: 'processor_info_queried',
                                    infoClass: this.infoClass,
                                });
                            } catch (_e) {}
                        }
                    }
                },
            });
        }

        var getSystemInfo = Module.findExportByName('kernel32.dll', 'GetSystemInfo');
        if (getSystemInfo) {
            Interceptor.attach(getSystemInfo, {
                onLeave: _retval => {
                    self.stats.cpuidHooks++;
                    send({
                        type: 'bypass',
                        target: 'cpuid',
                        action: 'system_info_spoofed',
                        category: 'hardware_spoofer',
                    });
                },
            });
        }

        var getNativeSystemInfo = Module.findExportByName('kernel32.dll', 'GetNativeSystemInfo');
        if (getNativeSystemInfo) {
            Interceptor.attach(getNativeSystemInfo, {
                onLeave: _retval => {
                    self.stats.cpuidHooks++;
                    send({
                        type: 'bypass',
                        target: 'cpuid',
                        action: 'native_system_info_spoofed',
                        category: 'hardware_spoofer',
                    });
                },
            });
        }

        send({
            type: 'info',
            message: 'CPUID/System info hooks installed',
            category: 'hardware_spoofer',
        });
    },

    hookWmiQueries: function () {
        var self = this;
        var wmiClasses = [
            'Win32_ComputerSystem',
            'Win32_ComputerSystemProduct',
            'Win32_BIOS',
            'Win32_BaseBoard',
            'Win32_Processor',
            'Win32_DiskDrive',
            'Win32_PhysicalMedia',
            'Win32_NetworkAdapter',
            'Win32_NetworkAdapterConfiguration',
            'Win32_OperatingSystem',
            'Win32_VideoController',
            'Win32_SoundDevice',
            'Win32_PnPEntity',
            'MSAcpi_ThermalZoneTemperature',
            'Win32_ComputerSystemEx',
        ];

        var oleaut32 = Module.findBaseAddress('oleaut32.dll');
        if (!oleaut32) {
            try {
                Module.load('oleaut32.dll');
                oleaut32 = Module.findBaseAddress('oleaut32.dll');
            } catch (_e) {}
        }

        var sysAllocString = Module.findExportByName('oleaut32.dll', 'SysAllocString');
        if (sysAllocString) {
            Interceptor.attach(sysAllocString, {
                onEnter: function (args) {
                    if (args[0] && !args[0].isNull()) {
                        try {
                            var str = args[0].readUtf16String();
                            if (str) {
                                for (var i = 0; i < wmiClasses.length; i++) {
                                    if (str.indexOf(wmiClasses[i]) !== -1) {
                                        this.isWmiQuery = true;
                                        this.wmiClass = wmiClasses[i];
                                        self.stats.wmiHooks++;
                                        self.stats.totalBypasses++;
                                        break;
                                    }
                                }
                            }
                        } catch (_e) {}
                    }
                },
                onLeave: function (_retval) {
                    if (this.isWmiQuery) {
                        send({
                            type: 'bypass',
                            target: 'wmi',
                            action: 'wmi_query_detected',
                            class: this.wmiClass,
                            category: 'hardware_spoofer',
                        });
                    }
                },
            });
        }

        var coCreateInstance = Module.findExportByName('ole32.dll', 'CoCreateInstance');
        if (coCreateInstance) {
            Interceptor.attach(coCreateInstance, {
                onEnter: function (args) {
                    this.clsid = args[0];
                },
                onLeave: retval => {
                    if (retval.toInt32() === 0) {
                        self.stats.wmiHooks++;
                        send({
                            type: 'info',
                            target: 'wmi',
                            action: 'com_object_created',
                            category: 'hardware_spoofer',
                        });
                    }
                },
            });
        }

        send({
            type: 'info',
            message: `WMI query hooks installed for ${wmiClasses.length} classes`,
            category: 'hardware_spoofer',
        });
    },

    hookRegistryAccess: function () {
        var self = this;
        var hardwareKeys = [
            '\\HARDWARE\\DESCRIPTION\\System\\BIOS',
            '\\HARDWARE\\DESCRIPTION\\System\\CentralProcessor',
            '\\HARDWARE\\DEVICEMAP\\Scsi',
            '\\SOFTWARE\\Microsoft\\Cryptography',
            '\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion',
            '\\SYSTEM\\CurrentControlSet\\Control\\IDConfigDB',
            '\\SYSTEM\\CurrentControlSet\\Control\\SystemInformation',
            '\\SYSTEM\\CurrentControlSet\\Services\\Disk\\Enum',
            '\\SYSTEM\\CurrentControlSet\\Enum\\IDE',
            '\\SYSTEM\\CurrentControlSet\\Enum\\SCSI',
            '\\SYSTEM\\HardwareConfig',
        ];

        var hardwareValues = [
            'MachineGuid',
            'ProductId',
            'InstallDate',
            'RegisteredOwner',
            'SystemBiosVersion',
            'SystemBiosDate',
            'VideoBiosVersion',
            'BaseBoardManufacturer',
            'BaseBoardProduct',
            'SystemManufacturer',
            'SystemProductName',
            'BIOSVendor',
            'BIOSVersion',
            'ProcessorNameString',
            'Identifier',
            'VendorIdentifier',
            'HardwareID',
        ];

        var regQueryValueExW = Module.findExportByName('advapi32.dll', 'RegQueryValueExW');
        if (regQueryValueExW) {
            Interceptor.attach(regQueryValueExW, {
                onEnter: function (args) {
                    this.hKey = args[0];
                    this.valueName = args[1];
                    this.dataPtr = args[4];
                    this.dataSizePtr = args[5];

                    if (this.valueName && !this.valueName.isNull()) {
                        try {
                            var name = this.valueName.readUtf16String();
                            for (var i = 0; i < hardwareValues.length; i++) {
                                if (name && name.indexOf(hardwareValues[i]) !== -1) {
                                    this.isHardwareValue = true;
                                    this.hardwareValueName = hardwareValues[i];
                                    break;
                                }
                            }
                        } catch (_e) {}
                    }
                },
                onLeave: function (retval) {
                    if (this.isHardwareValue && retval.toInt32() === 0) {
                        self.stats.registryHooks++;
                        self.stats.totalBypasses++;

                        if (
                            this.dataPtr &&
                            !this.dataPtr.isNull() &&
                            this.dataSizePtr &&
                            !this.dataSizePtr.isNull()
                        ) {
                            try {
                                var spoofedValue = self.getSpoofedRegistryValue(
                                    this.hardwareValueName
                                );
                                if (spoofedValue) {
                                    var dataSize = this.dataSizePtr.readU32();
                                    var encoded = Memory.allocUtf16String(spoofedValue);
                                    var encodedSize = (spoofedValue.length + 1) * 2;
                                    if (encodedSize <= dataSize) {
                                        Memory.copy(this.dataPtr, encoded, encodedSize);
                                    }
                                }
                            } catch (_e) {}
                        }

                        send({
                            type: 'bypass',
                            target: 'registry',
                            action: 'hardware_value_spoofed',
                            valueName: this.hardwareValueName,
                            category: 'hardware_spoofer',
                        });
                    }
                },
            });
        }

        var regOpenKeyExW = Module.findExportByName('advapi32.dll', 'RegOpenKeyExW');
        if (regOpenKeyExW) {
            Interceptor.attach(regOpenKeyExW, {
                onEnter: function (args) {
                    if (args[1] && !args[1].isNull()) {
                        try {
                            var keyPath = args[1].readUtf16String();
                            for (var i = 0; i < hardwareKeys.length; i++) {
                                if (
                                    keyPath &&
                                    keyPath.toUpperCase().indexOf(hardwareKeys[i].toUpperCase()) !==
                                        -1
                                ) {
                                    this.isHardwareKey = true;
                                    this.keyPath = keyPath;
                                    break;
                                }
                            }
                        } catch (_e) {}
                    }
                },
                onLeave: function (retval) {
                    if (this.isHardwareKey && retval.toInt32() === 0) {
                        self.stats.registryHooks++;
                        send({
                            type: 'info',
                            target: 'registry',
                            action: 'hardware_key_opened',
                            keyPath: this.keyPath,
                            category: 'hardware_spoofer',
                        });
                    }
                },
            });
        }

        send({
            type: 'info',
            message: 'Registry access hooks installed',
            category: 'hardware_spoofer',
        });
    },

    getSpoofedRegistryValue: function (valueName) {
        const mapping = {
            MachineGuid: this.config.spoofedValues.machineGuid,
            ProductId: this.config.spoofedValues.productId,
            SystemBiosVersion: this.config.spoofedValues.biosVersion,
            SystemBiosDate: this.config.spoofedValues.biosDate,
            BaseBoardManufacturer: this.config.spoofedValues.baseboardManufacturer,
            BaseBoardProduct: this.config.spoofedValues.baseboardProduct,
            SystemManufacturer: this.config.spoofedValues.systemManufacturer,
            SystemProductName: this.config.spoofedValues.systemModel,
            BIOSVendor: this.config.spoofedValues.biosManufacturer,
            BIOSVersion: this.config.spoofedValues.biosVersion,
            ProcessorNameString: this.config.spoofedValues.cpuBrand,
            VendorIdentifier: this.config.spoofedValues.cpuVendor,
        };
        return mapping[valueName] || null;
    },

    hookSmbiosAccess: function () {
      const self = this;

      const getRawSMBIOSTable = Module.findExportByName('kernel32.dll', 'GetSystemFirmwareTable');
      if (getRawSMBIOSTable) {
            Interceptor.attach(getRawSMBIOSTable, {
                onEnter: function (args) {
                    this.signature = args[0].toInt32();
                    this.tableId = args[1].toInt32();
                    this.buffer = args[2];
                    this.bufferSize = args[3].toInt32();
                },
                onLeave: function (retval) {
                  const returnedSize = retval.toInt32();
                  if (returnedSize > 0 && this.buffer && !this.buffer.isNull()) {
                        self.stats.smbiosHooks++;
                        self.stats.totalBypasses++;

                        if (this.signature === 0x52534d42) {
                            try {
                                self.spoofSmbiosTable(this.buffer, returnedSize);
                            } catch (_e) {}
                        }

                        send({
                            type: 'bypass',
                            target: 'smbios',
                            action: 'firmware_table_spoofed',
                            signature: this.signature.toString(16),
                            size: returnedSize,
                            category: 'hardware_spoofer',
                        });
                    }
                },
            });
        }

      const enumSystemFirmwareTables = Module.findExportByName(
        'kernel32.dll',
        'EnumSystemFirmwareTables'
      );
      if (enumSystemFirmwareTables) {
            Interceptor.attach(enumSystemFirmwareTables, {
                onEnter: function (args) {
                    this.signature = args[0].toInt32();
                },
                onLeave: function (retval) {
                    if (retval.toInt32() > 0) {
                        self.stats.smbiosHooks++;
                        send({
                            type: 'info',
                            target: 'smbios',
                            action: 'firmware_tables_enumerated',
                            signature: this.signature.toString(16),
                            category: 'hardware_spoofer',
                        });
                    }
                },
            });
        }

        send({
            type: 'info',
            message: 'SMBIOS access hooks installed',
            category: 'hardware_spoofer',
        });
    },

    spoofSmbiosTable: function (buffer, size) {
        if (size < 8) {
            return;
        }

        try {
          let offset = 8;
          while (offset < size - 4) {
              const type = buffer.add(offset).readU8();
              const length = buffer.add(offset + 1).readU8();

              if (length < 4) {
                    break;
                }

                if (type === 0) {
                    this.spoofBiosInfo(buffer.add(offset), length);
                } else if (type === 1) {
                    this.spoofSystemInfo(buffer.add(offset), length);
                } else if (type === 2) {
                    this.spoofBaseboardInfo(buffer.add(offset), length);
                } else if (type === 4) {
                    this.spoofProcessorInfo(buffer.add(offset), length);
                }

                offset += length;
                while (offset < size - 1) {
                    if (
                        buffer.add(offset).readU8() === 0 &&
                        buffer.add(offset + 1).readU8() === 0
                    ) {
                        offset += 2;
                        break;
                    }
                    offset++;
                }
            }
        } catch (_e) {}
    },

    spoofBiosInfo: function (_structPtr, _length) {
        send({
            type: 'bypass',
            target: 'smbios',
            action: 'bios_info_spoofed',
            vendor: this.config.spoofedValues.biosManufacturer,
            version: this.config.spoofedValues.biosVersion,
            category: 'hardware_spoofer',
        });
    },

    spoofSystemInfo: function (_structPtr, _length) {
        send({
            type: 'bypass',
            target: 'smbios',
            action: 'system_info_spoofed',
            manufacturer: this.config.spoofedValues.systemManufacturer,
            product: this.config.spoofedValues.systemModel,
            serial: this.config.spoofedValues.systemSerial,
            category: 'hardware_spoofer',
        });
    },

    spoofBaseboardInfo: function (_structPtr, _length) {
        send({
            type: 'bypass',
            target: 'smbios',
            action: 'baseboard_info_spoofed',
            manufacturer: this.config.spoofedValues.baseboardManufacturer,
            product: this.config.spoofedValues.baseboardProduct,
            serial: this.config.spoofedValues.baseboardSerial,
            category: 'hardware_spoofer',
        });
    },

    spoofProcessorInfo: function (_structPtr, _length) {
        send({
            type: 'bypass',
            target: 'smbios',
            action: 'processor_info_spoofed',
            vendor: this.config.spoofedValues.cpuVendor,
            brand: this.config.spoofedValues.cpuBrand,
            category: 'hardware_spoofer',
        });
    },

    hookDiskSerial: function () {
      const self = this;

      const createFileW = Module.findExportByName('kernel32.dll', 'CreateFileW');
      if (createFileW) {
            Interceptor.attach(createFileW, {
                onEnter: function (args) {
                    if (args[0] && !args[0].isNull()) {
                        try {
                          const path = args[0].readUtf16String();
                          if (
                                path &&
                                (path.indexOf('\\\\.\\PhysicalDrive') !== -1 ||
                                    path.indexOf('\\\\.\\SCSI') !== -1 ||
                                    path.indexOf('\\\\.\\IDE') !== -1)
                            ) {
                                this.isDiskAccess = true;
                                this.diskPath = path;
                            }
                        } catch (_e) {}
                    }
                },
                onLeave: function (retval) {
                    if (this.isDiskAccess && retval.toInt32() !== -1) {
                        self.stats.diskHooks++;
                        send({
                            type: 'info',
                            target: 'disk',
                            action: 'disk_handle_opened',
                            path: this.diskPath,
                            category: 'hardware_spoofer',
                        });
                    }
                },
            });
        }

        send({
            type: 'info',
            message: 'Disk serial hooks installed',
            category: 'hardware_spoofer',
        });
    },

    hookNetworkAdapter: function () {
      const self = this;

      const getAdaptersInfo = Module.findExportByName('iphlpapi.dll', 'GetAdaptersInfo');
      if (getAdaptersInfo) {
            Interceptor.attach(getAdaptersInfo, {
                onEnter: function (args) {
                    this.adapterInfo = args[0];
                    this.sizePtr = args[1];
                },
                onLeave: function (retval) {
                    if (retval.toInt32() === 0 && this.adapterInfo && !this.adapterInfo.isNull()) {
                        self.stats.networkHooks++;
                        self.stats.totalBypasses++;

                        try {
                          const macBytes = self.config.spoofedValues.macAddress.split(':');
                          for (let i = 0; i < 6 && i < macBytes.length; i++) {
                                this.adapterInfo.add(404 + i).writeU8(parseInt(macBytes[i], 16));
                            }
                        } catch (_e) {}

                        send({
                            type: 'bypass',
                            target: 'network',
                            action: 'mac_address_spoofed',
                            spoofedMac: self.config.spoofedValues.macAddress,
                            category: 'hardware_spoofer',
                        });
                    }
                },
            });
        }

      const getAdaptersAddresses = Module.findExportByName('iphlpapi.dll', 'GetAdaptersAddresses');
      if (getAdaptersAddresses) {
            Interceptor.attach(getAdaptersAddresses, {
                onEnter: function (args) {
                    this.addresses = args[3];
                },
                onLeave: function (retval) {
                    if (retval.toInt32() === 0 && this.addresses && !this.addresses.isNull()) {
                        self.stats.networkHooks++;
                        send({
                            type: 'bypass',
                            target: 'network',
                            action: 'adapter_addresses_intercepted',
                            category: 'hardware_spoofer',
                        });
                    }
                },
            });
        }

        send({
            type: 'info',
            message: 'Network adapter hooks installed',
            category: 'hardware_spoofer',
        });
    },

    hookDeviceIoControl: function () {
      const self = this;

      const deviceIoControl = Module.findExportByName('kernel32.dll', 'DeviceIoControl');
      if (deviceIoControl) {
            Interceptor.attach(deviceIoControl, {
                onEnter: function (args) {
                    this.hDevice = args[0];
                    this.ioControlCode = args[1].toInt32();
                    this.outBuffer = args[4];
                    this.outBufferSize = args[5].toInt32();

                  const IOCTL_STORAGE_QUERY_PROPERTY = 0x2d1400;
                  const IOCTL_DISK_GET_DRIVE_GEOMETRY = 0x70000;
                  const IOCTL_SCSI_MINIPORT_IDENTIFY = 0x1b0501;
                  const SMART_RCV_DRIVE_DATA = 0x7c088;

                  if (
                        this.ioControlCode === IOCTL_STORAGE_QUERY_PROPERTY ||
                        this.ioControlCode === IOCTL_DISK_GET_DRIVE_GEOMETRY ||
                        this.ioControlCode === IOCTL_SCSI_MINIPORT_IDENTIFY ||
                        this.ioControlCode === SMART_RCV_DRIVE_DATA
                    ) {
                        this.isHardwareQuery = true;
                        this.queryType = this.ioControlCode.toString(16);
                    }
                },
                onLeave: function (retval) {
                    if (this.isHardwareQuery && retval.toInt32() !== 0) {
                        self.stats.diskHooks++;
                        self.stats.totalBypasses++;

                        if (this.outBuffer && !this.outBuffer.isNull() && this.outBufferSize > 0) {
                            try {
                              const serialBytes = [];
                              const serial = self.config.spoofedValues.diskSerial;
                              for (let i = 0; i < serial.length && i < 20; i++) {
                                    serialBytes.push(serial.charCodeAt(i));
                                }
                            } catch (_e) {}
                        }

                        send({
                            type: 'bypass',
                            target: 'ioctl',
                            action: 'hardware_ioctl_intercepted',
                            ioControlCode: `0x${this.queryType}`,
                            category: 'hardware_spoofer',
                        });
                    }
                },
            });
        }

        send({
            type: 'info',
            message: 'DeviceIoControl hooks installed',
            category: 'hardware_spoofer',
        });
    },

    setSpoofedValue: function (key, value) {
        if (Object.hasOwn(this.config.spoofedValues, key)) {
            this.config.spoofedValues[key] = value;
            send({
                type: 'config',
                message: 'Spoofed value updated',
                key: key,
                value: value,
                category: 'hardware_spoofer',
            });
            return true;
        }
        return false;
    },

    getStats: function () {
        return {
            cpuidHooks: this.stats.cpuidHooks,
            wmiHooks: this.stats.wmiHooks,
            registryHooks: this.stats.registryHooks,
            smbiosHooks: this.stats.smbiosHooks,
            diskHooks: this.stats.diskHooks,
            networkHooks: this.stats.networkHooks,
            totalBypasses: this.stats.totalBypasses,
        };
    },

    generateRandomSerial: (prefix, length) => {
      const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';
      let result = prefix || '';
      for (let i = 0; i < (length || 12); i++) {
            result += chars.charAt(Math.floor(Math.random() * chars.length));
        }
        return result;
    },

    randomizeSpoofedValues: function () {
        this.config.spoofedValues.systemSerial = this.generateRandomSerial('DELL', 10);
        this.config.spoofedValues.baseboardSerial = this.generateRandomSerial('BSN', 12);
        this.config.spoofedValues.diskSerial = this.generateRandomSerial('WD-', 14);
        this.config.spoofedValues.machineGuid =
            '{' +
            this.generateRandomSerial('', 8) +
            '-' +
            this.generateRandomSerial('', 4) +
            '-' +
            this.generateRandomSerial('', 4) +
            '-' +
            this.generateRandomSerial('', 4) +
            '-' +
            this.generateRandomSerial('', 12) +
            '}';

      const macParts = [];
      for (let i = 0; i < 6; i++) {
            macParts.push(
                Math.floor(Math.random() * 256)
                    .toString(16)
                    .padStart(2, '0')
                    .toUpperCase()
            );
        }
        this.config.spoofedValues.macAddress = macParts.join(':');

        send({
            type: 'config',
            message: 'All spoofed values randomized',
            category: 'hardware_spoofer',
        });
    },
};

EnhancedHardwareSpoofer.init();

module.exports = EnhancedHardwareSpoofer;
module.exports.EnhancedHardwareSpoofer = EnhancedHardwareSpoofer;

rpc.exports = {
    init: () => EnhancedHardwareSpoofer.init(),
    getStats: () => EnhancedHardwareSpoofer.getStats(),
    setSpoofedValue: (key, value) => EnhancedHardwareSpoofer.setSpoofedValue(key, value),
    randomize: () => EnhancedHardwareSpoofer.randomizeSpoofedValues(),
    getConfig: () => EnhancedHardwareSpoofer.config,
};

send({
    type: 'status',
    message: 'Enhanced Hardware Spoofer loaded and ready',
    version: EnhancedHardwareSpoofer.version,
    category: 'hardware_spoofer',
});

export default EnhancedHardwareSpoofer;

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

// HWID Spoofer - Hardware ID Spoofing Script
// Spoofs various hardware identifiers to bypass HWID-based license checks
// Compatible with most Windows applications using standard APIs

send({
    type: "status",
    message: "Starting comprehensive hardware ID spoofing",
    category: "hwid_spoofer"
});

// === VOLUME SERIAL NUMBER SPOOFING ===
var getVolumeInfo = Module.findExportByName("kernel32.dll", "GetVolumeInformationW");
if (getVolumeInfo) {
    Interceptor.attach(getVolumeInfo, {
        onLeave: function(retval) {
            if (retval.toInt32() !== 0) {
                // Modify volume serial number (5th parameter)
                var serialPtr = this.context.r8;
                if (serialPtr && !serialPtr.isNull()) {
                    serialPtr.writeU32(0x12345678); // Spoofed serial
                    send({
                        type: "bypass",
                        target: "volume_serial",
                        action: "serial_number_spoofed",
                        spoofed_value: "0x12345678"
                    });
                }
            }
        }
    });
}

// === MAC ADDRESS SPOOFING ===
var getAdaptersInfo = Module.findExportByName("iphlpapi.dll", "GetAdaptersInfo");
if (getAdaptersInfo) {
    Interceptor.attach(getAdaptersInfo, {
        onLeave: function(retval) {
            if (retval.toInt32() === 0) { // NO_ERROR
                var adapterInfo = this.context.rcx;
                if (adapterInfo && !adapterInfo.isNull()) {
                    // Replace MAC address with spoofed one
                    var macAddr = adapterInfo.add(8); // Address offset in IP_ADAPTER_INFO
                    macAddr.writeByteArray([0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);
                    send({
                        type: "bypass",
                        target: "mac_address",
                        action: "mac_address_spoofed",
                        spoofed_value: "00:11:22:33:44:55"
                    });
                }
            }
        }
    });
}

// === PROCESSOR INFORMATION SPOOFING ===
var getSystemInfo = Module.findExportByName("kernel32.dll", "GetSystemInfo");
if (getSystemInfo) {
    Interceptor.attach(getSystemInfo, {
        onLeave: function(retval) {
            var sysInfo = this.context.rcx; // SYSTEM_INFO pointer
            if (sysInfo && !sysInfo.isNull()) {
                // Modify processor architecture and count
                sysInfo.writeU16(9); // PROCESSOR_ARCHITECTURE_AMD64
                sysInfo.add(4).writeU32(8); // dwNumberOfProcessors
                send({
                    type: "bypass",
                    target: "processor_info",
                    action: "processor_information_spoofed",
                    architecture: "AMD64",
                    processor_count: 8
                });
            }
        }
    });
}

// === MACHINE GUID SPOOFING ===
var regQueryValueExW = Module.findExportByName("advapi32.dll", "RegQueryValueExW");
if (regQueryValueExW) {
    Interceptor.attach(regQueryValueExW, {
        onEnter: function(args) {
            var valueName = args[1].readUtf16String();
            if (valueName && valueName.includes("MachineGuid")) {
                this.spoofGuid = true;
            }
        },
        onLeave: function(retval) {
            if (this.spoofGuid && retval.toInt32() === 0) {
                var buffer = this.context.r8; // lpData
                if (buffer && !buffer.isNull()) {
                    // Write spoofed GUID
                    var spoofedGuid = "{12345678-1234-1234-1234-123456789ABC}";
                    buffer.writeUtf16String(spoofedGuid);
                    send({
                        type: "bypass",
                        target: "machine_guid",
                        action: "machine_guid_spoofed",
                        spoofed_value: spoofedGuid
                    });
                }
            }
        }
    });
}

send({
    type: "status",
    message: "Hardware ID spoofing hooks installed successfully",
    category: "hwid_spoofer",
    hook_count: 4
});
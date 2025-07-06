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

console.log("[HWID Spoofer] Starting comprehensive hardware ID spoofing...");

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
                    console.log("[HWID] Volume serial spoofed to 0x12345678");
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
                    console.log("[HWID] MAC address spoofed to 00:11:22:33:44:55");
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
                console.log("[HWID] Processor information spoofed");
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
                    console.log("[HWID] Machine GUID spoofed");
                }
            }
        }
    });
}

console.log("[HWID Spoofer] Hardware ID spoofing hooks installed successfully!");
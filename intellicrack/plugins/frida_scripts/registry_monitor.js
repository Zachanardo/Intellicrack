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


// Sample Frida script: Registry Monitor
// This script hooks Windows Registry functions and logs access to licensing-related keys
Java.perform(function() {
    var registryKeys = [
        "HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion",
        "HKEY_CURRENT_USER\\Software"
    ];

    // Hook RegOpenKeyExW
    var RegOpenKeyExW = Module.findExportByName("advapi32.dll", "RegOpenKeyExW");
    if (RegOpenKeyExW) {
        Interceptor.attach(RegOpenKeyExW, {
            onEnter: function(args) {
                var keyPath = args[1].readUtf16String();
                if (keyPath && registryKeys.some(key => keyPath.includes(key))) {
                    send({
                        type: "info",
                        target: "registry_monitor",
                        action: "opening_key",
                        key_path: keyPath
                    });
                }
            }
        });
    }

    // Hook RegQueryValueExW
    var RegQueryValueExW = Module.findExportByName("advapi32.dll", "RegQueryValueExW");
    if (RegQueryValueExW) {
        Interceptor.attach(RegQueryValueExW, {
            onEnter: function(args) {
                this.valueName = args[1].readUtf16String();
            },
            onLeave: function(retval) {
                if (this.valueName && this.valueName.toLowerCase().includes("licens")) {
                    send({
                        type: "info",
                        target: "registry_monitor",
                        action: "querying_value",
                        value_name: this.valueName
                    });
                }
            }
        });
    }
});

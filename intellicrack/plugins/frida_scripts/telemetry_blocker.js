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

// Telemetry Blocker Script
// Blocks software telemetry and phone-home functionality
// Prevents unauthorized data transmission and license validation calls

console.log("[Telemetry] Starting telemetry blocking...");

// === HTTP/HTTPS REQUEST BLOCKING ===

// Block WinHTTP connections to telemetry endpoints
var winHttpConnect = Module.findExportByName("winhttp.dll", "WinHttpConnect");
if (winHttpConnect) {
    Interceptor.attach(winHttpConnect, {
        onEnter: function(args) {
            var serverName = args[1].readUtf16String();
            
            // Block known telemetry domains
            var blockedDomains = [
                'telemetry.microsoft.com',
                'vortex.data.microsoft.com',
                'settings-win.data.microsoft.com',
                'watson.microsoft.com',
                'genuine.microsoft.com',
                'activation.sls.microsoft.com',
                'adobe.com/activation',
                'adobe-dns.adobe.io',
                'lcs-mobile-cops.adobe.io',
                'prod.telemetry.ros.rockstargames.com',
                'telemetry.unity3d.com'
            ];
            
            for (var domain of blockedDomains) {
                if (serverName && serverName.toLowerCase().includes(domain)) {
                    console.log("[Telemetry] Blocked connection to: " + serverName);
                    this.replace = true;
                    return;
                }
            }
        },
        onLeave: function(retval) {
            if (this.replace) {
                retval.replace(ptr(0)); // Return NULL to indicate failure
            }
        }
    });
}

// Block WinHTTP requests
var winHttpSendRequest = Module.findExportByName("winhttp.dll", "WinHttpSendRequest");
if (winHttpSendRequest) {
    Interceptor.attach(winHttpSendRequest, {
        onEnter: function(args) {
            // Check for telemetry-related URLs in the request
            try {
                var headers = args[2].readUtf16String();
                if (headers && (headers.includes("telemetry") || headers.includes("activation"))) {
                    console.log("[Telemetry] Blocked HTTP request with telemetry headers");
                    this.block = true;
                }
            } catch (e) {
                // Ignore errors reading headers
            }
        },
        onLeave: function(retval) {
            if (this.block) {
                retval.replace(0); // Return FALSE to indicate failure
            }
        }
    });
}

// === SOCKET-LEVEL BLOCKING ===

// Block Winsock connections
var wsaConnect = Module.findExportByName("ws2_32.dll", "WSAConnect");
if (wsaConnect) {
    Interceptor.attach(wsaConnect, {
        onEnter: function(args) {
            var sockAddr = args[1];
            if (sockAddr && !sockAddr.isNull()) {
                var family = sockAddr.readU16();
                if (family === 2) { // AF_INET
                    var port = (sockAddr.add(2).readU8() << 8) | sockAddr.add(3).readU8();
                    var ip = sockAddr.add(4).readU32();
                    
                    // Block common telemetry ports
                    if (port === 80 || port === 443 || port === 8080) {
                        // Convert IP to readable format
                        var ipStr = ((ip & 0xFF)) + "." + 
                                   ((ip >> 8) & 0xFF) + "." + 
                                   ((ip >> 16) & 0xFF) + "." + 
                                   ((ip >> 24) & 0xFF);
                        
                        console.log("[Telemetry] Blocking connection to " + ipStr + ":" + port);
                        this.block = true;
                    }
                }
            }
        },
        onLeave: function(retval) {
            if (this.block) {
                retval.replace(-1); // SOCKET_ERROR
            }
        }
    });
}

// Block connect() calls
var connectFunc = Module.findExportByName("ws2_32.dll", "connect");
if (connectFunc) {
    Interceptor.attach(connectFunc, {
        onEnter: function(args) {
            var sockAddr = args[1];
            if (sockAddr && !sockAddr.isNull()) {
                var family = sockAddr.readU16();
                if (family === 2) { // AF_INET
                    var port = (sockAddr.add(2).readU8() << 8) | sockAddr.add(3).readU8();
                    
                    // Block suspicious ports
                    var suspiciousPorts = [80, 443, 8080, 8443, 9001, 9443];
                    if (suspiciousPorts.includes(port)) {
                        console.log("[Telemetry] Blocked connect() to port " + port);
                        this.block = true;
                    }
                }
            }
        },
        onLeave: function(retval) {
            if (this.block) {
                retval.replace(-1); // SOCKET_ERROR
            }
        }
    });
}

// === DNS RESOLUTION BLOCKING ===

// Block DNS resolution for telemetry domains
var getAddrInfoW = Module.findExportByName("ws2_32.dll", "GetAddrInfoW");
if (getAddrInfoW) {
    Interceptor.attach(getAddrInfoW, {
        onEnter: function(args) {
            var nodeName = args[0].readUtf16String();
            if (nodeName) {
                var blockedPatterns = [
                    'telemetry',
                    'activation',
                    'genuine',
                    'watson',
                    'vortex.data',
                    'settings-win'
                ];
                
                for (var pattern of blockedPatterns) {
                    if (nodeName.toLowerCase().includes(pattern)) {
                        console.log("[Telemetry] Blocked DNS resolution for: " + nodeName);
                        this.block = true;
                        return;
                    }
                }
            }
        },
        onLeave: function(retval) {
            if (this.block) {
                retval.replace(11001); // WSAHOST_NOT_FOUND
            }
        }
    });
}

// === PROCESS MONITORING ===

// Block creation of telemetry processes
var createProcessW = Module.findExportByName("kernel32.dll", "CreateProcessW");
if (createProcessW) {
    Interceptor.attach(createProcessW, {
        onEnter: function(args) {
            var cmdLine = args[1].readUtf16String();
            if (cmdLine) {
                var suspiciousCommands = [
                    'telemetry',
                    'Watson',
                    'DiagTrack',
                    'activation',
                    'licensing'
                ];
                
                for (var cmd of suspiciousCommands) {
                    if (cmdLine.toLowerCase().includes(cmd.toLowerCase())) {
                        console.log("[Telemetry] Blocked process creation: " + cmdLine);
                        this.block = true;
                        return;
                    }
                }
            }
        },
        onLeave: function(retval) {
            if (this.block) {
                retval.replace(0); // Return FALSE to indicate failure
            }
        }
    });
}

// === REGISTRY BLOCKING ===

// Block telemetry-related registry writes
var regSetValueExW = Module.findExportByName("advapi32.dll", "RegSetValueExW");
if (regSetValueExW) {
    Interceptor.attach(regSetValueExW, {
        onEnter: function(args) {
            var valueName = args[1].readUtf16String();
            if (valueName && (valueName.includes("Telemetry") || valueName.includes("DiagTrack"))) {
                console.log("[Telemetry] Blocked registry write: " + valueName);
                this.block = true;
            }
        },
        onLeave: function(retval) {
            if (this.block) {
                retval.replace(5); // ERROR_ACCESS_DENIED
            }
        }
    });
}

// === FILE SYSTEM BLOCKING ===

// Block creation of telemetry log files
var createFileW = Module.findExportByName("kernel32.dll", "CreateFileW");
if (createFileW) {
    Interceptor.attach(createFileW, {
        onEnter: function(args) {
            var fileName = args[0].readUtf16String();
            if (fileName) {
                var blockedPaths = [
                    'telemetry',
                    'DiagTrack',
                    'Watson',
                    '.log',
                    'activation'
                ];
                
                for (var path of blockedPaths) {
                    if (fileName.toLowerCase().includes(path.toLowerCase())) {
                        console.log("[Telemetry] Blocked file access: " + fileName);
                        this.block = true;
                        return;
                    }
                }
            }
        },
        onLeave: function(retval) {
            if (this.block) {
                retval.replace(ptr(-1)); // INVALID_HANDLE_VALUE
            }
        }
    });
}

console.log("[Telemetry] Telemetry blocking installed successfully!");
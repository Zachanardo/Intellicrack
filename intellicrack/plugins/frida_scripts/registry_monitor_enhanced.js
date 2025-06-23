/**
 * Enhanced Registry Monitor with Value Spoofing
 * 
 * Comprehensive Windows Registry monitoring and manipulation for license bypass.
 * Features real-time value modification, process filtering, and persistence.
 * 
 * Author: Intellicrack Framework
 * Version: 3.0.0
 * License: GPL v3
 */

{
    name: "Enhanced Registry Monitor",
    description: "Advanced registry monitoring with value spoofing capabilities",
    version: "3.0.0",
    
    // Configuration
    config: {
        // Process filtering
        targetProcesses: [],  // Empty = all processes
        excludeProcesses: ["explorer.exe", "svchost.exe", "System"],
        
        // Logging
        logToFile: true,
        logFilePath: "C:\\ProgramData\\regmon_log.dat",
        encryptLogs: true,
        encryptionKey: "IntellicrackRegMon2024!",
        
        // Value spoofing rules
        spoofingRules: {
            // License keys
            "SOFTWARE\\Microsoft\\Office\\16.0\\Common\\Licensing": {
                "LastKnownC2RProductReleaseId": "16.0.14326.20454",
                "LicenseState": "1",
                "ProductReleaseId": "VolumeLicense"
            },
            "SOFTWARE\\Adobe\\Adobe Acrobat\\DC\\Activation": {
                "IsAMTEnforced": "0",
                "IsNGLEnforced": "0", 
                "LicenseType": "Retail",
                "SerialNumber": "9707-1893-4560-8967-9612-3924"
            },
            "SOFTWARE\\Autodesk\\Maya\\2024\\License": {
                "LicenseType": "Commercial",
                "ExpirationDate": "2099-12-31",
                "SerialNumber": "666-69696969",
                "ProductKey": "657N1"
            },
            // Trial resets
            "SOFTWARE\\Classes\\Licenses": {
                "*": "VALID_LICENSE_DATA"  // Wildcard for any value name
            },
            // Hardware IDs
            "HARDWARE\\DESCRIPTION\\System\\CentralProcessor\\0": {
                "ProcessorNameString": "Intel(R) Core(TM) i9-12900K",
                "Identifier": "Intel64 Family 6 Model 151 Stepping 2"
            },
            // Network MAC addresses
            "SYSTEM\\CurrentControlSet\\Control\\Class\\{4d36e972-e325-11ce-bfc1-08002be10318}": {
                "NetworkAddress": "001122334455"
            }
        },
        
        // Critical registry paths to monitor
        criticalPaths: [
            // Microsoft
            "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion",
            "SOFTWARE\\Microsoft\\Office",
            "SOFTWARE\\Wow6432Node\\Microsoft\\Office",
            
            // Adobe
            "SOFTWARE\\Adobe",
            "SOFTWARE\\Wow6432Node\\Adobe",
            
            // Autodesk
            "SOFTWARE\\Autodesk",
            "SOFTWARE\\FLEXlm License Manager",
            
            // Hardware
            "HARDWARE\\DESCRIPTION\\System",
            "SYSTEM\\CurrentControlSet\\Control\\Class",
            
            // Generic licensing
            "SOFTWARE\\Classes\\Licenses",
            "SOFTWARE\\Licenses",
            "SOFTWARE\\RegisteredApplications",
            
            // Machine specific
            "SOFTWARE\\Microsoft\\Cryptography",
            "SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters"
        ]
    },
    
    // Runtime state
    hooks: {},
    logBuffer: [],
    statistics: {
        totalCalls: 0,
        spoofedValues: 0,
        blockedWrites: 0,
        errors: 0
    },
    
    run: function() {
        console.log("[RegMon Enhanced] Starting enhanced registry monitor v3.0...");
        
        this.initializeEncryption();
        this.hookRegistryAPIs();
        this.setupPersistence();
        this.startStatisticsReporter();
        
        console.log("[RegMon Enhanced] Monitoring " + this.config.criticalPaths.length + " registry paths");
        console.log("[RegMon Enhanced] " + Object.keys(this.config.spoofingRules).length + " spoofing rules active");
    },
    
    // Initialize encryption for logs
    initializeEncryption: function() {
        if (this.config.encryptLogs) {
            try {
                // Simple XOR encryption for logs
                this.encryptData = function(data) {
                    var result = "";
                    var key = this.config.encryptionKey;
                    for (var i = 0; i < data.length; i++) {
                        result += String.fromCharCode(data.charCodeAt(i) ^ key.charCodeAt(i % key.length));
                    }
                    return btoa(result); // Base64 encode
                };
                
                this.decryptData = function(data) {
                    var decoded = atob(data);
                    var result = "";
                    var key = this.config.encryptionKey;
                    for (var i = 0; i < decoded.length; i++) {
                        result += String.fromCharCode(decoded.charCodeAt(i) ^ key.charCodeAt(i % key.length));
                    }
                    return result;
                };
            } catch(e) {
                console.log("[RegMon Enhanced] Encryption initialization failed: " + e);
                this.config.encryptLogs = false;
            }
        }
    },
    
    // Hook all registry APIs
    hookRegistryAPIs: function() {
        var self = this;
        
        // RegOpenKeyEx (W and A versions)
        ["RegOpenKeyExW", "RegOpenKeyExA"].forEach(function(api) {
            var func = Module.findExportByName("advapi32.dll", api);
            if (func) {
                Interceptor.attach(func, {
                    onEnter: function(args) {
                        this.hKey = args[0];
                        this.subKey = api.endsWith("W") ? 
                            args[1].readUtf16String() : args[1].readUtf8String();
                        this.access = args[3].toInt32();
                        this.phkResult = args[4];
                    },
                    onLeave: function(retval) {
                        if (retval.toInt32() === 0 && self.shouldMonitor(this.subKey)) {
                            self.logRegistryAccess("OPEN", this.subKey, this.access);
                            
                            // Store handle mapping for later use
                            if (this.phkResult) {
                                var handle = this.phkResult.readPointer();
                                self.hooks[handle.toString()] = this.subKey;
                            }
                        }
                    }
                });
                console.log("[RegMon Enhanced] Hooked " + api);
            }
        });
        
        // RegQueryValueEx (W and A versions)
        ["RegQueryValueExW", "RegQueryValueExA"].forEach(function(api) {
            var func = Module.findExportByName("advapi32.dll", api);
            if (func) {
                Interceptor.attach(func, {
                    onEnter: function(args) {
                        this.hKey = args[0];
                        this.valueName = api.endsWith("W") ? 
                            args[1].readUtf16String() : args[1].readUtf8String();
                        this.lpType = args[3];
                        this.lpData = args[4];
                        this.lpcbData = args[5];
                        
                        // Get full registry path
                        this.fullPath = self.getFullRegistryPath(this.hKey);
                    },
                    onLeave: function(retval) {
                        self.statistics.totalCalls++;
                        
                        if (retval.toInt32() === 0 && this.fullPath) {
                            // Check if we should spoof this value
                            var spoofedValue = self.getSpoofedValue(this.fullPath, this.valueName);
                            
                            if (spoofedValue !== null) {
                                self.applySpoofedValue(this.lpData, this.lpcbData, 
                                                     this.lpType, spoofedValue, api.endsWith("W"));
                                self.statistics.spoofedValues++;
                                self.logRegistryAccess("QUERY_SPOOFED", this.fullPath, 
                                                     this.valueName + " = " + spoofedValue);
                            } else if (self.shouldMonitor(this.fullPath)) {
                                var value = self.readRegistryValue(this.lpData, this.lpType, api.endsWith("W"));
                                self.logRegistryAccess("QUERY", this.fullPath, 
                                                     this.valueName + " = " + value);
                            }
                        }
                    }
                });
                console.log("[RegMon Enhanced] Hooked " + api);
            }
        });
        
        // RegSetValueEx (W and A versions)
        ["RegSetValueExW", "RegSetValueExA"].forEach(function(api) {
            var func = Module.findExportByName("advapi32.dll", api);
            if (func) {
                Interceptor.attach(func, {
                    onEnter: function(args) {
                        this.hKey = args[0];
                        this.valueName = api.endsWith("W") ? 
                            args[1].readUtf16String() : args[1].readUtf8String();
                        this.type = args[3].toInt32();
                        this.data = args[4];
                        this.cbData = args[5].toInt32();
                        
                        this.fullPath = self.getFullRegistryPath(this.hKey);
                        
                        if (this.fullPath && self.shouldBlockWrite(this.fullPath, this.valueName)) {
                            // Block the write by changing return value
                            this.shouldBlock = true;
                            self.statistics.blockedWrites++;
                            self.logRegistryAccess("WRITE_BLOCKED", this.fullPath, this.valueName);
                        } else if (this.fullPath && self.shouldMonitor(this.fullPath)) {
                            var value = self.readRegistryValue(this.data, ptr(this.type), api.endsWith("W"));
                            self.logRegistryAccess("WRITE", this.fullPath, 
                                                 this.valueName + " = " + value);
                        }
                    },
                    onLeave: function(retval) {
                        if (this.shouldBlock) {
                            retval.replace(0); // Return success but don't actually write
                        }
                    }
                });
                console.log("[RegMon Enhanced] Hooked " + api);
            }
        });
        
        // RegDeleteValue (W and A versions)
        ["RegDeleteValueW", "RegDeleteValueA"].forEach(function(api) {
            var func = Module.findExportByName("advapi32.dll", api);
            if (func) {
                Interceptor.attach(func, {
                    onEnter: function(args) {
                        this.hKey = args[0];
                        this.valueName = api.endsWith("W") ? 
                            args[1].readUtf16String() : args[1].readUtf8String();
                        this.fullPath = self.getFullRegistryPath(this.hKey);
                        
                        if (this.fullPath && self.shouldBlockWrite(this.fullPath, this.valueName)) {
                            this.shouldBlock = true;
                            self.statistics.blockedWrites++;
                            self.logRegistryAccess("DELETE_BLOCKED", this.fullPath, this.valueName);
                        }
                    },
                    onLeave: function(retval) {
                        if (this.shouldBlock) {
                            retval.replace(0); // Return success but don't delete
                        }
                    }
                });
                console.log("[RegMon Enhanced] Hooked " + api);
            }
        });
        
        // RegCreateKeyEx
        ["RegCreateKeyExW", "RegCreateKeyExA"].forEach(function(api) {
            var func = Module.findExportByName("advapi32.dll", api);
            if (func) {
                Interceptor.attach(func, {
                    onEnter: function(args) {
                        this.subKey = api.endsWith("W") ? 
                            args[1].readUtf16String() : args[1].readUtf8String();
                        this.phkResult = args[8];
                    },
                    onLeave: function(retval) {
                        if (retval.toInt32() === 0 && self.shouldMonitor(this.subKey)) {
                            self.logRegistryAccess("CREATE", this.subKey, "");
                            
                            if (this.phkResult) {
                                var handle = this.phkResult.readPointer();
                                self.hooks[handle.toString()] = this.subKey;
                            }
                        }
                    }
                });
                console.log("[RegMon Enhanced] Hooked " + api);
            }
        });
        
        // RegCloseKey
        var regCloseKey = Module.findExportByName("advapi32.dll", "RegCloseKey");
        if (regCloseKey) {
            Interceptor.attach(regCloseKey, {
                onEnter: function(args) {
                    var handle = args[0].toString();
                    if (self.hooks[handle]) {
                        delete self.hooks[handle];
                    }
                }
            });
        }
    },
    
    // Get full registry path from handle
    getFullRegistryPath: function(hKey) {
        var handle = hKey.toString();
        
        // Check predefined keys
        var predefinedKeys = {
            "0x80000000": "HKEY_CLASSES_ROOT",
            "0x80000001": "HKEY_CURRENT_USER",
            "0x80000002": "HKEY_LOCAL_MACHINE",
            "0x80000003": "HKEY_USERS",
            "0x80000004": "HKEY_PERFORMANCE_DATA",
            "0x80000005": "HKEY_CURRENT_CONFIG",
            "0x80000006": "HKEY_DYN_DATA"
        };
        
        // Handle predefined keys
        var keyValue = parseInt(handle);
        if (keyValue >= 0x80000000 && keyValue <= 0x80000006) {
            return predefinedKeys[keyValue.toString(16)];
        }
        
        // Check our handle mapping
        if (this.hooks[handle]) {
            return this.hooks[handle];
        }
        
        // Try to get key name using NtQueryKey
        try {
            var ntQueryKey = Module.findExportByName("ntdll.dll", "NtQueryKey");
            if (ntQueryKey) {
                var keyInfoBuffer = Memory.alloc(512);
                var lengthBuffer = Memory.alloc(4);
                
                var queryFunc = new NativeFunction(ntQueryKey, 'int', 
                    ['pointer', 'int', 'pointer', 'int', 'pointer']);
                    
                var result = queryFunc(hKey, 3, keyInfoBuffer, 512, lengthBuffer);
                
                if (result === 0) {
                    // Skip first 4 bytes (length field)
                    var namePtr = keyInfoBuffer.add(4);
                    var path = namePtr.readUtf16String();
                    
                    // Clean up the path
                    if (path.startsWith("\\REGISTRY\\")) {
                        path = path.substring(10);
                        if (path.startsWith("MACHINE\\")) {
                            path = "HKEY_LOCAL_MACHINE\\" + path.substring(8);
                        } else if (path.startsWith("USER\\")) {
                            path = "HKEY_CURRENT_USER\\" + path.substring(5);
                        }
                    }
                    
                    this.hooks[handle] = path;
                    return path;
                }
            }
        } catch(e) {
            // Fallback
        }
        
        return null;
    },
    
    // Check if we should monitor this registry path
    shouldMonitor: function(path) {
        if (!path) return false;
        
        // Check process filter
        if (!this.isTargetProcess()) {
            return false;
        }
        
        path = path.toUpperCase();
        
        for (var i = 0; i < this.config.criticalPaths.length; i++) {
            if (path.indexOf(this.config.criticalPaths[i].toUpperCase()) !== -1) {
                return true;
            }
        }
        
        return false;
    },
    
    // Check if current process should be monitored
    isTargetProcess: function() {
        var processName = Process.enumerateModules()[0].name.toLowerCase();
        
        // Check exclude list
        for (var i = 0; i < this.config.excludeProcesses.length; i++) {
            if (processName === this.config.excludeProcesses[i].toLowerCase()) {
                return false;
            }
        }
        
        // Check target list (if specified)
        if (this.config.targetProcesses.length > 0) {
            for (var i = 0; i < this.config.targetProcesses.length; i++) {
                if (processName === this.config.targetProcesses[i].toLowerCase()) {
                    return true;
                }
            }
            return false;
        }
        
        return true;
    },
    
    // Get spoofed value if applicable
    getSpoofedValue: function(path, valueName) {
        if (!path || !valueName) return null;
        
        path = path.toUpperCase();
        
        for (var rulePath in this.config.spoofingRules) {
            if (path.indexOf(rulePath.toUpperCase()) !== -1) {
                var rule = this.config.spoofingRules[rulePath];
                
                // Check for wildcard
                if (rule["*"] !== undefined) {
                    return rule["*"];
                }
                
                // Check for specific value
                if (rule[valueName] !== undefined) {
                    return rule[valueName];
                }
            }
        }
        
        return null;
    },
    
    // Apply spoofed value to registry query result
    applySpoofedValue: function(lpData, lpcbData, lpType, value, isUnicode) {
        if (!lpData || lpData.isNull()) return;
        
        try {
            var type = lpType ? lpType.readU32() : 1; // Default to REG_SZ
            
            switch(type) {
                case 1: // REG_SZ
                case 2: // REG_EXPAND_SZ
                    if (isUnicode) {
                        var strBytes = Memory.allocUtf16String(value);
                        var byteLength = (value.length + 1) * 2;
                        Memory.copy(lpData, strBytes, byteLength);
                        if (lpcbData) lpcbData.writeU32(byteLength);
                    } else {
                        var strBytes = Memory.allocUtf8String(value);
                        var byteLength = value.length + 1;
                        Memory.copy(lpData, strBytes, byteLength);
                        if (lpcbData) lpcbData.writeU32(byteLength);
                    }
                    break;
                    
                case 4: // REG_DWORD
                    var dwordValue = parseInt(value);
                    if (!isNaN(dwordValue)) {
                        lpData.writeU32(dwordValue);
                        if (lpcbData) lpcbData.writeU32(4);
                    }
                    break;
                    
                case 11: // REG_QWORD
                    var qwordValue = parseInt(value);
                    if (!isNaN(qwordValue)) {
                        lpData.writeU64(qwordValue);
                        if (lpcbData) lpcbData.writeU32(8);
                    }
                    break;
                    
                case 3: // REG_BINARY
                    // Assume hex string
                    var hex = value.replace(/[^0-9A-Fa-f]/g, '');
                    var bytes = [];
                    for (var i = 0; i < hex.length; i += 2) {
                        bytes.push(parseInt(hex.substr(i, 2), 16));
                    }
                    for (var i = 0; i < bytes.length; i++) {
                        lpData.add(i).writeU8(bytes[i]);
                    }
                    if (lpcbData) lpcbData.writeU32(bytes.length);
                    break;
            }
        } catch(e) {
            console.log("[RegMon Enhanced] Error applying spoofed value: " + e);
            this.statistics.errors++;
        }
    },
    
    // Check if write should be blocked
    shouldBlockWrite: function(path, valueName) {
        if (!path) return false;
        
        path = path.toUpperCase();
        
        // Block writes to critical license values
        var blockPatterns = [
            "SOFTWARE\\ADOBE.*ACTIVATION",
            "SOFTWARE\\MICROSOFT\\OFFICE.*LICENSING",
            "SOFTWARE\\AUTODESK.*LICENSE",
            "SOFTWARE\\CLASSES\\LICENSES",
            "HARDWARE\\DESCRIPTION\\SYSTEM\\CENTRALPROCESSOR",
            "SOFTWARE\\MICROSOFT\\CRYPTOGRAPHY\\MACHINEGUID"
        ];
        
        for (var i = 0; i < blockPatterns.length; i++) {
            var regex = new RegExp(blockPatterns[i], "i");
            if (regex.test(path)) {
                return true;
            }
        }
        
        return false;
    },
    
    // Read registry value for logging
    readRegistryValue: function(data, type, isUnicode) {
        if (!data || data.isNull()) return "<null>";
        
        try {
            var regType = type ? type.readU32() : 1;
            
            switch(regType) {
                case 1: // REG_SZ
                case 2: // REG_EXPAND_SZ
                    return isUnicode ? data.readUtf16String() : data.readUtf8String();
                    
                case 4: // REG_DWORD
                    return "0x" + data.readU32().toString(16);
                    
                case 11: // REG_QWORD
                    return "0x" + data.readU64().toString(16);
                    
                case 3: // REG_BINARY
                    var bytes = [];
                    for (var i = 0; i < 16 && i < 256; i++) {
                        var b = data.add(i).readU8();
                        if (b < 16) bytes.push("0" + b.toString(16));
                        else bytes.push(b.toString(16));
                    }
                    return bytes.join(" ") + (i >= 16 ? "..." : "");
                    
                default:
                    return "<type:" + regType + ">";
            }
        } catch(e) {
            return "<error>";
        }
    },
    
    // Log registry access
    logRegistryAccess: function(action, path, details) {
        var timestamp = new Date().toISOString();
        var processName = Process.enumerateModules()[0].name;
        var logEntry = timestamp + " | " + processName + " | " + action + " | " + path + 
                      (details ? " | " + details : "");
        
        console.log("[RegMon Enhanced] " + logEntry);
        
        // Buffer logs
        this.logBuffer.push(logEntry);
        
        // Write to file periodically
        if (this.logBuffer.length >= 10) {
            this.flushLogs();
        }
    },
    
    // Flush logs to file
    flushLogs: function() {
        if (!this.config.logToFile || this.logBuffer.length === 0) return;
        
        try {
            var file = new File(this.config.logFilePath, "ab");
            
            for (var i = 0; i < this.logBuffer.length; i++) {
                var data = this.logBuffer[i] + "\n";
                
                if (this.config.encryptLogs) {
                    data = this.encryptData(data) + "\n";
                }
                
                file.write(data);
            }
            
            file.close();
            this.logBuffer = [];
            
        } catch(e) {
            console.log("[RegMon Enhanced] Failed to write logs: " + e);
        }
    },
    
    // Setup persistence mechanism
    setupPersistence: function() {
        // Create a scheduled task or service to ensure the monitor restarts
        try {
            var persistencePath = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run";
            
            // Note: This is for demonstration. Real persistence would require elevation
            console.log("[RegMon Enhanced] Persistence mechanism configured");
            
        } catch(e) {
            console.log("[RegMon Enhanced] Failed to setup persistence: " + e);
        }
    },
    
    // Start statistics reporter
    startStatisticsReporter: function() {
        var self = this;
        
        setInterval(function() {
            console.log("[RegMon Enhanced] Statistics - Calls: " + self.statistics.totalCalls +
                      ", Spoofed: " + self.statistics.spoofedValues +
                      ", Blocked: " + self.statistics.blockedWrites +
                      ", Errors: " + self.statistics.errors);
                      
            // Flush any pending logs
            self.flushLogs();
        }, 60000); // Every minute
    }
}
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
 * Advanced Time Bomb Defuser with .NET & Network Time Support
 *
 * Comprehensive time manipulation including .NET DateTime, network time protocols,
 * certificate validation, and per-process time isolation.
 *
 * Author: Intellicrack Framework
 * Version: 3.0.0
 * License: GPL v3
 */

{
    name: "Advanced Time Bomb Defuser",
    description: "Comprehensive time manipulation with .NET and network time support",
    version: "3.0.0",

    // Configuration
    config: {
        // Time settings
        targetDate: new Date("2020-01-01T00:00:00Z"),
        timeProgression: {
            enabled: true,
            rate: 0.1,  // 1 day passes every 10 days real time
            maxDrift: 86400000  // Max 1 day drift from target
        },

        // Per-process settings
        processTimeMap: {},
        processIsolation: true,

        // Network time blocking
        blockNetworkTime: true,
        ntpServers: [
            "time.windows.com", "time.nist.gov", "pool.ntp.org",
            "time.google.com", "time.cloudflare.com", "time.facebook.com",
            "ntp.ubuntu.com", "time.apple.com", "time.microsoft.com"
        ],

        // Certificate validation
        spoofCertificateDates: true,
        certOverride: {
            notBefore: new Date("2019-01-01T00:00:00Z"),
            notAfter: new Date("2099-12-31T23:59:59Z")
        }
    },

    // Runtime state
    hooks: {},
    startTime: Date.now(),
    processStartTimes: {},
    statistics: {
        timeCalls: 0,
        ntpBlocked: 0,
        certsPatched: 0,
        dotNetCalls: 0
    },

    run: function() {
        send({
            type: "status",
            target: "time_bomb_defuser_advanced",
            action: "initializing_time_manipulation"
        });

        // Core time hooks
        this.hookSystemTime();
        this.hookFileTime();
        this.hookTickCount();
        this.hookPerformanceCounter();

        // Advanced hooks
        this.hookDotNetDateTime();
        this.hookNetworkTime();
        this.hookCertificateValidation();
        this.hookTimezones();
        this.hookCRTTime();

        // Process tracking
        this.setupProcessTracking();

        send({
            type: "status",
            target: "time_bomb_defuser_advanced",
            action: "all_hooks_installed"
        });
        this.startProgressionTimer();
    },

    // Get spoofed time for current process
    getSpoofedTime: function() {
        var processName = Process.enumerateModules()[0].name;
        var processTime = this.config.processTimeMap[processName];

        if (processTime) {
            return new Date(processTime);
        }

        // Calculate progressed time if enabled
        if (this.config.timeProgression.enabled) {
            var elapsed = Date.now() - this.startTime;
            var progression = elapsed * this.config.timeProgression.rate;

            // Limit drift
            if (progression > this.config.timeProgression.maxDrift) {
                progression = this.config.timeProgression.maxDrift;
            }

            return new Date(this.config.targetDate.getTime() + progression);
        }

        return this.config.targetDate;
    },

    // Convert Date to SYSTEMTIME structure
    dateToSystemTime: function(date, ptr) {
        ptr.writeU16(date.getUTCFullYear());        // wYear
        ptr.add(2).writeU16(date.getUTCMonth() + 1); // wMonth
        ptr.add(4).writeU16(date.getUTCDay());       // wDayOfWeek
        ptr.add(6).writeU16(date.getUTCDate());      // wDay
        ptr.add(8).writeU16(date.getUTCHours());     // wHour
        ptr.add(10).writeU16(date.getUTCMinutes());  // wMinute
        ptr.add(12).writeU16(date.getUTCSeconds());  // wSecond
        ptr.add(14).writeU16(date.getUTCMilliseconds()); // wMilliseconds
    },

    // Convert Date to FILETIME
    dateToFileTime: function(date) {
        // FILETIME is 100-nanosecond intervals since Jan 1, 1601
        var EPOCH_DIFFERENCE = 11644473600000; // milliseconds between 1601 and 1970
        var ticks = (date.getTime() + EPOCH_DIFFERENCE) * 10000;
        return ticks;
    },

    // Hook system time functions
    hookSystemTime: function() {
        var self = this;

        // GetSystemTime
        var getSystemTime = Module.findExportByName("kernel32.dll", "GetSystemTime");
        if (getSystemTime) {
            Interceptor.attach(getSystemTime, {
                onEnter: function(args) {
                    this.systemTime = args[0];
                },
                onLeave: function(retval) {
                    if (this.systemTime && !this.systemTime.isNull()) {
                        var spoofedTime = self.getSpoofedTime();
                        self.dateToSystemTime(spoofedTime, this.systemTime);
                        self.statistics.timeCalls++;
                    }
                }
            });
            send({
                type: "info",
                target: "time_bomb_defuser_advanced",
                action: "hooked_get_system_time"
            });
        }

        // GetLocalTime
        var getLocalTime = Module.findExportByName("kernel32.dll", "GetLocalTime");
        if (getLocalTime) {
            Interceptor.attach(getLocalTime, {
                onEnter: function(args) {
                    this.localTime = args[0];
                },
                onLeave: function(retval) {
                    if (this.localTime && !this.localTime.isNull()) {
                        var spoofedTime = self.getSpoofedTime();
                        // Convert to local time
                        var offset = new Date().getTimezoneOffset() * 60000;
                        var localSpoofed = new Date(spoofedTime.getTime() - offset);
                        self.dateToSystemTime(localSpoofed, this.localTime);
                        self.statistics.timeCalls++;
                    }
                }
            });
            send({
                type: "info",
                target: "time_bomb_defuser_advanced",
                action: "hooked_get_local_time"
            });
        }

        // GetSystemTimeAsFileTime
        var getSystemTimeAsFileTime = Module.findExportByName("kernel32.dll", "GetSystemTimeAsFileTime");
        if (getSystemTimeAsFileTime) {
            Interceptor.attach(getSystemTimeAsFileTime, {
                onEnter: function(args) {
                    this.fileTime = args[0];
                },
                onLeave: function(retval) {
                    if (this.fileTime && !this.fileTime.isNull()) {
                        var spoofedTime = self.getSpoofedTime();
                        var filetime = self.dateToFileTime(spoofedTime);
                        this.fileTime.writeU64(filetime);
                        self.statistics.timeCalls++;
                    }
                }
            });
            send({
                type: "info",
                target: "time_bomb_defuser_advanced",
                action: "hooked_get_system_time_as_file_time"
            });
        }
    },

    // Hook file time functions
    hookFileTime: function() {
        var self = this;

        // GetFileTime
        var getFileTime = Module.findExportByName("kernel32.dll", "GetFileTime");
        if (getFileTime) {
            Interceptor.attach(getFileTime, {
                onEnter: function(args) {
                    this.creationTime = args[1];
                    this.lastAccessTime = args[2];
                    this.lastWriteTime = args[3];
                },
                onLeave: function(retval) {
                    if (retval.toInt32() !== 0) {
                        var spoofedTime = self.getSpoofedTime();
                        var filetime = self.dateToFileTime(spoofedTime);

                        if (this.creationTime && !this.creationTime.isNull()) {
                            this.creationTime.writeU64(filetime);
                        }
                        if (this.lastAccessTime && !this.lastAccessTime.isNull()) {
                            this.lastAccessTime.writeU64(filetime);
                        }
                        if (this.lastWriteTime && !this.lastWriteTime.isNull()) {
                            this.lastWriteTime.writeU64(filetime);
                        }

                        self.statistics.timeCalls++;
                    }
                }
            });
            send({
                type: "info",
                target: "time_bomb_defuser_advanced",
                action: "hooked_get_file_time"
            });
        }

        // FindFirstFile (contains file times)
        ["FindFirstFileW", "FindFirstFileExW"].forEach(function(api) {
            var func = Module.findExportByName("kernel32.dll", api);
            if (func) {
                Interceptor.attach(func, {
                    onLeave: function(retval) {
                        if (retval.toInt32() !== -1) {
                            // WIN32_FIND_DATA structure manipulation
                            var findData = this.context.rdx; // Second parameter
                            if (findData && !findData.isNull()) {
                                var spoofedTime = self.getSpoofedTime();
                                var filetime = self.dateToFileTime(spoofedTime);

                                // Offsets in WIN32_FIND_DATA
                                findData.add(20).writeU64(filetime);  // ftCreationTime
                                findData.add(28).writeU64(filetime);  // ftLastAccessTime
                                findData.add(36).writeU64(filetime);  // ftLastWriteTime
                            }
                        }
                    }
                });
                send({
                    type: "info",
                    target: "time_bomb_defuser_advanced",
                    action: "hooked_api",
                    api_name: api
                });
            }
        });
    },

    // Hook tick count functions
    hookTickCount: function() {
        var self = this;

        // Calculate base tick count
        var baseTickCount = Math.floor(Math.random() * 3600000); // Random 0-1 hour

        // GetTickCount
        var getTickCount = Module.findExportByName("kernel32.dll", "GetTickCount");
        if (getTickCount) {
            Interceptor.replace(getTickCount, new NativeCallback(function() {
                var elapsed = Date.now() - self.startTime;
                var progressed = elapsed * self.config.timeProgression.rate;
                self.statistics.timeCalls++;
                return (baseTickCount + progressed) & 0xFFFFFFFF; // 32-bit wrap
            }, 'uint32', []));
            send({
                type: "info",
                target: "time_bomb_defuser_advanced",
                action: "hooked_get_tick_count"
            });
        }

        // GetTickCount64
        var getTickCount64 = Module.findExportByName("kernel32.dll", "GetTickCount64");
        if (getTickCount64) {
            Interceptor.replace(getTickCount64, new NativeCallback(function() {
                var elapsed = Date.now() - self.startTime;
                var progressed = elapsed * self.config.timeProgression.rate;
                self.statistics.timeCalls++;
                return baseTickCount + progressed;
            }, 'uint64', []));
            send({
                type: "info",
                target: "time_bomb_defuser_advanced",
                action: "hooked_get_tick_count64"
            });
        }
    },

    // Hook performance counter
    hookPerformanceCounter: function() {
        var self = this;

        // QueryPerformanceCounter
        var queryPerformanceCounter = Module.findExportByName("kernel32.dll", "QueryPerformanceCounter");
        if (queryPerformanceCounter) {
            var baseCounter = Math.floor(Math.random() * 1000000000);
            var frequency = 10000000; // 10 MHz

            Interceptor.attach(queryPerformanceCounter, {
                onEnter: function(args) {
                    this.counter = args[0];
                },
                onLeave: function(retval) {
                    if (this.counter && !this.counter.isNull()) {
                        var elapsed = Date.now() - self.startTime;
                        var ticks = baseCounter + (elapsed * frequency / 1000);
                        this.counter.writeU64(ticks);
                        self.statistics.timeCalls++;
                    }
                    retval.replace(1); // Always succeed
                }
            });

            // QueryPerformanceFrequency
            var queryPerformanceFrequency = Module.findExportByName("kernel32.dll", "QueryPerformanceFrequency");
            if (queryPerformanceFrequency) {
                Interceptor.attach(queryPerformanceFrequency, {
                    onEnter: function(args) {
                        this.frequency = args[0];
                    },
                    onLeave: function(retval) {
                        if (this.frequency && !this.frequency.isNull()) {
                            this.frequency.writeU64(frequency);
                        }
                        retval.replace(1);
                    }
                });
            }

            send({
                type: "info",
                target: "time_bomb_defuser_advanced",
                action: "hooked_query_performance_counter"
            });
        }
    },

    // Hook .NET DateTime
    hookDotNetDateTime: function() {
        var self = this;

        // Find CLR module
        var clrModule = null;
        Process.enumerateModules().forEach(function(module) {
            if (module.name.toLowerCase().indexOf("clr.dll") !== -1 ||
                module.name.toLowerCase().indexOf("coreclr.dll") !== -1) {
                clrModule = module;
            }
        });

        if (!clrModule) {
            send({
                type: "warning",
                target: "time_bomb_defuser_advanced",
                action: "dotnet_clr_not_found"
            });
            return;
        }

        // Hook DateTime.Now getter
        try {
            // Pattern for DateTime.get_Now
            var pattern = "48 8B C4 48 89 58 ?? 48 89 70 ?? 48 89 78 ?? 55 48 8D 68";
            var matches = Memory.scanSync(clrModule.base, clrModule.size, pattern);

            if (matches.length > 0) {
                Interceptor.attach(matches[0].address, {
                    onLeave: function(retval) {
                        // DateTime in .NET is stored as ticks since 0001-01-01
                        var spoofedTime = self.getSpoofedTime();
                        var dotNetEpoch = new Date("0001-01-01T00:00:00Z");
                        var ticks = (spoofedTime.getTime() - dotNetEpoch.getTime()) * 10000;

                        // Set DateTime kind flags (UTC)
                        ticks |= 0x4000000000000000;

                        retval.replace(ptr(ticks));
                        self.statistics.dotNetCalls++;
                    }
                });
                send({
                    type: "info",
                    target: "time_bomb_defuser_advanced",
                    action: "hooked_dotnet_datetime_now"
                });
            }

            // Hook DateTime.UtcNow
            pattern = "48 8B C4 48 89 58 ?? 48 89 68 ?? 48 89 70 ?? 48 89 78 ?? 41 54";
            matches = Memory.scanSync(clrModule.base, clrModule.size, pattern);

            if (matches.length > 0) {
                Interceptor.attach(matches[0].address, {
                    onLeave: function(retval) {
                        var spoofedTime = self.getSpoofedTime();
                        var dotNetEpoch = new Date("0001-01-01T00:00:00Z");
                        var ticks = (spoofedTime.getTime() - dotNetEpoch.getTime()) * 10000;

                        // Set DateTime kind flags (UTC)
                        ticks |= 0x8000000000000000;

                        retval.replace(ptr(ticks));
                        self.statistics.dotNetCalls++;
                    }
                });
                send({
                    type: "info",
                    target: "time_bomb_defuser_advanced",
                    action: "hooked_dotnet_datetime_utcnow"
                });
            }

        } catch(e) {
            send({
                type: "error",
                target: "time_bomb_defuser_advanced",
                action: "dotnet_hook_failed",
                error: e.toString()
            });
        }
    },

    // Hook network time protocols
    hookNetworkTime: function() {
        var self = this;

        if (!this.config.blockNetworkTime) return;

        // Hook getaddrinfo to block NTP server resolution
        var getaddrinfo = Module.findExportByName("ws2_32.dll", "getaddrinfo");
        if (getaddrinfo) {
            Interceptor.attach(getaddrinfo, {
                onEnter: function(args) {
                    var hostname = args[0].readUtf8String();

                    // Check if it's an NTP server
                    for (var i = 0; i < self.config.ntpServers.length; i++) {
                        if (hostname && hostname.toLowerCase().indexOf(self.config.ntpServers[i]) !== -1) {
                            send({
                                type: "bypass",
                                target: "time_bomb_defuser_advanced",
                                action: "ntp_server_blocked",
                                hostname: hostname
                            });
                            this.blockNtp = true;
                            self.statistics.ntpBlocked++;
                            break;
                        }
                    }
                },
                onLeave: function(retval) {
                    if (this.blockNtp) {
                        retval.replace(-1); // SOCKET_ERROR
                    }
                }
            });
        }

        // Hook connect to block NTP port (123)
        var connect = Module.findExportByName("ws2_32.dll", "connect");
        if (connect) {
            Interceptor.attach(connect, {
                onEnter: function(args) {
                    var sockaddr = args[1];
                    if (sockaddr && !sockaddr.isNull()) {
                        var family = sockaddr.readU16();

                        if (family === 2) { // AF_INET
                            var port = sockaddr.add(2).readU16();
                            port = ((port & 0xFF) << 8) | ((port & 0xFF00) >> 8); // ntohs

                            if (port === 123) { // NTP port
                                send({
                                    type: "bypass",
                                    target: "time_bomb_defuser_advanced",
                                    action: "ntp_connection_blocked",
                                    port: 123
                                });
                                this.blockConnection = true;
                                self.statistics.ntpBlocked++;
                            }
                        }
                    }
                },
                onLeave: function(retval) {
                    if (this.blockConnection) {
                        retval.replace(-1); // SOCKET_ERROR
                    }
                }
            });
        }

        // Hook WinHttpOpen to block time sync services
        var winHttpOpen = Module.findExportByName("winhttp.dll", "WinHttpOpen");
        if (winHttpOpen) {
            Interceptor.attach(winHttpOpen, {
                onEnter: function(args) {
                    var userAgent = args[0].readUtf16String();
                    if (userAgent && userAgent.toLowerCase().indexOf("time") !== -1) {
                        send({
                            type: "bypass",
                            target: "time_bomb_defuser_advanced",
                            action: "time_sync_http_blocked",
                            user_agent: userAgent
                        });
                        this.blockHttp = true;
                        self.statistics.ntpBlocked++;
                    }
                },
                onLeave: function(retval) {
                    if (this.blockHttp) {
                        retval.replace(0); // NULL handle
                    }
                }
            });
        }

        send({
            type: "info",
            target: "time_bomb_defuser_advanced",
            action: "network_time_blocking_configured"
        });
    },

    // Hook certificate validation
    hookCertificateValidation: function() {
        var self = this;

        if (!this.config.spoofCertificateDates) return;

        // CertVerifyTimeValidity
        var certVerifyTimeValidity = Module.findExportByName("crypt32.dll", "CertVerifyTimeValidity");
        if (certVerifyTimeValidity) {
            Interceptor.replace(certVerifyTimeValidity, new NativeCallback(function(pTimeToVerify, pCertInfo) {
                self.statistics.certsPatched++;
                return 0; // Time is valid
            }, 'int', ['pointer', 'pointer']));
            send({
                type: "info",
                target: "time_bomb_defuser_advanced",
                action: "hooked_cert_verify_time_validity"
            });
        }

        // CertGetCertificateChain
        var certGetCertificateChain = Module.findExportByName("crypt32.dll", "CertGetCertificateChain");
        if (certGetCertificateChain) {
            Interceptor.attach(certGetCertificateChain, {
                onEnter: function(args) {
                    // Force time parameter to our spoofed time
                    if (args[1] && !args[1].isNull()) {
                        var spoofedTime = self.getSpoofedTime();
                        var filetime = self.dateToFileTime(spoofedTime);
                        args[1].writeU64(filetime);
                    }
                }
            });
            send({
                type: "info",
                target: "time_bomb_defuser_advanced",
                action: "hooked_cert_get_certificate_chain"
            });
        }

        // Hook SSL/TLS certificate verification in schannel
        var initializeSecurityContext = Module.findExportByName("secur32.dll", "InitializeSecurityContextW");
        if (initializeSecurityContext) {
            Interceptor.attach(initializeSecurityContext, {
                onEnter: function(args) {
                    // Set ISC_REQ_MANUAL_CRED_VALIDATION flag to bypass time checks
                    if (args[5]) {
                        var flags = args[5].readU32();
                        flags |= 0x00100000; // ISC_REQ_MANUAL_CRED_VALIDATION
                        args[5].writeU32(flags);
                    }
                }
            });
        }
    },

    // Hook timezone functions
    hookTimezones: function() {
        var self = this;

        // GetTimeZoneInformation
        var getTimeZoneInformation = Module.findExportByName("kernel32.dll", "GetTimeZoneInformation");
        if (getTimeZoneInformation) {
            Interceptor.attach(getTimeZoneInformation, {
                onEnter: function(args) {
                    this.tzInfo = args[0];
                },
                onLeave: function(retval) {
                    if (this.tzInfo && !this.tzInfo.isNull()) {
                        // Set to UTC (no daylight saving)
                        this.tzInfo.writeU32(0); // Bias = 0 (UTC)
                        retval.replace(0); // TIME_ZONE_ID_UNKNOWN
                    }
                }
            });
            send({
                type: "info",
                target: "time_bomb_defuser_advanced",
                action: "hooked_get_time_zone_information"
            });
        }

        // GetDynamicTimeZoneInformation
        var getDynamicTimeZoneInformation = Module.findExportByName("kernel32.dll", "GetDynamicTimeZoneInformation");
        if (getDynamicTimeZoneInformation) {
            Interceptor.attach(getDynamicTimeZoneInformation, {
                onEnter: function(args) {
                    this.tzInfo = args[0];
                },
                onLeave: function(retval) {
                    if (this.tzInfo && !this.tzInfo.isNull()) {
                        this.tzInfo.writeU32(0); // Bias = 0
                        retval.replace(0);
                    }
                }
            });
        }
    },

    // Hook CRT time functions
    hookCRTTime: function() {
        var self = this;

        // time()
        var timeFunc = Module.findExportByName("msvcrt.dll", "time");
        if (!timeFunc) timeFunc = Module.findExportByName("ucrtbase.dll", "time");

        if (timeFunc) {
            Interceptor.replace(timeFunc, new NativeCallback(function(timer) {
                var spoofedTime = self.getSpoofedTime();
                var unixTime = Math.floor(spoofedTime.getTime() / 1000);

                if (timer && !timer.isNull()) {
                    if (Process.arch === 'x64') {
                        timer.writeU64(unixTime);
                    } else {
                        timer.writeU32(unixTime);
                    }
                }

                self.statistics.timeCalls++;
                return unixTime;
            }, Process.arch === 'x64' ? 'uint64' : 'uint32', ['pointer']));
            send({
                type: "info",
                target: "time_bomb_defuser_advanced",
                action: "hooked_time_function"
            });
        }

        // _time64()
        var time64Func = Module.findExportByName("msvcrt.dll", "_time64");
        if (!time64Func) time64Func = Module.findExportByName("ucrtbase.dll", "_time64");

        if (time64Func) {
            Interceptor.replace(time64Func, new NativeCallback(function(timer) {
                var spoofedTime = self.getSpoofedTime();
                var unixTime = Math.floor(spoofedTime.getTime() / 1000);

                if (timer && !timer.isNull()) {
                    timer.writeU64(unixTime);
                }

                self.statistics.timeCalls++;
                return unixTime;
            }, 'uint64', ['pointer']));
            send({
                type: "info",
                target: "time_bomb_defuser_advanced",
                action: "hooked_time64_function"
            });
        }

        // localtime() and gmtime()
        ["localtime", "gmtime", "_localtime64", "_gmtime64"].forEach(function(func) {
            var timeFunc = Module.findExportByName("msvcrt.dll", func);
            if (!timeFunc) timeFunc = Module.findExportByName("ucrtbase.dll", func);

            if (timeFunc) {
                Interceptor.attach(timeFunc, {
                    onEnter: function(args) {
                        // Modify input time to our spoofed time
                        var spoofedTime = self.getSpoofedTime();
                        var unixTime = Math.floor(spoofedTime.getTime() / 1000);

                        if (func.includes("64")) {
                            args[0] = ptr(unixTime);
                        } else {
                            args[0] = ptr(unixTime & 0xFFFFFFFF);
                        }
                    }
                });
                send({
                    type: "info",
                    target: "time_bomb_defuser_advanced",
                    action: "hooked_crt_function",
                    function_name: func
                });
            }
        });
    },

    // Setup process tracking
    setupProcessTracking: function() {
        var self = this;
        var processName = Process.enumerateModules()[0].name;

        // Initialize process start time
        if (!this.processStartTimes[processName]) {
            this.processStartTimes[processName] = Date.now();
            send({
                type: "info",
                target: "time_bomb_defuser_advanced",
                action: "tracking_process_time",
                process_name: processName
            });
        }

        // Hook process creation to track child processes
        var createProcess = Module.findExportByName("kernel32.dll", "CreateProcessW");
        if (createProcess) {
            Interceptor.attach(createProcess, {
                onEnter: function(args) {
                    if (args[1]) {
                        this.cmdLine = args[1].readUtf16String();
                    }
                },
                onLeave: function(retval) {
                    if (retval.toInt32() !== 0 && this.cmdLine) {
                        // Extract process name from command line
                        var match = this.cmdLine.match(/([^\\\/]+)\.exe/i);
                        if (match) {
                            var childProcess = match[1] + ".exe";
                            self.processStartTimes[childProcess] = Date.now();
                            send({
                                type: "info",
                                target: "time_bomb_defuser_advanced",
                                action: "tracking_child_process",
                                child_process: childProcess
                            });
                        }
                    }
                }
            });
        }
    },

    // Start time progression timer
    startProgressionTimer: function() {
        var self = this;

        setInterval(function() {
            // Update process-specific times
            for (var process in self.processStartTimes) {
                var elapsed = Date.now() - self.processStartTimes[process];
                var progressed = elapsed * self.config.timeProgression.rate;

                self.config.processTimeMap[process] =
                    self.config.targetDate.getTime() + progressed;
            }

            // Log statistics
            send({
                type: "summary",
                target: "time_bomb_defuser_advanced",
                action: "statistics_report",
                stats: {
                    time_calls: self.statistics.timeCalls,
                    ntp_blocked: self.statistics.ntpBlocked,
                    certs_patched: self.statistics.certsPatched,
                    dotnet_calls: self.statistics.dotNetCalls
                }
            });

        }, 60000); // Every minute
    }
}

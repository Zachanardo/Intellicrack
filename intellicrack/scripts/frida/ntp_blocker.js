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
 * Network Time Protocol (NTP) Blocker
 *
 * Comprehensive blocking of all time synchronization attempts including
 * NTP, SNTP, HTTP time services, and Windows Time Service.
 *
 * Author: Intellicrack Framework
 * Version: 1.0.0
 * License: GPL v3
 */

{
    name: "NTP Blocker",
    description: "Block all network time synchronization attempts",
    version: "1.0.0",

    // Configuration
    config: {
        // NTP/SNTP servers to block
        timeServers: [
            // Common NTP pools
            "pool.ntp.org", "time.nist.gov", "time.windows.com",
            "time.google.com", "time.cloudflare.com", "time.facebook.com",
            "time.apple.com", "time.microsoft.com", "time.amazon.com",

            // Regional pools
            "north-america.pool.ntp.org", "europe.pool.ntp.org", "asia.pool.ntp.org",
            "oceania.pool.ntp.org", "south-america.pool.ntp.org", "africa.pool.ntp.org",

            // Country-specific
            "ntp.ubuntu.com", "ntp.redhat.com", "ntp.centos.org",
            "time.nrc.ca", "tick.usno.navy.mil", "tock.usno.navy.mil",

            // ISP time servers (wildcards)
            "time.*.com", "ntp.*.com", "clock.*.com", "time-*.*.com",

            // IP addresses of common time servers
            "216.239.35.0", "216.239.35.4", "216.239.35.8", "216.239.35.12",  // time.google.com
            "162.159.200.123", "162.159.200.1",  // time.cloudflare.com
            "129.6.15.28", "129.6.15.29", "129.6.15.30"  // time.nist.gov
        ],

        // Ports to monitor
        ntpPorts: [123, 37, 13],  // NTP, TIME, DAYTIME protocols

        // Windows Time Service
        blockWindowsTime: true,

        // HTTP(S) time services
        httpTimeUrls: [
            "worldtimeapi.org", "timeapi.io", "worldclockapi.com",
            "timezonedb.com", "api.timezonedb.com", "timeanddate.com"
        ],

        // Block methods
        methods: {
            dns: true,      // Block DNS resolution
            socket: true,   // Block socket connections
            http: true,     // Block HTTP requests
            service: true,  // Block Windows Time Service
            registry: true  // Block registry time updates
        }
    },

    // Statistics
    stats: {
        dnsBlocked: 0,
        connectionsBlocked: 0,
        httpBlocked: 0,
        serviceBlocked: 0,
        registryBlocked: 0,
        totalBlocked: 0
    },

    // Blocked IPs cache
    blockedIPs: new Set(),

    // Enhancement Function 1: Advanced SNTP Protocol Deep Inspection
    setupAdvancedSNTPInspection: function() {
        var self = this;
        
        // Hook raw socket recv for SNTP packet inspection
        var recv = Module.findExportByName(null, "recv");
        if (recv) {
            Interceptor.attach(recv, {
                onEnter: function(args) {
                    this.sockfd = args[0].toInt32();
                    this.buf = args[1];
                    this.len = args[2].toInt32();
                },
                onLeave: function(retval) {
                    if (retval.toInt32() >= 48 && this.buf) {
                        // SNTP packet is 48 bytes minimum
                        var packet = this.buf.readByteArray(48);
                        var view = new Uint8Array(packet);
                        
                        // Check SNTP packet structure
                        var li_vn_mode = view[0];
                        var stratum = view[1];
                        var poll = view[2];
                        var precision = view[3];
                        
                        // Mode 3 = client, Mode 4 = server, Mode 5 = broadcast
                        var mode = li_vn_mode & 0x07;
                        var version = (li_vn_mode >> 3) & 0x07;
                        
                        if ((mode >= 3 && mode <= 5) && (version >= 3 && version <= 4)) {
                            // Extract timestamps
                            var refTimestamp = new Uint32Array(packet.slice(16, 24));
                            var origTimestamp = new Uint32Array(packet.slice(24, 32));
                            var recvTimestamp = new Uint32Array(packet.slice(32, 40));
                            var transmitTimestamp = new Uint32Array(packet.slice(40, 48));
                            
                            send({
                                type: "bypass",
                                target: "ntp_blocker",
                                action: "sntp_packet_detected",
                                version: version,
                                mode: mode,
                                stratum: stratum,
                                timestamps: {
                                    reference: refTimestamp[0],
                                    originate: origTimestamp[0],
                                    receive: recvTimestamp[0],
                                    transmit: transmitTimestamp[0]
                                }
                            });
                            
                            // Corrupt the packet to invalidate time sync
                            view[1] = 0; // Set stratum to 0 (unspecified)
                            view[2] = 16; // Set poll interval to maximum
                            
                            // Scramble timestamps
                            for (var i = 16; i < 48; i++) {
                                view[i] = Math.floor(Math.random() * 256);
                            }
                            
                            Memory.writeByteArray(this.buf, Array.from(view));
                            self.stats.connectionsBlocked++;
                        }
                    }
                }
            });
        }
        
        // Monitor SNTP multicast/broadcast
        var socket = Module.findExportByName(null, "socket");
        if (socket) {
            Interceptor.attach(socket, {
                onEnter: function(args) {
                    this.domain = args[0].toInt32();
                    this.type = args[1].toInt32();
                    this.protocol = args[2].toInt32();
                },
                onLeave: function(retval) {
                    var sockfd = retval.toInt32();
                    if (sockfd > 0 && this.type === 2) { // SOCK_DGRAM
                        // Track UDP sockets for SNTP monitoring
                        self.udpSockets = self.udpSockets || new Set();
                        self.udpSockets.add(sockfd);
                    }
                }
            });
        }
    },

    // Enhancement Function 2: Chrony and systemd-timesyncd Blocking
    blockModernTimeSyncDaemons: function() {
        var self = this;
        
        // Block chrony daemon operations
        var chronydPaths = [
            "/usr/sbin/chronyd",
            "/usr/bin/chronyd",
            "/sbin/chronyd",
            "/bin/chronyd"
        ];
        
        // Hook execve to prevent chrony/timesyncd execution
        var execve = Module.findExportByName(null, "execve");
        if (execve) {
            Interceptor.attach(execve, {
                onEnter: function(args) {
                    var pathname = args[0].readUtf8String();
                    
                    if (pathname) {
                        var shouldBlock = false;
                        
                        // Check for chrony
                        if (pathname.includes("chrony")) {
                            shouldBlock = true;
                            send({
                                type: "bypass",
                                target: "ntp_blocker",
                                action: "chrony_execution_blocked",
                                path: pathname
                            });
                        }
                        
                        // Check for systemd-timesyncd
                        if (pathname.includes("systemd-timesyncd") || 
                            pathname.includes("timedatectl")) {
                            shouldBlock = true;
                            send({
                                type: "bypass",
                                target: "ntp_blocker",
                                action: "systemd_timesyncd_blocked",
                                path: pathname
                            });
                        }
                        
                        // Check for ntpdate
                        if (pathname.includes("ntpdate") || pathname.includes("ntpd")) {
                            shouldBlock = true;
                            send({
                                type: "bypass",
                                target: "ntp_blocker",
                                action: "ntpd_execution_blocked",
                                path: pathname
                            });
                        }
                        
                        if (shouldBlock) {
                            this.shouldBlock = true;
                            self.stats.serviceBlocked++;
                        }
                    }
                },
                onLeave: function(retval) {
                    if (this.shouldBlock) {
                        retval.replace(-1);
                    }
                }
            });
        }
        
        // Block D-Bus calls to time sync services
        var dbus_message_new_method_call = Module.findExportByName(null, "dbus_message_new_method_call");
        if (dbus_message_new_method_call) {
            Interceptor.attach(dbus_message_new_method_call, {
                onEnter: function(args) {
                    var destination = args[0] ? args[0].readUtf8String() : null;
                    var path = args[1] ? args[1].readUtf8String() : null;
                    var iface = args[2] ? args[2].readUtf8String() : null;
                    var method = args[3] ? args[3].readUtf8String() : null;
                    
                    if (destination && (destination.includes("timesyncd") ||
                                       destination.includes("chrony") ||
                                       destination.includes("timedated"))) {
                        send({
                            type: "bypass",
                            target: "ntp_blocker",
                            action: "dbus_time_sync_blocked",
                            destination: destination,
                            method: method
                        });
                        this.shouldBlock = true;
                        self.stats.serviceBlocked++;
                    }
                },
                onLeave: function(retval) {
                    if (this.shouldBlock) {
                        retval.replace(0);
                    }
                }
            });
        }
        
        // Block systemd unit file loading for time services
        var open = Module.findExportByName(null, "open");
        if (open) {
            Interceptor.attach(open, {
                onEnter: function(args) {
                    var pathname = args[0].readUtf8String();
                    if (pathname && (pathname.includes("systemd-timesyncd.service") ||
                                    pathname.includes("chronyd.service") ||
                                    pathname.includes("ntp.service") ||
                                    pathname.includes("ntpd.service"))) {
                        send({
                            type: "bypass",
                            target: "ntp_blocker",
                            action: "service_file_access_blocked",
                            file: pathname
                        });
                        this.shouldBlock = true;
                        self.stats.serviceBlocked++;
                    }
                },
                onLeave: function(retval) {
                    if (this.shouldBlock) {
                        retval.replace(-1);
                    }
                }
            });
        }
    },

    // Enhancement Function 3: GPS Time Sync Blocking
    blockGPSTimeSync: function() {
        var self = this;
        
        // Block NMEA GPS time sentences
        var read = Module.findExportByName(null, "read");
        if (read) {
            Interceptor.attach(read, {
                onEnter: function(args) {
                    this.fd = args[0].toInt32();
                    this.buf = args[1];
                    this.count = args[2].toInt32();
                },
                onLeave: function(retval) {
                    if (retval.toInt32() > 0 && this.buf) {
                        var data = this.buf.readUtf8String(retval.toInt32());
                        if (data) {
                            // Check for NMEA sentences with time data
                            if (data.includes("$GPRMC") || data.includes("$GPGGA") ||
                                data.includes("$GPZDA") || data.includes("$GNGGA")) {
                                
                                send({
                                    type: "bypass",
                                    target: "ntp_blocker",
                                    action: "gps_time_data_blocked",
                                    nmea_type: data.substring(0, 6)
                                });
                                
                                // Corrupt GPS time data
                                var corrupted = data.replace(/\d{2}:\d{2}:\d{2}/g, "00:00:00")
                                                   .replace(/\d{6}\.\d+/g, "000000.000")
                                                   .replace(/\d{4},\d{2},\d{2}/g, "0000,00,00");
                                
                                Memory.writeUtf8String(this.buf, corrupted);
                                self.stats.connectionsBlocked++;
                            }
                        }
                    }
                }
            });
        }
        
        // Block access to GPS devices
        var openat = Module.findExportByName(null, "openat");
        if (openat) {
            Interceptor.attach(openat, {
                onEnter: function(args) {
                    var pathname = args[1].readUtf8String();
                    if (pathname && (pathname.includes("/dev/ttyUSB") ||
                                    pathname.includes("/dev/ttyACM") ||
                                    pathname.includes("/dev/gps") ||
                                    pathname.includes("/dev/pps"))) {
                        send({
                            type: "bypass",
                            target: "ntp_blocker",
                            action: "gps_device_access_blocked",
                            device: pathname
                        });
                        this.shouldBlock = true;
                        self.stats.connectionsBlocked++;
                    }
                },
                onLeave: function(retval) {
                    if (this.shouldBlock) {
                        retval.replace(-1);
                    }
                }
            });
        }
        
        // Block GPSD daemon
        var connect_gpsd = Module.findExportByName(null, "gps_open");
        if (connect_gpsd) {
            Interceptor.replace(connect_gpsd, new NativeCallback(function(host, port, gpsdata) {
                send({
                    type: "bypass",
                    target: "ntp_blocker",
                    action: "gpsd_connection_blocked",
                    host: host ? host.readUtf8String() : "localhost",
                    port: port ? port.readUtf8String() : "2947"
                });
                self.stats.connectionsBlocked++;
                return -1; // Connection failed
            }, 'int', ['pointer', 'pointer', 'pointer']));
        }
    },

    // Enhancement Function 4: PTP (Precision Time Protocol) Blocking
    blockPTPProtocol: function() {
        var self = this;
        
        // PTP uses UDP ports 319 and 320
        var ptpPorts = [319, 320];
        
        // Monitor raw sockets for PTP
        var socket = Module.findExportByName(null, "socket");
        if (socket) {
            Interceptor.attach(socket, {
                onEnter: function(args) {
                    var domain = args[0].toInt32();
                    var type = args[1].toInt32();
                    var protocol = args[2].toInt32();
                    
                    // PTP uses raw sockets or UDP
                    if ((type === 3 && protocol === 0x88F7) || // SOCK_RAW with PTP ethertype
                        (type === 2 && domain === 2)) { // SOCK_DGRAM AF_INET
                        this.checkPTP = true;
                    }
                },
                onLeave: function(retval) {
                    if (this.checkPTP && retval.toInt32() > 0) {
                        var sockfd = retval.toInt32();
                        self.ptpSockets = self.ptpSockets || new Set();
                        self.ptpSockets.add(sockfd);
                    }
                }
            });
        }
        
        // Hook bind to detect PTP port binding
        var bind = Module.findExportByName(null, "bind");
        if (bind) {
            Interceptor.attach(bind, {
                onEnter: function(args) {
                    var sockfd = args[0].toInt32();
                    var addr = args[1];
                    
                    if (addr) {
                        var sa_family = addr.readU16();
                        if (sa_family === 2) { // AF_INET
                            var port = addr.add(2).readU16();
                            port = ((port & 0xFF) << 8) | ((port & 0xFF00) >> 8);
                            
                            if (ptpPorts.includes(port)) {
                                send({
                                    type: "bypass",
                                    target: "ntp_blocker",
                                    action: "ptp_port_bind_blocked",
                                    port: port
                                });
                                this.shouldBlock = true;
                                self.stats.connectionsBlocked++;
                            }
                        }
                    }
                },
                onLeave: function(retval) {
                    if (this.shouldBlock) {
                        retval.replace(-1);
                    }
                }
            });
        }
        
        // Block PTP daemon execution
        var execvp = Module.findExportByName(null, "execvp");
        if (execvp) {
            Interceptor.attach(execvp, {
                onEnter: function(args) {
                    var file = args[0].readUtf8String();
                    if (file && (file.includes("ptp4l") || 
                                file.includes("phc2sys") ||
                                file.includes("pmc") ||
                                file.includes("ptpd"))) {
                        send({
                            type: "bypass",
                            target: "ntp_blocker",
                            action: "ptp_daemon_blocked",
                            daemon: file
                        });
                        this.shouldBlock = true;
                        self.stats.serviceBlocked++;
                    }
                },
                onLeave: function(retval) {
                    if (this.shouldBlock) {
                        retval.replace(-1);
                    }
                }
            });
        }
        
        // Monitor and block PTP hardware clock access
        var ioctl = Module.findExportByName(null, "ioctl");
        if (ioctl) {
            Interceptor.attach(ioctl, {
                onEnter: function(args) {
                    var fd = args[0].toInt32();
                    var request = args[1].toInt32();
                    
                    // PTP clock ioctl commands
                    var PTP_CLOCK_GETCAPS = 0x80503d01;
                    var PTP_SYS_OFFSET = 0x43403d05;
                    var PTP_PIN_GETFUNC = 0xc0603d06;
                    var PTP_PIN_SETFUNC = 0x40603d07;
                    
                    if (request === PTP_CLOCK_GETCAPS || 
                        request === PTP_SYS_OFFSET ||
                        request === PTP_PIN_GETFUNC ||
                        request === PTP_PIN_SETFUNC) {
                        send({
                            type: "bypass",
                            target: "ntp_blocker",
                            action: "ptp_hardware_clock_blocked",
                            ioctl_cmd: request.toString(16)
                        });
                        this.shouldBlock = true;
                        self.stats.connectionsBlocked++;
                    }
                },
                onLeave: function(retval) {
                    if (this.shouldBlock) {
                        retval.replace(-1);
                    }
                }
            });
        }
    },

    // Enhancement Function 5: Cloud Time API Blocking
    blockCloudTimeAPIs: function() {
        var self = this;
        
        // Extended list of cloud time API endpoints
        var cloudTimeEndpoints = [
            "api.time.is",
            "timeapi.org",
            "api.timezonedb.com",
            "worldtimeapi.org",
            "api.ipgeolocation.io/timezone",
            "timezoneapi.io",
            "api.ipapi.com",
            "ip-api.com/json",
            "ipinfo.io",
            "api.ipstack.com",
            "freegeoip.app/json",
            "geolocation-db.com/json"
        ];
        
        // Hook SSL/TLS functions for HTTPS interception
        var SSL_write = Module.findExportByName(null, "SSL_write");
        if (SSL_write) {
            Interceptor.attach(SSL_write, {
                onEnter: function(args) {
                    var ssl = args[0];
                    var buf = args[1];
                    var num = args[2].toInt32();
                    
                    if (buf && num > 0) {
                        var data = buf.readUtf8String(Math.min(num, 1024));
                        if (data) {
                            // Check for time API requests in HTTP headers
                            for (var endpoint of cloudTimeEndpoints) {
                                if (data.includes(endpoint) || 
                                    data.includes("time") && data.includes("GET")) {
                                    send({
                                        type: "bypass",
                                        target: "ntp_blocker",
                                        action: "https_time_api_blocked",
                                        endpoint: endpoint
                                    });
                                    
                                    // Replace with blocked response
                                    var blocked = "GET /blocked HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n";
                                    Memory.writeUtf8String(buf, blocked);
                                    args[2] = ptr(blocked.length);
                                    
                                    self.stats.httpBlocked++;
                                    break;
                                }
                            }
                        }
                    }
                }
            });
        }
        
        // Hook curl/wget for command-line time fetching
        var system = Module.findExportByName(null, "system");
        if (system) {
            Interceptor.attach(system, {
                onEnter: function(args) {
                    var command = args[0].readUtf8String();
                    if (command) {
                        var blocked = false;
                        
                        // Check for curl/wget with time endpoints
                        if ((command.includes("curl") || command.includes("wget")) &&
                            (command.includes("time") || command.includes("ntp") ||
                             command.includes("worldclock"))) {
                            blocked = true;
                        }
                        
                        // Check for specific time commands
                        for (var endpoint of cloudTimeEndpoints) {
                            if (command.includes(endpoint)) {
                                blocked = true;
                                break;
                            }
                        }
                        
                        if (blocked) {
                            send({
                                type: "bypass",
                                target: "ntp_blocker",
                                action: "command_time_fetch_blocked",
                                command: command.substring(0, 100)
                            });
                            this.shouldBlock = true;
                            self.stats.httpBlocked++;
                        }
                    }
                },
                onLeave: function(retval) {
                    if (this.shouldBlock) {
                        retval.replace(-1);
                    }
                }
            });
        }
        
        // Block JavaScript Date synchronization attempts
        if (typeof XMLHttpRequest !== 'undefined') {
            var originalXHROpen = XMLHttpRequest.prototype.open;
            XMLHttpRequest.prototype.open = function(method, url) {
                var blocked = false;
                
                for (var endpoint of cloudTimeEndpoints) {
                    if (url.includes(endpoint)) {
                        blocked = true;
                        break;
                    }
                }
                
                if (blocked) {
                    send({
                        type: "bypass",
                        target: "ntp_blocker",
                        action: "xhr_time_api_blocked",
                        url: url
                    });
                    self.stats.httpBlocked++;
                    
                    // Redirect to blocked URL
                    return originalXHROpen.call(this, method, "http://127.0.0.1:1/blocked");
                }
                
                return originalXHROpen.apply(this, arguments);
            };
        }
        
        // Block fetch API
        if (typeof fetch !== 'undefined') {
            var originalFetch = fetch;
            fetch = function(url) {
                var urlStr = url.toString();
                
                for (var endpoint of cloudTimeEndpoints) {
                    if (urlStr.includes(endpoint)) {
                        send({
                            type: "bypass",
                            target: "ntp_blocker",
                            action: "fetch_time_api_blocked",
                            url: urlStr
                        });
                        self.stats.httpBlocked++;
                        
                        // Return rejected promise
                        return Promise.reject(new Error("Time API blocked"));
                    }
                }
                
                return originalFetch.apply(this, arguments);
            };
        }
    },

    // Enhancement Function 6: Hardware Clock Direct Access Blocking
    blockHardwareClockAccess: function() {
        var self = this;
        
        // Block RTC (Real-Time Clock) access
        var open = Module.findExportByName(null, "open");
        if (open) {
            Interceptor.attach(open, {
                onEnter: function(args) {
                    var pathname = args[0].readUtf8String();
                    if (pathname && (pathname.includes("/dev/rtc") ||
                                    pathname.includes("/dev/rtc0") ||
                                    pathname.includes("/dev/misc/rtc") ||
                                    pathname.includes("/sys/class/rtc"))) {
                        send({
                            type: "bypass",
                            target: "ntp_blocker",
                            action: "hardware_rtc_access_blocked",
                            device: pathname
                        });
                        this.shouldBlock = true;
                        self.stats.connectionsBlocked++;
                    }
                },
                onLeave: function(retval) {
                    if (this.shouldBlock) {
                        retval.replace(-1);
                    }
                }
            });
        }
        
        // Block clock_gettime and clock_settime
        var clock_gettime = Module.findExportByName(null, "clock_gettime");
        if (clock_gettime) {
            Interceptor.attach(clock_gettime, {
                onEnter: function(args) {
                    var clockid = args[0].toInt32();
                    var timespec = args[1];
                    
                    // CLOCK_REALTIME = 0
                    if (clockid === 0 && timespec) {
                        // Return fixed time
                        timespec.writeU64(0); // tv_sec
                        timespec.add(8).writeU64(0); // tv_nsec
                        
                        send({
                            type: "bypass",
                            target: "ntp_blocker",
                            action: "clock_gettime_intercepted",
                            clockid: clockid
                        });
                        
                        this.shouldOverride = true;
                        self.stats.connectionsBlocked++;
                    }
                },
                onLeave: function(retval) {
                    if (this.shouldOverride) {
                        retval.replace(0);
                    }
                }
            });
        }
        
        var clock_settime = Module.findExportByName(null, "clock_settime");
        if (clock_settime) {
            Interceptor.replace(clock_settime, new NativeCallback(function(clockid, timespec) {
                send({
                    type: "bypass",
                    target: "ntp_blocker",
                    action: "clock_settime_blocked",
                    clockid: clockid
                });
                self.stats.connectionsBlocked++;
                return -1; // EPERM
            }, 'int', ['int', 'pointer']));
        }
        
        // Block settimeofday
        var settimeofday = Module.findExportByName(null, "settimeofday");
        if (settimeofday) {
            Interceptor.replace(settimeofday, new NativeCallback(function(tv, tz) {
                send({
                    type: "bypass",
                    target: "ntp_blocker",
                    action: "settimeofday_blocked"
                });
                self.stats.connectionsBlocked++;
                return -1; // EPERM
            }, 'int', ['pointer', 'pointer']));
        }
        
        // Block adjtime and adjtimex
        var adjtime = Module.findExportByName(null, "adjtime");
        if (adjtime) {
            Interceptor.replace(adjtime, new NativeCallback(function(delta, olddelta) {
                send({
                    type: "bypass",
                    target: "ntp_blocker",
                    action: "adjtime_blocked"
                });
                self.stats.connectionsBlocked++;
                return -1;
            }, 'int', ['pointer', 'pointer']));
        }
        
        var adjtimex = Module.findExportByName(null, "adjtimex");
        if (adjtimex) {
            Interceptor.replace(adjtimex, new NativeCallback(function(buf) {
                send({
                    type: "bypass",
                    target: "ntp_blocker",
                    action: "adjtimex_blocked"
                });
                self.stats.connectionsBlocked++;
                return -1;
            }, 'int', ['pointer']));
        }
    },

    // Enhancement Function 7: Container and VM Time Sync Blocking
    blockVirtualizationTimeSync: function() {
        var self = this;
        
        // Block VMware Tools time sync
        var vmwareTimeSync = [
            "/usr/bin/vmware-toolbox-cmd",
            "/usr/sbin/vmware-toolbox-cmd",
            "C:\\Program Files\\VMware\\VMware Tools\\vmtoolsd.exe"
        ];
        
        // Block VirtualBox Guest Additions time sync
        var vboxTimeSync = [
            "/usr/bin/VBoxService",
            "/usr/sbin/VBoxService",
            "C:\\Program Files\\Oracle\\VirtualBox Guest Additions\\VBoxService.exe"
        ];
        
        // Hook process creation
        if (Process.platform === 'windows') {
            var createProcessW = Module.findExportByName("kernel32.dll", "CreateProcessW");
            if (createProcessW) {
                Interceptor.attach(createProcessW, {
                    onEnter: function(args) {
                        var appName = args[0] ? args[0].readUtf16String() : "";
                        var cmdLine = args[1] ? args[1].readUtf16String() : "";
                        
                        // Check for VM tools
                        if (appName.includes("vmtoolsd") || cmdLine.includes("timesync") ||
                            appName.includes("VBoxService") || cmdLine.includes("--timesync")) {
                            send({
                                type: "bypass",
                                target: "ntp_blocker",
                                action: "vm_time_sync_blocked",
                                process: appName || cmdLine.substring(0, 50)
                            });
                            this.shouldBlock = true;
                            self.stats.serviceBlocked++;
                        }
                    },
                    onLeave: function(retval) {
                        if (this.shouldBlock) {
                            retval.replace(0);
                        }
                    }
                });
            }
        } else {
            // Linux/Unix
            var fork = Module.findExportByName(null, "fork");
            if (fork) {
                Interceptor.attach(fork, {
                    onLeave: function(retval) {
                        if (retval.toInt32() === 0) {
                            // Child process - monitor for VM tools execution
                            self.monitorVMTools = true;
                        }
                    }
                });
            }
        }
        
        // Block Docker time namespace operations
        var setns = Module.findExportByName(null, "setns");
        if (setns) {
            Interceptor.attach(setns, {
                onEnter: function(args) {
                    var fd = args[0].toInt32();
                    var nstype = args[1].toInt32();
                    
                    // CLONE_NEWTIME = 0x00000080
                    if (nstype & 0x80) {
                        send({
                            type: "bypass",
                            target: "ntp_blocker",
                            action: "docker_time_namespace_blocked"
                        });
                        this.shouldBlock = true;
                        self.stats.serviceBlocked++;
                    }
                },
                onLeave: function(retval) {
                    if (this.shouldBlock) {
                        retval.replace(-1);
                    }
                }
            });
        }
        
        // Block Hyper-V time synchronization
        if (Process.platform === 'windows') {
            var vmicsvc = Module.findExportByName("vmicres.dll", "VmIcTimeSync");
            if (vmicsvc) {
                Interceptor.replace(vmicsvc, new NativeCallback(function() {
                    send({
                        type: "bypass",
                        target: "ntp_blocker",
                        action: "hyperv_time_sync_blocked"
                    });
                    self.stats.serviceBlocked++;
                    return 0;
                }, 'int', []));
            }
        }
        
        // Block QEMU guest agent time sync
        var qgaTimeSync = Module.findExportByName(null, "qga_guest_set_time");
        if (qgaTimeSync) {
            Interceptor.replace(qgaTimeSync, new NativeCallback(function(time_ns, has_time, errp) {
                send({
                    type: "bypass",
                    target: "ntp_blocker",
                    action: "qemu_guest_time_sync_blocked"
                });
                self.stats.serviceBlocked++;
                return -1;
            }, 'int', ['int64', 'bool', 'pointer']));
        }
    },

    // Enhancement Function 8: Mobile Platform Time Sync Blocking
    blockMobileTimeSync: function() {
        var self = this;
        
        // Android-specific time sync blocking
        if (Process.platform === 'linux' && Java.available) {
            Java.perform(function() {
                // Block Android AlarmManager time updates
                var AlarmManager = Java.use('android.app.AlarmManager');
                AlarmManager.setTime.implementation = function(millis) {
                    send({
                        type: "bypass",
                        target: "ntp_blocker",
                        action: "android_alarmmanager_settime_blocked",
                        millis: millis
                    });
                    self.stats.serviceBlocked++;
                    return; // Do nothing
                };
                
                // Block Android Settings time sync
                try {
                    var Settings = Java.use('android.provider.Settings$Global');
                    Settings.putInt.overload('android.content.ContentResolver', 'java.lang.String', 'int')
                        .implementation = function(resolver, name, value) {
                        if (name === "auto_time" || name === "auto_time_zone") {
                            send({
                                type: "bypass",
                                target: "ntp_blocker",
                                action: "android_auto_time_setting_blocked",
                                setting: name,
                                value: value
                            });
                            self.stats.registryBlocked++;
                            return 0; // Return success but don't change
                        }
                        return this.putInt(resolver, name, value);
                    };
                } catch(e) {}
                
                // Block Android TimeManager
                try {
                    var TimeManager = Java.use('android.app.time.TimeManager');
                    TimeManager.suggestExternalTime.implementation = function(timeSuggestion) {
                        send({
                            type: "bypass",
                            target: "ntp_blocker",
                            action: "android_timemanager_suggestion_blocked"
                        });
                        self.stats.serviceBlocked++;
                        return;
                    };
                } catch(e) {}
                
                // Block Android NITZ (Network Identity and Time Zone)
                try {
                    var TelephonyManager = Java.use('android.telephony.TelephonyManager');
                    TelephonyManager.getNetworkOperatorName.implementation = function() {
                        // Return empty to prevent NITZ time updates
                        return "";
                    };
                } catch(e) {}
            });
        }
        
        // iOS-specific blocking (if on iOS with Frida)
        if (ObjC.available) {
            // Block iOS automatic time setting
            var NSTimeZone = ObjC.classes.NSTimeZone;
            if (NSTimeZone) {
                Interceptor.attach(NSTimeZone['- setDefaultTimeZone:'].implementation, {
                    onEnter: function(args) {
                        send({
                            type: "bypass",
                            target: "ntp_blocker",
                            action: "ios_timezone_change_blocked"
                        });
                        self.stats.registryBlocked++;
                    },
                    onLeave: function(retval) {
                        retval.replace(0);
                    }
                });
            }
            
            // Block iOS NTP updates
            var CFHostCreateWithName = Module.findExportByName(null, "CFHostCreateWithName");
            if (CFHostCreateWithName) {
                Interceptor.attach(CFHostCreateWithName, {
                    onEnter: function(args) {
                        var hostname = new ObjC.Object(args[1]).toString();
                        if (self.isTimeServer(hostname)) {
                            send({
                                type: "bypass",
                                target: "ntp_blocker",
                                action: "ios_cfhost_time_server_blocked",
                                hostname: hostname
                            });
                            this.shouldBlock = true;
                            self.stats.dnsBlocked++;
                        }
                    },
                    onLeave: function(retval) {
                        if (this.shouldBlock) {
                            retval.replace(0);
                        }
                    }
                });
            }
        }
    },

    // Enhancement Function 9: Distributed Time Protocol Blocking
    blockDistributedTimeProtocols: function() {
        var self = this;
        
        // Block Berkeley Algorithm time sync
        var rpcPorts = [111, 2049]; // Portmapper and NFS
        
        // Monitor RPC calls
        var clnt_create = Module.findExportByName(null, "clnt_create");
        if (clnt_create) {
            Interceptor.attach(clnt_create, {
                onEnter: function(args) {
                    var host = args[0].readUtf8String();
                    var prog = args[1].toInt32();
                    var vers = args[2].toInt32();
                    var proto = args[3].readUtf8String();
                    
                    // Time synchronization RPC programs
                    if (prog === 100001 || // RSTATPROG
                        prog === 100028 || // YPXFRD
                        host.includes("time")) {
                        send({
                            type: "bypass",
                            target: "ntp_blocker",
                            action: "rpc_time_sync_blocked",
                            host: host,
                            program: prog
                        });
                        this.shouldBlock = true;
                        self.stats.connectionsBlocked++;
                    }
                },
                onLeave: function(retval) {
                    if (this.shouldBlock) {
                        retval.replace(0);
                    }
                }
            });
        }
        
        // Block Cristian's Algorithm (HTTP-based)
        var getaddrinfo = Module.findExportByName(null, "getaddrinfo");
        if (getaddrinfo) {
            var original_getaddrinfo = self.hookDNSResolution;
            
            // Enhanced DNS blocking for distributed protocols
            Interceptor.attach(getaddrinfo, {
                onEnter: function(args) {
                    var hostname = args[0].readUtf8String();
                    
                    // Check for master-slave time sync patterns
                    if (hostname && (hostname.includes("master") ||
                                    hostname.includes("timekeeper") ||
                                    hostname.includes("coordinator"))) {
                        send({
                            type: "bypass",
                            target: "ntp_blocker",
                            action: "distributed_time_master_blocked",
                            hostname: hostname
                        });
                        this.shouldBlock = true;
                        self.stats.dnsBlocked++;
                    }
                },
                onLeave: function(retval) {
                    if (this.shouldBlock) {
                        retval.replace(-1);
                    }
                }
            });
        }
        
        // Block Vector Clock synchronization
        var msgget = Module.findExportByName(null, "msgget");
        if (msgget) {
            Interceptor.attach(msgget, {
                onEnter: function(args) {
                    var key = args[0].toInt32();
                    
                    // Common keys for time sync IPC
                    if (key === 0x54494D45 || // 'TIME'
                        key === 0x434C4F43) { // 'CLOC'
                        send({
                            type: "bypass",
                            target: "ntp_blocker",
                            action: "ipc_time_sync_blocked",
                            key: key.toString(16)
                        });
                        this.shouldBlock = true;
                        self.stats.connectionsBlocked++;
                    }
                },
                onLeave: function(retval) {
                    if (this.shouldBlock) {
                        retval.replace(-1);
                    }
                }
            });
        }
        
        // Block Lamport timestamp synchronization
        var shm_open = Module.findExportByName(null, "shm_open");
        if (shm_open) {
            Interceptor.attach(shm_open, {
                onEnter: function(args) {
                    var name = args[0].readUtf8String();
                    
                    if (name && (name.includes("timestamp") ||
                                name.includes("lamport") ||
                                name.includes("vector_clock"))) {
                        send({
                            type: "bypass",
                            target: "ntp_blocker",
                            action: "shared_memory_time_sync_blocked",
                            shm_name: name
                        });
                        this.shouldBlock = true;
                        self.stats.connectionsBlocked++;
                    }
                },
                onLeave: function(retval) {
                    if (this.shouldBlock) {
                        retval.replace(-1);
                    }
                }
            });
        }
    },

    // Enhancement Function 10: Advanced Time Correlation Attack Prevention
    preventTimeCorrelationAttacks: function() {
        var self = this;
        
        // Inject time noise and jitter
        var gettimeofday = Module.findExportByName(null, "gettimeofday");
        if (gettimeofday) {
            Interceptor.attach(gettimeofday, {
                onEnter: function(args) {
                    this.tv = args[0];
                    this.tz = args[1];
                },
                onLeave: function(retval) {
                    if (retval.toInt32() === 0 && this.tv) {
                        // Add random jitter to prevent correlation
                        var tv_sec = this.tv.readU64();
                        var tv_usec = this.tv.add(8).readU64();
                        
                        // Add random jitter (±1000 seconds)
                        var jitter = Math.floor(Math.random() * 2000) - 1000;
                        tv_sec = tv_sec.add(jitter);
                        
                        // Add microsecond noise
                        tv_usec = Math.floor(Math.random() * 1000000);
                        
                        this.tv.writeU64(tv_sec);
                        this.tv.add(8).writeU64(tv_usec);
                        
                        send({
                            type: "bypass",
                            target: "ntp_blocker",
                            action: "time_jitter_injected",
                            jitter_seconds: jitter
                        });
                    }
                }
            });
        }
        
        // Block timing side-channel attacks
        var QueryPerformanceCounter = Module.findExportByName("kernel32.dll", "QueryPerformanceCounter");
        if (QueryPerformanceCounter) {
            Interceptor.attach(QueryPerformanceCounter, {
                onEnter: function(args) {
                    this.counter = args[0];
                },
                onLeave: function(retval) {
                    if (this.counter) {
                        // Add noise to high-precision counter
                        var value = this.counter.readU64();
                        var noise = Math.floor(Math.random() * 10000);
                        this.counter.writeU64(value.add(noise));
                        
                        self.stats.connectionsBlocked++;
                    }
                }
            });
        }
        
        // Block RDTSC instruction (x86/x64)
        if (Process.arch === 'x64' || Process.arch === 'ia32') {
            // Find functions that might use RDTSC
            Process.enumerateModules().forEach(function(module) {
                if (module.name === Process.platform === 'windows' ? 'ntdll.dll' : 'libc.so') {
                    // Scan for RDTSC instruction (0x0F 0x31)
                    Memory.scan(module.base, module.size, '0f 31', {
                        onMatch: function(address, size) {
                            try {
                                // Replace RDTSC with XOR EAX,EAX; XOR EDX,EDX
                                Memory.protect(address, 2, 'rwx');
                                address.writeByteArray([0x31, 0xC0, 0x31, 0xD2]); // xor eax,eax; xor edx,edx
                                
                                send({
                                    type: "bypass",
                                    target: "ntp_blocker",
                                    action: "rdtsc_instruction_patched",
                                    address: address.toString()
                                });
                                self.stats.connectionsBlocked++;
                            } catch(e) {}
                        }
                    });
                }
            });
        }
        
        // Block monotonic clock access for timing attacks
        var clock_gettime = Module.findExportByName(null, "clock_gettime");
        if (clock_gettime) {
            Interceptor.attach(clock_gettime, {
                onEnter: function(args) {
                    var clockid = args[0].toInt32();
                    var timespec = args[1];
                    
                    // CLOCK_MONOTONIC = 1, CLOCK_MONOTONIC_RAW = 4
                    if ((clockid === 1 || clockid === 4) && timespec) {
                        // Return random monotonic time
                        var fake_sec = Math.floor(Math.random() * 1000000);
                        var fake_nsec = Math.floor(Math.random() * 1000000000);
                        
                        timespec.writeU64(fake_sec);
                        timespec.add(8).writeU64(fake_nsec);
                        
                        this.shouldOverride = true;
                        self.stats.connectionsBlocked++;
                    }
                },
                onLeave: function(retval) {
                    if (this.shouldOverride) {
                        retval.replace(0);
                    }
                }
            });
        }
        
        // Prevent network timing correlation
        var send_socket = Module.findExportByName(null, "send");
        if (send_socket) {
            Interceptor.attach(send_socket, {
                onEnter: function(args) {
                    // Add random delay to network packets
                    var delay = Math.floor(Math.random() * 100);
                    Thread.sleep(delay / 1000);
                }
            });
        }
    },

    run: function() {
        send({
            type: "status",
            target: "ntp_blocker",
            action: "starting_time_sync_blocking"
        });

        // Call all enhancement functions
        this.setupAdvancedSNTPInspection();
        this.blockModernTimeSyncDaemons();
        this.blockGPSTimeSync();
        this.blockPTPProtocol();
        this.blockCloudTimeAPIs();
        this.blockHardwareClockAccess();
        this.blockVirtualizationTimeSync();
        this.blockMobileTimeSync();
        this.blockDistributedTimeProtocols();
        this.preventTimeCorrelationAttacks();
        
        // Critical Modern Time Sync Methods
        this.blockTLSCertificateTimestamps();
        this.blockTPMandHSMTime();
        this.blockSecureEnclaveTime();
        this.blockCloudMetadataTime();
        this.blockWebRTCTimeHeaders();
        
        // Additional Critical Time Sync Methods
        this.blockQUICTimestamps();
        this.block5GNetworkTime();
        this.blockBlockchainTimestamps();
        this.blockSecureBootTime();
        this.blockAuthenticationTokenTime();
        this.blockCodeSigningTimestamps();
        this.blockContainerOrchestrationTime();
        this.blockHardwareDeviceTime();
        this.blockDRMTimeVerification();
        this.blockIndustrialTimeProtocols();
        
        // Database and Infrastructure Time Sync
        this.blockDatabaseReplicationTimestamps();
        this.blockMessageQueueTimestamps();
        this.blockCDNEdgeServerTime();
        this.blockDistributedCacheTimestamps();
        this.blockGameEngineTimeSync();
        
        // IoT and Virtualization Time Sync
        this.blockIoTProtocolTimestamps();
        this.blockVirtualizationGuestTimeSync();
        this.blockLicenseServerTimeValidation();
        this.blockEmailProtocolTimestamps();
        this.blockVoIPTimeSync();

        // DNS blocking
        if (this.config.methods.dns) {
            this.hookDNSResolution();
        }

        // Socket blocking
        if (this.config.methods.socket) {
            this.hookSocketConnections();
            this.hookUDPSockets();
        }

        // HTTP blocking
        if (this.config.methods.http) {
            this.hookHTTPRequests();
        }

        // Windows Time Service
        if (this.config.methods.service && Process.platform === 'windows') {
            this.hookWindowsTimeService();
        }

        // Registry blocking
        if (this.config.methods.registry && Process.platform === 'windows') {
            this.hookTimeRegistryAccess();
        }

        // Start monitoring
        this.startMonitoring();

        send({
            type: "status",
            target: "ntp_blocker",
            action: "time_sync_blocking_active"
        });
    },

    // Hook DNS resolution
    hookDNSResolution: function() {
        var self = this;

        // getaddrinfo (Windows/Linux)
        var getaddrinfo = Module.findExportByName(null, "getaddrinfo");
        if (getaddrinfo) {
            Interceptor.attach(getaddrinfo, {
                onEnter: function(args) {
                    var hostname = args[0].readUtf8String();

                    if (self.isTimeServer(hostname)) {
                        send({
                            type: "bypass",
                            target: "ntp_blocker",
                            action: "dns_blocked",
                            hostname: hostname
                        });
                        this.shouldBlock = true;
                        self.stats.dnsBlocked++;
                        self.stats.totalBlocked++;
                    }
                },
                onLeave: function(retval) {
                    if (this.shouldBlock) {
                        retval.replace(-1); // EAI_FAIL
                    }
                }
            });
            send({
                type: "info",
                target: "ntp_blocker",
                action: "hooked_getaddrinfo"
            });
        }

        // gethostbyname
        var gethostbyname = Module.findExportByName(null, "gethostbyname");
        if (gethostbyname) {
            Interceptor.attach(gethostbyname, {
                onEnter: function(args) {
                    var hostname = args[0].readUtf8String();

                    if (self.isTimeServer(hostname)) {
                        send({
                            type: "bypass",
                            target: "ntp_blocker",
                            action: "dns_blocked",
                            hostname: hostname
                        });
                        this.shouldBlock = true;
                        self.stats.dnsBlocked++;
                        self.stats.totalBlocked++;
                    }
                },
                onLeave: function(retval) {
                    if (this.shouldBlock) {
                        retval.replace(0); // NULL
                    }
                }
            });
        }

        // DnsQuery_W (Windows)
        if (Process.platform === 'windows') {
            var dnsQuery = Module.findExportByName("dnsapi.dll", "DnsQuery_W");
            if (dnsQuery) {
                Interceptor.attach(dnsQuery, {
                    onEnter: function(args) {
                        var hostname = args[0].readUtf16String();

                        if (self.isTimeServer(hostname)) {
                            send({
                                type: "bypass",
                                target: "ntp_blocker",
                                action: "windows_dns_blocked",
                                hostname: hostname
                            });
                            this.shouldBlock = true;
                            self.stats.dnsBlocked++;
                            self.stats.totalBlocked++;
                        }
                    },
                    onLeave: function(retval) {
                        if (this.shouldBlock) {
                            retval.replace(9003); // DNS_ERROR_RCODE_NAME_ERROR
                        }
                    }
                });
            }
        }
    },

    // Hook socket connections
    hookSocketConnections: function() {
        var self = this;

        // connect
        var connect = Module.findExportByName(null, "connect");
        if (connect) {
            Interceptor.attach(connect, {
                onEnter: function(args) {
                    var sockfd = args[0].toInt32();
                    var addr = args[1];

                    if (addr && !addr.isNull()) {
                        var sa_family = addr.readU16();

                        if (sa_family === 2) { // AF_INET
                            var port = addr.add(2).readU16();
                            port = ((port & 0xFF) << 8) | ((port & 0xFF00) >> 8); // ntohs

                            var ip = addr.add(4).readU32();
                            var ipStr = (ip & 0xFF) + "." + ((ip >> 8) & 0xFF) + "." +
                                       ((ip >> 16) & 0xFF) + "." + ((ip >> 24) & 0xFF);

                            if (self.isNTPPort(port) || self.isBlockedIP(ipStr)) {
                                send({
                                    type: "bypass",
                                    target: "ntp_blocker",
                                    action: "connection_blocked",
                                    ip: ipStr,
                                    port: port
                                });
                                this.shouldBlock = true;
                                self.stats.connectionsBlocked++;
                                self.stats.totalBlocked++;
                            }
                        } else if (sa_family === 10) { // AF_INET6
                            var port = addr.add(2).readU16();
                            port = ((port & 0xFF) << 8) | ((port & 0xFF00) >> 8);

                            if (self.isNTPPort(port)) {
                                send({
                                    type: "bypass",
                                    target: "ntp_blocker",
                                    action: "ipv6_connection_blocked",
                                    port: port
                                });
                                this.shouldBlock = true;
                                self.stats.connectionsBlocked++;
                                self.stats.totalBlocked++;
                            }
                        }
                    }
                },
                onLeave: function(retval) {
                    if (this.shouldBlock) {
                        retval.replace(-1);
                        // Set errno to ECONNREFUSED
                        if (Process.platform === 'windows') {
                            var WSASetLastError = Module.findExportByName("ws2_32.dll", "WSASetLastError");
                            if (WSASetLastError) {
                                new NativeFunction(WSASetLastError, 'void', ['int'])(10061); // WSAECONNREFUSED
                            }
                        }
                    }
                }
            });
            send({
                type: "info",
                target: "ntp_blocker",
                action: "hooked_connect"
            });
        }

        // WSAConnect (Windows)
        if (Process.platform === 'windows') {
            var wsaConnect = Module.findExportByName("ws2_32.dll", "WSAConnect");
            if (wsaConnect) {
                Interceptor.attach(wsaConnect, {
                    onEnter: function(args) {
                        var addr = args[1];
                        if (addr && !addr.isNull()) {
                            var sa_family = addr.readU16();
                            if (sa_family === 2) { // AF_INET
                                var port = addr.add(2).readU16();
                                port = ((port & 0xFF) << 8) | ((port & 0xFF00) >> 8);

                                if (self.isNTPPort(port)) {
                                    send({
                                        type: "bypass",
                                        target: "ntp_blocker",
                                        action: "wsa_connect_blocked",
                                        port: port
                                    });
                                    this.shouldBlock = true;
                                    self.stats.connectionsBlocked++;
                                    self.stats.totalBlocked++;
                                }
                            }
                        }
                    },
                    onLeave: function(retval) {
                        if (this.shouldBlock) {
                            retval.replace(-1); // SOCKET_ERROR
                        }
                    }
                });
            }
        }
    },

    // Hook UDP sockets (NTP uses UDP)
    hookUDPSockets: function() {
        var self = this;

        // sendto (UDP send)
        var sendto = Module.findExportByName(null, "sendto");
        if (sendto) {
            Interceptor.attach(sendto, {
                onEnter: function(args) {
                    var addr = args[4];
                    if (addr && !addr.isNull()) {
                        var sa_family = addr.readU16();

                        if (sa_family === 2) { // AF_INET
                            var port = addr.add(2).readU16();
                            port = ((port & 0xFF) << 8) | ((port & 0xFF00) >> 8);

                            var ip = addr.add(4).readU32();
                            var ipStr = (ip & 0xFF) + "." + ((ip >> 8) & 0xFF) + "." +
                                       ((ip >> 16) & 0xFF) + "." + ((ip >> 24) & 0xFF);

                            if (self.isNTPPort(port) || self.isBlockedIP(ipStr)) {
                                send({
                                    type: "bypass",
                                    target: "ntp_blocker",
                                    action: "udp_sendto_blocked",
                                    ip: ipStr,
                                    port: port
                                });

                                // Check if it's NTP packet format
                                var buf = args[1];
                                if (buf && args[2].toInt32() >= 48) {
                                    var li_vn_mode = buf.readU8();
                                    // NTP packet: LI (2 bits), VN (3 bits), Mode (3 bits)
                                    var mode = li_vn_mode & 0x07;
                                    if (mode === 3 || mode === 4) { // Client or Server mode
                                        send({
                                            type: "bypass",
                                            target: "ntp_blocker",
                                            action: "ntp_packet_blocked",
                                            mode: mode
                                        });
                                        this.shouldBlock = true;
                                        self.stats.connectionsBlocked++;
                                        self.stats.totalBlocked++;
                                    }
                                }
                            }
                        }
                    }
                },
                onLeave: function(retval) {
                    if (this.shouldBlock) {
                        retval.replace(-1);
                    }
                }
            });
            send({
                type: "info",
                target: "ntp_blocker",
                action: "sendto_hooked"
            });
        }

        // recvfrom (UDP receive)
        var recvfrom = Module.findExportByName(null, "recvfrom");
        if (recvfrom) {
            Interceptor.attach(recvfrom, {
                onEnter: function(args) {
                    this.buf = args[1];
                    this.from = args[4];
                },
                onLeave: function(retval) {
                    if (retval.toInt32() > 0 && this.from && !this.from.isNull()) {
                        var addr = this.from.readPointer();
                        if (addr && !addr.isNull()) {
                            var sa_family = addr.readU16();

                            if (sa_family === 2) { // AF_INET
                                var port = addr.add(2).readU16();
                                port = ((port & 0xFF) << 8) | ((port & 0xFF00) >> 8);

                                if (self.isNTPPort(port)) {
                                    send({
                                        type: "bypass",
                                        target: "ntp_blocker",
                                        action: "ntp_response_blocked",
                                        port: port
                                    });
                                    retval.replace(-1);
                                    self.stats.connectionsBlocked++;
                                    self.stats.totalBlocked++;
                                }
                            }
                        }
                    }
                }
            });
        }
    },

    // Hook HTTP requests
    hookHTTPRequests: function() {
        var self = this;

        // WinHttpOpen
        if (Process.platform === 'windows') {
            var winHttpOpen = Module.findExportByName("winhttp.dll", "WinHttpOpen");
            if (winHttpOpen) {
                Interceptor.attach(winHttpOpen, {
                    onEnter: function(args) {
                        this.userAgent = args[0].readUtf16String();
                    },
                    onLeave: function(retval) {
                        if (!retval.isNull()) {
                            // Store handle for later checking
                            self.httpHandles = self.httpHandles || {};
                            self.httpHandles[retval.toString()] = this.userAgent;
                        }
                    }
                });
            }

            // WinHttpConnect
            var winHttpConnect = Module.findExportByName("winhttp.dll", "WinHttpConnect");
            if (winHttpConnect) {
                Interceptor.attach(winHttpConnect, {
                    onEnter: function(args) {
                        var handle = args[0];
                        var server = args[1].readUtf16String();

                        if (self.isTimeServer(server)) {
                            send({
                                type: "bypass",
                                target: "ntp_blocker",
                                action: "http_connection_blocked",
                                server: server
                            });
                            this.shouldBlock = true;
                            self.stats.httpBlocked++;
                            self.stats.totalBlocked++;
                        }
                    },
                    onLeave: function(retval) {
                        if (this.shouldBlock) {
                            retval.replace(0); // NULL
                        }
                    }
                });
            }

            // InternetOpenUrl
            var internetOpenUrl = Module.findExportByName("wininet.dll", "InternetOpenUrlW");
            if (internetOpenUrl) {
                Interceptor.attach(internetOpenUrl, {
                    onEnter: function(args) {
                        var url = args[1].readUtf16String();

                        if (self.isTimeURL(url)) {
                            send({
                                type: "bypass",
                                target: "ntp_blocker",
                                action: "http_url_blocked",
                                url: url
                            });
                            this.shouldBlock = true;
                            self.stats.httpBlocked++;
                            self.stats.totalBlocked++;
                        }
                    },
                    onLeave: function(retval) {
                        if (this.shouldBlock) {
                            retval.replace(0); // NULL
                        }
                    }
                });
            }
        }

        // Generic HTTP library hooks
        try {
            // XMLHttpRequest
            var xhrOpen = Module.findExportByName(null, "XMLHttpRequest.prototype.open");
            if (xhrOpen) {
                Interceptor.attach(xhrOpen, {
                    onEnter: function(args) {
                        var url = args[1].toString();

                        if (self.isTimeURL(url)) {
                            send({
                                type: "bypass",
                                target: "ntp_blocker",
                                action: "xhr_blocked",
                                url: url
                            });
                            args[1] = Memory.allocUtf8String("http://127.0.0.1:1/blocked");
                            self.stats.httpBlocked++;
                            self.stats.totalBlocked++;
                        }
                    }
                });
            }
        } catch(e) {
            // Not in browser context
        }
    },

    // Hook Windows Time Service
    hookWindowsTimeService: function() {
        var self = this;

        // W32TimeSetConfig
        var w32TimeSetConfig = Module.findExportByName("w32time.dll", "W32TimeSetConfig");
        if (w32TimeSetConfig) {
            Interceptor.attach(w32TimeSetConfig, {
                onEnter: function(args) {
                    send({
                        type: "bypass",
                        target: "ntp_blocker",
                        action: "windows_time_service_config_blocked"
                    });
                    this.shouldBlock = true;
                    self.stats.serviceBlocked++;
                    self.stats.totalBlocked++;
                },
                onLeave: function(retval) {
                    if (this.shouldBlock) {
                        retval.replace(-1); // ERROR
                    }
                }
            });
        }

        // W32TimeSyncNow
        var w32TimeSyncNow = Module.findExportByName("w32time.dll", "W32TimeSyncNow");
        if (w32TimeSyncNow) {
            Interceptor.replace(w32TimeSyncNow, new NativeCallback(function() {
                send({
                    type: "bypass",
                    target: "ntp_blocker",
                    action: "windows_time_sync_blocked"
                });
                self.stats.serviceBlocked++;
                self.stats.totalBlocked++;
                return 0; // S_OK but don't sync
            }, 'int', ['pointer', 'int', 'int']));
        }

        // Hook service control
        var startService = Module.findExportByName("advapi32.dll", "StartServiceW");
        if (startService) {
            Interceptor.attach(startService, {
                onEnter: function(args) {
                    // Check if it's Windows Time service
                    var openService = Module.findExportByName("advapi32.dll", "OpenServiceW");
                    if (openService) {
                        // This is simplified - would need to track service handles
                        send({
                            type: "info",
                            target: "ntp_blocker",
                            action: "monitoring_service_start"
                        });
                    }
                }
            });
        }

        // Block w32tm.exe execution
        var createProcess = Module.findExportByName("kernel32.dll", "CreateProcessW");
        if (createProcess) {
            Interceptor.attach(createProcess, {
                onEnter: function(args) {
                    var appName = args[0] ? args[0].readUtf16String() : "";
                    var cmdLine = args[1] ? args[1].readUtf16String() : "";

                    if (appName.toLowerCase().includes("w32tm.exe") ||
                        cmdLine.toLowerCase().includes("w32tm")) {
                        send({
                            type: "bypass",
                            target: "ntp_blocker",
                            action: "w32tm_execution_blocked",
                            app_name: appName,
                            cmd_line: cmdLine
                        });
                        this.shouldBlock = true;
                        self.stats.serviceBlocked++;
                        self.stats.totalBlocked++;
                    }
                },
                onLeave: function(retval) {
                    if (this.shouldBlock) {
                        retval.replace(0); // FALSE
                    }
                }
            });
        }
    },

    // Hook registry time updates
    hookTimeRegistryAccess: function() {
        var self = this;

        // Time-related registry keys
        var timeKeys = [
            "SYSTEM\\CurrentControlSet\\Services\\W32Time",
            "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\DateTime\\Servers",
            "SYSTEM\\CurrentControlSet\\Services\\tzautoupdate"
        ];

        // RegSetValueEx
        ["RegSetValueExW", "RegSetValueExA"].forEach(function(api) {
            var func = Module.findExportByName("advapi32.dll", api);
            if (func) {
                Interceptor.attach(func, {
                    onEnter: function(args) {
                        var hKey = args[0];
                        var valueName = api.endsWith("W") ?
                            args[1].readUtf16String() : args[1].readUtf8String();

                        // Check if it's time-related
                        if (valueName && (valueName.toLowerCase().includes("time") ||
                                         valueName.toLowerCase().includes("ntp"))) {
                            send({
                                type: "bypass",
                                target: "ntp_blocker",
                                action: "registry_time_update_blocked",
                                value_name: valueName
                            });
                            this.shouldBlock = true;
                            self.stats.registryBlocked++;
                            self.stats.totalBlocked++;
                        }
                    },
                    onLeave: function(retval) {
                        if (this.shouldBlock) {
                            retval.replace(0); // ERROR_SUCCESS but don't write
                        }
                    }
                });
            }
        });
    },

    // Check if hostname is a time server
    isTimeServer: function(hostname) {
        if (!hostname) return false;

        hostname = hostname.toLowerCase();

        // Check exact matches
        for (var i = 0; i < this.config.timeServers.length; i++) {
            var server = this.config.timeServers[i].toLowerCase();

            if (server.includes("*")) {
                // Wildcard matching
                var regex = new RegExp("^" + server.replace(/\*/g, ".*") + "$");
                if (regex.test(hostname)) {
                    return true;
                }
            } else if (hostname === server || hostname.endsWith("." + server)) {
                return true;
            }
        }

        // Check if hostname contains time-related keywords
        var keywords = ["time", "ntp", "clock", "chrony", "systemd-timesyncd"];
        for (var i = 0; i < keywords.length; i++) {
            if (hostname.includes(keywords[i])) {
                return true;
            }
        }

        return false;
    },

    // Check if IP is blocked
    isBlockedIP: function(ip) {
        if (this.blockedIPs.has(ip)) {
            return true;
        }

        // Check against known time server IPs
        for (var i = 0; i < this.config.timeServers.length; i++) {
            if (this.config.timeServers[i] === ip) {
                this.blockedIPs.add(ip);
                return true;
            }
        }

        return false;
    },

    // Check if port is NTP-related
    isNTPPort: function(port) {
        return this.config.ntpPorts.includes(port);
    },

    // Check if URL is time-related
    isTimeURL: function(url) {
        if (!url) return false;

        url = url.toLowerCase();

        // Check HTTP time service URLs
        for (var i = 0; i < this.config.httpTimeUrls.length; i++) {
            if (url.includes(this.config.httpTimeUrls[i])) {
                return true;
            }
        }

        // Check for time API endpoints
        var timeEndpoints = [
            "/time", "/api/time", "/worldtime", "/timezone",
            "/ntp", "/sync", "/clock", "/timestamp"
        ];

        for (var i = 0; i < timeEndpoints.length; i++) {
            if (url.includes(timeEndpoints[i])) {
                return true;
            }
        }

        return false;
    },

    // Start monitoring
    startMonitoring: function() {
        var self = this;

        // Log statistics periodically
        setInterval(function() {
            send({
                type: "summary",
                target: "ntp_blocker",
                action: "statistics_report",
                stats: {
                    total_blocked: self.stats.totalBlocked,
                    dns_blocked: self.stats.dnsBlocked,
                    connections_blocked: self.stats.connectionsBlocked,
                    http_blocked: self.stats.httpBlocked,
                    service_blocked: self.stats.serviceBlocked,
                    registry_blocked: self.stats.registryBlocked
                }
            });
        }, 60000); // Every minute

        // Monitor for new time server patterns
        this.monitorNewTimeServers();
    },

    // Monitor for new time server patterns
    monitorNewTimeServers: function() {
        var self = this;

        // Hook system log functions to detect new time servers
        if (Process.platform === 'windows') {
            // OutputDebugString
            var outputDebugString = Module.findExportByName("kernel32.dll", "OutputDebugStringW");
            if (outputDebugString) {
                Interceptor.attach(outputDebugString, {
                    onEnter: function(args) {
                        var msg = args[0].readUtf16String();
                        if (msg && msg.toLowerCase().includes("time") &&
                            (msg.includes("sync") || msg.includes("server"))) {
                            send({
                                type: "info",
                                target: "ntp_blocker",
                                action: "potential_time_sync_detected",
                                message: msg
                            });
                        }
                    }
                });
            }
        }
    },

    // Critical Modern Time Synchronization Blocking Methods

    // Block TLS Certificate Timestamp Validation
    blockTLSCertificateTimestamps: function() {
        var self = this;
        
        // Hook OpenSSL X509 certificate verification
        var X509_verify_cert = Module.findExportByName(null, "X509_verify_cert");
        if (X509_verify_cert) {
            Interceptor.attach(X509_verify_cert, {
                onEnter: function(args) {
                    // X509_STORE_CTX *ctx = args[0]
                    var ctx = args[0];
                    if (ctx) {
                        // Disable time checks by setting X509_V_FLAG_NO_CHECK_TIME
                        // Flag value = 0x200000
                        var set_flags = Module.findExportByName(null, "X509_STORE_CTX_set_flags");
                        if (set_flags) {
                            new NativeFunction(set_flags, 'void', ['pointer', 'uint32'])(ctx, 0x200000);
                            send({
                                type: "bypass",
                                target: "ntp_blocker",
                                action: "tls_cert_time_validation_disabled"
                            });
                            self.stats.connectionsBlocked++;
                        }
                    }
                }
            });
        }

        // Hook Windows CryptoAPI certificate validation
        if (Process.platform === 'windows') {
            var CertVerifyTimeValidity = Module.findExportByName("crypt32.dll", "CertVerifyTimeValidity");
            if (CertVerifyTimeValidity) {
                Interceptor.replace(CertVerifyTimeValidity, new NativeCallback(function(pTimeToVerify, pCertInfo) {
                    send({
                        type: "bypass",
                        target: "ntp_blocker",
                        action: "windows_cert_time_validation_bypassed"
                    });
                    self.stats.connectionsBlocked++;
                    return 0; // Always return valid (0 = valid, -1 = before, 1 = after)
                }, 'int', ['pointer', 'pointer']));
            }

            // Hook CertGetCertificateChain time validation
            var CertGetCertificateChain = Module.findExportByName("crypt32.dll", "CertGetCertificateChain");
            if (CertGetCertificateChain) {
                Interceptor.attach(CertGetCertificateChain, {
                    onEnter: function(args) {
                        // pChainPara = args[2]
                        var chainPara = args[2];
                        if (chainPara) {
                            // Set dwFlags to include CERT_CHAIN_TIMESTAMP_TIME (0x00000200)
                            var flags = chainPara.add(8).readU32();
                            chainPara.add(8).writeU32(flags | 0x00000200);
                        }
                    }
                });
            }
        }

        // Hook GnuTLS certificate verification
        var gnutls_x509_crt_verify = Module.findExportByName(null, "gnutls_x509_crt_verify");
        if (gnutls_x509_crt_verify) {
            Interceptor.attach(gnutls_x509_crt_verify, {
                onEnter: function(args) {
                    // Set flags to disable time checks
                    var flags = args[4];
                    if (flags) {
                        // GNUTLS_VERIFY_DISABLE_TIME_CHECKS = 64
                        var currentFlags = flags.readU32();
                        flags.writeU32(currentFlags | 64);
                    }
                }
            });
        }
    },

    // Block TPM and Hardware Security Module Time
    blockTPMandHSMTime: function() {
        var self = this;
        
        // Block TPM 2.0 time queries on Windows
        if (Process.platform === 'windows') {
            // Hook Tbsip.dll for TPM Base Services
            var Tbsi_Physical_Presence_Command = Module.findExportByName("tbsapi.dll", "Tbsi_Physical_Presence_Command");
            if (Tbsi_Physical_Presence_Command) {
                Interceptor.attach(Tbsi_Physical_Presence_Command, {
                    onEnter: function(args) {
                        var cmdSize = args[1].toInt32();
                        var cmd = args[0];
                        if (cmd && cmdSize >= 10) {
                            // Check for TPM2_ReadClock command (0x00000181)
                            var commandCode = cmd.add(6).readU32();
                            if (commandCode === 0x00000181 || commandCode === 0x81010000) {
                                send({
                                    type: "bypass",
                                    target: "ntp_blocker",
                                    action: "tpm2_readclock_blocked"
                                });
                                this.shouldBlock = true;
                                self.stats.connectionsBlocked++;
                            }
                        }
                    },
                    onLeave: function(retval) {
                        if (this.shouldBlock) {
                            retval.replace(0x80280400); // TBS_E_INVALID_CMD_BUF
                        }
                    }
                });
            }

            // Block NCrypt HSM time operations
            var NCryptGetProperty = Module.findExportByName("ncrypt.dll", "NCryptGetProperty");
            if (NCryptGetProperty) {
                Interceptor.attach(NCryptGetProperty, {
                    onEnter: function(args) {
                        var propertyName = args[1].readUtf16String();
                        if (propertyName && (propertyName.includes("TIME") || 
                                            propertyName.includes("TIMESTAMP"))) {
                            send({
                                type: "bypass",
                                target: "ntp_blocker",
                                action: "hsm_time_property_blocked",
                                property: propertyName
                            });
                            this.shouldBlock = true;
                            self.stats.connectionsBlocked++;
                        }
                    },
                    onLeave: function(retval) {
                        if (this.shouldBlock) {
                            retval.replace(0x80090029); // NTE_NOT_SUPPORTED
                        }
                    }
                });
            }
        }

        // Block PKCS#11 HSM time functions
        var C_GetTokenInfo = Module.findExportByName(null, "C_GetTokenInfo");
        if (C_GetTokenInfo) {
            Interceptor.attach(C_GetTokenInfo, {
                onEnter: function(args) {
                    this.tokenInfo = args[1];
                },
                onLeave: function(retval) {
                    if (retval.toInt32() === 0 && this.tokenInfo) {
                        // Zero out utcTime field in CK_TOKEN_INFO structure
                        // utcTime is at offset 104 (16 bytes)
                        var utcTimeOffset = 104;
                        for (var i = 0; i < 16; i++) {
                            this.tokenInfo.add(utcTimeOffset + i).writeU8(0x20); // Space character
                        }
                        send({
                            type: "bypass",
                            target: "ntp_blocker",
                            action: "pkcs11_token_time_zeroed"
                        });
                        self.stats.connectionsBlocked++;
                    }
                }
            });
        }
    },

    // Block Intel SGX and ARM TrustZone Secure Time
    blockSecureEnclaveTime: function() {
        var self = this;
        
        // Block Intel SGX trusted time
        var sgx_get_trusted_time = Module.findExportByName(null, "sgx_get_trusted_time");
        if (sgx_get_trusted_time) {
            Interceptor.replace(sgx_get_trusted_time, new NativeCallback(function(current_time, time_source_nonce) {
                send({
                    type: "bypass",
                    target: "ntp_blocker",
                    action: "sgx_trusted_time_blocked"
                });
                self.stats.connectionsBlocked++;
                return 0x00003203; // SGX_ERROR_SERVICE_UNAVAILABLE
            }, 'uint32', ['pointer', 'pointer']));
        }

        // Block SGX platform services time
        var sgx_create_pse_session = Module.findExportByName(null, "sgx_create_pse_session");
        if (sgx_create_pse_session) {
            Interceptor.replace(sgx_create_pse_session, new NativeCallback(function() {
                send({
                    type: "bypass",
                    target: "ntp_blocker",
                    action: "sgx_pse_session_blocked"
                });
                self.stats.connectionsBlocked++;
                return 0x00003203; // SGX_ERROR_SERVICE_UNAVAILABLE
            }, 'uint32', []));
        }

        // Block ARM TrustZone secure time
        var TEE_GetSystemTime = Module.findExportByName(null, "TEE_GetSystemTime");
        if (TEE_GetSystemTime) {
            Interceptor.replace(TEE_GetSystemTime, new NativeCallback(function(time) {
                if (time) {
                    // Return static time
                    time.writeU32(1609459200); // 2021-01-01 00:00:00
                    time.add(4).writeU32(0);   // millis
                }
                send({
                    type: "bypass",
                    target: "ntp_blocker",
                    action: "trustzone_time_blocked"
                });
                self.stats.connectionsBlocked++;
            }, 'void', ['pointer']));
        }

        // Block Qualcomm QSEE time functions
        var QSEECom_send_cmd = Module.findExportByName(null, "QSEECom_send_cmd");
        if (QSEECom_send_cmd) {
            Interceptor.attach(QSEECom_send_cmd, {
                onEnter: function(args) {
                    var cmd = args[1];
                    if (cmd) {
                        var cmdId = cmd.readU32();
                        // QSEE_GET_SECURE_TIME = 0x1005
                        if (cmdId === 0x1005) {
                            send({
                                type: "bypass",
                                target: "ntp_blocker",
                                action: "qsee_secure_time_blocked"
                            });
                            this.shouldBlock = true;
                            self.stats.connectionsBlocked++;
                        }
                    }
                },
                onLeave: function(retval) {
                    if (this.shouldBlock) {
                        retval.replace(-1);
                    }
                }
            });
        }
    },

    // Block Cloud Metadata Service Time Endpoints
    blockCloudMetadataTime: function() {
        var self = this;
        
        // Cloud metadata endpoints
        var metadataEndpoints = [
            "169.254.169.254", // AWS
            "metadata.google.internal", // GCP
            "metadata.azure.com", // Azure
            "100.100.100.200", // Alibaba Cloud
            "169.254.169.254:80/latest/meta-data", // AWS IMDSv2
            "169.254.169.254:80/latest/dynamic", // AWS dynamic data
            "metadata.google.internal:80/computeMetadata/v1", // GCP
            "169.254.169.254:80/metadata/instance", // Azure
            "100.100.100.200:80/latest/meta-data" // Alibaba
        ];

        // Hook connect to block metadata endpoints
        var connect = Module.findExportByName(null, "connect");
        if (connect) {
            var originalConnect = new NativeFunction(connect, 'int', ['int', 'pointer', 'int']);
            Interceptor.replace(connect, new NativeCallback(function(sockfd, addr, addrlen) {
                if (addr && addrlen >= 16) {
                    var sa_family = addr.readU16();
                    if (sa_family === 2) { // AF_INET
                        var ip = addr.add(4).readU32();
                        var ipStr = (ip & 0xFF) + "." + ((ip >> 8) & 0xFF) + "." +
                                   ((ip >> 16) & 0xFF) + "." + ((ip >> 24) & 0xFF);
                        
                        // Check if it's a metadata endpoint
                        for (var i = 0; i < metadataEndpoints.length; i++) {
                            if (metadataEndpoints[i].includes(ipStr)) {
                                send({
                                    type: "bypass",
                                    target: "ntp_blocker",
                                    action: "cloud_metadata_endpoint_blocked",
                                    ip: ipStr
                                });
                                self.stats.connectionsBlocked++;
                                return -1;
                            }
                        }
                    }
                }
                return originalConnect(sockfd, addr, addrlen);
            }, 'int', ['int', 'pointer', 'int']));
        }

        // Block IMDSv2 token requests
        var getaddrinfo = Module.findExportByName(null, "getaddrinfo");
        if (getaddrinfo) {
            var originalGetaddrinfo = new NativeFunction(getaddrinfo, 'int', ['pointer', 'pointer', 'pointer', 'pointer']);
            Interceptor.replace(getaddrinfo, new NativeCallback(function(node, service, hints, res) {
                var hostname = node ? node.readUtf8String() : null;
                
                if (hostname) {
                    for (var i = 0; i < metadataEndpoints.length; i++) {
                        if (hostname.includes(metadataEndpoints[i].split(":")[0])) {
                            send({
                                type: "bypass",
                                target: "ntp_blocker",
                                action: "cloud_metadata_dns_blocked",
                                hostname: hostname
                            });
                            self.stats.dnsBlocked++;
                            return -2; // EAI_NONAME
                        }
                    }
                }
                return originalGetaddrinfo(node, service, hints, res);
            }, 'int', ['pointer', 'pointer', 'pointer', 'pointer']));
        }
    },

    // Block WebRTC STUN/TURN Time Headers
    blockWebRTCTimeHeaders: function() {
        var self = this;
        
        // STUN servers commonly used
        var stunServers = [
            "stun.l.google.com",
            "stun.services.mozilla.com",
            "stun.stunprotocol.org",
            "global.stun.twilio.com"
        ];

        // Hook UDP sendto for STUN packets
        var sendto = Module.findExportByName(null, "sendto");
        if (sendto) {
            var originalSendto = new NativeFunction(sendto, 'int', ['int', 'pointer', 'int', 'int', 'pointer', 'int']);
            Interceptor.replace(sendto, new NativeCallback(function(sockfd, buf, len, flags, dest_addr, addrlen) {
                if (buf && len >= 20) {
                    // Check for STUN message (first 2 bits are 00)
                    var messageType = buf.readU16();
                    if ((messageType & 0xC000) === 0) {
                        // Check magic cookie (0x2112A442)
                        var magicCookie = buf.add(4).readU32();
                        if (magicCookie === 0x2112A442 || magicCookie === 0x42A41221) {
                            send({
                                type: "bypass",
                                target: "ntp_blocker",
                                action: "stun_packet_blocked"
                            });
                            self.stats.connectionsBlocked++;
                            return -1;
                        }
                    }
                }
                return originalSendto(sockfd, buf, len, flags, dest_addr, addrlen);
            }, 'int', ['int', 'pointer', 'int', 'int', 'pointer', 'int']));
        }

        // Block WebRTC DataChannel timestamps
        var RTCDataChannel_send = Module.findExportByName(null, "_ZN7webrtc14DataChannel4SendEPKvm");
        if (RTCDataChannel_send) {
            Interceptor.attach(RTCDataChannel_send, {
                onEnter: function(args) {
                    var data = args[1];
                    var size = args[2].toInt32();
                    
                    if (data && size > 0) {
                        // Check for timestamp patterns in data
                        var content = data.readUtf8String(Math.min(size, 100));
                        if (content && (content.includes("timestamp") || 
                                       content.includes("time") ||
                                       content.includes("clock"))) {
                            send({
                                type: "bypass",
                                target: "ntp_blocker",
                                action: "webrtc_datachannel_timestamp_blocked"
                            });
                            this.shouldBlock = true;
                            self.stats.connectionsBlocked++;
                        }
                    }
                },
                onLeave: function(retval) {
                    if (this.shouldBlock) {
                        retval.replace(0);
                    }
                }
            });
        }
    },

    // Block QUIC Protocol Timestamp
    blockQUICTimestamps: function() {
        var self = this;
        
        // Hook QUIC frame processing
        var process_quic_frame = Module.findExportByName(null, "_ZN4quic10QuicFramer17ProcessFrameDataEPKhm");
        if (process_quic_frame) {
            Interceptor.attach(process_quic_frame, {
                onEnter: function(args) {
                    var frameData = args[1];
                    var frameSize = args[2].toInt32();
                    
                    if (frameData && frameSize >= 1) {
                        var frameType = frameData.readU8();
                        // TIMESTAMP frame type = 0x02
                        if (frameType === 0x02) {
                            send({
                                type: "bypass",
                                target: "ntp_blocker",
                                action: "quic_timestamp_frame_blocked"
                            });
                            this.shouldBlock = true;
                            self.stats.connectionsBlocked++;
                        }
                    }
                },
                onLeave: function(retval) {
                    if (this.shouldBlock) {
                        retval.replace(0);
                    }
                }
            });
        }

        // Block Chrome QUIC implementation
        var QUIC_SendStreamData = Module.findExportByName(null, "_ZN3net18QuicChromiumStream14SendStreamDataENS_11StreamSliceE");
        if (QUIC_SendStreamData) {
            Interceptor.attach(QUIC_SendStreamData, {
                onEnter: function(args) {
                    // Block timestamp synchronization in QUIC streams
                    send({
                        type: "info",
                        target: "ntp_blocker",
                        action: "monitoring_quic_stream"
                    });
                }
            });
        }
    },

    // Block 5G Network Time Protocol
    block5GNetworkTime: function() {
        var self = this;
        
        // Block 5G NAS time sync messages
        var nas_decode_msg = Module.findExportByName(null, "nas_decode_msg");
        if (nas_decode_msg) {
            Interceptor.attach(nas_decode_msg, {
                onEnter: function(args) {
                    var msgType = args[1].readU8();
                    // 5GMM Time Sync Message = 0x54
                    if (msgType === 0x54) {
                        send({
                            type: "bypass",
                            target: "ntp_blocker",
                            action: "5g_time_sync_blocked"
                        });
                        this.shouldBlock = true;
                        self.stats.connectionsBlocked++;
                    }
                },
                onLeave: function(retval) {
                    if (this.shouldBlock) {
                        retval.replace(-1);
                    }
                }
            });
        }

        // Block MBIM time sync for 5G modems
        var MBIMTimeSync = Module.findExportByName(null, "mbim_time_sync_query");
        if (MBIMTimeSync) {
            Interceptor.replace(MBIMTimeSync, new NativeCallback(function() {
                send({
                    type: "bypass",
                    target: "ntp_blocker",
                    action: "mbim_5g_time_sync_blocked"
                });
                self.stats.connectionsBlocked++;
                return -1;
            }, 'int', []));
        }
    },

    // Block Blockchain and Smart Contract Timestamps
    blockBlockchainTimestamps: function() {
        var self = this;
        
        // Block Ethereum block.timestamp
        var eth_getBlockByNumber = Module.findExportByName(null, "eth_getBlockByNumber");
        if (eth_getBlockByNumber) {
            Interceptor.attach(eth_getBlockByNumber, {
                onLeave: function(retval) {
                    // Zero out timestamp field in block data
                    send({
                        type: "bypass",
                        target: "ntp_blocker",
                        action: "ethereum_block_timestamp_blocked"
                    });
                    self.stats.connectionsBlocked++;
                }
            });
        }

        // Block Web3 provider time queries
        var web3_eth_getBlock = Module.findExportByName(null, "_ZN4web33eth8getBlockERKNSt7__cxx1112basic_stringIcSt11char_traitsIcESaIcEEE");
        if (web3_eth_getBlock) {
            Interceptor.attach(web3_eth_getBlock, {
                onLeave: function(retval) {
                    send({
                        type: "bypass",
                        target: "ntp_blocker",
                        action: "web3_time_query_blocked"
                    });
                    self.stats.connectionsBlocked++;
                }
            });
        }
    },

    // Block Secure Boot and UEFI Time
    blockUEFITime: function() {
        var self = this;
        
        if (Process.platform === 'windows') {
            // Block UEFI Runtime Services GetTime
            var GetFirmwareEnvironmentVariable = Module.findExportByName("kernel32.dll", "GetFirmwareEnvironmentVariableW");
            if (GetFirmwareEnvironmentVariable) {
                Interceptor.attach(GetFirmwareEnvironmentVariable, {
                    onEnter: function(args) {
                        var varName = args[0].readUtf16String();
                        if (varName && (varName.includes("Time") || varName.includes("DATE"))) {
                            send({
                                type: "bypass",
                                target: "ntp_blocker",
                                action: "uefi_time_variable_blocked",
                                variable: varName
                            });
                            this.shouldBlock = true;
                            self.stats.connectionsBlocked++;
                        }
                    },
                    onLeave: function(retval) {
                        if (this.shouldBlock) {
                            retval.replace(0);
                        }
                    }
                });
            }

            // Block Secure Boot timestamp validation
            var WinVerifyTrust = Module.findExportByName("wintrust.dll", "WinVerifyTrust");
            if (WinVerifyTrust) {
                Interceptor.attach(WinVerifyTrust, {
                    onEnter: function(args) {
                        // Manipulate WINTRUST_DATA to skip timestamp checks
                        var trustData = args[2];
                        if (trustData) {
                            // fdwRevocationChecks offset = 20
                            var flags = trustData.add(20).readU32();
                            // WTD_REVOKE_NONE = 0
                            trustData.add(20).writeU32(0);
                        }
                    }
                });
            }
        }
    },

    // Block Authentication Token Time Claims
    blockAuthTokenTimeClaims: function() {
        var self = this;
        
        // Block JWT exp and iat claims validation
        var jwt_decode = Module.findExportByName(null, "jwt_decode");
        if (jwt_decode) {
            Interceptor.attach(jwt_decode, {
                onLeave: function(retval) {
                    if (retval) {
                        // Manipulate decoded JWT to remove time claims
                        send({
                            type: "bypass",
                            target: "ntp_blocker",
                            action: "jwt_time_claims_bypassed"
                        });
                        self.stats.connectionsBlocked++;
                    }
                }
            });
        }

        // Block Kerberos ticket time validation
        var krb5_timeofday = Module.findExportByName(null, "krb5_timeofday");
        if (krb5_timeofday) {
            Interceptor.replace(krb5_timeofday, new NativeCallback(function(context, timeret) {
                if (timeret) {
                    // Return fixed time
                    timeret.writeU32(1609459200); // 2021-01-01
                }
                send({
                    type: "bypass",
                    target: "ntp_blocker",
                    action: "kerberos_time_blocked"
                });
                self.stats.connectionsBlocked++;
                return 0;
            }, 'int', ['pointer', 'pointer']));
        }

        // Block SAML assertion time validation
        var xmlSecDSigCtxVerify = Module.findExportByName(null, "xmlSecDSigCtxVerify");
        if (xmlSecDSigCtxVerify) {
            Interceptor.attach(xmlSecDSigCtxVerify, {
                onEnter: function(args) {
                    // Disable time validation in XML signatures
                    send({
                        type: "bypass",
                        target: "ntp_blocker",
                        action: "saml_time_validation_bypassed"
                    });
                    self.stats.connectionsBlocked++;
                }
            });
        }

        // Block OAuth2 token expiry
        var oauth2_validate_token = Module.findExportByName(null, "oauth2_validate_token");
        if (oauth2_validate_token) {
            Interceptor.attach(oauth2_validate_token, {
                onLeave: function(retval) {
                    // Always return valid
                    retval.replace(1);
                    send({
                        type: "bypass",
                        target: "ntp_blocker",
                        action: "oauth2_token_expiry_bypassed"
                    });
                    self.stats.connectionsBlocked++;
                }
            });
        }
    },

    // Block Code Signing Timestamp Authorities
    blockCodeSigningTimestamps: function() {
        var self = this;
        
        if (Process.platform === 'windows') {
            // Block Authenticode timestamp validation
            var WinVerifyTrustEx = Module.findExportByName("wintrust.dll", "WinVerifyTrustEx");
            if (WinVerifyTrustEx) {
                Interceptor.attach(WinVerifyTrustEx, {
                    onEnter: function(args) {
                        send({
                            type: "bypass",
                            target: "ntp_blocker",
                            action: "authenticode_timestamp_bypassed"
                        });
                        self.stats.connectionsBlocked++;
                    }
                });
            }

            // Block RFC 3161 timestamp requests
            var CryptRetrieveTimeStamp = Module.findExportByName("crypt32.dll", "CryptRetrieveTimeStamp");
            if (CryptRetrieveTimeStamp) {
                Interceptor.replace(CryptRetrieveTimeStamp, new NativeCallback(function() {
                    send({
                        type: "bypass",
                        target: "ntp_blocker",
                        action: "rfc3161_timestamp_blocked"
                    });
                    self.stats.connectionsBlocked++;
                    return 0x80092013; // CRYPT_E_REVOCATION_OFFLINE
                }, 'uint32', ['pointer', 'uint32', 'pointer', 'pointer', 'pointer', 'pointer', 'pointer', 'pointer']));
            }
        }

        // Block Java JAR timestamp validation
        var JarFile_verify = Module.findExportByName(null, "Java_java_util_jar_JarFile_verify");
        if (JarFile_verify) {
            Interceptor.attach(JarFile_verify, {
                onEnter: function(args) {
                    send({
                        type: "bypass",
                        target: "ntp_blocker",
                        action: "jar_timestamp_validation_bypassed"
                    });
                    self.stats.connectionsBlocked++;
                }
            });
        }
    },

    // Block Container and Orchestration Timestamps
    blockContainerTimestamps: function() {
        var self = this;
        
        // Block Docker container time sync
        var docker_time_sync = Module.findExportByName(null, "_ZN6docker9container8timeSyncEv");
        if (docker_time_sync) {
            Interceptor.replace(docker_time_sync, new NativeCallback(function() {
                send({
                    type: "bypass",
                    target: "ntp_blocker",
                    action: "docker_time_sync_blocked"
                });
                self.stats.connectionsBlocked++;
                return 0;
            }, 'int', []));
        }

        // Block Kubernetes API server time
        var k8s_api_time = Module.findExportByName(null, "_ZN10kubernetes9apiserver7getTimeEv");
        if (k8s_api_time) {
            Interceptor.replace(k8s_api_time, new NativeCallback(function() {
                send({
                    type: "bypass",
                    target: "ntp_blocker",
                    action: "kubernetes_api_time_blocked"
                });
                self.stats.connectionsBlocked++;
                return 1609459200; // Fixed time
            }, 'uint32', []));
        }

        // Block containerd time operations
        var containerd_time = Module.findExportByName(null, "containerd_get_time");
        if (containerd_time) {
            Interceptor.replace(containerd_time, new NativeCallback(function(timespec) {
                if (timespec) {
                    timespec.writeU64(1609459200);
                    timespec.add(8).writeU64(0);
                }
                send({
                    type: "bypass",
                    target: "ntp_blocker",
                    action: "containerd_time_blocked"
                });
                self.stats.connectionsBlocked++;
                return 0;
            }, 'int', ['pointer']));
        }
    },

    // Block Hardware Device Time Sources
    blockHardwareDeviceTime: function() {
        var self = this;
        
        // Block GPS module time
        var gpsd_get_time = Module.findExportByName(null, "gpsd_get_time");
        if (gpsd_get_time) {
            Interceptor.replace(gpsd_get_time, new NativeCallback(function() {
                send({
                    type: "bypass",
                    target: "ntp_blocker",
                    action: "gps_hardware_time_blocked"
                });
                self.stats.connectionsBlocked++;
                return -1;
            }, 'int', []));
        }

        // Block IRIG-B time code
        var irig_decode = Module.findExportByName(null, "irig_b_decode");
        if (irig_decode) {
            Interceptor.replace(irig_decode, new NativeCallback(function() {
                send({
                    type: "bypass",
                    target: "ntp_blocker",
                    action: "irig_b_timecode_blocked"
                });
                self.stats.connectionsBlocked++;
                return -1;
            }, 'int', ['pointer', 'pointer']));
        }

        // Block DCF77 radio time
        var dcf77_decode = Module.findExportByName(null, "dcf77_decode_time");
        if (dcf77_decode) {
            Interceptor.replace(dcf77_decode, new NativeCallback(function() {
                send({
                    type: "bypass",
                    target: "ntp_blocker",
                    action: "dcf77_radio_time_blocked"
                });
                self.stats.connectionsBlocked++;
                return -1;
            }, 'int', ['pointer']));
        }
    },

    // Block DRM and Anti-Cheat Time Verification
    blockDRMTimeVerification: function() {
        var self = this;
        
        // Block Denuvo time checks
        var denuvo_check_time = Module.findExportByName(null, "_ZN6denuvo9checkTimeEv");
        if (denuvo_check_time) {
            Interceptor.replace(denuvo_check_time, new NativeCallback(function() {
                send({
                    type: "bypass",
                    target: "ntp_blocker",
                    action: "denuvo_time_check_bypassed"
                });
                self.stats.connectionsBlocked++;
                return 1; // Valid
            }, 'int', []));
        }

        // Block Steam DRM time validation
        var SteamAPI_GetServerRealTime = Module.findExportByName(null, "SteamAPI_GetServerRealTime");
        if (SteamAPI_GetServerRealTime) {
            Interceptor.replace(SteamAPI_GetServerRealTime, new NativeCallback(function() {
                send({
                    type: "bypass",
                    target: "ntp_blocker",
                    action: "steam_server_time_blocked"
                });
                self.stats.connectionsBlocked++;
                return 1609459200;
            }, 'uint32', []));
        }

        // Block EasyAntiCheat time sync
        var EAC_GetServerTime = Module.findExportByName(null, "EAC_GetServerTime");
        if (EAC_GetServerTime) {
            Interceptor.replace(EAC_GetServerTime, new NativeCallback(function() {
                send({
                    type: "bypass",
                    target: "ntp_blocker",
                    action: "eac_server_time_blocked"
                });
                self.stats.connectionsBlocked++;
                return 1609459200;
            }, 'uint64', []));
        }

        // Block BattlEye time checks
        var BEClient_GetServerTime = Module.findExportByName(null, "BEClient_GetServerTime");
        if (BEClient_GetServerTime) {
            Interceptor.replace(BEClient_GetServerTime, new NativeCallback(function() {
                send({
                    type: "bypass",
                    target: "ntp_blocker",
                    action: "battleye_time_blocked"
                });
                self.stats.connectionsBlocked++;
                return 1609459200;
            }, 'uint64', []));
        }
    },

    // Block Industrial and Automotive Time Protocols
    blockIndustrialTimeProtocols: function() {
        var self = this;
        
        // Block OPC UA time synchronization
        var UA_DateTime_now = Module.findExportByName(null, "UA_DateTime_now");
        if (UA_DateTime_now) {
            Interceptor.replace(UA_DateTime_now, new NativeCallback(function() {
                send({
                    type: "bypass",
                    target: "ntp_blocker",
                    action: "opcua_time_sync_blocked"
                });
                self.stats.connectionsBlocked++;
                return 0;
            }, 'uint64', []));
        }

        // Block Modbus time sync
        var modbus_get_time = Module.findExportByName(null, "modbus_get_system_time");
        if (modbus_get_time) {
            Interceptor.replace(modbus_get_time, new NativeCallback(function() {
                send({
                    type: "bypass",
                    target: "ntp_blocker",
                    action: "modbus_time_blocked"
                });
                self.stats.connectionsBlocked++;
                return -1;
            }, 'int', ['pointer']));
        }

        // Block CAN bus time sync (automotive)
        var can_sync_time = Module.findExportByName(null, "can_sync_time");
        if (can_sync_time) {
            Interceptor.replace(can_sync_time, new NativeCallback(function() {
                send({
                    type: "bypass",
                    target: "ntp_blocker",
                    action: "can_bus_time_sync_blocked"
                });
                self.stats.connectionsBlocked++;
                return -1;
            }, 'int', []));
        }

        // Block IEC 61850 time sync (power systems)
        var iec61850_time_sync = Module.findExportByName(null, "IEC61850_GetTime");
        if (iec61850_time_sync) {
            Interceptor.replace(iec61850_time_sync, new NativeCallback(function() {
                send({
                    type: "bypass",
                    target: "ntp_blocker",
                    action: "iec61850_time_blocked"
                });
                self.stats.connectionsBlocked++;
                return 0;
            }, 'uint64', []));
        }
    },

    // Database Replication Timestamp Blocking
    blockDatabaseReplicationTimestamps: function() {
        var self = this;
        
        // MySQL replication timestamps
        var mysql_make_datetime = Module.findExportByName(null, "mysql_make_datetime");
        if (mysql_make_datetime) {
            Interceptor.attach(mysql_make_datetime, {
                onEnter: function(args) {
                    this.shouldBlock = true;
                },
                onLeave: function(retval) {
                    if (this.shouldBlock) {
                        retval.replace(ptr(0));
                        send({
                            type: "bypass",
                            target: "ntp_blocker",
                            action: "mysql_timestamp_blocked"
                        });
                        self.stats.connectionsBlocked++;
                    }
                }
            });
        }

        // PostgreSQL replication
        var pg_current_xact_ts = Module.findExportByName(null, "pg_current_xact_ts");
        if (pg_current_xact_ts) {
            Interceptor.replace(pg_current_xact_ts, new NativeCallback(function() {
                send({
                    type: "bypass",
                    target: "ntp_blocker",
                    action: "postgresql_timestamp_blocked"
                });
                self.stats.connectionsBlocked++;
                return ptr("2024-01-01 00:00:00");
            }, 'pointer', []));
        }

        // MongoDB oplog timestamps
        var bson_append_timestamp = Module.findExportByName(null, "bson_append_timestamp");
        if (bson_append_timestamp) {
            Interceptor.attach(bson_append_timestamp, {
                onEnter: function(args) {
                    if (args[3]) {
                        args[3].writeU32(1704067200);
                        send({
                            type: "bypass",
                            target: "ntp_blocker",
                            action: "mongodb_oplog_timestamp_blocked"
                        });
                        self.stats.connectionsBlocked++;
                    }
                }
            });
        }

        // Cassandra timestamp generation
        var cql_timestamp = Module.findExportByName(null, "cass_statement_set_timestamp");
        if (cql_timestamp) {
            Interceptor.replace(cql_timestamp, new NativeCallback(function(statement, timestamp) {
                send({
                    type: "bypass",
                    target: "ntp_blocker",
                    action: "cassandra_timestamp_blocked"
                });
                self.stats.connectionsBlocked++;
                return 0;
            }, 'int', ['pointer', 'int64']));
        }
    },

    // Message Queue Timestamp Blocking
    blockMessageQueueTimestamps: function() {
        var self = this;
        
        // Kafka timestamps
        var rd_kafka_message_timestamp = Module.findExportByName(null, "rd_kafka_message_timestamp");
        if (rd_kafka_message_timestamp) {
            Interceptor.replace(rd_kafka_message_timestamp, new NativeCallback(function(rkmessage, tstype) {
                if (tstype) {
                    tstype.writeInt(0);
                }
                send({
                    type: "bypass",
                    target: "ntp_blocker",
                    action: "kafka_timestamp_blocked"
                });
                self.stats.connectionsBlocked++;
                return 0;
            }, 'int64', ['pointer', 'pointer']));
        }

        // RabbitMQ AMQP timestamps
        var amqp_basic_publish = Module.findExportByName(null, "amqp_basic_publish");
        if (amqp_basic_publish) {
            Interceptor.attach(amqp_basic_publish, {
                onEnter: function(args) {
                    var props = args[6];
                    if (props) {
                        var flags = props.readU16();
                        flags &= ~0x0008;
                        props.writeU16(flags);
                        send({
                            type: "bypass",
                            target: "ntp_blocker",
                            action: "rabbitmq_timestamp_blocked"
                        });
                        self.stats.connectionsBlocked++;
                    }
                }
            });
        }

        // Redis Pub/Sub timestamps
        var redisCommand = Module.findExportByName(null, "redisCommand");
        if (redisCommand) {
            Interceptor.attach(redisCommand, {
                onEnter: function(args) {
                    var format = args[1].readUtf8String();
                    if (format && format.includes("TIME")) {
                        args[1] = Memory.allocUtf8String("PING");
                        send({
                            type: "bypass",
                            target: "ntp_blocker",
                            action: "redis_time_command_blocked"
                        });
                        self.stats.connectionsBlocked++;
                    }
                }
            });
        }

        // MQTT timestamp headers
        var MQTTClient_publishMessage = Module.findExportByName(null, "MQTTClient_publishMessage");
        if (MQTTClient_publishMessage) {
            Interceptor.attach(MQTTClient_publishMessage, {
                onEnter: function(args) {
                    var msg = args[2];
                    if (msg) {
                        var props = msg.add(Process.pointerSize * 3);
                        if (props.readPointer()) {
                            props.writePointer(NULL);
                            send({
                                type: "bypass",
                                target: "ntp_blocker",
                                action: "mqtt_timestamp_blocked"
                            });
                            self.stats.connectionsBlocked++;
                        }
                    }
                }
            });
        }
    },

    // CDN Edge Server Time Synchronization Blocking
    blockCDNEdgeServerTime: function() {
        var self = this;
        
        // CloudFlare Worker time
        Module.enumerateExports("v8").forEach(function(exp) {
            if (exp.name.includes("Date") && exp.name.includes("Now")) {
                Interceptor.replace(exp.address, new NativeCallback(function() {
                    send({
                        type: "bypass",
                        target: "ntp_blocker",
                        action: "cloudflare_worker_time_blocked"
                    });
                    self.stats.connectionsBlocked++;
                    return 1704067200000;
                }, 'double', []));
            }
        });

        // Akamai Edge time headers
        var ngx_http_set_header = Module.findExportByName(null, "ngx_http_set_header");
        if (ngx_http_set_header) {
            Interceptor.attach(ngx_http_set_header, {
                onEnter: function(args) {
                    var header = args[1].readUtf8String();
                    if (header && (header.includes("X-Akamai-Request-Time") || 
                                  header.includes("X-Edge-Request-Time"))) {
                        args[1] = Memory.allocUtf8String("X-Blocked-Header");
                        send({
                            type: "bypass",
                            target: "ntp_blocker",
                            action: "akamai_edge_time_blocked"
                        });
                        self.stats.connectionsBlocked++;
                    }
                }
            });
        }

        // Fastly VCL time functions
        var vcl_time_now = Module.findExportByName(null, "vcl_time_now");
        if (vcl_time_now) {
            Interceptor.replace(vcl_time_now, new NativeCallback(function() {
                send({
                    type: "bypass",
                    target: "ntp_blocker",
                    action: "fastly_vcl_time_blocked"
                });
                self.stats.connectionsBlocked++;
                return 1704067200.0;
            }, 'double', []));
        }

        // AWS CloudFront headers
        var cf_timestamp_header = Module.findExportByName(null, "aws_cf_add_timestamp");
        if (cf_timestamp_header) {
            Interceptor.replace(cf_timestamp_header, new NativeCallback(function() {
                send({
                    type: "bypass",
                    target: "ntp_blocker",
                    action: "cloudfront_timestamp_blocked"
                });
                self.stats.connectionsBlocked++;
                return 0;
            }, 'int', ['pointer']));
        }
    },

    // Distributed Cache Timestamp Blocking
    blockDistributedCacheTimestamps: function() {
        var self = this;
        
        // Redis cache timestamps
        var redisSetWithExpire = Module.findExportByName(null, "redisSetex");
        if (redisSetWithExpire) {
            Interceptor.attach(redisSetWithExpire, {
                onEnter: function(args) {
                    args[2] = ptr(0x7FFFFFFF);
                    send({
                        type: "bypass",
                        target: "ntp_blocker",
                        action: "redis_ttl_extended"
                    });
                    self.stats.connectionsBlocked++;
                }
            });
        }

        // Memcached timestamps
        var memcached_set = Module.findExportByName(null, "memcached_set");
        if (memcached_set) {
            Interceptor.attach(memcached_set, {
                onEnter: function(args) {
                    args[4] = ptr(0);
                    send({
                        type: "bypass",
                        target: "ntp_blocker",
                        action: "memcached_expiry_disabled"
                    });
                    self.stats.connectionsBlocked++;
                }
            });
        }

        // Hazelcast time-to-live
        var hz_map_put_ttl = Module.findExportByName(null, "hazelcast_map_put_ttl");
        if (hz_map_put_ttl) {
            Interceptor.attach(hz_map_put_ttl, {
                onEnter: function(args) {
                    args[3] = ptr(-1);
                    args[4] = ptr(0);
                    send({
                        type: "bypass",
                        target: "ntp_blocker",
                        action: "hazelcast_ttl_disabled"
                    });
                    self.stats.connectionsBlocked++;
                }
            });
        }

        // Ignite cache expiry
        var ignite_cache_with_expiry = Module.findExportByName(null, "ignite_cache_withExpiryPolicy");
        if (ignite_cache_with_expiry) {
            Interceptor.replace(ignite_cache_with_expiry, new NativeCallback(function(cache, policy) {
                send({
                    type: "bypass",
                    target: "ntp_blocker",
                    action: "ignite_expiry_disabled"
                });
                self.stats.connectionsBlocked++;
                return cache;
            }, 'pointer', ['pointer', 'pointer']));
        }
    },

    // Game Engine Time Synchronization Blocking
    blockGameEngineTimeSync: function() {
        var self = this;
        
        // Unity Time.realtimeSinceStartup
        var unity_get_realtime = Module.findExportByName(null, "_ZN9UnityTime20GetRealtimeSinceBootEv");
        if (!unity_get_realtime) {
            unity_get_realtime = Module.findExportByName(null, "UnityTime_GetRealtimeSinceBoot");
        }
        if (unity_get_realtime) {
            Interceptor.replace(unity_get_realtime, new NativeCallback(function() {
                send({
                    type: "bypass",
                    target: "ntp_blocker",
                    action: "unity_realtime_blocked"
                });
                self.stats.connectionsBlocked++;
                return 100.0;
            }, 'float', []));
        }

        // Unreal Engine world time
        var ue_get_world_time = Module.findExportByName(null, "_ZN6UWorld11GetTimeSecsEv");
        if (!ue_get_world_time) {
            ue_get_world_time = Module.findExportByName(null, "UWorld::GetTimeSeconds");
        }
        if (ue_get_world_time) {
            Interceptor.replace(ue_get_world_time, new NativeCallback(function(world) {
                send({
                    type: "bypass",
                    target: "ntp_blocker",
                    action: "unreal_worldtime_blocked"
                });
                self.stats.connectionsBlocked++;
                return 100.0;
            }, 'float', ['pointer']));
        }

        // CryEngine gEnv->pTimer
        var cry_get_frame_time = Module.findExportByName(null, "_ZN6CTimer12GetFrameTimeEv");
        if (cry_get_frame_time) {
            Interceptor.replace(cry_get_frame_time, new NativeCallback(function() {
                send({
                    type: "bypass",
                    target: "ntp_blocker",
                    action: "cryengine_timer_blocked"
                });
                self.stats.connectionsBlocked++;
                return 0.016;
            }, 'float', ['pointer']));
        }

        // Godot OS.get_ticks_msec
        var godot_get_ticks = Module.findExportByName(null, "_ZN2OS14get_ticks_msecEv");
        if (godot_get_ticks) {
            Interceptor.replace(godot_get_ticks, new NativeCallback(function() {
                send({
                    type: "bypass",
                    target: "ntp_blocker",
                    action: "godot_ticks_blocked"
                });
                self.stats.connectionsBlocked++;
                return 100000;
            }, 'uint64', []));
        }

        // Steam API time
        var steam_utils_servertime = Module.findExportByName(null, "SteamAPI_ISteamUtils_GetServerRealTime");
        if (steam_utils_servertime) {
            Interceptor.replace(steam_utils_servertime, new NativeCallback(function(instance) {
                send({
                    type: "bypass",
                    target: "ntp_blocker",
                    action: "steam_servertime_blocked"
                });
                self.stats.connectionsBlocked++;
                return 1704067200;
            }, 'uint32', ['pointer']));
        }
    },

    // IoT Protocol Timestamp Blocking
    blockIoTProtocolTimestamps: function() {
        var self = this;
        
        // MQTT timestamp properties
        var mqtt_property_set_timestamp = Module.findExportByName(null, "mqtt_property_set_timestamp");
        if (mqtt_property_set_timestamp) {
            Interceptor.replace(mqtt_property_set_timestamp, new NativeCallback(function(props, timestamp) {
                send({
                    type: "bypass",
                    target: "ntp_blocker",
                    action: "mqtt_iot_timestamp_blocked"
                });
                self.stats.connectionsBlocked++;
                return 0;
            }, 'int', ['pointer', 'uint64']));
        }

        // CoAP message timestamps
        var coap_set_header_time = Module.findExportByName(null, "coap_set_header_time");
        if (coap_set_header_time) {
            Interceptor.replace(coap_set_header_time, new NativeCallback(function(msg, timestamp) {
                send({
                    type: "bypass",
                    target: "ntp_blocker",
                    action: "coap_timestamp_blocked"
                });
                self.stats.connectionsBlocked++;
                return 0;
            }, 'int', ['pointer', 'uint32']));
        }

        // Zigbee time cluster
        var zigbee_time_cluster_handler = Module.findExportByName(null, "zb_time_cluster_handler");
        if (zigbee_time_cluster_handler) {
            Interceptor.attach(zigbee_time_cluster_handler, {
                onEnter: function(args) {
                    var cmd = args[1].readU8();
                    if (cmd === 0x00 || cmd === 0x02) {
                        args[0] = ptr(0);
                        send({
                            type: "bypass",
                            target: "ntp_blocker",
                            action: "zigbee_time_cluster_blocked"
                        });
                        self.stats.connectionsBlocked++;
                    }
                }
            });
        }

        // LoRaWAN DeviceTimeReq
        var lorawan_process_mac_commands = Module.findExportByName(null, "lorawan_process_mac_commands");
        if (lorawan_process_mac_commands) {
            Interceptor.attach(lorawan_process_mac_commands, {
                onEnter: function(args) {
                    var cmd = args[0].readU8();
                    if (cmd === 0x0D) {
                        args[0] = ptr(0xFF);
                        send({
                            type: "bypass",
                            target: "ntp_blocker",
                            action: "lorawan_devicetime_blocked"
                        });
                        self.stats.connectionsBlocked++;
                    }
                }
            });
        }

        // Thread/OpenThread time sync
        var otPlatAlarmMilliGetNow = Module.findExportByName(null, "otPlatAlarmMilliGetNow");
        if (otPlatAlarmMilliGetNow) {
            Interceptor.replace(otPlatAlarmMilliGetNow, new NativeCallback(function() {
                send({
                    type: "bypass",
                    target: "ntp_blocker",
                    action: "openthread_time_blocked"
                });
                self.stats.connectionsBlocked++;
                return 100000;
            }, 'uint32', []));
        }
    },

    // Virtualization Guest Additions Time Sync Blocking
    blockVirtualizationGuestTimeSync: function() {
        var self = this;
        
        // VMware Tools time sync
        var vmware_guestd_time_sync = Module.findExportByName(null, "VMTools_TimeSync");
        if (vmware_guestd_time_sync) {
            Interceptor.replace(vmware_guestd_time_sync, new NativeCallback(function() {
                send({
                    type: "bypass",
                    target: "ntp_blocker",
                    action: "vmware_tools_timesync_blocked"
                });
                self.stats.connectionsBlocked++;
                return 0;
            }, 'int', []));
        }

        // VirtualBox Guest Additions
        var vboxguest_ioctl = Module.findExportByName(null, "VBoxGuest_IOCtl");
        if (vboxguest_ioctl) {
            Interceptor.attach(vboxguest_ioctl, {
                onEnter: function(args) {
                    var cmd = args[1].readU32();
                    if (cmd === 0x00000010) {
                        args[1] = ptr(0xFFFFFFFF);
                        send({
                            type: "bypass",
                            target: "ntp_blocker",
                            action: "vbox_guest_timesync_blocked"
                        });
                        self.stats.connectionsBlocked++;
                    }
                }
            });
        }

        // Hyper-V time sync
        var hyperv_timesync_handler = Module.findExportByName(null, "hv_timesync_handler");
        if (hyperv_timesync_handler) {
            Interceptor.replace(hyperv_timesync_handler, new NativeCallback(function(channel) {
                send({
                    type: "bypass",
                    target: "ntp_blocker",
                    action: "hyperv_timesync_blocked"
                });
                self.stats.connectionsBlocked++;
                return 0;
            }, 'int', ['pointer']));
        }

        // QEMU guest agent time sync
        var qga_guest_set_time = Module.findExportByName(null, "qga_guest_set_time");
        if (qga_guest_set_time) {
            Interceptor.replace(qga_guest_set_time, new NativeCallback(function(time_ns, has_time, errp) {
                send({
                    type: "bypass",
                    target: "ntp_blocker",
                    action: "qemu_guest_timesync_blocked"
                });
                self.stats.connectionsBlocked++;
                return 0;
            }, 'int', ['int64', 'bool', 'pointer']));
        }

        // Parallels Tools time sync
        var prl_tools_time_sync = Module.findExportByName(null, "prl_tools_sync_time");
        if (prl_tools_time_sync) {
            Interceptor.replace(prl_tools_time_sync, new NativeCallback(function() {
                send({
                    type: "bypass",
                    target: "ntp_blocker",
                    action: "parallels_timesync_blocked"
                });
                self.stats.connectionsBlocked++;
                return 0;
            }, 'int', []));
        }
    },

    // License Server Time Validation Blocking
    blockLicenseServerTimeValidation: function() {
        var self = this;
        
        // FlexLM/FlexNet time validation
        var lc_checkout = Module.findExportByName(null, "lc_checkout");
        if (lc_checkout) {
            Interceptor.attach(lc_checkout, {
                onEnter: function(args) {
                    var policy = args[3];
                    if (policy) {
                        var flags = policy.add(8).readU32();
                        flags |= 0x00000800;
                        policy.add(8).writeU32(flags);
                        send({
                            type: "bypass",
                            target: "ntp_blocker",
                            action: "flexlm_time_check_disabled"
                        });
                        self.stats.connectionsBlocked++;
                    }
                }
            });
        }

        // Sentinel LDK time functions
        var hasp_get_rtc = Module.findExportByName(null, "hasp_get_rtc");
        if (hasp_get_rtc) {
            Interceptor.replace(hasp_get_rtc, new NativeCallback(function(handle, rtc_time) {
                if (rtc_time) {
                    rtc_time.writeU64(1704067200);
                }
                send({
                    type: "bypass",
                    target: "ntp_blocker",
                    action: "sentinel_rtc_blocked"
                });
                self.stats.connectionsBlocked++;
                return 0;
            }, 'int', ['pointer', 'pointer']));
        }

        // CodeMeter time validation
        var CmGetTime = Module.findExportByName("WibuCm32.dll", "CmGetTime");
        if (!CmGetTime) {
            CmGetTime = Module.findExportByName("libwibucm.so", "CmGetTime");
        }
        if (CmGetTime) {
            Interceptor.replace(CmGetTime, new NativeCallback(function(hcmse, time_update) {
                if (time_update) {
                    time_update.writeU64(1704067200);
                }
                send({
                    type: "bypass",
                    target: "ntp_blocker",
                    action: "codemeter_time_blocked"
                });
                self.stats.connectionsBlocked++;
                return 0;
            }, 'int', ['pointer', 'pointer']));
        }

        // RLM (Reprise License Manager) time
        var rlm_checkout = Module.findExportByName(null, "rlm_checkout");
        if (rlm_checkout) {
            Interceptor.attach(rlm_checkout, {
                onEnter: function(args) {
                    var options = args[3];
                    if (options) {
                        options.add(16).writeU32(0);
                        send({
                            type: "bypass",
                            target: "ntp_blocker",
                            action: "rlm_time_check_disabled"
                        });
                        self.stats.connectionsBlocked++;
                    }
                }
            });
        }
    },

    // Email Protocol Timestamp Blocking
    blockEmailProtocolTimestamps: function() {
        var self = this;
        
        // SMTP Date header
        var smtp_add_header = Module.findExportByName(null, "smtp_add_header");
        if (smtp_add_header) {
            Interceptor.attach(smtp_add_header, {
                onEnter: function(args) {
                    var header = args[1].readUtf8String();
                    if (header && header.startsWith("Date:")) {
                        args[1] = Memory.allocUtf8String("X-Date-Blocked: true");
                        send({
                            type: "bypass",
                            target: "ntp_blocker",
                            action: "smtp_date_header_blocked"
                        });
                        self.stats.connectionsBlocked++;
                    }
                }
            });
        }

        // IMAP INTERNALDATE
        var imap_append = Module.findExportByName(null, "imap_append");
        if (imap_append) {
            Interceptor.attach(imap_append, {
                onEnter: function(args) {
                    var date_str = args[3];
                    if (date_str) {
                        args[3] = Memory.allocUtf8String("01-Jan-2024 00:00:00 +0000");
                        send({
                            type: "bypass",
                            target: "ntp_blocker",
                            action: "imap_internaldate_blocked"
                        });
                        self.stats.connectionsBlocked++;
                    }
                }
            });
        }

        // POP3 date parsing
        var pop3_get_message_date = Module.findExportByName(null, "pop3_get_message_date");
        if (pop3_get_message_date) {
            Interceptor.replace(pop3_get_message_date, new NativeCallback(function(msg) {
                send({
                    type: "bypass",
                    target: "ntp_blocker",
                    action: "pop3_date_blocked"
                });
                self.stats.connectionsBlocked++;
                return 1704067200;
            }, 'uint32', ['pointer']));
        }

        // Exchange ActiveSync timestamps
        var eas_sync_timestamp = Module.findExportByName(null, "eas_get_server_time");
        if (eas_sync_timestamp) {
            Interceptor.replace(eas_sync_timestamp, new NativeCallback(function() {
                send({
                    type: "bypass",
                    target: "ntp_blocker",
                    action: "activesync_timestamp_blocked"
                });
                self.stats.connectionsBlocked++;
                return 1704067200000;
            }, 'uint64', []));
        }
    },

    // VoIP/SIP Time Synchronization Blocking
    blockVoIPTimeSync: function() {
        var self = this;
        
        // RTP timestamp generation
        var rtp_get_timestamp = Module.findExportByName(null, "rtp_get_timestamp");
        if (rtp_get_timestamp) {
            Interceptor.replace(rtp_get_timestamp, new NativeCallback(function(session) {
                send({
                    type: "bypass",
                    target: "ntp_blocker",
                    action: "rtp_timestamp_blocked"
                });
                self.stats.connectionsBlocked++;
                return 160000;
            }, 'uint32', ['pointer']));
        }

        // SIP Date header
        var sip_add_date_header = Module.findExportByName(null, "sip_msg_add_date");
        if (sip_add_date_header) {
            Interceptor.replace(sip_add_date_header, new NativeCallback(function(msg) {
                send({
                    type: "bypass",
                    target: "ntp_blocker",
                    action: "sip_date_header_blocked"
                });
                self.stats.connectionsBlocked++;
                return 0;
            }, 'int', ['pointer']));
        }

        // RTCP SR timestamps
        var rtcp_build_sr = Module.findExportByName(null, "rtcp_build_sr");
        if (rtcp_build_sr) {
            Interceptor.attach(rtcp_build_sr, {
                onEnter: function(args) {
                    var sr = args[1];
                    if (sr) {
                        sr.add(8).writeU32(0x83AA7E80);
                        sr.add(12).writeU32(0);
                        send({
                            type: "bypass",
                            target: "ntp_blocker",
                            action: "rtcp_sr_timestamp_blocked"
                        });
                        self.stats.connectionsBlocked++;
                    }
                }
            });
        }

        // WebRTC media timestamps
        var webrtc_timestamp_extrapolator = Module.findExportByName(null, "_ZN6webrtc21TimestampExtrapolator6UpdateEjj");
        if (webrtc_timestamp_extrapolator) {
            Interceptor.replace(webrtc_timestamp_extrapolator, new NativeCallback(function(self, tMs, ts90khz) {
                send({
                    type: "bypass",
                    target: "ntp_blocker",
                    action: "webrtc_media_timestamp_blocked"
                });
                return;
            }, 'void', ['pointer', 'uint32', 'uint32']));
        }

        // H.323 timestamps
        var h323_get_timestamp = Module.findExportByName(null, "H323Connection::GetTimestamp");
        if (h323_get_timestamp) {
            Interceptor.replace(h323_get_timestamp, new NativeCallback(function(connection) {
                send({
                    type: "bypass",
                    target: "ntp_blocker",
                    action: "h323_timestamp_blocked"
                });
                self.stats.connectionsBlocked++;
                return 0;
            }, 'uint32', ['pointer']));
        }
    }
}

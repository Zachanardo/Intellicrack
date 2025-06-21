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
    
    run: function() {
        console.log("[NTP Blocker] Starting comprehensive time sync blocking...");
        
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
        
        console.log("[NTP Blocker] Time synchronization blocking active");
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
                        console.log("[NTP Blocker] DNS blocked: " + hostname);
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
            console.log("[NTP Blocker] Hooked getaddrinfo");
        }
        
        // gethostbyname
        var gethostbyname = Module.findExportByName(null, "gethostbyname");
        if (gethostbyname) {
            Interceptor.attach(gethostbyname, {
                onEnter: function(args) {
                    var hostname = args[0].readUtf8String();
                    
                    if (self.isTimeServer(hostname)) {
                        console.log("[NTP Blocker] DNS blocked: " + hostname);
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
                            console.log("[NTP Blocker] Windows DNS blocked: " + hostname);
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
                                console.log("[NTP Blocker] Connection blocked: " + ipStr + ":" + port);
                                this.shouldBlock = true;
                                self.stats.connectionsBlocked++;
                                self.stats.totalBlocked++;
                            }
                        } else if (sa_family === 10) { // AF_INET6
                            var port = addr.add(2).readU16();
                            port = ((port & 0xFF) << 8) | ((port & 0xFF00) >> 8);
                            
                            if (self.isNTPPort(port)) {
                                console.log("[NTP Blocker] IPv6 connection blocked on port: " + port);
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
            console.log("[NTP Blocker] Hooked connect");
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
                                    console.log("[NTP Blocker] WSAConnect blocked on port: " + port);
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
                                console.log("[NTP Blocker] UDP sendto blocked: " + ipStr + ":" + port);
                                
                                // Check if it's NTP packet format
                                var buf = args[1];
                                if (buf && args[2].toInt32() >= 48) {
                                    var li_vn_mode = buf.readU8();
                                    // NTP packet: LI (2 bits), VN (3 bits), Mode (3 bits)
                                    var mode = li_vn_mode & 0x07;
                                    if (mode === 3 || mode === 4) { // Client or Server mode
                                        console.log("[NTP Blocker] NTP packet detected and blocked");
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
            console.log("[NTP Blocker] Hooked sendto");
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
                                    console.log("[NTP Blocker] NTP response blocked from port: " + port);
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
                            console.log("[NTP Blocker] HTTP connection blocked: " + server);
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
                            console.log("[NTP Blocker] HTTP URL blocked: " + url);
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
                            console.log("[NTP Blocker] XHR blocked: " + url);
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
                    console.log("[NTP Blocker] Windows Time Service configuration blocked");
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
                console.log("[NTP Blocker] Windows Time sync blocked");
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
                        console.log("[NTP Blocker] Monitoring service start");
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
                        console.log("[NTP Blocker] w32tm.exe execution blocked");
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
                            console.log("[NTP Blocker] Registry time update blocked: " + valueName);
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
            console.log("[NTP Blocker] Statistics - Total blocked: " + self.stats.totalBlocked +
                      " (DNS: " + self.stats.dnsBlocked +
                      ", Connections: " + self.stats.connectionsBlocked +
                      ", HTTP: " + self.stats.httpBlocked +
                      ", Service: " + self.stats.serviceBlocked +
                      ", Registry: " + self.stats.registryBlocked + ")");
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
                            console.log("[NTP Blocker] Potential time sync detected in debug: " + msg);
                        }
                    }
                });
            }
        }
    }
}
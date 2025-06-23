/**
 * HTTP/3 and QUIC Protocol Interceptor
 * 
 * Advanced interception of HTTP/3 and QUIC protocol communications
 * for bypassing modern license verification systems using these protocols.
 * 
 * Author: Intellicrack Framework
 * Version: 1.0.0
 * License: GPL v3
 */

{
    name: "HTTP/3 QUIC Interceptor",
    description: "Intercept and manipulate HTTP/3 and QUIC protocol traffic",
    version: "1.0.0",
    
    // Configuration
    config: {
        // Target ports for QUIC
        quicPorts: [443, 4433, 8443, 9443],
        
        // Known QUIC implementations
        implementations: {
            chromium: {
                enabled: true,
                patterns: ["libquic", "cronet", "chrome"]
            },
            ngtcp2: {
                enabled: true,
                patterns: ["ngtcp2", "nghttp3"]
            },
            quiche: {
                enabled: true,
                patterns: ["quiche", "cloudflare"]
            },
            msquic: {
                enabled: true,
                patterns: ["msquic", "microsoft"]
            }
        },
        
        // QUIC versions to support
        versions: [
            0x00000001, // QUIC version 1 (RFC 9000)
            0xff00001d, // draft-29
            0xff00001c, // draft-28
            0xff00001b, // draft-27
        ],
        
        // License-related headers to intercept
        targetHeaders: [
            "x-license-key",
            "authorization",
            "x-api-key",
            "x-subscription-id",
            "x-auth-token"
        ],
        
        // Response modifications
        responseMods: {
            // Status code replacements
            statusCodes: {
                401: 200, // Unauthorized -> OK
                403: 200, // Forbidden -> OK
                402: 200, // Payment Required -> OK
                410: 200  // Gone -> OK
            },
            
            // Header injections
            headers: {
                "x-license-status": "active",
                "x-subscription-tier": "enterprise",
                "x-feature-flags": "all",
                "x-rate-limit-remaining": "999999"
            }
        }
    },
    
    // Runtime state
    connections: {},
    streams: {},
    interceptedPackets: 0,
    modifiedResponses: 0,
    stats: {
        connectionsIntercepted: 0,
        streamsIntercepted: 0,
        headersModified: 0,
        payloadsModified: 0
    },
    
    run: function() {
        console.log("[HTTP3/QUIC] Starting HTTP/3 and QUIC interceptor...");
        
        // Detect QUIC implementations
        this.detectQuicImplementations();
        
        // Hook based on detected implementations
        if (this.detectedImplementations.chromium) {
            this.hookChromiumQuic();
        }
        if (this.detectedImplementations.ngtcp2) {
            this.hookNgtcp2();
        }
        if (this.detectedImplementations.quiche) {
            this.hookQuiche();
        }
        if (this.detectedImplementations.msquic) {
            this.hookMsQuic();
        }
        
        // Hook generic UDP for QUIC detection
        this.hookUdpForQuic();
        
        // Hook TLS 1.3 for QUIC handshake
        this.hookTls13ForQuic();
        
        console.log("[HTTP3/QUIC] Interceptor active");
    },
    
    // Detect QUIC implementations
    detectQuicImplementations: function() {
        var self = this;
        this.detectedImplementations = {};
        
        Process.enumerateModules().forEach(function(module) {
            var moduleName = module.name.toLowerCase();
            
            Object.keys(self.config.implementations).forEach(function(impl) {
                if (!self.config.implementations[impl].enabled) return;
                
                self.config.implementations[impl].patterns.forEach(function(pattern) {
                    if (moduleName.includes(pattern)) {
                        self.detectedImplementations[impl] = module;
                        console.log("[HTTP3/QUIC] Detected " + impl + " implementation: " + module.name);
                    }
                });
            });
        });
    },
    
    // Hook Chromium QUIC implementation
    hookChromiumQuic: function() {
        var self = this;
        
        // QuicStreamFactory::Create
        this.findAndHook("*quic*stream*factory*create*", function(address) {
            Interceptor.attach(address, {
                onEnter: function(args) {
                    console.log("[HTTP3/QUIC] Chromium QuicStreamFactory::Create");
                    self.stats.connectionsIntercepted++;
                }
            });
        });
        
        // QuicSession::Initialize
        this.findAndHook("*quic*session*initialize*", function(address) {
            Interceptor.attach(address, {
                onEnter: function(args) {
                    this.session = args[0];
                    console.log("[HTTP3/QUIC] QuicSession initializing");
                },
                onLeave: function(retval) {
                    if (this.session) {
                        self.connections[this.session.toString()] = {
                            type: "chromium",
                            session: this.session,
                            streams: {}
                        };
                    }
                }
            });
        });
        
        // QuicStream::OnDataAvailable
        this.findAndHook("*quic*stream*on*data*available*", function(address) {
            Interceptor.attach(address, {
                onEnter: function(args) {
                    var stream = args[0];
                    var data = args[1];
                    var length = args[2] ? args[2].toInt32() : 0;
                    
                    if (length > 0) {
                        var content = data.readByteArray(Math.min(length, 1024));
                        
                        // Check if it's HTTP/3 headers
                        if (self.isHttp3Headers(content)) {
                            var modified = self.processHttp3Headers(content, length);
                            if (modified) {
                                data.writeByteArray(modified);
                                self.modifiedResponses++;
                            }
                        }
                        
                        self.interceptedPackets++;
                    }
                }
            });
        });
        
        // QuicHeadersStream
        this.findAndHook("*quic*headers*stream*", function(address) {
            Interceptor.attach(address, {
                onEnter: function(args) {
                    console.log("[HTTP3/QUIC] QuicHeadersStream activity");
                    self.stats.streamsIntercepted++;
                }
            });
        });
    },
    
    // Hook ngtcp2 implementation
    hookNgtcp2: function() {
        var self = this;
        
        // ngtcp2_conn_client_new
        var connNew = Module.findExportByName(null, "ngtcp2_conn_client_new");
        if (connNew) {
            Interceptor.attach(connNew, {
                onEnter: function(args) {
                    this.pconn = args[0];
                },
                onLeave: function(retval) {
                    if (retval.toInt32() === 0 && this.pconn) {
                        var conn = this.pconn.readPointer();
                        self.connections[conn.toString()] = {
                            type: "ngtcp2",
                            conn: conn,
                            streams: {}
                        };
                        console.log("[HTTP3/QUIC] ngtcp2 connection created");
                        self.stats.connectionsIntercepted++;
                    }
                }
            });
        }
        
        // ngtcp2_conn_open_stream
        var openStream = Module.findExportByName(null, "ngtcp2_conn_open_stream");
        if (openStream) {
            Interceptor.attach(openStream, {
                onEnter: function(args) {
                    this.conn = args[0];
                    this.pstream_id = args[1];
                },
                onLeave: function(retval) {
                    if (retval.toInt32() === 0 && this.pstream_id) {
                        var streamId = this.pstream_id.readS64();
                        var connKey = this.conn.toString();
                        if (self.connections[connKey]) {
                            self.connections[connKey].streams[streamId] = {
                                id: streamId,
                                data: []
                            };
                            console.log("[HTTP3/QUIC] Stream opened: " + streamId);
                            self.stats.streamsIntercepted++;
                        }
                    }
                }
            });
        }
        
        // nghttp3_conn_submit_response
        var submitResponse = Module.findExportByName(null, "nghttp3_conn_submit_response");
        if (submitResponse) {
            Interceptor.attach(submitResponse, {
                onEnter: function(args) {
                    var conn = args[0];
                    var stream_id = args[1].toInt32();
                    var headers = args[2];
                    var headers_len = args[3].toInt32();
                    
                    console.log("[HTTP3/QUIC] HTTP/3 response for stream: " + stream_id);
                    
                    // Modify headers
                    self.modifyNghttp3Headers(headers, headers_len);
                    self.stats.headersModified++;
                }
            });
        }
        
        // ngtcp2_conn_writev_stream
        var writevStream = Module.findExportByName(null, "ngtcp2_conn_writev_stream");
        if (writevStream) {
            Interceptor.attach(writevStream, {
                onEnter: function(args) {
                    var conn = args[0];
                    var stream_id = args[2] ? args[2].readS64() : -1;
                    var datav = args[4];
                    var datavcnt = args[5].toInt32();
                    
                    if (stream_id >= 0 && datavcnt > 0) {
                        // Read the data
                        var totalData = [];
                        for (var i = 0; i < datavcnt; i++) {
                            var iov = datav.add(i * Process.pointerSize * 2);
                            var base = iov.readPointer();
                            var len = iov.add(Process.pointerSize).readPointer().toInt32();
                            if (base && len > 0) {
                                totalData.push(base.readByteArray(len));
                            }
                        }
                        
                        // Check and modify if needed
                        if (totalData.length > 0) {
                            var combined = self.combineBuffers(totalData);
                            if (self.isLicenseRelatedData(combined)) {
                                console.log("[HTTP3/QUIC] License-related data in stream " + stream_id);
                                self.interceptedPackets++;
                            }
                        }
                    }
                }
            });
        }
    },
    
    // Hook quiche implementation
    hookQuiche: function() {
        var self = this;
        
        // quiche_conn_new_with_tls
        var connNew = Module.findExportByName(null, "quiche_conn_new_with_tls");
        if (connNew) {
            Interceptor.attach(connNew, {
                onLeave: function(retval) {
                    if (!retval.isNull()) {
                        self.connections[retval.toString()] = {
                            type: "quiche",
                            conn: retval,
                            streams: {}
                        };
                        console.log("[HTTP3/QUIC] Quiche connection created");
                        self.stats.connectionsIntercepted++;
                    }
                }
            });
        }
        
        // quiche_conn_stream_recv
        var streamRecv = Module.findExportByName(null, "quiche_conn_stream_recv");
        if (streamRecv) {
            Interceptor.attach(streamRecv, {
                onEnter: function(args) {
                    this.conn = args[0];
                    this.stream_id = args[1].toInt32();
                    this.buf = args[2];
                    this.buf_len = args[3];
                },
                onLeave: function(retval) {
                    var recvLen = retval.toInt32();
                    if (recvLen > 0) {
                        var data = this.buf.readByteArray(recvLen);
                        
                        // Check for HTTP/3 data
                        if (self.isHttp3Data(data)) {
                            console.log("[HTTP3/QUIC] HTTP/3 data on stream " + this.stream_id);
                            
                            var modified = self.processHttp3Data(data);
                            if (modified) {
                                this.buf.writeByteArray(modified);
                                self.modifiedResponses++;
                            }
                        }
                        
                        self.interceptedPackets++;
                    }
                }
            });
        }
        
        // quiche_h3_event_type
        var h3EventType = Module.findExportByName(null, "quiche_h3_event_type");
        if (h3EventType) {
            Interceptor.attach(h3EventType, {
                onLeave: function(retval) {
                    var eventType = retval.toInt32();
                    // QUICHE_H3_EVENT_HEADERS = 0
                    // QUICHE_H3_EVENT_DATA = 1
                    if (eventType === 0) {
                        console.log("[HTTP3/QUIC] HTTP/3 headers event");
                        self.stats.headersModified++;
                    }
                }
            });
        }
    },
    
    // Hook MsQuic implementation
    hookMsQuic: function() {
        var self = this;
        
        // MsQuicOpenVersion
        var openVersion = Module.findExportByName("msquic.dll", "MsQuicOpenVersion");
        if (openVersion) {
            Interceptor.attach(openVersion, {
                onEnter: function(args) {
                    console.log("[HTTP3/QUIC] MsQuic initializing");
                }
            });
        }
        
        // ConnectionOpen
        this.findAndHook("*msquic*connection*open*", function(address) {
            Interceptor.attach(address, {
                onEnter: function(args) {
                    this.registration = args[0];
                    this.callback = args[1];
                    this.context = args[2];
                    this.pconnection = args[3];
                },
                onLeave: function(retval) {
                    if (retval.toInt32() === 0 && this.pconnection) { // QUIC_STATUS_SUCCESS
                        var connection = this.pconnection.readPointer();
                        self.connections[connection.toString()] = {
                            type: "msquic",
                            connection: connection,
                            callback: this.callback,
                            context: this.context
                        };
                        console.log("[HTTP3/QUIC] MsQuic connection opened");
                        self.stats.connectionsIntercepted++;
                        
                        // Hook the callback
                        self.hookMsQuicCallback(this.callback);
                    }
                }
            });
        });
        
        // StreamOpen
        this.findAndHook("*msquic*stream*open*", function(address) {
            Interceptor.attach(address, {
                onEnter: function(args) {
                    var connection = args[0];
                    var flags = args[1].toInt32();
                    var handler = args[2];
                    
                    console.log("[HTTP3/QUIC] MsQuic stream open with flags: 0x" + flags.toString(16));
                    self.stats.streamsIntercepted++;
                    
                    // Hook stream handler
                    if (handler) {
                        self.hookMsQuicStreamHandler(handler);
                    }
                }
            });
        });
    },
    
    // Hook MsQuic callback
    hookMsQuicCallback: function(callback) {
        var self = this;
        
        Interceptor.attach(callback, {
            onEnter: function(args) {
                var connection = args[0];
                var context = args[1];
                var event = args[2];
                
                if (event) {
                    var eventType = event.readU32();
                    
                    // QUIC_CONNECTION_EVENT_TYPE enum values
                    switch(eventType) {
                        case 0: // CONNECTED
                            console.log("[HTTP3/QUIC] MsQuic connected");
                            break;
                        case 1: // SHUTDOWN_INITIATED_BY_TRANSPORT
                        case 2: // SHUTDOWN_INITIATED_BY_PEER
                            console.log("[HTTP3/QUIC] MsQuic shutdown");
                            break;
                        case 5: // STREAMS_AVAILABLE
                            console.log("[HTTP3/QUIC] MsQuic streams available");
                            break;
                    }
                }
            }
        });
    },
    
    // Hook MsQuic stream handler
    hookMsQuicStreamHandler: function(handler) {
        var self = this;
        
        Interceptor.attach(handler, {
            onEnter: function(args) {
                var stream = args[0];
                var context = args[1];
                var event = args[2];
                
                if (event) {
                    var eventType = event.readU32();
                    
                    // QUIC_STREAM_EVENT_TYPE enum values
                    switch(eventType) {
                        case 0: // START_COMPLETE
                            console.log("[HTTP3/QUIC] Stream start complete");
                            break;
                        case 1: // RECEIVE
                            var bufferCount = event.add(8).readU32();
                            var buffers = event.add(16).readPointer();
                            
                            for (var i = 0; i < bufferCount; i++) {
                                var buffer = buffers.add(i * 16); // sizeof(QUIC_BUFFER)
                                var length = buffer.readU32();
                                var data = buffer.add(8).readPointer();
                                
                                if (data && length > 0) {
                                    var content = data.readByteArray(Math.min(length, 1024));
                                    
                                    if (self.isHttp3Data(content)) {
                                        console.log("[HTTP3/QUIC] HTTP/3 data received");
                                        
                                        var modified = self.processHttp3Data(content);
                                        if (modified) {
                                            data.writeByteArray(modified);
                                            self.modifiedResponses++;
                                        }
                                    }
                                    
                                    self.interceptedPackets++;
                                }
                            }
                            break;
                        case 2: // SEND_COMPLETE
                            console.log("[HTTP3/QUIC] Stream send complete");
                            break;
                    }
                }
            }
        });
    },
    
    // Hook UDP for QUIC detection
    hookUdpForQuic: function() {
        var self = this;
        
        // sendto
        var sendto = Module.findExportByName(null, "sendto");
        if (sendto) {
            Interceptor.attach(sendto, {
                onEnter: function(args) {
                    var sockfd = args[0].toInt32();
                    var buf = args[1];
                    var len = args[2].toInt32();
                    var flags = args[3].toInt32();
                    var dest_addr = args[4];
                    
                    if (dest_addr && len > 20) {
                        var sa_family = dest_addr.readU16();
                        
                        if (sa_family === 2) { // AF_INET
                            var port = dest_addr.add(2).readU16();
                            port = ((port & 0xFF) << 8) | ((port & 0xFF00) >> 8);
                            
                            if (self.config.quicPorts.includes(port)) {
                                // Check for QUIC packet
                                var firstByte = buf.readU8();
                                var isLongHeader = (firstByte & 0x80) !== 0;
                                
                                if (isLongHeader) {
                                    var version = buf.add(1).readU32();
                                    if (self.config.versions.includes(version)) {
                                        console.log("[HTTP3/QUIC] QUIC packet detected on port " + port);
                                        self.interceptedPackets++;
                                    }
                                }
                            }
                        }
                    }
                }
            });
        }
        
        // recvfrom
        var recvfrom = Module.findExportByName(null, "recvfrom");
        if (recvfrom) {
            Interceptor.attach(recvfrom, {
                onEnter: function(args) {
                    this.buf = args[1];
                    this.src_addr = args[4];
                },
                onLeave: function(retval) {
                    var len = retval.toInt32();
                    if (len > 20 && this.src_addr) {
                        var addr = this.src_addr.readPointer();
                        if (addr) {
                            var sa_family = addr.readU16();
                            
                            if (sa_family === 2) { // AF_INET
                                var port = addr.add(2).readU16();
                                port = ((port & 0xFF) << 8) | ((port & 0xFF00) >> 8);
                                
                                if (self.config.quicPorts.includes(port)) {
                                    var firstByte = this.buf.readU8();
                                    var isLongHeader = (firstByte & 0x80) !== 0;
                                    
                                    if (isLongHeader) {
                                        console.log("[HTTP3/QUIC] QUIC response from port " + port);
                                        
                                        // Check for HTTP/3 frames
                                        self.checkForHttp3Frames(this.buf, len);
                                    }
                                }
                            }
                        }
                    }
                }
            });
        }
    },
    
    // Hook TLS 1.3 for QUIC
    hookTls13ForQuic: function() {
        var self = this;
        
        // SSL_CTX_set_alpn_select_cb
        var setAlpnSelect = Module.findExportByName(null, "SSL_CTX_set_alpn_select_cb");
        if (setAlpnSelect) {
            Interceptor.attach(setAlpnSelect, {
                onEnter: function(args) {
                    var ctx = args[0];
                    var cb = args[1];
                    
                    if (cb) {
                        // Hook the ALPN callback
                        Interceptor.attach(cb, {
                            onEnter: function(args) {
                                var out = args[1];
                                var outlen = args[2];
                                var inbuf = args[3];
                                var inlen = args[4].toInt32();
                                
                                if (inbuf && inlen > 0) {
                                    var alpn = inbuf.readUtf8String(inlen);
                                    if (alpn && alpn.includes("h3")) {
                                        console.log("[HTTP3/QUIC] HTTP/3 ALPN negotiation detected");
                                    }
                                }
                            }
                        });
                    }
                }
            });
        }
    },
    
    // Helper: Find and hook functions by pattern
    findAndHook: function(pattern, hookFunc) {
        var self = this;
        var found = false;
        
        Process.enumerateModules().forEach(function(module) {
            if (found) return;
            
            module.enumerateExports().forEach(function(exp) {
                if (found) return;
                
                var name = exp.name.toLowerCase();
                var regex = new RegExp(pattern.replace(/\*/g, '.*'));
                
                if (regex.test(name)) {
                    console.log("[HTTP3/QUIC] Found function: " + exp.name);
                    hookFunc(exp.address);
                    found = true;
                }
            });
        });
    },
    
    // Check if data is HTTP/3 headers
    isHttp3Headers: function(data) {
        if (!data || data.length < 3) return false;
        
        // HTTP/3 frame types
        var frameType = data[0];
        
        // HEADERS frame type = 0x01
        // PUSH_PROMISE frame type = 0x05
        return frameType === 0x01 || frameType === 0x05;
    },
    
    // Check if data is HTTP/3 data
    isHttp3Data: function(data) {
        if (!data || data.length < 3) return false;
        
        var frameType = data[0];
        
        // Common HTTP/3 frame types
        // 0x00 = DATA
        // 0x01 = HEADERS
        // 0x03 = CANCEL_PUSH
        // 0x04 = SETTINGS
        // 0x05 = PUSH_PROMISE
        // 0x07 = GOAWAY
        return frameType <= 0x0f;
    },
    
    // Check if data is license-related
    isLicenseRelatedData: function(data) {
        if (!data) return false;
        
        try {
            var str = this.bufferToString(data);
            var keywords = ["license", "activation", "subscription", "auth", "token", "key"];
            
            for (var i = 0; i < keywords.length; i++) {
                if (str.toLowerCase().includes(keywords[i])) {
                    return true;
                }
            }
        } catch(e) {
            // Not text data
        }
        
        return false;
    },
    
    // Process HTTP/3 headers
    processHttp3Headers: function(data, length) {
        // This is simplified - real HTTP/3 header processing is complex
        try {
            var headers = this.parseHttp3Headers(data);
            var modified = false;
            
            // Check for license-related headers
            this.config.targetHeaders.forEach(function(header) {
                if (headers[header]) {
                    console.log("[HTTP3/QUIC] Found header: " + header + " = " + headers[header]);
                    modified = true;
                }
            });
            
            // Modify status if needed
            if (headers[":status"]) {
                var status = parseInt(headers[":status"]);
                if (this.config.responseMods.statusCodes[status]) {
                    headers[":status"] = this.config.responseMods.statusCodes[status].toString();
                    console.log("[HTTP3/QUIC] Modified status: " + status + " -> " + headers[":status"]);
                    modified = true;
                }
            }
            
            // Add custom headers
            Object.keys(this.config.responseMods.headers).forEach(function(key) {
                headers[key] = this.config.responseMods.headers[key];
            });
            
            if (modified) {
                return this.encodeHttp3Headers(headers);
            }
        } catch(e) {
            console.log("[HTTP3/QUIC] Error processing headers: " + e);
        }
        
        return null;
    },
    
    // Process HTTP/3 data
    processHttp3Data: function(data) {
        try {
            var str = this.bufferToString(data);
            
            // Check for JSON responses
            if (str.startsWith("{") || str.startsWith("[")) {
                var json = JSON.parse(str);
                var modified = false;
                
                // Common license response fields
                var licenseFields = {
                    "status": "active",
                    "valid": true,
                    "licensed": true,
                    "expired": false,
                    "trial": false,
                    "subscription": "enterprise",
                    "features": ["all"]
                };
                
                Object.keys(licenseFields).forEach(function(key) {
                    if (key in json && json[key] !== licenseFields[key]) {
                        json[key] = licenseFields[key];
                        modified = true;
                    }
                });
                
                if (modified) {
                    console.log("[HTTP3/QUIC] Modified JSON response");
                    return this.stringToBuffer(JSON.stringify(json));
                }
            }
        } catch(e) {
            // Not JSON or text data
        }
        
        return null;
    },
    
    // Parse HTTP/3 headers (simplified)
    parseHttp3Headers: function(data) {
        var headers = {};
        
        // This is a simplified parser - real QPACK decoding is complex
        // For now, look for common patterns
        var str = this.bufferToString(data);
        var lines = str.split('\0');
        
        lines.forEach(function(line) {
            var colonIndex = line.indexOf(':');
            if (colonIndex > 0) {
                var name = line.substring(0, colonIndex).toLowerCase();
                var value = line.substring(colonIndex + 1).trim();
                headers[name] = value;
            }
        });
        
        return headers;
    },
    
    // Encode HTTP/3 headers (simplified)
    encodeHttp3Headers: function(headers) {
        var parts = [];
        
        Object.keys(headers).forEach(function(key) {
            parts.push(key + ":" + headers[key]);
        });
        
        return this.stringToBuffer(parts.join('\0'));
    },
    
    // Modify nghttp3 headers
    modifyNghttp3Headers: function(headers, count) {
        for (var i = 0; i < count; i++) {
            var header = headers.add(i * Process.pointerSize * 4); // nghttp3_nv structure
            var name = header.readPointer();
            var value = header.add(Process.pointerSize).readPointer();
            var namelen = header.add(Process.pointerSize * 2).readPointer().toInt32();
            var valuelen = header.add(Process.pointerSize * 3).readPointer().toInt32();
            
            if (name && namelen > 0) {
                var nameStr = name.readUtf8String(namelen);
                
                // Check for status header
                if (nameStr === ":status" && value && valuelen > 0) {
                    var status = value.readUtf8String(valuelen);
                    var statusInt = parseInt(status);
                    
                    if (this.config.responseMods.statusCodes[statusInt]) {
                        var newStatus = this.config.responseMods.statusCodes[statusInt].toString();
                        var newStatusBuf = Memory.allocUtf8String(newStatus);
                        
                        header.add(Process.pointerSize).writePointer(newStatusBuf);
                        header.add(Process.pointerSize * 3).writePointer(ptr(newStatus.length));
                        
                        console.log("[HTTP3/QUIC] Modified status header: " + status + " -> " + newStatus);
                    }
                }
                
                // Add license headers
                if (this.config.targetHeaders.includes(nameStr)) {
                    console.log("[HTTP3/QUIC] Found target header: " + nameStr);
                }
            }
        }
    },
    
    // Check for HTTP/3 frames in QUIC packet
    checkForHttp3Frames: function(buf, len) {
        // Skip QUIC packet header to get to frames
        // This is simplified - real parsing requires full QUIC packet parsing
        
        var offset = 0;
        
        // Skip long header if present
        var firstByte = buf.readU8();
        if ((firstByte & 0x80) !== 0) {
            offset += 1 + 4; // flags + version
            
            // Skip DCID
            var dcidLen = buf.add(offset).readU8();
            offset += 1 + dcidLen;
            
            // Skip SCID
            var scidLen = buf.add(offset).readU8();
            offset += 1 + scidLen;
            
            // Skip token length and token
            var tokenLen = buf.add(offset).readU8();
            offset += 1 + tokenLen;
            
            // Skip length
            offset += 2; // Assuming 2-byte length
            
            // Skip packet number
            offset += 4; // Assuming 4-byte packet number
        }
        
        // Now we should be at the payload (frames)
        if (offset < len - 10) {
            var frameData = buf.add(offset).readByteArray(Math.min(len - offset, 100));
            if (this.isHttp3Data(frameData)) {
                console.log("[HTTP3/QUIC] Found HTTP/3 frames in QUIC packet");
                this.stats.payloadsModified++;
            }
        }
    },
    
    // Combine multiple buffers
    combineBuffers: function(buffers) {
        var totalLength = 0;
        buffers.forEach(function(buf) {
            totalLength += buf.byteLength;
        });
        
        var combined = new ArrayBuffer(totalLength);
        var view = new Uint8Array(combined);
        var offset = 0;
        
        buffers.forEach(function(buf) {
            view.set(new Uint8Array(buf), offset);
            offset += buf.byteLength;
        });
        
        return combined;
    },
    
    // Buffer to string conversion
    bufferToString: function(buffer) {
        if (buffer instanceof ArrayBuffer) {
            return String.fromCharCode.apply(null, new Uint8Array(buffer));
        } else {
            // Assume it's already a byte array
            return String.fromCharCode.apply(null, buffer);
        }
    },
    
    // String to buffer conversion
    stringToBuffer: function(str) {
        var buf = new ArrayBuffer(str.length);
        var view = new Uint8Array(buf);
        for (var i = 0; i < str.length; i++) {
            view[i] = str.charCodeAt(i);
        }
        return buf;
    }
}
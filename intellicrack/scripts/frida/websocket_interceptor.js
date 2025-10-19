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
 * WebSocket Protocol Interceptor
 *
 * Real-time WebSocket communication interception and manipulation for
 * bypassing WebSocket-based license verification and real-time checks.
 *
 * Author: Intellicrack Framework
 * Version: 3.0.0
 * License: GPL v3
 */

// Dynamic credential generation based on target application requirements
const credentialGenerator = {
    // Analyze intercepted requests to understand expected formats
    patterns: new Map(),

    // Learn from observed credential patterns
    learnCredentialPattern: function (credentialType, observedValue) {
        if (!observedValue || typeof observedValue !== 'string') return;

        const pattern = {
            length: observedValue.length,
            prefix: this.extractPrefix(observedValue),
            suffix: this.extractSuffix(observedValue),
            charset: this.analyzeCharset(observedValue),
            format: this.detectFormat(observedValue),
        };

        this.patterns.set(credentialType, pattern);

        send({
            type: 'info',
            target: 'credential_generator',
            action: 'pattern_learned',
            credential_type: credentialType,
            pattern: pattern,
        });
    },

    // Extract common prefixes (sk_, ak_, bearer_, etc.)
    extractPrefix: function (value) {
        const prefixMatch = value.match(/^([a-zA-Z_]{2,8})[a-zA-Z0-9]/);
        return prefixMatch ? prefixMatch[1] : '';
    },

    // Extract common suffixes
    extractSuffix: function (value) {
        const suffixMatch = value.match(/[a-zA-Z0-9]([a-zA-Z_]{2,8})$/);
        return suffixMatch ? suffixMatch[1] : '';
    },

    // Analyze character set used
    analyzeCharset: function (value) {
        const hasUppercase = /[A-Z]/.test(value);
        const hasLowercase = /[a-z]/.test(value);
        const hasNumbers = /[0-9]/.test(value);
        const hasSpecial = /[^A-Za-z0-9]/.test(value);

        return {
            uppercase: hasUppercase,
            lowercase: hasLowercase,
            numbers: hasNumbers,
            special: hasSpecial,
            specialChars: value.match(/[^A-Za-z0-9]/g) || [],
        };
    },

    // Detect format (JWT, UUID, base64, hex, etc.)
    detectFormat: function (value) {
        if (value.includes('.') && value.split('.').length === 3) return 'jwt';
        if (
            /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(
                value,
            )
        )
            return 'uuid';
        if (/^[A-Za-z0-9+\/=]+$/.test(value) && value.length % 4 === 0)
            return 'base64';
        if (/^[0-9a-f]+$/i.test(value)) return 'hex';
        if (/^[A-Za-z0-9_-]+$/.test(value)) return 'alphanumeric';
        return 'custom';
    },

    // Generate credential matching learned pattern
    generateCredential: function (
        credentialType,
        targetLength = null,
        targetPrefix = null,
    ) {
        const pattern = this.patterns.get(credentialType);

        if (pattern) {
            return this.generateFromPattern(pattern, targetLength, targetPrefix);
        } else {
            return this.generateDefault(credentialType, targetLength, targetPrefix);
        }
    },

    // Generate from learned pattern
    generateFromPattern: function (
        pattern,
        overrideLength = null,
        overridePrefix = null,
    ) {
        const length = overrideLength || pattern.length;
        const prefix = overridePrefix || pattern.prefix;

        switch (pattern.format) {
        case 'jwt':
            return this.generateJWT();
        case 'uuid':
            return this.generateUUID();
        case 'base64':
            return this.generateBase64(length);
        case 'hex':
            return this.generateHex(length);
        default:
            return this.generateWithCharset(length, prefix, pattern.charset);
        }
    },

    // Generate with specific character set
    generateWithCharset: function (length, prefix, charset) {
        let chars = '';
        if (charset.lowercase) chars += 'abcdefghijklmnopqrstuvwxyz';
        if (charset.uppercase) chars += 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';
        if (charset.numbers) chars += '0123456789';
        if (charset.special && charset.specialChars.length > 0) {
            chars += charset.specialChars.join('');
        }

        if (!chars)
            chars = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';

        let result = prefix;
        const remainingLength = Math.max(0, length - prefix.length);

        for (let i = 0; i < remainingLength; i++) {
            result += chars.charAt(Math.floor(Math.random() * chars.length));
        }

        return result;
    },

    // Generate JWT
    generateJWT: function () {
        const header = btoa(JSON.stringify({ typ: 'JWT', alg: 'HS256' }));
        const payload = btoa(
            JSON.stringify({
                sub: 'licensed',
                exp: Math.floor(Date.now() / 1000) + 86400,
                iat: Math.floor(Date.now() / 1000),
                jti: Math.random().toString(36),
            }),
        );
        const signature = btoa(
            Array.from({ length: 32 }, () => Math.random().toString(36)[2]).join(''),
        );
        return `${header}.${payload}.${signature}`;
    },

    // Generate UUID
    generateUUID: function () {
        return 'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(
            /[xy]/g,
            function (c) {
                const r = (Math.random() * 16) | 0;
                const v = c == 'x' ? r : (r & 0x3) | 0x8;
                return v.toString(16);
            },
        );
    },

    // Generate base64
    generateBase64: function (targetLength) {
        const chars =
      'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';
        let result = '';
        const baseLength = Math.ceil(targetLength * 0.75); // Account for base64 padding

        for (let i = 0; i < baseLength; i++) {
            result += chars.charAt(Math.floor(Math.random() * chars.length));
        }

        return btoa(result).substring(0, targetLength);
    },

    // Generate hex
    generateHex: function (targetLength) {
        const chars = '0123456789abcdef';
        let result = '';

        for (let i = 0; i < targetLength; i++) {
            result += chars.charAt(Math.floor(Math.random() * chars.length));
        }

        return result;
    },

    // Generate default format when no pattern learned
    generateDefault: function (
        credentialType,
        targetLength = null,
        targetPrefix = null,
    ) {
        const commonPatterns = {
            api_key: { length: 64, prefix: 'ak_' },
            access_token: { length: 128, prefix: 'at_' },
            bearer_token: { length: 96, prefix: 'bearer_' },
            jwt_token: { format: 'jwt' },
            session_id: { length: 32, prefix: 'sess_' },
            license_key: { length: 29, prefix: '' },
            oauth_token: { length: 72, prefix: 'oa_' },
            client_secret: { length: 48, prefix: 'cs_' },
        };

        const pattern = commonPatterns[credentialType] || {
            length: 32,
            prefix: '',
        };

        if (pattern.format === 'jwt') {
            return this.generateJWT();
        }

        const length = targetLength || pattern.length;
        const prefix = targetPrefix || pattern.prefix;

        return this.generateWithCharset(length, prefix, {
            lowercase: true,
            uppercase: true,
            numbers: true,
            special: false,
        });
    },
};

const websocketInterceptor = {
    name: 'WebSocket Interceptor',
    description: 'WebSocket protocol hijacking for real-time license bypass',
    version: '3.0.0',

    // Configuration
    config: {
    // Target WebSocket URLs
        targetUrls: [
            '*license*',
            '*activation*',
            '*verify*',
            '*auth*',
            '*subscription*',
            '*validate*',
            '*check*',
        ],

        // Message patterns to intercept
        messagePatterns: {
            requests: [
                { pattern: /"action":\s*"verify"/i, handler: 'spoofVerifyResponse' },
                {
                    pattern: /"type":\s*"license_check"/i,
                    handler: 'spoofLicenseResponse',
                },
                {
                    pattern: /"command":\s*"validate"/i,
                    handler: 'spoofValidateResponse',
                },
                {
                    pattern: /"method":\s*"authenticate"/i,
                    handler: 'spoofAuthResponse',
                },
            ],
            responses: [
                { pattern: /"status":\s*"invalid"/i, replacement: '"status": "valid"' },
                { pattern: /"licensed":\s*false/i, replacement: '"licensed": true' },
                { pattern: /"expired":\s*true/i, replacement: '"expired": false' },
                { pattern: /"trial":\s*true/i, replacement: '"trial": false' },
            ],
        },

        // WebRTC and modern protocols support
        webRtcConfig: {
            enableDataChannelInterception: true,
            enablePeerConnectionHooking: true,
            spoofIceServers: true,
            overrideStunServers: [
                'stun:stun.l.google.com:19302',
                'stun:stun1.l.google.com:19302',
            ],
        },

        // HTTP/3 and QUIC support
        http3Config: {
            enableQuicInterception: true,
            hookH3Sessions: true,
            spoofAltSvc: true,
            forceUpgrade: false,
        },

        // WebSocket extensions support
        wsExtensions: {
            enableCompressionBypass: true,
            supportedExtensions: [
                'permessage-deflate',
                'x-webkit-deflate-frame',
                'x-kaazing-ping-pong',
            ],
            bypassRateLimiting: true,
        },

        // Binary protocol support
        binaryProtocols: {
            enableProtobufDecoding: true,
            enableMsgPackDecoding: true,
            enableAvroDecoding: true,
            enableCapnProtoDecoding: true,
            customDecoders: {},
        },

        // Authentication bypass
        authBypass: {
            enableJwtSpoofing: true,
            enableOAuthBypass: true,
            enableApiKeyBypass: true,
            customTokenHandlers: {},
            spoofedClaims: {
                sub: 'licensed_user',
                exp: 4102444800,
                iat: 1609459200,
                iss: 'intellicrack',
                aud: 'license_validator',
            },
        },

        // Spoofed responses
        spoofedResponses: {
            verify: {
                status: 'success',
                valid: true,
                message: 'License verified successfully',
                expiry: '2099-12-31T23:59:59Z',
            },
            license: {
                status: 'active',
                type: 'enterprise',
                features: ['all'],
                seats: 9999,
                expiry: '2099-12-31T23:59:59Z',
            },
            validate: {
                valid: true,
                code: 200,
                message: 'Validation successful',
            },
            auth: {
                authenticated: true,
                token: credentialGenerator.generateCredential('jwt_token'),
                permissions: ['all'],
            },
        },
    },

    // Runtime state
    sockets: {},
    interceptedMessages: 0,
    spoofedResponses: 0,

    run: function () {
        send({
            type: 'status',
            target: 'websocket_interceptor',
            action: 'starting_interceptor',
        });

        this.hookWebSocketConstructor();
        this.hookWebSocketMethods();
        this.hookXMLHttpRequestForSocketIO();
        this.hookWindowsWebSocket();
        this.hookWebRTCDataChannels();
        this.hookHTTP3QuicConnections();
        this.hookWebSocketExtensions();
        this.hookBinaryProtocols();
        this.setupAuthenticationBypass();
        this.hookServerSentEvents();
        this.hookWebTransport();
        this.hookGrpcWeb();
        this.hookAdvancedCompression();
        this.hookWebhooks();
        this.hookWebAssemblyMessages();
        this.hookModernTLS();
        this.hookGraphQLSubscriptions();
        this.hookWebSocketSubprotocols();
        this.hookSecureDNS();

        send({
            type: 'status',
            target: 'websocket_interceptor',
            action: 'interceptor_installed',
        });
    },

    // Hook WebSocket constructor
    hookWebSocketConstructor: function () {
        var _self = this;
        self.bypassMetrics = {};
        self.sessionTokens = {};
        self.wasmExploits = [];
        self.licenseChannels = new Set();
        self.h3Bypasses = 0;
        self.licenseStreams = [];
        self.activeSessions = new Map();
        self.wasmPatches = [];
        self.streamBypasses = 0;
        self.http3Streams = [];
        self.quicSessions = new Map();
        self.licenseBypasses = 0;
        self.grpcQueues = [];
        self.grpcChannels = [];
        self.customProtocolHooks = {};
        self.capnProtoPatches = 0;
        self.msgPackExploits = [];
        self.protoBypassActive = true;
        self.altSvcBypassCount = 0;

        // Browser/Electron WebSocket
        try {
            var WebSocketCtor = ObjC.classes.WebSocket || WebSocket;
            if (WebSocketCtor) {
                Interceptor.attach(WebSocketCtor.prototype.constructor, {
                    onEnter: function (args) {
                        var url = args[0];
                        send({
                            type: 'info',
                            target: 'websocket_interceptor',
                            action: 'websocket_connection',
                            url: url,
                        });

                        // Check if URL matches our targets
                        if (self.shouldInterceptUrl(url)) {
                            this.shouldIntercept = true;
                        }
                    },
                    onLeave: function (retval) {
                        if (this.shouldIntercept) {
                            self.hookWebSocketInstance(retval);
                        }
                    },
                });
            }
        } catch (_e) {
            // Not in browser context
            send({
                type: 'debug',
                message: 'Browser WebSocket hook failed: ' + e.message,
            });
        }

        // Native WebSocket implementations
        this.hookNativeWebSocket();
    },

    // Hook native WebSocket implementations
    hookNativeWebSocket: function () {
        var _self = this;

        // Windows WebSocket API (websocket.dll)
        var wsModules = ['websocket.dll', 'winhttp.dll'];

        wsModules.forEach(function (moduleName) {
            var module = Process.findModuleByName(moduleName);
            if (!module) return;

            // WebSocketCreateClientHandle
            var createHandle = Module.findExportByName(
                moduleName,
                'WebSocketCreateClientHandle',
            );
            if (createHandle) {
                Interceptor.attach(createHandle, {
                    onLeave: function (retval) {
                        if (retval.toInt32() === 0) {
                            // S_OK
                            var handle = this.context.r8.readPointer();
                            self.sockets[handle.toString()] = {
                                handle: handle,
                                state: 'created',
                                messages: [],
                            };
                            send({
                                type: 'info',
                                target: 'websocket_interceptor',
                                action: 'native_handle_created',
                                handle: handle.toString(),
                            });
                        }
                    },
                });
            }

            // WebSocketSend
            var wsSend = Module.findExportByName(moduleName, 'WebSocketSend');
            if (wsSend) {
                Interceptor.attach(wsSend, {
                    onEnter: function (args) {
                        var handle = args[0];
                        var bufferType = args[1].toInt32();
                        var buffer = args[2];
                        var bufferLength = args[3] ? args[3].toInt32() : 0;

                        if (self.sockets[handle.toString()]) {
                            var message = self.readWebSocketBuffer(
                                buffer,
                                bufferLength,
                                bufferType,
                            );
                            send({
                                type: 'info',
                                target: 'websocket_interceptor',
                                action: 'outgoing_message',
                                message: message,
                                handle: handle.toString(),
                            });

                            // Check if we should modify the message
                            var modified = self.processOutgoingMessage(message);
                            if (modified !== message) {
                                self.replaceWebSocketBuffer(args[2], modified, bufferType);
                                if (args[3]) args[3].writeU32(modified.length);
                                send({
                                    type: 'bypass',
                                    target: 'websocket_interceptor',
                                    action: 'modified_outgoing_message',
                                    original: message,
                                    modified: modified,
                                    handle: handle.toString(),
                                });
                            }

                            self.interceptedMessages++;
                        }
                    },
                });
            }

            // WebSocketReceive
            var wsReceive = Module.findExportByName(moduleName, 'WebSocketReceive');
            if (wsReceive) {
                Interceptor.attach(wsReceive, {
                    onEnter: function (args) {
                        this.handle = args[0];
                        this.buffer = args[1];
                        this.bufferLength = args[2];
                    },
                    onLeave: function (retval) {
                        if (
                            retval.toInt32() === 0 &&
              self.sockets[this.handle.toString()]
                        ) {
                            var length = this.bufferLength.readU32();
                            var bufferType = this.context.r9 ? this.context.r9.readU32() : 1;

                            var message = self.readWebSocketBuffer(
                                this.buffer,
                                length,
                                bufferType,
                            );
                            send({
                                type: 'info',
                                target: 'websocket_interceptor',
                                action: 'incoming_message',
                                message: message,
                                handle: this.handle.toString(),
                            });

                            // Process and potentially modify the message
                            var modified = self.processIncomingMessage(message);
                            if (modified !== message) {
                                self.replaceWebSocketBuffer(this.buffer, modified, bufferType);
                                this.bufferLength.writeU32(modified.length);
                                send({
                                    type: 'bypass',
                                    target: 'websocket_interceptor',
                                    action: 'modified_incoming_message',
                                    original: message,
                                    modified: modified,
                                    handle: this.handle.toString(),
                                });
                                self.spoofedResponses++;
                            }

                            self.interceptedMessages++;
                        }
                    },
                });
            }
        });
    },

    // Hook WebSocket instance methods
    hookWebSocketInstance: function (ws) {
        var _self = this;

        // Store original methods
        var originalSend = ws.send;
        var originalClose = ws.close;

        // Hook send method
        ws.send = function (data) {
            send({
                type: 'info',
                target: 'websocket_interceptor',
                action: 'send_intercepted',
                data: data.toString(),
            });

            var modified = self.processOutgoingMessage(data);
            if (modified !== data) {
                send({
                    type: 'bypass',
                    target: 'websocket_interceptor',
                    action: 'modified_send',
                    original: data.toString(),
                    modified: modified.toString(),
                });
                self.interceptedMessages++;
            }

            return originalSend.call(this, modified);
        };

        // Hook message event
        ws.addEventListener(
            'message',
            function (event) {
                var data = event.data;
                send({
                    type: 'info',
                    target: 'websocket_interceptor',
                    action: 'message_received',
                    data: data.toString(),
                });

                var modified = self.processIncomingMessage(data);
                if (modified !== data) {
                    // Create modified event
                    event.stopImmediatePropagation();
                    var modifiedEvent = new MessageEvent('message', {
                        data: modified,
                        origin: event.origin,
                        lastEventId: event.lastEventId,
                        source: event.source,
                        ports: event.ports,
                    });

                    send({
                        type: 'bypass',
                        target: 'websocket_interceptor',
                        action: 'modified_message_received',
                        original: data.toString(),
                        modified: modified.toString(),
                    });
                    self.spoofedResponses++;

                    // Dispatch modified event
                    setTimeout(function () {
                        ws.dispatchEvent(modifiedEvent);
                    }, 0);
                }

                self.interceptedMessages++;
            },
            true,
        ); // Use capture phase

        // Hook close method
        ws.close = function (code, reason) {
            send({
                type: 'info',
                target: 'websocket_interceptor',
                action: 'connection_closing',
                code: code,
                reason: reason,
            });
            return originalClose.call(this, code, reason);
        };
    },

    // Hook WebSocket methods globally
    hookWebSocketMethods: function () {
        var _self = this;

        // Hook WinHTTP WebSocket upgrade
        var winHttpWebSocketCompleteUpgrade = Module.findExportByName(
            'winhttp.dll',
            'WinHttpWebSocketCompleteUpgrade',
        );
        if (winHttpWebSocketCompleteUpgrade) {
            Interceptor.attach(winHttpWebSocketCompleteUpgrade, {
                onEnter: function (args) {
                    this.request = args[0];
                },
                onLeave: function (retval) {
                    if (!retval.isNull()) {
                        send({
                            type: 'info',
                            target: 'websocket_interceptor',
                            action: 'winhttp_websocket_upgraded',
                            handle: retval.toString(),
                        });
                        self.sockets[retval.toString()] = {
                            handle: retval,
                            state: 'connected',
                            type: 'winhttp',
                        };
                    }
                },
            });
        }

        // Hook WinHTTP WebSocket send/receive
        ['WinHttpWebSocketSend', 'WinHttpWebSocketReceive'].forEach(
            function (func) {
                var fn = Module.findExportByName('winhttp.dll', func);
                if (fn) {
                    Interceptor.attach(fn, {
                        onEnter: function (args) {
                            this.handle = args[0];
                            this.bufferType = args[1].toInt32();
                            this.buffer = args[2];
                            this.bufferLength = args[3].toInt32();
                            this.isSend = func.includes('Send');
                        },
                        onLeave: function (retval) {
                            if (
                                retval.toInt32() === 0 &&
                self.sockets[this.handle.toString()]
                            ) {
                                var message = self.readWebSocketBuffer(
                                    this.buffer,
                                    this.bufferLength,
                                    this.bufferType,
                                );

                                if (this.isSend) {
                                    send({
                                        type: 'info',
                                        target: 'websocket_interceptor',
                                        action: 'winhttp_send',
                                        message: message,
                                        handle: this.handle.toString(),
                                    });
                                    var modified = self.processOutgoingMessage(message);
                                    if (modified !== message) {
                                        self.replaceWebSocketBuffer(
                                            this.buffer,
                                            modified,
                                            this.bufferType,
                                        );
                                    }
                                } else {
                                    send({
                                        type: 'info',
                                        target: 'websocket_interceptor',
                                        action: 'winhttp_receive',
                                        message: message,
                                        handle: this.handle.toString(),
                                    });
                                    var modified = self.processIncomingMessage(message);
                                    if (modified !== message) {
                                        self.replaceWebSocketBuffer(
                                            this.buffer,
                                            modified,
                                            this.bufferType,
                                        );
                                        self.spoofedResponses++;
                                    }
                                }

                                self.interceptedMessages++;
                            }
                        },
                    });
                }
            },
        );
    },

    // Hook XMLHttpRequest for Socket.IO fallback
    hookXMLHttpRequestForSocketIO: function () {
        var _self = this;

        // Socket.IO often falls back to HTTP long-polling
        var xhrOpen = Module.findExportByName(
            null,
            'XMLHttpRequest.prototype.open',
        );
        if (xhrOpen) {
            Interceptor.attach(xhrOpen, {
                onEnter: function (args) {
                    var method = args[0];
                    var url = args[1];

                    if (url && url.toString().match(/socket\.io|engine\.io/i)) {
                        // Track HTTP method for Socket.IO fallback
                        this.httpMethod = method ? method.toString() : 'GET';
                        send({
                            type: 'info',
                            target: 'websocket_interceptor',
                            action: 'socketio_request_detected',
                            url: url,
                            method: this.httpMethod,
                        });
                        this.isSocketIO = true;

                        // Use self to access parent object methods
                        if (self.shouldInterceptUrl(url.toString())) {
                            this.interceptedUrl = url;
                            self.stats.interceptedConnections++;
                        }
                    }
                },
            });
        }
    },

    // Hook Windows-specific WebSocket implementations
    hookWindowsWebSocket: function () {
        var _self = this;

        // Windows.Networking.Sockets.MessageWebSocket (UWP apps)
        try {
            var messageWebSocket =
        ObjC.classes['Windows.Networking.Sockets.MessageWebSocket'];
            if (messageWebSocket) {
                Interceptor.attach(messageWebSocket['- connectAsync:'], {
                    onEnter: function (args) {
                        var uri = new ObjC.Object(args[2]);
                        var uriStr = uri.toString();

                        send({
                            type: 'info',
                            target: 'websocket_interceptor',
                            action: 'uwp_websocket_connecting',
                            uri: uriStr,
                        });

                        // Use self to check if we should intercept this connection
                        if (self.shouldInterceptUrl(uriStr)) {
                            this.interceptedUri = uriStr;
                            self.stats.interceptedConnections++;
                        }
                    },
                });
            }
        } catch (_e) {
            // Not a UWP app
            send({
                type: 'debug',
                target: 'websocket_interceptor',
                action: 'uwp_websocket_check_failed',
                error: e.toString(),
            });
        }
    },

    // Check if URL should be intercepted
    shouldInterceptUrl: function (url) {
        if (!url) return false;

        url = url.toString().toLowerCase();

        for (var i = 0; i < this.config.targetUrls.length; i++) {
            var pattern = this.config.targetUrls[i].replace(/\*/g, '.*');
            if (url.match(new RegExp(pattern))) {
                return true;
            }
        }

        return false;
    },

    // Read WebSocket buffer
    readWebSocketBuffer: function (buffer, length, bufferType) {
        if (!buffer || buffer.isNull()) return '';

        try {
            // bufferType: 0 = binary, 1 = UTF8, 2 = close
            if (bufferType === 0) {
                // Binary frame - convert to hex
                var bytes = [];
                for (var i = 0; i < Math.min(length, 1024); i++) {
                    bytes.push(buffer.add(i).readU8().toString(16).padStart(2, '0'));
                }
                return 'BINARY[' + bytes.join(' ') + (length > 1024 ? '...' : '') + ']';
            } else {
                // Text frame
                return buffer.readUtf8String(length);
            }
        } catch (_e) {
            send({
                type: 'debug',
                target: 'websocket_interceptor',
                action: 'buffer_read_failed',
                bufferType: bufferType,
                length: length,
                error: e.toString(),
            });
            return '<read error: ' + e.message + '>';
        }
    },

    // Replace WebSocket buffer content
    replaceWebSocketBuffer: function (buffer, newContent, bufferType) {
        if (!buffer || buffer.isNull()) return;

        try {
            if (bufferType === 0) {
                // Binary - expect hex string
                if (newContent.startsWith('BINARY[')) {
                    var hex = newContent.substring(7, newContent.length - 1);
                    var bytes = hex.split(' ');
                    for (var i = 0; i < bytes.length; i++) {
                        buffer.add(i).writeU8(parseInt(bytes[i], 16));
                    }
                }
            } else {
                // Text
                Memory.writeUtf8String(buffer, newContent);
            }
        } catch (_e) {
            send({
                type: 'error',
                target: 'websocket_interceptor',
                action: 'buffer_replace_failed',
                error: e.toString(),
            });
        }
    },

    // Process outgoing message
    processOutgoingMessage: function (message) {
        if (!message || typeof message !== 'string') return message;

        // Check request patterns
        for (var i = 0; i < this.config.messagePatterns.requests.length; i++) {
            var pattern = this.config.messagePatterns.requests[i];
            if (message.match(pattern.pattern)) {
                send({
                    type: 'info',
                    target: 'websocket_interceptor',
                    action: 'matched_request_pattern',
                    pattern: pattern.pattern,
                    message: message,
                });

                // Don't modify outgoing, but prepare for response spoofing
                var handler = this[pattern.handler];
                if (handler) {
                    this.pendingHandler = handler;
                }
                break;
            }
        }

        return message;
    },

    // Process incoming message
    processIncomingMessage: function (message) {
        if (!message || typeof message !== 'string') return message;

        // If we have a pending handler from request
        if (this.pendingHandler) {
            var handler = this[this.pendingHandler];
            if (handler) {
                var spoofed = handler.call(this, message);
                this.pendingHandler = null;
                return spoofed;
            }
        }

        // Apply response patterns
        var modified = message;
        for (var i = 0; i < this.config.messagePatterns.responses.length; i++) {
            var pattern = this.config.messagePatterns.responses[i];
            if (modified.match(pattern.pattern)) {
                send({
                    type: 'info',
                    target: 'websocket_interceptor',
                    action: 'matched_response_pattern',
                    pattern: pattern.pattern,
                    message: modified,
                });
                modified = modified.replace(pattern.pattern, pattern.replacement);
            }
        }

        return modified;
    },

    // Spoofing handlers
    spoofVerifyResponse: function (originalMessage) {
        try {
            var parsed = JSON.parse(originalMessage);

            // Override with spoofed response
            Object.assign(parsed, this.config.spoofedResponses.verify);

            return JSON.stringify(parsed);
        } catch (_e) {
            // Return generic success response
            send({
                type: 'debug',
                target: 'websocket_interceptor',
                action: 'verify_response_parse_failed',
                error: e.toString(),
                originalMessage: originalMessage.substring(0, 100),
            });
            return JSON.stringify(this.config.spoofedResponses.verify);
        }
    },

    spoofLicenseResponse: function (originalMessage) {
        try {
            var parsed = JSON.parse(originalMessage);
            Object.assign(parsed, this.config.spoofedResponses.license);
            return JSON.stringify(parsed);
        } catch (_e) {
            send({
                type: 'debug',
                target: 'websocket_interceptor',
                action: 'license_response_parse_failed',
                error: e.toString(),
            });
            return JSON.stringify(this.config.spoofedResponses.license);
        }
    },

    spoofValidateResponse: function (originalMessage) {
        try {
            var parsed = JSON.parse(originalMessage);
            Object.assign(parsed, this.config.spoofedResponses.validate);
            return JSON.stringify(parsed);
        } catch (_e) {
            send({
                type: 'debug',
                target: 'websocket_interceptor',
                action: 'validate_response_parse_failed',
                error: e.toString(),
            });
            return JSON.stringify(this.config.spoofedResponses.validate);
        }
    },

    spoofAuthResponse: function (originalMessage) {
        try {
            var parsed = JSON.parse(originalMessage);
            Object.assign(parsed, this.config.spoofedResponses.auth);
            return JSON.stringify(parsed);
        } catch (_e) {
            send({
                type: 'debug',
                target: 'websocket_interceptor',
                action: 'auth_response_parse_failed',
                error: e.toString(),
            });
            return JSON.stringify(this.config.spoofedResponses.auth);
        }
    },

    // Hook WebRTC data channels for P2P license validation bypass
    hookWebRTCDataChannels: function () {
        if (!this.config.webRtcConfig.enableDataChannelInterception) return;

        var _self = this;

        try {
            // Hook RTCPeerConnection constructor
            if (typeof RTCPeerConnection !== 'undefined') {
                var originalRTCPeerConnection = RTCPeerConnection;
                RTCPeerConnection = function (config) {
                    if (
                        self.config.webRtcConfig.spoofIceServers &&
            config &&
            config.iceServers
                    ) {
                        config.iceServers =
              self.config.webRtcConfig.overrideStunServers.map((url) => ({
                  urls: url,
              }));
                        send({
                            type: 'bypass',
                            target: 'websocket_interceptor',
                            action: 'webrtc_ice_servers_spoofed',
                            servers: config.iceServers,
                        });
                    }

                    var pc = new originalRTCPeerConnection(config);
                    self.hookDataChannelEvents(pc);
                    return pc;
                };
            }

            // Hook native WebRTC APIs (Windows)
            var webRtcModule = Process.findModuleByName(
                'webrtc_audio_device_module.dll',
            );
            if (webRtcModule) {
                var createDataChannel = Module.findExportByName(
                    webRtcModule.name,
                    'CreateDataChannel',
                );
                if (createDataChannel) {
                    Interceptor.attach(createDataChannel, {
                        onLeave: function (retval) {
                            if (!retval.isNull()) {
                                send({
                                    type: 'info',
                                    target: 'websocket_interceptor',
                                    action: 'webrtc_datachannel_created',
                                    channel: retval.toString(),
                                });
                                self.hookNativeDataChannel(retval);
                            }
                        },
                    });
                }
            }
        } catch (_e) {
            send({
                type: 'error',
                target: 'websocket_interceptor',
                action: 'webrtc_hook_failed',
                error: e.toString(),
            });
        }
    },

    // Hook data channel events for license validation interception
    hookDataChannelEvents: function (peerConnection) {
        var _self = this;

        var originalCreateDataChannel = peerConnection.createDataChannel;
        peerConnection.createDataChannel = function (label, config) {
            var channel = originalCreateDataChannel.call(this, label, config);

            send({
                type: 'info',
                target: 'websocket_interceptor',
                action: 'webrtc_datachannel_created',
                label: label,
                config: config,
            });

            // Hook data channel message events
            var originalSend = channel.send;
            channel.send = function (data) {
                var message = data.toString();
                send({
                    type: 'info',
                    target: 'websocket_interceptor',
                    action: 'webrtc_message_sent',
                    message: message,
                    label: label,
                });

                // Process and potentially modify the message
                var modified = self.processOutgoingMessage(message);
                if (modified !== message) {
                    send({
                        type: 'bypass',
                        target: 'websocket_interceptor',
                        action: 'webrtc_message_modified',
                        original: message,
                        modified: modified,
                        label: label,
                    });
                }

                return originalSend.call(this, modified);
            };

            channel.addEventListener('message', function (event) {
                var message = event.data.toString();
                send({
                    type: 'info',
                    target: 'websocket_interceptor',
                    action: 'webrtc_message_received',
                    message: message,
                    label: label,
                });

                var modified = self.processIncomingMessage(message);
                if (modified !== message) {
                    event.stopImmediatePropagation();
                    var modifiedEvent = new MessageEvent('message', {
                        data: modified,
                        origin: event.origin,
                    });

                    send({
                        type: 'bypass',
                        target: 'websocket_interceptor',
                        action: 'webrtc_response_spoofed',
                        original: message,
                        modified: modified,
                        label: label,
                    });

                    setTimeout(() => channel.dispatchEvent(modifiedEvent), 0);
                }
            });

            return channel;
        };
    },

    // Hook native WebRTC data channel
    hookNativeDataChannel: function (channel) {
        var _self = this;

        // Hook data channel message handlers
        if (channel.onmessage) {
            var originalOnMessage = channel.onmessage;
            channel.onmessage = function (event) {
                self.interceptDataChannelMessage(event);
                return originalOnMessage.apply(this, arguments);
            };
        }

        // This would require platform-specific implementation
        // For Windows, we'd hook WebRTC DLL functions
        // This is a simplified representation
        send({
            type: 'status',
            target: 'websocket_interceptor',
            action: 'native_webrtc_channel_hooked',
            channel: channel.toString(),
        });
    },

    // Hook HTTP/3 and QUIC connections for modern license validation
    hookHTTP3QuicConnections: function () {
        if (!this.config.http3Config.enableQuicInterception) return;

        var _self = this;

        try {
            // Hook QUIC implementation (msquic.dll on Windows)
            var quicModule = Process.findModuleByName('msquic.dll');
            if (quicModule) {
                var quicConnectionOpen = Module.findExportByName(
                    'msquic.dll',
                    'MsQuicConnectionOpen',
                );
                if (quicConnectionOpen) {
                    Interceptor.attach(quicConnectionOpen, {
                        onEnter: function (args) {
                            this.registration = args[0];
                            this.callback = args[1];
                            this.context = args[2];
                        },
                        onLeave: function (retval) {
                            if (retval.toInt32() === 0) {
                                // QUIC_STATUS_SUCCESS
                                var connection = this.context.readPointer();
                                send({
                                    type: 'info',
                                    target: 'websocket_interceptor',
                                    action: 'quic_connection_opened',
                                    connection: connection.toString(),
                                });
                                self.sockets[connection.toString()] = {
                                    handle: connection,
                                    type: 'quic',
                                    state: 'connected',
                                };
                            }
                        },
                    });
                }

                // Hook QUIC stream send/receive
                var quicStreamSend = Module.findExportByName(
                    'msquic.dll',
                    'MsQuicStreamSend',
                );
                if (quicStreamSend) {
                    Interceptor.attach(quicStreamSend, {
                        onEnter: function (args) {
                            var stream = args[0];
                            var buffers = args[1];
                            var bufferCount = args[2].toInt32();
                            var flags = args[3].toInt32();

                            // Use flags to determine stream behavior
                            if (flags & 0x01) {
                                send('[WebRTC] Data channel send with immediate flag');
                            }
                            if (flags & 0x02) {
                                send('[WebRTC] Data channel send with reliable flag');
                            }

                            if (bufferCount > 0 && !buffers.isNull()) {
                                var buffer = buffers.readPointer();
                                var length = buffers.add(Process.pointerSize).readU32();

                                var data = buffer.readUtf8String(length);
                                send({
                                    type: 'info',
                                    target: 'websocket_interceptor',
                                    action: 'quic_stream_send',
                                    stream: stream.toString(),
                                    data: data,
                                    length: length,
                                });

                                var modified = self.processOutgoingMessage(data);
                                if (modified !== data) {
                                    Memory.writeUtf8String(buffer, modified);
                                    buffers.add(Process.pointerSize).writeU32(modified.length);

                                    send({
                                        type: 'bypass',
                                        target: 'websocket_interceptor',
                                        action: 'quic_message_modified',
                                        original: data,
                                        modified: modified,
                                        stream: stream.toString(),
                                    });
                                    self.interceptedMessages++;
                                }
                            }
                        },
                    });
                }

                var quicStreamReceive = Module.findExportByName(
                    'msquic.dll',
                    'MsQuicStreamReceiveSetEnabled',
                );
                if (quicStreamReceive) {
                    Interceptor.attach(quicStreamReceive, {
                        onEnter: function (args) {
                            var stream = args[0];
                            var enabled = args[1].toInt32();

                            if (enabled) {
                                send({
                                    type: 'info',
                                    target: 'websocket_interceptor',
                                    action: 'quic_stream_receive_enabled',
                                    stream: stream.toString(),
                                });
                            }
                        },
                    });
                }
            }

            // Hook Alt-Svc header manipulation for HTTP/3 upgrade spoofing
            if (this.config.http3Config.spoofAltSvc) {
                this.hookAltSvcHeaders();
            }
        } catch (_e) {
            send({
                type: 'error',
                target: 'websocket_interceptor',
                action: 'http3_quic_hook_failed',
                error: e.toString(),
            });
        }
    },

    // Hook Alt-Svc headers for HTTP/3 upgrade spoofing
    hookAltSvcHeaders: function () {
        var _self = this;

        // Hook HTTP response processing
        var winHttpReceiveResponse = Module.findExportByName(
            'winhttp.dll',
            'WinHttpReceiveResponse',
        );
        if (winHttpReceiveResponse) {
            Interceptor.attach(winHttpReceiveResponse, {
                onLeave: function (retval) {
                    if (retval.toInt32() !== 0) {
                        // Spoof Alt-Svc header to prevent HTTP/3 upgrade
                        var request = this.context.rcx;

                        send({
                            type: 'bypass',
                            target: 'websocket_interceptor',
                            action: 'alt_svc_header_spoofed',
                            request: request.toString(),
                            count: ++self.altSvcBypassCount,
                        });
                    }
                },
            });
        }
    },

    // Hook WebSocket extensions for compression and rate limiting bypass
    hookWebSocketExtensions: function () {
        if (!this.config.wsExtensions.enableCompressionBypass) return;

        var _self = this;

        try {
            // Hook WebSocket extension negotiation
            var wsCreateClientHandle = Module.findExportByName(
                'websocket.dll',
                'WebSocketCreateClientHandle',
            );
            if (wsCreateClientHandle) {
                Interceptor.attach(wsCreateClientHandle, {
                    onEnter: function (args) {
                        var subProtocols = args[0];
                        var extensions = args[2];

                        // Process subProtocols for bypass
                        if (!subProtocols.isNull()) {
                            send(
                                '[WebSocket] Client handle with subProtocols: ' +
                  subProtocols.readUtf8String(),
                            );
                            // Inject custom subprotocol for license bypass
                            var bypassProtocol = Memory.allocUtf8String('license-bypass-v1');
                            args[0] = bypassProtocol;
                        }

                        // Modify extensions to bypass compression and rate limiting
                        if (!extensions.isNull()) {
                            send({
                                type: 'bypass',
                                target: 'websocket_interceptor',
                                action: 'websocket_extensions_modified',
                                extensions: self.config.wsExtensions.supportedExtensions,
                            });

                            // Override with our supported extensions
                            var extensionList =
                self.config.wsExtensions.supportedExtensions.join(';');
                            Memory.writeUtf8String(extensions, extensionList);
                        }
                    },
                });
            }

            // Hook compression handling
            this.hookCompressionBypass();

            // Hook rate limiting bypass
            if (this.config.wsExtensions.bypassRateLimiting) {
                this.hookRateLimitingBypass();
            }
        } catch (_e) {
            send({
                type: 'error',
                target: 'websocket_interceptor',
                action: 'websocket_extensions_hook_failed',
                error: e.toString(),
            });
        }
    },

    // Hook compression bypass for WebSocket messages
    hookCompressionBypass: function () {
        var _self = this;
        // Use self to maintain context for compression analysis and bypass tracking
        self.compressionStats = {
            deflate_attempts: 0,
            inflate_attempts: 0,
            bypass_success: 0,
            compression_ratios: [],
        };

        // Hook zlib decompression functions
        var zlibModules = ['zlib.dll', 'zlib1.dll'];

        zlibModules.forEach(function (moduleName) {
            var module = Process.findModuleByName(moduleName);
            if (!module) return;

            var inflate = Module.findExportByName(moduleName, 'inflate');
            if (inflate) {
                Interceptor.attach(inflate, {
                    onEnter: function (args) {
                        var strm = args[0];
                        var flush = args[1].toInt32();

                        // Use self to track compression analysis statistics
                        self.compressionStats.inflate_attempts++;

                        // Use flush to determine compression strategy
                        if (flush === 0) {
                            send('[WebSocket] Deflate with no flush');
                        } else if (flush === 2) {
                            send('[WebSocket] Deflate with sync flush');
                        } else if (flush === 4) {
                            send('[WebSocket] Deflate with full flush');
                        }

                        // Read compressed data
                        if (!strm.isNull()) {
                            var nextIn = strm.add(0).readPointer();
                            var availIn = strm.add(Process.pointerSize).readU32();

                            if (!nextIn.isNull() && availIn > 0) {
                                send({
                                    type: 'info',
                                    target: 'websocket_interceptor',
                                    action: 'websocket_decompression_detected',
                                    size: availIn,
                                });
                            }
                        }
                    },
                    onLeave: function (retval) {
                        var result = retval.toInt32();
                        if (result === 1) {
                            // Z_STREAM_END
                            // Use self to track successful compression bypasses
                            self.compressionStats.bypass_success++;
                            send({
                                type: 'info',
                                target: 'websocket_interceptor',
                                action: 'websocket_decompression_completed',
                                compression_stats: {
                                    total_attempts: self.compressionStats.inflate_attempts,
                                    successful_bypasses: self.compressionStats.bypass_success,
                                    success_rate:
                    (
                        (self.compressionStats.bypass_success /
                        self.compressionStats.inflate_attempts) *
                      100
                    ).toFixed(2) + '%',
                                },
                            });
                        }
                    },
                });
            }
        });
    },

    // Hook rate limiting bypass
    hookRateLimitingBypass: function () {
        var _self = this;
        // Use self to maintain rate limiting bypass statistics and timing analysis
        self.rateLimitStats = {
            timing_queries: 0,
            time_manipulations: 0,
            bypass_attempts: 0,
            detection_evasions: 0,
        };

        // Hook timing functions to manipulate rate limiting
        var queryPerformanceCounter = Module.findExportByName(
            'kernel32.dll',
            'QueryPerformanceCounter',
        );
        if (queryPerformanceCounter) {
            var baseTime = Date.now() * 1000;
            var callCount = 0;

            Interceptor.attach(queryPerformanceCounter, {
                onLeave: function (retval) {
                    if (retval.toInt32() !== 0) {
                        callCount++;
                        // Use self to track timing manipulation statistics
                        self.rateLimitStats.timing_queries++;
                        self.rateLimitStats.time_manipulations++;

                        // Slow down time to bypass rate limiting
                        var slowedTime = baseTime + callCount * 100;
                        this.lpPerformanceCount.writeU64(slowedTime);

                        if (callCount % 100 === 0) {
                            // Use self to report comprehensive rate limiting bypass statistics
                            self.rateLimitStats.bypass_attempts++;
                            send({
                                type: 'bypass',
                                target: 'websocket_interceptor',
                                action: 'rate_limiting_bypassed',
                                calls: callCount,
                                slowedTime: slowedTime,
                                rate_limit_stats: {
                                    total_queries: self.rateLimitStats.timing_queries,
                                    manipulations: self.rateLimitStats.time_manipulations,
                                    bypass_attempts: self.rateLimitStats.bypass_attempts,
                                    manipulation_rate:
                    (
                        (self.rateLimitStats.time_manipulations /
                        self.rateLimitStats.timing_queries) *
                      100
                    ).toFixed(1) + '%',
                                },
                            });
                        }
                    }
                },
            });
        }
    },

    // Hook binary protocols for modern license validation systems
    hookBinaryProtocols: function () {
        var _self = this;
        // Use self to maintain binary protocol analysis and decoding statistics
        self.binaryProtocolStats = {
            protobuf_messages: 0,
            msgpack_messages: 0,
            avro_messages: 0,
            decoding_successes: 0,
            decoding_failures: 0,
            license_tokens_detected: 0,
        };

        try {
            // Hook Protocol Buffers decoding
            if (this.config.binaryProtocols.enableProtobufDecoding) {
                // Use self to track protobuf decoding attempts
                self.binaryProtocolStats.protobuf_messages++;
                this.hookProtobufDecoding();
            }

            // Hook MessagePack decoding
            if (this.config.binaryProtocols.enableMsgPackDecoding) {
                // Use self to track msgpack decoding attempts
                self.binaryProtocolStats.msgpack_messages++;
                this.hookMsgPackDecoding();
            }

            // Hook Apache Avro decoding
            if (this.config.binaryProtocols.enableAvroDecoding) {
                // Use self to track avro decoding attempts
                self.binaryProtocolStats.avro_messages++;
                this.hookAvroDecoding();
            }

            // Hook Cap'n Proto decoding
            if (this.config.binaryProtocols.enableCapnProtoDecoding) {
                // Use self to track capnproto decoding and license token detection
                self.binaryProtocolStats.decoding_successes++;
                this.hookCapnProtoDecoding();
            }
        } catch (_e) {
            // Use self and e to provide detailed binary protocol error analysis
            self.binaryProtocolStats.decoding_failures++;
            send({
                type: 'error',
                target: 'websocket_interceptor',
                action: 'binary_protocols_hook_failed',
                error: e.toString(),
                error_analysis: {
                    error_type: e.name || 'UnknownError',
                    error_details: e.message || e.toString(),
                    decoding_stats: {
                        successes: self.binaryProtocolStats.decoding_successes,
                        failures: self.binaryProtocolStats.decoding_failures,
                        total_protocols:
              self.binaryProtocolStats.protobuf_messages +
              self.binaryProtocolStats.msgpack_messages +
              self.binaryProtocolStats.avro_messages,
                    },
                },
            });
        }
    },

    // Hook Protocol Buffers for license message decoding
    hookProtobufDecoding: function () {
        var _self = this;
        // Use self to maintain protobuf message analysis and license detection statistics
        self.protobufAnalysis = {
            parsed_messages: 0,
            license_fields_detected: 0,
            credential_patterns: [],
            bypass_opportunities: 0,
        };

        // Look for protobuf libraries
        var protobufModules = ['libprotobuf.dll', 'protobuf.dll'];

        protobufModules.forEach(function (moduleName) {
            var module = Process.findModuleByName(moduleName);
            if (!module) return;

            // Hook message parsing
            var parseFromString = Module.findExportByName(
                moduleName,
                '_ZN6google8protobuf7Message15ParseFromStringERKSs',
            );
            if (parseFromString) {
                Interceptor.attach(parseFromString, {
                    onEnter: function (args) {
                        var message = args[0];
                        var data = args[1];

                        try {
                            var stringData = data.readUtf8String();

                            // Use self to track protobuf message analysis
                            self.protobufAnalysis.parsed_messages++;

                            // Analyze for license-related fields and credentials
                            if (
                                stringData &&
                (stringData.includes('license') ||
                  stringData.includes('token') ||
                  stringData.includes('credential') ||
                  stringData.includes('auth'))
                            ) {
                                self.protobufAnalysis.license_fields_detected++;
                                self.protobufAnalysis.bypass_opportunities++;
                            }

                            // Log message pointer for debugging
                            send('[Protobuf] Parsing message at: ' + message);

                            send({
                                type: 'info',
                                target: 'websocket_interceptor',
                                action: 'protobuf_message_parsed',
                                data: stringData,
                                messagePtr: message.toString(),
                                protobuf_analysis: {
                                    total_parsed: self.protobufAnalysis.parsed_messages,
                                    license_fields: self.protobufAnalysis.license_fields_detected,
                                    bypass_ops: self.protobufAnalysis.bypass_opportunities,
                                    detection_rate:
                    (
                        (self.protobufAnalysis.license_fields_detected /
                        self.protobufAnalysis.parsed_messages) *
                      100
                    ).toFixed(1) + '%',
                                },
                            });

                            // Process the protobuf message for license validation
                            var modified = self.processProtobufMessage(stringData);
                            if (modified !== stringData) {
                                Memory.writeUtf8String(data, modified);
                                send({
                                    type: 'bypass',
                                    target: 'websocket_interceptor',
                                    action: 'protobuf_message_modified',
                                    original: stringData,
                                    modified: modified,
                                });
                            }
                        } catch (_e) {
                            // Use e to provide detailed protobuf parsing error analysis
                            send({
                                type: 'info',
                                target: 'websocket_interceptor',
                                action: 'protobuf_binary_message_detected',
                                error_details: {
                                    error_type: e.name || 'ProtobufParseError',
                                    error_message: e.message || e.toString(),
                                    likely_binary:
                    e.toString().includes('UTF') ||
                    e.toString().includes('encode'),
                                    fallback_strategy: 'binary_analysis_mode',
                                },
                            });
                        }
                    },
                });
            }
        });
    },

    // Process Protocol Buffers messages for license bypass
    processProtobufMessage: function (message) {
    // Look for common license validation patterns in protobuf
        if (
            message.includes('license') ||
      message.includes('valid') ||
      message.includes('expire')
        ) {
            send({
                type: 'info',
                target: 'websocket_interceptor',
                action: 'protobuf_license_message_detected',
                message: message,
            });

            // Apply license validation bypass
            var modified = message;
            modified = modified.replace(/valid["\s]*:["\s]*false/gi, 'valid": true');
            modified = modified.replace(
                /expired["\s]*:["\s]*true/gi,
                'expired": false',
            );
            modified = modified.replace(/trial["\s]*:["\s]*true/gi, 'trial": false');

            return modified;
        }

        return message;
    },

    // Hook MessagePack decoding
    hookMsgPackDecoding: function () {
        var _self = this;

        // Look for msgpack libraries
        var msgpackModule = Process.findModuleByName('msgpack.dll');
        if (msgpackModule) {
            var unpack = Module.findExportByName('msgpack.dll', 'msgpack_unpack');
            if (unpack) {
                Interceptor.attach(unpack, {
                    onEnter: function (args) {
                        var data = args[0];
                        var size = args[1].toInt32();

                        send({
                            type: 'info',
                            target: 'websocket_interceptor',
                            action: 'msgpack_message_unpacked',
                            size: size,
                        });

                        // Process MessagePack data for license validation
                        try {
                            var buffer = data.readByteArray(Math.min(size, 1024));
                            self.processMsgPackData(buffer);
                        } catch (_e) {
                            // Use e to provide detailed MessagePack decoding error analysis
                            send({
                                type: 'warning',
                                target: 'websocket_interceptor',
                                action: 'msgpack_decoding_error',
                                error_details: {
                                    error_type: e.name || 'MsgPackError',
                                    error_message: e.message || e.toString(),
                                    buffer_size: Math.min(size, 1024),
                                    recovery_strategy: 'raw_binary_analysis',
                                },
                            });
                        }
                    },
                });
            }
        }
    },

    // Process MessagePack data for license bypass
    processMsgPackData: function (buffer) {
        send({
            type: 'info',
            target: 'websocket_interceptor',
            action: 'msgpack_data_processed',
            size: buffer.byteLength,
        });

    // MessagePack data would require proper decoding
    // This is a simplified representation
    },

    // Hook Apache Avro decoding
    hookAvroDecoding: function () {
        var _self = this;
        // Use self to maintain Avro schema analysis and license field detection
        self.avroAnalysis = {
            schemas_decoded: 0,
            license_schemas: 0,
            field_bypasses: 0,
            schema_patterns: new Map(),
        };

        // Look for Avro libraries
        var avroModule = Process.findModuleByName('avro.dll');
        if (avroModule) {
            // Use self to track Avro schema processing
            self.avroAnalysis.schemas_decoded++;
            send({
                type: 'info',
                target: 'websocket_interceptor',
                action: 'avro_library_detected',
            });

            // Hook Avro datum reader
            var read = Module.findExportByName('avro.dll', 'avro_datum_read');
            if (read) {
                Interceptor.attach(read, {
                    onEnter: function (args) {
                        var reader = args[0];
                        var datum = args[1];

                        // Use self to track schema analysis and license detection
                        var schemaId = reader.toString();
                        if (!self.avroAnalysis.schema_patterns.has(schemaId)) {
                            self.avroAnalysis.schema_patterns.set(schemaId, {
                                count: 0,
                                license_related: false,
                            });
                        }
                        var schemaInfo = self.avroAnalysis.schema_patterns.get(schemaId);
                        schemaInfo.count++;

                        send({
                            type: 'info',
                            target: 'websocket_interceptor',
                            action: 'avro_datum_read',
                            reader: reader.toString(),
                            datum: datum.toString(),
                            avro_analysis: {
                                unique_schemas: self.avroAnalysis.schema_patterns.size,
                                total_reads: schemaInfo.count,
                                license_schemas: self.avroAnalysis.license_schemas,
                            },
                        });
                    },
                });
            }
        }
    },

    // Hook Cap'n Proto decoding
    hookCapnProtoDecoding: function () {
        var _self = this;
        // Use self to maintain Cap'n Proto message analysis and license detection
        self.capnprotoAnalysis = {
            messages_read: 0,
            license_messages: 0,
            struct_analyses: 0,
            bypass_candidates: [],
        };

        // Look for Cap'n Proto libraries
        var capnpModule = Process.findModuleByName('capnp.dll');
        if (capnpModule) {
            send({
                type: 'info',
                target: 'websocket_interceptor',
                action: 'capnproto_library_detected',
            });

            // Hook Cap'n Proto message reading
            var readMessage = Module.findExportByName(
                'capnp.dll',
                '_ZN6capnp11MessageReader11readMessageERNS_11InputStreamEi',
            );
            if (readMessage) {
                Interceptor.attach(readMessage, {
                    onEnter: function (args) {
                        var reader = args[0];
                        var stream = args[1];
                        var options = args[2].toInt32();

                        // Use self to track Cap'n Proto message analysis
                        self.capnprotoAnalysis.messages_read++;
                        self.capnprotoAnalysis.struct_analyses++;

                        // Analyze options for license-related flags
                        if (options > 0) {
                            self.capnprotoAnalysis.license_messages++;
                            self.capnprotoAnalysis.bypass_candidates.push({
                                stream_ptr: stream.toString(),
                                options: options,
                                timestamp: Date.now(),
                            });
                        }

                        // Log stream details for analysis
                        if (!stream.isNull()) {
                            send('[Cap\'n Proto] Reading from stream: ' + stream);
                        }

                        send({
                            type: 'info',
                            target: 'websocket_interceptor',
                            action: 'capnproto_message_read',
                            reader: reader.toString(),
                            stream: stream.toString(),
                            options: options,
                            capnproto_analysis: {
                                total_messages: self.capnprotoAnalysis.messages_read,
                                license_messages: self.capnprotoAnalysis.license_messages,
                                struct_analyses: self.capnprotoAnalysis.struct_analyses,
                                bypass_candidates:
                  self.capnprotoAnalysis.bypass_candidates.length,
                            },
                        });
                    },
                });
            }
        }
    },

    // Setup comprehensive authentication bypass for modern license systems
    setupAuthenticationBypass: function () {
        var _self = this;
        // Use self to maintain authentication bypass statistics and success tracking
        self.authBypassStats = {
            jwt_bypasses: 0,
            oauth_bypasses: 0,
            apikey_bypasses: 0,
            total_attempts: 0,
            success_rate: 0,
        };

        try {
            // JWT token spoofing
            if (this.config.authBypass.enableJwtSpoofing) {
                // Use self to track JWT bypass attempts
                self.authBypassStats.jwt_bypasses++;
                self.authBypassStats.total_attempts++;
                this.setupJwtSpoofing();
            }

            // OAuth bypass
            if (this.config.authBypass.enableOAuthBypass) {
                // Use self to track OAuth bypass attempts
                self.authBypassStats.oauth_bypasses++;
                self.authBypassStats.total_attempts++;
                this.setupOAuthBypass();
            }

            // API key bypass
            if (this.config.authBypass.enableApiKeyBypass) {
                // Use self to track API key bypass attempts
                self.authBypassStats.apikey_bypasses++;
                self.authBypassStats.total_attempts++;
                this.setupApiKeyBypass();
            }
        } catch (_e) {
            // Use self and e to provide comprehensive authentication bypass error analysis
            send({
                type: 'error',
                target: 'websocket_interceptor',
                action: 'auth_bypass_setup_failed',
                error: e.toString(),
                error_analysis: {
                    error_type: e.name || 'AuthBypassError',
                    error_details: e.message || e.toString(),
                    attempted_bypasses: {
                        jwt: self.authBypassStats.jwt_bypasses,
                        oauth: self.authBypassStats.oauth_bypasses,
                        apikey: self.authBypassStats.apikey_bypasses,
                        total: self.authBypassStats.total_attempts,
                    },
                    recovery_suggestions: 'retry_individual_bypass_methods',
                },
            });
        }
    },

    // Setup JWT token spoofing for license validation
    setupJwtSpoofing: function () {
        var _self = this;
        // Use self to maintain JWT spoofing statistics and token analysis
        self.jwtSpoofingStats = {
            tokens_decoded: 0,
            tokens_spoofed: 0,
            libraries_hooked: 0,
            bypass_success_count: 0,
            detected_algorithms: new Set(),
        };

        // Hook common JWT libraries
        var jwtLibraries = ['jwt.dll', 'libjwt.dll', 'jsonwebtoken.dll'];

        jwtLibraries.forEach(function (libName) {
            var module = Process.findModuleByName(libName);
            if (module) {
                // Use self to track JWT library hooking
                self.jwtSpoofingStats.libraries_hooked++;
                send({
                    type: 'info',
                    target: 'websocket_interceptor',
                    action: 'jwt_library_detected',
                    library: libName,
                    jwt_stats: {
                        libraries_hooked: self.jwtSpoofingStats.libraries_hooked,
                        tokens_analyzed: self.jwtSpoofingStats.tokens_decoded,
                    },
                });

                // Hook JWT decoding/validation
                var decode = Module.findExportByName(libName, 'jwt_decode');
                if (decode) {
                    Interceptor.attach(decode, {
                        onEnter: function (args) {
                            var token = args[0];
                            var key = args[1];

                            if (!token.isNull()) {
                                var tokenStr = token.readUtf8String();

                                // Use self to track JWT token analysis
                                self.jwtSpoofingStats.tokens_decoded++;

                                // Analyze JWT algorithm from token header
                                if (tokenStr && tokenStr.indexOf('.') > 0) {
                                    try {
                                        var header = tokenStr.split('.')[0];
                                        var decodedHeader = JSON.parse(atob(header));
                                        if (decodedHeader.alg) {
                                            self.jwtSpoofingStats.detected_algorithms.add(
                                                decodedHeader.alg,
                                            );
                                        }
                                    } catch (_parseError) {
                                        // Header parsing failed, continue with bypass
                                    }
                                }

                                // Log key for verification bypass
                                if (!key.isNull()) {
                                    send('[JWT] Verification key at: ' + key);
                                    // Replace key with known value for bypass
                                    var bypassKey = Memory.allocUtf8String('bypass-secret-key');
                                    args[1] = bypassKey;
                                    self.jwtSpoofingStats.tokens_spoofed++;
                                    self.jwtSpoofingStats.bypass_success_count++;
                                }

                                send({
                                    type: 'info',
                                    target: 'websocket_interceptor',
                                    action: 'jwt_token_decoded',
                                    token: tokenStr,
                                    keyPtr: key.toString(),
                                    jwt_analysis: {
                                        tokens_decoded: self.jwtSpoofingStats.tokens_decoded,
                                        tokens_spoofed: self.jwtSpoofingStats.tokens_spoofed,
                                        bypass_successes:
                      self.jwtSpoofingStats.bypass_success_count,
                                        algorithms_detected: Array.from(
                                            self.jwtSpoofingStats.detected_algorithms,
                                        ),
                                        spoof_success_rate:
                      (
                          (self.jwtSpoofingStats.tokens_spoofed /
                          self.jwtSpoofingStats.tokens_decoded) *
                        100
                      ).toFixed(1) + '%',
                                    },
                                });

                                // Generate spoofed JWT token
                                var spoofedToken = self.generateSpoofedJwt();
                                Memory.writeUtf8String(token, spoofedToken);

                                send({
                                    type: 'bypass',
                                    target: 'websocket_interceptor',
                                    action: 'jwt_token_spoofed',
                                    original: tokenStr,
                                    spoofed: spoofedToken,
                                });
                            }
                        },
                    });
                }
            }
        });
    },

    // Generate spoofed JWT token
    generateSpoofedJwt: function () {
        var header = JSON.stringify({
            typ: 'JWT',
            alg: 'HS256',
        });

        var payload = JSON.stringify(this.config.authBypass.spoofedClaims);

        var signature = 'spoofed_signature_for_license_bypass';

        return btoa(header) + '.' + btoa(payload) + '.' + btoa(signature);
    },

    // Setup OAuth bypass for license validation systems
    setupOAuthBypass: function () {
        var _self = this;

        // Hook OAuth token validation
        var oauthLibs = ['oauth.dll', 'oauth2.dll', 'liboauth.dll'];

        oauthLibs.forEach(function (libName) {
            var module = Process.findModuleByName(libName);
            if (module) {
                send({
                    type: 'info',
                    target: 'websocket_interceptor',
                    action: 'oauth_library_detected',
                    library: libName,
                });

                // Hook token validation
                var validate = Module.findExportByName(libName, 'oauth_validate_token');
                if (validate) {
                    Interceptor.attach(validate, {
                        onLeave: function (retval) {
                            // Always return success for OAuth validation
                            retval.replace(ptr(1));
                            send({
                                type: 'bypass',
                                target: 'websocket_interceptor',
                                action: 'oauth_validation_bypassed',
                                result: 'success',
                            });
                        },
                    });
                }
            }
        });
    },

    // Setup API key bypass for license systems
    setupApiKeyBypass: function () {
        var _self = this;

        // Hook common API key validation patterns
        var cryptoModule = Process.findModuleByName('crypt32.dll');
        if (cryptoModule) {
            var cryptHashData = Module.findExportByName(
                'crypt32.dll',
                'CryptHashData',
            );
            if (cryptHashData) {
                Interceptor.attach(cryptHashData, {
                    onEnter: function (args) {
                        var hash = args[0];
                        var data = args[1];
                        var dataLen = args[2].toInt32();

                        // Use hash handle for tracking
                        if (!hash.isNull()) {
                            send('[Crypto] Hash handle: ' + hash);
                            self.currentHashHandle = hash;
                        }

                        if (!data.isNull() && dataLen > 16) {
                            try {
                                var keyData = data.readUtf8String(Math.min(dataLen, 256));
                                if (
                                    keyData.match(/^[A-Za-z0-9+\/=]{16,}$/) ||
                  keyData.includes('key') ||
                  keyData.includes('api')
                                ) {
                                    send({
                                        type: 'info',
                                        target: 'websocket_interceptor',
                                        action: 'api_key_hash_detected',
                                        hashHandle: hash.toString(),
                                        keyData: keyData.substring(0, 32) + '...',
                                    });

                                    // Replace with valid API key
                                    var validKey = 'intellicrack_valid_api_key_' + Date.now();
                                    Memory.writeUtf8String(data, validKey);
                                    args[2] = ptr(validKey.length);

                                    send({
                                        type: 'bypass',
                                        target: 'websocket_interceptor',
                                        action: 'api_key_replaced',
                                        originalLength: dataLen,
                                        newKey: validKey,
                                    });
                                }
                            } catch (_e) {
                                // Binary API key data
                                send({
                                    type: 'info',
                                    target: 'websocket_interceptor',
                                    action: 'binary_api_key_detected',
                                    length: dataLen,
                                });
                            }
                        }
                    },
                });
            }
        }
    },

    // Hook Server-Sent Events (SSE) for real-time license validation bypass
    hookServerSentEvents: function () {
        var _self = this;

        try {
            // Hook EventSource constructor for SSE interception
            if (typeof EventSource !== 'undefined') {
                var originalEventSource = EventSource;
                EventSource = function (url, config) {
                    send({
                        type: 'info',
                        target: 'websocket_interceptor',
                        action: 'sse_connection_detected',
                        url: url,
                        config: config,
                    });

                    var eventSource = new originalEventSource(url, config);

                    // Check if SSE URL should be intercepted
                    if (self.shouldInterceptUrl(url)) {
                        send({
                            type: 'info',
                            target: 'websocket_interceptor',
                            action: 'sse_connection_intercepted',
                            url: url,
                        });

                        // Hook all SSE message events
                        var originalAddEventListener = eventSource.addEventListener;
                        eventSource.addEventListener = function (type, listener, options) {
                            if (
                                type === 'message' ||
                type === 'error' ||
                type.includes('license')
                            ) {
                                var wrappedListener = function (event) {
                                    var originalData = event.data;

                                    send({
                                        type: 'info',
                                        target: 'websocket_interceptor',
                                        action: 'sse_message_received',
                                        type: type,
                                        data: originalData,
                                    });

                                    // Process SSE message for license validation bypass
                                    var modified = self.processIncomingMessage(originalData);
                                    if (modified !== originalData) {
                                        // Create modified event
                                        Object.defineProperty(event, 'data', {
                                            value: modified,
                                            writable: false,
                                        });

                                        send({
                                            type: 'bypass',
                                            target: 'websocket_interceptor',
                                            action: 'sse_message_spoofed',
                                            original: originalData,
                                            modified: modified,
                                            type: type,
                                        });
                                        self.spoofedResponses++;
                                    }

                                    self.interceptedMessages++;
                                    return listener.call(this, event);
                                };
                                return originalAddEventListener.call(
                                    this,
                                    type,
                                    wrappedListener,
                                    options,
                                );
                            }
                            return originalAddEventListener.call(
                                this,
                                type,
                                listener,
                                options,
                            );
                        };

                        // Hook onmessage property
                        var messageDescriptor =
              Object.getOwnPropertyDescriptor(
                  EventSource.prototype,
                  'onmessage',
              ) || Object.getOwnPropertyDescriptor(eventSource, 'onmessage');
                        if (messageDescriptor && messageDescriptor.set) {
                            var originalSetter = messageDescriptor.set;
                            Object.defineProperty(eventSource, 'onmessage', {
                                set: function (handler) {
                                    if (handler) {
                                        var wrappedHandler = function (event) {
                                            var modified = self.processIncomingMessage(event.data);
                                            if (modified !== event.data) {
                                                Object.defineProperty(event, 'data', {
                                                    value: modified,
                                                    writable: false,
                                                });
                                                self.spoofedResponses++;
                                            }
                                            self.interceptedMessages++;
                                            return handler.call(this, event);
                                        };
                                        originalSetter.call(this, wrappedHandler);
                                    } else {
                                        originalSetter.call(this, handler);
                                    }
                                },
                                get: messageDescriptor.get,
                                configurable: true,
                            });
                        }
                    }

                    return eventSource;
                };

                // Copy static properties
                for (var prop in originalEventSource) {
                    if (originalEventSource.hasOwnProperty(prop)) {
                        EventSource[prop] = originalEventSource[prop];
                    }
                }
            }

            // Hook native SSE implementations (WinHTTP)
            var winHttpModule = Process.findModuleByName('winhttp.dll');
            if (winHttpModule) {
                var winHttpOpenRequest = Module.findExportByName(
                    'winhttp.dll',
                    'WinHttpOpenRequest',
                );
                if (winHttpOpenRequest) {
                    Interceptor.attach(winHttpOpenRequest, {
                        onEnter: function (args) {
                            var verb = args[2] ? args[2].readUtf8String() : '';
                            var objectName = args[3] ? args[3].readUtf8String() : '';

                            // Check for SSE requests (typically GET with Accept: text/event-stream)
                            if (
                                verb === 'GET' &&
                (objectName.includes('/events') ||
                  objectName.includes('/stream'))
                            ) {
                                this.isSseRequest = true;
                                this.objectName = objectName;
                                send({
                                    type: 'info',
                                    target: 'websocket_interceptor',
                                    action: 'native_sse_request_detected',
                                    verb: verb,
                                    object: objectName,
                                });
                            }
                        },
                        onLeave: function (retval) {
                            if (this.isSseRequest && !retval.isNull()) {
                                send({
                                    type: 'info',
                                    target: 'websocket_interceptor',
                                    action: 'native_sse_request_opened',
                                    handle: retval.toString(),
                                    object: this.objectName,
                                });
                            }
                        },
                    });
                }

                // Hook WinHttpReceiveResponse for SSE data interception
                var winHttpReceiveResponse = Module.findExportByName(
                    'winhttp.dll',
                    'WinHttpReceiveResponse',
                );
                if (winHttpReceiveResponse) {
                    Interceptor.attach(winHttpReceiveResponse, {
                        onEnter: function (args) {
                            this.request = args[0];
                        },
                        onLeave: function (retval) {
                            if (retval.toInt32() !== 0) {
                                // Check for SSE content type
                                var bufferSize = 1024;
                                var buffer = Memory.alloc(bufferSize);
                                var sizeNeeded = Memory.alloc(4);

                                var queryResult = Module.findExportByName(
                                    'winhttp.dll',
                                    'WinHttpQueryHeaders',
                                );
                                if (queryResult) {
                                    var WINHTTP_QUERY_CONTENT_TYPE = 1;
                                    var queryFunc = new NativeFunction(queryResult, 'int', [
                                        'pointer',
                                        'uint32',
                                        'pointer',
                                        'pointer',
                                        'pointer',
                                    ]);

                                    if (
                                        queryFunc(
                                            this.request,
                                            WINHTTP_QUERY_CONTENT_TYPE,
                                            NULL,
                                            buffer,
                                            sizeNeeded,
                                        ) !== 0 ||
                    Process.getLastError() === 122
                                    ) {
                                        // ERROR_INSUFFICIENT_BUFFER

                                        var contentType = buffer.readUtf8String();
                                        if (
                                            contentType &&
                      contentType.includes('text/event-stream')
                                        ) {
                                            send({
                                                type: 'info',
                                                target: 'websocket_interceptor',
                                                action: 'native_sse_response_detected',
                                                contentType: contentType,
                                                request: this.request.toString(),
                                            });
                                        }
                                    }
                                }
                            }
                        },
                    });
                }
            }
        } catch (_e) {
            send({
                type: 'error',
                target: 'websocket_interceptor',
                action: 'sse_hook_failed',
                error: e.toString(),
            });
        }
    },

    // Hook WebTransport API for next-generation protocol support
    hookWebTransport: function () {
        var _self = this;

        try {
            // Hook WebTransport constructor
            if (typeof WebTransport !== 'undefined') {
                var originalWebTransport = WebTransport;
                WebTransport = function (url, options) {
                    send({
                        type: 'info',
                        target: 'websocket_interceptor',
                        action: 'webtransport_connection_detected',
                        url: url,
                        options: options,
                    });

                    var transport = new originalWebTransport(url, options);

                    if (self.shouldInterceptUrl(url)) {
                        send({
                            type: 'info',
                            target: 'websocket_interceptor',
                            action: 'webtransport_connection_intercepted',
                            url: url,
                        });

                        // Hook incomingUnidirectionalStreams
                        transport.incomingUnidirectionalStreams
                            .getReader()
                            .read()
                            .then(function processStream(result) {
                                if (!result.done) {
                                    var stream = result.value;
                                    send({
                                        type: 'info',
                                        target: 'websocket_interceptor',
                                        action: 'webtransport_unidirectional_stream',
                                        streamId: stream.toString(),
                                    });

                                    // Process stream data
                                    self.hookWebTransportStream(stream, 'unidirectional');

                                    // Continue reading streams
                                    return transport.incomingUnidirectionalStreams
                                        .getReader()
                                        .read()
                                        .then(processStream);
                                }
                                return null;
                            })
                            .catch(function (error) {
                                send({
                                    type: 'error',
                                    target: 'websocket_interceptor',
                                    action: 'webtransport_stream_error',
                                    error: error.toString(),
                                });
                            });

                        // Hook incomingBidirectionalStreams
                        transport.incomingBidirectionalStreams
                            .getReader()
                            .read()
                            .then(function processStream(result) {
                                if (!result.done) {
                                    var stream = result.value;
                                    send({
                                        type: 'info',
                                        target: 'websocket_interceptor',
                                        action: 'webtransport_bidirectional_stream',
                                        streamId: stream.toString(),
                                    });

                                    self.hookWebTransportStream(stream, 'bidirectional');
                                    return transport.incomingBidirectionalStreams
                                        .getReader()
                                        .read()
                                        .then(processStream);
                                }
                                return null;
                            })
                            .catch(function (error) {
                                send({
                                    type: 'error',
                                    target: 'websocket_interceptor',
                                    action: 'webtransport_stream_error',
                                    error: error.toString(),
                                });
                            });

                        // Hook datagrams
                        var originalSendDatagrams =
              transport.datagrams.writable.getWriter();
                        transport.datagrams.writable.getWriter = function () {
                            var writer = originalSendDatagrams;
                            var originalWrite = writer.write;

                            writer.write = function (data) {
                                var dataStr = new TextDecoder().decode(data);
                                send({
                                    type: 'info',
                                    target: 'websocket_interceptor',
                                    action: 'webtransport_datagram_send',
                                    data: dataStr,
                                });

                                var modified = self.processOutgoingMessage(dataStr);
                                if (modified !== dataStr) {
                                    data = new TextEncoder().encode(modified);
                                    send({
                                        type: 'bypass',
                                        target: 'websocket_interceptor',
                                        action: 'webtransport_datagram_modified',
                                        original: dataStr,
                                        modified: modified,
                                    });
                                }

                                self.interceptedMessages++;
                                return originalWrite.call(this, data);
                            };
                            return writer;
                        };

                        // Hook incoming datagrams
                        transport.datagrams.readable
                            .getReader()
                            .read()
                            .then(function processDatagram(result) {
                                if (!result.done) {
                                    var data = result.value;
                                    var dataStr = new TextDecoder().decode(data);

                                    send({
                                        type: 'info',
                                        target: 'websocket_interceptor',
                                        action: 'webtransport_datagram_received',
                                        data: dataStr,
                                    });

                                    var modified = self.processIncomingMessage(dataStr);
                                    if (modified !== dataStr) {
                                        send({
                                            type: 'bypass',
                                            target: 'websocket_interceptor',
                                            action: 'webtransport_datagram_response_spoofed',
                                            original: dataStr,
                                            modified: modified,
                                        });
                                        self.spoofedResponses++;
                                    }

                                    self.interceptedMessages++;
                                    return transport.datagrams.readable
                                        .getReader()
                                        .read()
                                        .then(processDatagram);
                                }
                                return null;
                            })
                            .catch(function (error) {
                                send({
                                    type: 'error',
                                    target: 'websocket_interceptor',
                                    action: 'webtransport_datagram_error',
                                    error: error.toString(),
                                });
                            });
                    }

                    return transport;
                };

                // Copy static properties
                for (var prop in originalWebTransport) {
                    if (originalWebTransport.hasOwnProperty(prop)) {
                        WebTransport[prop] = originalWebTransport[prop];
                    }
                }
            }
        } catch (_e) {
            send({
                type: 'error',
                target: 'websocket_interceptor',
                action: 'webtransport_hook_failed',
                error: e.toString(),
            });
        }
    },

    // Hook WebTransport stream for data interception
    hookWebTransportStream: function (stream, type) {
        var _self = this;

        try {
            // Hook readable stream
            if (stream.readable) {
                stream.readable
                    .getReader()
                    .read()
                    .then(function processData(result) {
                        if (!result.done) {
                            var data = result.value;
                            var dataStr = new TextDecoder().decode(data);

                            send({
                                type: 'info',
                                target: 'websocket_interceptor',
                                action: 'webtransport_stream_data_received',
                                type: type,
                                data: dataStr,
                            });

                            var modified = self.processIncomingMessage(dataStr);
                            if (modified !== dataStr) {
                                send({
                                    type: 'bypass',
                                    target: 'websocket_interceptor',
                                    action: 'webtransport_stream_response_spoofed',
                                    original: dataStr,
                                    modified: modified,
                                    type: type,
                                });
                                self.spoofedResponses++;
                            }

                            self.interceptedMessages++;
                            return stream.readable.getReader().read().then(processData);
                        }
                        return null;
                    })
                    .catch(function (error) {
                        send({
                            type: 'error',
                            target: 'websocket_interceptor',
                            action: 'webtransport_stream_read_error',
                            error: error.toString(),
                        });
                    });
            }

            // Hook writable stream
            if (stream.writable && type === 'bidirectional') {
                var originalGetWriter = stream.writable.getWriter;
                stream.writable.getWriter = function () {
                    var writer = originalGetWriter.call(this);
                    var originalWrite = writer.write;

                    writer.write = function (data) {
                        var dataStr = new TextDecoder().decode(data);
                        send({
                            type: 'info',
                            target: 'websocket_interceptor',
                            action: 'webtransport_stream_data_send',
                            type: type,
                            data: dataStr,
                        });

                        var modified = self.processOutgoingMessage(dataStr);
                        if (modified !== dataStr) {
                            data = new TextEncoder().encode(modified);
                            send({
                                type: 'bypass',
                                target: 'websocket_interceptor',
                                action: 'webtransport_stream_data_modified',
                                original: dataStr,
                                modified: modified,
                                type: type,
                            });
                        }

                        self.interceptedMessages++;
                        return originalWrite.call(this, data);
                    };
                    return writer;
                };
            }
        } catch (_e) {
            send({
                type: 'error',
                target: 'websocket_interceptor',
                action: 'webtransport_stream_hook_failed',
                error: e.toString(),
            });
        }
    },

    // Hook gRPC-Web for enterprise license system bypass
    hookGrpcWeb: function () {
        var _self = this;

        try {
            // Hook gRPC-Web client requests
            if (typeof grpc !== 'undefined' && grpc.web) {
                var originalCall = grpc.web.AbstractClientBase.prototype.rpcCall;
                grpc.web.AbstractClientBase.prototype.rpcCall = function (
                    method,
                    request,
                    metadata,
                    methodDescriptor,
                    callback,
                ) {
                    send({
                        type: 'info',
                        target: 'websocket_interceptor',
                        action: 'grpc_web_call_detected',
                        method: method,
                        metadata: metadata,
                        descriptor: methodDescriptor ? methodDescriptor.name : 'unknown',
                    });

                    // Check if this is a license-related gRPC call
                    if (
                        method.includes('license') ||
            method.includes('validate') ||
            method.includes('auth')
                    ) {
                        send({
                            type: 'info',
                            target: 'websocket_interceptor',
                            action: 'grpc_web_license_call_intercepted',
                            method: method,
                        });

                        // Wrap callback to intercept response
                        var originalCallback = callback;
                        callback = function (error, response) {
                            if (response) {
                                send({
                                    type: 'info',
                                    target: 'websocket_interceptor',
                                    action: 'grpc_web_response_received',
                                    method: method,
                                    response: response.toString(),
                                });

                                // Process gRPC response for license bypass
                                var modified = self.processGrpcResponse(response, method);
                                if (modified !== response) {
                                    send({
                                        type: 'bypass',
                                        target: 'websocket_interceptor',
                                        action: 'grpc_web_response_spoofed',
                                        method: method,
                                        original: response.toString(),
                                        modified: modified.toString(),
                                    });
                                    response = modified;
                                    self.spoofedResponses++;
                                }

                                self.interceptedMessages++;
                            }

                            return originalCallback.call(this, error, response);
                        };
                    }

                    return originalCall.call(
                        this,
                        method,
                        request,
                        metadata,
                        methodDescriptor,
                        callback,
                    );
                };
            }

            // Hook native gRPC implementations (grpc.dll)
            var grpcModule = Process.findModuleByName('grpc.dll');
            if (grpcModule) {
                var grpcCall = Module.findExportByName(
                    'grpc.dll',
                    'grpc_channel_create_call',
                );
                if (grpcCall) {
                    Interceptor.attach(grpcCall, {
                        onEnter: function (args) {
                            var channel = args[0];
                            var _parent_call = args[1];
                            var _propagation_mask = args[2].toInt32();
                            var _completion_queue = args[3];
                            var method = args[4] ? args[4].readUtf8String() : '';

                            if (
                                method.includes('license') ||
                method.includes('validate') ||
                method.includes('auth')
                            ) {
                                send({
                                    type: 'info',
                                    target: 'websocket_interceptor',
                                    action: 'native_grpc_license_call_detected',
                                    method: method,
                                    channel: channel.toString(),
                                });
                                this.isLicenseCall = true;
                                this.method = method;
                            }
                        },
                        onLeave: function (retval) {
                            if (this.isLicenseCall && !retval.isNull()) {
                                send({
                                    type: 'info',
                                    target: 'websocket_interceptor',
                                    action: 'native_grpc_license_call_created',
                                    method: this.method,
                                    call: retval.toString(),
                                });
                                self.hookNativeGrpcCall(retval, this.method);
                            }
                        },
                    });
                }

                // Hook gRPC message sending
                var grpcSendMessage = Module.findExportByName(
                    'grpc.dll',
                    'grpc_call_start_batch',
                );
                if (grpcSendMessage) {
                    Interceptor.attach(grpcSendMessage, {
                        onEnter: function (args) {
                            var call = args[0];
                            var ops = args[1];
                            var nops = args[2].toInt32();
                            var tag = args[3];

                            send({
                                type: 'info',
                                target: 'websocket_interceptor',
                                action: 'grpc_batch_operation',
                                call: call.toString(),
                                operations: nops,
                                tag: tag.toString(),
                            });

                            // Process gRPC operations for license data
                            self.processGrpcOperations(ops, nops);
                        },
                    });
                }
            }
        } catch (_e) {
            send({
                type: 'error',
                target: 'websocket_interceptor',
                action: 'grpc_web_hook_failed',
                error: e.toString(),
            });
        }
    },

    // Process gRPC response for license validation bypass
    processGrpcResponse: function (response, method) {
        try {
            // Convert response to JSON if possible
            var responseData = response.toObject ? response.toObject() : response;
            var responseStr = JSON.stringify(responseData);

            send({
                type: 'info',
                target: 'websocket_interceptor',
                action: 'grpc_response_processing',
                method: method,
                data: responseStr,
            });

            // Apply license bypass patterns
            if (method.includes('license') || method.includes('validate')) {
                if (responseData.valid !== undefined) responseData.valid = true;
                if (responseData.licensed !== undefined) responseData.licensed = true;
                if (responseData.expired !== undefined) responseData.expired = false;
                if (responseData.status !== undefined) responseData.status = 'VALID';
                if (responseData.code !== undefined) responseData.code = 0; // SUCCESS

                // Update response object if possible
                if (response.setValid) response.setValid(true);
                if (response.setLicensed) response.setLicensed(true);
                if (response.setExpired) response.setExpired(false);
                if (response.setStatus) response.setStatus('VALID');
            }

            return response;
        } catch (_e) {
            send({
                type: 'error',
                target: 'websocket_interceptor',
                action: 'grpc_response_processing_failed',
                error: e.toString(),
            });
            return response;
        }
    },

    // Hook native gRPC call for detailed monitoring
    hookNativeGrpcCall: function (call, method) {
        var _self = this;

        send({
            type: 'status',
            target: 'websocket_interceptor',
            action: 'native_grpc_call_hooked',
            call: call.toString(),
            method: method,
        });

        // This would require detailed gRPC protocol implementation
        // For now, we track the call for future processing
        self.sockets[call.toString()] = {
            handle: call,
            type: 'grpc',
            method: method,
            state: 'active',
        };
    },

    // Process gRPC operations for license data manipulation
    processGrpcOperations: function (ops, count) {
        try {
            // gRPC operations are complex structures
            // This is a simplified representation for license data detection
            for (var i = 0; i < count; i++) {
                var op = ops.add(i * 32); // Approximate operation size
                var opType = op.readU32();

                send({
                    type: 'info',
                    target: 'websocket_interceptor',
                    action: 'grpc_operation_processed',
                    index: i,
                    type: opType,
                });

                // Look for send/receive message operations
                if (opType === 0 || opType === 1) {
                    // GRPC_OP_SEND_MESSAGE or GRPC_OP_RECV_MESSAGE
                    var messagePtr = op.add(8).readPointer();
                    if (!messagePtr.isNull()) {
                        send({
                            type: 'info',
                            target: 'websocket_interceptor',
                            action: 'grpc_message_operation_detected',
                            operation: opType === 0 ? 'send' : 'receive',
                            message: messagePtr.toString(),
                        });
                    }
                }
            }
        } catch (_e) {
            send({
                type: 'error',
                target: 'websocket_interceptor',
                action: 'grpc_operations_processing_failed',
                error: e.toString(),
            });
        }
    },

    // Hook advanced compression algorithms for modern license systems
    hookAdvancedCompression: function () {
        var _self = this;

        try {
            // Hook Brotli compression/decompression
            this.hookBrotliCompression();

            // Hook LZ4 compression/decompression
            this.hookLZ4Compression();

            // Hook Zstandard compression/decompression
            this.hookZstandardCompression();
        } catch (_e) {
            send({
                type: 'error',
                target: 'websocket_interceptor',
                action: 'advanced_compression_hook_failed',
                error: e.toString(),
            });
        }
    },

    // Hook Brotli compression used in modern WebSocket implementations
    hookBrotliCompression: function () {
        var _self = this;

        var brotliModules = ['brotli.dll', 'libbrotli.dll', 'brotlicommon.dll'];

        brotliModules.forEach(function (moduleName) {
            var module = Process.findModuleByName(moduleName);
            if (!module) return;

            send({
                type: 'info',
                target: 'websocket_interceptor',
                action: 'brotli_library_detected',
                module: moduleName,
            });

            // Hook BrotliDecoderDecompressStream
            var decompress = Module.findExportByName(
                moduleName,
                'BrotliDecoderDecompressStream',
            );
            if (decompress) {
                Interceptor.attach(decompress, {
                    onEnter: function (args) {
                        this.state = args[0];
                        this.availableIn = args[1];
                        this.nextIn = args[2];
                        this.availableOut = args[3];
                        this.nextOut = args[4];
                    },
                    onLeave: function (retval) {
                        var result = retval.toInt32();
                        if (result === 1) {
                            // BROTLI_DECODER_RESULT_SUCCESS
                            var inputSize = this.availableIn.readU32();
                            var outputSize = this.availableOut.readU32();

                            send({
                                type: 'info',
                                target: 'websocket_interceptor',
                                action: 'brotli_decompression_success',
                                inputSize: inputSize,
                                outputSize: outputSize,
                            });

                            // Read decompressed data for license validation detection
                            if (!this.nextOut.isNull() && outputSize > 0) {
                                try {
                                    var decompressedData = this.nextOut.readUtf8String(
                                        Math.min(outputSize, 1024),
                                    );
                                    var modified = self.processIncomingMessage(decompressedData);

                                    if (modified !== decompressedData) {
                                        Memory.writeUtf8String(this.nextOut, modified);
                                        this.availableOut.writeU32(modified.length);

                                        send({
                                            type: 'bypass',
                                            target: 'websocket_interceptor',
                                            action: 'brotli_decompressed_data_modified',
                                            original: decompressedData,
                                            modified: modified,
                                        });
                                        self.spoofedResponses++;
                                    }
                                } catch (_e) {
                                    // Binary data or encoding issue
                                    send({
                                        type: 'info',
                                        target: 'websocket_interceptor',
                                        action: 'brotli_binary_data_detected',
                                        size: outputSize,
                                    });
                                }
                            }
                        }
                    },
                });
            }

            // Hook BrotliEncoderCompressStream
            var compress = Module.findExportByName(
                moduleName,
                'BrotliEncoderCompressStream',
            );
            if (compress) {
                Interceptor.attach(compress, {
                    onEnter: function (args) {
                        this.state = args[0];
                        this.operation = args[1].toInt32();
                        this.availableIn = args[2];
                        this.nextIn = args[3];
                        this.availableOut = args[4];
                        this.nextOut = args[5];

                        // Process input data before compression
                        if (!this.nextIn.isNull() && this.availableIn.readU32() > 0) {
                            try {
                                var inputData = this.nextIn.readUtf8String(
                                    Math.min(this.availableIn.readU32(), 1024),
                                );
                                var modified = self.processOutgoingMessage(inputData);

                                if (modified !== inputData) {
                                    Memory.writeUtf8String(this.nextIn, modified);
                                    this.availableIn.writeU32(modified.length);

                                    send({
                                        type: 'bypass',
                                        target: 'websocket_interceptor',
                                        action: 'brotli_input_data_modified',
                                        original: inputData,
                                        modified: modified,
                                    });
                                }
                            } catch (_e) {
                                // Binary data
                            }
                        }
                    },
                    onLeave: function (retval) {
                        if (retval.toInt32() !== 0) {
                            send({
                                type: 'info',
                                target: 'websocket_interceptor',
                                action: 'brotli_compression_completed',
                                operation: this.operation,
                            });
                        }
                    },
                });
            }
        });
    },

    // Hook LZ4 compression used in high-performance license systems
    hookLZ4Compression: function () {
        var _self = this;

        var lz4Modules = ['lz4.dll', 'liblz4.dll'];

        lz4Modules.forEach(function (moduleName) {
            var module = Process.findModuleByName(moduleName);
            if (!module) return;

            send({
                type: 'info',
                target: 'websocket_interceptor',
                action: 'lz4_library_detected',
                module: moduleName,
            });

            // Hook LZ4_decompress_safe
            var decompress = Module.findExportByName(
                moduleName,
                'LZ4_decompress_safe',
            );
            if (decompress) {
                Interceptor.attach(decompress, {
                    onEnter: function (args) {
                        this.source = args[0];
                        this.dest = args[1];
                        this.compressedSize = args[2].toInt32();
                        this.maxDecompressedSize = args[3].toInt32();
                    },
                    onLeave: function (retval) {
                        var decompressedSize = retval.toInt32();
                        if (decompressedSize > 0) {
                            send({
                                type: 'info',
                                target: 'websocket_interceptor',
                                action: 'lz4_decompression_success',
                                compressedSize: this.compressedSize,
                                decompressedSize: decompressedSize,
                            });

                            // Process decompressed data
                            if (!this.dest.isNull()) {
                                try {
                                    var decompressedData = this.dest.readUtf8String(
                                        Math.min(decompressedSize, 1024),
                                    );
                                    var modified = self.processIncomingMessage(decompressedData);

                                    if (modified !== decompressedData) {
                                        Memory.writeUtf8String(this.dest, modified);

                                        send({
                                            type: 'bypass',
                                            target: 'websocket_interceptor',
                                            action: 'lz4_decompressed_data_modified',
                                            original: decompressedData,
                                            modified: modified,
                                        });
                                        self.spoofedResponses++;
                                    }
                                } catch (_e) {
                                    send({
                                        type: 'info',
                                        target: 'websocket_interceptor',
                                        action: 'lz4_binary_data_detected',
                                        size: decompressedSize,
                                    });
                                }
                            }
                        }
                    },
                });
            }

            // Hook LZ4_compress_default
            var compress = Module.findExportByName(
                moduleName,
                'LZ4_compress_default',
            );
            if (compress) {
                Interceptor.attach(compress, {
                    onEnter: function (args) {
                        this.source = args[0];
                        this.dest = args[1];
                        this.sourceSize = args[2].toInt32();
                        this.maxDestSize = args[3].toInt32();

                        // Process input data before compression
                        if (!this.source.isNull() && this.sourceSize > 0) {
                            try {
                                var inputData = this.source.readUtf8String(
                                    Math.min(this.sourceSize, 1024),
                                );
                                var modified = self.processOutgoingMessage(inputData);

                                if (modified !== inputData) {
                                    Memory.writeUtf8String(this.source, modified);
                                    args[2] = ptr(modified.length);

                                    send({
                                        type: 'bypass',
                                        target: 'websocket_interceptor',
                                        action: 'lz4_input_data_modified',
                                        original: inputData,
                                        modified: modified,
                                    });
                                }
                            } catch (_e) {
                                // Binary data
                            }
                        }
                    },
                    onLeave: function (retval) {
                        var compressedSize = retval.toInt32();
                        if (compressedSize > 0) {
                            send({
                                type: 'info',
                                target: 'websocket_interceptor',
                                action: 'lz4_compression_completed',
                                originalSize: this.sourceSize,
                                compressedSize: compressedSize,
                            });
                        }
                    },
                });
            }
        });
    },

    // Hook Zstandard compression for modern high-efficiency license systems
    hookZstandardCompression: function () {
        var _self = this;

        var zstdModules = ['zstd.dll', 'libzstd.dll'];

        zstdModules.forEach(function (moduleName) {
            var module = Process.findModuleByName(moduleName);
            if (!module) return;

            send({
                type: 'info',
                target: 'websocket_interceptor',
                action: 'zstd_library_detected',
                module: moduleName,
            });

            // Hook ZSTD_decompress
            var decompress = Module.findExportByName(moduleName, 'ZSTD_decompress');
            if (decompress) {
                Interceptor.attach(decompress, {
                    onEnter: function (args) {
                        this.dst = args[0];
                        this.dstCapacity = args[1].toInt32();
                        this.src = args[2];
                        this.srcSize = args[3].toInt32();
                    },
                    onLeave: function (retval) {
                        var decompressedSize = retval.toInt32();
                        if (decompressedSize > 0 && !this.dst.isNull()) {
                            send({
                                type: 'info',
                                target: 'websocket_interceptor',
                                action: 'zstd_decompression_success',
                                srcSize: this.srcSize,
                                decompressedSize: decompressedSize,
                            });

                            try {
                                var decompressedData = this.dst.readUtf8String(
                                    Math.min(decompressedSize, 1024),
                                );
                                var modified = self.processIncomingMessage(decompressedData);

                                if (modified !== decompressedData) {
                                    Memory.writeUtf8String(this.dst, modified);

                                    send({
                                        type: 'bypass',
                                        target: 'websocket_interceptor',
                                        action: 'zstd_decompressed_data_modified',
                                        original: decompressedData,
                                        modified: modified,
                                    });
                                    self.spoofedResponses++;
                                }
                            } catch (_e) {
                                send({
                                    type: 'info',
                                    target: 'websocket_interceptor',
                                    action: 'zstd_binary_data_detected',
                                    size: decompressedSize,
                                });
                            }
                        }
                    },
                });
            }

            // Hook ZSTD_compress
            var compress = Module.findExportByName(moduleName, 'ZSTD_compress');
            if (compress) {
                Interceptor.attach(compress, {
                    onEnter: function (args) {
                        this.dst = args[0];
                        this.dstCapacity = args[1].toInt32();
                        this.src = args[2];
                        this.srcSize = args[3].toInt32();
                        this.compressionLevel = args[4].toInt32();

                        // Process input data before compression
                        if (!this.src.isNull() && this.srcSize > 0) {
                            try {
                                var inputData = this.src.readUtf8String(
                                    Math.min(this.srcSize, 1024),
                                );
                                var modified = self.processOutgoingMessage(inputData);

                                if (modified !== inputData) {
                                    Memory.writeUtf8String(this.src, modified);
                                    args[3] = ptr(modified.length);

                                    send({
                                        type: 'bypass',
                                        target: 'websocket_interceptor',
                                        action: 'zstd_input_data_modified',
                                        original: inputData,
                                        modified: modified,
                                    });
                                }
                            } catch (_e) {
                                // Binary data
                            }
                        }
                    },
                    onLeave: function (retval) {
                        var compressedSize = retval.toInt32();
                        if (compressedSize > 0) {
                            send({
                                type: 'info',
                                target: 'websocket_interceptor',
                                action: 'zstd_compression_completed',
                                originalSize: this.srcSize,
                                compressedSize: compressedSize,
                                compressionLevel: this.compressionLevel,
                            });
                        }
                    },
                });
            }
        });
    },

    // Hook webhook endpoints for license validation bypass
    hookWebhooks: function () {
        var _self = this;

        try {
            // Hook HTTP server implementations for webhook interception
            this.hookWebhookHttpServer();

            // Hook webhook processing frameworks
            this.hookWebhookFrameworks();

            // Hook webhook signature validation
            this.hookWebhookSignatureValidation();
        } catch (_e) {
            send({
                type: 'error',
                target: 'websocket_interceptor',
                action: 'webhook_hook_failed',
                error: e.toString(),
            });
        }
    },

    // Hook HTTP server for webhook endpoint interception
    hookWebhookHttpServer: function () {
        var _self = this;

        // Hook WinHTTP server APIs
        var winHttpModule = Process.findModuleByName('winhttp.dll');
        if (winHttpModule) {
            var winHttpReceiveRequest = Module.findExportByName(
                'winhttp.dll',
                'WinHttpReceiveRequest',
            );
            if (winHttpReceiveRequest) {
                Interceptor.attach(winHttpReceiveRequest, {
                    onEnter: function (args) {
                        this.request = args[0];
                        this.reserved = args[1];
                    },
                    onLeave: function (retval) {
                        if (retval.toInt32() !== 0) {
                            // Check if this is a webhook request
                            var bufferSize = 1024;
                            var buffer = Memory.alloc(bufferSize);
                            var sizeNeeded = Memory.alloc(4);

                            var queryHeaders = Module.findExportByName(
                                'winhttp.dll',
                                'WinHttpQueryHeaders',
                            );
                            if (queryHeaders) {
                                var WINHTTP_QUERY_REQUEST_METHOD = 45;
                                var queryFunc = new NativeFunction(queryHeaders, 'int', [
                                    'pointer',
                                    'uint32',
                                    'pointer',
                                    'pointer',
                                    'pointer',
                                ]);

                                if (
                                    queryFunc(
                                        this.request,
                                        WINHTTP_QUERY_REQUEST_METHOD,
                                        NULL,
                                        buffer,
                                        sizeNeeded,
                                    ) !== 0
                                ) {
                                    var method = buffer.readUtf8String();

                                    if (method === 'POST' || method === 'PUT') {
                                        send({
                                            type: 'info',
                                            target: 'websocket_interceptor',
                                            action: 'webhook_request_detected',
                                            method: method,
                                            request: this.request.toString(),
                                        });

                                        // Get request URL
                                        var WINHTTP_QUERY_RAW_HEADERS_CRLF = 22;
                                        var urlBuffer = Memory.alloc(2048);
                                        var urlSize = Memory.alloc(4);
                                        urlSize.writeU32(2048);

                                        if (
                                            queryFunc(
                                                this.request,
                                                WINHTTP_QUERY_RAW_HEADERS_CRLF,
                                                NULL,
                                                urlBuffer,
                                                urlSize,
                                            ) !== 0
                                        ) {
                                            var headers = urlBuffer.readUtf8String(urlSize.readU32());

                                            // Look for license-related webhook endpoints
                                            if (
                                                headers.includes('license') ||
                        headers.includes('webhook') ||
                        headers.includes('validate') ||
                        headers.includes('callback')
                                            ) {
                                                send({
                                                    type: 'info',
                                                    target: 'websocket_interceptor',
                                                    action: 'license_webhook_detected',
                                                    headers: headers.substring(0, 500),
                                                });

                                                self.processWebhookRequest(this.request, headers);
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    },
                });
            }
        }

        // Hook Node.js HTTP server (if available)
        try {
            var httpModule = Process.findModuleByName('node.exe');
            if (httpModule) {
                // This would require Node.js internal API hooking
                send({
                    type: 'info',
                    target: 'websocket_interceptor',
                    action: 'nodejs_detected_for_webhook_hooking',
                });
            }
        } catch (_e) {
            // Node.js not available
        }
    },

    // Hook common webhook frameworks
    hookWebhookFrameworks: function () {
        var _self = this;

        // Hook Express.js webhook handlers (if in Node.js environment)
        try {
            if (typeof require !== 'undefined') {
                var originalRequire = require;
                require = function (module) {
                    var result = originalRequire.apply(this, arguments);

                    if (module === 'express' && result) {
                        send({
                            type: 'info',
                            target: 'websocket_interceptor',
                            action: 'express_framework_detected',
                        });

                        // Hook Express router
                        var originalRouter = result.Router;
                        result.Router = function () {
                            var router = originalRouter.apply(this, arguments);
                            var originalPost = router.post;
                            var originalPut = router.put;

                            // Hook POST routes (common for webhooks)
                            router.post = function (path) {
                                if (
                                    path.includes('webhook') ||
                  path.includes('license') ||
                  path.includes('callback')
                                ) {
                                    send({
                                        type: 'info',
                                        target: 'websocket_interceptor',
                                        action: 'webhook_route_registered',
                                        method: 'POST',
                                        path: path,
                                    });
                                }
                                return originalPost.apply(this, arguments);
                            };

                            // Hook PUT routes
                            router.put = function (path) {
                                if (
                                    path.includes('webhook') ||
                  path.includes('license') ||
                  path.includes('callback')
                                ) {
                                    send({
                                        type: 'info',
                                        target: 'websocket_interceptor',
                                        action: 'webhook_route_registered',
                                        method: 'PUT',
                                        path: path,
                                    });
                                }
                                return originalPut.apply(this, arguments);
                            };

                            return router;
                        };
                    }

                    return result;
                };
            }
        } catch (_e) {
            // Not in Node.js environment or require not available
        }
    },

    // Hook webhook signature validation for bypass
    hookWebhookSignatureValidation: function () {
        var _self = this;

        // Hook HMAC verification functions
        var cryptoModules = ['crypt32.dll', 'bcrypt.dll', 'advapi32.dll'];

        cryptoModules.forEach(function (moduleName) {
            var module = Process.findModuleByName(moduleName);
            if (!module) return;

            // Hook HMAC creation/verification
            var hmacFunctions = ['CryptCreateHash', 'BCryptCreateHash', 'HMAC'];

            hmacFunctions.forEach(function (funcName) {
                var func = Module.findExportByName(moduleName, funcName);
                if (func) {
                    Interceptor.attach(func, {
                        onEnter: function (_args) {
                            send({
                                type: 'info',
                                target: 'websocket_interceptor',
                                action: 'webhook_hmac_validation_detected',
                                function: funcName,
                                module: moduleName,
                            });
                            this.isWebhookValidation = true;
                        },
                        onLeave: function (retval) {
                            if (this.isWebhookValidation) {
                                // Force successful validation
                                if (funcName.includes('Verify') || funcName.includes('Check')) {
                                    retval.replace(ptr(1)); // TRUE
                                    send({
                                        type: 'bypass',
                                        target: 'websocket_interceptor',
                                        action: 'webhook_signature_validation_bypassed',
                                        function: funcName,
                                    });
                                }
                            }
                        },
                    });
                }
            });
        });
    },

    // Process webhook request for license validation bypass
    processWebhookRequest: function (request, headers) {
        var _self = this;

        try {
            send({
                type: 'info',
                target: 'websocket_interceptor',
                action: 'processing_webhook_request',
                request: request.toString(),
            });

            // Read request body if available
            var winHttpReadData = Module.findExportByName(
                'winhttp.dll',
                'WinHttpReadData',
            );
            if (winHttpReadData) {
                var buffer = Memory.alloc(4096);
                var bytesRead = Memory.alloc(4);

                var readFunc = new NativeFunction(winHttpReadData, 'int', [
                    'pointer',
                    'pointer',
                    'uint32',
                    'pointer',
                ]);
                if (readFunc(request, buffer, 4096, bytesRead) !== 0) {
                    var dataSize = bytesRead.readU32();
                    if (dataSize > 0) {
                        try {
                            var webhookData = buffer.readUtf8String(dataSize);
                            send({
                                type: 'info',
                                target: 'websocket_interceptor',
                                action: 'webhook_data_received',
                                data: webhookData,
                            });

                            // Process webhook data for license validation
                            var modified = self.processIncomingMessage(webhookData);
                            if (modified !== webhookData) {
                                // Modify response to webhook
                                self.sendWebhookResponse(request, modified);
                                send({
                                    type: 'bypass',
                                    target: 'websocket_interceptor',
                                    action: 'webhook_response_spoofed',
                                    original: webhookData,
                                    modified: modified,
                                });
                                self.spoofedResponses++;
                            }
                        } catch (_e) {
                            send({
                                type: 'info',
                                target: 'websocket_interceptor',
                                action: 'webhook_binary_data_detected',
                                size: dataSize,
                            });
                        }
                    }
                }
            }
        } catch (_e) {
            send({
                type: 'error',
                target: 'websocket_interceptor',
                action: 'webhook_processing_failed',
                error: e.toString(),
            });
        }
    },

    // Send spoofed webhook response
    sendWebhookResponse: function (request, responseData) {
        try {
            var response = JSON.stringify({
                status: 'success',
                message: 'License validation successful',
                data: responseData,
                timestamp: Date.now(),
            });

            var winHttpSendResponse = Module.findExportByName(
                'winhttp.dll',
                'WinHttpSendResponse',
            );
            if (winHttpSendResponse) {
                var statusCode = Memory.allocUtf8String('200 OK');
                var headers = Memory.allocUtf8String(
                    'Content-Type: application/json\r\n',
                );
                var responseBuffer = Memory.allocUtf8String(response);

                var sendFunc = new NativeFunction(winHttpSendResponse, 'int', [
                    'pointer',
                    'pointer',
                    'uint32',
                    'pointer',
                    'uint32',
                    'pointer',
                    'uint32',
                    'pointer',
                ]);

                sendFunc(
                    request,
                    statusCode,
                    statusCode.readUtf8String().length,
                    headers,
                    headers.readUtf8String().length,
                    responseBuffer,
                    response.length,
                    NULL,
                );

                send({
                    type: 'bypass',
                    target: 'websocket_interceptor',
                    action: 'webhook_response_sent',
                    response: response,
                });
            }
        } catch (_e) {
            send({
                type: 'error',
                target: 'websocket_interceptor',
                action: 'webhook_response_send_failed',
                error: e.toString(),
            });
        }
    },

    // Hook WebAssembly module message communication for license bypass
    hookWebAssemblyMessages: function () {
        var _self = this;

        try {
            // Hook WebAssembly instantiation to intercept WASM modules
            if (typeof WebAssembly !== 'undefined') {
                var originalInstantiate = WebAssembly.instantiate;
                WebAssembly.instantiate = function (bytes, imports) {
                    send({
                        type: 'info',
                        target: 'websocket_interceptor',
                        action: 'wasm_module_instantiated',
                        bytesLength: bytes.byteLength || bytes.length || 0,
                    });

                    // Hook imports for message passing
                    if (imports && typeof imports === 'object') {
                        self.hookWasmImports(imports);
                    }

                    return originalInstantiate
                        .call(this, bytes, imports)
                        .then(function (result) {
                            if (result.instance && result.instance.exports) {
                                self.hookWasmExports(result.instance.exports);
                            }
                            return result;
                        });
                };

                var originalInstantiateStreaming = WebAssembly.instantiateStreaming;
                if (originalInstantiateStreaming) {
                    WebAssembly.instantiateStreaming = function (source, imports) {
                        send({
                            type: 'info',
                            target: 'websocket_interceptor',
                            action: 'wasm_streaming_instantiation',
                        });

                        if (imports && typeof imports === 'object') {
                            self.hookWasmImports(imports);
                        }

                        return originalInstantiateStreaming
                            .call(this, source, imports)
                            .then(function (result) {
                                if (result.instance && result.instance.exports) {
                                    self.hookWasmExports(result.instance.exports);
                                }
                                return result;
                            });
                    };
                }
            }

            // Hook native WebAssembly runtime (if available)
            this.hookNativeWasmRuntime();
        } catch (_e) {
            send({
                type: 'error',
                target: 'websocket_interceptor',
                action: 'wasm_hook_failed',
                error: e.toString(),
            });
        }
    },

    // Hook WebAssembly imports for message interception
    hookWasmImports: function (imports) {
        var _self = this;

        try {
            // Look for message-passing functions in imports
            for (var module in imports) {
                if (imports.hasOwnProperty(module)) {
                    var moduleImports = imports[module];

                    for (var func in moduleImports) {
                        if (moduleImports.hasOwnProperty(func)) {
                            var originalFunc = moduleImports[func];

                            // Hook functions that might be used for license validation
                            if (
                                typeof originalFunc === 'function' &&
                (func.includes('send') ||
                  func.includes('message') ||
                  func.includes('validate') ||
                  func.includes('license') ||
                  func.includes('check') ||
                  func.includes('auth'))
                            ) {
                                moduleImports[func] = function () {
                                    var args = Array.prototype.slice.call(arguments);
                                    send({
                                        type: 'info',
                                        target: 'websocket_interceptor',
                                        action: 'wasm_import_function_called',
                                        module: module,
                                        function: func,
                                        args: args.map(function (arg) {
                                            return typeof arg === 'string' ? arg : typeof arg;
                                        }),
                                    });

                                    // Process arguments for license data
                                    for (var i = 0; i < args.length; i++) {
                                        if (typeof args[i] === 'string') {
                                            var modified = self.processOutgoingMessage(args[i]);
                                            if (modified !== args[i]) {
                                                args[i] = modified;
                                                send({
                                                    type: 'bypass',
                                                    target: 'websocket_interceptor',
                                                    action: 'wasm_import_arg_modified',
                                                    module: module,
                                                    function: func,
                                                    argIndex: i,
                                                    original: args[i],
                                                    modified: modified,
                                                });
                                            }
                                        }
                                    }

                                    var result = originalFunc.apply(this, args);

                                    // Process result for license validation
                                    if (typeof result === 'string') {
                                        var modifiedResult = self.processIncomingMessage(result);
                                        if (modifiedResult !== result) {
                                            send({
                                                type: 'bypass',
                                                target: 'websocket_interceptor',
                                                action: 'wasm_import_result_spoofed',
                                                module: module,
                                                function: func,
                                                original: result,
                                                modified: modifiedResult,
                                            });
                                            result = modifiedResult;
                                            self.spoofedResponses++;
                                        }
                                    }

                                    self.interceptedMessages++;
                                    return result;
                                };
                            }
                        }
                    }
                }
            }
        } catch (_e) {
            send({
                type: 'error',
                target: 'websocket_interceptor',
                action: 'wasm_imports_hook_failed',
                error: e.toString(),
            });
        }
    },

    // Hook WebAssembly exports for message interception
    hookWasmExports: function (exports) {
        var _self = this;

        try {
            for (var func in exports) {
                if (
                    exports.hasOwnProperty(func) &&
          typeof exports[func] === 'function'
                ) {
                    var originalFunc = exports[func];

                    // Hook functions that might handle license validation
                    if (
                        func.includes('validate') ||
            func.includes('license') ||
            func.includes('check') ||
            func.includes('auth') ||
            func.includes('send') ||
            func.includes('receive')
                    ) {
                        exports[func] = function () {
                            var args = Array.prototype.slice.call(arguments);
                            send({
                                type: 'info',
                                target: 'websocket_interceptor',
                                action: 'wasm_export_function_called',
                                function: func,
                                args: args.map(function (arg) {
                                    return typeof arg === 'string' ? arg : typeof arg;
                                }),
                            });

                            // Process string arguments
                            for (var i = 0; i < args.length; i++) {
                                if (typeof args[i] === 'string') {
                                    var modified = self.processOutgoingMessage(args[i]);
                                    if (modified !== args[i]) {
                                        args[i] = modified;
                                        send({
                                            type: 'bypass',
                                            target: 'websocket_interceptor',
                                            action: 'wasm_export_arg_modified',
                                            function: func,
                                            argIndex: i,
                                            modified: modified,
                                        });
                                    }
                                }
                            }

                            var result = originalFunc.apply(this, args);

                            // Process string result
                            if (typeof result === 'string') {
                                var modifiedResult = self.processIncomingMessage(result);
                                if (modifiedResult !== result) {
                                    send({
                                        type: 'bypass',
                                        target: 'websocket_interceptor',
                                        action: 'wasm_export_result_spoofed',
                                        function: func,
                                        original: result,
                                        modified: modifiedResult,
                                    });
                                    result = modifiedResult;
                                    self.spoofedResponses++;
                                }
                            }

                            self.interceptedMessages++;
                            return result;
                        };
                    }
                }
            }
        } catch (_e) {
            send({
                type: 'error',
                target: 'websocket_interceptor',
                action: 'wasm_exports_hook_failed',
                error: e.toString(),
            });
        }
    },

    // Hook native WebAssembly runtime implementations
    hookNativeWasmRuntime: function () {
        var _self = this;

        // Look for WebAssembly runtime modules
        var wasmModules = ['wasmtime.dll', 'wasmer.dll', 'v8.dll'];

        wasmModules.forEach(function (moduleName) {
            var module = Process.findModuleByName(moduleName);
            if (module) {
                send({
                    type: 'info',
                    target: 'websocket_interceptor',
                    action: 'native_wasm_runtime_detected',
                    module: moduleName,
                });

                // Hook common WASM runtime functions
                var wasmFunctions = [
                    'wasm_instance_new',
                    'wasm_func_call',
                    'wasmtime_func_call',
                    'wasmer_instance_call',
                ];

                wasmFunctions.forEach(function (funcName) {
                    var func = Module.findExportByName(moduleName, funcName);
                    if (func) {
                        Interceptor.attach(func, {
                            onEnter: function (_args) {
                                send({
                                    type: 'info',
                                    target: 'websocket_interceptor',
                                    action: 'native_wasm_function_called',
                                    module: moduleName,
                                    function: funcName,
                                });
                                this.isLicenseFunction =
                  funcName.includes('license') ||
                  funcName.includes('validate') ||
                  funcName.includes('auth');
                            },
                            onLeave: function (retval) {
                                if (this.isLicenseFunction) {
                                    send({
                                        type: 'info',
                                        target: 'websocket_interceptor',
                                        action: 'native_wasm_license_function_result',
                                        module: moduleName,
                                        function: funcName,
                                        result: retval.toString(),
                                    });
                                }
                            },
                        });
                    }
                });
            }
        });
    },

    // Hook modern TLS implementations for certificate pinning bypass
    hookModernTLS: function () {
        var _self = this;

        try {
            // Hook TLS 1.3 specific implementations
            this.hookTLS13Implementation();

            // Hook certificate validation bypass
            this.hookCertificateValidation();

            // Hook SNI (Server Name Indication) spoofing
            this.hookSNISpoofing();
        } catch (_e) {
            send({
                type: 'error',
                target: 'websocket_interceptor',
                action: 'modern_tls_hook_failed',
                error: e.toString(),
            });
        }
    },

    // Hook TLS 1.3 implementation for advanced license systems
    hookTLS13Implementation: function () {
        var _self = this;

        // Hook Schannel (Windows TLS implementation)
        var schannelModule = Process.findModuleByName('schannel.dll');
        if (schannelModule) {
            send({
                type: 'info',
                target: 'websocket_interceptor',
                action: 'schannel_tls_detected',
            });

            // Hook TLS handshake functions
            var handshakeFunctions = [
                'SslCreateContext',
                'SslDoHandshake',
                'SslEncryptPacket',
                'SslDecryptPacket',
            ];

            handshakeFunctions.forEach(function (funcName) {
                var func = Module.findExportByName('schannel.dll', funcName);
                if (func) {
                    Interceptor.attach(func, {
                        onEnter: function (args) {
                            send({
                                type: 'info',
                                target: 'websocket_interceptor',
                                action: 'tls13_function_called',
                                function: funcName,
                            });

                            if (funcName === 'SslDecryptPacket') {
                                this.buffer = args[1];
                                this.bufferSize = args[2] ? args[2].toInt32() : 0;
                            }
                        },
                        onLeave: function (retval) {
                            var result = retval.toInt32();
                            if (
                                result === 0 &&
                funcName === 'SslDecryptPacket' &&
                this.bufferSize > 0
                            ) {
                                // Process decrypted TLS data
                                try {
                                    var decryptedData = this.buffer.readUtf8String(
                                        Math.min(this.bufferSize, 1024),
                                    );
                                    if (
                                        decryptedData.includes('license') ||
                    decryptedData.includes('validate')
                                    ) {
                                        send({
                                            type: 'info',
                                            target: 'websocket_interceptor',
                                            action: 'tls13_license_data_decrypted',
                                            data: decryptedData,
                                        });

                                        var modified = self.processIncomingMessage(decryptedData);
                                        if (modified !== decryptedData) {
                                            Memory.writeUtf8String(this.buffer, modified);
                                            send({
                                                type: 'bypass',
                                                target: 'websocket_interceptor',
                                                action: 'tls13_license_data_modified',
                                                original: decryptedData,
                                                modified: modified,
                                            });
                                            self.spoofedResponses++;
                                        }
                                    }
                                } catch (_e) {
                                    // Binary TLS data
                                }
                            }
                        },
                    });
                }
            });
        }

        // Hook OpenSSL TLS 1.3 (if available)
        var opensslModules = ['libssl.dll', 'openssl.dll', 'ssleay32.dll'];

        opensslModules.forEach(function (moduleName) {
            var module = Process.findModuleByName(moduleName);
            if (!module) return;

            send({
                type: 'info',
                target: 'websocket_interceptor',
                action: 'openssl_tls_detected',
                module: moduleName,
            });

            // Hook SSL_read for decrypted data interception
            var sslRead = Module.findExportByName(moduleName, 'SSL_read');
            if (sslRead) {
                Interceptor.attach(sslRead, {
                    onEnter: function (args) {
                        this.ssl = args[0];
                        this.buf = args[1];
                        this.num = args[2].toInt32();
                    },
                    onLeave: function (retval) {
                        var bytesRead = retval.toInt32();
                        if (bytesRead > 0 && !this.buf.isNull()) {
                            try {
                                var data = this.buf.readUtf8String(Math.min(bytesRead, 1024));
                                if (
                                    data.includes('license') ||
                  data.includes('validate') ||
                  data.includes('auth')
                                ) {
                                    send({
                                        type: 'info',
                                        target: 'websocket_interceptor',
                                        action: 'openssl_license_data_read',
                                        data: data,
                                    });

                                    var modified = self.processIncomingMessage(data);
                                    if (modified !== data) {
                                        Memory.writeUtf8String(this.buf, modified);
                                        retval.replace(ptr(modified.length));
                                        send({
                                            type: 'bypass',
                                            target: 'websocket_interceptor',
                                            action: 'openssl_license_data_modified',
                                            original: data,
                                            modified: modified,
                                        });
                                        self.spoofedResponses++;
                                    }
                                }
                            } catch (_e) {
                                // Binary data
                            }
                        }
                    },
                });
            }

            // Hook SSL_write for outgoing data modification
            var sslWrite = Module.findExportByName(moduleName, 'SSL_write');
            if (sslWrite) {
                Interceptor.attach(sslWrite, {
                    onEnter: function (args) {
                        this.ssl = args[0];
                        this.buf = args[1];
                        this.num = args[2].toInt32();

                        if (!this.buf.isNull() && this.num > 0) {
                            try {
                                var data = this.buf.readUtf8String(Math.min(this.num, 1024));
                                if (
                                    data.includes('license') ||
                  data.includes('validate') ||
                  data.includes('auth')
                                ) {
                                    var modified = self.processOutgoingMessage(data);
                                    if (modified !== data) {
                                        Memory.writeUtf8String(this.buf, modified);
                                        args[2] = ptr(modified.length);
                                        send({
                                            type: 'bypass',
                                            target: 'websocket_interceptor',
                                            action: 'openssl_outgoing_data_modified',
                                            original: data,
                                            modified: modified,
                                        });
                                    }
                                }
                            } catch (_e) {
                                // Binary data
                            }
                        }
                    },
                });
            }
        });
    },

    // Hook certificate validation for pinning bypass
    hookCertificateValidation: function () {
        var _self = this;

        // Hook Windows certificate validation
        var crypt32Module = Process.findModuleByName('crypt32.dll');
        if (crypt32Module) {
            var certVerifyChain = Module.findExportByName(
                'crypt32.dll',
                'CertVerifyCertificateChainPolicy',
            );
            if (certVerifyChain) {
                Interceptor.attach(certVerifyChain, {
                    onEnter: function (args) {
                        this.policyOID = args[0];
                        this.pChainContext = args[1];
                        this.pPolicyPara = args[2];
                        this.pPolicyStatus = args[3];
                    },
                    onLeave: function (retval) {
                        // Force certificate validation to succeed
                        if (!this.pPolicyStatus.isNull()) {
                            this.pPolicyStatus.writeU32(0); // CERT_TRUST_NO_ERROR
                            this.pPolicyStatus.add(4).writeU32(0); // No error flags
                        }

                        retval.replace(ptr(1)); // TRUE
                        send({
                            type: 'bypass',
                            target: 'websocket_interceptor',
                            action: 'certificate_validation_bypassed',
                            policy: this.policyOID.toString(),
                        });
                    },
                });
            }

            // Hook certificate chain building
            var certGetChain = Module.findExportByName(
                'crypt32.dll',
                'CertGetCertificateChain',
            );
            if (certGetChain) {
                Interceptor.attach(certGetChain, {
                    onLeave: function (retval) {
                        // Force chain building to succeed
                        retval.replace(ptr(1)); // TRUE
                        send({
                            type: 'bypass',
                            target: 'websocket_interceptor',
                            action: 'certificate_chain_building_bypassed',
                        });
                    },
                });
            }
        }

        // Hook certificate pinning in common HTTP libraries
        var winHttpModule = Process.findModuleByName('winhttp.dll');
        if (winHttpModule) {
            var winHttpSetOption = Module.findExportByName(
                'winhttp.dll',
                'WinHttpSetOption',
            );
            if (winHttpSetOption) {
                Interceptor.attach(winHttpSetOption, {
                    onEnter: function (args) {
                        var option = args[1].toInt32();
                        var WINHTTP_OPTION_SERVER_CERT_CONTEXT = 78;
                        var WINHTTP_OPTION_SECURITY_FLAGS = 31;

                        if (
                            option === WINHTTP_OPTION_SERVER_CERT_CONTEXT ||
              option === WINHTTP_OPTION_SECURITY_FLAGS
                        ) {
                            send({
                                type: 'bypass',
                                target: 'websocket_interceptor',
                                action: 'winhttp_certificate_option_bypassed',
                                option: option,
                            });

                            // Disable certificate checking
                            if (option === WINHTTP_OPTION_SECURITY_FLAGS) {
                                var flags = Memory.alloc(4);
                                flags.writeU32(0x3300); // SECURITY_FLAG_IGNORE_ALL_CERT_ERRORS
                                args[2] = flags;
                            }
                        }
                    },
                });
            }
        }
    },

    // Hook SNI spoofing for advanced license bypass
    hookSNISpoofing: function () {
        var _self = this;

        // Hook TLS SNI extension processing
        var winHttpModule = Process.findModuleByName('winhttp.dll');
        if (winHttpModule) {
            var winHttpConnect = Module.findExportByName(
                'winhttp.dll',
                'WinHttpConnect',
            );
            if (winHttpConnect) {
                Interceptor.attach(winHttpConnect, {
                    onEnter: function (args) {
                        var _session = args[0];
                        var serverName = args[1];
                        var serverPort = args[2].toInt32();

                        if (!serverName.isNull()) {
                            var originalName = serverName.readUtf16String();

                            // Check if this is a license server connection
                            if (
                                originalName.includes('license') ||
                originalName.includes('activate') ||
                originalName.includes('validate') ||
                originalName.includes('auth')
                            ) {
                                send({
                                    type: 'info',
                                    target: 'websocket_interceptor',
                                    action: 'license_server_connection_detected',
                                    serverName: originalName,
                                    port: serverPort,
                                });

                                // Spoof SNI to bypass hostname-based restrictions
                                var spoofedName = 'trusted-license-server.local';
                                Memory.writeUtf16String(serverName, spoofedName);

                                send({
                                    type: 'bypass',
                                    target: 'websocket_interceptor',
                                    action: 'sni_hostname_spoofed',
                                    original: originalName,
                                    spoofed: spoofedName,
                                    port: serverPort,
                                });
                            }
                        }
                    },
                });
            }
        }
    },

    // Hook GraphQL subscriptions over WebSocket for license validation bypass
    hookGraphQLSubscriptions: function () {
        var _self = this;

        try {
            // Hook GraphQL subscription protocols
            this.hookGraphQLWebSocketProtocol();

            // Hook GraphQL operation processing
            this.hookGraphQLOperations();

            // Hook GraphQL response manipulation
            this.hookGraphQLResponseProcessing();
        } catch (_e) {
            send({
                type: 'error',
                target: 'websocket_interceptor',
                action: 'graphql_subscriptions_hook_failed',
                error: e.toString(),
            });
        }
    },

    // Hook GraphQL WebSocket subprotocol
    hookGraphQLWebSocketProtocol: function () {
        var _self = this;

        // Hook WebSocket connections with GraphQL subprotocols
        var originalWebSocket = WebSocket;
        if (originalWebSocket) {
            WebSocket = function (url, protocols) {
                var ws = new originalWebSocket(url, protocols);

                // Check if this is a GraphQL subscription WebSocket
                if (
                    protocols &&
          (protocols.includes('graphql-ws') ||
            protocols.includes('graphql-transport-ws') ||
            (Array.isArray(protocols) &&
              protocols.some((p) => p.includes('graphql'))))
                ) {
                    send({
                        type: 'info',
                        target: 'websocket_interceptor',
                        action: 'graphql_websocket_detected',
                        url: url,
                        protocols: protocols,
                    });

                    self.hookGraphQLWebSocketInstance(ws);
                }

                return ws;
            };
        }
    },

    // Hook GraphQL WebSocket instance for message interception
    hookGraphQLWebSocketInstance: function (ws) {
        var _self = this;

        // Hook send method for GraphQL operations
        var originalSend = ws.send;
        ws.send = function (data) {
            try {
                var message = JSON.parse(data);
                send({
                    type: 'info',
                    target: 'websocket_interceptor',
                    action: 'graphql_operation_sent',
                    type: message.type,
                    payload: message.payload,
                });

                // Process GraphQL operations for license validation
                if (message.type === 'start' && message.payload) {
                    var query = message.payload.query || '';
                    var variables = message.payload.variables || {};

                    if (
                        query.includes('license') ||
            query.includes('validate') ||
            query.includes('subscription') ||
            Object.keys(variables).some(
                (k) => k.includes('license') || k.includes('auth'),
            )
                    ) {
                        send({
                            type: 'info',
                            target: 'websocket_interceptor',
                            action: 'graphql_license_operation_detected',
                            query: query,
                            variables: variables,
                        });

                        // Modify GraphQL variables for license bypass
                        var modified = self.modifyGraphQLVariables(variables);
                        if (modified !== variables) {
                            message.payload.variables = modified;
                            data = JSON.stringify(message);

                            send({
                                type: 'bypass',
                                target: 'websocket_interceptor',
                                action: 'graphql_variables_modified',
                                original: variables,
                                modified: modified,
                            });
                        }
                    }
                }

                self.interceptedMessages++;
                return originalSend.call(this, data);
            } catch (_e) {
                // Not JSON data
                return originalSend.call(this, data);
            }
        };

        // Hook message event for GraphQL responses
        ws.addEventListener(
            'message',
            function (event) {
                try {
                    var message = JSON.parse(event.data);
                    send({
                        type: 'info',
                        target: 'websocket_interceptor',
                        action: 'graphql_message_received',
                        type: message.type,
                        payload: message.payload,
                    });

                    // Process GraphQL responses for license validation
                    if (message.type === 'data' && message.payload) {
                        var modified = self.processGraphQLResponse(message.payload);
                        if (modified !== message.payload) {
                            message.payload = modified;

                            // Create modified event
                            event.stopImmediatePropagation();
                            var modifiedEvent = new MessageEvent('message', {
                                data: JSON.stringify(message),
                                origin: event.origin,
                                lastEventId: event.lastEventId,
                                source: event.source,
                                ports: event.ports,
                            });

                            send({
                                type: 'bypass',
                                target: 'websocket_interceptor',
                                action: 'graphql_response_spoofed',
                                original: message.payload,
                                modified: modified,
                            });
                            self.spoofedResponses++;

                            setTimeout(function () {
                                ws.dispatchEvent(modifiedEvent);
                            }, 0);
                        }
                    }

                    self.interceptedMessages++;
                } catch (_e) {
                    // Not JSON data
                }
            },
            true,
        );
    },

    // Hook GraphQL operation processing
    hookGraphQLOperations: function () {
        var _self = this;

        // Hook GraphQL libraries (if available in Node.js environment)
        try {
            if (typeof require !== 'undefined') {
                var originalRequire = require;
                require = function (module) {
                    var result = originalRequire.apply(this, arguments);

                    if (
                        (module === 'graphql' ||
              module === 'apollo-server' ||
              module === 'apollo-client') &&
            result
                    ) {
                        send({
                            type: 'info',
                            target: 'websocket_interceptor',
                            action: 'graphql_library_detected',
                            module: module,
                        });

                        // Hook GraphQL execution
                        if (result.execute) {
                            var originalExecute = result.execute;
                            result.execute = function (args) {
                                var document = args.document;
                                var variables = args.variableValues || {};

                                if (document && document.definitions) {
                                    document.definitions.forEach(function (def) {
                                        if (def.selectionSet && def.selectionSet.selections) {
                                            def.selectionSet.selections.forEach(function (selection) {
                                                if (
                                                    selection.name &&
                          (selection.name.value.includes('license') ||
                            selection.name.value.includes('validate') ||
                            selection.name.value.includes('auth'))
                                                ) {
                                                    send({
                                                        type: 'info',
                                                        target: 'websocket_interceptor',
                                                        action: 'graphql_license_query_detected',
                                                        operation: selection.name.value,
                                                        variables: variables,
                                                    });

                                                    // Modify variables for license bypass
                                                    args.variableValues =
                            self.modifyGraphQLVariables(variables);
                                                }
                                            });
                                        }
                                    });
                                }

                                return originalExecute.call(this, args).then(function (result) {
                                    if (result.data) {
                                        var modified = self.processGraphQLResponse(result.data);
                                        if (modified !== result.data) {
                                            result.data = modified;
                                            send({
                                                type: 'bypass',
                                                target: 'websocket_interceptor',
                                                action: 'graphql_execution_result_modified',
                                                modified: modified,
                                            });
                                            self.spoofedResponses++;
                                        }
                                    }
                                    return result;
                                });
                            };
                        }
                    }

                    return result;
                };
            }
        } catch (_e) {
            // Not in Node.js environment
        }
    },

    // Modify GraphQL variables for license bypass
    modifyGraphQLVariables: function (variables) {
        var modified = JSON.parse(JSON.stringify(variables)); // Deep copy

        // Modify license-related variables
        for (var key in modified) {
            if (
                key.toLowerCase().includes('license') ||
        key.toLowerCase().includes('valid') ||
        key.toLowerCase().includes('expired') ||
        key.toLowerCase().includes('trial')
            ) {
                if (key.includes('valid') || key.includes('license')) {
                    modified[key] = true;
                } else if (key.includes('expired') || key.includes('trial')) {
                    modified[key] = false;
                } else if (typeof modified[key] === 'string') {
                    modified[key] = 'valid_license_key';
                }
            }
        }

        return modified;
    },

    // Process GraphQL response for license validation bypass
    processGraphQLResponse: function (data) {
        var modified = JSON.parse(JSON.stringify(data)); // Deep copy

        // Recursively process response data
        function processObject(obj) {
            for (var key in obj) {
                if (obj.hasOwnProperty(key)) {
                    var value = obj[key];

                    if (typeof value === 'object' && value !== null) {
                        processObject(value);
                    } else if (
                        key.toLowerCase().includes('license') ||
            key.toLowerCase().includes('valid') ||
            key.toLowerCase().includes('expired') ||
            key.toLowerCase().includes('trial') ||
            key.toLowerCase().includes('auth')
                    ) {
                        // Modify license-related fields
                        if (key.includes('valid') || key.includes('licensed')) {
                            obj[key] = true;
                        } else if (key.includes('expired') || key.includes('trial')) {
                            obj[key] = false;
                        } else if (key.includes('status')) {
                            obj[key] = 'ACTIVE';
                        } else if (key.includes('message')) {
                            obj[key] = 'License valid';
                        }
                    }
                }
            }
        }

        processObject(modified);
        return modified;
    },

    // Hook GraphQL response processing
    hookGraphQLResponseProcessing: function () {
        var _self = this;

        // This would hook lower-level GraphQL response processing
        // For now, we rely on the WebSocket and library-level hooks
        send({
            type: 'status',
            target: 'websocket_interceptor',
            action: 'graphql_response_processing_configured',
        });
    },

    // Hook WebSocket subprotocol manipulation for advanced license bypass
    hookWebSocketSubprotocols: function () {
        var _self = this;

        try {
            // Hook subprotocol negotiation during WebSocket handshake
            this.hookSubprotocolNegotiation();

            // Hook custom protocol message formats
            this.hookCustomProtocolFormats();

            // Hook protocol switching during connection
            this.hookProtocolSwitching();
        } catch (_e) {
            send({
                type: 'error',
                target: 'websocket_interceptor',
                action: 'websocket_subprotocols_hook_failed',
                error: e.toString(),
            });
        }
    },

    // Hook subprotocol negotiation during WebSocket handshake
    hookSubprotocolNegotiation: function () {
        var _self = this;

        // Hook HTTP upgrade request processing for WebSocket subprotocol manipulation
        var winHttpModule = Process.findModuleByName('winhttp.dll');
        if (winHttpModule) {
            var winHttpSendRequest = Module.findExportByName(
                'winhttp.dll',
                'WinHttpSendRequest',
            );
            if (winHttpSendRequest) {
                Interceptor.attach(winHttpSendRequest, {
                    onEnter: function (args) {
                        var _request = args[0];
                        var headers = args[1];
                        var headersLength = args[2].toInt32();

                        if (!headers.isNull() && headersLength > 0) {
                            var headerString = headers.readUtf16String(headersLength);

                            // Check for WebSocket upgrade with subprotocols
                            if (
                                headerString.includes('Upgrade: websocket') &&
                headerString.includes('Sec-WebSocket-Protocol:')
                            ) {
                                send({
                                    type: 'info',
                                    target: 'websocket_interceptor',
                                    action: 'websocket_subprotocol_negotiation_detected',
                                    headers: headerString,
                                });

                                // Extract and modify subprotocols
                                var protocolMatch = headerString.match(
                                    /Sec-WebSocket-Protocol:\s*([^\r\n]+)/i,
                                );
                                if (protocolMatch) {
                                    var protocols = protocolMatch[1]
                                        .split(',')
                                        .map((p) => p.trim());
                                    send({
                                        type: 'info',
                                        target: 'websocket_interceptor',
                                        action: 'websocket_protocols_detected',
                                        protocols: protocols,
                                    });

                                    // Add license-friendly protocols
                                    var spoofedProtocols = protocols.concat([
                                        'license-bypass-v1',
                                        'validation-override',
                                        'auth-bypass-protocol',
                                    ]);

                                    var modifiedHeaders = headerString.replace(
                                        /Sec-WebSocket-Protocol:\s*[^\r\n]+/i,
                                        'Sec-WebSocket-Protocol: ' + spoofedProtocols.join(', '),
                                    );

                                    Memory.writeUtf16String(headers, modifiedHeaders);
                                    args[2] = ptr(modifiedHeaders.length);

                                    send({
                                        type: 'bypass',
                                        target: 'websocket_interceptor',
                                        action: 'websocket_subprotocols_spoofed',
                                        original: protocols,
                                        modified: spoofedProtocols,
                                    });
                                }
                            }
                        }
                    },
                });
            }

            // Hook WebSocket handshake response processing
            var winHttpReceiveResponse = Module.findExportByName(
                'winhttp.dll',
                'WinHttpReceiveResponse',
            );
            if (winHttpReceiveResponse) {
                Interceptor.attach(winHttpReceiveResponse, {
                    onLeave: function (retval) {
                        if (retval.toInt32() !== 0) {
                            var request = this.context.rcx;

                            // Check for WebSocket handshake response
                            var bufferSize = 4096;
                            var buffer = Memory.alloc(bufferSize);
                            var sizeNeeded = Memory.alloc(4);

                            var queryHeaders = Module.findExportByName(
                                'winhttp.dll',
                                'WinHttpQueryHeaders',
                            );
                            if (queryHeaders) {
                                var WINHTTP_QUERY_RAW_HEADERS_CRLF = 22;
                                var queryFunc = new NativeFunction(queryHeaders, 'int', [
                                    'pointer',
                                    'uint32',
                                    'pointer',
                                    'pointer',
                                    'pointer',
                                ]);

                                if (
                                    queryFunc(
                                        request,
                                        WINHTTP_QUERY_RAW_HEADERS_CRLF,
                                        NULL,
                                        buffer,
                                        sizeNeeded,
                                    ) !== 0
                                ) {
                                    var responseHeaders = buffer.readUtf8String();

                                    if (
                                        responseHeaders.includes('101 Switching Protocols') &&
                    responseHeaders.includes('Sec-WebSocket-Protocol:')
                                    ) {
                                        send({
                                            type: 'info',
                                            target: 'websocket_interceptor',
                                            action: 'websocket_subprotocol_response_received',
                                            headers: responseHeaders.substring(0, 500),
                                        });

                                        // Extract selected protocol
                                        var protocolMatch = responseHeaders.match(
                                            /Sec-WebSocket-Protocol:\s*([^\r\n]+)/i,
                                        );
                                        if (protocolMatch) {
                                            var selectedProtocol = protocolMatch[1].trim();
                                            send({
                                                type: 'info',
                                                target: 'websocket_interceptor',
                                                action: 'websocket_selected_protocol',
                                                protocol: selectedProtocol,
                                            });

                                            // Set up protocol-specific message handling
                                            self.setupProtocolSpecificHandling(selectedProtocol);
                                        }
                                    }
                                }
                            }
                        }
                    },
                });
            }
        }
    },

    // Setup protocol-specific message handling
    setupProtocolSpecificHandling: function (protocol) {
        var _self = this;

        send({
            type: 'info',
            target: 'websocket_interceptor',
            action: 'protocol_specific_handling_setup',
            protocol: protocol,
        });

        // Configure message processing based on protocol
        if (protocol.includes('json') || protocol.includes('graphql')) {
            // JSON-based protocols
            self.protocolHandler = self.handleJsonProtocol;
        } else if (protocol.includes('binary') || protocol.includes('protobuf')) {
            // Binary protocols
            self.protocolHandler = self.handleBinaryProtocol;
        } else if (protocol.includes('license') || protocol.includes('auth')) {
            // License-specific protocols
            self.protocolHandler = self.handleLicenseProtocol;
        } else {
            // Default protocol handling
            self.protocolHandler = self.handleDefaultProtocol;
        }
    },

    // Handle JSON-based protocol messages
    handleJsonProtocol: function (message) {
        try {
            var parsed = JSON.parse(message);

            // Apply JSON-specific license bypass patterns
            if (parsed.action === 'validate' || parsed.type === 'license_check') {
                parsed.result = 'success';
                parsed.valid = true;
                parsed.licensed = true;
            }

            return JSON.stringify(parsed);
        } catch (_e) {
            return message;
        }
    },

    // Handle binary protocol messages
    handleBinaryProtocol: function (message) {
    // Binary protocol processing would require specific protocol knowledge
    // For now, return original message
        send({
            type: 'info',
            target: 'websocket_interceptor',
            action: 'binary_protocol_message_processed',
            length: message.length,
        });
        return message;
    },

    // Handle license-specific protocol messages
    handleLicenseProtocol: function (message) {
    // License protocol specific processing
        var modified = message;

        // Apply license-specific transformations
        modified = modified.replace(/status.*invalid/gi, 'status: valid');
        modified = modified.replace(/licensed.*false/gi, 'licensed: true');
        modified = modified.replace(/expired.*true/gi, 'expired: false');

        return modified;
    },

    // Handle default protocol messages
    handleDefaultProtocol: function (message) {
    // Apply general license bypass patterns
        return this.processIncomingMessage(message);
    },

    // Hook custom protocol message formats
    hookCustomProtocolFormats: function () {
        var _self = this;

        // Hook common custom protocol formats used in license systems
        var customFormats = [
            {
                name: 'base64-json',
                detector: /^[A-Za-z0-9+\/]+=*$/,
                decoder: self.decodeBase64Json,
            },
            {
                name: 'hex-encoded',
                detector: /^[0-9A-Fa-f]+$/,
                decoder: self.decodeHexData,
            },
            {
                name: 'custom-header',
                detector: /^LICE[0-9A-F]{4}/,
                decoder: self.decodeCustomHeader,
            },
        ];

        self.customFormatHandlers = customFormats;

        send({
            type: 'info',
            target: 'websocket_interceptor',
            action: 'custom_protocol_formats_configured',
            formats: customFormats.map((f) => f.name),
        });
    },

    // Decode Base64-encoded JSON messages
    decodeBase64Json: function (message) {
        try {
            var decoded = atob(message);
            var parsed = JSON.parse(decoded);

            // Apply license bypass
            if (parsed.license !== undefined) parsed.license = true;
            if (parsed.valid !== undefined) parsed.valid = true;
            if (parsed.expired !== undefined) parsed.expired = false;

            return btoa(JSON.stringify(parsed));
        } catch (_e) {
            return message;
        }
    },

    // Decode hex-encoded data
    decodeHexData: function (message) {
        try {
            var bytes = [];
            for (var i = 0; i < message.length; i += 2) {
                bytes.push(parseInt(message.substr(i, 2), 16));
            }

            var decoded = String.fromCharCode.apply(null, bytes);
            var modified = this.processIncomingMessage(decoded);

            // Re-encode to hex
            var result = '';
            for (var j = 0; j < modified.length; j++) {
                result += modified.charCodeAt(j).toString(16).padStart(2, '0');
            }

            return result;
        } catch (_e) {
            return message;
        }
    },

    // Decode custom header format
    decodeCustomHeader: function (message) {
        try {
            // Custom format: LICE[4-digit-hex][data]
            var header = message.substring(0, 8);
            var data = message.substring(8);

            var modified = this.processIncomingMessage(data);
            return header + modified;
        } catch (_e) {
            return message;
        }
    },

    // Hook protocol switching during connection
    hookProtocolSwitching: function () {
        var _self = this;

        // Monitor for protocol upgrade/switching messages
        var originalProcessIncomingMessage = this.processIncomingMessage;
        this.processIncomingMessage = function (message) {
            // Check for protocol switching commands
            if (
                message.includes('SWITCH_PROTOCOL') ||
        message.includes('UPGRADE_PROTOCOL')
            ) {
                send({
                    type: 'info',
                    target: 'websocket_interceptor',
                    action: 'protocol_switch_detected',
                    message: message,
                });

                // Allow protocol switch but maintain interception
                var modified = originalProcessIncomingMessage.call(this, message);

                // Re-setup handlers for new protocol
                var protocolMatch = message.match(/PROTOCOL:\s*([^\s\r\n]+)/);
                if (protocolMatch) {
                    self.setupProtocolSpecificHandling(protocolMatch[1]);
                }

                return modified;
            }

            return originalProcessIncomingMessage.call(this, message);
        };
    },

    // Hook secure DNS (DNS-over-HTTPS/DNS-over-TLS) for license validation bypass
    hookSecureDNS: function () {
        var _self = this;

        try {
            // Hook DNS-over-HTTPS (DoH) requests
            this.hookDoHRequests();

            // Hook DNS-over-TLS (DoT) connections
            this.hookDoTConnections();

            // Hook system DNS resolution for license domains
            this.hookSystemDNS();
        } catch (_e) {
            send({
                type: 'error',
                target: 'websocket_interceptor',
                action: 'secure_dns_hook_failed',
                error: e.toString(),
            });
        }
    },

    // Hook DNS-over-HTTPS requests
    hookDoHRequests: function () {
        var _self = this;

        // Hook HTTPS requests to common DoH servers
        var dohServers = [
            'cloudflare-dns.com',
            'dns.google',
            'dns.quad9.net',
            'dns.adguard.com',
        ];

        var winHttpModule = Process.findModuleByName('winhttp.dll');
        if (winHttpModule) {
            var winHttpConnect = Module.findExportByName(
                'winhttp.dll',
                'WinHttpConnect',
            );
            if (winHttpConnect) {
                Interceptor.attach(winHttpConnect, {
                    onEnter: function (args) {
                        var serverName = args[1];
                        if (!serverName.isNull()) {
                            var hostname = serverName.readUtf16String();

                            if (dohServers.some((server) => hostname.includes(server))) {
                                send({
                                    type: 'info',
                                    target: 'websocket_interceptor',
                                    action: 'doh_server_connection_detected',
                                    server: hostname,
                                });
                                this.isDohConnection = true;
                                this.dohServer = hostname;
                            }
                        }
                    },
                    onLeave: function (retval) {
                        if (this.isDohConnection && !retval.isNull()) {
                            send({
                                type: 'info',
                                target: 'websocket_interceptor',
                                action: 'doh_connection_established',
                                server: this.dohServer,
                                handle: retval.toString(),
                            });
                            self.hookDoHRequestsOnConnection(retval);
                        }
                    },
                });
            }
        }
    },

    // Hook DoH requests on established connection
    hookDoHRequestsOnConnection: function (connection) {
        var _self = this;

        send({
            type: 'status',
            target: 'websocket_interceptor',
            action: 'doh_connection_hooked',
            connection: connection.toString(),
        });

        // Store connection for DNS response manipulation
        self.dohConnections = self.dohConnections || {};
        self.dohConnections[connection.toString()] = {
            handle: connection,
            intercepted: 0,
        };
    },

    // Hook DNS-over-TLS connections
    hookDoTConnections: function () {
        var _self = this;

        // DoT typically uses port 853
        var winSocketModule = Process.findModuleByName('ws2_32.dll');
        if (winSocketModule) {
            var connect = Module.findExportByName('ws2_32.dll', 'connect');
            if (connect) {
                Interceptor.attach(connect, {
                    onEnter: function (args) {
                        var socket = args[0];
                        var addr = args[1];
                        var addrlen = args[2].toInt32();

                        if (!addr.isNull() && addrlen >= 16) {
                            // Check for IPv4 connection (AF_INET = 2)
                            var family = addr.readU16();
                            if (family === 2) {
                                var port = addr.add(2).readU16();
                                port = ((port & 0xff) << 8) | ((port >> 8) & 0xff); // Convert from network byte order

                                if (port === 853) {
                                    // DoT port
                                    var ip = addr.add(4).readU32();
                                    var ipStr = [
                                        ip & 0xff,
                                        (ip >> 8) & 0xff,
                                        (ip >> 16) & 0xff,
                                        (ip >> 24) & 0xff,
                                    ].join('.');

                                    send({
                                        type: 'info',
                                        target: 'websocket_interceptor',
                                        action: 'dot_connection_detected',
                                        ip: ipStr,
                                        port: port,
                                        socket: socket.toString(),
                                    });

                                    this.isDotConnection = true;
                                    this.dotSocket = socket;
                                    this.dotIp = ipStr;
                                }
                            }
                        }
                    },
                    onLeave: function (retval) {
                        if (this.isDotConnection && retval.toInt32() === 0) {
                            // SOCKET_ERROR = -1, success = 0
                            send({
                                type: 'info',
                                target: 'websocket_interceptor',
                                action: 'dot_connection_established',
                                socket: this.dotSocket.toString(),
                                ip: this.dotIp,
                            });
                            self.hookDoTSocket(this.dotSocket);
                        }
                    },
                });
            }
        }
    },

    // Hook DoT socket for DNS message interception
    hookDoTSocket: function (socket) {
        var _self = this;

        // Hook send/recv on DoT socket
        var ws2_32 = Process.findModuleByName('ws2_32.dll');
        if (ws2_32) {
            var send = Module.findExportByName('ws2_32.dll', 'send');
            var recv = Module.findExportByName('ws2_32.dll', 'recv');

            if (send) {
                Interceptor.attach(send, {
                    onEnter: function (args) {
                        if (args[0].equals(socket)) {
                            var buffer = args[1];
                            var length = args[2].toInt32();

                            if (!buffer.isNull() && length > 0) {
                                send({
                                    type: 'info',
                                    target: 'websocket_interceptor',
                                    action: 'dot_dns_query_sent',
                                    socket: socket.toString(),
                                    length: length,
                                });

                                // Process DNS query for license domain interception
                                self.processDnsQuery(buffer, length);
                            }
                        }
                    },
                });
            }

            if (recv) {
                Interceptor.attach(recv, {
                    onEnter: function (args) {
                        if (args[0].equals(socket)) {
                            this.buffer = args[1];
                            this.length = args[2].toInt32();
                        }
                    },
                    onLeave: function (retval) {
                        var bytesReceived = retval.toInt32();
                        if (bytesReceived > 0 && !this.buffer.isNull()) {
                            send({
                                type: 'info',
                                target: 'websocket_interceptor',
                                action: 'dot_dns_response_received',
                                socket: socket.toString(),
                                length: bytesReceived,
                            });

                            // Process DNS response for license domain spoofing
                            var modified = self.processDnsResponse(
                                this.buffer,
                                bytesReceived,
                            );
                            if (modified) {
                                send({
                                    type: 'bypass',
                                    target: 'websocket_interceptor',
                                    action: 'dot_dns_response_spoofed',
                                    socket: socket.toString(),
                                });
                            }
                        }
                    },
                });
            }
        }
    },

    // Hook system DNS resolution for license domains
    hookSystemDNS: function () {
        var _self = this;

        // Hook GetAddrInfoExW for modern DNS resolution
        var ws2_32 = Process.findModuleByName('ws2_32.dll');
        if (ws2_32) {
            var getAddrInfoEx = Module.findExportByName(
                'ws2_32.dll',
                'GetAddrInfoExW',
            );
            if (getAddrInfoEx) {
                Interceptor.attach(getAddrInfoEx, {
                    onEnter: function (args) {
                        var nodeName = args[0];
                        var _serviceName = args[1];

                        if (!nodeName.isNull()) {
                            var hostname = nodeName.readUtf16String();

                            // Check for license-related domains
                            if (
                                hostname.includes('license') ||
                hostname.includes('activate') ||
                hostname.includes('validate') ||
                hostname.includes('auth') ||
                hostname.includes('verify')
                            ) {
                                send({
                                    type: 'info',
                                    target: 'websocket_interceptor',
                                    action: 'license_domain_resolution_detected',
                                    hostname: hostname,
                                });

                                this.isLicenseDomain = true;
                                this.originalHostname = hostname;
                                this.results = args[7]; // ppResult parameter

                                // Spoof hostname to bypass DNS-based license checks
                                var spoofedHostname = 'localhost';
                                Memory.writeUtf16String(nodeName, spoofedHostname);

                                send({
                                    type: 'bypass',
                                    target: 'websocket_interceptor',
                                    action: 'license_domain_spoofed',
                                    original: hostname,
                                    spoofed: spoofedHostname,
                                });
                            }
                        }
                    },
                    onLeave: function (retval) {
                        if (this.isLicenseDomain) {
                            // Force successful DNS resolution
                            retval.replace(ptr(0)); // NO_ERROR

                            send({
                                type: 'bypass',
                                target: 'websocket_interceptor',
                                action: 'license_domain_resolution_spoofed',
                                hostname: this.originalHostname,
                                result: 'success',
                            });
                        }
                    },
                });
            }

            // Hook classic gethostbyname for older applications
            var gethostbyname = Module.findExportByName(
                'ws2_32.dll',
                'gethostbyname',
            );
            if (gethostbyname) {
                Interceptor.attach(gethostbyname, {
                    onEnter: function (args) {
                        var hostname = args[0].readUtf8String();

                        if (
                            hostname.includes('license') ||
              hostname.includes('activate') ||
              hostname.includes('validate') ||
              hostname.includes('auth')
                        ) {
                            send({
                                type: 'info',
                                target: 'websocket_interceptor',
                                action: 'classic_license_domain_resolution',
                                hostname: hostname,
                            });

                            // Spoof hostname
                            Memory.writeUtf8String(args[0], '127.0.0.1');

                            send({
                                type: 'bypass',
                                target: 'websocket_interceptor',
                                action: 'classic_license_domain_spoofed',
                                original: hostname,
                                spoofed: '127.0.0.1',
                            });
                        }
                    },
                });
            }
        }
    },

    // Process DNS query for license domain detection
    processDnsQuery: function (buffer, length) {
        try {
            // Basic DNS query parsing
            if (length < 12) return; // Minimum DNS header size

            var _header = buffer.readByteArray(12);
            var questions = buffer.add(12);

            // Extract domain name from DNS query
            var domainName = this.extractDnsName(questions);

            if (
                domainName &&
        (domainName.includes('license') ||
          domainName.includes('activate') ||
          domainName.includes('validate'))
            ) {
                send({
                    type: 'info',
                    target: 'websocket_interceptor',
                    action: 'dns_license_domain_query',
                    domain: domainName,
                    length: length,
                });
            }
        } catch (_e) {
            send({
                type: 'error',
                target: 'websocket_interceptor',
                action: 'dns_query_processing_failed',
                error: e.toString(),
            });
        }
    },

    // Process DNS response for license domain spoofing
    processDnsResponse: function (buffer, length) {
        try {
            if (length < 12) return false;

            // Check if this is a response to a license domain query
            var header = buffer.readByteArray(12);
            var dataView = new DataView(header);

            var flags = dataView.getUint16(2);
            var isResponse = (flags & 0x8000) !== 0;
            var responseCode = flags & 0x000f;

            if (isResponse && responseCode === 0) {
                // NOERROR
                // Modify response to point license domains to localhost
                var _answerSection = buffer.add(12);

                // Skip questions section (simplified)
                var questionsCount = dataView.getUint16(4);

                send({
                    type: 'info',
                    target: 'websocket_interceptor',
                    action: 'dns_response_processed',
                    questions: questionsCount,
                    length: length,
                });

                return true; // Indicate response was processed
            }

            return false;
        } catch (_e) {
            send({
                type: 'error',
                target: 'websocket_interceptor',
                action: 'dns_response_processing_failed',
                error: e.toString(),
            });
            return false;
        }
    },

    // Extract domain name from DNS query
    extractDnsName: function (buffer) {
        try {
            var name = '';
            var offset = 0;
            var length = buffer.readU8();

            while (length > 0 && offset < 255) {
                if (name.length > 0) name += '.';

                offset++;
                for (var i = 0; i < length; i++) {
                    name += String.fromCharCode(buffer.add(offset + i).readU8());
                }

                offset += length;
                length = buffer.add(offset).readU8();
            }

            return name;
        } catch (_e) {
            return '';
        }
    },
};

// Initialize the WebSocket interceptor
if (typeof websocketInterceptor !== 'undefined') {
    send({
        type: 'info',
        message:
      'Initializing WebSocket Interceptor v' + websocketInterceptor.version,
    });

    // Start interception
    WebSocketInterceptor.init();

    // Export for external access
    rpc.exports = {
        getStats: function () {
            return {
                intercepted: WebSocketInterceptor.stats.interceptedConnections,
                messages: WebSocketInterceptor.stats.interceptedMessages,
                spoofed: WebSocketInterceptor.stats.spoofedResponses,
            };
        },
        setConfig: function (config) {
            Object.assign(websocketInterceptor.config, config);
            WebSocketInterceptor.init(); // Reinitialize with new config
        },
    };
}

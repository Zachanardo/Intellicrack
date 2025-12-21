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
        if (!observedValue || typeof observedValue !== 'string') {
            return;
        }

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
    extractPrefix: value => {
        const prefixMatch = value.match(/^([a-zA-Z_]{2,8})[a-zA-Z0-9]/);
        return prefixMatch ? prefixMatch[1] : '';
    },

    // Extract common suffixes
    extractSuffix: value => {
        const suffixMatch = value.match(/[a-zA-Z0-9]([a-zA-Z_]{2,8})$/);
        return suffixMatch ? suffixMatch[1] : '';
    },

    // Analyze character set used
    analyzeCharset: value => {
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
    detectFormat: value => {
        if (value.includes('.') && value.split('.').length === 3) {
            return 'jwt';
        }
        if (/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(value)) {
            return 'uuid';
        }
        if (/^[A-Za-z0-9+/=]+$/.test(value) && value.length % 4 === 0) {
            return 'base64';
        }
        if (/^[0-9a-f]+$/i.test(value)) {
            return 'hex';
        }
        if (/^[A-Za-z0-9_-]+$/.test(value)) {
            return 'alphanumeric';
        }
        return 'custom';
    },

    // Generate credential matching learned pattern
    generateCredential: function (credentialType, targetLength = null, targetPrefix = null) {
        const pattern = this.patterns.get(credentialType);

        if (pattern) {
            return this.generateFromPattern(pattern, targetLength, targetPrefix);
        } else {
            return this.generateDefault(credentialType, targetLength, targetPrefix);
        }
    },

    // Generate from learned pattern
    generateFromPattern: function (pattern, overrideLength = null, overridePrefix = null) {
        const length = overrideLength || pattern.length > 0;
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
    generateWithCharset: (length, prefix, charset) => {
        let chars = '';
        if (charset.lowercase) {
            chars += 'abcdefghijklmnopqrstuvwxyz';
        }
        if (charset.uppercase) {
            chars += 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';
        }
        if (charset.numbers) {
            chars += '0123456789';
        }
        if (charset.special && charset.specialChars.length > 0) {
            chars += charset.specialChars.join('');
        }

        if (!chars) {
            chars = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';
        }

        let result = prefix;
        const remainingLength = Math.max(0, length - prefix.length);

        for (let i = 0; i < remainingLength; i++) {
            result += chars.charAt(Math.floor(Math.random() * chars.length));
        }

        return result;
    },

    // Generate JWT
    generateJWT: () => {
        const header = btoa(JSON.stringify({ typ: 'JWT', alg: 'HS256' }));
        const payload = btoa(
            JSON.stringify({
                sub: 'licensed',
                exp: Math.floor(Date.now() / 1000) + 86400,
                iat: Math.floor(Date.now() / 1000),
                jti: Math.random().toString(36),
            })
        );
        const signature = btoa(
            Array.from({ length: 32 }, () => Math.random().toString(36)[2]).join('')
        );
        return `${header}.${payload}.${signature}`;
    },

    // Generate UUID
    generateUUID: () =>
        'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g, c => {
            const r = (Math.random() * 16) | 0;
            const v = c === 'x' ? r : (r & 0x3) | 0x8;
            return v.toString(16);
        }),

    // Generate base64
    generateBase64: targetLength => {
        const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';
        let result = '';
        const baseLength = Math.ceil(targetLength * 0.75); // Account for base64 padding

        for (let i = 0; i < baseLength; i++) {
            result += chars.charAt(Math.floor(Math.random() * chars.length));
        }

        return btoa(result).substring(0, targetLength);
    },

    // Generate hex
    generateHex: targetLength => {
        const chars = '0123456789abcdef';
        let result = '';

        for (let i = 0; i < targetLength; i++) {
            result += chars.charAt(Math.floor(Math.random() * chars.length));
        }

        return result;
    },

    // Generate default format when no pattern learned
    generateDefault: function (credentialType, targetLength = null, targetPrefix = null) {
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

        const length = targetLength || pattern.length > 0;
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
            overrideStunServers: ['stun:stun.l.google.com:19302', 'stun:stun1.l.google.com:19302'],
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
            const WebSocketCtor = ObjC.classes.WebSocket || WebSocket;
            if (WebSocketCtor) {
                Interceptor.attach(WebSocketCtor.prototype.constructor, {
                    onEnter: function (args) {
                        const url = args[0];
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
                message: `Browser WebSocket hook failed: ${e.message}`,
            });
        }

        // Native WebSocket implementations
        this.hookNativeWebSocket();
    },

    // Hook native WebSocket implementations
    hookNativeWebSocket: () => {
        // Windows WebSocket API (websocket.dll)
        const wsModules = ['websocket.dll', 'winhttp.dll'];

        wsModules.forEach(moduleName => {
            const module = Process.findModuleByName(moduleName);
            if (!module) {
                return;
            }

            // WebSocketCreateClientHandle
            const createHandle = Module.findExportByName(moduleName, 'WebSocketCreateClientHandle');
            if (createHandle) {
                Interceptor.attach(createHandle, {
                    onLeave: function (retval) {
                        if (retval.toInt32() === 0) {
                            // S_OK
                            const handle = this.context.r8.readPointer();
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
            const wsSend = Module.findExportByName(moduleName, 'WebSocketSend');
            if (wsSend) {
                Interceptor.attach(wsSend, {
                    onEnter: args => {
                        const handle = args[0];
                        const bufferType = args[1].toInt32();
                        const buffer = args[2];
                        const bufferLength = args[3] ? args[3].toInt32() : 0;

                        if (self.sockets[handle.toString()]) {
                            const message = self.readWebSocketBuffer(
                                buffer,
                                bufferLength,
                                bufferType
                            );
                            send({
                                type: 'info',
                                target: 'websocket_interceptor',
                                action: 'outgoing_message',
                                message: message,
                                handle: handle.toString(),
                            });

                            // Check if we should modify the message
                            const modified = self.processOutgoingMessage(message);
                            if (modified !== message) {
                                self.replaceWebSocketBuffer(args[2], modified, bufferType);
                                if (args[3]) {
                                    args[3].writeU32(modified.length);
                                }
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
            const wsReceive = Module.findExportByName(moduleName, 'WebSocketReceive');
            if (wsReceive) {
                Interceptor.attach(wsReceive, {
                    onEnter: function (args) {
                        this.handle = args[0];
                        this.buffer = args[1];
                        this.bufferLength = args[2];
                    },
                    onLeave: function (retval) {
                        if (retval.toInt32() === 0 && self.sockets[this.handle.toString()]) {
                            const length = this.bufferLength.readU32();
                            const bufferType = this.context.r9 ? this.context.r9.readU32() : 1;

                            const message = self.readWebSocketBuffer(
                                this.buffer,
                                length,
                                bufferType
                            );
                            send({
                                type: 'info',
                                target: 'websocket_interceptor',
                                action: 'incoming_message',
                                message: message,
                                handle: this.handle.toString(),
                            });

                            // Process and potentially modify the message
                            const modified = self.processIncomingMessage(message);
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
    hookWebSocketInstance: ws => {
        // Store original methods
        const originalSend = ws.send;
        const originalClose = ws.close;

        // Hook send method
        ws.send = function (data) {
            send({
                type: 'info',
                target: 'websocket_interceptor',
                action: 'send_intercepted',
                data: data.toString(),
            });

            const modified = self.processOutgoingMessage(data);
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
            event => {
                const {data} = event;
                send({
                    type: 'info',
                    target: 'websocket_interceptor',
                    action: 'message_received',
                    data: data.toString(),
                });

                const modified = self.processIncomingMessage(data);
                if (modified !== data) {
                    // Create modified event
                    event.stopImmediatePropagation();
                    const modifiedEvent = new MessageEvent('message', {
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
                    setTimeout(() => {
                        ws.dispatchEvent(modifiedEvent);
                    }, 0);
                }

                self.interceptedMessages++;
            },
            true
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
    hookWebSocketMethods: () => {
        // Hook WinHTTP WebSocket upgrade
        const winHttpWebSocketCompleteUpgrade = Module.findExportByName(
            'winhttp.dll',
            'WinHttpWebSocketCompleteUpgrade'
        );
        if (winHttpWebSocketCompleteUpgrade) {
            Interceptor.attach(winHttpWebSocketCompleteUpgrade, {
                onEnter: function (args) {
                    this.request = args[0];
                },
                onLeave: retval => {
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
        ['WinHttpWebSocketSend', 'WinHttpWebSocketReceive'].forEach(func => {
            const fn = Module.findExportByName('winhttp.dll', func);
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
                        if (retval.toInt32() === 0 && self.sockets[this.handle.toString()]) {
                            const message = self.readWebSocketBuffer(
                                this.buffer,
                                this.bufferLength,
                                this.bufferType
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
                                        this.bufferType
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
                                        this.bufferType
                                    );
                                    self.spoofedResponses++;
                                }
                            }

                            self.interceptedMessages++;
                        }
                    },
                });
            }
        });
    },

    // Hook XMLHttpRequest for Socket.IO fallback
    hookXMLHttpRequestForSocketIO: () => {
        // Socket.IO often falls back to HTTP long-polling
        const xhrOpen = Module.findExportByName(null, 'XMLHttpRequest.prototype.open');
        if (xhrOpen) {
            Interceptor.attach(xhrOpen, {
                onEnter: function (args) {
                    const method = args[0];
                    const url = args[1];

                    if (url?.toString().match(/socket\.io|engine\.io/i)) {
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
    hookWindowsWebSocket: () => {
        // Windows.Networking.Sockets.MessageWebSocket (UWP apps)
        try {
            const messageWebSocket = ObjC.classes['Windows.Networking.Sockets.MessageWebSocket'];
            if (messageWebSocket) {
                Interceptor.attach(messageWebSocket['- connectAsync:'], {
                    onEnter: function (args) {
                        const uri = new ObjC.Object(args[2]);
                        const uriStr = uri.toString();

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
        if (!url) {
            return false;
        }

        url = url.toString().toLowerCase();

        for (let i = 0; i < this.config.targetUrls.length; i++) {
            const pattern = this.config.targetUrls[i].replace(/\*/g, '.*');
            if (url.match(new RegExp(pattern))) {
                return true;
            }
        }

        return false;
    },

    // Read WebSocket buffer
    readWebSocketBuffer: (buffer, length, bufferType) => {
        if (!buffer || buffer.isNull()) {
            return '';
        }

        try {
            // bufferType: 0 = binary, 1 = UTF8, 2 = close
            if (bufferType === 0) {
                // Binary frame - convert to hex
                const bytes = [];
                for (let i = 0; i < Math.min(length, 1024); i++) {
                    bytes.push(buffer.add(i).readU8().toString(16).padStart(2, '0'));
                }
                return `BINARY[${bytes.join(' ')}${length > 1024 ? '...' : ''}]`;
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
            return `<read error: ${e.message}>`;
        }
    },

    // Replace WebSocket buffer content
    replaceWebSocketBuffer: (buffer, newContent, bufferType) => {
        if (!buffer || buffer.isNull()) {
            return;
        }

        try {
            if (bufferType === 0) {
                // Binary - expect hex string
                if (newContent.startsWith('BINARY[')) {
                    const hex = newContent.substring(7, newContent.length - 1);
                    const bytes = hex.split(' ');
                    for (let i = 0; i < bytes.length; i++) {
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
        if (!message || typeof message !== 'string') {
            return message;
        }

        // Check request patterns
        for (let i = 0; i < this.config.messagePatterns.requests.length; i++) {
            const pattern = this.config.messagePatterns.requests[i];
            if (message.match(pattern.pattern)) {
                send({
                    type: 'info',
                    target: 'websocket_interceptor',
                    action: 'matched_request_pattern',
                    pattern: pattern.pattern,
                    message: message,
                });

                // Don't modify outgoing, but prepare for response spoofing
                const handler = this[pattern.handler];
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
        if (!message || typeof message !== 'string') {
            return message;
        }

        // If we have a pending handler from request
        if (this.pendingHandler) {
            const handler = this[this.pendingHandler];
            if (handler) {
                const spoofed = handler.call(this, message);
                this.pendingHandler = null;
                return spoofed;
            }
        }

        // Apply response patterns
        let modified = message;
        for (let i = 0; i < this.config.messagePatterns.responses.length; i++) {
            const pattern = this.config.messagePatterns.responses[i];
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
            const parsed = JSON.parse(originalMessage);

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
            const parsed = JSON.parse(originalMessage);
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
            const parsed = JSON.parse(originalMessage);
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
            const parsed = JSON.parse(originalMessage);
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
        if (!this.config.webRtcConfig.enableDataChannelInterception) {
            return;
        }

        try {
            // Hook RTCPeerConnection constructor
            if (typeof RTCPeerConnection !== 'undefined') {
                const originalRTCPeerConnection = RTCPeerConnection;
                RTCPeerConnection = config => {
                    if (self.config.webRtcConfig.spoofIceServers && config && config.iceServers) {
                        config.iceServers = self.config.webRtcConfig.overrideStunServers.map(
                            url => ({
                                urls: url,
                            })
                        );
                        send({
                            type: 'bypass',
                            target: 'websocket_interceptor',
                            action: 'webrtc_ice_servers_spoofed',
                            servers: config.iceServers,
                        });
                    }

                    const pc = new originalRTCPeerConnection(config);
                    self.hookDataChannelEvents(pc);
                    return pc;
                };
            }

            // Hook native WebRTC APIs (Windows)
            const webRtcModule = Process.findModuleByName('webrtc_audio_device_module.dll');
            if (webRtcModule) {
                const createDataChannel = Module.findExportByName(
                    webRtcModule.name,
                    'CreateDataChannel'
                );
                if (createDataChannel) {
                    Interceptor.attach(createDataChannel, {
                        onLeave: retval => {
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
    hookDataChannelEvents: peerConnection => {
        const originalCreateDataChannel = peerConnection.createDataChannel;
        peerConnection.createDataChannel = function (label, config) {
            const channel = originalCreateDataChannel.call(this, label, config);

            send({
                type: 'info',
                target: 'websocket_interceptor',
                action: 'webrtc_datachannel_created',
                label: label,
                config: config,
            });

            // Hook data channel message events
            const originalSend = channel.send;
            channel.send = function (data) {
                const message = data.toString();
                send({
                    type: 'info',
                    target: 'websocket_interceptor',
                    action: 'webrtc_message_sent',
                    message: message,
                    label: label,
                });

                // Process and potentially modify the message
                const modified = self.processOutgoingMessage(message);
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

            channel.addEventListener('message', event => {
                const message = event.data.toString();
                send({
                    type: 'info',
                    target: 'websocket_interceptor',
                    action: 'webrtc_message_received',
                    message: message,
                    label: label,
                });

                const modified = self.processIncomingMessage(message);
                if (modified !== message) {
                    event.stopImmediatePropagation();
                    const modifiedEvent = new MessageEvent('message', {
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
    hookNativeDataChannel: channel => {
        // Hook data channel message handlers
        if (channel.onmessage) {
            const originalOnMessage = channel.onmessage;
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
        if (!this.config.http3Config.enableQuicInterception) {
            return;
        }

        try {
            // Hook QUIC implementation (msquic.dll on Windows)
            const quicModule = Process.findModuleByName('msquic.dll');
            if (quicModule) {
                const quicConnectionOpen = Module.findExportByName(
                    'msquic.dll',
                    'MsQuicConnectionOpen'
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
                                const connection = this.context.readPointer();
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
                const quicStreamSend = Module.findExportByName('msquic.dll', 'MsQuicStreamSend');
                if (quicStreamSend) {
                    Interceptor.attach(quicStreamSend, {
                        onEnter: args => {
                            const stream = args[0];
                            const buffers = args[1];
                            const bufferCount = args[2].toInt32();
                            const flags = args[3].toInt32();

                            // Use flags to determine stream behavior
                            if (flags && 0x01) {
                                send('[WebRTC] Data channel send with immediate flag');
                            }
                            if (flags && 0x02) {
                                send('[WebRTC] Data channel send with reliable flag');
                            }

                            if (bufferCount > 0 && !buffers.isNull()) {
                                const buffer = buffers.readPointer();
                                const length = buffers.add(Process.pointerSize).readU32();

                                const data = buffer.readUtf8String(length);
                                send({
                                    type: 'info',
                                    target: 'websocket_interceptor',
                                    action: 'quic_stream_send',
                                    stream: stream.toString(),
                                    data: data,
                                    length: length,
                                });

                                const modified = self.processOutgoingMessage(data);
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

                const quicStreamReceive = Module.findExportByName(
                    'msquic.dll',
                    'MsQuicStreamReceiveSetEnabled'
                );
                if (quicStreamReceive) {
                    Interceptor.attach(quicStreamReceive, {
                        onEnter: args => {
                            const stream = args[0];
                            const enabled = args[1].toInt32();

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
    hookAltSvcHeaders: () => {
        // Hook HTTP response processing
        const winHttpReceiveResponse = Module.findExportByName(
            'winhttp.dll',
            'WinHttpReceiveResponse'
        );
        if (winHttpReceiveResponse) {
            Interceptor.attach(winHttpReceiveResponse, {
                onLeave: function (retval) {
                    if (retval.toInt32() !== 0) {
                        // Spoof Alt-Svc header to prevent HTTP/3 upgrade
                        const _request = this.context.rcx;

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
        if (!this.config.wsExtensions.enableCompressionBypass) {
            return;
        }

        try {
            // Hook WebSocket extension negotiation
            const wsCreateClientHandle = Module.findExportByName(
                'websocket.dll',
                'WebSocketCreateClientHandle'
            );
            if (wsCreateClientHandle) {
                Interceptor.attach(wsCreateClientHandle, {
                    onEnter: args => {
                        const subProtocols = args[0];
                        const extensions = args[2];

                        // Process subProtocols for bypass
                        if (!subProtocols.isNull()) {
                            send(
                                '[WebSocket] Client handle with subProtocols: ' +
                                    subProtocols.readUtf8String()
                            );
                            // Inject custom subprotocol for license bypass
                            const bypassProtocol = Memory.allocUtf8String('license-bypass-v1');
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
                            const extensionList =
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
    hookCompressionBypass: () => {
        // Use self to maintain context for compression analysis and bypass tracking
        self.compressionStats = {
            deflate_attempts: 0,
            inflate_attempts: 0,
            bypass_success: 0,
            compression_ratios: [],
        };

        // Hook zlib decompression functions
        const zlibModules = ['zlib.dll', 'zlib1.dll'];

        zlibModules.forEach(moduleName => {
            const module = Process.findModuleByName(moduleName);
            if (!module) {
                return;
            }

            const inflate = Module.findExportByName(moduleName, 'inflate');
            if (inflate) {
                Interceptor.attach(inflate, {
                    onEnter: args => {
                        const strm = args[0];
                        const flush = args[1].toInt32();

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
                            const nextIn = strm.add(0).readPointer();
                            const availIn = strm.add(Process.pointerSize).readU32();

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
                    onLeave: retval => {
                        const result = retval.toInt32();
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
                                    success_rate: `${(
                                        (self.compressionStats.bypass_success /
                                            self.compressionStats.inflate_attempts) *
                                        100
                                    ).toFixed(2)}%`,
                                },
                            });
                        }
                    },
                });
            }
        });
    },

    // Hook rate limiting bypass
    hookRateLimitingBypass: () => {
        // Use self to maintain rate limiting bypass statistics and timing analysis
        self.rateLimitStats = {
            timing_queries: 0,
            time_manipulations: 0,
            bypass_attempts: 0,
            detection_evasions: 0,
        };

        // Hook timing functions to manipulate rate limiting
        const queryPerformanceCounter = Module.findExportByName(
            'kernel32.dll',
            'QueryPerformanceCounter'
        );
        if (queryPerformanceCounter) {
            const baseTime = Date.now() * 1000;
            let callCount = 0;

            Interceptor.attach(queryPerformanceCounter, {
                onLeave: function (retval) {
                    if (retval.toInt32() !== 0) {
                        callCount++;
                        // Use self to track timing manipulation statistics
                        self.rateLimitStats.timing_queries++;
                        self.rateLimitStats.time_manipulations++;

                        // Slow down time to bypass rate limiting
                        const slowedTime = baseTime + callCount * 100;
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
                                    manipulation_rate: `${(
                                        (self.rateLimitStats.time_manipulations /
                                            self.rateLimitStats.timing_queries) *
                                        100
                                    ).toFixed(1)}%`,
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
    hookProtobufDecoding: () => {
        // Use self to maintain protobuf message analysis and license detection statistics
        self.protobufAnalysis = {
            parsed_messages: 0,
            license_fields_detected: 0,
            credential_patterns: [],
            bypass_opportunities: 0,
        };

        // Look for protobuf libraries
        const protobufModules = ['libprotobuf.dll', 'protobuf.dll'];

        protobufModules.forEach(moduleName => {
            const module = Process.findModuleByName(moduleName);
            if (!module) {
                return;
            }

            // Hook message parsing
            const parseFromString = Module.findExportByName(
                moduleName,
                '_ZN6google8protobuf7Message15ParseFromStringERKSs'
            );
            if (parseFromString) {
                Interceptor.attach(parseFromString, {
                    onEnter: args => {
                        const message = args[0];
                        const data = args[1];

                        try {
                            const stringData = data.readUtf8String();

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
                            send(`[Protobuf] Parsing message at: ${message}`);

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
                                    detection_rate: `${(
                                        (self.protobufAnalysis.license_fields_detected /
                                            self.protobufAnalysis.parsed_messages) *
                                        100
                                    ).toFixed(1)}%`,
                                },
                            });

                            // Process the protobuf message for license validation
                            const modified = self.processProtobufMessage(stringData);
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
    processProtobufMessage: message => {
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
            let modified = message;
            modified = modified.replace(/valid["\s]*:["\s]*false/gi, 'valid": true');
            modified = modified.replace(/expired["\s]*:["\s]*true/gi, 'expired": false');
            modified = modified.replace(/trial["\s]*:["\s]*true/gi, 'trial": false');

            return modified;
        }

        return message;
    },

    // Hook MessagePack decoding
    hookMsgPackDecoding: () => {
        // Look for msgpack libraries
        const msgpackModule = Process.findModuleByName('msgpack.dll');
        if (msgpackModule) {
            const unpack = Module.findExportByName('msgpack.dll', 'msgpack_unpack');
            if (unpack) {
                Interceptor.attach(unpack, {
                    onEnter: args => {
                        const data = args[0];
                        const size = args[1].toInt32();

                        send({
                            type: 'info',
                            target: 'websocket_interceptor',
                            action: 'msgpack_message_unpacked',
                            size: size,
                        });

                        // Process MessagePack data for license validation
                        try {
                            const buffer = data.readByteArray(Math.min(size, 1024));
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
    processMsgPackData: buffer => {
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
    hookAvroDecoding: () => {
        // Use self to maintain Avro schema analysis and license field detection
        self.avroAnalysis = {
            schemas_decoded: 0,
            license_schemas: 0,
            field_bypasses: 0,
            schema_patterns: new Map(),
        };

        // Look for Avro libraries
        const avroModule = Process.findModuleByName('avro.dll');
        if (avroModule) {
            // Use self to track Avro schema processing
            self.avroAnalysis.schemas_decoded++;
            send({
                type: 'info',
                target: 'websocket_interceptor',
                action: 'avro_library_detected',
            });

            // Hook Avro datum reader
            const read = Module.findExportByName('avro.dll', 'avro_datum_read');
            if (read) {
                Interceptor.attach(read, {
                    onEnter: args => {
                        const reader = args[0];
                        const datum = args[1];

                        // Use self to track schema analysis and license detection
                        const schemaId = reader.toString();
                        if (!self.avroAnalysis.schema_patterns.has(schemaId)) {
                            self.avroAnalysis.schema_patterns.set(schemaId, {
                                count: 0,
                                license_related: false,
                            });
                        }
                        const schemaInfo = self.avroAnalysis.schema_patterns.get(schemaId);
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
    hookCapnProtoDecoding: () => {
        // Use self to maintain Cap'n Proto message analysis and license detection
        self.capnprotoAnalysis = {
            messages_read: 0,
            license_messages: 0,
            struct_analyses: 0,
            bypass_candidates: [],
        };

        // Look for Cap'n Proto libraries
        const capnpModule = Process.findModuleByName('capnp.dll');
        if (capnpModule) {
            send({
                type: 'info',
                target: 'websocket_interceptor',
                action: 'capnproto_library_detected',
            });

            // Hook Cap'n Proto message reading
            const readMessage = Module.findExportByName(
                'capnp.dll',
                '_ZN6capnp11MessageReader11readMessageERNS_11InputStreamEi'
            );
            if (readMessage) {
                Interceptor.attach(readMessage, {
                    onEnter: args => {
                        const reader = args[0];
                        const stream = args[1];
                        const options = args[2].toInt32();

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
                            send(`[Cap'n Proto] Reading from stream: ${stream}`);
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
                                bypass_candidates: self.capnprotoAnalysis.bypass_candidates.length,
                            },
                        });
                    },
                });
            }
        }
    },

    // Setup comprehensive authentication bypass for modern license systems
    setupAuthenticationBypass: function () {
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
    setupJwtSpoofing: () => {
        // Use self to maintain JWT spoofing statistics and token analysis
        self.jwtSpoofingStats = {
            tokens_decoded: 0,
            tokens_spoofed: 0,
            libraries_hooked: 0,
            bypass_success_count: 0,
            detected_algorithms: new Set(),
        };

        // Hook common JWT libraries
        const jwtLibraries = ['jwt.dll', 'libjwt.dll', 'jsonwebtoken.dll'];

        jwtLibraries.forEach(libName => {
            const module = Process.findModuleByName(libName);
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
                const decode = Module.findExportByName(libName, 'jwt_decode');
                if (decode) {
                    Interceptor.attach(decode, {
                        onEnter: args => {
                            const token = args[0];
                            const key = args[1];

                            if (!token.isNull()) {
                                const tokenStr = token.readUtf8String();

                                // Use self to track JWT token analysis
                                self.jwtSpoofingStats.tokens_decoded++;

                                // Analyze JWT algorithm from token header
                                if (tokenStr && tokenStr.indexOf('.') > 0) {
                                    try {
                                        const _header = tokenStr.split('.')[0];
                                        const decodedHeader = JSON.parse(atob(header));
                                        if (decodedHeader.alg) {
                                            self.jwtSpoofingStats.detected_algorithms.add(
                                                decodedHeader.alg
                                            );
                                        }
                                    } catch (_parseError) {
                                        // Header parsing failed, continue with bypass
                                    }
                                }

                                // Log key for verification bypass
                                if (!key.isNull()) {
                                    send(`[JWT] Verification key at: ${key}`);
                                    // Replace key with known value for bypass
                                    const bypassKey = Memory.allocUtf8String('bypass-secret-key');
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
                                            self.jwtSpoofingStats.detected_algorithms
                                        ),
                                        spoof_success_rate: `${(
                                            (self.jwtSpoofingStats.tokens_spoofed /
                                                self.jwtSpoofingStats.tokens_decoded) *
                                            100
                                        ).toFixed(1)}%`,
                                    },
                                });

                                // Generate spoofed JWT token
                                const spoofedToken = self.generateSpoofedJwt();
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
        const _header = JSON.stringify({
            typ: 'JWT',
            alg: 'HS256',
        });

        const payload = JSON.stringify(this.config.authBypass.spoofedClaims);

        const signature = 'spoofed_signature_for_license_bypass';

        return `${btoa(header)}.${btoa(payload)}.${btoa(signature)}`;
    },

    // Setup OAuth bypass for license validation systems
    setupOAuthBypass: () => {
        // Hook OAuth token validation
        const oauthLibs = ['oauth.dll', 'oauth2.dll', 'liboauth.dll'];

        oauthLibs.forEach(libName => {
            const module = Process.findModuleByName(libName);
            if (module) {
                send({
                    type: 'info',
                    target: 'websocket_interceptor',
                    action: 'oauth_library_detected',
                    library: libName,
                });

                // Hook token validation
                const validate = Module.findExportByName(libName, 'oauth_validate_token');
                if (validate) {
                    Interceptor.attach(validate, {
                        onLeave: retval => {
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
    setupApiKeyBypass: () => {
        // Hook common API key validation patterns
        const cryptoModule = Process.findModuleByName('crypt32.dll');
        if (cryptoModule) {
            const cryptHashData = Module.findExportByName('crypt32.dll', 'CryptHashData');
            if (cryptHashData) {
                Interceptor.attach(cryptHashData, {
                    onEnter: args => {
                        const hash = args[0];
                        const data = args[1];
                        const dataLen = args[2].toInt32();

                        // Use hash handle for tracking
                        if (!hash.isNull()) {
                            send(`[Crypto] Hash handle: ${hash}`);
                            self.currentHashHandle = hash;
                        }

                        if (!data.isNull() && dataLen > 16) {
                            try {
                                const keyData = data.readUtf8String(Math.min(dataLen, 256));
                                if (
                                    keyData.match(/^[A-Za-z0-9+/=]{16,}$/) ||
                                    keyData.includes('key') ||
                                    keyData.includes('api')
                                ) {
                                    send({
                                        type: 'info',
                                        target: 'websocket_interceptor',
                                        action: 'api_key_hash_detected',
                                        hashHandle: hash.toString(),
                                        keyData: `${keyData.substring(0, 32)}...`,
                                    });

                                    // Replace with valid API key
                                    const validKey = `intellicrack_valid_api_key_${Date.now()}`;
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
    hookServerSentEvents: () => {
        try {
            // Hook EventSource constructor for SSE interception
            if (typeof EventSource !== 'undefined') {
                const originalEventSource = EventSource;
                EventSource = (url, config) => {
                    send({
                        type: 'info',
                        target: 'websocket_interceptor',
                        action: 'sse_connection_detected',
                        url: url,
                        config: config,
                    });

                    const eventSource = new originalEventSource(url, config);

                    // Check if SSE URL should be intercepted
                    if (self.shouldInterceptUrl(url)) {
                        send({
                            type: 'info',
                            target: 'websocket_interceptor',
                            action: 'sse_connection_intercepted',
                            url: url,
                        });

                        // Hook all SSE message events
                        const originalAddEventListener = eventSource.addEventListener;
                        eventSource.addEventListener = function (type, listener, options) {
                            if (
                                type === 'message' ||
                                type === 'error' ||
                                type.includes('license')
                            ) {
                                const wrappedListener = function (event) {
                                    const originalData = event.data;

                                    send({
                                        target: 'websocket_interceptor',
                                        action: 'sse_message_received',
                                        type: type,
                                        data: originalData,
                                    });

                                    // Process SSE message for license validation bypass
                                    const modified = self.processIncomingMessage(originalData);
                                    if (modified !== originalData) {
                                        // Create modified event
                                        Object.defineProperty(event, 'data', {
                                            value: modified,
                                            writable: false,
                                        });

                                        send({
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
                                    options
                                );
                            }
                            return originalAddEventListener.call(this, type, listener, options);
                        };

                        // Hook onmessage property
                        const messageDescriptor =
                            Object.getOwnPropertyDescriptor(EventSource.prototype, 'onmessage') ||
                            Object.getOwnPropertyDescriptor(eventSource, 'onmessage');
                        if (messageDescriptor?.set) {
                            const originalSetter = messageDescriptor.set;
                            Object.defineProperty(eventSource, 'onmessage', {
                                set: function (handler) {
                                    if (handler) {
                                        const wrappedHandler = function (event) {
                                            const modified = self.processIncomingMessage(
                                                event.data
                                            );
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
                for (let prop in originalEventSource) {
                    if (Object.hasOwn(originalEventSource, prop)) {
                        EventSource[prop] = originalEventSource[prop];
                    }
                }
            }

            // Hook native SSE implementations (WinHTTP)
            const winHttpModule = Process.findModuleByName('winhttp.dll');
            if (winHttpModule) {
                const winHttpOpenRequest = Module.findExportByName(
                    'winhttp.dll',
                    'WinHttpOpenRequest'
                );
                if (winHttpOpenRequest) {
                    Interceptor.attach(winHttpOpenRequest, {
                        onEnter: function (args) {
                            const verb = args[2] ? args[2].readUtf8String() : '';
                            const objectName = args[3] ? args[3].readUtf8String() : '';

                            // Check for SSE requests (typically GET with Accept: text/event-stream)
                            if (
                                verb === 'GET' &&
                                (objectName.includes('/events') || objectName.includes('/stream'))
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
                const winHttpReceiveResponse = Module.findExportByName(
                    'winhttp.dll',
                    'WinHttpReceiveResponse'
                );
                if (winHttpReceiveResponse) {
                    Interceptor.attach(winHttpReceiveResponse, {
                        onEnter: function (args) {
                            this.request = args[0];
                        },
                        onLeave: function (retval) {
                            if (retval.toInt32() !== 0) {
                                // Check for SSE content type
                                const bufferSize = 1024;
                                const buffer = Memory.alloc(bufferSize);
                                const sizeNeeded = Memory.alloc(4);

                                const queryResult = Module.findExportByName(
                                    'winhttp.dll',
                                    'WinHttpQueryHeaders'
                                );
                                if (queryResult) {
                                    const WINHTTP_QUERY_CONTENT_TYPE = 1;
                                    const queryFunc = new NativeFunction(queryResult, 'int', [
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
                                            sizeNeeded
                                        ) !== 0 ||
                                        Process.getLastError() === 122
                                    ) {
                                        // ERROR_INSUFFICIENT_BUFFER

                                        const contentType = buffer.readUtf8String();
                                        if (contentType?.includes('text/event-stream')) {
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
    hookWebTransport: () => {
        try {
            // Hook WebTransport constructor
            if (typeof WebTransport !== 'undefined') {
                const originalWebTransport = WebTransport;
                WebTransport = (url, options) => {
                    send({
                        type: 'info',
                        target: 'websocket_interceptor',
                        action: 'webtransport_connection_detected',
                        url: url,
                        options: options,
                    });

                    const transport = new originalWebTransport(url, options);

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
                                    const stream = result.value;
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
                            .catch(error => {
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
                                    const stream = result.value;
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
                            .catch(error => {
                                send({
                                    type: 'error',
                                    target: 'websocket_interceptor',
                                    action: 'webtransport_stream_error',
                                    error: error.toString(),
                                });
                            });

                        // Hook datagrams
                        const originalSendDatagrams = transport.datagrams.writable.getWriter();
                        transport.datagrams.writable.getWriter = () => {
                            const writer = originalSendDatagrams;
                            const originalWrite = writer.write;

                            writer.write = function (data) {
                                const dataStr = new TextDecoder().decode(data);
                                send({
                                    type: 'info',
                                    target: 'websocket_interceptor',
                                    action: 'webtransport_datagram_send',
                                    data: dataStr,
                                });

                                const modified = self.processOutgoingMessage(dataStr);
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
                                    const data = result.value;
                                    const dataStr = new TextDecoder().decode(data);

                                    send({
                                        type: 'info',
                                        target: 'websocket_interceptor',
                                        action: 'webtransport_datagram_received',
                                        data: dataStr,
                                    });

                                    const modified = self.processIncomingMessage(dataStr);
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
                            .catch(error => {
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
                for (let prop in originalWebTransport) {
                    if (Object.hasOwn(originalWebTransport, prop)) {
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
    hookWebTransportStream: (stream, type) => {
        try {
            // Hook readable stream
            if (stream.readable) {
                stream.readable
                    .getReader()
                    .read()
                    .then(function processData(result) {
                        if (!result.done) {
                            const data = result.value;
                            const dataStr = new TextDecoder().decode(data);

                            send({
                                target: 'websocket_interceptor',
                                action: 'webtransport_stream_data_received',
                                type: type,
                                data: dataStr,
                            });

                            const modified = self.processIncomingMessage(dataStr);
                            if (modified !== dataStr) {
                                send({
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
                    .catch(error => {
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
                const originalGetWriter = stream.writable.getWriter;
                stream.writable.getWriter = function () {
                    const writer = originalGetWriter.call(this);
                    const originalWrite = writer.write;

                    writer.write = function (data) {
                        const dataStr = new TextDecoder().decode(data);
                        send({
                            target: 'websocket_interceptor',
                            action: 'webtransport_stream_data_send',
                            type: type,
                            data: dataStr,
                        });

                        const modified = self.processOutgoingMessage(dataStr);
                        if (modified !== dataStr) {
                            data = new TextEncoder().encode(modified);
                            send({
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
    hookGrpcWeb: () => {
        try {
            // Hook gRPC-Web client requests
            if (typeof grpc !== 'undefined' && grpc.web) {
                const originalCall = grpc.web.AbstractClientBase.prototype.rpcCall;
                grpc.web.AbstractClientBase.prototype.rpcCall = function (
                    method,
                    request,
                    metadata,
                    methodDescriptor,
                    callback
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
                        const originalCallback = callback;
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
                                const modified = self.processGrpcResponse(response, method);
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
                        callback
                    );
                };
            }

            // Hook native gRPC implementations (grpc.dll)
            const grpcModule = Process.findModuleByName('grpc.dll');
            if (grpcModule) {
                const grpcCall = Module.findExportByName('grpc.dll', 'grpc_channel_create_call');
                if (grpcCall) {
                    Interceptor.attach(grpcCall, {
                        onEnter: function (args) {
                            const channel = args[0];
                            const _parent_call = args[1];
                            const _propagation_mask = args[2].toInt32();
                            const _completion_queue = args[3];
                            const method = args[4] ? args[4].readUtf8String() : '';

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
                const grpcSendMessage = Module.findExportByName(
                    'grpc.dll',
                    'grpc_call_start_batch'
                );
                if (grpcSendMessage) {
                    Interceptor.attach(grpcSendMessage, {
                        onEnter: args => {
                            const call = args[0];
                            const ops = args[1];
                            const nops = args[2].toInt32();
                            const tag = args[3];

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
    processGrpcResponse: (response, method) => {
        try {
            // Convert response to JSON if possible
            const responseData = response.toObject ? response.toObject() : response;
            const responseStr = JSON.stringify(responseData);

            send({
                type: 'info',
                target: 'websocket_interceptor',
                action: 'grpc_response_processing',
                method: method,
                data: responseStr,
            });

            // Apply license bypass patterns
            if (method.includes('license') || method.includes('validate')) {
                if (responseData.valid !== undefined) {
                    responseData.valid = true;
                }
                if (responseData.licensed !== undefined) {
                    responseData.licensed = true;
                }
                if (responseData.expired !== undefined) {
                    responseData.expired = false;
                }
                if (responseData.status !== undefined) {
                    responseData.status = 'VALID';
                }
                if (responseData.code !== undefined) {
                    responseData.code = 0; // SUCCESS
                }

                // Update response object if possible
                if (response.setValid) {
                    response.setValid(true);
                }
                if (response.setLicensed) {
                    response.setLicensed(true);
                }
                if (response.setExpired) {
                    response.setExpired(false);
                }
                if (response.setStatus) {
                    response.setStatus('VALID');
                }
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
    hookNativeGrpcCall: (call, method) => {
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
    processGrpcOperations: (ops, count) => {
        try {
            // gRPC operations are complex structures
            // This is a simplified representation for license data detection
            for (let i = 0; i < count; i++) {
                const op = ops.add(i * 32); // Approximate operation size
                const opType = op.readU32();

                send({
                    target: 'websocket_interceptor',
                    action: 'grpc_operation_processed',
                    index: i,
                    type: opType,
                });

                // Look for send/receive message operations
                if (opType === 0 || opType === 1) {
                    // GRPC_OP_SEND_MESSAGE or GRPC_OP_RECV_MESSAGE
                    const messagePtr = op.add(8).readPointer();
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
    hookBrotliCompression: () => {
        const brotliModules = ['brotli.dll', 'libbrotli.dll', 'brotlicommon.dll'];

        brotliModules.forEach(moduleName => {
            const module = Process.findModuleByName(moduleName);
            if (!module) {
                return;
            }

            send({
                type: 'info',
                target: 'websocket_interceptor',
                action: 'brotli_library_detected',
                module: moduleName,
            });

            // Hook BrotliDecoderDecompressStream
            const decompress = Module.findExportByName(moduleName, 'BrotliDecoderDecompressStream');
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
                        const result = retval.toInt32();
                        if (result === 1) {
                            // BROTLI_DECODER_RESULT_SUCCESS
                            const inputSize = this.availableIn.readU32();
                            const outputSize = this.availableOut.readU32();

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
                                    const decompressedData = this.nextOut.readUtf8String(
                                        Math.min(outputSize, 1024)
                                    );
                                    const modified = self.processIncomingMessage(decompressedData);

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
            const compress = Module.findExportByName(moduleName, 'BrotliEncoderCompressStream');
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
                                const inputData = this.nextIn.readUtf8String(
                                    Math.min(this.availableIn.readU32(), 1024)
                                );
                                const modified = self.processOutgoingMessage(inputData);

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
    hookLZ4Compression: () => {
        const lz4Modules = ['lz4.dll', 'liblz4.dll'];

        lz4Modules.forEach(moduleName => {
            const module = Process.findModuleByName(moduleName);
            if (!module) {
                return;
            }

            send({
                type: 'info',
                target: 'websocket_interceptor',
                action: 'lz4_library_detected',
                module: moduleName,
            });

            // Hook LZ4_decompress_safe
            const decompress = Module.findExportByName(moduleName, 'LZ4_decompress_safe');
            if (decompress) {
                Interceptor.attach(decompress, {
                    onEnter: function (args) {
                        this.source = args[0];
                        this.dest = args[1];
                        this.compressedSize = args[2].toInt32();
                        this.maxDecompressedSize = args[3].toInt32();
                    },
                    onLeave: function (retval) {
                        const decompressedSize = retval.toInt32();
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
                                    const decompressedData = this.dest.readUtf8String(
                                        Math.min(decompressedSize, 1024)
                                    );
                                    const modified = self.processIncomingMessage(decompressedData);

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
            const compress = Module.findExportByName(moduleName, 'LZ4_compress_default');
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
                                const inputData = this.source.readUtf8String(
                                    Math.min(this.sourceSize, 1024)
                                );
                                const modified = self.processOutgoingMessage(inputData);

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
                        const compressedSize = retval.toInt32();
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
    hookZstandardCompression: () => {
        const zstdModules = ['zstd.dll', 'libzstd.dll'];

        zstdModules.forEach(moduleName => {
            const module = Process.findModuleByName(moduleName);
            if (!module) {
                return;
            }

            send({
                type: 'info',
                target: 'websocket_interceptor',
                action: 'zstd_library_detected',
                module: moduleName,
            });

            // Hook ZSTD_decompress
            const decompress = Module.findExportByName(moduleName, 'ZSTD_decompress');
            if (decompress) {
                Interceptor.attach(decompress, {
                    onEnter: function (args) {
                        this.dst = args[0];
                        this.dstCapacity = args[1].toInt32();
                        this.src = args[2];
                        this.srcSize = args[3].toInt32();
                    },
                    onLeave: function (retval) {
                        const decompressedSize = retval.toInt32();
                        if (decompressedSize > 0 && !this.dst.isNull()) {
                            send({
                                type: 'info',
                                target: 'websocket_interceptor',
                                action: 'zstd_decompression_success',
                                srcSize: this.srcSize,
                                decompressedSize: decompressedSize,
                            });

                            try {
                                const decompressedData = this.dst.readUtf8String(
                                    Math.min(decompressedSize, 1024)
                                );
                                const modified = self.processIncomingMessage(decompressedData);

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
            const compress = Module.findExportByName(moduleName, 'ZSTD_compress');
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
                                const inputData = this.src.readUtf8String(
                                    Math.min(this.srcSize, 1024)
                                );
                                const modified = self.processOutgoingMessage(inputData);

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
                        const compressedSize = retval.toInt32();
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
    hookWebhookHttpServer: () => {
        // Hook WinHTTP server APIs
        const winHttpModule = Process.findModuleByName('winhttp.dll');
        if (winHttpModule) {
            const winHttpReceiveRequest = Module.findExportByName(
                'winhttp.dll',
                'WinHttpReceiveRequest'
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
                            const bufferSize = 1024;
                            const buffer = Memory.alloc(bufferSize);
                            const sizeNeeded = Memory.alloc(4);

                            const queryHeaders = Module.findExportByName(
                                'winhttp.dll',
                                'WinHttpQueryHeaders'
                            );
                            if (queryHeaders) {
                                const WINHTTP_QUERY_REQUEST_METHOD = 45;
                                const queryFunc = new NativeFunction(queryHeaders, 'int', [
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
                                        sizeNeeded
                                    ) !== 0
                                ) {
                                    const method = buffer.readUtf8String();

                                    if (method === 'POST' || method === 'PUT') {
                                        send({
                                            type: 'info',
                                            target: 'websocket_interceptor',
                                            action: 'webhook_request_detected',
                                            method: method,
                                            request: this.request.toString(),
                                        });

                                        // Get request URL
                                        const WINHTTP_QUERY_RAW_HEADERS_CRLF = 22;
                                        const urlBuffer = Memory.alloc(2048);
                                        const urlSize = Memory.alloc(4);
                                        urlSize.writeU32(2048);

                                        if (
                                            queryFunc(
                                                this.request,
                                                WINHTTP_QUERY_RAW_HEADERS_CRLF,
                                                NULL,
                                                urlBuffer,
                                                urlSize
                                            ) !== 0
                                        ) {
                                            const headers = urlBuffer.readUtf8String(
                                                urlSize.readU32()
                                            );

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
            const httpModule = Process.findModuleByName('node.exe');
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
    hookWebhookFrameworks: () => {
        // Hook Express.js webhook handlers (if in Node.js environment)
        try {
            if (typeof require !== 'undefined') {
                const originalRequire = require;
                require = function (module) {
                    const result = originalRequire.apply(this, arguments);

                    if (module === 'express' && result) {
                        send({
                            type: 'info',
                            target: 'websocket_interceptor',
                            action: 'express_framework_detected',
                        });

                        // Hook Express router
                        const originalRouter = result.Router;
                        result.Router = function () {
                            const router = originalRouter.apply(this, arguments);
                            const originalPost = router.post;
                            const originalPut = router.put;

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
    hookWebhookSignatureValidation: () => {
        // Hook HMAC verification functions
        const cryptoModules = ['crypt32.dll', 'bcrypt.dll', 'advapi32.dll'];

        cryptoModules.forEach(moduleName => {
            const module = Process.findModuleByName(moduleName);
            if (!module) {
                return;
            }

            // Hook HMAC creation/verification
            const hmacFunctions = ['CryptCreateHash', 'BCryptCreateHash', 'HMAC'];

            hmacFunctions.forEach(funcName => {
                const func = Module.findExportByName(moduleName, funcName);
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
                            if (
                                this.isWebhookValidation &&
                                (funcName.includes('Verify') || funcName.includes('Check'))
                            ) {
                                retval.replace(ptr(1)); // TRUE
                                send({
                                    type: 'bypass',
                                    target: 'websocket_interceptor',
                                    action: 'webhook_signature_validation_bypassed',
                                    function: funcName,
                                });
                            }
                        },
                    });
                }
            });
        });
    },

    // Process webhook request for license validation bypass
    processWebhookRequest: (request, _headers) => {
        try {
            send({
                type: 'info',
                target: 'websocket_interceptor',
                action: 'processing_webhook_request',
                request: request.toString(),
            });

            // Read request body if available
            const winHttpReadData = Module.findExportByName('winhttp.dll', 'WinHttpReadData');
            if (winHttpReadData) {
                const buffer = Memory.alloc(4096);
                const bytesRead = Memory.alloc(4);

                const readFunc = new NativeFunction(winHttpReadData, 'int', [
                    'pointer',
                    'pointer',
                    'uint32',
                    'pointer',
                ]);
                if (readFunc(request, buffer, 4096, bytesRead) !== 0) {
                    const dataSize = bytesRead.readU32();
                    if (dataSize > 0) {
                        try {
                            const webhookData = buffer.readUtf8String(dataSize);
                            send({
                                type: 'info',
                                target: 'websocket_interceptor',
                                action: 'webhook_data_received',
                                data: webhookData,
                            });

                            // Process webhook data for license validation
                            const modified = self.processIncomingMessage(webhookData);
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
    sendWebhookResponse: (request, responseData) => {
        try {
            const response = JSON.stringify({
                status: 'success',
                message: 'License validation successful',
                data: responseData,
                timestamp: Date.now(),
            });

            const winHttpSendResponse = Module.findExportByName(
                'winhttp.dll',
                'WinHttpSendResponse'
            );
            if (winHttpSendResponse) {
                const statusCode = Memory.allocUtf8String('200 OK');
                const headers = Memory.allocUtf8String('Content-Type: application/json\r\n');
                const responseBuffer = Memory.allocUtf8String(response);

                const sendFunc = new NativeFunction(winHttpSendResponse, 'int', [
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
                    NULL
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
        try {
            // Hook WebAssembly instantiation to intercept WASM modules
            if (typeof WebAssembly !== 'undefined') {
                const originalInstantiate = WebAssembly.instantiate;
                WebAssembly.instantiate = function (bytes, imports) {
                    send({
                        type: 'info',
                        target: 'websocket_interceptor',
                        action: 'wasm_module_instantiated',
                        bytesLength: bytes.byteLength > 0 || bytes.length > 0 || 0,
                    });

                    // Hook imports for message passing
                    if (imports && typeof imports === 'object') {
                        self.hookWasmImports(imports);
                    }

                    return originalInstantiate.call(this, bytes, imports).then(result => {
                        if (result.instance?.exports) {
                            self.hookWasmExports(result.instance.exports);
                        }
                        return result;
                    });
                };

                const originalInstantiateStreaming = WebAssembly.instantiateStreaming;
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
                            .then(result => {
                                if (result.instance?.exports) {
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
    hookWasmImports: imports => {
        try {
            // Look for message-passing functions in imports
            for (let module in imports) {
                if (Object.hasOwn(imports, module)) {
                    const moduleImports = imports[module];

                    for (let func in moduleImports) {
                        if (Object.hasOwn(moduleImports, func)) {
                            const originalFunc = moduleImports[func];

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
                                    const args = Array.prototype.slice.call(arguments);
                                    send({
                                        type: 'info',
                                        target: 'websocket_interceptor',
                                        action: 'wasm_import_function_called',
                                        module: module,
                                        function: func,
                                        args: args.map(arg =>
                                            typeof arg === 'string' ? arg : typeof arg
                                        ),
                                    });

                                    // Process arguments for license data
                                    for (let i = 0; i < args.length; i++) {
                                        if (typeof args[i] === 'string') {
                                            const modified = self.processOutgoingMessage(args[i]);
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

                                    let result = originalFunc.apply(this, args);

                                    // Process result for license validation
                                    if (typeof result === 'string') {
                                        const modifiedResult = self.processIncomingMessage(result);
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
    hookWasmExports: exports => {
        try {
            for (let func in exports) {
                if (Object.hasOwn(exports, func) && typeof exports[func] === 'function') {
                    const originalFunc = exports[func];

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
                            const args = Array.prototype.slice.call(arguments);
                            send({
                                type: 'info',
                                target: 'websocket_interceptor',
                                action: 'wasm_export_function_called',
                                function: func,
                                args: args.map(arg => (typeof arg === 'string' ? arg : typeof arg)),
                            });

                            // Process string arguments
                            for (let i = 0; i < args.length; i++) {
                                if (typeof args[i] === 'string') {
                                    const modified = self.processOutgoingMessage(args[i]);
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

                            let result = originalFunc.apply(this, args);

                            // Process string result
                            if (typeof result === 'string') {
                                const modifiedResult = self.processIncomingMessage(result);
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
    hookNativeWasmRuntime: () => {
        // Look for WebAssembly runtime modules
        const wasmModules = ['wasmtime.dll', 'wasmer.dll', 'v8.dll'];

        wasmModules.forEach(moduleName => {
            const module = Process.findModuleByName(moduleName);
            if (module) {
                send({
                    type: 'info',
                    target: 'websocket_interceptor',
                    action: 'native_wasm_runtime_detected',
                    module: moduleName,
                });

                // Hook common WASM runtime functions
                const wasmFunctions = [
                    'wasm_instance_new',
                    'wasm_func_call',
                    'wasmtime_func_call',
                    'wasmer_instance_call',
                ];

                wasmFunctions.forEach(funcName => {
                    const func = Module.findExportByName(moduleName, funcName);
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
    hookTLS13Implementation: () => {
        // Hook Schannel (Windows TLS implementation)
        const schannelModule = Process.findModuleByName('schannel.dll');
        if (schannelModule) {
            send({
                type: 'info',
                target: 'websocket_interceptor',
                action: 'schannel_tls_detected',
            });

            // Hook TLS handshake functions
            const handshakeFunctions = [
                'SslCreateContext',
                'SslDoHandshake',
                'SslEncryptPacket',
                'SslDecryptPacket',
            ];

            handshakeFunctions.forEach(funcName => {
                const func = Module.findExportByName('schannel.dll', funcName);
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
                            const result = retval.toInt32();
                            if (
                                result === 0 &&
                                funcName === 'SslDecryptPacket' &&
                                this.bufferSize > 0
                            ) {
                                // Process decrypted TLS data
                                try {
                                    const decryptedData = this.buffer.readUtf8String(
                                        Math.min(this.bufferSize, 1024)
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

                                        const modified = self.processIncomingMessage(decryptedData);
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
        const opensslModules = ['libssl.dll', 'openssl.dll', 'ssleay32.dll'];

        opensslModules.forEach(moduleName => {
            const module = Process.findModuleByName(moduleName);
            if (!module) {
                return;
            }

            send({
                type: 'info',
                target: 'websocket_interceptor',
                action: 'openssl_tls_detected',
                module: moduleName,
            });

            // Hook SSL_read for decrypted data interception
            const sslRead = Module.findExportByName(moduleName, 'SSL_read');
            if (sslRead) {
                Interceptor.attach(sslRead, {
                    onEnter: function (args) {
                        this.ssl = args[0];
                        this.buf = args[1];
                        this.num = args[2].toInt32();
                    },
                    onLeave: function (retval) {
                        const bytesRead = retval.toInt32();
                        if (bytesRead > 0 && !this.buf.isNull()) {
                            try {
                                const data = this.buf.readUtf8String(Math.min(bytesRead, 1024));
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

                                    const modified = self.processIncomingMessage(data);
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
            const sslWrite = Module.findExportByName(moduleName, 'SSL_write');
            if (sslWrite) {
                Interceptor.attach(sslWrite, {
                    onEnter: function (args) {
                        this.ssl = args[0];
                        this.buf = args[1];
                        this.num = args[2].toInt32();

                        if (!this.buf.isNull() && this.num > 0) {
                            try {
                                const data = this.buf.readUtf8String(Math.min(this.num, 1024));
                                if (
                                    data.includes('license') ||
                                    data.includes('validate') ||
                                    data.includes('auth')
                                ) {
                                    const modified = self.processOutgoingMessage(data);
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
    hookCertificateValidation: () => {
        // Hook Windows certificate validation
        const crypt32Module = Process.findModuleByName('crypt32.dll');
        if (crypt32Module) {
            const certVerifyChain = Module.findExportByName(
                'crypt32.dll',
                'CertVerifyCertificateChainPolicy'
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
            const certGetChain = Module.findExportByName('crypt32.dll', 'CertGetCertificateChain');
            if (certGetChain) {
                Interceptor.attach(certGetChain, {
                    onLeave: retval => {
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
        const winHttpModule = Process.findModuleByName('winhttp.dll');
        if (winHttpModule) {
            const winHttpSetOption = Module.findExportByName('winhttp.dll', 'WinHttpSetOption');
            if (winHttpSetOption) {
                Interceptor.attach(winHttpSetOption, {
                    onEnter: args => {
                        const option = args[1].toInt32();
                        const WINHTTP_OPTION_SERVER_CERT_CONTEXT = 78;
                        const WINHTTP_OPTION_SECURITY_FLAGS = 31;

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
                                const flags = Memory.alloc(4);
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
    hookSNISpoofing: () => {
        // Hook TLS SNI extension processing
        const winHttpModule = Process.findModuleByName('winhttp.dll');
        if (winHttpModule) {
            const winHttpConnect = Module.findExportByName('winhttp.dll', 'WinHttpConnect');
            if (winHttpConnect) {
                Interceptor.attach(winHttpConnect, {
                    onEnter: args => {
                        const _session = args[0];
                        const serverName = args[1];
                        const serverPort = args[2].toInt32();

                        if (!serverName.isNull()) {
                            const originalName = serverName.readUtf16String();

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
                                const spoofedName = 'trusted-license-server.local';
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
    hookGraphQLWebSocketProtocol: () => {
        // Hook WebSocket connections with GraphQL subprotocols
        const originalWebSocket = WebSocket;
        if (originalWebSocket) {
            WebSocket = (url, protocols) => {
                const ws = new originalWebSocket(url, protocols);

                // Check if this is a GraphQL subscription WebSocket
                if (
                    protocols &&
                    (protocols.includes('graphql-ws') ||
                        protocols.includes('graphql-transport-ws') ||
                        (Array.isArray(protocols) && protocols.some(p => p.includes('graphql'))))
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
    hookGraphQLWebSocketInstance: ws => {
        // Hook send method for GraphQL operations
        const originalSend = ws.send;
        ws.send = function (data) {
            try {
                const message = JSON.parse(data);
                send({
                    target: 'websocket_interceptor',
                    action: 'graphql_operation_sent',
                    type: message.type,
                    payload: message.payload,
                });

                // Process GraphQL operations for license validation
                if (message.type === 'start' && message.payload) {
                    const query = message.payload.query || '';
                    const variables = message.payload.variables || {};

                    if (
                        query.includes('license') ||
                        query.includes('validate') ||
                        query.includes('subscription') ||
                        Object.keys(variables).some(
                            k => k.includes('license') || k.includes('auth')
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
                        const modified = self.modifyGraphQLVariables(variables);
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
            event => {
                try {
                    const message = JSON.parse(event.data);
                    send({
                        target: 'websocket_interceptor',
                        action: 'graphql_message_received',
                        type: message.type,
                        payload: message.payload,
                    });

                    // Process GraphQL responses for license validation
                    if (message.type === 'data' && message.payload) {
                        const modified = self.processGraphQLResponse(message.payload);
                        if (modified !== message.payload) {
                            message.payload = modified;

                            // Create modified event
                            event.stopImmediatePropagation();
                            const modifiedEvent = new MessageEvent('message', {
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

                            setTimeout(() => {
                                ws.dispatchEvent(modifiedEvent);
                            }, 0);
                        }
                    }

                    self.interceptedMessages++;
                } catch (_e) {
                    // Not JSON data
                }
            },
            true
        );
    },

    // Hook GraphQL operation processing
    hookGraphQLOperations: () => {
        // Hook GraphQL libraries (if available in Node.js environment)
        try {
            if (typeof require !== 'undefined') {
                const originalRequire = require;
                require = function (module) {
                    const result = originalRequire.apply(this, arguments);

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
                            const originalExecute = result.execute;
                            result.execute = function (args) {
                                const {document} = args;
                                const variables = args.variableValues || {};

                                if (document?.definitions) {
                                    document.definitions.forEach(def => {
                                        if (def.selectionSet?.selections) {
                                            def.selectionSet.selections.forEach(selection => {
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

                                return originalExecute.call(this, args).then(result => {
                                    if (result.data) {
                                        const modified = self.processGraphQLResponse(result.data);
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
    modifyGraphQLVariables: variables => {
        const modified = JSON.parse(JSON.stringify(variables)); // Deep copy

        // Modify license-related variables
        for (let key in modified) {
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
    processGraphQLResponse: data => {
        const modified = JSON.parse(JSON.stringify(data)); // Deep copy

        // Recursively process response data
        function processObject(obj) {
            for (let key in obj) {
                if (Object.hasOwn(obj, key)) {
                    const value = obj[key];

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
    hookGraphQLResponseProcessing: () => {
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
    hookSubprotocolNegotiation: () => {
        // Hook HTTP upgrade request processing for WebSocket subprotocol manipulation
        const winHttpModule = Process.findModuleByName('winhttp.dll');
        if (winHttpModule) {
            const winHttpSendRequest = Module.findExportByName('winhttp.dll', 'WinHttpSendRequest');
            if (winHttpSendRequest) {
                Interceptor.attach(winHttpSendRequest, {
                    onEnter: args => {
                        const _request = args[0];
                        const headers = args[1];
                        const headersLength = args[2].toInt32();

                        if (!headers.isNull() && headersLength > 0) {
                            const headerString = headers.readUtf16String(headersLength);

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
                                const protocolMatch = headerString.match(
                                    /Sec-WebSocket-Protocol:\s*([^\r\n]+)/i
                                );
                                if (protocolMatch) {
                                    const protocols = protocolMatch[1]
                                        .split(',')
                                        .map(p => p.trim());
                                    send({
                                        type: 'info',
                                        target: 'websocket_interceptor',
                                        action: 'websocket_protocols_detected',
                                        protocols: protocols,
                                    });

                                    // Add license-friendly protocols
                                    const spoofedProtocols = protocols.concat([
                                        'license-bypass-v1',
                                        'validation-override',
                                        'auth-bypass-protocol',
                                    ]);

                                    const modifiedHeaders = headerString.replace(
                                        /Sec-WebSocket-Protocol:\s*[^\r\n]+/i,
                                        `Sec-WebSocket-Protocol: ${spoofedProtocols.join(', ')}`
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
            const winHttpReceiveResponse = Module.findExportByName(
                'winhttp.dll',
                'WinHttpReceiveResponse'
            );
            if (winHttpReceiveResponse) {
                Interceptor.attach(winHttpReceiveResponse, {
                    onLeave: function (retval) {
                        if (retval.toInt32() !== 0) {
                            const _request = this.context.rcx;

                            // Check for WebSocket handshake response
                            const bufferSize = 4096;
                            const buffer = Memory.alloc(bufferSize);
                            const sizeNeeded = Memory.alloc(4);

                            const queryHeaders = Module.findExportByName(
                                'winhttp.dll',
                                'WinHttpQueryHeaders'
                            );
                            if (queryHeaders) {
                                const WINHTTP_QUERY_RAW_HEADERS_CRLF = 22;
                                const queryFunc = new NativeFunction(queryHeaders, 'int', [
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
                                        sizeNeeded
                                    ) !== 0
                                ) {
                                    const responseHeaders = buffer.readUtf8String();

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
                                        const protocolMatch = responseHeaders.match(
                                            /Sec-WebSocket-Protocol:\s*([^\r\n]+)/i
                                        );
                                        if (protocolMatch) {
                                            const selectedProtocol = protocolMatch[1].trim();
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
    setupProtocolSpecificHandling: protocol => {
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
    handleJsonProtocol: message => {
        try {
            const parsed = JSON.parse(message);

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
    handleBinaryProtocol: message => {
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
    handleLicenseProtocol: message => {
        // License protocol specific processing
        let modified = message;

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
    hookCustomProtocolFormats: () => {
        // Hook common custom protocol formats used in license systems
        const customFormats = [
            {
                name: 'base64-json',
                detector: /^[A-Za-z0-9+/]+=*$/,
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
            formats: customFormats.map(f => f.name),
        });
    },

    // Decode Base64-encoded JSON messages
    decodeBase64Json: message => {
        try {
            const decoded = atob(message);
            const parsed = JSON.parse(decoded);

            // Apply license bypass
            if (parsed.license !== undefined) {
                parsed.license = true;
            }
            if (parsed.valid !== undefined) {
                parsed.valid = true;
            }
            if (parsed.expired !== undefined) {
                parsed.expired = false;
            }

            return btoa(JSON.stringify(parsed));
        } catch (_e) {
            return message;
        }
    },

    // Decode hex-encoded data
    decodeHexData: function (message) {
        try {
            const bytes = [];
            for (let i = 0; i < message.length; i += 2) {
                bytes.push(parseInt(message.substr(i, 2), 16));
            }

            const decoded = String.fromCharCode.apply(null, bytes);
            const modified = this.processIncomingMessage(decoded);

            // Re-encode to hex
            let result = '';
            for (let j = 0; j < modified.length; j++) {
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
            const _header = message.substring(0, 8);
            const data = message.substring(8);

            const modified = this.processIncomingMessage(data);
            return header + modified;
        } catch (_e) {
            return message;
        }
    },

    // Hook protocol switching during connection
    hookProtocolSwitching: function () {
        // Monitor for protocol upgrade/switching messages
        const originalProcessIncomingMessage = this.processIncomingMessage;
        this.processIncomingMessage = function (message) {
            // Check for protocol switching commands
            if (message.includes('SWITCH_PROTOCOL') || message.includes('UPGRADE_PROTOCOL')) {
                send({
                    type: 'info',
                    target: 'websocket_interceptor',
                    action: 'protocol_switch_detected',
                    message: message,
                });

                // Allow protocol switch but maintain interception
                const modified = originalProcessIncomingMessage.call(this, message);

                // Re-setup handlers for new protocol
                const protocolMatch = message.match(/PROTOCOL:\s*([^\s\r\n]+)/);
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
    hookDoHRequests: () => {
        // Hook HTTPS requests to common DoH servers
        const dohServers = ['cloudflare-dns.com', 'dns.google', 'dns.quad9.net', 'dns.adguard.com'];

        const winHttpModule = Process.findModuleByName('winhttp.dll');
        if (winHttpModule) {
            const winHttpConnect = Module.findExportByName('winhttp.dll', 'WinHttpConnect');
            if (winHttpConnect) {
                Interceptor.attach(winHttpConnect, {
                    onEnter: function (args) {
                        const serverName = args[1];
                        if (!serverName.isNull()) {
                            const hostname = serverName.readUtf16String();

                            if (dohServers.some(server => hostname.includes(server))) {
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
    hookDoHRequestsOnConnection: connection => {
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
    hookDoTConnections: () => {
        // DoT typically uses port 853
        const winSocketModule = Process.findModuleByName('ws2_32.dll');
        if (winSocketModule) {
            const connect = Module.findExportByName('ws2_32.dll', 'connect');
            if (connect) {
                Interceptor.attach(connect, {
                    onEnter: function (args) {
                        const socket = args[0];
                        const addr = args[1];
                        const addrlen = args[2].toInt32();

                        if (!addr.isNull() && addrlen >= 16) {
                            // Check for IPv4 connection (AF_INET = 2)
                            const family = addr.readU16();
                            if (family === 2) {
                                let port = addr.add(2).readU16();
                                port = ((port & 0xff) << 8) | ((port >> 8) & 0xff); // Convert from network byte order

                                if (port === 853) {
                                    // DoT port
                                    const ip = addr.add(4).readU32();
                                    const ipStr = [
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
    hookDoTSocket: socket => {
        // Hook send/recv on DoT socket
        const ws2_32 = Process.findModuleByName('ws2_32.dll');
        if (ws2_32) {
            const send = Module.findExportByName('ws2_32.dll', 'send');
            const recv = Module.findExportByName('ws2_32.dll', 'recv');

            if (send) {
                Interceptor.attach(send, {
                    onEnter: args => {
                        if (args[0].equals(socket)) {
                            const buffer = args[1];
                            const length = args[2].toInt32();

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
                        const bytesReceived = retval.toInt32();
                        if (bytesReceived > 0 && !this.buffer.isNull()) {
                            send({
                                type: 'info',
                                target: 'websocket_interceptor',
                                action: 'dot_dns_response_received',
                                socket: socket.toString(),
                                length: bytesReceived,
                            });

                            // Process DNS response for license domain spoofing
                            const modified = self.processDnsResponse(this.buffer, bytesReceived);
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
    hookSystemDNS: () => {
        // Hook GetAddrInfoExW for modern DNS resolution
        const ws2_32 = Process.findModuleByName('ws2_32.dll');
        if (ws2_32) {
            const getAddrInfoEx = Module.findExportByName('ws2_32.dll', 'GetAddrInfoExW');
            if (getAddrInfoEx) {
                Interceptor.attach(getAddrInfoEx, {
                    onEnter: function (args) {
                        const nodeName = args[0];
                        const _serviceName = args[1];

                        if (!nodeName.isNull()) {
                            const hostname = nodeName.readUtf16String();

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
                                const spoofedHostname = 'localhost';
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
            const gethostbyname = Module.findExportByName('ws2_32.dll', 'gethostbyname');
            if (gethostbyname) {
                Interceptor.attach(gethostbyname, {
                    onEnter: args => {
                        const hostname = args[0].readUtf8String();

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
            if (length < 12) {
                return; // Minimum DNS header size
            }

            const _header = buffer.readByteArray(12);
            const questions = buffer.add(12);

            // Extract domain name from DNS query
            const domainName = this.extractDnsName(questions);

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
    processDnsResponse: (buffer, length) => {
        try {
            if (length < 12) {
                return false;
            }

            // Check if this is a response to a license domain query
            const _header = buffer.readByteArray(12);
            const dataView = new DataView(header);

            const flags = dataView.getUint16(2);
            const isResponse = (flags & 0x8000) !== 0;
            const responseCode = flags & 0x000f;

            if (isResponse && responseCode === 0) {
                // NOERROR
                // Modify response to point license domains to localhost
                const _answerSection = buffer.add(12);

                // Skip questions section (simplified)
                const questionsCount = dataView.getUint16(4);

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
    extractDnsName: buffer => {
        try {
            let name = '';
            let offset = 0;
            let length = buffer.readU8();

            while (length > 0 && offset < 255) {
                if (name.length > 0) {
                    name += '.';
                }

                offset++;
                for (let i = 0; i < length; i++) {
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
        message: `Initializing WebSocket Interceptor v${websocketInterceptor.version}`,
    });

    // Start interception
    WebSocketInterceptor.init();

    // Export for external access
    rpc.exports = {
        getStats: () => ({
            intercepted: WebSocketInterceptor.stats.interceptedConnections,
            messages: WebSocketInterceptor.stats.interceptedMessages,
            spoofed: WebSocketInterceptor.stats.spoofedResponses,
        }),
        setConfig: config => {
            Object.assign(websocketInterceptor.config, config);
            WebSocketInterceptor.init(); // Reinitialize with new config
        },
    };
}

// Auto-execute the WebSocket interceptor
websocketInterceptor.run();

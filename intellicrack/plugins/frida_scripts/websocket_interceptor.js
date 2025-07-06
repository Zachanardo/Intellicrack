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
 * Version: 1.0.0
 * License: GPL v3
 */

{
    name: "WebSocket Interceptor",
    description: "WebSocket protocol hijacking for real-time license bypass",
    version: "1.0.0",
    
    // Configuration
    config: {
        // Target WebSocket URLs
        targetUrls: [
            "*license*", "*activation*", "*verify*", "*auth*",
            "*subscription*", "*validate*", "*check*"
        ],
        
        // Message patterns to intercept
        messagePatterns: {
            requests: [
                { pattern: /"action":\s*"verify"/i, handler: "spoofVerifyResponse" },
                { pattern: /"type":\s*"license_check"/i, handler: "spoofLicenseResponse" },
                { pattern: /"command":\s*"validate"/i, handler: "spoofValidateResponse" },
                { pattern: /"method":\s*"authenticate"/i, handler: "spoofAuthResponse" }
            ],
            responses: [
                { pattern: /"status":\s*"invalid"/i, replacement: '"status": "valid"' },
                { pattern: /"licensed":\s*false/i, replacement: '"licensed": true' },
                { pattern: /"expired":\s*true/i, replacement: '"expired": false' },
                { pattern: /"trial":\s*true/i, replacement: '"trial": false' }
            ]
        },
        
        // Spoofed responses
        spoofedResponses: {
            verify: {
                status: "success",
                valid: true,
                message: "License verified successfully",
                expiry: "2099-12-31T23:59:59Z"
            },
            license: {
                status: "active",
                type: "enterprise",
                features: ["all"],
                seats: 9999,
                expiry: "2099-12-31T23:59:59Z"
            },
            validate: {
                valid: true,
                code: 200,
                message: "Validation successful"
            },
            auth: {
                authenticated: true,
                token: "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJsaWNlbnNlZCIsImV4cCI6NDEwMjQ0NDgwMH0.valid",
                permissions: ["all"]
            }
        }
    },
    
    // Runtime state
    sockets: {},
    interceptedMessages: 0,
    spoofedResponses: 0,
    
    run: function() {
        console.log("[WebSocket] Starting WebSocket interceptor...");
        
        this.hookWebSocketConstructor();
        this.hookWebSocketMethods();
        this.hookXMLHttpRequestForSocketIO();
        this.hookWindowsWebSocket();
        
        console.log("[WebSocket] Interceptor installed");
    },
    
    // Hook WebSocket constructor
    hookWebSocketConstructor: function() {
        var self = this;
        
        // Browser/Electron WebSocket
        try {
            var WebSocketCtor = ObjC.classes.WebSocket || WebSocket;
            if (WebSocketCtor) {
                Interceptor.attach(WebSocketCtor.prototype.constructor, {
                    onEnter: function(args) {
                        var url = args[0];
                        console.log("[WebSocket] New WebSocket connection: " + url);
                        
                        // Check if URL matches our targets
                        if (self.shouldInterceptUrl(url)) {
                            this.shouldIntercept = true;
                        }
                    },
                    onLeave: function(retval) {
                        if (this.shouldIntercept) {
                            self.hookWebSocketInstance(retval);
                        }
                    }
                });
            }
        } catch(e) {
            // Not in browser context
        }
        
        // Native WebSocket implementations
        this.hookNativeWebSocket();
    },
    
    // Hook native WebSocket implementations
    hookNativeWebSocket: function() {
        var self = this;
        
        // Windows WebSocket API (websocket.dll)
        var wsModules = ["websocket.dll", "winhttp.dll"];
        
        wsModules.forEach(function(moduleName) {
            var module = Process.findModuleByName(moduleName);
            if (!module) return;
            
            // WebSocketCreateClientHandle
            var createHandle = Module.findExportByName(moduleName, "WebSocketCreateClientHandle");
            if (createHandle) {
                Interceptor.attach(createHandle, {
                    onLeave: function(retval) {
                        if (retval.toInt32() === 0) { // S_OK
                            var handle = this.context.r8.readPointer();
                            self.sockets[handle.toString()] = {
                                handle: handle,
                                state: "created",
                                messages: []
                            };
                            console.log("[WebSocket] Created native handle: " + handle);
                        }
                    }
                });
            }
            
            // WebSocketSend
            var wsSend = Module.findExportByName(moduleName, "WebSocketSend");
            if (wsSend) {
                Interceptor.attach(wsSend, {
                    onEnter: function(args) {
                        var handle = args[0];
                        var bufferType = args[1].toInt32();
                        var buffer = args[2];
                        var bufferLength = args[3] ? args[3].toInt32() : 0;
                        
                        if (self.sockets[handle.toString()]) {
                            var message = self.readWebSocketBuffer(buffer, bufferLength, bufferType);
                            console.log("[WebSocket] Outgoing: " + message);
                            
                            // Check if we should modify the message
                            var modified = self.processOutgoingMessage(message);
                            if (modified !== message) {
                                self.replaceWebSocketBuffer(args[2], modified, bufferType);
                                if (args[3]) args[3].writeU32(modified.length);
                                console.log("[WebSocket] Modified outgoing: " + modified);
                            }
                            
                            self.interceptedMessages++;
                        }
                    }
                });
            }
            
            // WebSocketReceive
            var wsReceive = Module.findExportByName(moduleName, "WebSocketReceive");
            if (wsReceive) {
                Interceptor.attach(wsReceive, {
                    onEnter: function(args) {
                        this.handle = args[0];
                        this.buffer = args[1];
                        this.bufferLength = args[2];
                    },
                    onLeave: function(retval) {
                        if (retval.toInt32() === 0 && self.sockets[this.handle.toString()]) {
                            var length = this.bufferLength.readU32();
                            var bufferType = this.context.r9 ? this.context.r9.readU32() : 1;
                            
                            var message = self.readWebSocketBuffer(this.buffer, length, bufferType);
                            console.log("[WebSocket] Incoming: " + message);
                            
                            // Process and potentially modify the message
                            var modified = self.processIncomingMessage(message);
                            if (modified !== message) {
                                self.replaceWebSocketBuffer(this.buffer, modified, bufferType);
                                this.bufferLength.writeU32(modified.length);
                                console.log("[WebSocket] Modified incoming: " + modified);
                                self.spoofedResponses++;
                            }
                            
                            self.interceptedMessages++;
                        }
                    }
                });
            }
        });
    },
    
    // Hook WebSocket instance methods
    hookWebSocketInstance: function(ws) {
        var self = this;
        
        // Store original methods
        var originalSend = ws.send;
        var originalClose = ws.close;
        
        // Hook send method
        ws.send = function(data) {
            console.log("[WebSocket] Send intercepted: " + data);
            
            var modified = self.processOutgoingMessage(data);
            if (modified !== data) {
                console.log("[WebSocket] Modified send: " + modified);
                self.interceptedMessages++;
            }
            
            return originalSend.call(this, modified);
        };
        
        // Hook message event
        ws.addEventListener('message', function(event) {
            var data = event.data;
            console.log("[WebSocket] Message received: " + data);
            
            var modified = self.processIncomingMessage(data);
            if (modified !== data) {
                // Create modified event
                event.stopImmediatePropagation();
                var modifiedEvent = new MessageEvent('message', {
                    data: modified,
                    origin: event.origin,
                    lastEventId: event.lastEventId,
                    source: event.source,
                    ports: event.ports
                });
                
                console.log("[WebSocket] Modified message: " + modified);
                self.spoofedResponses++;
                
                // Dispatch modified event
                setTimeout(function() {
                    ws.dispatchEvent(modifiedEvent);
                }, 0);
            }
            
            self.interceptedMessages++;
        }, true); // Use capture phase
        
        // Hook close method
        ws.close = function(code, reason) {
            console.log("[WebSocket] Connection closing: " + code + " " + reason);
            return originalClose.call(this, code, reason);
        };
    },
    
    // Hook WebSocket methods globally
    hookWebSocketMethods: function() {
        var self = this;
        
        // Hook WinHTTP WebSocket upgrade
        var winHttpWebSocketCompleteUpgrade = Module.findExportByName("winhttp.dll", "WinHttpWebSocketCompleteUpgrade");
        if (winHttpWebSocketCompleteUpgrade) {
            Interceptor.attach(winHttpWebSocketCompleteUpgrade, {
                onEnter: function(args) {
                    this.request = args[0];
                },
                onLeave: function(retval) {
                    if (!retval.isNull()) {
                        console.log("[WebSocket] WinHTTP WebSocket upgraded");
                        self.sockets[retval.toString()] = {
                            handle: retval,
                            state: "connected",
                            type: "winhttp"
                        };
                    }
                }
            });
        }
        
        // Hook WinHTTP WebSocket send/receive
        ["WinHttpWebSocketSend", "WinHttpWebSocketReceive"].forEach(function(func) {
            var fn = Module.findExportByName("winhttp.dll", func);
            if (fn) {
                Interceptor.attach(fn, {
                    onEnter: function(args) {
                        this.handle = args[0];
                        this.bufferType = args[1].toInt32();
                        this.buffer = args[2];
                        this.bufferLength = args[3].toInt32();
                        this.isSend = func.includes("Send");
                    },
                    onLeave: function(retval) {
                        if (retval.toInt32() === 0 && self.sockets[this.handle.toString()]) {
                            var message = self.readWebSocketBuffer(this.buffer, this.bufferLength, this.bufferType);
                            
                            if (this.isSend) {
                                console.log("[WebSocket] WinHTTP Send: " + message);
                                var modified = self.processOutgoingMessage(message);
                                if (modified !== message) {
                                    self.replaceWebSocketBuffer(this.buffer, modified, this.bufferType);
                                }
                            } else {
                                console.log("[WebSocket] WinHTTP Receive: " + message);
                                var modified = self.processIncomingMessage(message);
                                if (modified !== message) {
                                    self.replaceWebSocketBuffer(this.buffer, modified, this.bufferType);
                                    self.spoofedResponses++;
                                }
                            }
                            
                            self.interceptedMessages++;
                        }
                    }
                });
            }
        });
    },
    
    // Hook XMLHttpRequest for Socket.IO fallback
    hookXMLHttpRequestForSocketIO: function() {
        var self = this;
        
        // Socket.IO often falls back to HTTP long-polling
        var xhrOpen = Module.findExportByName(null, "XMLHttpRequest.prototype.open");
        if (xhrOpen) {
            Interceptor.attach(xhrOpen, {
                onEnter: function(args) {
                    var method = args[0];
                    var url = args[1];
                    
                    if (url && url.toString().match(/socket\.io|engine\.io/i)) {
                        console.log("[WebSocket] Socket.IO request detected: " + url);
                        this.isSocketIO = true;
                    }
                }
            });
        }
    },
    
    // Hook Windows-specific WebSocket implementations
    hookWindowsWebSocket: function() {
        var self = this;
        
        // Windows.Networking.Sockets.MessageWebSocket (UWP apps)
        try {
            var messageWebSocket = ObjC.classes["Windows.Networking.Sockets.MessageWebSocket"];
            if (messageWebSocket) {
                Interceptor.attach(messageWebSocket["- connectAsync:"], {
                    onEnter: function(args) {
                        var uri = new ObjC.Object(args[2]);
                        console.log("[WebSocket] UWP WebSocket connecting to: " + uri.toString());
                    }
                });
            }
        } catch(e) {
            // Not a UWP app
        }
    },
    
    // Check if URL should be intercepted
    shouldInterceptUrl: function(url) {
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
    readWebSocketBuffer: function(buffer, length, bufferType) {
        if (!buffer || buffer.isNull()) return "";
        
        try {
            // bufferType: 0 = binary, 1 = UTF8, 2 = close
            if (bufferType === 0) {
                // Binary frame - convert to hex
                var bytes = [];
                for (var i = 0; i < Math.min(length, 1024); i++) {
                    bytes.push(buffer.add(i).readU8().toString(16).padStart(2, '0'));
                }
                return "BINARY[" + bytes.join(' ') + (length > 1024 ? "..." : "") + "]";
            } else {
                // Text frame
                return buffer.readUtf8String(length);
            }
        } catch(e) {
            return "<read error>";
        }
    },
    
    // Replace WebSocket buffer content
    replaceWebSocketBuffer: function(buffer, newContent, bufferType) {
        if (!buffer || buffer.isNull()) return;
        
        try {
            if (bufferType === 0) {
                // Binary - expect hex string
                if (newContent.startsWith("BINARY[")) {
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
        } catch(e) {
            console.log("[WebSocket] Failed to replace buffer: " + e);
        }
    },
    
    // Process outgoing message
    processOutgoingMessage: function(message) {
        if (!message || typeof message !== 'string') return message;
        
        // Check request patterns
        for (var i = 0; i < this.config.messagePatterns.requests.length; i++) {
            var pattern = this.config.messagePatterns.requests[i];
            if (message.match(pattern.pattern)) {
                console.log("[WebSocket] Matched request pattern: " + pattern.pattern);
                
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
    processIncomingMessage: function(message) {
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
                console.log("[WebSocket] Matched response pattern: " + pattern.pattern);
                modified = modified.replace(pattern.pattern, pattern.replacement);
            }
        }
        
        return modified;
    },
    
    // Spoofing handlers
    spoofVerifyResponse: function(originalMessage) {
        try {
            var parsed = JSON.parse(originalMessage);
            
            // Override with spoofed response
            Object.assign(parsed, this.config.spoofedResponses.verify);
            
            return JSON.stringify(parsed);
        } catch(e) {
            // Return generic success response
            return JSON.stringify(this.config.spoofedResponses.verify);
        }
    },
    
    spoofLicenseResponse: function(originalMessage) {
        try {
            var parsed = JSON.parse(originalMessage);
            Object.assign(parsed, this.config.spoofedResponses.license);
            return JSON.stringify(parsed);
        } catch(e) {
            return JSON.stringify(this.config.spoofedResponses.license);
        }
    },
    
    spoofValidateResponse: function(originalMessage) {
        try {
            var parsed = JSON.parse(originalMessage);
            Object.assign(parsed, this.config.spoofedResponses.validate);
            return JSON.stringify(parsed);
        } catch(e) {
            return JSON.stringify(this.config.spoofedResponses.validate);
        }
    },
    
    spoofAuthResponse: function(originalMessage) {
        try {
            var parsed = JSON.parse(originalMessage);
            Object.assign(parsed, this.config.spoofedResponses.auth);
            return JSON.stringify(parsed);
        } catch(e) {
            return JSON.stringify(this.config.spoofedResponses.auth);
        }
    }
}
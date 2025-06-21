/**
 * Central Orchestrator
 * 
 * Unified control system for coordinating all Frida scripts and bypass
 * techniques. Provides centralized management, monitoring, and automation.
 * 
 * Author: Intellicrack Framework
 * Version: 1.0.0
 * License: GPL v3
 */

{
    name: "Central Orchestrator",
    description: "Master control system for all bypass operations",
    version: "1.0.0",
    
    // Configuration
    config: {
        // Available scripts
        scripts: {
            registry: {
                name: "Registry Monitor Enhanced",
                path: "registry_monitor_enhanced.js",
                enabled: true,
                priority: 1
            },
            timeBomb: {
                name: "Time Bomb Defuser Advanced",
                path: "time_bomb_defuser_advanced.js",
                enabled: true,
                priority: 2
            },
            certPinner: {
                name: "Certificate Pinner Bypass",
                path: "certificate_pinner_bypass.js",
                enabled: true,
                priority: 1
            },
            websocket: {
                name: "WebSocket Interceptor",
                path: "websocket_interceptor.js",
                enabled: true,
                priority: 3
            },
            ntpBlocker: {
                name: "NTP Blocker",
                path: "ntp_blocker.js",
                enabled: true,
                priority: 2
            },
            tpmEmulator: {
                name: "TPM 2.0 Emulator",
                path: "tpm_emulator.js",
                enabled: true,
                priority: 1
            },
            http3Quic: {
                name: "HTTP/3 QUIC Interceptor",
                path: "http3_quic_interceptor.js",
                enabled: true,
                priority: 3
            },
            dotnetBypass: {
                name: ".NET Bypass Suite",
                path: "dotnet_bypass_suite.js",
                enabled: true,
                priority: 1
            }
        },
        
        // Automation rules
        automation: {
            // Auto-detect and load scripts
            autoDetect: true,
            
            // Auto-response patterns
            autoResponse: {
                license: {
                    pattern: /license|activation|serial/i,
                    response: "valid",
                    confidence: 0.8
                },
                trial: {
                    pattern: /trial|expire|demo/i,
                    response: "full",
                    confidence: 0.9
                },
                auth: {
                    pattern: /auth|login|credential/i,
                    response: "success",
                    confidence: 0.7
                }
            },
            
            // Behavioral rules
            behavioral: {
                // If registry check detected, enable time bomb defuser
                registryToTime: true,
                // If network check detected, enable certificate bypass
                networkToCert: true,
                // If TPM check detected, enable hardware emulation
                tpmToHardware: true
            }
        },
        
        // Monitoring
        monitoring: {
            // Log all operations
            logLevel: "info", // debug, info, warn, error
            
            // Statistics collection
            collectStats: true,
            statsInterval: 60000, // 1 minute
            
            // Alert thresholds
            alerts: {
                failedBypass: 5,
                highCpu: 80,
                memoryLeak: 100 // MB
            }
        },
        
        // Communication
        communication: {
            // IPC with main process
            ipc: {
                enabled: true,
                channel: "frida-orchestrator"
            },
            
            // Web dashboard
            dashboard: {
                enabled: true,
                port: 9999
            },
            
            // Remote control
            remote: {
                enabled: false,
                host: "127.0.0.1",
                port: 8888
            }
        }
    },
    
    // Runtime state
    loadedScripts: {},
    scriptInstances: {},
    globalStats: {
        startTime: Date.now(),
        totalBypasses: 0,
        totalFailures: 0,
        activeScripts: 0,
        memoryUsage: 0,
        cpuUsage: 0
    },
    detectedProtections: [],
    automationQueue: [],
    messageHandlers: {},
    
    run: function() {
        console.log("[Orchestrator] Initializing Central Orchestrator v" + this.version);
        console.log("[Orchestrator] Process: " + Process.id + " - " + Process.getCurrentThreadId());
        
        // Initialize components
        this.initializeMonitoring();
        this.initializeCommunication();
        this.detectEnvironment();
        
        // Load scripts based on priority
        this.loadScriptsByPriority();
        
        // Start automation engine
        this.startAutomation();
        
        // Start dashboard if enabled
        if (this.config.communication.dashboard.enabled) {
            this.startDashboard();
        }
        
        console.log("[Orchestrator] Initialization complete - " + 
                   this.globalStats.activeScripts + " scripts loaded");
    },
    
    // Initialize monitoring
    initializeMonitoring: function() {
        var self = this;
        
        // CPU monitoring
        this.cpuMonitor = setInterval(function() {
            // Simple CPU estimation based on script activity
            var activity = 0;
            Object.keys(self.scriptInstances).forEach(function(name) {
                var instance = self.scriptInstances[name];
                if (instance.stats) {
                    activity += instance.stats.interceptedCalls || 0;
                }
            });
            
            self.globalStats.cpuUsage = Math.min(activity / 100, 100);
            
            if (self.globalStats.cpuUsage > self.config.monitoring.alerts.highCpu) {
                self.alert("High CPU usage: " + self.globalStats.cpuUsage + "%");
            }
        }, 5000);
        
        // Memory monitoring
        this.memoryMonitor = setInterval(function() {
            if (Process.getCurrentThreadId) {
                // Estimate memory usage
                self.globalStats.memoryUsage = Process.enumerateModules().length * 0.1;
            }
        }, 10000);
        
        // Stats collection
        if (this.config.monitoring.collectStats) {
            this.statsCollector = setInterval(function() {
                self.collectStatistics();
            }, this.config.monitoring.statsInterval);
        }
        
        console.log("[Orchestrator] Monitoring initialized");
    },
    
    // Initialize communication
    initializeCommunication: function() {
        var self = this;
        
        // IPC setup
        if (this.config.communication.ipc.enabled) {
            this.setupIPC();
        }
        
        // Message handler for inter-script communication
        this.messageHandlers['orchestrator'] = function(message) {
            self.handleOrchestratorMessage(message);
        };
        
        // Global error handler
        Process.setExceptionHandler(function(details) {
            console.error("[Orchestrator] Exception: " + JSON.stringify(details));
            self.globalStats.totalFailures++;
            
            // Attempt recovery
            self.attemptRecovery(details);
        });
        
        console.log("[Orchestrator] Communication initialized");
    },
    
    // Detect environment
    detectEnvironment: function() {
        var self = this;
        
        console.log("[Orchestrator] Detecting environment...");
        
        // Detect platform
        this.platform = {
            os: Process.platform,
            arch: Process.arch,
            pointer: Process.pointerSize,
            pageSize: Process.pageSize
        };
        
        // Detect runtime
        this.runtime = {
            hasJava: typeof Java !== 'undefined',
            hasObjC: typeof ObjC !== 'undefined',
            hasWin32: Process.platform === 'windows'
        };
        
        // Detect protections
        this.detectProtections();
        
        // Detect target application
        this.detectTargetApp();
        
        console.log("[Orchestrator] Environment: " + JSON.stringify(this.platform));
        console.log("[Orchestrator] Runtime: " + JSON.stringify(this.runtime));
    },
    
    // Detect protections
    detectProtections: function() {
        var self = this;
        
        // Check for anti-debug
        if (this.checkAntiDebug()) {
            this.detectedProtections.push("anti-debug");
        }
        
        // Check for obfuscation
        if (this.checkObfuscation()) {
            this.detectedProtections.push("obfuscation");
        }
        
        // Check for virtualization
        if (this.checkVirtualization()) {
            this.detectedProtections.push("virtualization");
        }
        
        // Check for specific protections
        var protections = [
            { module: "themida", name: "Themida" },
            { module: "vmprotect", name: "VMProtect" },
            { module: "enigma", name: "Enigma" },
            { module: "asprotect", name: "ASProtect" },
            { module: "obsidium", name: "Obsidium" }
        ];
        
        Process.enumerateModules().forEach(function(module) {
            var moduleName = module.name.toLowerCase();
            
            protections.forEach(function(protection) {
                if (moduleName.includes(protection.module)) {
                    self.detectedProtections.push(protection.name);
                    console.log("[Orchestrator] Detected protection: " + protection.name);
                }
            });
        });
        
        if (this.detectedProtections.length > 0) {
            console.log("[Orchestrator] Protections detected: " + this.detectedProtections.join(", "));
        }
    },
    
    // Check for anti-debug
    checkAntiDebug: function() {
        // Check PEB for debugger flag
        if (Process.platform === 'windows') {
            try {
                var peb = Process.getCurrentThreadId(); // Simplified
                return false; // Would check actual PEB
            } catch(e) {}
        }
        
        return false;
    },
    
    // Check for obfuscation
    checkObfuscation: function() {
        // Check for obfuscated strings
        var suspiciousCount = 0;
        
        Process.enumerateModules().forEach(function(module) {
            if (module.name.match(/[^\x20-\x7E]/)) {
                suspiciousCount++;
            }
        });
        
        return suspiciousCount > 3;
    },
    
    // Check for virtualization
    checkVirtualization: function() {
        // Check for VM artifacts
        var vmIndicators = ["vmware", "virtualbox", "qemu", "xen", "parallels"];
        var found = false;
        
        Process.enumerateModules().forEach(function(module) {
            var moduleName = module.name.toLowerCase();
            vmIndicators.forEach(function(indicator) {
                if (moduleName.includes(indicator)) {
                    found = true;
                }
            });
        });
        
        return found;
    },
    
    // Detect target application
    detectTargetApp: function() {
        var self = this;
        
        this.targetApp = {
            name: "Unknown",
            version: "Unknown",
            modules: []
        };
        
        // Get main module
        var mainModule = Process.enumerateModules()[0];
        if (mainModule) {
            this.targetApp.name = mainModule.name;
            this.targetApp.path = mainModule.path;
            
            // Try to get version
            if (Process.platform === 'windows') {
                // Would use GetFileVersionInfo
            }
        }
        
        // Detect known applications
        var knownApps = [
            { pattern: /adobe/i, scripts: ["timeBomb", "registry", "certPinner"] },
            { pattern: /autodesk/i, scripts: ["websocket", "http3Quic", "dotnetBypass"] },
            { pattern: /microsoft/i, scripts: ["dotnetBypass", "tpmEmulator"] },
            { pattern: /jetbrains/i, scripts: ["certPinner", "timeBomb"] }
        ];
        
        knownApps.forEach(function(app) {
            if (mainModule.name.match(app.pattern)) {
                console.log("[Orchestrator] Detected known application type");
                
                // Enable recommended scripts
                app.scripts.forEach(function(scriptName) {
                    if (self.config.scripts[scriptName]) {
                        self.config.scripts[scriptName].priority = 0; // Highest priority
                    }
                });
            }
        });
    },
    
    // Load scripts by priority
    loadScriptsByPriority: function() {
        var self = this;
        
        // Sort scripts by priority
        var sortedScripts = Object.keys(this.config.scripts)
            .filter(function(name) {
                return self.config.scripts[name].enabled;
            })
            .sort(function(a, b) {
                return self.config.scripts[a].priority - self.config.scripts[b].priority;
            });
        
        // Load scripts
        sortedScripts.forEach(function(name) {
            self.loadScript(name);
        });
    },
    
    // Load individual script
    loadScript: function(name) {
        var scriptConfig = this.config.scripts[name];
        if (!scriptConfig || !scriptConfig.enabled) return;
        
        try {
            console.log("[Orchestrator] Loading script: " + scriptConfig.name);
            
            // Create script instance
            var instance = {
                name: name,
                config: scriptConfig,
                stats: {
                    loaded: Date.now(),
                    interceptedCalls: 0,
                    bypasses: 0,
                    failures: 0
                },
                api: this.createScriptAPI(name)
            };
            
            // Load and execute script
            // In real implementation, would load from file
            this.scriptInstances[name] = instance;
            this.globalStats.activeScripts++;
            
            console.log("[Orchestrator] Script loaded: " + scriptConfig.name);
            
            // Send initialization message
            this.sendToScript(name, {
                type: "init",
                config: this.config,
                environment: {
                    platform: this.platform,
                    runtime: this.runtime,
                    protections: this.detectedProtections
                }
            });
            
        } catch(e) {
            console.error("[Orchestrator] Failed to load script " + name + ": " + e);
            this.globalStats.totalFailures++;
        }
    },
    
    // Create script API
    createScriptAPI: function(scriptName) {
        var self = this;
        
        return {
            // Report bypass success
            reportSuccess: function(details) {
                self.scriptInstances[scriptName].stats.bypasses++;
                self.globalStats.totalBypasses++;
                
                if (self.config.monitoring.logLevel === "debug") {
                    console.log("[Orchestrator] " + scriptName + " bypass: " + JSON.stringify(details));
                }
                
                // Trigger automation rules
                self.checkAutomationRules(scriptName, "success", details);
            },
            
            // Report bypass failure
            reportFailure: function(details) {
                self.scriptInstances[scriptName].stats.failures++;
                self.globalStats.totalFailures++;
                
                console.warn("[Orchestrator] " + scriptName + " failure: " + JSON.stringify(details));
                
                // Check alert threshold
                if (self.scriptInstances[scriptName].stats.failures >= self.config.monitoring.alerts.failedBypass) {
                    self.alert(scriptName + " has exceeded failure threshold");
                }
                
                // Trigger automation rules
                self.checkAutomationRules(scriptName, "failure", details);
            },
            
            // Send message to another script
            sendMessage: function(targetScript, message) {
                self.sendToScript(targetScript, {
                    from: scriptName,
                    message: message
                });
            },
            
            // Request coordination
            requestCoordination: function(action, params) {
                return self.coordinate(scriptName, action, params);
            },
            
            // Update statistics
            updateStats: function(stats) {
                Object.assign(self.scriptInstances[scriptName].stats, stats);
            },
            
            // Get global configuration
            getConfig: function() {
                return self.config;
            },
            
            // Get environment info
            getEnvironment: function() {
                return {
                    platform: self.platform,
                    runtime: self.runtime,
                    protections: self.detectedProtections,
                    targetApp: self.targetApp
                };
            }
        };
    },
    
    // Start automation engine
    startAutomation: function() {
        var self = this;
        
        console.log("[Orchestrator] Starting automation engine");
        
        // Process automation queue
        this.automationProcessor = setInterval(function() {
            self.processAutomationQueue();
        }, 100);
        
        // Pattern monitoring
        this.patternMonitor = setInterval(function() {
            self.monitorPatterns();
        }, 1000);
        
        // Behavioral monitoring
        if (this.config.automation.behavioral) {
            this.behavioralMonitor = setInterval(function() {
                self.monitorBehavior();
            }, 5000);
        }
    },
    
    // Process automation queue
    processAutomationQueue: function() {
        while (this.automationQueue.length > 0) {
            var task = this.automationQueue.shift();
            
            try {
                this.executeAutomationTask(task);
            } catch(e) {
                console.error("[Orchestrator] Automation error: " + e);
            }
        }
    },
    
    // Execute automation task
    executeAutomationTask: function(task) {
        switch(task.type) {
            case "enableScript":
                if (!this.scriptInstances[task.script]) {
                    this.loadScript(task.script);
                }
                break;
                
            case "disableScript":
                if (this.scriptInstances[task.script]) {
                    this.unloadScript(task.script);
                }
                break;
                
            case "coordinate":
                this.coordinateScripts(task.scripts, task.action);
                break;
                
            case "respond":
                this.autoRespond(task.pattern, task.response);
                break;
        }
    },
    
    // Monitor patterns
    monitorPatterns: function() {
        var self = this;
        
        // Check loaded modules for patterns
        Process.enumerateModules().forEach(function(module) {
            Object.keys(self.config.automation.autoResponse).forEach(function(key) {
                var rule = self.config.automation.autoResponse[key];
                
                if (module.name.match(rule.pattern)) {
                    // Queue auto-response
                    self.automationQueue.push({
                        type: "respond",
                        pattern: key,
                        response: rule.response
                    });
                }
            });
        });
    },
    
    // Monitor behavior
    monitorBehavior: function() {
        var behavioral = this.config.automation.behavioral;
        
        // Registry to time bomb
        if (behavioral.registryToTime && 
            this.scriptInstances.registry && 
            this.scriptInstances.registry.stats.bypasses > 0) {
            
            if (!this.scriptInstances.timeBomb) {
                console.log("[Orchestrator] Behavioral rule: Enabling time bomb defuser");
                this.automationQueue.push({
                    type: "enableScript",
                    script: "timeBomb"
                });
            }
        }
        
        // Network to certificate
        if (behavioral.networkToCert) {
            var networkActivity = false;
            
            ["websocket", "http3Quic"].forEach(function(script) {
                if (this.scriptInstances[script] && 
                    this.scriptInstances[script].stats.interceptedCalls > 0) {
                    networkActivity = true;
                }
            }, this);
            
            if (networkActivity && !this.scriptInstances.certPinner) {
                console.log("[Orchestrator] Behavioral rule: Enabling certificate bypass");
                this.automationQueue.push({
                    type: "enableScript",
                    script: "certPinner"
                });
            }
        }
        
        // TPM to hardware
        if (behavioral.tpmToHardware &&
            this.detectedProtections.includes("hardware")) {
            
            if (!this.scriptInstances.tpmEmulator) {
                console.log("[Orchestrator] Behavioral rule: Enabling TPM emulator");
                this.automationQueue.push({
                    type: "enableScript",
                    script: "tpmEmulator"
                });
            }
        }
    },
    
    // Check automation rules
    checkAutomationRules: function(scriptName, event, details) {
        // Script-specific rules
        if (scriptName === "registry" && event === "success") {
            if (details && details.includes("license")) {
                // Registry license check detected
                this.automationQueue.push({
                    type: "coordinate",
                    scripts: ["registry", "timeBomb"],
                    action: "syncLicense"
                });
            }
        }
        
        // Chain reactions
        if (event === "failure") {
            // If one script fails, try alternatives
            this.attemptAlternatives(scriptName);
        }
    },
    
    // Coordinate between scripts
    coordinate: function(requester, action, params) {
        console.log("[Orchestrator] Coordination request from " + requester + ": " + action);
        
        switch(action) {
            case "syncLicense":
                // Synchronize license information across scripts
                var licenseData = params || {};
                
                ["registry", "dotnetBypass", "websocket"].forEach(function(script) {
                    if (this.scriptInstances[script] && script !== requester) {
                        this.sendToScript(script, {
                            type: "updateLicense",
                            data: licenseData
                        });
                    }
                }, this);
                break;
                
            case "blockTime":
                // Coordinate time blocking
                ["timeBomb", "ntpBlocker"].forEach(function(script) {
                    if (this.scriptInstances[script]) {
                        this.sendToScript(script, {
                            type: "enforceTime",
                            time: params.time
                        });
                    }
                }, this);
                break;
                
            case "bypassNetwork":
                // Coordinate network bypass
                ["certPinner", "websocket", "http3Quic"].forEach(function(script) {
                    if (this.scriptInstances[script]) {
                        this.sendToScript(script, {
                            type: "bypassAll"
                        });
                    }
                }, this);
                break;
        }
        
        return true;
    },
    
    // Send message to script
    sendToScript: function(scriptName, message) {
        if (this.scriptInstances[scriptName]) {
            // In real implementation, would use actual messaging
            console.log("[Orchestrator] Message to " + scriptName + ": " + JSON.stringify(message));
        }
    },
    
    // Handle orchestrator messages
    handleOrchestratorMessage: function(message) {
        switch(message.type) {
            case "loadScript":
                this.loadScript(message.script);
                break;
                
            case "unloadScript":
                this.unloadScript(message.script);
                break;
                
            case "updateConfig":
                Object.assign(this.config, message.config);
                break;
                
            case "getStatus":
                return this.getStatus();
                
            case "executeCommand":
                return this.executeCommand(message.command, message.params);
        }
    },
    
    // Unload script
    unloadScript: function(name) {
        if (this.scriptInstances[name]) {
            console.log("[Orchestrator] Unloading script: " + name);
            
            // Send shutdown message
            this.sendToScript(name, { type: "shutdown" });
            
            // Remove instance
            delete this.scriptInstances[name];
            this.globalStats.activeScripts--;
        }
    },
    
    // Get orchestrator status
    getStatus: function() {
        return {
            uptime: Date.now() - this.globalStats.startTime,
            stats: this.globalStats,
            scripts: Object.keys(this.scriptInstances).map(function(name) {
                return {
                    name: name,
                    stats: this.scriptInstances[name].stats
                };
            }, this),
            protections: this.detectedProtections,
            targetApp: this.targetApp
        };
    },
    
    // Execute command
    executeCommand: function(command, params) {
        switch(command) {
            case "reload":
                this.reloadAllScripts();
                break;
                
            case "reset":
                this.resetStatistics();
                break;
                
            case "setLogLevel":
                this.config.monitoring.logLevel = params.level;
                break;
                
            case "enableScript":
                this.config.scripts[params.script].enabled = true;
                this.loadScript(params.script);
                break;
                
            case "disableScript":
                this.config.scripts[params.script].enabled = false;
                this.unloadScript(params.script);
                break;
        }
    },
    
    // Collect statistics
    collectStatistics: function() {
        var stats = {
            timestamp: Date.now(),
            global: this.globalStats,
            scripts: {}
        };
        
        Object.keys(this.scriptInstances).forEach(function(name) {
            stats.scripts[name] = this.scriptInstances[name].stats;
        }, this);
        
        // Log or send stats
        if (this.config.monitoring.logLevel === "debug") {
            console.log("[Orchestrator] Statistics: " + JSON.stringify(stats));
        }
        
        // Check for anomalies
        this.checkAnomalies(stats);
    },
    
    // Check for anomalies
    checkAnomalies: function(stats) {
        // High failure rate
        if (stats.global.totalFailures > stats.global.totalBypasses * 0.5) {
            this.alert("High failure rate detected");
        }
        
        // Script not responding
        Object.keys(this.scriptInstances).forEach(function(name) {
            var script = this.scriptInstances[name];
            var idle = Date.now() - script.stats.lastActivity;
            
            if (idle > 300000) { // 5 minutes
                this.alert("Script not responding: " + name);
            }
        }, this);
    },
    
    // Alert
    alert: function(message) {
        console.warn("[Orchestrator] ALERT: " + message);
        
        // Send alert through IPC if enabled
        if (this.config.communication.ipc.enabled) {
            send({
                type: "alert",
                message: message,
                timestamp: Date.now()
            });
        }
    },
    
    // Attempt recovery
    attemptRecovery: function(details) {
        console.log("[Orchestrator] Attempting recovery...");
        
        // Identify failed component
        var failedScript = null;
        Object.keys(this.scriptInstances).forEach(function(name) {
            // Simple heuristic - check last activity
            if (Date.now() - this.scriptInstances[name].stats.lastActivity > 10000) {
                failedScript = name;
            }
        }, this);
        
        if (failedScript) {
            console.log("[Orchestrator] Restarting failed script: " + failedScript);
            this.unloadScript(failedScript);
            this.loadScript(failedScript);
        }
    },
    
    // Attempt alternatives
    attemptAlternatives: function(failedScript) {
        var alternatives = {
            "certPinner": ["websocket", "http3Quic"],
            "timeBomb": ["ntpBlocker", "registry"],
            "registry": ["dotnetBypass"],
            "websocket": ["http3Quic"],
            "http3Quic": ["websocket"]
        };
        
        if (alternatives[failedScript]) {
            alternatives[failedScript].forEach(function(alt) {
                if (!this.scriptInstances[alt]) {
                    console.log("[Orchestrator] Trying alternative: " + alt);
                    this.automationQueue.push({
                        type: "enableScript",
                        script: alt
                    });
                }
            }, this);
        }
    },
    
    // Setup IPC
    setupIPC: function() {
        var self = this;
        
        // Frida's send/recv for IPC
        recv(this.config.communication.ipc.channel, function(message) {
            var response = self.handleOrchestratorMessage(message);
            if (response) {
                send({
                    type: "response",
                    data: response
                });
            }
        });
        
        // Send ready signal
        send({
            type: "ready",
            version: this.version,
            scripts: Object.keys(this.config.scripts)
        });
    },
    
    // Start dashboard
    startDashboard: function() {
        console.log("[Orchestrator] Dashboard would start on port " + 
                   this.config.communication.dashboard.port);
        
        // In real implementation, would start web server
        // For now, just log status periodically
        setInterval(function() {
            var status = this.getStatus();
            console.log("[Orchestrator] Dashboard update: " + 
                       status.scripts.length + " scripts, " +
                       status.stats.totalBypasses + " bypasses");
        }.bind(this), 30000);
    },
    
    // Reload all scripts
    reloadAllScripts: function() {
        console.log("[Orchestrator] Reloading all scripts");
        
        var scripts = Object.keys(this.scriptInstances);
        scripts.forEach(function(name) {
            this.unloadScript(name);
        }, this);
        
        this.loadScriptsByPriority();
    },
    
    // Reset statistics
    resetStatistics: function() {
        this.globalStats = {
            startTime: Date.now(),
            totalBypasses: 0,
            totalFailures: 0,
            activeScripts: this.globalStats.activeScripts,
            memoryUsage: 0,
            cpuUsage: 0
        };
        
        Object.keys(this.scriptInstances).forEach(function(name) {
            this.scriptInstances[name].stats = {
                loaded: this.scriptInstances[name].stats.loaded,
                interceptedCalls: 0,
                bypasses: 0,
                failures: 0
            };
        }, this);
        
        console.log("[Orchestrator] Statistics reset");
    }
}
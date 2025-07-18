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
 * Obfuscation Detector
 * 
 * Advanced detection and bypass of code obfuscation techniques including
 * control flow flattening, opaque predicates, virtualization, and more.
 * 
 * Author: Intellicrack Framework
 * Version: 1.0.0
 * License: GPL v3
 */

{
    name: "Obfuscation Detector",
    description: "Detect and bypass advanced code obfuscation techniques",
    version: "1.0.0",
    
    // Configuration
    config: {
        // Detection methods
        detection: {
            controlFlow: true,
            opaquePredicates: true,
            virtualization: true,
            stringEncryption: true,
            apiHashing: true,
            junkCode: true,
            polymorphism: true,
            metamorphism: true
        },
        
        // Analysis depth
        analysis: {
            maxDepth: 10,
            timeout: 30000,
            cacheResults: true,
            parallelAnalysis: true
        },
        
        // Bypass techniques
        bypass: {
            autoDeobfuscate: true,
            patchPredicates: true,
            devirtualize: true,
            decryptStrings: true,
            resolveAPIs: true,
            removeJunk: true
        },
        
        // Machine learning
        ml: {
            enabled: true,
            modelPath: null,
            confidence: 0.85,
            updateModel: true
        }
    },
    
    // Runtime state
    detectedObfuscations: [],
    bypassedTechniques: {},
    stats: {
        functionsAnalyzed: 0,
        obfuscationsDetected: 0,
        obfuscationsBypassed: 0,
        stringsDecrypted: 0,
        apisResolved: 0
    },
    mlModel: null,
    cache: {},
    
    run: function() {
        send({
            type: "status",
            target: "obfuscation_detector",
            action: "initializing_detector",
            version: this.version
        });
        
        // Initialize ML model
        if (this.config.ml.enabled) {
            this.initializeML();
        }
        
        // Start analysis
        this.analyzeLoadedModules();
        
        // Hook dynamic loading
        this.hookModuleLoading();
        
        // Start monitoring
        this.startMonitoring();
        
        send({
            type: "status",
            target: "obfuscation_detector",
            action: "detector_initialized"
        });
    },
    
    // Initialize machine learning
    initializeML: function() {
        send({
            type: "info",
            target: "obfuscation_detector",
            action: "initializing_ml_detection"
        });
        
        // Create feature extractor
        this.featureExtractor = {
            extractFeatures: function(code, size) {
                var features = {
                    entropy: 0,
                    jumpDensity: 0,
                    callDensity: 0,
                    unusualInstructions: 0,
                    stackManipulation: 0,
                    indirectBranches: 0,
                    selfModifying: 0,
                    antiDebug: 0
                };
                
                // Calculate entropy
                var bytes = code.readByteArray(Math.min(size, 1024));
                features.entropy = this.calculateEntropy(bytes);
                
                // Analyze instructions
                var instructions = this.disassemble(code, size);
                features.jumpDensity = this.calculateJumpDensity(instructions);
                features.callDensity = this.calculateCallDensity(instructions);
                features.unusualInstructions = this.countUnusualInstructions(instructions);
                features.stackManipulation = this.analyzeStackOperations(instructions);
                features.indirectBranches = this.countIndirectBranches(instructions);
                
                return features;
            }.bind(this),
            
            calculateEntropy: function(bytes) {
                var freq = {};
                for (var i = 0; i < bytes.length; i++) {
                    freq[bytes[i]] = (freq[bytes[i]] || 0) + 1;
                }
                
                var entropy = 0;
                for (var byte in freq) {
                    var p = freq[byte] / bytes.length;
                    entropy -= p * Math.log2(p);
                }
                
                return entropy;
            },
            
            disassemble: function(code, size) {
                // Simple disassembly for feature extraction
                var instructions = [];
                var offset = 0;
                
                while (offset < size && offset < 1024) {
                    try {
                        var inst = Instruction.parse(code.add(offset));
                        instructions.push({
                            address: code.add(offset),
                            mnemonic: inst.mnemonic,
                            operands: inst.operands,
                            size: inst.size
                        });
                        offset += inst.size;
                    } catch(e) {
                        offset++;
                    }
                }
                
                return instructions;
            },
            
            calculateJumpDensity: function(instructions) {
                var jumps = 0;
                var jumpMnemonics = ["jmp", "je", "jne", "jz", "jnz", "ja", "jb", "jg", "jl"];
                
                instructions.forEach(function(inst) {
                    if (jumpMnemonics.some(function(j) { return inst.mnemonic.startsWith(j); })) {
                        jumps++;
                    }
                });
                
                return jumps / Math.max(instructions.length, 1);
            },
            
            calculateCallDensity: function(instructions) {
                var calls = 0;
                
                instructions.forEach(function(inst) {
                    if (inst.mnemonic === "call") {
                        calls++;
                    }
                });
                
                return calls / Math.max(instructions.length, 1);
            },
            
            countUnusualInstructions: function(instructions) {
                var unusual = 0;
                var unusualMnemonics = ["int3", "ud2", "hlt", "in", "out", "rdtsc", "cpuid"];
                
                instructions.forEach(function(inst) {
                    if (unusualMnemonics.includes(inst.mnemonic)) {
                        unusual++;
                    }
                });
                
                return unusual;
            },
            
            analyzeStackOperations: function(instructions) {
                var stackOps = 0;
                
                instructions.forEach(function(inst) {
                    if (inst.mnemonic.includes("push") || inst.mnemonic.includes("pop") ||
                        (inst.operands && inst.operands.includes("esp")) ||
                        (inst.operands && inst.operands.includes("rsp"))) {
                        stackOps++;
                    }
                });
                
                return stackOps / Math.max(instructions.length, 1);
            },
            
            countIndirectBranches: function(instructions) {
                var indirect = 0;
                
                instructions.forEach(function(inst) {
                    if ((inst.mnemonic === "jmp" || inst.mnemonic === "call") &&
                        inst.operands && inst.operands.includes("[")) {
                        indirect++;
                    }
                });
                
                return indirect;
            }
        };
        
        // Create simple neural network for classification
        this.mlModel = {
            predict: function(features) {
                // Simple threshold-based classification
                var score = 0;
                
                if (features.entropy > 6.5) score += 0.3;
                if (features.jumpDensity > 0.3) score += 0.2;
                if (features.unusualInstructions > 2) score += 0.2;
                if (features.indirectBranches > 3) score += 0.15;
                if (features.stackManipulation > 0.4) score += 0.15;
                
                return {
                    isObfuscated: score > this.config.ml.confidence,
                    confidence: score,
                    type: this.classifyObfuscationType(features)
                };
            }.bind(this),
            
            classifyObfuscationType: function(features) {
                var types = [];
                
                if (features.jumpDensity > 0.4) types.push("control_flow_flattening");
                if (features.indirectBranches > 5) types.push("virtualization");
                if (features.entropy > 7) types.push("encryption");
                if (features.unusualInstructions > 3) types.push("anti_analysis");
                
                return types;
            }
        };
    },
    
    // Analyze loaded modules
    analyzeLoadedModules: function() {
        var self = this;
        
        send({
            type: "info",
            target: "obfuscation_detector",
            action: "analyzing_loaded_modules"
        });
        
        Process.enumerateModules().forEach(function(module) {
            // Skip system modules
            if (self.isSystemModule(module.name)) return;
            
            send({
                type: "info",
                target: "obfuscation_detector",
                action: "analyzing_module",
                module_name: module.name
            });
            
            // Analyze exports
            module.enumerateExports().forEach(function(exp) {
                if (exp.type === 'function') {
                    self.analyzeFunction(exp.address, exp.name, module.name);
                }
            });
            
            // Analyze code sections
            module.enumerateRanges('r-x').forEach(function(range) {
                self.analyzeCodeSection(range, module.name);
            });
        });
    },
    
    // Analyze function
    analyzeFunction: function(address, name, moduleName) {
        this.stats.functionsAnalyzed++;
        
        // Check cache
        var cacheKey = address.toString();
        if (this.config.analysis.cacheResults && this.cache[cacheKey]) {
            return this.cache[cacheKey];
        }
        
        var result = {
            address: address,
            name: name,
            module: moduleName,
            obfuscations: [],
            bypassed: false
        };
        
        // Control flow analysis
        if (this.config.detection.controlFlow) {
            var cfResult = this.detectControlFlowObfuscation(address);
            if (cfResult.detected) {
                result.obfuscations.push(cfResult);
                this.detectedObfuscations.push(cfResult);
            }
        }
        
        // Opaque predicate detection
        if (this.config.detection.opaquePredicates) {
            var opResult = this.detectOpaquePredicates(address);
            if (opResult.detected) {
                result.obfuscations.push(opResult);
                this.detectedObfuscations.push(opResult);
            }
        }
        
        // Virtualization detection
        if (this.config.detection.virtualization) {
            var vmResult = this.detectVirtualization(address);
            if (vmResult.detected) {
                result.obfuscations.push(vmResult);
                this.detectedObfuscations.push(vmResult);
            }
        }
        
        // String encryption detection
        if (this.config.detection.stringEncryption) {
            var strResult = this.detectStringEncryption(address);
            if (strResult.detected) {
                result.obfuscations.push(strResult);
                this.detectedObfuscations.push(strResult);
            }
        }
        
        // ML-based detection
        if (this.config.ml.enabled && this.mlModel) {
            var features = this.featureExtractor.extractFeatures(address, 1024);
            var prediction = this.mlModel.predict(features);
            
            if (prediction.isObfuscated) {
                result.obfuscations.push({
                    type: "ml_detected",
                    confidence: prediction.confidence,
                    subtypes: prediction.type
                });
            }
        }
        
        // Apply bypasses
        if (result.obfuscations.length > 0 && this.config.bypass.autoDeobfuscate) {
            result.bypassed = this.applyBypasses(address, result.obfuscations);
        }
        
        // Cache result
        if (this.config.analysis.cacheResults) {
            this.cache[cacheKey] = result;
        }
        
        if (result.obfuscations.length > 0) {
            send({
                type: "warning",
                target: "obfuscation_detector",
                action: "obfuscation_detected",
                function_name: name,
                obfuscation_types: result.obfuscations.map(function(o) { return o.type; })
            });
            this.stats.obfuscationsDetected += result.obfuscations.length;
        }
        
        return result;
    },
    
    // Detect control flow obfuscation
    detectControlFlowObfuscation: function(address) {
        var result = {
            type: "control_flow_flattening",
            detected: false,
            patterns: [],
            confidence: 0
        };
        
        try {
            // Look for dispatcher pattern
            var code = address.readByteArray(512);
            
            // Pattern 1: Switch-based dispatcher
            var switchPattern = [0xFF, 0x24, 0x85]; // jmp [eax*4 + dispatcher_table]
            if (this.findPattern(code, switchPattern)) {
                result.patterns.push("switch_dispatcher");
                result.confidence += 0.4;
            }
            
            // Pattern 2: State machine pattern
            var statePattern = [0x83, 0xF8]; // cmp eax, state
            var stateCount = this.countPattern(code, statePattern);
            if (stateCount > 5) {
                result.patterns.push("state_machine");
                result.confidence += 0.3;
            }
            
            // Pattern 3: Excessive jumps
            var jumpCount = 0;
            for (var i = 0; i < code.length - 1; i++) {
                if (code[i] === 0xE9 || code[i] === 0xEB || // jmp
                    (code[i] === 0x0F && code[i+1] >= 0x80 && code[i+1] <= 0x8F)) { // jcc
                    jumpCount++;
                }
            }
            
            if (jumpCount > code.length * 0.1) {
                result.patterns.push("excessive_jumps");
                result.confidence += 0.3;
            }
            
            result.detected = result.confidence > 0.6;
            
        } catch(e) {
            console.error("[Obfuscation] Error detecting control flow: " + e);
        }
        
        return result;
    },
    
    // Detect opaque predicates
    detectOpaquePredicates: function(address) {
        var result = {
            type: "opaque_predicates",
            detected: false,
            predicates: [],
            confidence: 0
        };
        
        try {
            var code = address.readByteArray(256);
            
            // Common opaque predicate patterns
            var patterns = [
                // (x^2) >= 0 always true
                {
                    bytes: [0x0F, 0xAF, 0xC0, 0x79], // imul eax, eax; jns
                    name: "square_non_negative"
                },
                // (x & -x) == x for x = 2^n
                {
                    bytes: [0x89, 0xC2, 0xF7, 0xD2, 0x21, 0xD0, 0x39, 0xC2],
                    name: "power_of_two"
                },
                // ((x * 7) & 1) == (x & 1)
                {
                    bytes: [0x6B, 0xC0, 0x07, 0x83, 0xE0, 0x01],
                    name: "modular_arithmetic"
                }
            ];
            
            patterns.forEach(function(pattern) {
                if (this.findPattern(code, pattern.bytes)) {
                    result.predicates.push({
                        type: pattern.name,
                        address: address
                    });
                    result.confidence += 0.35;
                }
            }.bind(this));
            
            // Check for always-taken branches
            var branches = this.findConditionalBranches(address);
            branches.forEach(function(branch) {
                if (this.isAlwaysTaken(branch)) {
                    result.predicates.push({
                        type: "always_taken",
                        address: branch.address
                    });
                    result.confidence += 0.2;
                }
            }.bind(this));
            
            result.detected = result.predicates.length > 0 && result.confidence > 0.5;
            
        } catch(e) {
            console.error("[Obfuscation] Error detecting opaque predicates: " + e);
        }
        
        return result;
    },
    
    // Detect virtualization
    detectVirtualization: function(address) {
        var result = {
            type: "virtualization",
            detected: false,
            vmType: "unknown",
            confidence: 0
        };
        
        try {
            // Check for VM dispatcher patterns
            var patterns = {
                // VMProtect pattern
                vmprotect: [0x8B, 0x04, 0x24, 0x83, 0xC4, 0x04, 0xFF, 0x20],
                // Themida pattern
                themida: [0x60, 0x9C, 0xE8, 0x00, 0x00, 0x00, 0x00, 0x5D],
                // Code Virtualizer pattern
                cv: [0x55, 0x8B, 0xEC, 0x83, 0xEC, 0x20, 0x53, 0x56, 0x57, 0xE8]
            };
            
            var code = address.readByteArray(512);
            
            Object.keys(patterns).forEach(function(vmType) {
                if (this.findPattern(code, patterns[vmType])) {
                    result.vmType = vmType;
                    result.confidence += 0.6;
                }
            }.bind(this));
            
            // Check for VM context structure
            var contextPattern = this.findVMContext(address);
            if (contextPattern) {
                result.confidence += 0.3;
                result.context = contextPattern;
            }
            
            // Check for bytecode handlers
            var handlers = this.findBytecodeHandlers(address);
            if (handlers.length > 10) {
                result.confidence += 0.2;
                result.handlers = handlers;
            }
            
            result.detected = result.confidence > 0.7;
            
        } catch(e) {
            console.error("[Obfuscation] Error detecting virtualization: " + e);
        }
        
        return result;
    },
    
    // Detect string encryption
    detectStringEncryption: function(address) {
        var result = {
            type: "string_encryption",
            detected: false,
            methods: [],
            confidence: 0
        };
        
        try {
            // Check for common decryption patterns
            var patterns = [
                // XOR decryption loop
                {
                    bytes: [0x80, 0x34, 0x08], // xor byte [eax+ecx], key
                    name: "xor_loop"
                },
                // RC4 initialization
                {
                    bytes: [0x88, 0x04, 0x08, 0x40, 0x3D, 0x00, 0x01],
                    name: "rc4_init"
                },
                // Base64 decode
                {
                    bytes: [0x0F, 0xB6, 0x00, 0x83, 0xE8, 0x41],
                    name: "base64_decode"
                }
            ];
            
            var code = address.readByteArray(512);
            
            patterns.forEach(function(pattern) {
                if (this.findPattern(code, pattern.bytes)) {
                    result.methods.push(pattern.name);
                    result.confidence += 0.4;
                }
            }.bind(this));
            
            // Check for string obfuscation calls
            var calls = this.findFunctionCalls(address);
            calls.forEach(function(call) {
                if (this.isStringDecryptor(call.target)) {
                    result.methods.push("decryptor_call");
                    result.confidence += 0.3;
                }
            }.bind(this));
            
            result.detected = result.methods.length > 0 && result.confidence > 0.5;
            
        } catch(e) {
            console.error("[Obfuscation] Error detecting string encryption: " + e);
        }
        
        return result;
    },
    
    // Apply bypasses
    applyBypasses: function(address, obfuscations) {
        var self = this;
        var bypassed = false;
        
        obfuscations.forEach(function(obfuscation) {
            switch(obfuscation.type) {
                case "control_flow_flattening":
                    if (self.config.bypass.autoDeobfuscate) {
                        bypassed |= self.bypassControlFlow(address, obfuscation);
                    }
                    break;
                    
                case "opaque_predicates":
                    if (self.config.bypass.patchPredicates) {
                        bypassed |= self.bypassOpaquePredicates(address, obfuscation);
                    }
                    break;
                    
                case "virtualization":
                    if (self.config.bypass.devirtualize) {
                        bypassed |= self.bypassVirtualization(address, obfuscation);
                    }
                    break;
                    
                case "string_encryption":
                    if (self.config.bypass.decryptStrings) {
                        bypassed |= self.bypassStringEncryption(address, obfuscation);
                    }
                    break;
            }
        });
        
        return bypassed;
    },
    
    // Bypass control flow flattening
    bypassControlFlow: function(address, obfuscation) {
        send({
            type: "bypass",
            target: "obfuscation_detector",
            action: "bypassing_control_flow_flattening",
            address: address.toString()
        });
        
        try {
            // Find dispatcher
            var dispatcher = this.findDispatcher(address);
            if (!dispatcher) return false;
            
            // Extract state transitions
            var transitions = this.extractStateTransitions(dispatcher);
            
            // Rebuild original flow
            var originalFlow = this.rebuildControlFlow(transitions);
            
            // Patch the function
            if (originalFlow.length > 0) {
                this.patchControlFlow(address, originalFlow);
                this.stats.obfuscationsBypassed++;
                return true;
            }
            
        } catch(e) {
            console.error("[Obfuscation] Error bypassing control flow: " + e);
        }
        
        return false;
    },
    
    // Bypass opaque predicates
    bypassOpaquePredicates: function(address, obfuscation) {
        send({
            type: "bypass",
            target: "obfuscation_detector",
            action: "bypassing_opaque_predicates",
            address: address.toString()
        });
        
        var patched = 0;
        
        obfuscation.predicates.forEach(function(predicate) {
            try {
                switch(predicate.type) {
                    case "always_taken":
                        // Convert conditional jump to unconditional
                        this.patchToUnconditionalJump(predicate.address);
                        patched++;
                        break;
                        
                    case "never_taken":
                        // NOP out the jump
                        this.nopInstruction(predicate.address);
                        patched++;
                        break;
                        
                    case "square_non_negative":
                    case "power_of_two":
                    case "modular_arithmetic":
                        // Simplify the predicate
                        this.simplifyPredicate(predicate.address);
                        patched++;
                        break;
                }
            } catch(e) {
                send({
                    type: "error",
                    target: "obfuscation_detector",
                    action: "error_patching_predicate",
                    error: e.toString()
                });
            }
        }.bind(this));
        
        if (patched > 0) {
            this.stats.obfuscationsBypassed++;
            send({
                type: "success",
                target: "obfuscation_detector",
                action: "patched_opaque_predicates",
                count: patched
            });
        }
        
        return patched > 0;
    },
    
    // Bypass virtualization
    bypassVirtualization: function(address, obfuscation) {
        send({
            type: "bypass",
            target: "obfuscation_detector",
            action: "bypassing_virtualization",
            address: address.toString()
        });
        
        try {
            switch(obfuscation.vmType) {
                case "vmprotect":
                    return this.bypassVMProtect(address, obfuscation);
                    
                case "themida":
                    return this.bypassThemida(address, obfuscation);
                    
                case "cv":
                    return this.bypassCodeVirtualizer(address, obfuscation);
                    
                default:
                    return this.bypassGenericVM(address, obfuscation);
            }
        } catch(e) {
            send({
                type: "error",
                target: "obfuscation_detector",
                action: "error_bypassing_virtualization",
                error: e.toString()
            });
        }
        
        return false;
    },
    
    // Bypass string encryption
    bypassStringEncryption: function(address, obfuscation) {
        send({
            type: "bypass",
            target: "obfuscation_detector",
            action: "bypassing_string_encryption",
            address: address.toString()
        });
        
        var decrypted = 0;
        
        obfuscation.methods.forEach(function(method) {
            try {
                switch(method) {
                    case "xor_loop":
                        decrypted += this.decryptXorStrings(address);
                        break;
                        
                    case "rc4_init":
                        decrypted += this.decryptRC4Strings(address);
                        break;
                        
                    case "base64_decode":
                        decrypted += this.decryptBase64Strings(address);
                        break;
                        
                    case "decryptor_call":
                        decrypted += this.hookStringDecryptor(address);
                        break;
                }
            } catch(e) {
                send({
                    type: "error",
                    target: "obfuscation_detector",
                    action: "error_decrypting_strings",
                    error: e.toString()
                });
            }
        }.bind(this));
        
        if (decrypted > 0) {
            this.stats.stringsDecrypted += decrypted;
            this.stats.obfuscationsBypassed++;
            send({
                type: "success",
                target: "obfuscation_detector",
                action: "decrypted_strings",
                count: decrypted
            });
        }
        
        return decrypted > 0;
    },
    
    // Decrypt XOR strings
    decryptXorStrings: function(address) {
        var decrypted = 0;
        
        // Find XOR loops
        var xorLoops = this.findXorLoops(address);
        
        xorLoops.forEach(function(loop) {
            // Extract encrypted data
            var data = this.extractEncryptedData(loop);
            if (!data) return;
            
            // Find XOR key
            var key = this.findXorKey(loop);
            if (!key) return;
            
            // Decrypt
            var plaintext = this.xorDecrypt(data, key);
            
            // Replace encrypted with plaintext
            this.replaceEncryptedString(loop.dataAddress, plaintext);
            decrypted++;
            
            send({
                type: "info",
                target: "obfuscation_detector",
                action: "decrypted_xor_string",
                plaintext: plaintext
            });
        }.bind(this));
        
        return decrypted;
    },
    
    // Hook module loading
    hookModuleLoading: function() {
        var self = this;
        
        // Windows
        if (Process.platform === 'windows') {
            var loadLibrary = Module.findExportByName("kernel32.dll", "LoadLibraryW");
            if (loadLibrary) {
                Interceptor.attach(loadLibrary, {
                    onLeave: function(retval) {
                        if (!retval.isNull()) {
                            var module = Process.findModuleByAddress(retval);
                            if (module) {
                                send({
                                    type: "info",
                                    target: "obfuscation_detector",
                                    action: "new_module_loaded",
                                    module_name: module.name,
                                    base_address: module.base.toString()
                                });
                                self.analyzeModule(module);
                            }
                        }
                    }
                });
            }
        }
        
        // Linux
        else if (Process.platform === 'linux') {
            var dlopen = Module.findExportByName(null, "dlopen");
            if (dlopen) {
                Interceptor.attach(dlopen, {
                    onEnter: function(args) {
                        this.path = args[0].readCString();
                    },
                    onLeave: function(retval) {
                        if (!retval.isNull() && this.path) {
                            send({
                                type: "info",
                                target: "obfuscation_detector",
                                action: "new_module_loaded_dlopen",
                                module_path: this.path
                            });
                            var module = Process.findModuleByName(this.path);
                            if (module) {
                                self.analyzeModule(module);
                            }
                        }
                    }
                });
            }
        }
    },
    
    // Start monitoring
    startMonitoring: function() {
        var self = this;
        
        // Monitor for dynamic code generation
        this.monitorDynamicCode();
        
        // Monitor for self-modifying code
        this.monitorSelfModifying();
        
        // Periodic analysis
        setInterval(function() {
            self.periodicAnalysis();
        }, 30000);
    },
    
    // Monitor dynamic code generation
    monitorDynamicCode: function() {
        var self = this;
        
        // VirtualAlloc
        var virtualAlloc = Module.findExportByName("kernel32.dll", "VirtualAlloc");
        if (virtualAlloc) {
            Interceptor.attach(virtualAlloc, {
                onLeave: function(retval) {
                    if (!retval.isNull()) {
                        var protection = this.context.r9.toInt32();
                        if (protection & 0x20) { // PAGE_EXECUTE
                            send({
                                type: "info",
                                target: "obfuscation_detector",
                                action: "executable_memory_allocated",
                                address: retval.toString(),
                                protection: protection.toString(16)
                            });
                            
                            // Delay analysis to allow code to be written
                            setTimeout(function() {
                                self.analyzeCodeSection({
                                    base: retval,
                                    size: this.context.rdx.toInt32()
                                }, "dynamic");
                            }.bind(this), 100);
                        }
                    }
                }
            });
        }
    },
    
    // Helper functions
    findPattern: function(haystack, needle) {
        for (var i = 0; i <= haystack.length - needle.length; i++) {
            var found = true;
            for (var j = 0; j < needle.length; j++) {
                if (haystack[i + j] !== needle[j]) {
                    found = false;
                    break;
                }
            }
            if (found) return i;
        }
        return -1;
    },
    
    countPattern: function(haystack, needle) {
        var count = 0;
        var offset = 0;
        
        while (offset < haystack.length) {
            var pos = this.findPattern(haystack.slice(offset), needle);
            if (pos === -1) break;
            count++;
            offset += pos + needle.length;
        }
        
        return count;
    },
    
    isSystemModule: function(name) {
        var systemModules = [
            "ntdll", "kernel32", "user32", "advapi32", "msvcrt",
            "libc", "libpthread", "ld-linux"
        ];
        
        name = name.toLowerCase();
        return systemModules.some(function(sys) {
            return name.includes(sys);
        });
    },
    
    analyzeCodeSection: function(range, moduleName) {
        // Analyze code section for obfuscation
        var features = this.featureExtractor.extractFeatures(range.base, range.size);
        var prediction = this.mlModel.predict(features);
        
        if (prediction.isObfuscated) {
            send({
                type: "info",
                target: "obfuscation_detector",
                action: "obfuscated_code_section_detected",
                module_name: moduleName,
                address: range.base.toString(),
                confidence: prediction.confidence,
                obfuscation_type: prediction.type
            });
            
            this.detectedObfuscations.push({
                address: range.base,
                size: range.size,
                module: moduleName,
                type: prediction.type,
                confidence: prediction.confidence
            });
            
            this.stats.obfuscationsDetected++;
        }
    },
    
    // Get statistics
    getStatistics: function() {
        return {
            functionsAnalyzed: this.stats.functionsAnalyzed,
            obfuscationsDetected: this.stats.obfuscationsDetected,
            obfuscationsBypassed: this.stats.obfuscationsBypassed,
            stringsDecrypted: this.stats.stringsDecrypted,
            apisResolved: this.stats.apisResolved,
            detectedTypes: this.detectedObfuscations.map(function(o) { return o.type; })
                .filter(function(v, i, a) { return a.indexOf(v) === i; })
        };
    }
};

// Run the detector
ObfuscationDetector.run();
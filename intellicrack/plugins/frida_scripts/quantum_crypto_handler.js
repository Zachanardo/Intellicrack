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
 * Quantum Cryptography Handler for Frida
 * 
 * Comprehensive post-quantum cryptography bypass supporting lattice-based,
 * code-based, hash-based, and multivariate algorithms. Handles Kyber, Dilithium,
 * SPHINCS+, Rainbow, and other NIST PQC candidates.
 * 
 * Author: Intellicrack Framework
 * Version: 2.0.0
 * License: GPL v3
 */

{
    name: "Quantum Crypto Handler",
    description: "Post-quantum cryptography detection and bypass for future-proof protection",
    version: "2.0.0",
    
    // Configuration
    config: {
        // Post-quantum algorithms
        algorithms: {
            // Lattice-based
            lattice: {
                kyber: {
                    name: "CRYSTALS-Kyber",
                    type: "KEM",
                    security_levels: [512, 768, 1024],
                    patterns: ["kyber", "KYBER", "crystals", "mlkem"],
                    constants: {
                        n: 256,
                        q: 3329,
                        eta1: 3,
                        eta2: 2
                    }
                },
                dilithium: {
                    name: "CRYSTALS-Dilithium",
                    type: "Signature",
                    security_levels: [2, 3, 5],
                    patterns: ["dilithium", "DILITHIUM", "mldsa"],
                    constants: {
                        q: 8380417,
                        d: 13,
                        tau: 39
                    }
                },
                ntru: {
                    name: "NTRU",
                    type: "KEM",
                    patterns: ["ntru", "NTRU", "NTRUEncrypt"],
                    constants: {
                        n: 701,
                        q: 8192
                    }
                }
            },
            
            // Code-based
            code_based: {
                classic_mceliece: {
                    name: "Classic McEliece",
                    type: "KEM",
                    patterns: ["mceliece", "mce", "goppa"],
                    parameters: {
                        m: 13,
                        n: 6960,
                        t: 119
                    }
                }
            },
            
            // Hash-based
            hash_based: {
                sphincs: {
                    name: "SPHINCS+",
                    type: "Signature",
                    patterns: ["sphincs", "SPHINCS", "slhdsa"],
                    variants: ["shake256", "sha256", "haraka"],
                    parameters: {
                        n: 32,
                        w: 16,
                        h: 64
                    }
                }
            },
            
            // Multivariate
            multivariate: {
                rainbow: {
                    name: "Rainbow",
                    type: "Signature",
                    patterns: ["rainbow", "RAINBOW", "uov"],
                    parameters: {
                        v1: 68,
                        o1: 32,
                        o2: 48
                    }
                }
            },
            
            // Isogeny-based (deprecated but still in use)
            isogeny: {
                sike: {
                    name: "SIKE",
                    type: "KEM",
                    patterns: ["sike", "SIKE", "sidh"],
                    note: "Broken but may still be encountered"
                }
            }
        },
        
        // Detection settings
        detection: {
            scan_crypto_libs: true,
            detect_hybrid_modes: true,
            hook_all_pqc: false,
            log_operations: true
        },
        
        // Bypass strategies
        bypass: {
            forge_signatures: true,
            fake_key_exchange: true,
            return_success: true,
            skip_verification: true
        }
    },
    
    // State tracking
    state: {
        detected_algorithms: new Set(),
        hooked_functions: new Map(),
        bypassed_operations: [],
        crypto_contexts: new Map(),
        key_materials: new Map()
    },
    
    // Initialize the handler
    initialize: function() {
        console.log("[Quantum Crypto] Initializing post-quantum crypto handler...");
        
        // Detect PQC libraries
        this.detectPQCLibraries();
        
        // Hook crypto operations
        this.hookCryptoOperations();
        
        // Hook key generation
        this.hookKeyGeneration();
        
        // Hook verification functions
        this.hookVerification();
        
        // Start monitoring
        this.startMonitoring();
        
        console.log("[Quantum Crypto] Initialization complete!");
    },
    
    // Detect post-quantum crypto libraries
    detectPQCLibraries: function() {
        console.log("[PQC Detection] Scanning for post-quantum crypto libraries...");
        
        // Common PQC library patterns
        const libPatterns = [
            // NIST PQC reference implementations
            "pqcrystals", "liboqs", "PQClean",
            
            // Specific implementations
            "libkyber", "libdilithium", "libsphincs",
            "libmceliece", "librainbow",
            
            // Commercial libraries
            "wolfssl", "bouncycastle", "openquantum",
            
            // Hybrid modes
            "hybrid_kem", "composite_sig"
        ];
        
        // Scan loaded modules
        Process.enumerateModules({
            onMatch: function(module) {
                libPatterns.forEach(pattern => {
                    if (module.name.toLowerCase().includes(pattern.toLowerCase())) {
                        console.log(`[PQC Detection] Found library: ${module.name}`);
                        this.analyzeLibrary(module);
                    }
                }.bind(this));
            }.bind(this),
            onComplete: function() {
                console.log("[PQC Detection] Module scan complete");
            }
        });
        
        // Scan for algorithm-specific patterns
        this.scanForAlgorithmPatterns();
    },
    
    // Analyze detected library
    analyzeLibrary: function(module) {
        console.log(`[Library Analysis] Analyzing ${module.name}...`);
        
        // Get exports
        const exports = module.enumerateExports();
        exports.forEach(exp => {
            // Check for PQC-related exports
            Object.values(this.config.algorithms).forEach(category => {
                Object.values(category).forEach(algo => {
                    algo.patterns.forEach(pattern => {
                        if (exp.name.toLowerCase().includes(pattern.toLowerCase())) {
                            console.log(`[Library Analysis] Found ${algo.name} function: ${exp.name}`);
                            this.hookPQCFunction(exp, algo);
                        }
                    });
                });
            });
        });
    },
    
    // Scan for algorithm patterns in memory
    scanForAlgorithmPatterns: function() {
        console.log("[Pattern Scan] Searching for PQC algorithm patterns...");
        
        // Kyber constants
        this.scanForKyber();
        
        // Dilithium constants
        this.scanForDilithium();
        
        // SPHINCS+ structures
        this.scanForSPHINCS();
        
        // Other algorithms
        this.scanForOtherPQC();
    },
    
    // Scan for Kyber implementation
    scanForKyber: function() {
        // Kyber polynomial operations use q=3329
        const kyberQ = 3329;
        const qBytes = [(kyberQ >> 8) & 0xFF, kyberQ & 0xFF];
        
        try {
            const matches = Memory.scanSync(Process.enumerateRanges('r-x'), {
                pattern: qBytes.map(b => b.toString(16).padStart(2, '0')).join(' '),
                mask: 'FF FF'
            });
            
            matches.forEach(match => {
                console.log(`[Kyber] Found q constant at ${match.address}`);
                
                // Hook nearby functions
                this.hookNearbyPQCFunctions(match.address, 'kyber');
            });
        } catch (e) {
            console.log("[Kyber Scan] Error:", e);
        }
        
        // Look for Kyber function names
        const kyberFuncs = [
            "kyber_keypair",
            "kyber_encaps",
            "kyber_decaps",
            "poly_ntt",
            "poly_invntt",
            "poly_basemul",
            "cbd2",
            "cbd3"
        ];
        
        kyberFuncs.forEach(func => {
            this.findAndHookFunction(func, 'kyber');
        });
    },
    
    // Scan for Dilithium implementation
    scanForDilithium: function() {
        // Dilithium uses q=8380417
        const dilithiumQ = 8380417;
        
        try {
            // Search for the constant
            const qBytes = [
                (dilithiumQ >> 24) & 0xFF,
                (dilithiumQ >> 16) & 0xFF,
                (dilithiumQ >> 8) & 0xFF,
                dilithiumQ & 0xFF
            ];
            
            const pattern = qBytes.map(b => b.toString(16).padStart(2, '0')).join(' ');
            
            const matches = Memory.scanSync(Process.enumerateRanges('r-x'), {
                pattern: pattern,
                mask: 'FF FF FF FF'
            });
            
            matches.forEach(match => {
                console.log(`[Dilithium] Found q constant at ${match.address}`);
                this.hookNearbyPQCFunctions(match.address, 'dilithium');
            });
        } catch (e) {
            console.log("[Dilithium Scan] Error:", e);
        }
        
        // Dilithium function patterns
        const dilithiumFuncs = [
            "dilithium_keypair",
            "dilithium_sign",
            "dilithium_verify",
            "polyvec_ntt",
            "polyvec_reduce",
            "challenge",
            "decompose"
        ];
        
        dilithiumFuncs.forEach(func => {
            this.findAndHookFunction(func, 'dilithium');
        });
    },
    
    // Hook crypto operations
    hookCryptoOperations: function() {
        console.log("[Crypto Ops] Hooking post-quantum crypto operations...");
        
        // Hook key encapsulation
        this.hookKEMOperations();
        
        // Hook digital signatures
        this.hookSignatureOperations();
        
        // Hook hybrid modes
        this.hookHybridOperations();
    },
    
    // Hook KEM operations
    hookKEMOperations: function() {
        // Generic KEM interface
        const kemOps = [
            "crypto_kem_keypair",
            "crypto_kem_enc",
            "crypto_kem_dec",
            "encapsulate",
            "decapsulate",
            "kem_keygen"
        ];
        
        kemOps.forEach(op => {
            this.findAndHookFunction(op, 'kem', {
                onEnter: function(args) {
                    console.log(`[KEM] ${op} called`);
                    
                    // Store context
                    this.context = {
                        operation: op,
                        args: args,
                        timestamp: Date.now()
                    };
                },
                onLeave: function(retval) {
                    console.log(`[KEM] ${op} returned:`, retval);
                    
                    // Bypass based on operation
                    if (this.config.bypass.fake_key_exchange) {
                        if (op.includes("enc") || op.includes("encapsulate")) {
                            // Fake successful encapsulation
                            this.fakeEncapsulation(this.context, retval);
                        } else if (op.includes("dec") || op.includes("decapsulate")) {
                            // Fake successful decapsulation
                            this.fakeDecapsulation(this.context, retval);
                        }
                    }
                }.bind(this)
            });
        });
    },
    
    // Hook signature operations
    hookSignatureOperations: function() {
        const sigOps = [
            "crypto_sign_keypair",
            "crypto_sign",
            "crypto_sign_verify",
            "crypto_sign_open",
            "sign_message",
            "verify_signature"
        ];
        
        sigOps.forEach(op => {
            this.findAndHookFunction(op, 'signature', {
                onEnter: function(args) {
                    console.log(`[Signature] ${op} called`);
                    this.sigContext = {
                        operation: op,
                        args: args
                    };
                },
                onLeave: function(retval) {
                    console.log(`[Signature] ${op} returned:`, retval);
                    
                    if (this.config.bypass.forge_signatures) {
                        if (op.includes("verify")) {
                            // Always return verification success
                            console.log("[Signature] Bypassing verification");
                            retval.replace(ptr(0)); // 0 = success in most implementations
                        } else if (op.includes("sign")) {
                            // Log signed data for analysis
                            this.logSignature(this.sigContext);
                        }
                    }
                }.bind(this)
            });
        });
    },
    
    // Find and hook function by name
    findAndHookFunction: function(funcName, category, callbacks) {
        try {
            // Search in exports first
            const exp = Module.findExportByName(null, funcName);
            if (exp) {
                console.log(`[Hook] Found ${funcName} in exports`);
                this.hookFunction(exp, funcName, category, callbacks);
                return;
            }
            
            // Search in memory
            const matches = Memory.scanSync(Process.enumerateRanges('r-x'), 
                'utf8:' + funcName);
            
            matches.forEach(match => {
                console.log(`[Hook] Found ${funcName} at ${match.address}`);
                
                // Find actual function
                const funcAddr = this.findNearestFunction(match.address);
                if (funcAddr) {
                    this.hookFunction(funcAddr, funcName, category, callbacks);
                }
            });
            
        } catch (e) {
            // Function not found
        }
    },
    
    // Hook a specific function
    hookFunction: function(address, name, category, callbacks) {
        if (this.state.hooked_functions.has(address.toString())) {
            return; // Already hooked
        }
        
        const hook = Interceptor.attach(address, callbacks || {
            onEnter: function(args) {
                console.log(`[${category}] ${name} called`);
                
                // Log arguments
                for (let i = 0; i < 4; i++) {
                    try {
                        console.log(`  arg[${i}]: ${args[i]}`);
                    } catch (e) {
                        // Invalid pointer
                    }
                }
            },
            onLeave: function(retval) {
                console.log(`[${category}] ${name} returned: ${retval}`);
                
                // Apply bypasses based on function name
                this.applyBypass(name, retval);
            }.bind(this)
        });
        
        this.state.hooked_functions.set(address.toString(), {
            name: name,
            category: category,
            hook: hook
        });
    },
    
    // Apply bypass based on function type
    applyBypass: function(funcName, retval) {
        const lowerName = funcName.toLowerCase();
        
        // Verification functions - return success
        if (lowerName.includes("verify") || lowerName.includes("check")) {
            if (this.config.bypass.skip_verification) {
                console.log(`[Bypass] Skipping verification in ${funcName}`);
                retval.replace(ptr(0)); // 0 = success
            }
        }
        
        // Validation functions - return valid
        if (lowerName.includes("valid") || lowerName.includes("authenticate")) {
            if (this.config.bypass.return_success) {
                console.log(`[Bypass] Returning success for ${funcName}`);
                retval.replace(ptr(1)); // 1 = valid/true
            }
        }
        
        // Key comparison - return equal
        if (lowerName.includes("compare") || lowerName.includes("equal")) {
            console.log(`[Bypass] Faking equality in ${funcName}`);
            retval.replace(ptr(0)); // 0 = equal
        }
    },
    
    // Hook key generation
    hookKeyGeneration: function() {
        console.log("[KeyGen] Hooking PQC key generation...");
        
        // Generic keypair functions
        const keygenPatterns = [
            "keypair",
            "keygen",
            "generate_key",
            "gen_key",
            "make_key"
        ];
        
        keygenPatterns.forEach(pattern => {
            this.findAndHookFunction(pattern, 'keygen', {
                onEnter: function(args) {
                    console.log(`[KeyGen] Key generation started: ${pattern}`);
                    this.keygenContext = {
                        pattern: pattern,
                        publicKey: args[0],
                        privateKey: args[1],
                        seed: args[2]
                    };
                },
                onLeave: function(retval) {
                    console.log(`[KeyGen] Key generation completed`);
                    
                    // Extract generated keys
                    this.extractGeneratedKeys(this.keygenContext);
                    
                    // Store for later use
                    this.storeKeyMaterial(this.keygenContext);
                }.bind(this)
            });
        });
    },
    
    // Extract generated keys
    extractGeneratedKeys: function(context) {
        try {
            // Determine key sizes based on algorithm
            const keySizes = this.getKeySizesForContext(context);
            
            if (context.publicKey && !context.publicKey.isNull()) {
                const pubKey = context.publicKey.readByteArray(keySizes.publicKey);
                console.log("[KeyGen] Public key extracted:", pubKey.length, "bytes");
                
                // Log first few bytes
                if (pubKey.length > 0) {
                    const preview = Array.from(pubKey.slice(0, 16))
                        .map(b => b.toString(16).padStart(2, '0'))
                        .join(' ');
                    console.log("[KeyGen] Public key preview:", preview);
                }
            }
            
            if (context.privateKey && !context.privateKey.isNull()) {
                const privKey = context.privateKey.readByteArray(keySizes.privateKey);
                console.log("[KeyGen] Private key extracted:", privKey.length, "bytes");
            }
            
        } catch (e) {
            console.log("[KeyGen] Error extracting keys:", e);
        }
    },
    
    // Get key sizes based on context
    getKeySizesForContext: function(context) {
        // Default sizes for common PQC algorithms
        const sizes = {
            kyber: { publicKey: 1568, privateKey: 3168 },      // Kyber-1024
            dilithium: { publicKey: 2592, privateKey: 4864 },  // Dilithium5
            sphincs: { publicKey: 64, privateKey: 128 },       // SPHINCS+
            mceliece: { publicKey: 1357824, privateKey: 14080 } // Classic McEliece
        };
        
        // Try to determine algorithm from context
        const pattern = context.pattern.toLowerCase();
        for (const [algo, size] of Object.entries(sizes)) {
            if (pattern.includes(algo)) {
                return size;
            }
        }
        
        // Default sizes
        return { publicKey: 4096, privateKey: 4096 };
    },
    
    // Hook verification functions
    hookVerification: function() {
        console.log("[Verify] Hooking PQC verification functions...");
        
        // Signature verification
        const verifyPatterns = [
            "verify",
            "check_sig",
            "validate_signature",
            "authenticate",
            "is_valid"
        ];
        
        verifyPatterns.forEach(pattern => {
            this.findAndHookFunction(pattern, 'verify', {
                onEnter: function(args) {
                    console.log(`[Verify] Verification started: ${pattern}`);
                    
                    // Store verification context
                    this.verifyContext = {
                        pattern: pattern,
                        message: args[0],
                        signature: args[1],
                        publicKey: args[2]
                    };
                },
                onLeave: function(retval) {
                    console.log(`[Verify] Verification result: ${retval}`);
                    
                    if (this.config.bypass.skip_verification) {
                        // Check current return value
                        const currentResult = retval.toInt32();
                        
                        // Most implementations: 0 = success, non-zero = failure
                        if (currentResult !== 0) {
                            console.log("[Verify] Bypassing failed verification");
                            retval.replace(ptr(0));
                            
                            // Log bypass
                            this.logBypass('verification', this.verifyContext);
                        }
                    }
                }.bind(this)
            });
        });
    },
    
    // Fake encapsulation result
    fakeEncapsulation: function(context, retval) {
        try {
            // Most KEM functions return 0 on success
            if (retval.toInt32() !== 0) {
                console.log("[KEM] Faking successful encapsulation");
                retval.replace(ptr(0));
                
                // Generate fake ciphertext if needed
                if (context.args[0] && !context.args[0].isNull()) {
                    // Get expected ciphertext size
                    const ctSize = this.getCiphertextSize(context.operation);
                    
                    // Fill with random-looking data
                    const fakeData = this.generateFakeData(ctSize);
                    context.args[0].writeByteArray(fakeData);
                }
            }
        } catch (e) {
            console.log("[KEM] Error faking encapsulation:", e);
        }
    },
    
    // Get expected ciphertext size
    getCiphertextSize: function(operation) {
        // Ciphertext sizes for common algorithms
        const sizes = {
            kyber512: 768,
            kyber768: 1088,
            kyber1024: 1568,
            ntru: 1230,
            mceliece: 240
        };
        
        // Try to match operation name
        const op = operation.toLowerCase();
        for (const [algo, size] of Object.entries(sizes)) {
            if (op.includes(algo)) {
                return size;
            }
        }
        
        // Default size
        return 1024;
    },
    
    // Generate fake random data
    generateFakeData: function(size) {
        const data = new Uint8Array(size);
        for (let i = 0; i < size; i++) {
            data[i] = Math.floor(Math.random() * 256);
        }
        return data;
    },
    
    // Hook hybrid crypto operations
    hookHybridOperations: function() {
        console.log("[Hybrid] Hooking hybrid PQC operations...");
        
        // Hybrid schemes combine classical and PQC
        const hybridPatterns = [
            "hybrid_kem",
            "composite_signature",
            "ecdh_kyber",
            "rsa_dilithium",
            "hybrid_tls"
        ];
        
        hybridPatterns.forEach(pattern => {
            this.findAndHookFunction(pattern, 'hybrid', {
                onEnter: function(args) {
                    console.log(`[Hybrid] ${pattern} called`);
                },
                onLeave: function(retval) {
                    // Hybrid schemes need both parts to succeed
                    if (this.config.bypass.fake_key_exchange) {
                        console.log(`[Hybrid] Bypassing ${pattern}`);
                        retval.replace(ptr(0)); // Success
                    }
                }.bind(this)
            });
        });
    },
    
    // Find nearest function from address
    findNearestFunction: function(address) {
        try {
            let addr = ptr(address);
            
            // Search backwards for function prologue
            for (let i = 0; i < 1000; i++) {
                addr = addr.sub(1);
                
                // Check for common prologues
                const inst = Instruction.parse(addr);
                if (inst && this.isFunctionPrologue(inst)) {
                    return addr;
                }
            }
        } catch (e) {
            // Continue searching
        }
        
        return null;
    },
    
    // Check if instruction is function prologue
    isFunctionPrologue: function(inst) {
        const prologues = [
            "push",
            "sub rsp",
            "sub esp",
            "stp",     // ARM64
            "str"      // ARM
        ];
        
        return prologues.some(p => inst.mnemonic.startsWith(p));
    },
    
    // Hook nearby PQC functions
    hookNearbyPQCFunctions: function(address, algorithm) {
        console.log(`[Hook] Searching for ${algorithm} functions near ${address}`);
        
        try {
            // Search around the constant
            const searchRange = 0x1000; // 4KB
            const startAddr = ptr(address).sub(searchRange);
            const endAddr = ptr(address).add(searchRange);
            
            // Find functions in range
            for (let addr = startAddr; addr.compare(endAddr) < 0; addr = addr.add(4)) {
                try {
                    const inst = Instruction.parse(addr);
                    if (inst && this.isFunctionPrologue(inst)) {
                        console.log(`[Hook] Found function at ${addr}`);
                        
                        // Hook it
                        this.hookFunction(addr, `${algorithm}_func_${addr}`, algorithm);
                        
                        // Skip past this function
                        addr = addr.add(0x100);
                    }
                } catch (e) {
                    // Invalid instruction
                }
            }
        } catch (e) {
            console.log("[Hook] Error searching nearby:", e);
        }
    },
    
    // Store key material
    storeKeyMaterial: function(context) {
        const keyId = `key_${Date.now()}`;
        
        this.state.key_materials.set(keyId, {
            algorithm: this.detectAlgorithmFromContext(context),
            publicKey: context.publicKey,
            privateKey: context.privateKey,
            timestamp: Date.now()
        });
        
        console.log(`[KeyStore] Stored key material: ${keyId}`);
    },
    
    // Detect algorithm from context
    detectAlgorithmFromContext: function(context) {
        const pattern = context.pattern.toLowerCase();
        
        // Check against known algorithms
        for (const [category, algos] of Object.entries(this.config.algorithms)) {
            for (const [key, algo] of Object.entries(algos)) {
                if (algo.patterns.some(p => pattern.includes(p.toLowerCase()))) {
                    return algo.name;
                }
            }
        }
        
        return "Unknown PQC";
    },
    
    // Log bypass operation
    logBypass: function(type, context) {
        const bypass = {
            type: type,
            timestamp: Date.now(),
            context: {
                pattern: context.pattern,
                algorithm: this.detectAlgorithmFromContext(context)
            }
        };
        
        this.state.bypassed_operations.push(bypass);
        
        // Keep only last 100 bypasses
        if (this.state.bypassed_operations.length > 100) {
            this.state.bypassed_operations.shift();
        }
    },
    
    // Start monitoring
    startMonitoring: function() {
        console.log("[Monitor] Starting PQC monitoring...");
        
        // Monitor memory allocations for key material
        this.monitorKeyAllocations();
        
        // Monitor crypto library loads
        this.monitorLibraryLoads();
        
        // Periodic statistics
        setInterval(() => {
            this.printStats();
        }, 30000);
    },
    
    // Monitor key allocations
    monitorKeyAllocations: function() {
        // Hook malloc/calloc for large allocations (potential keys)
        const malloc = Module.findExportByName(null, "malloc");
        if (malloc) {
            Interceptor.attach(malloc, {
                onEnter: function(args) {
                    const size = args[0].toInt32();
                    
                    // Check for PQC key sizes
                    const pqcSizes = [
                        1568, 3168,    // Kyber
                        2592, 4864,    // Dilithium
                        64, 128,       // SPHINCS+
                        1357824        // McEliece
                    ];
                    
                    if (pqcSizes.includes(size)) {
                        console.log(`[Malloc] Potential PQC key allocation: ${size} bytes`);
                        this.pendingAlloc = {
                            size: size,
                            timestamp: Date.now()
                        };
                    }
                }.bind(this),
                onLeave: function(retval) {
                    if (this.pendingAlloc) {
                        console.log(`[Malloc] PQC allocation at ${retval}`);
                        
                        // Track this allocation
                        this.state.crypto_contexts.set(retval.toString(), this.pendingAlloc);
                        this.pendingAlloc = null;
                    }
                }.bind(this)
            });
        }
    },
    
    // Print statistics
    printStats: function() {
        console.log("\n[Stats] Quantum Crypto Handler Statistics:");
        console.log(`  Detected algorithms: ${this.state.detected_algorithms.size}`);
        console.log(`  Hooked functions: ${this.state.hooked_functions.size}`);
        console.log(`  Bypassed operations: ${this.state.bypassed_operations.length}`);
        console.log(`  Stored keys: ${this.state.key_materials.size}`);
        console.log(`  Crypto contexts: ${this.state.crypto_contexts.size}`);
        
        if (this.state.detected_algorithms.size > 0) {
            console.log("\n  Detected algorithms:");
            this.state.detected_algorithms.forEach(algo => {
                console.log(`    - ${algo}`);
            });
        }
        
        if (this.state.bypassed_operations.length > 0) {
            console.log("\n  Recent bypasses:");
            this.state.bypassed_operations.slice(-5).forEach(bypass => {
                console.log(`    - ${bypass.type} (${bypass.context.algorithm}) at ${new Date(bypass.timestamp).toLocaleTimeString()}`);
            });
        }
    },
    
    // Hook PQC function from export
    hookPQCFunction: function(exp, algo) {
        this.state.detected_algorithms.add(algo.name);
        
        this.hookFunction(exp.address, exp.name, algo.name, {
            onEnter: function(args) {
                console.log(`[${algo.name}] ${exp.name} called`);
                
                // Special handling based on algorithm type
                if (algo.type === "KEM") {
                    this.handleKEMFunction(exp.name, args, algo);
                } else if (algo.type === "Signature") {
                    this.handleSignatureFunction(exp.name, args, algo);
                }
            }.bind(this),
            onLeave: function(retval) {
                console.log(`[${algo.name}] ${exp.name} returned: ${retval}`);
                
                // Apply algorithm-specific bypasses
                this.applyAlgorithmBypass(exp.name, retval, algo);
            }.bind(this)
        });
    },
    
    // Handle KEM function call
    handleKEMFunction: function(funcName, args, algo) {
        const lowerName = funcName.toLowerCase();
        
        if (lowerName.includes("encaps") || lowerName.includes("enc")) {
            console.log(`[${algo.name}] Encapsulation detected`);
            
            // Log public key if available
            if (args[1] && !args[1].isNull()) {
                console.log(`[${algo.name}] Public key at: ${args[1]}`);
            }
        } else if (lowerName.includes("decaps") || lowerName.includes("dec")) {
            console.log(`[${algo.name}] Decapsulation detected`);
            
            // Log ciphertext if available
            if (args[1] && !args[1].isNull()) {
                console.log(`[${algo.name}] Ciphertext at: ${args[1]}`);
            }
        }
    },
    
    // Handle signature function call
    handleSignatureFunction: function(funcName, args, algo) {
        const lowerName = funcName.toLowerCase();
        
        if (lowerName.includes("sign") && !lowerName.includes("verify")) {
            console.log(`[${algo.name}] Signing operation detected`);
            
            // Log message being signed
            if (args[1] && !args[1].isNull()) {
                try {
                    const msgLen = args[2] ? args[2].toInt32() : 64;
                    const message = args[1].readByteArray(Math.min(msgLen, 64));
                    console.log(`[${algo.name}] Message preview:`, message);
                } catch (e) {
                    // Can't read message
                }
            }
        } else if (lowerName.includes("verify")) {
            console.log(`[${algo.name}] Verification detected`);
        }
    },
    
    // Apply algorithm-specific bypass
    applyAlgorithmBypass: function(funcName, retval, algo) {
        const lowerName = funcName.toLowerCase();
        
        // Algorithm-specific bypasses
        switch (algo.name) {
            case "CRYSTALS-Kyber":
                if (lowerName.includes("decaps")) {
                    // Kyber decapsulation returns 0 on success
                    if (retval.toInt32() !== 0) {
                        console.log("[Kyber] Bypassing failed decapsulation");
                        retval.replace(ptr(0));
                    }
                }
                break;
                
            case "CRYSTALS-Dilithium":
                if (lowerName.includes("verify")) {
                    // Dilithium verify returns 0 on success
                    if (retval.toInt32() !== 0) {
                        console.log("[Dilithium] Bypassing failed verification");
                        retval.replace(ptr(0));
                    }
                }
                break;
                
            case "SPHINCS+":
                if (lowerName.includes("verify") || lowerName.includes("open")) {
                    // SPHINCS+ returns 0 on success
                    if (retval.toInt32() !== 0) {
                        console.log("[SPHINCS+] Bypassing failed verification");
                        retval.replace(ptr(0));
                    }
                }
                break;
                
            default:
                // Generic bypass
                if (lowerName.includes("verify") || lowerName.includes("check")) {
                    if (retval.toInt32() !== 0) {
                        console.log(`[${algo.name}] Generic bypass applied`);
                        retval.replace(ptr(0));
                    }
                }
        }
    },
    
    // Entry point
    run: function() {
        console.log("=====================================");
        console.log("Quantum Crypto Handler v2.0.0");
        console.log("Post-Quantum Cryptography Bypass");
        console.log("=====================================\n");
        
        this.initialize();
    }
};

// Auto-run on script load
rpc.exports = {
    init: function() {
        Java.performNow(function() {
            quantumCryptoHandler.run();
        });
    }
};

// Also run immediately if in Frida CLI
if (typeof Java !== 'undefined') {
    Java.performNow(function() {
        quantumCryptoHandler.run();
    });
} else {
    quantumCryptoHandler.run();
}
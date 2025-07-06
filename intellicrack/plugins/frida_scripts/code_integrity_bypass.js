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
 * Code Integrity Bypass
 * 
 * Advanced code integrity bypass for modern license protection systems.
 * Handles hash verification, digital signatures, and PE checksums.
 * 
 * Author: Intellicrack Framework
 * Version: 2.0.0
 * License: GPL v3
 */

{
    name: "Code Integrity Bypass",
    description: "Advanced code integrity and signature verification bypass",
    version: "2.0.0",
    
    // Configuration for code integrity bypass
    config: {
        // Hash algorithm spoofing
        hashAlgorithms: {
            md5: {
                enabled: true,
                spoofedHash: "d41d8cd98f00b204e9800998ecf8427e", // Empty MD5
                realHashes: new Set()
            },
            sha1: {
                enabled: true,
                spoofedHash: "da39a3ee5e6b4b0d3255bfef95601890afd80709", // Empty SHA1
                realHashes: new Set()
            },
            sha256: {
                enabled: true,
                spoofedHash: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", // Empty SHA256
                realHashes: new Set()
            },
            sha512: {
                enabled: true,
                spoofedHash: "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e", // Empty SHA512
                realHashes: new Set()
            },
            crc32: {
                enabled: true,
                spoofedHash: "00000000",
                realHashes: new Set()
            }
        },
        
        // Digital signature verification
        signatures: {
            enabled: true,
            spoofValidSignature: true,
            trustedPublishers: [
                "Microsoft Corporation",
                "Adobe Systems Incorporated", 
                "Autodesk, Inc.",
                "Intel Corporation",
                "NVIDIA Corporation"
            ],
            spoofedCertificates: {}
        },
        
        // PE checksum manipulation
        peChecksum: {
            enabled: true,
            spoofValidChecksum: true,
            originalChecksums: new Map()
        },
        
        // File integrity monitoring
        fileIntegrity: {
            monitoredFiles: new Set(),
            originalHashes: new Map(),
            spoofingActive: true
        }
    },
    
    // Hook tracking
    hooksInstalled: {},
    interceptedCalls: 0,
    
    onAttach: function(pid) {
        console.log("[Code Integrity] Attaching to process: " + pid);
        this.processId = pid;
    },
    
    run: function() {
        console.log("[Code Integrity] Installing comprehensive code integrity bypass...");
        
        // Initialize bypass components
        this.hookHashFunctions();
        this.hookSignatureVerification();
        this.hookPeChecksumValidation();
        this.hookFileIntegrityChecks();
        this.hookCryptographicVerification();
        this.hookTrustedPlatformModule();
        this.hookCodeSigningAPIs();
        this.hookCertificateValidation();
        
        this.installSummary();
    },
    
    // === HASH FUNCTION HOOKS ===
    hookHashFunctions: function() {
        console.log("[Code Integrity] Installing hash function bypass hooks...");
        
        // Hook CryptHashData (Windows Crypto API)
        this.hookCryptHashData();
        
        // Hook MD5 functions
        this.hookMd5Functions();
        
        // Hook SHA functions
        this.hookShaFunctions();
        
        // Hook CRC32 functions
        this.hookCrc32Functions();
        
        // Hook generic hash functions
        this.hookGenericHashFunctions();
    },
    
    hookCryptHashData: function() {
        var cryptHashData = Module.findExportByName("advapi32.dll", "CryptHashData");
        if (cryptHashData) {
            Interceptor.attach(cryptHashData, {
                onEnter: function(args) {
                    this.hHash = args[0];
                    this.pbData = args[1];
                    this.dwDataLen = args[2].toInt32();
                    this.dwFlags = args[3].toInt32();
                    
                    console.log("[Code Integrity] CryptHashData called with " + this.dwDataLen + " bytes");
                    this.spoofHash = true;
                },
                
                onLeave: function(retval) {
                    if (this.spoofHash && retval.toInt32() !== 0) {
                        // Hash operation successful - we'll spoof the final result
                        console.log("[Code Integrity] CryptHashData result will be spoofed");
                    }
                }
            });
            
            this.hooksInstalled['CryptHashData'] = true;
        }
        
        // Hook CryptGetHashParam to spoof final hash values
        var cryptGetHashParam = Module.findExportByName("advapi32.dll", "CryptGetHashParam");
        if (cryptGetHashParam) {
            Interceptor.attach(cryptGetHashParam, {
                onEnter: function(args) {
                    this.hHash = args[0];
                    this.dwParam = args[1].toInt32();
                    this.pbData = args[2];
                    this.pdwDataLen = args[3];
                    this.dwFlags = args[4].toInt32();
                    
                    // HP_HASHVAL = 2 (getting the hash value)
                    if (this.dwParam === 2) {
                        this.isGettingHashValue = true;
                        console.log("[Code Integrity] CryptGetHashParam requesting hash value");
                    }
                },
                
                onLeave: function(retval) {
                    if (this.isGettingHashValue && retval.toInt32() !== 0 && 
                        this.pbData && !this.pbData.isNull()) {
                        
                        this.spoofHashValue();
                    }
                },
                
                spoofHashValue: function() {
                    try {
                        var config = this.parent.parent.config;
                        var hashLength = this.pdwDataLen.readU32();
                        
                        // Determine hash type by length and spoof accordingly
                        var spoofedHash = null;
                        
                        if (hashLength === 16) { // MD5
                            if (config.hashAlgorithms.md5.enabled) {
                                spoofedHash = this.hexToBytes(config.hashAlgorithms.md5.spoofedHash);
                            }
                        } else if (hashLength === 20) { // SHA1
                            if (config.hashAlgorithms.sha1.enabled) {
                                spoofedHash = this.hexToBytes(config.hashAlgorithms.sha1.spoofedHash);
                            }
                        } else if (hashLength === 32) { // SHA256
                            if (config.hashAlgorithms.sha256.enabled) {
                                spoofedHash = this.hexToBytes(config.hashAlgorithms.sha256.spoofedHash);
                            }
                        } else if (hashLength === 64) { // SHA512
                            if (config.hashAlgorithms.sha512.enabled) {
                                spoofedHash = this.hexToBytes(config.hashAlgorithms.sha512.spoofedHash);
                            }
                        }
                        
                        if (spoofedHash && spoofedHash.length === hashLength) {
                            this.pbData.writeByteArray(spoofedHash);
                            console.log("[Code Integrity] Spoofed hash value (" + hashLength + " bytes)");
                        }
                    } catch(e) {
                        console.log("[Code Integrity] Hash spoofing error: " + e);
                    }
                },
                
                hexToBytes: function(hexString) {
                    var bytes = [];
                    for (var i = 0; i < hexString.length; i += 2) {
                        bytes.push(parseInt(hexString.substr(i, 2), 16));
                    }
                    return bytes;
                }
            });
            
            this.hooksInstalled['CryptGetHashParam'] = true;
        }
    },
    
    hookMd5Functions: function() {
        console.log("[Code Integrity] Installing MD5 function hooks...");
        
        // Hook common MD5 function names
        var md5Functions = [
            "MD5Init", "MD5Update", "MD5Final",
            "md5_init", "md5_update", "md5_final", 
            "MD5_Init", "MD5_Update", "MD5_Final"
        ];
        
        md5Functions.forEach(funcName => {
            this.hookHashFunction(funcName, "md5", 16);
        });
        
        // Hook MD5 computation functions
        this.hookComputeHashFunction("MD5", "md5", 16);
    },
    
    hookShaFunctions: function() {
        console.log("[Code Integrity] Installing SHA function hooks...");
        
        // SHA1 functions
        var sha1Functions = [
            "SHA1Init", "SHA1Update", "SHA1Final",
            "sha1_init", "sha1_update", "sha1_final",
            "SHA_Init", "SHA_Update", "SHA_Final"
        ];
        
        sha1Functions.forEach(funcName => {
            this.hookHashFunction(funcName, "sha1", 20);
        });
        
        // SHA256 functions
        var sha256Functions = [
            "SHA256Init", "SHA256Update", "SHA256Final",
            "sha256_init", "sha256_update", "sha256_final",
            "SHA256_Init", "SHA256_Update", "SHA256_Final"
        ];
        
        sha256Functions.forEach(funcName => {
            this.hookHashFunction(funcName, "sha256", 32);
        });
        
        // SHA512 functions
        var sha512Functions = [
            "SHA512Init", "SHA512Update", "SHA512Final",
            "sha512_init", "sha512_update", "sha512_final",
            "SHA512_Init", "SHA512_Update", "SHA512_Final"
        ];
        
        sha512Functions.forEach(funcName => {
            this.hookHashFunction(funcName, "sha512", 64);
        });
        
        // Hook computation functions
        this.hookComputeHashFunction("SHA1", "sha1", 20);
        this.hookComputeHashFunction("SHA256", "sha256", 32);
        this.hookComputeHashFunction("SHA512", "sha512", 64);
    },
    
    hookCrc32Functions: function() {
        console.log("[Code Integrity] Installing CRC32 function hooks...");
        
        var crc32Functions = [
            "crc32", "CRC32", "crc32_compute", "CalcCRC32"
        ];
        
        crc32Functions.forEach(funcName => {
            this.hookHashFunction(funcName, "crc32", 4);
        });
    },
    
    hookHashFunction: function(functionName, hashType, hashSize) {
        var modules = Process.enumerateModules();
        
        for (var i = 0; i < modules.length; i++) {
            var module = modules[i];
            
            try {
                var hashFunc = Module.findExportByName(module.name, functionName);
                if (hashFunc) {
                    Interceptor.attach(hashFunc, {
                        onEnter: function(args) {
                            console.log("[Code Integrity] " + functionName + " called in " + module.name);
                            this.hashType = hashType;
                            this.hashSize = hashSize;
                        },
                        
                        onLeave: function(retval) {
                            if (functionName.includes("Final") && this.hashType) {
                                // This is a final hash function - spoof the result
                                this.spoofFinalHash();
                            }
                        },
                        
                        spoofFinalHash: function() {
                            try {
                                var config = this.parent.parent.parent.config;
                                var hashConfig = config.hashAlgorithms[this.hashType];
                                
                                if (hashConfig && hashConfig.enabled) {
                                    // The hash result is typically in the first argument for Final functions
                                    var hashBuffer = this.context.rcx; // First argument
                                    
                                    if (hashBuffer && !hashBuffer.isNull()) {
                                        var spoofedBytes = this.hexToBytes(hashConfig.spoofedHash);
                                        if (spoofedBytes.length >= this.hashSize) {
                                            hashBuffer.writeByteArray(spoofedBytes.slice(0, this.hashSize));
                                            console.log("[Code Integrity] Spoofed " + this.hashType.toUpperCase() + 
                                                      " hash in " + functionName);
                                        }
                                    }
                                }
                            } catch(e) {
                                console.log("[Code Integrity] Hash spoofing error in " + functionName + ": " + e);
                            }
                        },
                        
                        hexToBytes: function(hexString) {
                            var bytes = [];
                            for (var j = 0; j < hexString.length; j += 2) {
                                bytes.push(parseInt(hexString.substr(j, 2), 16));
                            }
                            return bytes;
                        }
                    });
                    
                    this.hooksInstalled[functionName + '_' + module.name] = true;
                    console.log("[Code Integrity] Hooked " + functionName + " in " + module.name);
                }
            } catch(e) {
                // Module doesn't have this function - continue
            }
        }
    },
    
    hookComputeHashFunction: function(hashName, hashType, hashSize) {
        var computeFunctions = [
            "Compute" + hashName,
            "Calculate" + hashName,
            "Hash" + hashName,
            hashName.toLowerCase() + "_compute"
        ];
        
        computeFunctions.forEach(funcName => {
            var modules = Process.enumerateModules();
            
            for (var i = 0; i < modules.length; i++) {
                var module = modules[i];
                
                try {
                    var func = Module.findExportByName(module.name, funcName);
                    if (func) {
                        Interceptor.attach(func, {
                            onLeave: function(retval) {
                                // For compute functions, the result is often returned or in an output parameter
                                this.spoofComputeResult();
                            },
                            
                            spoofComputeResult: function() {
                                try {
                                    var config = this.parent.parent.parent.config;
                                    var hashConfig = config.hashAlgorithms[hashType];
                                    
                                    if (hashConfig && hashConfig.enabled) {
                                        // Try to find hash output buffer (usually second or third parameter)
                                        var outputBuffer = this.context.rdx || this.context.r8;
                                        
                                        if (outputBuffer && !outputBuffer.isNull()) {
                                            var spoofedBytes = this.hexToBytes(hashConfig.spoofedHash);
                                            if (spoofedBytes.length >= hashSize) {
                                                outputBuffer.writeByteArray(spoofedBytes.slice(0, hashSize));
                                                console.log("[Code Integrity] Spoofed " + hashType.toUpperCase() + 
                                                          " compute result in " + funcName);
                                            }
                                        }
                                    }
                                } catch(e) {
                                    console.log("[Code Integrity] Compute hash spoofing error: " + e);
                                }
                            },
                            
                            hexToBytes: function(hexString) {
                                var bytes = [];
                                for (var j = 0; j < hexString.length; j += 2) {
                                    bytes.push(parseInt(hexString.substr(j, 2), 16));
                                }
                                return bytes;
                            }
                        });
                        
                        this.hooksInstalled[funcName + '_' + module.name] = true;
                    }
                } catch(e) {
                    // Continue with next module
                }
            }
        });
    },
    
    hookGenericHashFunctions: function() {
        console.log("[Code Integrity] Installing generic hash function hooks...");
        
        // Hook memory comparison functions that might be used for hash comparison
        var memcmp = Module.findExportByName("msvcrt.dll", "memcmp");
        if (memcmp) {
            Interceptor.attach(memcmp, {
                onEnter: function(args) {
                    this.ptr1 = args[0];
                    this.ptr2 = args[1];
                    this.size = args[2].toInt32();
                    
                    // Check if this looks like a hash comparison (common hash sizes)
                    if (this.size === 16 || this.size === 20 || this.size === 32 || this.size === 64) {
                        this.isHashComparison = true;
                        console.log("[Code Integrity] Potential hash comparison detected (" + this.size + " bytes)");
                    }
                },
                
                onLeave: function(retval) {
                    if (this.isHashComparison && retval.toInt32() !== 0) {
                        // Hash comparison failed - make it succeed
                        retval.replace(0);
                        console.log("[Code Integrity] Hash comparison forced to succeed");
                    }
                }
            });
            
            this.hooksInstalled['memcmp'] = true;
        }
        
        // Hook strcmp for string-based hash comparisons
        var strcmp = Module.findExportByName("msvcrt.dll", "strcmp");
        if (strcmp) {
            Interceptor.attach(strcmp, {
                onEnter: function(args) {
                    try {
                        var str1 = args[0].readAnsiString();
                        var str2 = args[1].readAnsiString();
                        
                        // Check if these look like hex-encoded hashes
                        if (str1 && str2 && 
                            (str1.length === 32 || str1.length === 40 || str1.length === 64 || str1.length === 128) &&
                            /^[0-9a-fA-F]+$/.test(str1) && /^[0-9a-fA-F]+$/.test(str2)) {
                            
                            this.isHashStringComparison = true;
                            console.log("[Code Integrity] Hash string comparison detected: " + str1.length + " chars");
                        }
                    } catch(e) {
                        // String read failed - not a string comparison
                    }
                },
                
                onLeave: function(retval) {
                    if (this.isHashStringComparison && retval.toInt32() !== 0) {
                        // Hash string comparison failed - make it succeed
                        retval.replace(0);
                        console.log("[Code Integrity] Hash string comparison forced to succeed");
                    }
                }
            });
            
            this.hooksInstalled['strcmp'] = true;
        }
    },
    
    // === SIGNATURE VERIFICATION HOOKS ===
    hookSignatureVerification: function() {
        console.log("[Code Integrity] Installing signature verification bypass hooks...");
        
        // Hook Windows signature verification APIs
        this.hookWinVerifyTrust();
        this.hookCryptVerifySignature();
        this.hookCodeSigningAPIs();
        this.hookAuthenticodeVerification();
    },
    
    hookWinVerifyTrust: function() {
        var winVerifyTrust = Module.findExportByName("wintrust.dll", "WinVerifyTrust");
        if (winVerifyTrust) {
            Interceptor.attach(winVerifyTrust, {
                onEnter: function(args) {
                    this.hwnd = args[0];
                    this.pgActionID = args[1];
                    this.pWVTData = args[2];
                    
                    console.log("[Code Integrity] WinVerifyTrust called - will spoof as valid");
                    this.spoofSignature = true;
                },
                
                onLeave: function(retval) {
                    if (this.spoofSignature) {
                        var config = this.parent.parent.config;
                        if (config.signatures.enabled && config.signatures.spoofValidSignature) {
                            retval.replace(0); // ERROR_SUCCESS
                            console.log("[Code Integrity] WinVerifyTrust result spoofed to valid signature");
                        }
                    }
                }
            });
            
            this.hooksInstalled['WinVerifyTrust'] = true;
        }
    },
    
    hookCryptVerifySignature: function() {
        var cryptVerifySignature = Module.findExportByName("crypt32.dll", "CryptVerifySignature");
        if (cryptVerifySignature) {
            Interceptor.attach(cryptVerifySignature, {
                onEnter: function(args) {
                    console.log("[Code Integrity] CryptVerifySignature called");
                    this.spoofResult = true;
                },
                
                onLeave: function(retval) {
                    if (this.spoofResult) {
                        var config = this.parent.parent.config;
                        if (config.signatures.enabled) {
                            retval.replace(1); // TRUE
                            console.log("[Code Integrity] CryptVerifySignature spoofed to valid");
                        }
                    }
                }
            });
            
            this.hooksInstalled['CryptVerifySignature'] = true;
        }
        
        // Hook CryptVerifyDetachedMessageSignature
        var cryptVerifyDetached = Module.findExportByName("crypt32.dll", "CryptVerifyDetachedMessageSignature");
        if (cryptVerifyDetached) {
            Interceptor.attach(cryptVerifyDetached, {
                onLeave: function(retval) {
                    var config = this.parent.parent.config;
                    if (config.signatures.enabled) {
                        retval.replace(1); // TRUE
                        console.log("[Code Integrity] CryptVerifyDetachedMessageSignature spoofed to valid");
                    }
                }
            });
            
            this.hooksInstalled['CryptVerifyDetachedMessageSignature'] = true;
        }
    },
    
    hookAuthenticodeVerification: function() {
        console.log("[Code Integrity] Installing Authenticode verification hooks...");
        
        // Hook ImageGetDigestStream
        var imageGetDigestStream = Module.findExportByName("imagehlp.dll", "ImageGetDigestStream");
        if (imageGetDigestStream) {
            Interceptor.attach(imageGetDigestStream, {
                onLeave: function(retval) {
                    if (retval.toInt32() !== 0) {
                        console.log("[Code Integrity] ImageGetDigestStream - digest stream accessed");
                    }
                }
            });
            
            this.hooksInstalled['ImageGetDigestStream'] = true;
        }
        
        // Hook ImageGetCertificateData
        var imageGetCertData = Module.findExportByName("imagehlp.dll", "ImageGetCertificateData");
        if (imageGetCertData) {
            Interceptor.attach(imageGetCertData, {
                onLeave: function(retval) {
                    if (retval.toInt32() !== 0) {
                        console.log("[Code Integrity] ImageGetCertificateData - certificate data retrieved");
                        // Could modify certificate data here if needed
                    }
                }
            });
            
            this.hooksInstalled['ImageGetCertificateData'] = true;
        }
    },
    
    // === PE CHECKSUM VALIDATION HOOKS ===
    hookPeChecksumValidation: function() {
        console.log("[Code Integrity] Installing PE checksum validation hooks...");
        
        // Hook CheckSumMappedFile
        var checkSumMapped = Module.findExportByName("imagehlp.dll", "CheckSumMappedFile");
        if (checkSumMapped) {
            Interceptor.attach(checkSumMapped, {
                onEnter: function(args) {
                    this.baseAddress = args[0];
                    this.fileLength = args[1].toInt32();
                    this.headerSum = args[2];
                    this.checkSum = args[3];
                    
                    console.log("[Code Integrity] CheckSumMappedFile called for " + this.fileLength + " bytes");
                },
                
                onLeave: function(retval) {
                    if (retval.toInt32() === 0 && this.checkSum && !this.checkSum.isNull()) { // CHECKSUM_SUCCESS
                        var config = this.parent.parent.config;
                        if (config.peChecksum.enabled && config.peChecksum.spoofValidChecksum) {
                            // Make calculated checksum match header checksum
                            var headerSumValue = this.headerSum.readU32();
                            this.checkSum.writeU32(headerSumValue);
                            console.log("[Code Integrity] PE checksum spoofed to match header: 0x" + 
                                      headerSumValue.toString(16));
                        }
                    }
                }
            });
            
            this.hooksInstalled['CheckSumMappedFile'] = true;
        }
        
        // Hook MapFileAndCheckSum
        var mapFileAndCheckSum = Module.findExportByName("imagehlp.dll", "MapFileAndCheckSumW");
        if (mapFileAndCheckSum) {
            Interceptor.attach(mapFileAndCheckSum, {
                onEnter: function(args) {
                    if (args[0] && !args[0].isNull()) {
                        this.fileName = args[0].readUtf16String();
                        this.headerSum = args[1];
                        this.checkSum = args[2];
                        
                        console.log("[Code Integrity] MapFileAndCheckSumW called for: " + this.fileName);
                    }
                },
                
                onLeave: function(retval) {
                    if (retval.toInt32() === 0 && this.checkSum && !this.checkSum.isNull()) { // CHECKSUM_SUCCESS
                        var config = this.parent.parent.config;
                        if (config.peChecksum.enabled && config.peChecksum.spoofValidChecksum) {
                            // Make calculated checksum match header checksum
                            var headerSumValue = this.headerSum.readU32();
                            this.checkSum.writeU32(headerSumValue);
                            console.log("[Code Integrity] File checksum spoofed for: " + this.fileName);
                        }
                    }
                }
            });
            
            this.hooksInstalled['MapFileAndCheckSumW'] = true;
        }
    },
    
    // === FILE INTEGRITY CHECK HOOKS ===
    hookFileIntegrityChecks: function() {
        console.log("[Code Integrity] Installing file integrity check hooks...");
        
        // Hook GetFileAttributes to potentially spoof file properties
        var getFileAttribs = Module.findExportByName("kernel32.dll", "GetFileAttributesW");
        if (getFileAttribs) {
            Interceptor.attach(getFileAttribs, {
                onEnter: function(args) {
                    if (args[0] && !args[0].isNull()) {
                        this.fileName = args[0].readUtf16String();
                        
                        // Track access to potentially protected files
                        if (this.fileName.includes(".exe") || this.fileName.includes(".dll")) {
                            console.log("[Code Integrity] File attributes check: " + this.fileName);
                        }
                    }
                }
            });
            
            this.hooksInstalled['GetFileAttributesW'] = true;
        }
        
        // Hook GetFileTime to spoof file timestamps
        var getFileTime = Module.findExportByName("kernel32.dll", "GetFileTime");
        if (getFileTime) {
            Interceptor.attach(getFileTime, {
                onEnter: function(args) {
                    this.hFile = args[0];
                    this.lpCreationTime = args[1];
                    this.lpLastAccessTime = args[2];
                    this.lpLastWriteTime = args[3];
                    
                    console.log("[Code Integrity] GetFileTime called");
                },
                
                onLeave: function(retval) {
                    if (retval.toInt32() !== 0) {
                        // Could spoof file times here if needed
                        console.log("[Code Integrity] File time retrieved - could be spoofed");
                    }
                }
            });
            
            this.hooksInstalled['GetFileTime'] = true;
        }
        
        // Hook CreateFile to monitor file access patterns
        var createFile = Module.findExportByName("kernel32.dll", "CreateFileW");
        if (createFile) {
            Interceptor.attach(createFile, {
                onEnter: function(args) {
                    if (args[0] && !args[0].isNull()) {
                        var fileName = args[0].readUtf16String();
                        var config = this.parent.parent.config;
                        
                        // Track files that might be integrity checked
                        if (fileName.includes(".exe") || fileName.includes(".dll") || 
                            fileName.includes(".sys") || fileName.includes(".cat")) {
                            
                            config.fileIntegrity.monitoredFiles.add(fileName);
                            console.log("[Code Integrity] Monitoring file access: " + fileName);
                        }
                    }
                }
            });
            
            this.hooksInstalled['CreateFileW_Integrity'] = true;
        }
    },
    
    // === CRYPTOGRAPHIC VERIFICATION HOOKS ===
    hookCryptographicVerification: function() {
        console.log("[Code Integrity] Installing cryptographic verification hooks...");
        
        // Hook CryptImportKey
        var cryptImportKey = Module.findExportByName("advapi32.dll", "CryptImportKey");
        if (cryptImportKey) {
            Interceptor.attach(cryptImportKey, {
                onEnter: function(args) {
                    console.log("[Code Integrity] CryptImportKey called - cryptographic key import");
                },
                
                onLeave: function(retval) {
                    if (retval.toInt32() !== 0) {
                        console.log("[Code Integrity] Cryptographic key imported successfully");
                    }
                }
            });
            
            this.hooksInstalled['CryptImportKey'] = true;
        }
        
        // Hook CryptVerifySignature for low-level signature verification
        var cryptVerifySig = Module.findExportByName("advapi32.dll", "CryptVerifySignature");
        if (cryptVerifySig) {
            Interceptor.attach(cryptVerifySig, {
                onLeave: function(retval) {
                    var config = this.parent.parent.config;
                    if (config.signatures.enabled) {
                        retval.replace(1); // TRUE - signature valid
                        console.log("[Code Integrity] CryptVerifySignature spoofed to valid");
                    }
                }
            });
            
            this.hooksInstalled['CryptVerifySignature_LowLevel'] = true;
        }
        
        // Hook BCrypt functions (newer crypto API)
        this.hookBCryptFunctions();
    },
    
    hookBCryptFunctions: function() {
        console.log("[Code Integrity] Installing BCrypt function hooks...");
        
        // Hook BCryptVerifySignature
        var bcryptVerifySignature = Module.findExportByName("bcrypt.dll", "BCryptVerifySignature");
        if (bcryptVerifySignature) {
            Interceptor.attach(bcryptVerifySignature, {
                onLeave: function(retval) {
                    var config = this.parent.parent.config;
                    if (config.signatures.enabled) {
                        retval.replace(0); // STATUS_SUCCESS
                        console.log("[Code Integrity] BCryptVerifySignature spoofed to valid");
                    }
                }
            });
            
            this.hooksInstalled['BCryptVerifySignature'] = true;
        }
        
        // Hook BCryptHash
        var bcryptHash = Module.findExportByName("bcrypt.dll", "BCryptHash");
        if (bcryptHash) {
            Interceptor.attach(bcryptHash, {
                onEnter: function(args) {
                    this.hAlgorithm = args[0];
                    this.pbSecret = args[1];
                    this.cbSecret = args[2].toInt32();
                    this.pbInput = args[3];
                    this.cbInput = args[4].toInt32();
                    this.pbOutput = args[5];
                    this.cbOutput = args[6].toInt32();
                    
                    console.log("[Code Integrity] BCryptHash called with " + this.cbInput + " input bytes");
                    this.spoofBCryptHash = true;
                },
                
                onLeave: function(retval) {
                    if (this.spoofBCryptHash && retval.toInt32() === 0 && // STATUS_SUCCESS
                        this.pbOutput && !this.pbOutput.isNull()) {
                        
                        this.spoofBCryptResult();
                    }
                },
                
                spoofBCryptResult: function() {
                    try {
                        var config = this.parent.parent.parent.config;
                        
                        // Determine hash type by output size and spoof accordingly
                        if (this.cbOutput === 16 && config.hashAlgorithms.md5.enabled) {
                            var spoofedHash = this.hexToBytes(config.hashAlgorithms.md5.spoofedHash);
                            this.pbOutput.writeByteArray(spoofedHash);
                            console.log("[Code Integrity] BCryptHash MD5 result spoofed");
                        } else if (this.cbOutput === 20 && config.hashAlgorithms.sha1.enabled) {
                            var spoofedHash = this.hexToBytes(config.hashAlgorithms.sha1.spoofedHash);
                            this.pbOutput.writeByteArray(spoofedHash);
                            console.log("[Code Integrity] BCryptHash SHA1 result spoofed");
                        } else if (this.cbOutput === 32 && config.hashAlgorithms.sha256.enabled) {
                            var spoofedHash = this.hexToBytes(config.hashAlgorithms.sha256.spoofedHash);
                            this.pbOutput.writeByteArray(spoofedHash);
                            console.log("[Code Integrity] BCryptHash SHA256 result spoofed");
                        } else if (this.cbOutput === 64 && config.hashAlgorithms.sha512.enabled) {
                            var spoofedHash = this.hexToBytes(config.hashAlgorithms.sha512.spoofedHash);
                            this.pbOutput.writeByteArray(spoofedHash);
                            console.log("[Code Integrity] BCryptHash SHA512 result spoofed");
                        }
                    } catch(e) {
                        console.log("[Code Integrity] BCrypt hash spoofing error: " + e);
                    }
                },
                
                hexToBytes: function(hexString) {
                    var bytes = [];
                    for (var i = 0; i < hexString.length; i += 2) {
                        bytes.push(parseInt(hexString.substr(i, 2), 16));
                    }
                    return bytes;
                }
            });
            
            this.hooksInstalled['BCryptHash'] = true;
        }
    },
    
    // === TRUSTED PLATFORM MODULE HOOKS ===
    hookTrustedPlatformModule: function() {
        console.log("[Code Integrity] Installing TPM bypass hooks...");
        
        // Hook TPM-related functions if they exist
        var tpmFunctions = [
            "Tbsi_Context_Create",
            "Tbsi_Create_Windows_Key", 
            "Tbsi_Get_TCG_Log",
            "Tbsip_Context_Create",
            "Tbsip_Submit_Command"
        ];
        
        tpmFunctions.forEach(funcName => {
            var tpmFunc = Module.findExportByName("tbs.dll", funcName);
            if (tpmFunc) {
                Interceptor.attach(tpmFunc, {
                    onEnter: function(args) {
                        console.log("[Code Integrity] TPM function called: " + funcName);
                        this.bypassTPM = true;
                    },
                    
                    onLeave: function(retval) {
                        if (this.bypassTPM) {
                            // Make TPM operations appear successful
                            retval.replace(0); // TBS_SUCCESS
                            console.log("[Code Integrity] TPM function " + funcName + " bypassed");
                        }
                    }
                });
                
                this.hooksInstalled[funcName] = true;
            }
        });
        
        // Hook NCrypt functions that might use TPM
        var ncryptFunctions = [
            "NCryptCreatePersistedKey",
            "NCryptDeleteKey",
            "NCryptFinalizeKey"
        ];
        
        ncryptFunctions.forEach(funcName => {
            var ncryptFunc = Module.findExportByName("ncrypt.dll", funcName);
            if (ncryptFunc) {
                Interceptor.attach(ncryptFunc, {
                    onLeave: function(retval) {
                        // Make NCrypt operations succeed
                        retval.replace(0); // ERROR_SUCCESS
                        console.log("[Code Integrity] NCrypt function " + funcName + " spoofed");
                    }
                });
                
                this.hooksInstalled[funcName] = true;
            }
        });
    },
    
    // === CODE SIGNING API HOOKS ===
    hookCodeSigningAPIs: function() {
        console.log("[Code Integrity] Installing code signing API hooks...");
        
        // Hook SignerSign
        var signerSign = Module.findExportByName("mssign32.dll", "SignerSign");
        if (signerSign) {
            Interceptor.attach(signerSign, {
                onLeave: function(retval) {
                    retval.replace(0); // S_OK
                    console.log("[Code Integrity] SignerSign spoofed to success");
                }
            });
            
            this.hooksInstalled['SignerSign'] = true;
        }
        
        // Hook SignerSignEx
        var signerSignEx = Module.findExportByName("mssign32.dll", "SignerSignEx");
        if (signerSignEx) {
            Interceptor.attach(signerSignEx, {
                onLeave: function(retval) {
                    retval.replace(0); // S_OK
                    console.log("[Code Integrity] SignerSignEx spoofed to success");
                }
            });
            
            this.hooksInstalled['SignerSignEx'] = true;
        }
        
        // Hook SignerTimeStamp
        var signerTimeStamp = Module.findExportByName("mssign32.dll", "SignerTimeStamp");
        if (signerTimeStamp) {
            Interceptor.attach(signerTimeStamp, {
                onLeave: function(retval) {
                    retval.replace(0); // S_OK
                    console.log("[Code Integrity] SignerTimeStamp spoofed to success");
                }
            });
            
            this.hooksInstalled['SignerTimeStamp'] = true;
        }
    },
    
    // === CERTIFICATE VALIDATION HOOKS ===
    hookCertificateValidation: function() {
        console.log("[Code Integrity] Installing certificate validation hooks...");
        
        // Hook CertVerifyCertificateChainPolicy
        var certVerifyChain = Module.findExportByName("crypt32.dll", "CertVerifyCertificateChainPolicy");
        if (certVerifyChain) {
            Interceptor.attach(certVerifyChain, {
                onEnter: function(args) {
                    this.pszPolicyOID = args[0];
                    this.pChainContext = args[1];
                    this.pPolicyPara = args[2];
                    this.pPolicyStatus = args[3];
                    
                    console.log("[Code Integrity] CertVerifyCertificateChainPolicy called");
                },
                
                onLeave: function(retval) {
                    if (retval.toInt32() !== 0 && this.pPolicyStatus && !this.pPolicyStatus.isNull()) {
                        // Set policy status to success
                        this.pPolicyStatus.writeU32(0); // ERROR_SUCCESS
                        this.pPolicyStatus.add(4).writeU32(0); // No chain errors
                        console.log("[Code Integrity] Certificate chain policy spoofed to valid");
                    }
                }
            });
            
            this.hooksInstalled['CertVerifyCertificateChainPolicy'] = true;
        }
        
        // Hook CertGetCertificateChain
        var certGetChain = Module.findExportByName("crypt32.dll", "CertGetCertificateChain");
        if (certGetChain) {
            Interceptor.attach(certGetChain, {
                onLeave: function(retval) {
                    if (retval.toInt32() !== 0) {
                        console.log("[Code Integrity] CertGetCertificateChain - certificate chain retrieved");
                    }
                }
            });
            
            this.hooksInstalled['CertGetCertificateChain'] = true;
        }
        
        // Hook CertFreeCertificateChain
        var certFreeChain = Module.findExportByName("crypt32.dll", "CertFreeCertificateChain");
        if (certFreeChain) {
            Interceptor.attach(certFreeChain, {
                onEnter: function(args) {
                    console.log("[Code Integrity] CertFreeCertificateChain - cleaning up certificate chain");
                }
            });
            
            this.hooksInstalled['CertFreeCertificateChain'] = true;
        }
    },
    
    // === INSTALLATION SUMMARY ===
    installSummary: function() {
        setTimeout(() => {
            console.log("\n[Code Integrity] =====================================");
            console.log("[Code Integrity] Code Integrity Bypass Summary:");
            console.log("[Code Integrity] =====================================");
            
            var categories = {
                "Hash Functions": 0,
                "Signature Verification": 0,
                "PE Checksum": 0,
                "File Integrity": 0,
                "Cryptographic APIs": 0,
                "Certificate Validation": 0,
                "TPM/Hardware Security": 0
            };
            
            for (var hook in this.hooksInstalled) {
                if (hook.includes("Hash") || hook.includes("MD5") || hook.includes("SHA") || 
                    hook.includes("CRC") || hook.includes("cmp")) {
                    categories["Hash Functions"]++;
                } else if (hook.includes("Signature") || hook.includes("WinVerifyTrust") || 
                          hook.includes("Authenticode")) {
                    categories["Signature Verification"]++;
                } else if (hook.includes("CheckSum") || hook.includes("Checksum")) {
                    categories["PE Checksum"]++;
                } else if (hook.includes("File") || hook.includes("Integrity")) {
                    categories["File Integrity"]++;
                } else if (hook.includes("Crypt") || hook.includes("BCrypt")) {
                    categories["Cryptographic APIs"]++;
                } else if (hook.includes("Cert") || hook.includes("Certificate")) {
                    categories["Certificate Validation"]++;
                } else if (hook.includes("TPM") || hook.includes("Tbs") || hook.includes("NCrypt")) {
                    categories["TPM/Hardware Security"]++;
                }
            }
            
            for (var category in categories) {
                if (categories[category] > 0) {
                    console.log("[Code Integrity]   ✓ " + category + ": " + categories[category] + " hooks");
                }
            }
            
            console.log("[Code Integrity] =====================================");
            console.log("[Code Integrity] Active Hash Spoofing:");
            
            var config = this.config;
            for (var hashType in config.hashAlgorithms) {
                if (config.hashAlgorithms[hashType].enabled) {
                    console.log("[Code Integrity]   ✓ " + hashType.toUpperCase() + 
                              " spoofed to: " + config.hashAlgorithms[hashType].spoofedHash.substring(0, 16) + "...");
                }
            }
            
            console.log("[Code Integrity] =====================================");
            console.log("[Code Integrity] Total hooks installed: " + Object.keys(this.hooksInstalled).length);
            console.log("[Code Integrity] =====================================");
            console.log("[Code Integrity] Advanced code integrity bypass is now ACTIVE!");
        }, 100);
    }
}
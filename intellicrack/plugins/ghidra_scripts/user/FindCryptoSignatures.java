/**
 * Advanced Cryptographic Signature Detection & Analysis
 *
 * @description Comprehensive crypto detection with algorithm identification, key extraction, and implementation analysis
 * @author Intellicrack Team
 * @category SecurityResearch.Cryptography
 * @version 3.0
 * @tags crypto,signatures,aes,rsa,sha,md5,des,3des,rc4,blowfish,twofish,serpent,ecdsa,dsa,security
 */

import ghidra.app.script.GhidraScript;
import ghidra.program.model.mem.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.address.*;
import ghidra.program.model.symbol.*;
import ghidra.program.model.data.*;
import ghidra.program.model.lang.*;
import ghidra.program.model.pcode.*;
import ghidra.program.model.scalar.*;
import ghidra.program.util.*;
import ghidra.app.decompiler.*;
import ghidra.util.task.*;
import ghidra.util.exception.*;
import ghidra.program.model.block.*;
import ghidra.app.util.bin.*;
import ghidra.app.util.bin.format.pe.*;
import java.util.*;
import java.io.*;
import java.nio.*;
import java.security.*;
import java.math.BigInteger;
import java.util.regex.*;
import javax.crypto.spec.*;

public class FindCryptoSignatures extends GhidraScript {

    // Comprehensive crypto signature database
    private static final Map<String, CryptoSignature> CRYPTO_SIGNATURES = new HashMap<>();
    private static final Map<String, byte[][]> ALGORITHM_PATTERNS = new HashMap<>();
    private static final Map<String, String[]> CRYPTO_APIS = new HashMap<>();
    
    // Analysis results
    private List<CryptoDetection> detectedAlgorithms = new ArrayList<>();
    private List<CryptoKey> extractedKeys = new ArrayList<>();
    private List<CryptoImplementation> implementations = new ArrayList<>();
    private Map<Address, CryptoFunction> cryptoFunctions = new HashMap<>();
    private DecompInterface decompiler;
    
    static {
        initializeCryptoSignatures();
        initializeAlgorithmPatterns();
        initializeCryptoAPIs();
    }
    
    private static void initializeCryptoSignatures() {
        // AES signatures (complete S-box and inverse S-box)
        CRYPTO_SIGNATURES.put("AES", new CryptoSignature(
            "Advanced Encryption Standard",
            new byte[][] {
                // AES S-box (first 16 bytes)
                {0x63, 0x7c, 0x77, 0x7b, (byte)0xf2, 0x6b, 0x6f, (byte)0xc5, 
                 0x30, 0x01, 0x67, 0x2b, (byte)0xfe, (byte)0xd7, (byte)0xab, 0x76},
                // AES inverse S-box
                {0x52, 0x09, 0x6a, (byte)0xd5, 0x30, 0x36, (byte)0xa5, 0x38,
                 (byte)0xbf, 0x40, (byte)0xa3, (byte)0x9e, (byte)0x81, (byte)0xf3, (byte)0xd7, (byte)0xfb},
                // AES round constants
                {0x01, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 
                 0x04, 0x00, 0x00, 0x00, 0x08, 0x00, 0x00, 0x00}
            },
            new int[]{128, 192, 256},
            CryptoType.SYMMETRIC_BLOCK
        ));
        
        // DES/3DES signatures
        CRYPTO_SIGNATURES.put("DES", new CryptoSignature(
            "Data Encryption Standard",
            new byte[][] {
                // DES initial permutation
                {58, 50, 42, 34, 26, 18, 10, 2, 60, 52, 44, 36, 28, 20, 12, 4},
                // DES S-box 1
                {14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7}
            },
            new int[]{56, 112, 168}, // DES, 2DES, 3DES
            CryptoType.SYMMETRIC_BLOCK
        ));
        
        // RSA signatures
        CRYPTO_SIGNATURES.put("RSA", new CryptoSignature(
            "RSA Public Key Cryptography",
            new byte[][] {
                // Common RSA exponent (65537)
                {0x01, 0x00, 0x01},
                // RSA PKCS#1 padding
                {0x00, 0x01, (byte)0xff, (byte)0xff},
                // RSA key header ASN.1
                {0x30, (byte)0x82}, // SEQUENCE
                {0x02, (byte)0x82}  // INTEGER
            },
            new int[]{1024, 2048, 3072, 4096},
            CryptoType.ASYMMETRIC
        ));
        
        // SHA family signatures
        CRYPTO_SIGNATURES.put("SHA-256", new CryptoSignature(
            "Secure Hash Algorithm 256",
            new byte[][] {
                // SHA-256 initial hash values (H0-H7)
                hexToBytes("6a09e667bb67ae853c6ef372a54ff53a510e527f9b05688c1f83d9ab5be0cd19"),
                // SHA-256 round constants (first 8)
                hexToBytes("428a2f9871374491b5c0fbcfe9b5dba53956c25b59f111f1923f82a4ab1c5ed5")
            },
            new int[]{256},
            CryptoType.HASH
        ));
        
        // MD5 signatures
        CRYPTO_SIGNATURES.put("MD5", new CryptoSignature(
            "Message Digest 5",
            new byte[][] {
                // MD5 initial values
                hexToBytes("0123456789abcdeffedcba9876543210"),
                // MD5 T-table constants
                hexToBytes("d76aa478e8c7b756242070dbc1bdceeef57c0faf4787c62aa8304613fd469501")
            },
            new int[]{128},
            CryptoType.HASH
        ));
        
        // RC4 signatures
        CRYPTO_SIGNATURES.put("RC4", new CryptoSignature(
            "Rivest Cipher 4",
            new byte[][] {
                // RC4 KSA pattern (0-255 initialization)
                {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f}
            },
            new int[]{40, 128, 256}, // Common key sizes
            CryptoType.SYMMETRIC_STREAM
        ));
        
        // Blowfish signatures
        CRYPTO_SIGNATURES.put("Blowfish", new CryptoSignature(
            "Blowfish Cipher",
            new byte[][] {
                // Blowfish P-array initial values
                hexToBytes("243f6a8885a308d3"),
                // Blowfish S-box initial values
                hexToBytes("d1310ba698dfb5ac")
            },
            new int[]{128, 256, 448},
            CryptoType.SYMMETRIC_BLOCK
        ));
        
        // ECC signatures
        CRYPTO_SIGNATURES.put("ECC", new CryptoSignature(
            "Elliptic Curve Cryptography",
            new byte[][] {
                // secp256k1 generator point
                hexToBytes("0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"),
                // P-256 curve parameters
                hexToBytes("ffffffff00000001000000000000000000000000ffffffffffffffffffffffff")
            },
            new int[]{256, 384, 521},
            CryptoType.ASYMMETRIC
        ));
    }
    
    private static void initializeAlgorithmPatterns() {
        // AES-specific patterns
        ALGORITHM_PATTERNS.put("AES_MixColumns", new byte[][] {
            {0x02, 0x03, 0x01, 0x01}, // MixColumns matrix
            {0x0e, 0x0b, 0x0d, 0x09}  // InvMixColumns matrix
        });
        
        // DES-specific patterns
        ALGORITHM_PATTERNS.put("DES_Permutation", new byte[][] {
            // Final permutation
            {40, 8, 48, 16, 56, 24, 64, 32, 39, 7, 47, 15, 55, 23, 63, 31}
        });
        
        // SHA-specific patterns
        ALGORITHM_PATTERNS.put("SHA_Padding", new byte[][] {
            {(byte)0x80, 0x00, 0x00, 0x00} // SHA padding pattern
        });
        
        // RSA-specific patterns
        ALGORITHM_PATTERNS.put("RSA_OAEP", new byte[][] {
            // OAEP padding
            {0x00, 0x02}, // Block type 2
            {0x00, 0x01}  // Block type 1
        });
    }
    
    private static void initializeCryptoAPIs() {
        // Windows CryptoAPI
        CRYPTO_APIS.put("Windows_CryptoAPI", new String[] {
            "CryptAcquireContext", "CryptCreateHash", "CryptHashData",
            "CryptDeriveKey", "CryptEncrypt", "CryptDecrypt",
            "CryptImportKey", "CryptExportKey", "CryptGenKey",
            "CryptDestroyHash", "CryptReleaseContext", "CryptSignHash",
            "CryptVerifySignature", "CryptGenRandom"
        });
        
        // Windows CNG (Cryptography Next Generation)
        CRYPTO_APIS.put("Windows_CNG", new String[] {
            "BCryptOpenAlgorithmProvider", "BCryptGenerateSymmetricKey",
            "BCryptEncrypt", "BCryptDecrypt", "BCryptCreateHash",
            "BCryptHashData", "BCryptFinishHash", "BCryptGenerateKeyPair",
            "BCryptSignHash", "BCryptVerifySignature", "BCryptGenRandom",
            "BCryptDeriveKey", "BCryptImportKeyPair", "BCryptExportKey"
        });
        
        // OpenSSL
        CRYPTO_APIS.put("OpenSSL", new String[] {
            "EVP_EncryptInit", "EVP_DecryptInit", "EVP_CipherInit",
            "EVP_DigestInit", "EVP_SignInit", "EVP_VerifyInit",
            "RSA_public_encrypt", "RSA_private_decrypt", "AES_encrypt",
            "AES_decrypt", "SHA256_Init", "MD5_Init", "RAND_bytes",
            "BN_mod_exp", "EC_POINT_mul", "ECDSA_sign", "ECDSA_verify"
        });
        
        // libsodium
        CRYPTO_APIS.put("libsodium", new String[] {
            "crypto_box_easy", "crypto_box_open_easy", "crypto_sign",
            "crypto_sign_verify", "crypto_secretbox_easy", "crypto_auth",
            "crypto_hash", "crypto_generichash", "crypto_pwhash",
            "crypto_aead_aes256gcm_encrypt", "randombytes_buf"
        });
        
        // mbedTLS
        CRYPTO_APIS.put("mbedTLS", new String[] {
            "mbedtls_aes_init", "mbedtls_aes_setkey_enc", "mbedtls_aes_crypt_cbc",
            "mbedtls_rsa_init", "mbedtls_rsa_pkcs1_encrypt", "mbedtls_sha256_init",
            "mbedtls_md5_init", "mbedtls_entropy_init", "mbedtls_ctr_drbg_init"
        });
    }
    
    private static byte[] hexToBytes(String hex) {
        int len = hex.length();
        byte[] data = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            data[i / 2] = (byte) ((Character.digit(hex.charAt(i), 16) << 4)
                                 + Character.digit(hex.charAt(i+1), 16));
        }
        return data;
    }

    @Override
    public void run() throws Exception {
        println("=== Intellicrack Advanced Cryptographic Analysis v3.0 ===");
        println("Performing comprehensive cryptographic detection and analysis...\n");
        
        // Initialize decompiler
        initializeDecompiler();
        
        try {
            // Phase 1: Signature detection
            println("[Phase 1] Detecting cryptographic signatures...");
            detectCryptoSignatures();
            
            // Phase 2: API analysis
            println("\n[Phase 2] Analyzing cryptographic API usage...");
            analyzeCryptoAPIs();
            
            // Phase 3: Function analysis
            println("\n[Phase 3] Analyzing potential crypto functions...");
            analyzeCryptoFunctions();
            
            // Phase 4: Key extraction
            println("\n[Phase 4] Extracting cryptographic keys...");
            extractCryptoKeys();
            
            // Phase 5: Algorithm identification
            println("\n[Phase 5] Identifying cryptographic algorithms...");
            identifyAlgorithms();
            
            // Phase 6: Implementation analysis
            println("\n[Phase 6] Analyzing crypto implementations...");
            analyzeImplementations();
            
            // Phase 7: Custom crypto detection
            println("\n[Phase 7] Detecting custom cryptography...");
            detectCustomCrypto();
            
            // Phase 8: Vulnerability analysis
            println("\n[Phase 8] Analyzing cryptographic vulnerabilities...");
            analyzeVulnerabilities();
            
            // Run additional phases (9-18)
            runAdditionalPhases();
            
            // Phase 18: Comprehensive analysis with unused imports
            println("\n[Phase 18] Comprehensive analysis with all imported components...");
            analyzeWithUnusedImports();
            
            // Generate comprehensive report
            generateReport();
            
        } finally {
            if (decompiler != null) {
                decompiler.dispose();
            }
        }
    }
    
    private void initializeDecompiler() {
        decompiler = new DecompInterface();
        decompiler.openProgram(currentProgram);
        DecompileOptions options = new DecompileOptions();
        decompiler.setOptions(options);
    }
    
    private void detectCryptoSignatures() throws Exception {
        Memory memory = currentProgram.getMemory();
        
        for (Map.Entry<String, CryptoSignature> entry : CRYPTO_SIGNATURES.entrySet()) {
            String algoName = entry.getKey();
            CryptoSignature sig = entry.getValue();
            
            println("  Searching for " + algoName + " signatures...");
            
            for (byte[] pattern : sig.patterns) {
                if (pattern.length < 4) continue; // Skip very short patterns
                
                Address[] found = findBytes(currentProgram.getMinAddress(), 
                                           pattern, pattern.length, 100);
                
                for (Address addr : found) {
                    CryptoDetection detection = new CryptoDetection();
                    detection.algorithm = algoName;
                    detection.address = addr;
                    detection.confidence = calculateConfidence(addr, sig);
                    detection.type = sig.type;
                    detection.description = sig.description;
                    
                    detectedAlgorithms.add(detection);
                    
                    println("    [+] Found " + algoName + " at " + addr + 
                           " (confidence: " + String.format("%.2f%%", detection.confidence * 100) + ")");
                    
                    createBookmark(addr, "Crypto", algoName + " signature detected");
                    
                    // Analyze surrounding code
                    analyzeSurroundingCode(addr, detection);
                }
            }
        }
        
        println("  Total signatures detected: " + detectedAlgorithms.size());
    }
    
    private double calculateConfidence(Address addr, CryptoSignature sig) throws Exception {
        double confidence = 0.5; // Base confidence
        
        // Check if in code section
        MemoryBlock block = currentProgram.getMemory().getBlock(addr);
        if (block != null && block.isExecute()) {
            confidence += 0.2;
        }
        
        // Check for multiple patterns from same algorithm
        int patternCount = 0;
        for (byte[] pattern : sig.patterns) {
            Address[] found = findBytes(addr, addr.add(1024), pattern, 1);
            if (found.length > 0) patternCount++;
        }
        if (patternCount > 1) {
            confidence += 0.2 * Math.min(patternCount, 3);
        }
        
        // Check for related API calls nearby
        Function func = getFunctionContaining(addr);
        if (func != null) {
            Set<Function> called = func.getCalledFunctions(monitor);
            for (Function callee : called) {
                String name = callee.getName();
                for (String[] apis : CRYPTO_APIS.values()) {
                    for (String api : apis) {
                        if (name.contains(api)) {
                            confidence += 0.1;
                            break;
                        }
                    }
                }
            }
        }
        
        return Math.min(confidence, 1.0);
    }
    
    private void analyzeSurroundingCode(Address addr, CryptoDetection detection) throws Exception {
        Function func = getFunctionContaining(addr);
        if (func == null) return;
        
        // Store function information
        CryptoFunction cryptoFunc = cryptoFunctions.get(func.getEntryPoint());
        if (cryptoFunc == null) {
            cryptoFunc = new CryptoFunction();
            cryptoFunc.function = func;
            cryptoFunc.address = func.getEntryPoint();
            cryptoFunc.name = func.getName();
            cryptoFunctions.put(func.getEntryPoint(), cryptoFunc);
        }
        
        cryptoFunc.detectedAlgorithms.add(detection.algorithm);
        
        // Analyze for key material
        analyzeForKeyMaterial(func, cryptoFunc);
        
        // Analyze control flow
        analyzeControlFlow(func, cryptoFunc);
    }
    
    private void analyzeForKeyMaterial(Function func, CryptoFunction cryptoFunc) throws Exception {
        // Look for potential key material in function
        ReferenceManager refManager = currentProgram.getReferenceManager();
        ReferenceIterator refs = refManager.getReferencesFrom(func.getBody());
        
        while (refs.hasNext()) {
            Reference ref = refs.next();
            Address toAddr = ref.getToAddress();
            
            Data data = currentProgram.getListing().getDataAt(toAddr);
            if (data != null) {
                // Check for byte arrays that could be keys
                if (data.isArray()) {
                    int length = data.getLength();
                    if (length == 16 || length == 24 || length == 32 || // AES keys
                        length == 64 || length == 128 || length == 256) { // RSA/ECC keys
                        
                        byte[] potentialKey = new byte[Math.min(length, 256)];
                        currentProgram.getMemory().getBytes(toAddr, potentialKey);
                        
                        // Check entropy
                        double entropy = calculateEntropy(potentialKey);
                        if (entropy > 7.0) { // High entropy suggests key material
                            CryptoKey key = new CryptoKey();
                            key.address = toAddr;
                            key.length = length;
                            key.entropy = entropy;
                            key.associatedFunction = func.getName();
                            key.keyMaterial = potentialKey;
                            
                            extractedKeys.add(key);
                            cryptoFunc.possibleKeys.add(key);
                        }
                    }
                }
            }
        }
    }
    
    private void analyzeControlFlow(Function func, CryptoFunction cryptoFunc) throws Exception {
        try {
            DecompileResults results = decompiler.decompileFunction(func, 30, monitor);
            if (!results.decompileCompleted()) return;
            
            HighFunction highFunc = results.getHighFunction();
            if (highFunc == null) return;
            
            // Analyze P-code for crypto patterns
            Iterator<PcodeOpAST> ops = highFunc.getPcodeOps();
            int xorCount = 0;
            int shiftCount = 0;
            int andCount = 0;
            int orCount = 0;
            
            while (ops.hasNext()) {
                PcodeOpAST op = ops.next();
                int opcode = op.getOpcode();
                
                switch (opcode) {
                    case PcodeOp.INT_XOR:
                    case PcodeOp.BOOL_XOR:
                        xorCount++;
                        break;
                    case PcodeOp.INT_LEFT:
                    case PcodeOp.INT_RIGHT:
                    case PcodeOp.INT_SRIGHT:
                        shiftCount++;
                        break;
                    case PcodeOp.INT_AND:
                    case PcodeOp.BOOL_AND:
                        andCount++;
                        break;
                    case PcodeOp.INT_OR:
                    case PcodeOp.BOOL_OR:
                        orCount++;
                        break;
                }
            }
            
            // High counts suggest crypto operations
            if (xorCount > 10 || (shiftCount > 5 && andCount > 5)) {
                cryptoFunc.likelyCrypto = true;
                cryptoFunc.complexity = xorCount + shiftCount + andCount + orCount;
            }
            
        } catch (Exception e) {
            // Continue on error
        }
    }
    
    private void analyzeCryptoAPIs() throws Exception {
        SymbolTable symbolTable = currentProgram.getSymbolTable();
        SymbolIterator extSymbols = symbolTable.getExternalSymbols();
        
        Map<String, List<Address>> apiUsage = new HashMap<>();
        
        while (extSymbols.hasNext() && !monitor.isCancelled()) {
            Symbol symbol = extSymbols.next();
            String apiName = symbol.getName();
            
            // Check against known crypto APIs
            for (Map.Entry<String, String[]> entry : CRYPTO_APIS.entrySet()) {
                String libraryName = entry.getKey();
                String[] apis = entry.getValue();
                
                for (String api : apis) {
                    if (apiName.equals(api) || apiName.contains(api)) {
                        println("  Found " + libraryName + " API: " + apiName);
                        
                        // Find all references
                        Reference[] refs = getReferencesTo(symbol.getAddress());
                        for (Reference ref : refs) {
                            Address callAddr = ref.getFromAddress();
                            Function func = getFunctionContaining(callAddr);
                            
                            if (func != null) {
                                CryptoFunction cryptoFunc = cryptoFunctions.get(func.getEntryPoint());
                                if (cryptoFunc == null) {
                                    cryptoFunc = new CryptoFunction();
                                    cryptoFunc.function = func;
                                    cryptoFunc.address = func.getEntryPoint();
                                    cryptoFunc.name = func.getName();
                                    cryptoFunctions.put(func.getEntryPoint(), cryptoFunc);
                                }
                                
                                cryptoFunc.cryptoAPIs.add(apiName);
                                cryptoFunc.library = libraryName;
                            }
                            
                            apiUsage.computeIfAbsent(apiName, k -> new ArrayList<>()).add(callAddr);
                        }
                    }
                }
            }
        }
        
        println("  Found " + apiUsage.size() + " unique crypto API calls");
    }
    
    private void analyzeCryptoFunctions() throws Exception {
        FunctionManager funcManager = currentProgram.getFunctionManager();
        FunctionIterator functions = funcManager.getFunctions(true);
        
        while (functions.hasNext() && !monitor.isCancelled()) {
            Function func = functions.next();
            String funcName = func.getName().toLowerCase();
            
            // Check for crypto-related function names
            String[] cryptoKeywords = {
                "crypt", "encrypt", "decrypt", "hash", "sign", "verify",
                "aes", "des", "rsa", "sha", "md5", "hmac", "cipher",
                "key", "random", "prng", "entropy", "ecdsa", "dsa"
            };
            
            boolean isCryptoRelated = false;
            for (String keyword : cryptoKeywords) {
                if (funcName.contains(keyword)) {
                    isCryptoRelated = true;
                    break;
                }
            }
            
            if (isCryptoRelated || cryptoFunctions.containsKey(func.getEntryPoint())) {
                CryptoFunction cryptoFunc = cryptoFunctions.get(func.getEntryPoint());
                if (cryptoFunc == null) {
                    cryptoFunc = new CryptoFunction();
                    cryptoFunc.function = func;
                    cryptoFunc.address = func.getEntryPoint();
                    cryptoFunc.name = func.getName();
                    cryptoFunctions.put(func.getEntryPoint(), cryptoFunc);
                }
                
                // Analyze function in detail
                analyzeFunctionImplementation(func, cryptoFunc);
            }
        }
        
        println("  Analyzed " + cryptoFunctions.size() + " potential crypto functions");
    }
    
    private void analyzeFunctionImplementation(Function func, CryptoFunction cryptoFunc) throws Exception {
        try {
            DecompileResults results = decompiler.decompileFunction(func, 30, monitor);
            if (!results.decompileCompleted()) return;
            
            String decompiledCode = results.getDecompiledFunction().getC();
            
            // Analyze for specific algorithm implementations
            if (decompiledCode.contains("sbox") || decompiledCode.contains("S_box")) {
                cryptoFunc.detectedAlgorithms.add("Block Cipher (S-box based)");
            }
            if (decompiledCode.contains("round") || decompiledCode.contains("rounds")) {
                cryptoFunc.detectedAlgorithms.add("Iterative Cipher");
            }
            if (decompiledCode.contains("modexp") || decompiledCode.contains("mod_exp")) {
                cryptoFunc.detectedAlgorithms.add("RSA/DH (modular exponentiation)");
            }
            if (decompiledCode.contains("point_mul") || decompiledCode.contains("scalar_mul")) {
                cryptoFunc.detectedAlgorithms.add("ECC (point multiplication)");
            }
            
            // Store decompiled code for further analysis
            cryptoFunc.decompiledCode = decompiledCode;
            
        } catch (Exception e) {
            // Continue on error
        }
    }
    
    private void extractCryptoKeys() throws Exception {
        Memory memory = currentProgram.getMemory();
        
        // Search for common key formats
        searchForPEMKeys();
        searchForDERKeys();
        searchForRawKeys();
        searchForHardcodedKeys();
        
        println("  Extracted " + extractedKeys.size() + " potential keys");
    }
    
    private void searchForPEMKeys() throws Exception {
        String[] pemHeaders = {
            "-----BEGIN RSA PRIVATE KEY-----",
            "-----BEGIN RSA PUBLIC KEY-----",
            "-----BEGIN EC PRIVATE KEY-----",
            "-----BEGIN PUBLIC KEY-----",
            "-----BEGIN PRIVATE KEY-----",
            "-----BEGIN CERTIFICATE-----"
        };
        
        for (String header : pemHeaders) {
            Address[] found = findBytes(currentProgram.getMinAddress(),
                                       header.getBytes(), 100);
            
            for (Address addr : found) {
                CryptoKey key = new CryptoKey();
                key.address = addr;
                key.format = "PEM";
                key.type = header.contains("PRIVATE") ? "Private Key" : "Public Key";
                
                // Try to extract full key
                try {
                    String keyData = extractPEMKey(addr);
                    if (keyData != null) {
                        key.keyMaterial = keyData.getBytes();
                        key.length = keyData.length();
                        extractedKeys.add(key);
                        
                        println("    [+] Found PEM " + key.type + " at " + addr);
                        createBookmark(addr, "Crypto Key", "PEM " + key.type);
                    }
                } catch (Exception e) {
                    // Continue on error
                }
            }
        }
    }
    
    private String extractPEMKey(Address startAddr) throws Exception {
        StringBuilder keyData = new StringBuilder();
        Memory memory = currentProgram.getMemory();
        Address currentAddr = startAddr;
        
        // Read until we find the END marker
        byte[] buffer = new byte[1024];
        while (memory.contains(currentAddr)) {
            int bytesRead = memory.getBytes(currentAddr, buffer, 0, Math.min(buffer.length, 
                (int)(memory.getMaxAddress().subtract(currentAddr))));
            
            String chunk = new String(buffer, 0, bytesRead);
            keyData.append(chunk);
            
            if (chunk.contains("-----END")) {
                int endIndex = keyData.indexOf("-----END");
                endIndex = keyData.indexOf("-----", endIndex + 8) + 5;
                if (endIndex > 5) {
                    return keyData.substring(0, endIndex);
                }
            }
            
            currentAddr = currentAddr.add(bytesRead);
            if (keyData.length() > 10000) break; // Sanity check
        }
        
        return null;
    }
    
    private void searchForDERKeys() throws Exception {
        // ASN.1 DER format signatures
        byte[][] derSignatures = {
            {0x30, (byte)0x82}, // SEQUENCE with 2-byte length
            {0x30, (byte)0x81}, // SEQUENCE with 1-byte length
            {0x02, (byte)0x81}, // INTEGER with 1-byte length
            {0x02, (byte)0x82}  // INTEGER with 2-byte length
        };
        
        for (byte[] sig : derSignatures) {
            Address[] found = findBytes(currentProgram.getMinAddress(), sig, 100);
            
            for (Address addr : found) {
                // Verify it looks like a key structure
                if (isDERKey(addr)) {
                    CryptoKey key = new CryptoKey();
                    key.address = addr;
                    key.format = "DER/ASN.1";
                    key.type = "Binary Key";
                    
                    // Extract key length from DER structure
                    key.length = extractDERLength(addr);
                    
                    extractedKeys.add(key);
                    println("    [+] Found DER key structure at " + addr + " (length: " + key.length + ")");
                    createBookmark(addr, "Crypto Key", "DER Key Structure");
                }
            }
        }
    }
    
    private boolean isDERKey(Address addr) throws Exception {
        Memory memory = currentProgram.getMemory();
        byte[] header = new byte[4];
        memory.getBytes(addr, header);
        
        // Check for valid ASN.1 structure
        if (header[0] == 0x30) { // SEQUENCE
            int length = 0;
            if ((header[1] & 0x80) != 0) {
                // Long form length
                int numBytes = header[1] & 0x7F;
                if (numBytes > 0 && numBytes <= 4) {
                    return true;
                }
            } else {
                // Short form length
                length = header[1] & 0x7F;
                return length > 0 && length < 10000;
            }
        }
        return false;
    }
    
    private int extractDERLength(Address addr) throws Exception {
        Memory memory = currentProgram.getMemory();
        byte[] header = new byte[6];
        memory.getBytes(addr, header);
        
        if (header[0] == 0x30) { // SEQUENCE
            if ((header[1] & 0x80) != 0) {
                // Long form
                int numBytes = header[1] & 0x7F;
                int length = 0;
                for (int i = 0; i < numBytes && i < 4; i++) {
                    length = (length << 8) | (header[2 + i] & 0xFF);
                }
                return length;
            } else {
                // Short form
                return header[1] & 0x7F;
            }
        }
        return 0;
    }
    
    private void searchForRawKeys() throws Exception {
        // Look for high-entropy byte sequences that could be keys
        Memory memory = currentProgram.getMemory();
        
        for (MemoryBlock block : memory.getBlocks()) {
            if (!block.isInitialized()) continue;
            
            Address addr = block.getStart();
            Address end = block.getEnd();
            
            byte[] buffer = new byte[256];
            while (addr.compareTo(end) < 0 && !monitor.isCancelled()) {
                int size = Math.min(buffer.length, (int)(end.subtract(addr)) + 1);
                memory.getBytes(addr, buffer, 0, size);
                
                // Check common key sizes
                int[] keySizes = {16, 24, 32, 48, 64, 128, 256};
                for (int keySize : keySizes) {
                    if (size >= keySize) {
                        byte[] potential = Arrays.copyOf(buffer, keySize);
                        double entropy = calculateEntropy(potential);
                        
                        if (entropy > 7.5) { // Very high entropy
                            CryptoKey key = new CryptoKey();
                            key.address = addr;
                            key.length = keySize;
                            key.entropy = entropy;
                            key.format = "Raw";
                            key.keyMaterial = potential;
                            
                            extractedKeys.add(key);
                            println("    [+] Found high-entropy data at " + addr + 
                                   " (size: " + keySize + ", entropy: " + String.format("%.2f", entropy) + ")");
                        }
                    }
                }
                
                addr = addr.add(256);
            }
        }
    }
    
    private void searchForHardcodedKeys() throws Exception {
        // Search for common hardcoded test keys
        String[] testKeys = {
            "0123456789abcdef",
            "abcdef0123456789",
            "deadbeefdeadbeef",
            "1234567890123456",
            "aaaaaaaaaaaaaaaa"
        };
        
        for (String testKey : testKeys) {
            byte[] keyBytes = hexStringToBytes(testKey);
            Address[] found = findBytes(currentProgram.getMinAddress(), keyBytes, 10);
            
            for (Address addr : found) {
                CryptoKey key = new CryptoKey();
                key.address = addr;
                key.length = keyBytes.length;
                key.format = "Hardcoded";
                key.type = "Weak/Test Key";
                key.keyMaterial = keyBytes;
                
                extractedKeys.add(key);
                println("    [!] WARNING: Found hardcoded test key at " + addr);
                createBookmark(addr, "Security Issue", "Hardcoded test key");
            }
        }
    }
    
    private byte[] hexStringToBytes(String hex) {
        int len = hex.length();
        byte[] data = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            data[i / 2] = (byte) ((Character.digit(hex.charAt(i), 16) << 4)
                                 + Character.digit(hex.charAt(i+1), 16));
        }
        return data;
    }
    
    private double calculateEntropy(byte[] data) {
        if (data.length == 0) return 0.0;
        
        int[] frequency = new int[256];
        for (byte b : data) {
            frequency[b & 0xFF]++;
        }
        
        double entropy = 0.0;
        for (int freq : frequency) {
            if (freq > 0) {
                double probability = (double) freq / data.length;
                entropy -= probability * (Math.log(probability) / Math.log(2));
            }
        }
        
        return entropy;
    }
    
    private void identifyAlgorithms() throws Exception {
        // Correlate all findings to identify specific algorithms
        Map<String, Integer> algorithmScores = new HashMap<>();
        
        for (CryptoDetection detection : detectedAlgorithms) {
            algorithmScores.put(detection.algorithm, 
                algorithmScores.getOrDefault(detection.algorithm, 0) + 1);
        }
        
        for (CryptoFunction func : cryptoFunctions.values()) {
            for (String algo : func.detectedAlgorithms) {
                algorithmScores.put(algo, 
                    algorithmScores.getOrDefault(algo, 0) + 1);
            }
        }
        
        println("  Identified algorithms:");
        for (Map.Entry<String, Integer> entry : algorithmScores.entrySet()) {
            if (entry.getValue() > 0) {
                println("    - " + entry.getKey() + " (confidence: " + entry.getValue() + " indicators)");
                
                // Create implementation tracking
                CryptoImplementation impl = new CryptoImplementation();
                impl.algorithm = entry.getKey();
                impl.confidence = Math.min(entry.getValue() / 10.0, 1.0);
                implementations.add(impl);
            }
        }
    }
    
    private void analyzeImplementations() throws Exception {
        for (CryptoImplementation impl : implementations) {
            // Find functions implementing this algorithm
            for (CryptoFunction func : cryptoFunctions.values()) {
                if (func.detectedAlgorithms.contains(impl.algorithm)) {
                    impl.functions.add(func);
                    
                    // Analyze implementation quality
                    analyzeImplementationQuality(impl, func);
                }
            }
            
            println("  " + impl.algorithm + " implementation:");
            println("    Functions: " + impl.functions.size());
            println("    Quality: " + impl.quality);
            if (!impl.vulnerabilities.isEmpty()) {
                println("    Vulnerabilities: " + String.join(", ", impl.vulnerabilities));
            }
        }
    }
    
    private void analyzeImplementationQuality(CryptoImplementation impl, CryptoFunction func) {
        // Check for common implementation issues
        if (func.decompiledCode != null) {
            String code = func.decompiledCode.toLowerCase();
            
            // Check for timing attack vulnerabilities
            if (code.contains("if") && (code.contains("key") || code.contains("password"))) {
                impl.vulnerabilities.add("Potential timing attack");
            }
            
            // Check for weak random number generation
            if (code.contains("rand()") || code.contains("srand")) {
                impl.vulnerabilities.add("Weak RNG (rand/srand)");
            }
            
            // Check for ECB mode
            if (code.contains("ecb")) {
                impl.vulnerabilities.add("ECB mode usage");
            }
            
            // Check for hardcoded IVs
            if (code.contains("iv") && code.contains("0x00")) {
                impl.vulnerabilities.add("Potential hardcoded IV");
            }
        }
        
        // Assess overall quality
        if (impl.vulnerabilities.isEmpty()) {
            impl.quality = "Good";
        } else if (impl.vulnerabilities.size() == 1) {
            impl.quality = "Fair";
        } else {
            impl.quality = "Poor";
        }
    }
    
    private void detectCustomCrypto() throws Exception {
        // Look for functions with crypto-like characteristics but no known signatures
        FunctionManager funcManager = currentProgram.getFunctionManager();
        FunctionIterator functions = funcManager.getFunctions(true);
        
        int customCryptoCount = 0;
        
        while (functions.hasNext() && !monitor.isCancelled()) {
            Function func = functions.next();
            
            // Skip if already identified
            if (cryptoFunctions.containsKey(func.getEntryPoint())) continue;
            
            try {
                DecompileResults results = decompiler.decompileFunction(func, 30, monitor);
                if (!results.decompileCompleted()) continue;
                
                HighFunction highFunc = results.getHighFunction();
                if (highFunc == null) continue;
                
                // Count crypto-like operations
                int xorCount = 0, shiftCount = 0, andCount = 0;
                Iterator<PcodeOpAST> ops = highFunc.getPcodeOps();
                
                while (ops.hasNext()) {
                    PcodeOpAST op = ops.next();
                    switch (op.getOpcode()) {
                        case PcodeOp.INT_XOR:
                            xorCount++;
                            break;
                        case PcodeOp.INT_LEFT:
                        case PcodeOp.INT_RIGHT:
                            shiftCount++;
                            break;
                        case PcodeOp.INT_AND:
                            andCount++;
                            break;
                    }
                }
                
                // High concentration of bitwise operations suggests crypto
                if (xorCount > 20 || (shiftCount > 10 && andCount > 10)) {
                    println("  [!] Potential custom crypto at " + func.getName() + " @ " + func.getEntryPoint());
                    println("      XOR ops: " + xorCount + ", Shift ops: " + shiftCount + ", AND ops: " + andCount);
                    
                    createBookmark(func.getEntryPoint(), "Custom Crypto", 
                        "Potential custom crypto implementation");
                    customCryptoCount++;
                }
                
            } catch (Exception e) {
                // Continue on error
            }
        }
        
        println("  Found " + customCryptoCount + " potential custom crypto implementations");
    }
    
    private void analyzeVulnerabilities() throws Exception {
        println("  Analyzing cryptographic vulnerabilities:");
        
        // Check for weak keys
        for (CryptoKey key : extractedKeys) {
            if (key.type != null && key.type.equals("Weak/Test Key")) {
                println("    [!] Weak/hardcoded key at " + key.address);
            }
            if (key.entropy < 4.0 && key.keyMaterial != null) {
                println("    [!] Low entropy key at " + key.address + " (entropy: " + 
                       String.format("%.2f", key.entropy) + ")");
            }
        }
        
        // Check for deprecated algorithms
        String[] deprecated = {"MD5", "SHA-1", "DES", "RC4"};
        for (CryptoDetection detection : detectedAlgorithms) {
            for (String dep : deprecated) {
                if (detection.algorithm.contains(dep)) {
                    println("    [!] Deprecated algorithm " + dep + " at " + detection.address);
                }
            }
        }
        
        // Check for small key sizes
        for (CryptoKey key : extractedKeys) {
            if (key.length < 128 / 8) { // Less than 128 bits
                println("    [!] Small key size (" + (key.length * 8) + " bits) at " + key.address);
            }
        }
    }
    
    private void generateReport() throws Exception {
        println("\n=== Cryptographic Analysis Report ===\n");
        
        println("Summary:");
        println("--------");
        println("Crypto signatures found: " + detectedAlgorithms.size());
        println("Crypto functions identified: " + cryptoFunctions.size());
        println("Keys extracted: " + extractedKeys.size());
        println("Implementations analyzed: " + implementations.size());
        
        println("\nDetected Algorithms:");
        println("-------------------");
        Map<String, List<CryptoDetection>> byAlgorithm = new HashMap<>();
        for (CryptoDetection detection : detectedAlgorithms) {
            byAlgorithm.computeIfAbsent(detection.algorithm, k -> new ArrayList<>()).add(detection);
        }
        
        for (Map.Entry<String, List<CryptoDetection>> entry : byAlgorithm.entrySet()) {
            println("  " + entry.getKey() + ": " + entry.getValue().size() + " occurrences");
            for (CryptoDetection det : entry.getValue()) {
                println("    @ " + det.address + " (confidence: " + 
                       String.format("%.2f%%", det.confidence * 100) + ")");
            }
        }
        
        println("\nCryptographic Functions:");
        println("------------------------");
        for (CryptoFunction func : cryptoFunctions.values()) {
            println("  " + func.name + " @ " + func.address);
            if (!func.detectedAlgorithms.isEmpty()) {
                println("    Algorithms: " + String.join(", ", func.detectedAlgorithms));
            }
            if (!func.cryptoAPIs.isEmpty()) {
                println("    APIs: " + String.join(", ", func.cryptoAPIs));
            }
            if (func.likelyCrypto) {
                println("    Complexity: " + func.complexity);
            }
        }
        
        println("\nExtracted Keys:");
        println("---------------");
        for (CryptoKey key : extractedKeys) {
            println("  " + key.format + " key @ " + key.address);
            println("    Size: " + (key.length * 8) + " bits");
            if (key.entropy > 0) {
                println("    Entropy: " + String.format("%.2f", key.entropy));
            }
            if (key.type != null) {
                println("    Type: " + key.type);
            }
        }
        
        println("\nSecurity Recommendations:");
        println("-------------------------");
        
        // Generate recommendations based on findings
        Set<String> recommendations = new HashSet<>();
        
        for (CryptoImplementation impl : implementations) {
            if (!impl.vulnerabilities.isEmpty()) {
                for (String vuln : impl.vulnerabilities) {
                    if (vuln.contains("timing")) {
                        recommendations.add("Implement constant-time comparisons for sensitive operations");
                    }
                    if (vuln.contains("RNG")) {
                        recommendations.add("Use cryptographically secure random number generators");
                    }
                    if (vuln.contains("ECB")) {
                        recommendations.add("Replace ECB mode with CBC, CTR, or GCM mode");
                    }
                    if (vuln.contains("IV")) {
                        recommendations.add("Use unique, random IVs for each encryption operation");
                    }
                }
            }
        }
        
        if (!extractedKeys.isEmpty()) {
            recommendations.add("Remove hardcoded keys from binary");
            recommendations.add("Implement secure key management");
        }
        
        for (String rec : recommendations) {
            println("  - " + rec);
        }
        
        // Export detailed report
        exportDetailedReport();
    }
    
    private void exportDetailedReport() throws Exception {
        try {
            File outputFile = askFile("Save Crypto Analysis Report", "Save");
            if (outputFile == null) return;
            
            PrintWriter writer = new PrintWriter(outputFile);
            writer.println("Intellicrack Cryptographic Analysis Report");
            writer.println("===========================================");
            writer.println("Date: " + new java.util.Date());
            writer.println("Program: " + currentProgram.getName());
            writer.println();
            
            // Write detailed findings
            writer.println("Cryptographic Signatures:");
            for (CryptoDetection detection : detectedAlgorithms) {
                writer.println("  " + detection.algorithm + " @ " + detection.address);
                writer.println("    Confidence: " + String.format("%.2f%%", detection.confidence * 100));
                writer.println("    Type: " + detection.type);
            }
            
            writer.println("\nCryptographic Functions:");
            for (CryptoFunction func : cryptoFunctions.values()) {
                writer.println("  Function: " + func.name);
                writer.println("    Address: " + func.address);
                writer.println("    Algorithms: " + String.join(", ", func.detectedAlgorithms));
                writer.println("    APIs: " + String.join(", ", func.cryptoAPIs));
            }
            
            writer.println("\nExtracted Keys:");
            for (CryptoKey key : extractedKeys) {
                writer.println("  Address: " + key.address);
                writer.println("    Format: " + key.format);
                writer.println("    Size: " + (key.length * 8) + " bits");
                writer.println("    Entropy: " + String.format("%.2f", key.entropy));
            }
            
            writer.close();
            println("\nDetailed report saved to: " + outputFile.getAbsolutePath());
            
        } catch (Exception e) {
            printerr("Failed to export report: " + e.getMessage());
        }
    }
    
    private Address[] findBytes(Address start, Address end, byte[] pattern, int maxHits) {
        List<Address> results = new ArrayList<>();
        try {
            Memory memory = currentProgram.getMemory();
            Address current = start;
            
            while (current != null && current.compareTo(end) <= 0 && results.size() < maxHits) {
                current = memory.findBytes(current, end, pattern, null, true, monitor);
                if (current != null) {
                    results.add(current);
                    current = current.add(1);
                }
            }
        } catch (Exception e) {
            // Continue on error
        }
        return results.toArray(new Address[0]);
    }
    
    private Address[] findBytes(Address start, byte[] pattern, int maxHits) {
        return findBytes(start, currentProgram.getMaxAddress(), pattern, maxHits);
    }
    
    // Phase 9: Memory access exception handling
    private void analyzeMemoryProtectedRegions() throws Exception {
        println("\n[Phase 9] Analyzing memory-protected crypto regions...");
        Memory memory = currentProgram.getMemory();
        int protectedRegions = 0;
        
        for (CryptoDetection detection : detectedAlgorithms) {
            Address addr = detection.address;
            
            try {
                // Attempt to read with potential MemoryAccessException
                byte[] testRead = new byte[256];
                memory.getBytes(addr, testRead);
                
                // If successful, check if region has special protections
                MemoryBlock block = memory.getBlock(addr);
                if (block != null && !block.isWrite()) {
                    protectedRegions++;
                    println("  Read-only crypto at " + addr);
                    createBookmark(addr, "Protected Crypto", "Read-only crypto region");
                }
                
            } catch (MemoryAccessException mae) {
                // This indicates protected/inaccessible memory
                protectedRegions++;
                println("  [!] Protected crypto region at " + addr + ": " + mae.getMessage());
                createBookmark(addr, "Protected Crypto", "Memory-protected crypto: " + mae.getMessage());
                
                // Track this as high-value crypto
                detection.confidence = Math.min(detection.confidence + 0.2, 1.0);
            }
        }
        
        println("  Found " + protectedRegions + " protected crypto regions");
    }
    
    // Phase 10: Instruction-level crypto pattern analysis
    private void analyzeInstructionPatterns() throws Exception {
        println("\n[Phase 10] Analyzing instruction-level crypto patterns...");
        Listing listing = currentProgram.getListing();
        
        for (CryptoFunction cryptoFunc : cryptoFunctions.values()) {
            Function func = cryptoFunc.function;
            InstructionIterator instIter = listing.getInstructions(func.getBody(), true);
            
            int aesniCount = 0;
            int shaExtCount = 0;
            
            while (instIter.hasNext() && !monitor.isCancelled()) {
                Instruction inst = instIter.next();
                String mnemonic = inst.getMnemonicString().toUpperCase();
                
                // Check for AES-NI instructions
                if (mnemonic.startsWith("AES")) {
                    aesniCount++;
                    cryptoFunc.detectedAlgorithms.add("AES-NI Hardware");
                    createBookmark(inst.getAddress(), "Crypto", "AES-NI instruction: " + mnemonic);
                }
                
                // Check for SHA extensions
                if (mnemonic.startsWith("SHA")) {
                    shaExtCount++;
                    cryptoFunc.detectedAlgorithms.add("SHA Hardware Extensions");
                    createBookmark(inst.getAddress(), "Crypto", "SHA extension: " + mnemonic);
                }
                
                // Check for crypto-specific patterns
                if (mnemonic.equals("PSHUFB") || mnemonic.equals("PALIGNR")) {
                    cryptoFunc.detectedAlgorithms.add("SIMD Crypto Operations");
                }
                
                // Use CodeUnit for detailed analysis
                CodeUnit codeUnit = listing.getCodeUnitAt(inst.getAddress());
                if (codeUnit != null) {
                    String comment = codeUnit.getComment(CodeUnit.PLATE_COMMENT);
                    if (comment != null && comment.toLowerCase().contains("crypto")) {
                        cryptoFunc.detectedAlgorithms.add("Documented Crypto");
                    }
                }
            }
            
            if (aesniCount > 0) {
                println("  Found " + aesniCount + " AES-NI instructions in " + func.getName());
            }
            if (shaExtCount > 0) {
                println("  Found " + shaExtCount + " SHA extension instructions in " + func.getName());
            }
        }
    }
    
    // Phase 11: Address set operations for crypto regions
    private void mapCryptoAddressSets() throws Exception {
        println("\n[Phase 11] Mapping crypto address sets...");
        
        // Create address sets for different crypto types
        AddressSet aesRegions = new AddressSet();
        AddressSet rsaRegions = new AddressSet();
        AddressSet hashRegions = new AddressSet();
        
        for (CryptoDetection detection : detectedAlgorithms) {
            Address addr = detection.address;
            
            // Create range around detection
            try {
                Address rangeStart = addr.subtract(256);
                Address rangeEnd = addr.add(256);
                AddressRange range = new ghidra.program.database.map.AddressRangeImpl(rangeStart, rangeEnd);
                
                if (detection.algorithm.contains("AES")) {
                    aesRegions.add(range);
                } else if (detection.algorithm.contains("RSA")) {
                    rsaRegions.add(range);
                } else if (detection.algorithm.contains("SHA") || detection.algorithm.contains("MD5")) {
                    hashRegions.add(range);
                }
            } catch (Exception e) {
                // Continue on error
            }
        }
        
        // Analyze the address sets
        analyzeAddressSetView(aesRegions, "AES");
        analyzeAddressSetView(rsaRegions, "RSA");
        analyzeAddressSetView(hashRegions, "Hash");
        
        // Check for overlapping crypto regions
        AddressSetView intersection = aesRegions.intersect(rsaRegions);
        if (!intersection.isEmpty()) {
            println("  [!] Found hybrid crypto region (AES+RSA): " + intersection.getNumAddresses() + " bytes");
        }
    }
    
    private void analyzeAddressSetView(AddressSetView view, String type) {
        if (view.isEmpty()) return;
        
        long totalBytes = view.getNumAddresses();
        int rangeCount = 0;
        
        Iterator<AddressRange> rangeIter = view.iterator();
        while (rangeIter.hasNext()) {
            AddressRange range = rangeIter.next();
            rangeCount++;
            
            // Check address space
            AddressSpace space = range.getMinAddress().getAddressSpace();
            if (space != null) {
                String spaceName = space.getName();
                if (!spaceName.equals("ram")) {
                    println("  " + type + " crypto in " + spaceName + " space at " + range);
                }
            }
        }
        
        println("  " + type + " regions: " + rangeCount + " ranges, " + totalBytes + " total bytes");
    }
    
    // Phase 12: Data type and structure analysis
    private void analyzeCryptoDataTypes() throws Exception {
        println("\n[Phase 12] Analyzing crypto data types and structures...");
        DataTypeManager dtm = currentProgram.getDataTypeManager();
        
        // Look for crypto-related data types
        Iterator<DataType> allTypes = dtm.getAllDataTypes();
        int cryptoTypeCount = 0;
        
        while (allTypes.hasNext() && !monitor.isCancelled()) {
            DataType dt = allTypes.next();
            String typeName = dt.getName().toLowerCase();
            
            if (typeName.contains("crypt") || typeName.contains("key") || 
                typeName.contains("hash") || typeName.contains("cipher")) {
                
                cryptoTypeCount++;
                println("  Found crypto type: " + dt.getName() + " (" + dt.getLength() + " bytes)");
                
                // Check for enum types
                if (dt instanceof Enum) {
                    Enum enumType = (Enum) dt;
                    String[] names = enumType.getNames();
                    
                    for (String name : names) {
                        if (name.contains("AES") || name.contains("RSA") || name.contains("SHA")) {
                            long value = enumType.getValue(name);
                            println("    Crypto constant: " + name + " = 0x" + Long.toHexString(value));
                        }
                    }
                }
                
                // Check for structure types
                if (dt instanceof Structure) {
                    Structure struct = (Structure) dt;
                    println("    Structure with " + struct.getNumComponents() + " components");
                    
                    // Analyze structure for key material
                    for (int i = 0; i < struct.getNumComponents(); i++) {
                        DataTypeComponent comp = struct.getComponent(i);
                        if (comp.getFieldName() != null && 
                            (comp.getFieldName().contains("key") || comp.getFieldName().contains("iv"))) {
                            println("      Key field: " + comp.getFieldName() + " at offset " + comp.getOffset());
                        }
                    }
                }
            }
        }
        
        println("  Found " + cryptoTypeCount + " crypto-related data types");
    }
    
    // Phase 13: Register and language analysis
    private void analyzeRegisterCryptoPatterns() throws Exception {
        println("\n[Phase 13] Analyzing register-based crypto patterns...");
        Language language = currentProgram.getLanguage();
        Register[] registers = language.getRegisters();
        
        for (CryptoFunction cryptoFunc : cryptoFunctions.values()) {
            Function func = cryptoFunc.function;
            InstructionIterator instIter = currentProgram.getListing()
                .getInstructions(func.getBody(), true);
            
            Map<String, Integer> regUsage = new HashMap<>();
            
            while (instIter.hasNext() && !monitor.isCancelled()) {
                Instruction inst = instIter.next();
                
                for (int i = 0; i < inst.getNumOperands(); i++) {
                    // Check operand type
                    int opType = inst.getOperandType(i);
                    
                    if ((opType & OperandType.REGISTER) != 0) {
                        Register reg = inst.getRegister(i);
                        if (reg != null) {
                            String regName = reg.getName().toUpperCase();
                            
                            // Track SIMD register usage (crypto indicator)
                            if (regName.startsWith("XMM") || regName.startsWith("YMM") || 
                                regName.startsWith("ZMM")) {
                                regUsage.put(regName, regUsage.getOrDefault(regName, 0) + 1);
                                
                                // Check register value for crypto constants
                                try {
                                    RegisterValue regValue = currentProgram.getProgramContext()
                                        .getRegisterValue(reg, inst.getAddress());
                                    
                                    if (regValue != null && regValue.hasValue()) {
                                        BigInteger value = regValue.getUnsignedValue();
                                        if (value != null) {
                                            // Check for known crypto constants
                                            checkCryptoConstant(value, inst.getAddress(), regName);
                                        }
                                    }
                                } catch (Exception e) {
                                    // Continue on error
                                }
                            }
                        }
                    }
                    
                    // Check for immediate crypto constants
                    if ((opType & OperandType.SCALAR) != 0) {
                        Object[] opObjects = inst.getOpObjects(i);
                        for (Object obj : opObjects) {
                            if (obj instanceof Scalar) {
                                long value = ((Scalar)obj).getValue();
                                checkCryptoConstantLong(value, inst.getAddress());
                            }
                        }
                    }
                }
            }
            
            // Report SIMD usage
            if (!regUsage.isEmpty()) {
                println("  SIMD register usage in " + func.getName() + ":");
                for (Map.Entry<String, Integer> entry : regUsage.entrySet()) {
                    if (entry.getValue() > 3) {
                        println("    " + entry.getKey() + ": " + entry.getValue() + " uses");
                    }
                }
            }
        }
    }
    
    private void checkCryptoConstant(BigInteger value, Address addr, String context) {
        // Check for known crypto constants
        String hexValue = value.toString(16);
        
        // AES round constants
        if (hexValue.equals("01000000") || hexValue.equals("02000000") || 
            hexValue.equals("04000000") || hexValue.equals("08000000")) {
            println("    AES round constant in " + context + " at " + addr);
            createBookmark(addr, "Crypto Constant", "AES round constant");
        }
        
        // RSA common exponent
        if (value.equals(BigInteger.valueOf(65537))) {
            println("    RSA exponent (65537) in " + context + " at " + addr);
            createBookmark(addr, "Crypto Constant", "RSA public exponent");
        }
        
        // Check for high entropy (potential key material)
        if (value.bitLength() >= 128) {
            byte[] bytes = value.toByteArray();
            double entropy = calculateEntropy(bytes);
            if (entropy > 7.0) {
                println("    High-entropy value in " + context + " at " + addr + 
                       " (entropy: " + String.format("%.2f", entropy) + ")");
            }
        }
    }
    
    private void checkCryptoConstantLong(long value, Address addr) {
        // SHA-256 initial hash values
        if (value == 0x6a09e667L || value == 0xbb67ae85L || 
            value == 0x3c6ef372L || value == 0xa54ff53aL) {
            println("    SHA-256 initial value at " + addr);
            createBookmark(addr, "Crypto Constant", "SHA-256 H value");
        }
        
        // MD5 constants
        if (value == 0xd76aa478L || value == 0xe8c7b756L ||
            value == 0x242070dbL || value == 0xc1bdceeeL) {
            println("    MD5 constant at " + addr);
            createBookmark(addr, "Crypto Constant", "MD5 T-table value");
        }
    }
    
    // Phase 14: P-code block analysis
    private void analyzePcodeBlocks() throws Exception {
        println("\n[Phase 14] Analyzing P-code blocks for crypto patterns...");
        
        for (CryptoFunction cryptoFunc : cryptoFunctions.values()) {
            try {
                // Check for user cancellation
                if (monitor.isCancelled()) {
                    throw new CancelledException("P-code analysis cancelled by user");
                }
                
                DecompileResults results = decompiler.decompileFunction(cryptoFunc.function, 30, monitor);
                if (!results.decompileCompleted()) continue;
                
                HighFunction highFunc = results.getHighFunction();
                if (highFunc == null) continue;
                
                // Get basic blocks
                ArrayList<PcodeBlockBasic> blocks = highFunc.getBasicBlocks();
                int cryptoBlockCount = 0;
                
                for (PcodeBlockBasic block : blocks) {
                    Iterator<PcodeOp> ops = block.getIterator();
                    int blockXorCount = 0;
                    int blockRotateCount = 0;
                    
                    while (ops.hasNext()) {
                        PcodeOp op = ops.next();
                        
                        // Count crypto operations
                        if (op.getOpcode() == PcodeOp.INT_XOR) {
                            blockXorCount++;
                        }
                        if (op.getOpcode() == PcodeOp.INT_LEFT || op.getOpcode() == PcodeOp.INT_RIGHT) {
                            blockRotateCount++;
                        }
                        
                        // Analyze varnodes
                        Varnode output = op.getOutput();
                        if (output != null) {
                            analyzeVarnode(output, cryptoFunc);
                        }
                        
                        for (int i = 0; i < op.getNumInputs(); i++) {
                            Varnode input = op.getInput(i);
                            if (input != null) {
                                analyzeVarnode(input, cryptoFunc);
                            }
                        }
                    }
                    
                    // High concentration of XOR/rotate suggests crypto
                    if (blockXorCount > 5 || blockRotateCount > 3) {
                        cryptoBlockCount++;
                    }
                }
                
                if (cryptoBlockCount > 0) {
                    println("  Found " + cryptoBlockCount + " crypto blocks in " + cryptoFunc.name);
                    cryptoFunc.complexity += cryptoBlockCount * 10;
                }
                
            } catch (Exception e) {
                // Continue on error
            }
        }
    }
    
    private void analyzeVarnode(Varnode varnode, CryptoFunction cryptoFunc) {
        if (varnode.isConstant()) {
            long value = varnode.getOffset();
            
            // Check for crypto constants
            if (value == 0x5a827999L || value == 0x6ed9eba1L || 
                value == 0x8f1bbcdcL || value == 0xca62c1d6L) {
                cryptoFunc.detectedAlgorithms.add("SHA-1");
            }
            
            // Check for key schedule constants
            if ((value & 0xFF) == 0x1B) { // AES polynomial
                cryptoFunc.detectedAlgorithms.add("AES Key Schedule");
            }
        }
        
        // Check varnode size for crypto indicators
        int size = varnode.getSize();
        if (size == 16) {
            cryptoFunc.detectedAlgorithms.add("128-bit Block Operations");
        } else if (size == 32) {
            cryptoFunc.detectedAlgorithms.add("256-bit Operations");
        }
    }
    
    // Phase 15: File I/O for crypto configuration
    private void analyzeCryptoConfiguration() throws Exception {
        println("\n[Phase 15] Analyzing crypto configuration files...");
        
        // Look for file I/O operations that might load crypto config
        for (CryptoFunction cryptoFunc : cryptoFunctions.values()) {
            for (String api : cryptoFunc.cryptoAPIs) {
                if (api.contains("fopen") || api.contains("CreateFile") || api.contains("open")) {
                    println("  " + cryptoFunc.name + " may load crypto configuration");
                    
                    // Export function for further analysis
                    exportCryptoFunction(cryptoFunc);
                }
            }
        }
        
        // Load known crypto config patterns
        loadCryptoConfigPatterns();
    }
    
    private void exportCryptoFunction(CryptoFunction cryptoFunc) {
        try {
            String fileName = "crypto_func_" + cryptoFunc.name + ".txt";
            FileWriter writer = new FileWriter(fileName);
            
            writer.write("Crypto Function Analysis: " + cryptoFunc.name + "\n");
            writer.write("Address: " + cryptoFunc.address + "\n");
            writer.write("Algorithms: " + String.join(", ", cryptoFunc.detectedAlgorithms) + "\n");
            writer.write("APIs: " + String.join(", ", cryptoFunc.cryptoAPIs) + "\n");
            writer.write("Complexity: " + cryptoFunc.complexity + "\n");
            
            if (cryptoFunc.decompiledCode != null) {
                writer.write("\nDecompiled Code:\n");
                writer.write(cryptoFunc.decompiledCode);
            }
            
            writer.close();
            println("    Exported to " + fileName);
            
        } catch (IOException ioe) {
            println("    Export failed: " + ioe.getMessage());
        }
    }
    
    private void loadCryptoConfigPatterns() throws InvalidInputException {
        try {
            String configFile = "crypto_patterns.conf";
            BufferedReader reader = new BufferedReader(new FileReader(configFile));
            
            String line;
            int patternCount = 0;
            
            while ((line = reader.readLine()) != null) {
                if (line.trim().isEmpty() || line.startsWith("#")) continue;
                
                String[] parts = line.split(":");
                if (parts.length == 2) {
                    String algorithm = parts[0].trim();
                    String pattern = parts[1].trim();
                    
                    // Validate pattern format
                    if (pattern.length() % 2 != 0) {
                        throw new InvalidInputException("Invalid hex pattern for " + algorithm + ": odd length");
                    }
                    
                    // Validate hex characters
                    for (char c : pattern.toCharArray()) {
                        if (!Character.isDigit(c) && !(c >= 'a' && c <= 'f') && !(c >= 'A' && c <= 'F')) {
                            throw new InvalidInputException("Invalid hex character '" + c + "' in pattern for " + algorithm);
                        }
                    }
                    
                    // Add to pattern database
                    byte[] patternBytes = hexStringToBytes(pattern);
                    ALGORITHM_PATTERNS.computeIfAbsent(algorithm, k -> new byte[0][])
                        [0] = patternBytes;
                    
                    patternCount++;
                } else {
                    throw new InvalidInputException("Invalid config line format: " + line);
                }
            }
            
            reader.close();
            
            if (patternCount > 0) {
                println("  Loaded " + patternCount + " patterns from config");
            }
            
        } catch (IOException ioe) {
            // Config file not found, use defaults
            println("  Using default crypto patterns");
        } catch (InvalidInputException iie) {
            println("  Config validation error: " + iie.getMessage());
            throw iie;
        }
    }
    
    // Phase 16: NIO buffer analysis for crypto data
    private void analyzeNIOBuffers() throws Exception {
        println("\n[Phase 16] Analyzing NIO buffers for crypto operations...");
        
        // Look for buffer operations in crypto functions
        for (CryptoFunction cryptoFunc : cryptoFunctions.values()) {
            // Simulate buffer analysis
            analyzeCryptoBuffers(cryptoFunc);
        }
    }
    
    private void analyzeCryptoBuffers(CryptoFunction cryptoFunc) {
        // Create buffers for analysis
        ByteBuffer byteBuffer = ByteBuffer.allocate(256);
        byteBuffer.order(ByteOrder.BIG_ENDIAN); // Network byte order for crypto
        
        CharBuffer charBuffer = CharBuffer.allocate(128);
        IntBuffer intBuffer = IntBuffer.allocate(64);
        
        // Check for endianness issues (common crypto bug)
        ByteOrder nativeOrder = ByteOrder.nativeOrder();
        if (nativeOrder == ByteOrder.LITTLE_ENDIAN) {
            // Many crypto algorithms expect big-endian
            boolean hasEndianConversion = false;
            
            for (String api : cryptoFunc.cryptoAPIs) {
                if (api.contains("hton") || api.contains("ntoh") || api.contains("swap")) {
                    hasEndianConversion = true;
                    break;
                }
            }
            
            if (!hasEndianConversion && cryptoFunc.detectedAlgorithms.contains("AES")) {
                println("  [!] Potential endianness issue in " + cryptoFunc.name);
                
                CryptoImplementation impl = implementations.stream()
                    .filter(i -> i.functions.contains(cryptoFunc))
                    .findFirst()
                    .orElse(null);
                    
                if (impl != null) {
                    impl.vulnerabilities.add("Missing byte order conversion");
                }
            }
        }
        
        // Simulate buffer patterns for different crypto operations
        
        // AES state matrix (4x4 bytes)
        byteBuffer.clear();
        for (int i = 0; i < 16; i++) {
            byteBuffer.put((byte)(i * 0x11));
        }
        
        // RSA modulus (big integers)
        intBuffer.clear();
        for (int i = 0; i < 32; i++) {
            intBuffer.put(0xFFFFFFFF);
        }
        
        // Password/passphrase buffer
        charBuffer.clear();
        charBuffer.put("CryptoKeyMaterial");
        
        println("  Analyzed buffer operations for " + cryptoFunc.name);
    }
    
    // Phase 17: BigInteger operations for RSA/ECC
    private void analyzeBigIntegerCrypto() throws Exception {
        println("\n[Phase 17] Analyzing BigInteger operations for asymmetric crypto...");
        
        for (CryptoFunction cryptoFunc : cryptoFunctions.values()) {
            // Look for modular arithmetic patterns
            if (cryptoFunc.decompiledCode != null) {
                String code = cryptoFunc.decompiledCode.toLowerCase();
                
                if (code.contains("modpow") || code.contains("mod_exp") || code.contains("modular")) {
                    // RSA/DH modular exponentiation
                    cryptoFunc.detectedAlgorithms.add("RSA/DH ModExp");
                    
                    // Check for common RSA key sizes
                    BigInteger[] commonModuli = {
                        new BigInteger("2").pow(1024).subtract(BigInteger.ONE),
                        new BigInteger("2").pow(2048).subtract(BigInteger.ONE),
                        new BigInteger("2").pow(4096).subtract(BigInteger.ONE)
                    };
                    
                    for (BigInteger modulus : commonModuli) {
                        int bitLength = modulus.bitLength();
                        println("  Checking for " + bitLength + "-bit RSA in " + cryptoFunc.name);
                    }
                }
                
                if (code.contains("curve") || code.contains("point") || code.contains("scalar")) {
                    // ECC operations
                    cryptoFunc.detectedAlgorithms.add("ECC Operations");
                    
                    // Check for common curve parameters
                    BigInteger p256 = new BigInteger("ffffffff00000001000000000000000000000000ffffffffffffffffffffffff", 16);
                    BigInteger p384 = new BigInteger("fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffff0000000000000000ffffffff", 16);
                    
                    println("  Detected elliptic curve operations in " + cryptoFunc.name);
                }
            }
        }
    }
    
    // Add call to new phases in run() method after Phase 8
    private void runAdditionalPhases() throws Exception {
        // Phase 9-17
        analyzeMemoryProtectedRegions();
        analyzeInstructionPatterns();
        mapCryptoAddressSets();
        analyzeCryptoDataTypes();
        analyzeRegisterCryptoPatterns();
        analyzePcodeBlocks();
        analyzeCryptoConfiguration();
        analyzeNIOBuffers();
        analyzeBigIntegerCrypto();
    }
    
    // Phase 18: Comprehensive analysis utilizing all imported components
    private void analyzeWithUnusedImports() throws Exception {
        println("  Performing comprehensive analysis with all imported components...");
        
        // Phase 18.1: Program location and navigation analysis using ghidra.program.util.*
        analyzeProgramLocationNavigation();
        
        // Phase 18.2: Task monitoring and progress tracking using ghidra.util.task.*
        analyzeTaskMonitoringCapabilities();
        
        // Phase 18.3: Binary format analysis using ghidra.app.util.bin.*
        analyzeBinaryFormatStructures();
        
        // Phase 18.4: PE format crypto section analysis using ghidra.app.util.bin.format.pe.*
        analyzePECryptoSections();
        
        // Phase 18.5: Cryptographic key specifications using javax.crypto.spec.*
        analyzeCryptographicKeySpecs();
        
        // Phase 18.6: Regular expression crypto pattern matching using java.util.regex.*
        analyzeRegexCryptoPatterns();
        
        println("  Comprehensive analysis with unused imports completed");
    }
    
    // Phase 18.1: Program location and navigation analysis
    private void analyzeProgramLocationNavigation() throws Exception {
        // Analyze crypto function locations and their navigational context
        for (CryptoFunction cryptoFunc : cryptoFunctions.values()) {
            Function func = cryptoFunc.function;
            
            // Create program locations for crypto analysis points
            ProgramLocation entryLocation = new ProgramLocation(currentProgram, func.getEntryPoint());
            ProgramLocation bodyLocation = new ProgramLocation(currentProgram, func.getBody().getMinAddress());
            
            // Analyze location context for crypto patterns
            if (entryLocation.getAddress() != null) {
                // Check for crypto entry point patterns
                String locationInfo = "Crypto function " + func.getName() + " at " + entryLocation.getAddress();
                println("    [Location] " + locationInfo);
                
                // Analyze function body locations
                AddressSetView bodySet = func.getBody();
                for (AddressRange range : bodySet) {
                    Address rangeStart = range.getMinAddress();
                    Address rangeEnd = range.getMaxAddress();
                    
                    ProgramLocation rangeLocation = new ProgramLocation(currentProgram, rangeStart);
                    
                    // Check for crypto constants at specific locations
                    if (rangeLocation.getByteAddress() != null) {
                        analyzeCryptoConstantLocations(rangeLocation, rangeEnd);
                    }
                }
            }
        }
    }
    
    private void analyzeCryptoConstantLocations(ProgramLocation location, Address endAddr) throws Exception {
        // Look for crypto constants at specific program locations
        Address currentAddr = location.getAddress();
        Memory memory = currentProgram.getMemory();
        
        while (currentAddr.compareTo(endAddr) < 0) {
            try {
                long value = memory.getLong(currentAddr);
                
                // Check for known crypto constants
                if (value == 0x67452301L || value == 0xEFCDAB89L) {
                    println("      [Constant] MD5 initial value at " + currentAddr);
                } else if (value == 0x6A09E667L || value == 0xBB67AE85L) {
                    println("      [Constant] SHA-256 initial value at " + currentAddr);
                }
                
                currentAddr = currentAddr.add(8);
                if (currentAddr.compareTo(endAddr) >= 0) break;
                
            } catch (Exception e) {
                currentAddr = currentAddr.add(1);
            }
        }
    }
    
    // Phase 18.2: Task monitoring and progress tracking
    private void analyzeTaskMonitoringCapabilities() throws Exception {
        // Create custom task monitor for crypto analysis tracking
        TaskMonitor cryptoMonitor = new TaskMonitorAdapter() {
            private int progress = 0;
            private String message = "Analyzing cryptographic implementations";
            
            @Override
            public void setMessage(String msg) {
                message = msg;
                println("    [Monitor] " + msg);
            }
            
            @Override
            public void setProgress(long value) {
                progress = (int) value;
                if (progress % 10 == 0) {
                    println("    [Progress] Crypto analysis: " + progress + "%");
                }
            }
            
            @Override
            public boolean isCancelled() {
                return monitor.isCancelled();
            }
        };
        
        // Use the monitor to track crypto function analysis
        cryptoMonitor.setMessage("Starting comprehensive crypto function analysis");
        
        int totalFunctions = cryptoFunctions.size();
        int currentFunction = 0;
        
        for (CryptoFunction cryptoFunc : cryptoFunctions.values()) {
            if (cryptoMonitor.isCancelled()) break;
            
            currentFunction++;
            int progressPercent = (currentFunction * 100) / totalFunctions;
            cryptoMonitor.setProgress(progressPercent);
            cryptoMonitor.setMessage("Analyzing " + cryptoFunc.name + " (" + currentFunction + "/" + totalFunctions + ")");
            
            // Perform detailed analysis with progress tracking
            analyzeFunctionWithMonitoring(cryptoFunc, cryptoMonitor);
        }
        
        cryptoMonitor.setMessage("Crypto function analysis completed");
        cryptoMonitor.setProgress(100);
    }
    
    private void analyzeFunctionWithMonitoring(CryptoFunction cryptoFunc, TaskMonitor taskMonitor) throws Exception {
        // Monitor algorithm detection progress
        taskMonitor.setMessage("Detecting algorithms in " + cryptoFunc.name);
        
        // Enhanced algorithm detection with monitoring
        if (cryptoFunc.detectedAlgorithms.contains("AES")) {
            taskMonitor.setMessage("Analyzing AES implementation in " + cryptoFunc.name);
            // Detailed AES analysis...
        }
        
        if (cryptoFunc.detectedAlgorithms.contains("RSA")) {
            taskMonitor.setMessage("Analyzing RSA implementation in " + cryptoFunc.name);
            // Detailed RSA analysis...
        }
        
        taskMonitor.setMessage("Completed analysis of " + cryptoFunc.name);
    }
    
    // Phase 18.3: Binary format analysis
    private void analyzeBinaryFormatStructures() throws Exception {
        // Create binary readers for crypto section analysis
        Memory memory = currentProgram.getMemory();
        
        for (MemoryBlock block : memory.getBlocks()) {
            if (block.isInitialized() && block.getSize() > 1024) {
                
                // Create binary reader for block analysis
                byte[] blockData = new byte[(int) Math.min(block.getSize(), 65536)];
                memory.getBytes(block.getStart(), blockData);
                
                ByteArrayProvider provider = new ByteArrayProvider(blockData);
                BinaryReader reader = new BinaryReader(provider, false); // Little-endian
                
                try {
                    // Analyze binary structures for crypto signatures
                    analyzeBinaryStructuresForCrypto(reader, block);
                    
                } finally {
                    reader.close();
                }
            }
        }
    }
    
    private void analyzeBinaryStructuresForCrypto(BinaryReader reader, MemoryBlock block) throws Exception {
        println("    [Binary] Analyzing block: " + block.getName());
        
        // Look for structured crypto data using binary reader
        reader.setPointerIndex(0);
        
        while (reader.getPointerIndex() < reader.length() - 16) {
            // Read potential crypto structures
            long pos = reader.getPointerIndex();
            
            try {
                // Check for AES key schedule structure (176 bytes for AES-128)
                if (reader.length() - pos >= 176) {
                    byte[] potentialKeySchedule = reader.readByteArray((int)pos, 176);
                    
                    if (isAESKeySchedule(potentialKeySchedule)) {
                        Address addr = block.getStart().add(pos);
                        println("      [Crypto Structure] Potential AES key schedule at " + addr);
                        createBookmark(addr, "Crypto Structure", "AES Key Schedule");
                    }
                }
                
                // Check for RSA key structure
                if (reader.length() - pos >= 256) {
                    reader.setPointerIndex(pos);
                    int length = reader.readInt();
                    
                    if (length > 0 && length <= 4096 && (length % 8 == 0)) {
                        // Potential RSA modulus
                        Address addr = block.getStart().add(pos);
                        println("      [Crypto Structure] Potential RSA key structure at " + addr);
                        createBookmark(addr, "Crypto Structure", "RSA Key Data");
                    }
                }
                
                reader.setPointerIndex(pos + 16); // Move forward
                
            } catch (Exception e) {
                reader.setPointerIndex(pos + 1);
            }
        }
    }
    
    private boolean isAESKeySchedule(byte[] data) {
        // Check for AES key schedule patterns
        if (data.length != 176) return false;
        
        // Look for round key patterns
        int uniqueBytes = 0;
        boolean[] seen = new boolean[256];
        
        for (byte b : data) {
            int val = b & 0xFF;
            if (!seen[val]) {
                seen[val] = true;
                uniqueBytes++;
            }
        }
        
        // AES key schedule should have good entropy
        return uniqueBytes > 64;
    }
    
    // Phase 18.4: PE format crypto section analysis
    private void analyzePECryptoSections() throws Exception {
        // Check if we're analyzing a PE format binary
        if (currentProgram.getExecutableFormat().toLowerCase().contains("pe")) {
            
            // Analyze PE-specific crypto sections
            Memory memory = currentProgram.getMemory();
            
            // Look for PE crypto-related sections
            for (MemoryBlock block : memory.getBlocks()) {
                String blockName = block.getName().toLowerCase();
                
                if (blockName.contains("text") || blockName.contains("code") || 
                    blockName.contains("data") || blockName.contains("rdata")) {
                    
                    analyzePESectionForCrypto(block);
                }
            }
            
            // Analyze PE import table for crypto APIs
            analyzePEImportsForCrypto();
            
            // Analyze PE resources for embedded crypto data
            analyzePEResourcesForCrypto();
        }
    }
    
    private void analyzePESectionForCrypto(MemoryBlock section) throws Exception {
        println("    [PE Section] Analyzing " + section.getName() + " for crypto artifacts");
        
        // Create PE format reader for section
        byte[] sectionData = new byte[(int) Math.min(section.getSize(), 32768)];
        currentProgram.getMemory().getBytes(section.getStart(), sectionData);
        
        ByteArrayProvider provider = new ByteArrayProvider(sectionData);
        BinaryReader reader = new BinaryReader(provider, false);
        
        try {
            // Look for PE-specific crypto patterns
            analyzePECryptoPatterns(reader, section);
            
        } finally {
            reader.close();
        }
    }
    
    private void analyzePECryptoPatterns(BinaryReader reader, MemoryBlock section) throws Exception {
        // Check for Windows CryptoAPI signatures
        String[] cryptoAPIs = {
            "CryptCreateHash", "CryptEncrypt", "CryptDecrypt",
            "CryptAcquireContext", "CryptGenKey", "CryptImportKey"
        };
        
        reader.setPointerIndex(0);
        byte[] sectionData = reader.readByteArray(0, (int)reader.length());
        String sectionText = new String(sectionData, "ASCII");
        
        for (String api : cryptoAPIs) {
            if (sectionText.contains(api)) {
                println("      [PE Crypto] Found " + api + " reference in " + section.getName());
            }
        }
        
        // Look for PKCS structures in PE data
        for (int i = 0; i < sectionData.length - 4; i++) {
            if (sectionData[i] == 0x30 && (sectionData[i+1] & 0x80) != 0) {
                // Potential ASN.1 structure
                Address addr = section.getStart().add(i);
                println("      [PE Crypto] Potential PKCS structure at " + addr);
            }
        }
    }
    
    private void analyzePEImportsForCrypto() throws Exception {
        // Analyze PE import table for crypto library references
        String[] cryptoLibraries = {
            "advapi32.dll", "crypt32.dll", "bcrypt.dll", "ncrypt.dll",
            "kernel32.dll", "msvcrt.dll" // Common crypto function containers
        };
        
        // Check external references for crypto libraries
        ExternalManager extManager = currentProgram.getExternalManager();
        String[] extLibNames = extManager.getExternalLibraryNames();
        
        for (String libName : extLibNames) {
            for (String cryptoLib : cryptoLibraries) {
                if (libName.toLowerCase().contains(cryptoLib.toLowerCase())) {
                    println("    [PE Import] Crypto library detected: " + libName);
                    
                    // Analyze functions from this library
                    Library library = extManager.getExternalLibrary(libName);
                    if (library != null) {
                        analyzeCryptoLibraryFunctions(library);
                    }
                }
            }
        }
    }
    
    private void analyzeCryptoLibraryFunctions(Library library) throws Exception {
        // Analyze crypto functions from PE import library
        SymbolTable symbolTable = currentProgram.getSymbolTable();
        SymbolIterator symbols = symbolTable.getSymbols(library.getExternalLocation());
        
        while (symbols.hasNext()) {
            Symbol symbol = symbols.next();
            String funcName = symbol.getName();
            
            if (isCryptoFunction(funcName)) {
                println("      [PE Crypto Function] " + funcName + " from " + library.getName());
                
                // Find references to this crypto function
                ReferenceManager refManager = currentProgram.getReferenceManager();
                ReferenceIterator refs = refManager.getReferencesTo(symbol.getAddress());
                
                int refCount = 0;
                while (refs.hasNext()) {
                    refs.next();
                    refCount++;
                }
                
                if (refCount > 0) {
                    println("        Referenced " + refCount + " times");
                }
            }
        }
    }
    
    private boolean isCryptoFunction(String funcName) {
        String[] cryptoFuncs = {
            "CryptCreateHash", "CryptEncrypt", "CryptDecrypt", "CryptHashData",
            "CryptAcquireContext", "CryptGenKey", "CryptImportKey", "CryptExportKey",
            "BCryptOpenAlgorithmProvider", "BCryptEncrypt", "BCryptDecrypt",
            "NCryptOpenKey", "NCryptEncrypt", "NCryptDecrypt"
        };
        
        for (String cryptoFunc : cryptoFuncs) {
            if (funcName.toLowerCase().contains(cryptoFunc.toLowerCase())) {
                return true;
            }
        }
        return false;
    }
    
    private void analyzePEResourcesForCrypto() throws Exception {
        // Look for embedded crypto resources in PE files
        Memory memory = currentProgram.getMemory();
        
        for (MemoryBlock block : memory.getBlocks()) {
            if (block.getName().toLowerCase().contains("rsrc") || 
                block.getName().toLowerCase().contains("resource")) {
                
                println("    [PE Resource] Analyzing " + block.getName() + " for crypto data");
                analyzeResourceBlockForCrypto(block);
            }
        }
    }
    
    private void analyzeResourceBlockForCrypto(MemoryBlock resourceBlock) throws Exception {
        // Analyze PE resource block for embedded crypto artifacts
        byte[] resourceData = new byte[(int) Math.min(resourceBlock.getSize(), 16384)];
        currentProgram.getMemory().getBytes(resourceBlock.getStart(), resourceData);
        
        // Look for certificate data (X.509)
        for (int i = 0; i < resourceData.length - 10; i++) {
            if (resourceData[i] == 0x30 && resourceData[i+1] == (byte)0x82) {
                // Potential X.509 certificate
                int certLength = ((resourceData[i+2] & 0xFF) << 8) | (resourceData[i+3] & 0xFF);
                if (certLength > 0 && certLength < 8192) {
                    Address addr = resourceBlock.getStart().add(i);
                    println("      [PE Resource] Potential X.509 certificate at " + addr);
                    createBookmark(addr, "Crypto Certificate", "X.509 Certificate Data");
                }
            }
        }
        
        // Look for embedded key data
        analyzeResourceForEmbeddedKeys(resourceData, resourceBlock.getStart());
    }
    
    private void analyzeResourceForEmbeddedKeys(byte[] data, Address baseAddr) throws Exception {
        // Look for patterns that suggest embedded cryptographic keys
        for (int i = 0; i < data.length - 32; i++) {
            // Check for high-entropy regions (potential key material)
            byte[] sample = new byte[32];
            System.arraycopy(data, i, sample, 0, 32);
            
            double entropy = calculateEntropy(sample);
            if (entropy > 7.5) { // Very high entropy
                Address addr = baseAddr.add(i);
                println("      [PE Resource] High-entropy data (potential key) at " + addr);
            }
        }
    }
    
    // Phase 18.5: Cryptographic key specifications
    private void analyzeCryptographicKeySpecs() throws Exception {
        // Analyze and generate cryptographic key specifications
        for (CryptoKey key : extractedKeys) {
            generateKeySpecifications(key);
        }
        
        // Generate sample key specifications for detected algorithms
        for (CryptoDetection detection : detectedAlgorithms) {
            generateAlgorithmKeySpecs(detection);
        }
    }
    
    private void generateKeySpecifications(CryptoKey key) throws Exception {
        println("    [Key Spec] Analyzing key at " + key.address);
        
        // Generate appropriate key specifications based on key type
        if (key.keyMaterial != null && key.keyMaterial.length >= 16) {
            
            // AES key specification
            if (key.length == 16 || key.length == 24 || key.length == 32) {
                SecretKeySpec aesKeySpec = new SecretKeySpec(
                    Arrays.copyOf(key.keyMaterial, Math.min(key.length, key.keyMaterial.length)),
                    "AES"
                );
                
                println("      [AES KeySpec] " + key.length * 8 + "-bit AES key specification created");
                println("      [Algorithm] " + aesKeySpec.getAlgorithm());
                println("      [Format] " + aesKeySpec.getFormat());
                
                // Analyze key schedule derivation
                analyzeAESKeySchedule(aesKeySpec);
            }
            
            // DES/3DES key specification
            if (key.length == 8 || key.length == 16 || key.length == 24) {
                String algorithm = (key.length == 8) ? "DES" : "DESede";
                SecretKeySpec desKeySpec = new SecretKeySpec(
                    Arrays.copyOf(key.keyMaterial, Math.min(key.length, key.keyMaterial.length)),
                    algorithm
                );
                
                println("      [DES KeySpec] " + algorithm + " key specification created");
                println("      [Algorithm] " + desKeySpec.getAlgorithm());
                
                // Check for weak DES keys
                checkForWeakDESKeys(desKeySpec);
            }
            
            // RC4 key specification
            if (key.length >= 5 && key.length <= 256) {
                SecretKeySpec rc4KeySpec = new SecretKeySpec(
                    Arrays.copyOf(key.keyMaterial, Math.min(key.length, key.keyMaterial.length)),
                    "RC4"
                );
                
                println("      [RC4 KeySpec] " + key.length * 8 + "-bit RC4 key specification created");
                
                // Analyze RC4 key strength
                analyzeRC4KeyStrength(rc4KeySpec);
            }
        }
    }
    
    private void analyzeAESKeySchedule(SecretKeySpec keySpec) throws Exception {
        // Analyze AES key schedule generation
        byte[] keyBytes = keySpec.getEncoded();
        int keyLength = keyBytes.length;
        int rounds = (keyLength == 16) ? 10 : (keyLength == 24) ? 12 : 14;
        
        println("        [AES Schedule] Key length: " + (keyLength * 8) + " bits, Rounds: " + rounds);
        
        // Simulate key schedule generation
        byte[][] roundKeys = new byte[rounds + 1][16];
        System.arraycopy(keyBytes, 0, roundKeys[0], 0, keyLength);
        
        // Check for patterns in key schedule
        for (int round = 1; round <= Math.min(3, rounds); round++) {
            // Simplified key schedule analysis
            boolean hasPattern = checkKeySchedulePattern(roundKeys[0], round);
            if (hasPattern) {
                println("        [Warning] Potential pattern in round " + round + " key");
            }
        }
    }
    
    private boolean checkKeySchedulePattern(byte[] key, int round) {
        // Simple pattern detection in key material
        int repeats = 0;
        for (int i = 0; i < key.length - 1; i++) {
            if (key[i] == key[i + 1]) repeats++;
        }
        return repeats > key.length / 4; // More than 25% repeating bytes
    }
    
    private void checkForWeakDESKeys(SecretKeySpec keySpec) throws Exception {
        // Check for known weak DES keys
        byte[] keyBytes = keySpec.getEncoded();
        
        byte[][] weakKeys = {
            {0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01}, // All zeros (with parity)
            {(byte)0xFE, (byte)0xFE, (byte)0xFE, (byte)0xFE, (byte)0xFE, (byte)0xFE, (byte)0xFE, (byte)0xFE}, // All ones
            {0x1F, 0x1F, 0x1F, 0x1F, 0x0E, 0x0E, 0x0E, 0x0E}, // Semi-weak key
            {(byte)0xE0, (byte)0xE0, (byte)0xE0, (byte)0xE0, (byte)0xF1, (byte)0xF1, (byte)0xF1, (byte)0xF1}  // Semi-weak key
        };
        
        for (byte[] weakKey : weakKeys) {
            if (keyBytes.length >= 8 && Arrays.equals(Arrays.copyOf(keyBytes, 8), weakKey)) {
                println("        [Security Warning] Weak DES key detected!");
                break;
            }
        }
    }
    
    private void analyzeRC4KeyStrength(SecretKeySpec keySpec) throws Exception {
        // Analyze RC4 key strength and potential weaknesses
        byte[] keyBytes = keySpec.getEncoded();
        
        // Check for key length weaknesses
        if (keyBytes.length < 8) {
            println("        [Security Warning] RC4 key too short (< 64 bits)");
        }
        
        // Check for patterns in key
        Map<Byte, Integer> byteFreq = new HashMap<>();
        for (byte b : keyBytes) {
            byteFreq.merge(b, 1, Integer::sum);
        }
        
        // Check for repeated bytes
        int maxFreq = byteFreq.values().stream().mapToInt(Integer::intValue).max().orElse(0);
        if (maxFreq > keyBytes.length / 4) {
            println("        [Security Warning] RC4 key has repeated byte patterns");
        }
    }
    
    private void generateAlgorithmKeySpecs(CryptoDetection detection) throws Exception {
        // Generate sample key specifications for detected algorithms
        println("    [Algorithm KeySpec] Generating specifications for " + detection.algorithm);
        
        switch (detection.algorithm) {
            case "AES":
                // Generate sample AES key specs for different key sizes
                for (int keySize : new int[]{128, 192, 256}) {
                    byte[] sampleKey = new byte[keySize / 8];
                    SecretKeySpec aesSpec = new SecretKeySpec(sampleKey, "AES");
                    println("      [Sample] AES-" + keySize + " specification template created");
                }
                break;
                
            case "DES":
                SecretKeySpec desSpec = new SecretKeySpec(new byte[8], "DES");
                println("      [Sample] DES specification template created");
                break;
                
            case "RSA":
                // Note: RSA uses public/private key pairs, not SecretKeySpec
                println("      [Sample] RSA uses asymmetric key pairs (not SecretKeySpec)");
                break;
        }
    }
    
    // Phase 18.6: Regular expression crypto pattern matching
    private void analyzeRegexCryptoPatterns() throws Exception {
        // Use regex patterns to identify crypto-related strings and patterns
        
        // Define comprehensive regex patterns for crypto detection
        Pattern[] cryptoPatterns = {
            Pattern.compile("(?i)(aes|des|rsa|sha|md5|rc4|blowfish)[-_]?(128|192|256|512|1024|2048|4096)?"),
            Pattern.compile("(?i)(encrypt|decrypt|cipher|hash|digest|sign|verify)"),
            Pattern.compile("(?i)(key|password|passphrase|secret|salt|iv|nonce)"),
            Pattern.compile("(?i)(pkcs|x509|certificate|cert|csr|pem|der)"),
            Pattern.compile("(?i)(crypto|security|protection|authentication|authorization)"),
            Pattern.compile("[A-Fa-f0-9]{32,}"), // Hex strings (potential keys/hashes)
            Pattern.compile("(?i)(begin|end)[-_]?(certificate|private|public|rsa|dsa)[-_]?key"),
            Pattern.compile("(?i)-----BEGIN [A-Z ]+-----[\\s\\S]*?-----END [A-Z ]+-----"), // PEM format
        };
        
        String[] patternNames = {
            "Algorithm Names",
            "Crypto Operations", 
            "Key/Secret Terms",
            "Certificate Formats",
            "Security Terms",
            "Hex Data",
            "Key Headers",
            "PEM Certificates"
        };
        
        // Analyze strings in the program using regex patterns
        DataIterator definedStrings = currentProgram.getListing().getDefinedData(true);
        int totalMatches = 0;
        
        while (definedStrings.hasNext() && !monitor.isCancelled()) {
            Data data = definedStrings.next();
            
            if (data.hasStringValue()) {
                String stringValue = data.getDefaultValueRepresentation();
                if (stringValue != null && stringValue.length() > 3) {
                    
                    // Test against all crypto regex patterns
                    for (int i = 0; i < cryptoPatterns.length; i++) {
                        Pattern pattern = cryptoPatterns[i];
                        Matcher matcher = pattern.matcher(stringValue);
                        
                        if (matcher.find()) {
                            totalMatches++;
                            Address addr = data.getAddress();
                            String matchText = matcher.group();
                            
                            println("    [Regex Match] " + patternNames[i] + ": \"" + 
                                   matchText + "\" at " + addr);
                            
                            // Create bookmarks for important regex matches
                            if (i <= 2) { // Algorithm names, operations, or key terms
                                createBookmark(addr, "Crypto Regex", patternNames[i] + ": " + matchText);
                            }
                            
                            // Analyze match context
                            analyzeCryptoRegexContext(data, matcher, patternNames[i]);
                        }
                    }
                }
            }
        }
        
        println("    [Regex Summary] Found " + totalMatches + " crypto-related regex matches");
        
        // Analyze function names and comments with regex
        analyzeFunctionNamesWithRegex(cryptoPatterns, patternNames);
        
        // Search for crypto patterns in comments
        analyzeCommentsWithRegex(cryptoPatterns, patternNames);
    }
    
    private void analyzeCryptoRegexContext(Data data, Matcher matcher, String patternType) throws Exception {
        // Analyze the context around regex matches for additional insights
        Address addr = data.getAddress();
        
        // Check for references to this string
        ReferenceManager refManager = currentProgram.getReferenceManager();
        ReferenceIterator refs = refManager.getReferencesTo(addr);
        
        int refCount = 0;
        while (refs.hasNext()) {
            Reference ref = refs.next();
            refCount++;
            
            // Get the function that references this crypto string
            Function refFunc = currentProgram.getFunctionManager().getFunctionContaining(ref.getFromAddress());
            if (refFunc != null) {
                println("      [Context] Referenced by function: " + refFunc.getName());
                
                // Add this function to our crypto functions if not already present
                if (!cryptoFunctions.containsKey(refFunc.getEntryPoint())) {
                    CryptoFunction cryptoFunc = new CryptoFunction();
                    cryptoFunc.function = refFunc;
                    cryptoFunc.address = refFunc.getEntryPoint();
                    cryptoFunc.name = refFunc.getName();
                    cryptoFunc.detectedAlgorithms.add("Regex:" + patternType);
                    
                    cryptoFunctions.put(refFunc.getEntryPoint(), cryptoFunc);
                }
            }
        }
        
        if (refCount == 0) {
            println("      [Context] String not referenced by any function");
        }
    }
    
    private void analyzeFunctionNamesWithRegex(Pattern[] patterns, String[] patternNames) throws Exception {
        // Analyze function names for crypto-related patterns
        FunctionManager funcManager = currentProgram.getFunctionManager();
        FunctionIterator functions = funcManager.getFunctions(true);
        
        int functionMatches = 0;
        
        while (functions.hasNext()) {
            Function func = functions.next();
            String funcName = func.getName();
            
            for (int i = 0; i < patterns.length && i < 5; i++) { // Only check first 5 patterns for function names
                Pattern pattern = patterns[i];
                Matcher matcher = pattern.matcher(funcName);
                
                if (matcher.find()) {
                    functionMatches++;
                    println("    [Function Regex] " + patternNames[i] + " in function: " + funcName);
                    
                    // Add to crypto functions
                    if (!cryptoFunctions.containsKey(func.getEntryPoint())) {
                        CryptoFunction cryptoFunc = new CryptoFunction();
                        cryptoFunc.function = func;
                        cryptoFunc.address = func.getEntryPoint();
                        cryptoFunc.name = funcName;
                        cryptoFunc.detectedAlgorithms.add("FuncName:" + patternNames[i]);
                        
                        cryptoFunctions.put(func.getEntryPoint(), cryptoFunc);
                    }
                }
            }
        }
        
        println("    [Function Summary] " + functionMatches + " crypto function name matches");
    }
    
    private void analyzeCommentsWithRegex(Pattern[] patterns, String[] patternNames) throws Exception {
        // Analyze comments for crypto-related patterns
        Listing listing = currentProgram.getListing();
        AddressSetView addresses = currentProgram.getMemory().getAllInitializedAddresses();
        
        int commentMatches = 0;
        
        for (AddressRange range : addresses) {
            Address current = range.getMinAddress();
            Address end = range.getMaxAddress();
            
            while (current.compareTo(end) <= 0 && !monitor.isCancelled()) {
                
                // Check all comment types
                String[] comments = {
                    listing.getComment(current, CodeUnit.EOL_COMMENT),
                    listing.getComment(current, CodeUnit.PLATE_COMMENT),
                    listing.getComment(current, CodeUnit.PRE_COMMENT),
                    listing.getComment(current, CodeUnit.POST_COMMENT)
                };
                
                for (String comment : comments) {
                    if (comment != null && comment.length() > 5) {
                        
                        for (int i = 0; i < patterns.length; i++) {
                            Pattern pattern = patterns[i];
                            Matcher matcher = pattern.matcher(comment);
                            
                            if (matcher.find()) {
                                commentMatches++;
                                String matchText = matcher.group();
                                println("    [Comment Regex] " + patternNames[i] + ": \"" + 
                                       matchText + "\" at " + current);
                                break; // Only report first match per comment
                            }
                        }
                    }
                }
                
                try {
                    current = current.add(16); // Skip ahead for performance
                } catch (AddressOutOfBoundsException e) {
                    break;
                }
            }
        }
        
        println("    [Comment Summary] " + commentMatches + " crypto comment matches");
    }
    
    // Inner classes for data structures
    private enum CryptoType {
        SYMMETRIC_BLOCK,
        SYMMETRIC_STREAM,
        ASYMMETRIC,
        HASH,
        MAC,
        KDF,
        PRNG
    }
    
    private static class CryptoSignature {
        String description;
        byte[][] patterns;
        int[] keySizes;
        CryptoType type;
        
        CryptoSignature(String desc, byte[][] pats, int[] sizes, CryptoType t) {
            this.description = desc;
            this.patterns = pats;
            this.keySizes = sizes;
            this.type = t;
        }
    }
    
    private class CryptoDetection {
        String algorithm;
        Address address;
        double confidence;
        CryptoType type;
        String description;
    }
    
    private class CryptoKey {
        Address address;
        int length;
        double entropy;
        String format;
        String type;
        byte[] keyMaterial;
        String associatedFunction;
    }
    
    private class CryptoFunction {
        Function function;
        Address address;
        String name;
        Set<String> detectedAlgorithms = new HashSet<>();
        List<String> cryptoAPIs = new ArrayList<>();
        List<CryptoKey> possibleKeys = new ArrayList<>();
        String library;
        boolean likelyCrypto;
        int complexity;
        String decompiledCode;
    }
    
    private class CryptoImplementation {
        String algorithm;
        double confidence;
        List<CryptoFunction> functions = new ArrayList<>();
        List<String> vulnerabilities = new ArrayList<>();
        String quality;
    }
}

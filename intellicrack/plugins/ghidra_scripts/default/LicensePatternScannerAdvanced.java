/**
 * Advanced License Pattern Scanner
 *
 * Comprehensive license detection using binary patterns, string deobfuscation,
 * cross-reference analysis, algorithm identification, and entropy analysis.
 *
 * @author Intellicrack Team
 * @category License Analysis
 * @version 2.0
 */

import ghidra.app.script.GhidraScript;
import ghidra.program.model.mem.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.pcode.*;
import ghidra.program.model.symbol.*;
import ghidra.program.model.address.*;
import ghidra.program.model.data.*;
import ghidra.program.model.scalar.*;
import ghidra.util.task.TaskMonitor;
import ghidra.app.decompiler.*;
import ghidra.app.util.bin.format.pe.*;
import ghidra.program.model.lang.*;
import ghidra.program.util.*;

import java.util.*;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import javax.xml.bind.DatatypeConverter;

public class LicensePatternScannerAdvanced extends GhidraScript {

    // Binary patterns for common license formats
    private static final Map<String, byte[]> BINARY_PATTERNS = new HashMap<>();
    static {
        // FlexLM license format
        BINARY_PATTERNS.put("FlexLM", hexToBytes("464C45584C4D2D"));
        // HASP envelope
        BINARY_PATTERNS.put("HASP", hexToBytes("48415350"));
        // Sentinel license
        BINARY_PATTERNS.put("Sentinel", hexToBytes("53454E54494E454C"));
        // Custom license headers
        BINARY_PATTERNS.put("LicenseHeader1", hexToBytes("4C49430100"));
        BINARY_PATTERNS.put("LicenseHeader2", hexToBytes("4C4B455900"));
    }

    // Common obfuscation keys
    private static final int[] XOR_KEYS = {
        0x00, 0xFF, 0xAA, 0x55, 0x12, 0x34, 0x56, 0x78,
        0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE, 0xBA, 0xBE
    };

    // License-related function signatures
    private static final String[] LICENSE_SIGNATURES = {
        "bool __cdecl verify_license",
        "int __stdcall CheckLicense",
        "BOOL __fastcall ValidateLicense",
        "long __thiscall CLicense::Validate",
        "int64 __usercall check_activation"
    };

    // Results storage
    private List<LicenseLocation> licenseLocations = new ArrayList<>();
    private Map<Address, String> deobfuscatedStrings = new HashMap<>();
    private Set<Address> keyValidationFunctions = new HashSet<>();
    private Map<Address, Double> entropyMap = new HashMap<>();

    @Override
    public void run() throws Exception {
        println("=== Advanced License Pattern Scanner ===\n");

        // Phase 1: Binary pattern detection
        println("Phase 1: Scanning for binary license patterns...");
        scanBinaryPatterns();

        // Phase 2: String deobfuscation
        println("\nPhase 2: Deobfuscating strings...");
        deobfuscateStrings();

        // Phase 3: Cross-reference analysis
        println("\nPhase 3: Analyzing cross-references...");
        analyzeCrossReferences();

        // Phase 4: Algorithm identification
        println("\nPhase 4: Identifying license algorithms...");
        identifyLicenseAlgorithms();

        // Phase 5: Entropy analysis
        println("\nPhase 5: Performing entropy analysis...");
        performEntropyAnalysis();

        // Phase 6: Key extraction
        println("\nPhase 6: Extracting embedded keys/certificates...");
        extractEmbeddedKeys();

        // Generate report
        generateReport();
    }

    private void scanBinaryPatterns() throws Exception {
        Memory memory = currentProgram.getMemory();

        for (Map.Entry<String, byte[]> entry : BINARY_PATTERNS.entrySet()) {
            String patternName = entry.getKey();
            byte[] pattern = entry.getValue();

            Address start = currentProgram.getMinAddress();
            while (start != null && !monitor.isCancelled()) {
                Address found = memory.findBytes(start, pattern, null, true, monitor);
                if (found != null) {
                    println("  [+] Found " + patternName + " pattern at " + found);
                    createBookmark(found, "License", patternName + " binary pattern");

                    // Analyze surrounding area
                    analyzeLicenseStructure(found, patternName);

                    start = found.add(1);
                } else {
                    break;
                }
            }
        }

        // Scan for YARA-like patterns
        scanYaraPatterns();
    }

    private void scanYaraPatterns() throws Exception {
        // License file signatures
        String[] yaraPatterns = {
            // Adobe license
            "{61 64 6F 62 65 3A 6C 69 63 65 6E 73 65 3A}",
            // Microsoft product key
            "{50 72 6F 64 75 63 74 4B 65 79 3A [0-20] 2D [0-20] 2D}",
            // Generic serial pattern
            "{[0-9A-F]{4} 2D [0-9A-F]{4} 2D [0-9A-F]{4} 2D [0-9A-F]{4}}"
        };

        // This is simplified - real YARA engine would be more complex
        Memory memory = currentProgram.getMemory();
        MemoryBlock[] blocks = memory.getBlocks();

        for (MemoryBlock block : blocks) {
            if (!block.isInitialized()) continue;

            byte[] data = new byte[(int)Math.min(block.getSize(), 1024*1024)]; // Max 1MB
            block.getBytes(block.getStart(), data);

            // Check for patterns
            findSerialPatterns(data, block.getStart());
        }
    }

    private void findSerialPatterns(byte[] data, Address baseAddr) {
        // Look for XXXX-XXXX-XXXX patterns
        String dataStr = new String(data, StandardCharsets.US_ASCII);
        String regex = "[A-Z0-9]{4,5}-[A-Z0-9]{4,5}-[A-Z0-9]{4,5}";

        java.util.regex.Pattern pattern = java.util.regex.Pattern.compile(regex);
        java.util.regex.Matcher matcher = pattern.matcher(dataStr);

        while (matcher.find()) {
            int offset = matcher.start();
            Address addr = baseAddr.add(offset);
            String serial = matcher.group();

            println("  [+] Potential serial number at " + addr + ": " + serial);
            createBookmark(addr, "License", "Serial pattern: " + serial);

            licenseLocations.add(new LicenseLocation(addr, "Serial", serial));
        }
    }

    private void deobfuscateStrings() throws Exception {
        // Find all string references
        DataIterator dataIterator = currentProgram.getListing().getData(true);

        while (dataIterator.hasNext() && !monitor.isCancelled()) {
            Data data = dataIterator.next();

            if (data.hasStringValue()) {
                String str = data.getDefaultValueRepresentation();

                // Check if string might be obfuscated
                if (isLikelyObfuscated(str)) {
                    tryDeobfuscation(data.getAddress(), str);
                }
            }
        }

        // Also check undefined data areas
        scanUndefinedDataForStrings();
    }

    private boolean isLikelyObfuscated(String str) {
        // High entropy or non-printable characters
        int nonPrintable = 0;
        for (char c : str.toCharArray()) {
            if (c < 32 || c > 126) nonPrintable++;
        }

        return nonPrintable > str.length() / 4 || calculateEntropy(str.getBytes()) > 5.0;
    }

    private void tryDeobfuscation(Address addr, String obfuscated) throws Exception {
        byte[] bytes = obfuscated.getBytes();

        // Try XOR deobfuscation
        for (int key : XOR_KEYS) {
            byte[] deobfuscated = new byte[bytes.length];
            for (int i = 0; i < bytes.length; i++) {
                deobfuscated[i] = (byte)(bytes[i] ^ key);
            }

            String result = new String(deobfuscated, StandardCharsets.US_ASCII);
            if (isLicenseRelated(result) && isPrintable(result)) {
                println("  [+] Deobfuscated string at " + addr + " (XOR 0x" +
                       Integer.toHexString(key) + "): " + result);
                deobfuscatedStrings.put(addr, result);
                createBookmark(addr, "License", "Deobfuscated: " + result);
                break;
            }
        }

        // Try Base64 decoding
        try {
            byte[] decoded = Base64.getDecoder().decode(obfuscated);
            String result = new String(decoded, StandardCharsets.US_ASCII);
            if (isLicenseRelated(result) && isPrintable(result)) {
                println("  [+] Base64 decoded string at " + addr + ": " + result);
                deobfuscatedStrings.put(addr, result);
            }
        } catch (Exception e) {
            // Not Base64
        }

        // Try ROT13
        String rot13 = rot13Decode(obfuscated);
        if (isLicenseRelated(rot13)) {
            println("  [+] ROT13 decoded string at " + addr + ": " + rot13);
            deobfuscatedStrings.put(addr, rot13);
        }
    }

    private String rot13Decode(String input) {
        StringBuilder result = new StringBuilder();
        for (char c : input.toCharArray()) {
            if (c >= 'a' && c <= 'z') {
                c = (char)('a' + (c - 'a' + 13) % 26);
            } else if (c >= 'A' && c <= 'Z') {
                c = (char)('A' + (c - 'A' + 13) % 26);
            }
            result.append(c);
        }
        return result.toString();
    }

    private boolean isPrintable(String str) {
        for (char c : str.toCharArray()) {
            if (c < 32 || c > 126) return false;
        }
        return true;
    }

    private boolean isLicenseRelated(String str) {
        String lower = str.toLowerCase();
        String[] keywords = {
            "license", "serial", "key", "activation", "registration",
            "trial", "expire", "valid", "crack", "patch", "genuine"
        };

        for (String keyword : keywords) {
            if (lower.contains(keyword)) return true;
        }
        return false;
    }

    private void analyzeCrossReferences() throws Exception {
        // Find all functions that reference license-related strings
        Set<Function> candidateFunctions = new HashSet<>();

        // Check string references
        for (Map.Entry<Address, String> entry : deobfuscatedStrings.entrySet()) {
            Reference[] refs = getReferencesTo(entry.getKey());

            for (Reference ref : refs) {
                Function func = getFunctionContaining(ref.getFromAddress());
                if (func != null) {
                    candidateFunctions.add(func);
                }
            }
        }

        // Analyze candidate functions
        DecompileOptions options = new DecompileOptions();
        DecompInterface decompiler = new DecompInterface();
        decompiler.openProgram(currentProgram);

        for (Function func : candidateFunctions) {
            println("  [*] Analyzing function: " + func.getName() + " at " + func.getEntryPoint());

            // Decompile to analyze logic
            DecompileResults results = decompiler.decompileFunction(func, 30, monitor);
            if (results.decompileCompleted()) {
                analyzeFunctionLogic(func, results);
            }

            // Trace data flow
            traceDataFlow(func);
        }

        decompiler.closeProgram();
    }

    private void analyzeFunctionLogic(Function func, DecompileResults results) {
        ClangTokenGroup tokens = results.getCCodeMarkup();

        // Look for comparison operations
        Iterator<ClangNode> nodeIter = tokens.nodeIterator();
        while (nodeIter.hasNext()) {
            ClangNode node = nodeIter.next();

            if (node instanceof ClangOpToken) {
                ClangOpToken op = (ClangOpToken)node;
                String opStr = op.getText();

                if (opStr.equals("==") || opStr.equals("!=") || opStr.equals("strcmp")) {
                    // This might be a license check
                    println("    [+] Potential license check operation: " + opStr);
                    keyValidationFunctions.add(func.getEntryPoint());
                }
            }
        }
    }

    private void traceDataFlow(Function func) throws Exception {
        // Get all instructions in function
        InstructionIterator instrIter = currentProgram.getListing()
            .getInstructions(func.getBody(), true);

        Set<Register> trackedRegisters = new HashSet<>();
        Map<Address, String> constants = new HashMap<>();

        while (instrIter.hasNext() && !monitor.isCancelled()) {
            Instruction instr = instrIter.next();

            // Track MOV operations with constants
            if (instr.getMnemonicString().startsWith("MOV")) {
                Object[] opObjects = instr.getOpObjects(1);
                if (opObjects.length > 0 && opObjects[0] instanceof Scalar) {
                    Scalar scalar = (Scalar)opObjects[0];
                    long value = scalar.getUnsignedValue();

                    // Check if it looks like a license constant
                    if (isLicenseConstant(value)) {
                        constants.put(instr.getAddress(), "0x" + Long.toHexString(value));
                        println("    [+] License constant at " + instr.getAddress() +
                               ": 0x" + Long.toHexString(value));
                    }
                }
            }

            // Track CALL operations
            if (instr.getMnemonicString().equals("CALL")) {
                Reference[] refs = instr.getReferencesFrom();
                for (Reference ref : refs) {
                    Function calledFunc = getFunctionAt(ref.getToAddress());
                    if (calledFunc != null && isLicenseFunction(calledFunc)) {
                        println("    [+] Calls license function: " + calledFunc.getName());
                        keyValidationFunctions.add(func.getEntryPoint());
                    }
                }
            }
        }
    }

    private boolean isLicenseConstant(long value) {
        // Common magic numbers in license checks
        long[] magicNumbers = {
            0xDEADBEEF, 0xCAFEBABE, 0x12345678, 0x87654321,
            0xAAAAAAAA, 0x55555555, 0xFFFFFFFF, 0x00000000
        };

        for (long magic : magicNumbers) {
            if (value == magic) return true;
        }

        // Check if it's a date (common in expiration checks)
        if (value > 20000101 && value < 20991231) return true;

        return false;
    }

    private boolean isLicenseFunction(Function func) {
        String name = func.getName().toLowerCase();
        return name.contains("license") || name.contains("valid") ||
               name.contains("check") || name.contains("verify");
    }

    private void identifyLicenseAlgorithms() throws Exception {
        // Look for cryptographic operations
        InstructionIterator instrIter = currentProgram.getListing().getInstructions(true);

        Map<String, Integer> cryptoOps = new HashMap<>();

        while (instrIter.hasNext() && !monitor.isCancelled()) {
            Instruction instr = instrIter.next();
            String mnemonic = instr.getMnemonicString();

            // x86/x64 crypto instructions
            if (mnemonic.startsWith("AES") || mnemonic.startsWith("SHA") ||
                mnemonic.equals("PCLMULQDQ") || mnemonic.equals("CRC32")) {

                cryptoOps.put(mnemonic, cryptoOps.getOrDefault(mnemonic, 0) + 1);

                Function func = getFunctionContaining(instr.getAddress());
                if (func != null) {
                    println("  [+] Crypto instruction " + mnemonic + " in function " +
                           func.getName() + " at " + instr.getAddress());
                    createBookmark(instr.getAddress(), "Crypto", mnemonic + " instruction");
                }
            }

            // Look for rotate operations (common in hash functions)
            if (mnemonic.equals("ROL") || mnemonic.equals("ROR") ||
                mnemonic.equals("ROTL") || mnemonic.equals("ROTR")) {

                Function func = getFunctionContaining(instr.getAddress());
                if (func != null && func.getName().toLowerCase().contains("hash")) {
                    println("  [+] Hash operation in " + func.getName());
                }
            }
        }

        // Identify elliptic curve operations
        identifyEllipticCurveOps();

        // Identify RSA operations
        identifyRSAOperations();
    }

    private void identifyEllipticCurveOps() throws Exception {
        // Look for ECC curve parameters
        String[] eccCurves = {
            "secp256k1", "secp256r1", "secp384r1", "secp521r1",
            "curve25519", "ed25519"
        };

        for (String curve : eccCurves) {
            Address[] found = findBytes(currentProgram.getMinAddress(),
                                       curve.getBytes(), 100);
            for (Address addr : found) {
                println("  [+] Found ECC curve parameter: " + curve + " at " + addr);
                createBookmark(addr, "Crypto", "ECC curve: " + curve);
            }
        }
    }

    private void identifyRSAOperations() throws Exception {
        // Look for RSA key sizes (in bits)
        int[] rsaKeySizes = {1024, 2048, 3072, 4096};

        Memory memory = currentProgram.getMemory();

        for (int keySize : rsaKeySizes) {
            // Search for the key size as a 32-bit integer
            byte[] sizeBytes = intToBytes(keySize);
            Address start = currentProgram.getMinAddress();

            while (start != null) {
                Address found = memory.findBytes(start, sizeBytes, null, true, monitor);
                if (found != null) {
                    // Check if this might be part of an RSA structure
                    if (isLikelyRSAKeySize(found, keySize)) {
                        println("  [+] Potential RSA-" + keySize + " operation near " + found);
                        createBookmark(found, "Crypto", "RSA-" + keySize);
                    }
                    start = found.add(1);
                } else {
                    break;
                }
            }
        }
    }

    private boolean isLikelyRSAKeySize(Address addr, int keySize) throws Exception {
        // Check surrounding bytes for RSA-like patterns
        byte[] surrounding = new byte[32];
        currentProgram.getMemory().getBytes(addr.subtract(16), surrounding);

        // Look for big number operations nearby
        Function func = getFunctionContaining(addr);
        if (func != null) {
            String funcName = func.getName().toLowerCase();
            return funcName.contains("rsa") || funcName.contains("crypt") ||
                   funcName.contains("sign") || funcName.contains("verify");
        }

        return false;
    }

    private void performEntropyAnalysis() throws Exception {
        // Analyze entropy of data sections
        Memory memory = currentProgram.getMemory();
        MemoryBlock[] blocks = memory.getBlocks();

        for (MemoryBlock block : blocks) {
            if (!block.isInitialized() || block.isExecute()) continue;

            // Sample the block
            int sampleSize = (int)Math.min(block.getSize(), 4096);
            byte[] sample = new byte[sampleSize];
            block.getBytes(block.getStart(), sample);

            double entropy = calculateEntropy(sample);
            entropyMap.put(block.getStart(), entropy);

            if (entropy > 7.0) { // High entropy - possibly encrypted
                println("  [!] High entropy section: " + block.getName() +
                       " (entropy: " + String.format("%.2f", entropy) + ")");

                // Check for license data patterns
                analyzePotentialLicenseData(block, sample);
            }
        }
    }

    private double calculateEntropy(byte[] data) {
        if (data.length == 0) return 0.0;

        int[] frequency = new int[256];
        for (byte b : data) {
            frequency[b & 0xFF]++;
        }

        double entropy = 0.0;
        for (int count : frequency) {
            if (count > 0) {
                double probability = (double)count / data.length;
                entropy -= probability * (Math.log(probability) / Math.log(2));
            }
        }

        return entropy;
    }

    private void analyzePotentialLicenseData(MemoryBlock block, byte[] data) throws Exception {
        // Check for structured data that might be encrypted licenses

        // Look for repeating patterns (block cipher patterns)
        Map<String, Integer> patternCounts = new HashMap<>();
        int blockSize = 16; // AES block size

        for (int i = 0; i <= data.length - blockSize; i += blockSize) {
            byte[] blockData = Arrays.copyOfRange(data, i, i + blockSize);
            String pattern = DatatypeConverter.printHexBinary(blockData);
            patternCounts.put(pattern, patternCounts.getOrDefault(pattern, 0) + 1);
        }

        // If we see repeating blocks, might be ECB mode encryption
        for (Map.Entry<String, Integer> entry : patternCounts.entrySet()) {
            if (entry.getValue() > 2) {
                println("    [*] Repeating encrypted block detected (possible ECB mode)");
                createBookmark(block.getStart(), "License", "Possible encrypted license data");
                break;
            }
        }
    }

    private void extractEmbeddedKeys() throws Exception {
        // Look for embedded certificates (X.509)
        findX509Certificates();

        // Look for PGP keys
        findPGPKeys();

        // Look for hardcoded symmetric keys
        findSymmetricKeys();

        // Look for public key parameters
        findPublicKeyParams();
    }

    private void findX509Certificates() throws Exception {
        // X.509 certificate header: 30 82 (SEQUENCE)
        byte[] certHeader = hexToBytes("3082");

        Memory memory = currentProgram.getMemory();
        Address start = currentProgram.getMinAddress();

        while (start != null && !monitor.isCancelled()) {
            Address found = memory.findBytes(start, certHeader, null, true, monitor);
            if (found != null) {
                // Read next 2 bytes for length
                byte[] lengthBytes = new byte[2];
                memory.getBytes(found.add(2), lengthBytes);
                int certLength = ((lengthBytes[0] & 0xFF) << 8) | (lengthBytes[1] & 0xFF);

                if (certLength > 100 && certLength < 10000) { // Reasonable cert size
                    println("  [+] Potential X.509 certificate at " + found +
                           " (length: " + certLength + " bytes)");
                    createBookmark(found, "Certificate", "X.509 cert, " + certLength + " bytes");

                    // Extract certificate data
                    extractCertificateInfo(found, certLength);
                }

                start = found.add(1);
            } else {
                break;
            }
        }
    }

    private void extractCertificateInfo(Address addr, int length) throws Exception {
        // This would parse the X.509 structure
        // For now, just mark it
        licenseLocations.add(new LicenseLocation(addr, "X509Certificate",
                                                length + " bytes"));
    }

    private void findPGPKeys() throws Exception {
        String[] pgpHeaders = {
            "-----BEGIN PGP PUBLIC KEY BLOCK-----",
            "-----BEGIN PGP PRIVATE KEY BLOCK-----",
            "-----BEGIN PGP SIGNATURE-----"
        };

        for (String header : pgpHeaders) {
            Address[] found = findBytes(currentProgram.getMinAddress(),
                                       header.getBytes(), 10);
            for (Address addr : found) {
                println("  [+] Found PGP key at " + addr);
                createBookmark(addr, "Certificate", "PGP key block");
                licenseLocations.add(new LicenseLocation(addr, "PGPKey", header));
            }
        }
    }

    private void findSymmetricKeys() throws Exception {
        // Look for 128, 256-bit keys with high entropy
        Memory memory = currentProgram.getMemory();
        MemoryBlock[] blocks = memory.getBlocks();

        int[] keySizes = {16, 32}; // AES-128, AES-256

        for (MemoryBlock block : blocks) {
            if (!block.isInitialized() || block.isExecute()) continue;

            for (int keySize : keySizes) {
                Address addr = block.getStart();
                while (addr.compareTo(block.getEnd().subtract(keySize)) < 0) {
                    byte[] potential = new byte[keySize];
                    memory.getBytes(addr, potential);

                    double entropy = calculateEntropy(potential);
                    if (entropy > 7.5) { // Very high entropy
                        // Check if it's referenced by crypto functions
                        Reference[] refs = getReferencesTo(addr);
                        for (Reference ref : refs) {
                            Function func = getFunctionContaining(ref.getFromAddress());
                            if (func != null && isCryptoFunction(func)) {
                                println("  [+] Potential " + (keySize * 8) +
                                       "-bit symmetric key at " + addr);
                                createBookmark(addr, "Crypto",
                                             "Potential AES-" + (keySize * 8) + " key");
                                break;
                            }
                        }
                    }

                    addr = addr.add(keySize);
                }
            }
        }
    }

    private boolean isCryptoFunction(Function func) {
        String name = func.getName().toLowerCase();
        return name.contains("crypt") || name.contains("aes") ||
               name.contains("encrypt") || name.contains("decrypt") ||
               name.contains("cipher") || name.contains("hash");
    }

    private void findPublicKeyParams() throws Exception {
        // Look for common RSA public exponents
        long[] commonExponents = {3, 17, 65537};

        for (long exp : commonExponents) {
            byte[] expBytes = longToBytes(exp);
            Address[] found = findBytes(currentProgram.getMinAddress(), expBytes, 50);

            for (Address addr : found) {
                // Check if this might be part of an RSA public key
                Function func = getFunctionContaining(addr);
                if (func != null && isCryptoFunction(func)) {
                    println("  [+] RSA public exponent " + exp + " at " + addr);
                    createBookmark(addr, "Crypto", "RSA exponent: " + exp);
                }
            }
        }
    }

    private void scanUndefinedDataForStrings() throws Exception {
        AddressSetView undefined = currentProgram.getListing().getUndefinedRanges(
            currentProgram.getMemory().getExecuteSet(), false, monitor);

        if (undefined.isEmpty()) return;

        Memory memory = currentProgram.getMemory();

        for (AddressRange range : undefined) {
            Address start = range.getMinAddress();
            Address end = range.getMaxAddress();

            while (start.compareTo(end) < 0 && !monitor.isCancelled()) {
                // Try to read as string
                List<Byte> bytes = new ArrayList<>();
                Address current = start;

                while (current.compareTo(end) < 0) {
                    try {
                        byte b = memory.getByte(current);
                        if (b == 0) break; // Null terminator
                        if (b >= 32 && b <= 126) { // Printable
                            bytes.add(b);
                        } else {
                            break;
                        }
                        current = current.add(1);
                    } catch (Exception e) {
                        break;
                    }
                }

                if (bytes.size() >= 4) { // Minimum string length
                    byte[] strBytes = new byte[bytes.size()];
                    for (int i = 0; i < bytes.size(); i++) {
                        strBytes[i] = bytes.get(i);
                    }

                    String str = new String(strBytes, StandardCharsets.US_ASCII);
                    if (isLicenseRelated(str)) {
                        println("  [+] Found hidden string at " + start + ": " + str);
                        createBookmark(start, "License", "Hidden: " + str);
                        deobfuscatedStrings.put(start, str);
                    }
                }

                start = current.add(1);
            }
        }
    }

    private void generateReport() {
        println("\n=== License Pattern Analysis Report ===");

        println("\nBinary Patterns Found: " + licenseLocations.size());
        for (LicenseLocation loc : licenseLocations) {
            println("  - " + loc.type + " at " + loc.address + ": " + loc.description);
        }

        println("\nDeobfuscated Strings: " + deobfuscatedStrings.size());
        for (Map.Entry<Address, String> entry : deobfuscatedStrings.entrySet()) {
            println("  - " + entry.getKey() + ": " + entry.getValue());
        }

        println("\nKey Validation Functions: " + keyValidationFunctions.size());
        for (Address addr : keyValidationFunctions) {
            Function func = getFunctionAt(addr);
            if (func != null) {
                println("  - " + func.getName() + " at " + addr);
            }
        }

        println("\nHigh Entropy Sections:");
        for (Map.Entry<Address, Double> entry : entropyMap.entrySet()) {
            if (entry.getValue() > 7.0) {
                println("  - " + entry.getKey() + ": " +
                       String.format("%.2f", entry.getValue()) + " bits");
            }
        }

        println("\n[*] Analysis complete. Check bookmarks for detailed findings.");
    }

    // Helper methods
    private static byte[] hexToBytes(String hex) {
        hex = hex.replaceAll("\\s", "");
        int len = hex.length();
        byte[] data = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            data[i / 2] = (byte) ((Character.digit(hex.charAt(i), 16) << 4)
                                 + Character.digit(hex.charAt(i+1), 16));
        }
        return data;
    }

    private byte[] intToBytes(int value) {
        return new byte[] {
            (byte)(value & 0xFF),
            (byte)((value >> 8) & 0xFF),
            (byte)((value >> 16) & 0xFF),
            (byte)((value >> 24) & 0xFF)
        };
    }

    private byte[] longToBytes(long value) {
        return new byte[] {
            (byte)(value & 0xFF),
            (byte)((value >> 8) & 0xFF),
            (byte)((value >> 16) & 0xFF),
            (byte)((value >> 24) & 0xFF),
            (byte)((value >> 32) & 0xFF),
            (byte)((value >> 40) & 0xFF),
            (byte)((value >> 48) & 0xFF),
            (byte)((value >> 56) & 0xFF)
        };
    }

    // Data classes
    private static class LicenseLocation {
        Address address;
        String type;
        String description;

        LicenseLocation(Address addr, String type, String desc) {
            this.address = addr;
            this.type = type;
            this.description = desc;
        }
    }
}

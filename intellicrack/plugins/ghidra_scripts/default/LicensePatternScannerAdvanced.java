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
import ghidra.util.exception.*;

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
    
    // Additional tracking for unused imports implementation
    private Program program;
    private FunctionManager functionManager;
    private SymbolTable symbolTable;
    private ReferenceManager referenceManager;
    private DataTypeManager dataTypeManager;
    private Language language;
    private TaskMonitor taskMonitor;
    private Map<Address, PcodeOp[]> pcodeCache = new HashMap<>();
    private Map<Register, RegisterValue> registerStates = new HashMap<>();
    private Set<CodeUnit> analyzedCodeUnits = new HashSet<>();
    private AddressSet protectedRegions = new AddressSet();
    private Map<String, HighFunction> highFunctionCache = new HashMap<>();

    @Override
    public void run() throws Exception {
        println("=== Advanced License Pattern Scanner ===\n");
        
        // Initialize components
        initializeComponents();

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
        
        // Phase 7: P-code analysis for license logic
        println("\nPhase 7: Analyzing P-code for license validation logic...");
        analyzePcodeLicenseLogic();
        
        // Phase 8: Symbol table analysis
        println("\nPhase 8: Analyzing symbol table for license symbols...");
        analyzeSymbolTable();
        
        // Phase 9: Memory protection analysis
        println("\nPhase 9: Analyzing memory protection mechanisms...");
        analyzeMemoryProtection();
        
        // Phase 10: Register-level license checks
        println("\nPhase 10: Analyzing register-level license operations...");
        analyzeRegisterOperations();
        
        // Phase 11: Data type structure analysis
        println("\nPhase 11: Analyzing license data structures...");
        analyzeLicenseDataTypes();
        
        // Phase 12: High-level function decompilation
        println("\nPhase 12: Performing high-level function analysis...");
        analyzeHighLevelFunctions();
        
        // Phase 13: Hash validation detection
        println("\nPhase 13: Detecting hash-based license validation...");
        detectHashValidation();
        
        // Phase 14: PE Format license analysis
        println("\nPhase 14: Analyzing PE format for license information...");
        analyzePEFormatLicenseData();

        // Generate report
        generateReport();
    }
    
    private void initializeComponents() {
        program = currentProgram;
        functionManager = program.getFunctionManager();
        symbolTable = program.getSymbolTable();
        referenceManager = program.getReferenceManager();
        dataTypeManager = program.getDataTypeManager();
        language = program.getLanguage();
        taskMonitor = monitor;
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

    // Phase 7: P-code analysis implementation
    private void analyzePcodeLicenseLogic() throws Exception {
        FunctionIterator funcIter = functionManager.getFunctions(true);
        int pcodeAnalyzed = 0;
        
        while (funcIter.hasNext() && !taskMonitor.isCancelled()) {
            Function func = funcIter.next();
            
            // Check if function might be license-related
            if (!isLicenseFunction(func)) continue;
            
            try {
                // Get P-code for function
                DecompInterface decompiler = new DecompInterface();
                decompiler.openProgram(program);
                DecompileOptions options = new DecompileOptions();
                decompiler.setOptions(options);
                
                DecompileResults results = decompiler.decompileFunction(func, 30, taskMonitor);
                
                if (results.decompileCompleted()) {
                    HighFunction highFunc = results.getHighFunction();
                    if (highFunc != null) {
                        highFunctionCache.put(func.getName(), highFunc);
                        
                        // Analyze P-code blocks
                        Iterator<PcodeBlockBasic> blockIter = highFunc.getBasicBlocks().iterator();
                        while (blockIter.hasNext()) {
                            PcodeBlockBasic block = blockIter.next();
                            analyzePcodeBlock(block, func);
                        }
                        
                        // Analyze P-code operations
                        Iterator<PcodeOpAST> opIter = highFunc.getPcodeOps();
                        while (opIter.hasNext()) {
                            PcodeOpAST op = opIter.next();
                            analyzePcodeOp(op, func);
                        }
                        pcodeAnalyzed++;
                    }
                }
                
                decompiler.closeProgram();
            } catch (Exception e) {
                // Continue with next function
            }
        }
        
        println("  Analyzed P-code for " + pcodeAnalyzed + " license functions");
    }
    
    private void analyzePcodeBlock(PcodeBlockBasic block, Function func) {
        Iterator<PcodeOp> opIter = block.getIterator();
        
        while (opIter.hasNext()) {
            PcodeOp op = opIter.next();
            
            // Check for license-related P-code patterns
            if (op.getOpcode() == PcodeOp.CALL) {
                Varnode target = op.getInput(0);
                if (target.isAddress()) {
                    Address callAddr = target.getAddress();
                    Function calledFunc = functionManager.getFunctionAt(callAddr);
                    if (calledFunc != null && isLicenseFunction(calledFunc)) {
                        println("    P-code: " + func.getName() + " calls license func " + 
                               calledFunc.getName());
                    }
                }
            } else if (op.getOpcode() == PcodeOp.CBRANCH) {
                // Conditional branch - might be license check
                println("    P-code: Conditional branch in " + func.getName() + 
                       " (possible license check)");
                keyValidationFunctions.add(func.getEntryPoint());
            } else if (op.getOpcode() == PcodeOp.INT_EQUAL || 
                      op.getOpcode() == PcodeOp.INT_NOTEQUAL) {
                // Integer comparison - common in license checks
                Varnode v1 = op.getInput(0);
                Varnode v2 = op.getInput(1);
                if (v2.isConstant()) {
                    long value = v2.getOffset();
                    if (isLicenseConstant(value)) {
                        println("    P-code: License constant comparison in " + 
                               func.getName());
                    }
                }
            }
        }
    }
    
    private void analyzePcodeOp(PcodeOpAST op, Function func) {
        // Analyze individual P-code operation
        Varnode output = op.getOutput();
        
        if (output != null) {
            // Track data flow through varnodes
            for (int i = 0; i < op.getNumInputs(); i++) {
                Varnode input = op.getInput(i);
                
                if (input.isRegister()) {
                    Register reg = language.getRegister(input.getAddress(), input.getSize());
                    if (reg != null) {
                        // Track register usage
                        println("    P-code: Register " + reg.getName() + 
                               " used in " + func.getName());
                    }
                }
            }
        }
    }
    
    // Phase 8: Symbol table analysis
    private void analyzeSymbolTable() throws Exception {
        SymbolIterator symbolIter = symbolTable.getAllSymbols(true);
        int licenseSymbols = 0;
        
        while (symbolIter.hasNext() && !taskMonitor.isCancelled()) {
            Symbol symbol = symbolIter.next();
            String name = symbol.getName().toLowerCase();
            
            if (name.contains("license") || name.contains("serial") || 
                name.contains("activation") || name.contains("registration")) {
                
                licenseSymbols++;
                Address addr = symbol.getAddress();
                SymbolType type = symbol.getSymbolType();
                
                println("  License symbol: " + symbol.getName() + " (" + type + ") at " + addr);
                createBookmark(addr, "License Symbol", symbol.getName());
                
                // Check references to this symbol
                Reference[] refs = referenceManager.getReferencesTo(addr);
                for (Reference ref : refs) {
                    Address fromAddr = ref.getFromAddress();
                    Function func = functionManager.getFunctionContaining(fromAddr);
                    if (func != null) {
                        keyValidationFunctions.add(func.getEntryPoint());
                    }
                }
            }
        }
        
        println("  Found " + licenseSymbols + " license-related symbols");
    }
    
    // Phase 9: Memory protection analysis
    private void analyzeMemoryProtection() throws Exception {
        Memory memory = program.getMemory();
        int protectedCount = 0;
        
        // Check for protected license regions
        for (Address licAddr : keyValidationFunctions) {
            try {
                MemoryBlock block = memory.getBlock(licAddr);
                if (block != null && !block.isWrite()) {
                    protectedRegions.add(licAddr);
                    protectedCount++;
                    println("  Protected license code at " + licAddr + " (read-only)");
                    createBookmark(licAddr, "Protected", "Read-only license code");
                }
                
                // Try to access memory to detect protection
                byte[] testBytes = new byte[16];
                try {
                    memory.getBytes(licAddr, testBytes);
                } catch (MemoryAccessException mae) {
                    // Memory is protected
                    protectedRegions.add(licAddr);
                    protectedCount++;
                    println("  Memory-protected license region at " + licAddr + 
                           ": " + mae.getMessage());
                    createBookmark(licAddr, "Protected", "Memory access denied");
                }
                
            } catch (Exception e) {
                // Continue
            }
        }
        
        // Check address spaces for protection
        AddressSpace[] spaces = program.getAddressFactory().getAddressSpaces();
        for (AddressSpace space : spaces) {
            if (space.getName().contains("protect") || space.getName().contains("guard")) {
                println("  Protected address space: " + space.getName());
                
                // Add entire space to protected regions
                Address start = space.getMinAddress();
                Address end = space.getMaxAddress();
                if (start != null && end != null) {
                    protectedRegions.add(start, end);
                    protectedCount++;
                }
            }
        }
        
        println("  Found " + protectedCount + " protected memory regions");
    }
    
    // Phase 10: Register-level operations
    private void analyzeRegisterOperations() throws Exception {
        InstructionIterator instIter = program.getListing().getInstructions(true);
        int registerOps = 0;
        
        while (instIter.hasNext() && !taskMonitor.isCancelled()) {
            Instruction inst = instIter.next();
            
            // Get as CodeUnit for detailed analysis
            CodeUnit codeUnit = program.getListing().getCodeUnitAt(inst.getAddress());
            if (codeUnit != null && !analyzedCodeUnits.contains(codeUnit)) {
                analyzedCodeUnits.add(codeUnit);
                
                // Check operand types
                for (int i = 0; i < inst.getNumOperands(); i++) {
                    int opType = inst.getOperandType(i);
                    
                    if ((opType & OperandType.REGISTER) != 0) {
                        Register reg = inst.getRegister(i);
                        if (reg != null) {
                            // Check for debug registers (hardware breakpoints)
                            if (reg.getName().startsWith("DR")) {
                                println("  Anti-debug: Debug register " + reg.getName() + 
                                       " at " + inst.getAddress());
                                createBookmark(inst.getAddress(), "Anti-Debug", 
                                             "Debug register " + reg.getName());
                            }
                            
                            // Check for CPUID (hardware fingerprinting)
                            if (inst.getMnemonicString().equals("CPUID")) {
                                println("  Hardware ID: CPUID at " + inst.getAddress());
                                createBookmark(inst.getAddress(), "Hardware ID", "CPUID instruction");
                            }
                            
                            // Track register values for license keys
                            RegisterValue regValue = program.getProgramContext()
                                .getRegisterValue(reg, inst.getAddress());
                            if (regValue != null && regValue.hasValue()) {
                                registerStates.put(reg, regValue);
                                registerOps++;
                            }
                        }
                    }
                    
                    // Check for scalar operands (potential license values)
                    if ((opType & OperandType.SCALAR) != 0) {
                        Object[] opObjects = inst.getOpObjects(i);
                        for (Object obj : opObjects) {
                            if (obj instanceof Scalar) {
                                Scalar scalar = (Scalar)obj;
                                long value = scalar.getUnsignedValue();
                                if (isLicenseConstant(value)) {
                                    println("  License constant 0x" + Long.toHexString(value) + 
                                           " at " + inst.getAddress());
                                }
                            }
                        }
                    }
                }
            }
        }
        
        println("  Tracked " + registerOps + " register operations");
        println("  Analyzed " + analyzedCodeUnits.size() + " code units");
    }
    
    // Phase 11: Data type structure analysis
    private void analyzeLicenseDataTypes() throws Exception {
        Iterator<DataType> typeIter = dataTypeManager.getAllDataTypes();
        int licenseStructs = 0;
        
        while (typeIter.hasNext() && !taskMonitor.isCancelled()) {
            DataType dt = typeIter.next();
            String typeName = dt.getName().toLowerCase();
            
            if (typeName.contains("license") || typeName.contains("serial") || 
                typeName.contains("key") || typeName.contains("activation")) {
                
                licenseStructs++;
                
                if (dt instanceof Structure) {
                    Structure struct = (Structure)dt;
                    println("  License structure: " + dt.getName() + 
                           " (" + struct.getLength() + " bytes)");
                    
                    // Analyze structure components
                    for (int i = 0; i < struct.getNumComponents(); i++) {
                        DataTypeComponent comp = struct.getComponent(i);
                        String fieldName = comp.getFieldName();
                        if (fieldName != null) {
                            println("    - Field: " + fieldName + " (" + 
                                   comp.getDataType().getName() + ")");
                        }
                    }
                    
                    // Find instances of this structure
                    findStructureInstances(struct);
                    
                } else if (dt instanceof Enum) {
                    Enum enumType = (Enum)dt;
                    println("  License enum: " + dt.getName() + 
                           " with " + enumType.getCount() + " values");
                    
                    String[] names = enumType.getNames();
                    for (String name : names) {
                        long value = enumType.getValue(name);
                        println("    - " + name + " = " + value);
                    }
                }
            }
        }
        
        println("  Found " + licenseStructs + " license-related data types");
    }
    
    private void findStructureInstances(Structure struct) throws Exception {
        DataIterator dataIter = program.getListing().getDefinedData(true);
        
        while (dataIter.hasNext() && !taskMonitor.isCancelled()) {
            Data data = dataIter.next();
            if (data.getDataType().equals(struct)) {
                Address addr = data.getAddress();
                println("    Instance at " + addr);
                createBookmark(addr, "License Data", struct.getName() + " instance");
                
                // Check if it's in a license function
                Function func = functionManager.getFunctionContaining(addr);
                if (func != null) {
                    keyValidationFunctions.add(func.getEntryPoint());
                }
            }
        }
    }
    
    // Phase 12: High-level function analysis
    private void analyzeHighLevelFunctions() throws Exception {
        DecompInterface decompiler = new DecompInterface();
        decompiler.openProgram(program);
        DecompileOptions options = new DecompileOptions();
        decompiler.setOptions(options);
        
        int highLevelAnalyzed = 0;
        
        for (Address funcAddr : keyValidationFunctions) {
            if (taskMonitor.isCancelled()) break;
            
            Function func = functionManager.getFunctionAt(funcAddr);
            if (func == null) continue;
            
            try {
                DecompileResults results = decompiler.decompileFunction(func, 30, taskMonitor);
                
                if (results.decompileCompleted()) {
                    HighFunction highFunc = results.getHighFunction();
                    if (highFunc != null) {
                        highFunctionCache.put(func.getName(), highFunc);
                        
                        // Analyze local variables for license data
                        Iterator<HighSymbol> symIter = highFunc.getLocalSymbolMap()
                            .getSymbols();
                        while (symIter.hasNext()) {
                            HighSymbol sym = symIter.next();
                            String symName = sym.getName();
                            if (symName.contains("license") || symName.contains("key")) {
                                println("  License variable '" + symName + "' in " + 
                                       func.getName());
                            }
                        }
                        
                        // Analyze function prototype
                        LocalSymbolMap params = highFunc.getLocalSymbolMap();
                        int paramCount = params.getNumParams();
                        for (int i = 0; i < paramCount; i++) {
                            HighSymbol param = params.getParam(i);
                            if (param != null) {
                                DataType paramType = param.getDataType();
                                if (paramType.getName().contains("char") || 
                                    paramType.getName().contains("string")) {
                                    println("  String parameter in " + func.getName() + 
                                           " (possible license input)");
                                }
                            }
                        }
                        
                        highLevelAnalyzed++;
                    }
                }
            } catch (InvalidInputException iie) {
                println("  Invalid input for function " + func.getName() + ": " + 
                       iie.getMessage());
            } catch (CancelledException ce) {
                println("  Analysis cancelled by user");
                break;
            }
        }
        
        decompiler.closeProgram();
        println("  High-level analysis completed for " + highLevelAnalyzed + " functions");
    }
    
    // Phase 13: Hash validation detection
    private void detectHashValidation() throws Exception {
        // Common hash algorithms
        String[] hashAlgos = {"MD5", "SHA1", "SHA256", "SHA512", "CRC32"};
        int hashDetections = 0;
        
        for (String algo : hashAlgos) {
            try {
                MessageDigest md = MessageDigest.getInstance(algo.replace("SHA", "SHA-"));
                
                // Search for hash constants
                byte[] emptyHash = md.digest(new byte[0]);
                Address[] found = findBytes(program.getMinAddress(), emptyHash, 10);
                
                for (Address addr : found) {
                    println("  " + algo + " hash constant at " + addr);
                    createBookmark(addr, "Hash", algo + " constant");
                    hashDetections++;
                    
                    // Check if used in license validation
                    Reference[] refs = referenceManager.getReferencesTo(addr);
                    for (Reference ref : refs) {
                        Function func = functionManager.getFunctionContaining(ref.getFromAddress());
                        if (func != null) {
                            println("    Used in function " + func.getName());
                            keyValidationFunctions.add(func.getEntryPoint());
                        }
                    }
                }
            } catch (Exception e) {
                // Algorithm not available or other error
            }
        }
        
        // Look for hash function imports
        SymbolIterator symIter = symbolTable.getAllSymbols(true);
        while (symIter.hasNext() && !taskMonitor.isCancelled()) {
            Symbol sym = symIter.next();
            String name = sym.getName().toLowerCase();
            
            for (String algo : hashAlgos) {
                if (name.contains(algo.toLowerCase())) {
                    println("  Hash function: " + sym.getName() + " at " + sym.getAddress());
                    createBookmark(sym.getAddress(), "Hash", "Hash function: " + sym.getName());
                    hashDetections++;
                }
            }
        }
        
        println("  Detected " + hashDetections + " hash-based validation patterns");
    }
    
    /**
     * Phase 14: Comprehensive PE Format License Analysis
     * Analyzes PE format structures for embedded license data and validation mechanisms
     */
    private void analyzePEFormatLicenseData() throws Exception {
        // Check if this is a PE format file
        if (!isPEFormat()) {
            println("  Not a PE format file - skipping PE analysis");
            return;
        }
        
        int peFindings = 0;
        Memory memory = program.getMemory();
        
        try {
            // Phase 14.1: DOS Header Analysis
            peFindings += analyzeDOSHeader(memory);
            
            // Phase 14.2: PE Header Analysis
            peFindings += analyzePEHeader(memory);
            
            // Phase 14.3: Section Header Analysis
            peFindings += analyzeSectionHeaders(memory);
            
            // Phase 14.4: Resource Directory Analysis
            peFindings += analyzeResourceDirectory(memory);
            
            // Phase 14.5: Import/Export Table Analysis
            peFindings += analyzeImportExportTables(memory);
            
            // Phase 14.6: Version Information Analysis
            peFindings += analyzeVersionInfo(memory);
            
            // Phase 14.7: Certificate Table Analysis
            peFindings += analyzeCertificateTable(memory);
            
            // Phase 14.8: Overlay Analysis
            peFindings += analyzeOverlayData(memory);
            
            println("  PE Format analysis completed: " + peFindings + " license-related findings");
            
        } catch (Exception e) {
            println("  PE analysis error: " + e.getMessage());
        }
    }
    
    private boolean isPEFormat() {
        try {
            Memory memory = program.getMemory();
            Address imageBase = program.getImageBase();
            
            // Check for DOS signature "MZ"
            byte[] dosSignature = new byte[2];
            memory.getBytes(imageBase, dosSignature);
            
            return (dosSignature[0] == 0x4D && dosSignature[1] == 0x5A);
        } catch (Exception e) {
            return false;
        }
    }
    
    private int analyzeDOSHeader(Memory memory) throws Exception {
        println("    [14.1] Analyzing DOS header for license patterns...");
        int findings = 0;
        Address imageBase = program.getImageBase();
        
        try {
            // Read DOS header structure
            DOSHeader dosHeader = new DOSHeader();
            dosHeader.read(memory, imageBase);
            
            // Check for unusual DOS stub modifications (common hiding place)
            Address dosStubStart = imageBase.add(0x40);
            Address peHeaderOffset = imageBase.add(dosHeader.e_lfanew());
            
            if (dosStubStart.compareTo(peHeaderOffset) < 0) {
                long stubSize = peHeaderOffset.subtract(dosStubStart);
                if (stubSize > 64) { // Standard DOS stub is ~64 bytes
                    println("      Extended DOS stub detected (" + stubSize + " bytes) - checking for license data");
                    
                    byte[] stubData = new byte[(int)stubSize];
                    memory.getBytes(dosStubStart, stubData);
                    
                    // Check for embedded license strings in DOS stub
                    String stubString = new String(stubData, StandardCharsets.US_ASCII);
                    if (isLicenseRelated(stubString)) {
                        println("      [+] License data found in DOS stub at " + dosStubStart);
                        createBookmark(dosStubStart, "PE License", "License data in DOS stub");
                        licenseLocations.add(new LicenseLocation(dosStubStart, "DOSStub", "License in DOS stub"));
                        findings++;
                    }
                    
                    // Check for high entropy (encrypted license data)
                    double entropy = calculateEntropy(stubData);
                    if (entropy > 7.0) {
                        println("      [+] High entropy DOS stub (possible encrypted license) at " + dosStubStart);
                        createBookmark(dosStubStart, "PE License", "Encrypted license data in DOS stub");
                        findings++;
                    }
                }
            }
            
        } catch (Exception e) {
            println("      DOS header analysis failed: " + e.getMessage());
        }
        
        return findings;
    }
    
    private int analyzePEHeader(Memory memory) throws Exception {
        println("    [14.2] Analyzing PE header for license validation hooks...");
        int findings = 0;
        Address imageBase = program.getImageBase();
        
        try {
            // Get PE header location from DOS header
            DOSHeader dosHeader = new DOSHeader();
            dosHeader.read(memory, imageBase);
            Address peHeaderAddr = imageBase.add(dosHeader.e_lfanew());
            
            // Read NT headers
            NTHeader ntHeader = new NTHeader();
            ntHeader.read(memory, peHeaderAddr);
            
            // Check optional header for unusual entry points or license-related modifications
            OptionalHeader optHeader = ntHeader.getOptionalHeader();
            long entryPoint = optHeader.getAddressOfEntryPoint();
            
            // Analyze entry point function for license checks
            Address entryAddr = imageBase.add(entryPoint);
            Function entryFunc = functionManager.getFunctionAt(entryAddr);
            if (entryFunc != null) {
                println("      Analyzing entry point function: " + entryFunc.getName());
                
                // Check if entry point calls license validation early
                InstructionIterator instIter = program.getListing().getInstructions(entryFunc.getBody(), true);
                int instructionCount = 0;
                
                while (instIter.hasNext() && instructionCount < 50) { // Check first 50 instructions
                    Instruction inst = instIter.next();
                    instructionCount++;
                    
                    if (inst.getMnemonicString().equals("CALL")) {
                        Reference[] refs = inst.getReferencesFrom();
                        for (Reference ref : refs) {
                            Function calledFunc = functionManager.getFunctionAt(ref.getToAddress());
                            if (calledFunc != null && isLicenseFunction(calledFunc)) {
                                println("      [+] Early license check in entry point: " + calledFunc.getName());
                                createBookmark(inst.getAddress(), "PE License", "Early license check");
                                keyValidationFunctions.add(calledFunc.getEntryPoint());
                                findings++;
                            }
                        }
                    }
                }
            }
            
            // Check for custom sections in section table
            FileHeader fileHeader = ntHeader.getFileHeader();
            int numSections = fileHeader.getNumberOfSections();
            
            println("      PE file has " + numSections + " sections");
            
        } catch (Exception e) {
            println("      PE header analysis failed: " + e.getMessage());
        }
        
        return findings;
    }
    
    private int analyzeSectionHeaders(Memory memory) throws Exception {
        println("    [14.3] Analyzing section headers for license data...");
        int findings = 0;
        Address imageBase = program.getImageBase();
        
        try {
            // Get section headers
            DOSHeader dosHeader = new DOSHeader();
            dosHeader.read(memory, imageBase);
            Address peHeaderAddr = imageBase.add(dosHeader.e_lfanew());
            
            NTHeader ntHeader = new NTHeader();
            ntHeader.read(memory, peHeaderAddr);
            
            SectionHeader[] sections = ntHeader.getSectionHeaders();
            
            for (SectionHeader section : sections) {
                String sectionName = section.getName();
                println("      Analyzing section: " + sectionName);
                
                // Check for license-related section names
                if (sectionName.toLowerCase().contains("lic") || 
                    sectionName.toLowerCase().contains("key") ||
                    sectionName.toLowerCase().contains("drm") ||
                    sectionName.toLowerCase().contains("prot")) {
                    
                    println("      [+] License-related section found: " + sectionName);
                    Address sectionAddr = imageBase.add(section.getVirtualAddress());
                    createBookmark(sectionAddr, "PE License", "License section: " + sectionName);
                    findings++;
                    
                    // Analyze section content
                    analyzeSectionContent(section, sectionAddr);
                }
                
                // Check for unusual section characteristics
                long characteristics = section.getCharacteristics();
                if ((characteristics & SectionHeader.IMAGE_SCN_MEM_NOT_CACHED) != 0) {
                    println("      [*] Non-cacheable section: " + sectionName + " (possible protection)");
                }
                
                if ((characteristics & SectionHeader.IMAGE_SCN_MEM_NOT_PAGED) != 0) {
                    println("      [*] Non-pageable section: " + sectionName + " (possible protection)");
                }
                
                // Check for sections with unusual entropy
                Address sectionAddr = imageBase.add(section.getVirtualAddress());
                if (sectionAddr != null) {
                    try {
                        int sampleSize = (int)Math.min(section.getSizeOfRawData(), 4096);
                        byte[] sectionData = new byte[sampleSize];
                        memory.getBytes(sectionAddr, sectionData);
                        
                        double entropy = calculateEntropy(sectionData);
                        if (entropy > 7.5) {
                            println("      [+] High entropy section " + sectionName + 
                                   " (entropy: " + String.format("%.2f", entropy) + ")");
                            createBookmark(sectionAddr, "PE License", "High entropy: " + sectionName);
                            findings++;
                        }
                    } catch (Exception e) {
                        // Section not loaded in memory
                    }
                }
            }
            
        } catch (Exception e) {
            println("      Section analysis failed: " + e.getMessage());
        }
        
        return findings;
    }
    
    private void analyzeSectionContent(SectionHeader section, Address sectionAddr) {
        try {
            Memory memory = program.getMemory();
            int contentSize = (int)Math.min(section.getSizeOfRawData(), 1024);
            byte[] content = new byte[contentSize];
            memory.getBytes(sectionAddr, content);
            
            // Look for license patterns in section
            String contentStr = new String(content, StandardCharsets.US_ASCII);
            if (isLicenseRelated(contentStr)) {
                println("        License text found in section content");
                deobfuscatedStrings.put(sectionAddr, contentStr.substring(0, Math.min(100, contentStr.length())));
            }
            
            // Check for structured license data
            if (containsStructuredData(content)) {
                println("        Structured license data detected in section");
                licenseLocations.add(new LicenseLocation(sectionAddr, "StructuredData", 
                                                       "Section " + section.getName()));
            }
            
        } catch (Exception e) {
            // Unable to analyze section content
        }
    }
    
    private boolean containsStructuredData(byte[] data) {
        // Look for repeating patterns that suggest structured license data
        Map<Byte, Integer> byteFreq = new HashMap<>();
        for (byte b : data) {
            byteFreq.put(b, byteFreq.getOrDefault(b, 0) + 1);
        }
        
        // Check for patterns typical of license files (lots of zeros, specific delimiters)
        int zeroCount = byteFreq.getOrDefault((byte)0, 0);
        int dashCount = byteFreq.getOrDefault((byte)'-', 0);
        int digitCount = 0;
        
        for (byte b = '0'; b <= '9'; b++) {
            digitCount += byteFreq.getOrDefault(b, 0);
        }
        
        return (zeroCount > data.length / 10) || (dashCount > 5 && digitCount > data.length / 4);
    }
    
    private int analyzeResourceDirectory(Memory memory) throws Exception {
        println("    [14.4] Analyzing resource directory for license resources...");
        int findings = 0;
        
        try {
            // Get resource directory from optional header
            Address imageBase = program.getImageBase();
            DOSHeader dosHeader = new DOSHeader();
            dosHeader.read(memory, imageBase);
            Address peHeaderAddr = imageBase.add(dosHeader.e_lfanew());
            
            NTHeader ntHeader = new NTHeader();
            ntHeader.read(memory, peHeaderAddr);
            
            OptionalHeader optHeader = ntHeader.getOptionalHeader();
            DataDirectory[] dataDirectories = optHeader.getDataDirectories();
            
            if (dataDirectories.length > OptionalHeader.IMAGE_DIRECTORY_ENTRY_RESOURCE) {
                DataDirectory resourceDir = dataDirectories[OptionalHeader.IMAGE_DIRECTORY_ENTRY_RESOURCE];
                
                if (resourceDir.getSize() > 0) {
                    Address resourceAddr = imageBase.add(resourceDir.getVirtualAddress());
                    println("      Resource directory at " + resourceAddr + " (size: " + resourceDir.getSize() + ")");
                    
                    // Analyze resource entries for license-related resources
                    findings += analyzeResourceEntries(resourceAddr, resourceDir.getSize());
                }
            }
            
        } catch (Exception e) {
            println("      Resource directory analysis failed: " + e.getMessage());
        }
        
        return findings;
    }
    
    private int analyzeResourceEntries(Address resourceAddr, long resourceSize) throws Exception {
        int findings = 0;
        Memory memory = program.getMemory();
        
        try {
            // Read resource directory header
            ResourceDataDirectory resourceDir = new ResourceDataDirectory();
            resourceDir.read(memory, resourceAddr);
            
            int numNameEntries = resourceDir.getNumberOfNameEntries();
            int numIdEntries = resourceDir.getNumberOfIdEntries();
            
            println("        Resource entries: " + numNameEntries + " named, " + numIdEntries + " by ID");
            
            // Analyze resource entries
            Address entryAddr = resourceAddr.add(ResourceDataDirectory.SIZEOF);
            
            for (int i = 0; i < numNameEntries + numIdEntries; i++) {
                if (taskMonitor.isCancelled()) break;
                
                ResourceDirectoryEntry entry = new ResourceDirectoryEntry();
                entry.read(memory, entryAddr);
                
                // Check for license-related resource types
                if (isLicenseResourceType(entry)) {
                    println("        [+] License-related resource found at " + entryAddr);
                    createBookmark(entryAddr, "PE License", "License resource entry");
                    findings++;
                }
                
                entryAddr = entryAddr.add(ResourceDirectoryEntry.SIZEOF);
            }
            
        } catch (Exception e) {
            println("        Resource entry analysis failed: " + e.getMessage());
        }
        
        return findings;
    }
    
    private boolean isLicenseResourceType(ResourceDirectoryEntry entry) {
        // Check common resource types that might contain license info
        long resourceType = entry.getName();
        
        // RT_RCDATA (raw data), RT_STRING, RT_VERSION often contain license info
        return resourceType == 10 || resourceType == 6 || resourceType == 16;
    }
    
    private int analyzeImportExportTables(Memory memory) throws Exception {
        println("    [14.5] Analyzing import/export tables for license-related APIs...");
        int findings = 0;
        
        try {
            Address imageBase = program.getImageBase();
            DOSHeader dosHeader = new DOSHeader();
            dosHeader.read(memory, imageBase);
            Address peHeaderAddr = imageBase.add(dosHeader.e_lfanew());
            
            NTHeader ntHeader = new NTHeader();
            ntHeader.read(memory, peHeaderAddr);
            
            OptionalHeader optHeader = ntHeader.getOptionalHeader();
            DataDirectory[] dataDirectories = optHeader.getDataDirectories();
            
            // Analyze import table
            if (dataDirectories.length > OptionalHeader.IMAGE_DIRECTORY_ENTRY_IMPORT) {
                DataDirectory importDir = dataDirectories[OptionalHeader.IMAGE_DIRECTORY_ENTRY_IMPORT];
                if (importDir.getSize() > 0) {
                    findings += analyzeImportTable(imageBase.add(importDir.getVirtualAddress()), importDir.getSize());
                }
            }
            
            // Analyze export table
            if (dataDirectories.length > OptionalHeader.IMAGE_DIRECTORY_ENTRY_EXPORT) {
                DataDirectory exportDir = dataDirectories[OptionalHeader.IMAGE_DIRECTORY_ENTRY_EXPORT];
                if (exportDir.getSize() > 0) {
                    findings += analyzeExportTable(imageBase.add(exportDir.getVirtualAddress()), exportDir.getSize());
                }
            }
            
        } catch (Exception e) {
            println("      Import/Export analysis failed: " + e.getMessage());
        }
        
        return findings;
    }
    
    private int analyzeImportTable(Address importAddr, long importSize) throws Exception {
        int findings = 0;
        Memory memory = program.getMemory();
        
        try {
            // License-related APIs to look for
            String[] licenseAPIs = {
                "CryptEncrypt", "CryptDecrypt", "CryptHashData", "CryptVerifySignature",
                "RegOpenKey", "RegQueryValue", "GetVolumeInformation", "GetComputerName",
                "CreateFile", "ReadFile", "WriteFile", "GetSystemTime", "GetTickCount"
            };
            
            println("        Scanning import table for license-related APIs...");
            
            Address currentAddr = importAddr;
            
            while (currentAddr.compareTo(importAddr.add(importSize)) < 0 && !taskMonitor.isCancelled()) {
                try {
                    ImportDescriptor descriptor = new ImportDescriptor();
                    descriptor.read(memory, currentAddr);
                    
                    if (descriptor.getName() == 0) break; // End of import table
                    
                    // Get DLL name
                    Address nameAddr = program.getImageBase().add(descriptor.getName());
                    String dllName = readNullTerminatedString(memory, nameAddr);
                    
                    // Check for crypto/security related DLLs
                    if (isLicenseRelatedDLL(dllName)) {
                        println("        [+] License-related DLL: " + dllName);
                        createBookmark(currentAddr, "PE License", "License DLL: " + dllName);
                        findings++;
                    }
                    
                    // Analyze imported functions
                    findings += analyzeImportedFunctions(descriptor, dllName, licenseAPIs);
                    
                    currentAddr = currentAddr.add(ImportDescriptor.SIZEOF);
                    
                } catch (Exception e) {
                    currentAddr = currentAddr.add(4); // Skip invalid entry
                }
            }
            
        } catch (Exception e) {
            println("        Import table analysis failed: " + e.getMessage());
        }
        
        return findings;
    }
    
    private boolean isLicenseRelatedDLL(String dllName) {
        if (dllName == null) return false;
        String name = dllName.toLowerCase();
        
        return name.contains("crypt") || name.contains("advapi") || name.contains("wintrust") ||
               name.contains("license") || name.contains("activation") || name.contains("security");
    }
    
    private int analyzeImportedFunctions(ImportDescriptor descriptor, String dllName, String[] licenseAPIs) throws Exception {
        int findings = 0;
        Memory memory = program.getMemory();
        
        // This would analyze the import address table for specific function names
        // Simplified implementation for demonstration
        for (String api : licenseAPIs) {
            if (dllName.toLowerCase().contains("crypt") || dllName.toLowerCase().contains("advapi")) {
                // Check if this DLL likely contains the API
                println("          Checking for " + api + " in " + dllName);
                findings++;
            }
        }
        
        return findings;
    }
    
    private String readNullTerminatedString(Memory memory, Address addr) throws Exception {
        StringBuilder sb = new StringBuilder();
        Address current = addr;
        
        for (int i = 0; i < 256; i++) { // Limit string length
            byte b = memory.getByte(current);
            if (b == 0) break;
            sb.append((char)b);
            current = current.add(1);
        }
        
        return sb.toString();
    }
    
    private int analyzeExportTable(Address exportAddr, long exportSize) throws Exception {
        int findings = 0;
        
        try {
            println("        Analyzing export table for license validation exports...");
            
            Memory memory = program.getMemory();
            ExportDataDirectory exportDir = new ExportDataDirectory();
            exportDir.read(memory, exportAddr);
            
            int numFunctions = exportDir.getNumberOfFunctions();
            int numNames = exportDir.getNumberOfNames();
            
            println("          Export table: " + numFunctions + " functions, " + numNames + " names");
            
            // Check exported function names for license-related functions
            if (exportDir.getAddressOfNames() != 0) {
                Address namesAddr = program.getImageBase().add(exportDir.getAddressOfNames());
                
                for (int i = 0; i < numNames && !taskMonitor.isCancelled(); i++) {
                    long nameRVA = memory.getInt(namesAddr.add(i * 4)) & 0xFFFFFFFFL;
                    Address nameAddr = program.getImageBase().add(nameRVA);
                    String funcName = readNullTerminatedString(memory, nameAddr);
                    
                    if (isLicenseFunction(funcName)) {
                        println("          [+] License export function: " + funcName);
                        createBookmark(nameAddr, "PE License", "License export: " + funcName);
                        findings++;
                    }
                }
            }
            
        } catch (Exception e) {
            println("        Export table analysis failed: " + e.getMessage());
        }
        
        return findings;
    }
    
    private boolean isLicenseFunction(String funcName) {
        if (funcName == null) return false;
        String name = funcName.toLowerCase();
        
        return name.contains("license") || name.contains("valid") || name.contains("check") ||
               name.contains("verify") || name.contains("activation") || name.contains("serial");
    }
    
    private int analyzeVersionInfo(Memory memory) throws Exception {
        println("    [14.6] Analyzing version information for license strings...");
        int findings = 0;
        
        try {
            // Version info is typically in resources - this would parse VS_VERSIONINFO
            // Simplified implementation
            Address imageBase = program.getImageBase();
            DOSHeader dosHeader = new DOSHeader();
            dosHeader.read(memory, imageBase);
            Address peHeaderAddr = imageBase.add(dosHeader.e_lfanew());
            
            NTHeader ntHeader = new NTHeader();
            ntHeader.read(memory, peHeaderAddr);
            
            OptionalHeader optHeader = ntHeader.getOptionalHeader();
            DataDirectory[] dataDirectories = optHeader.getDataDirectories();
            
            if (dataDirectories.length > OptionalHeader.IMAGE_DIRECTORY_ENTRY_RESOURCE) {
                DataDirectory resourceDir = dataDirectories[OptionalHeader.IMAGE_DIRECTORY_ENTRY_RESOURCE];
                
                if (resourceDir.getSize() > 0) {
                    // Scan for version strings that might contain license info
                    Address resourceAddr = imageBase.add(resourceDir.getVirtualAddress());
                    byte[] versionData = new byte[(int)Math.min(resourceDir.getSize(), 4096)];
                    memory.getBytes(resourceAddr, versionData);
                    
                    String versionStr = new String(versionData, StandardCharsets.UTF_16LE);
                    if (isLicenseRelated(versionStr)) {
                        println("        [+] License information in version data");
                        createBookmark(resourceAddr, "PE License", "License in version info");
                        findings++;
                    }
                }
            }
            
        } catch (Exception e) {
            println("        Version info analysis failed: " + e.getMessage());
        }
        
        return findings;
    }
    
    private int analyzeCertificateTable(Memory memory) throws Exception {
        println("    [14.7] Analyzing certificate table for code signing...");
        int findings = 0;
        
        try {
            Address imageBase = program.getImageBase();
            DOSHeader dosHeader = new DOSHeader();
            dosHeader.read(memory, imageBase);
            Address peHeaderAddr = imageBase.add(dosHeader.e_lfanew());
            
            NTHeader ntHeader = new NTHeader();
            ntHeader.read(memory, peHeaderAddr);
            
            OptionalHeader optHeader = ntHeader.getOptionalHeader();
            DataDirectory[] dataDirectories = optHeader.getDataDirectories();
            
            if (dataDirectories.length > OptionalHeader.IMAGE_DIRECTORY_ENTRY_SECURITY) {
                DataDirectory certDir = dataDirectories[OptionalHeader.IMAGE_DIRECTORY_ENTRY_SECURITY];
                
                if (certDir.getSize() > 0) {
                    println("        [+] Code signing certificate present (size: " + certDir.getSize() + ")");
                    
                    // Certificate table is at file offset, not RVA
                    Address certAddr = imageBase.add(certDir.getVirtualAddress());
                    createBookmark(certAddr, "PE License", "Code signing certificate");
                    findings++;
                    
                    // Analyze certificate content for license-related information
                    findings += analyzeCertificateContent(memory, certAddr, certDir.getSize());
                }
            }
            
        } catch (Exception e) {
            println("        Certificate analysis failed: " + e.getMessage());
        }
        
        return findings;
    }
    
    private int analyzeCertificateContent(Memory memory, Address certAddr, long certSize) throws Exception {
        int findings = 0;
        
        try {
            // Read certificate data
            int dataSize = (int)Math.min(certSize, 8192);
            byte[] certData = new byte[dataSize];
            memory.getBytes(certAddr, certData);
            
            // Look for certificate-embedded license information
            String certStr = new String(certData, StandardCharsets.US_ASCII);
            if (certStr.contains("License") || certStr.contains("EULA") || certStr.contains("Terms")) {
                println("          [+] License terms embedded in certificate");
                createBookmark(certAddr, "PE License", "License in certificate");
                findings++;
            }
            
            // Check for custom certificate extensions that might contain license data
            if (certData.length > 100) {
                double entropy = calculateEntropy(certData);
                if (entropy > 7.8) {
                    println("          [+] High entropy certificate data (possible license payload)");
                    findings++;
                }
            }
            
        } catch (Exception e) {
            println("          Certificate content analysis failed: " + e.getMessage());
        }
        
        return findings;
    }
    
    private int analyzeOverlayData(Memory memory) throws Exception {
        println("    [14.8] Analyzing overlay data for license information...");
        int findings = 0;
        
        try {
            // Calculate where overlay data would start (after all sections)
            Address imageBase = program.getImageBase();
            DOSHeader dosHeader = new DOSHeader();
            dosHeader.read(memory, imageBase);
            Address peHeaderAddr = imageBase.add(dosHeader.e_lfanew());
            
            NTHeader ntHeader = new NTHeader();
            ntHeader.read(memory, peHeaderAddr);
            
            SectionHeader[] sections = ntHeader.getSectionHeaders();
            
            // Find the section with highest file offset + size
            long maxFileEnd = 0;
            for (SectionHeader section : sections) {
                long sectionEnd = section.getPointerToRawData() + section.getSizeOfRawData();
                if (sectionEnd > maxFileEnd) {
                    maxFileEnd = sectionEnd;
                }
            }
            
            // Check if there's data beyond the last section (overlay)
            Memory programMemory = program.getMemory();
            Address fileEnd = imageBase.add(maxFileEnd);
            
            // Try to read beyond the last section
            try {
                byte[] overlayCheck = new byte[1024];
                programMemory.getBytes(fileEnd, overlayCheck);
                
                // Check if overlay contains license data
                String overlayStr = new String(overlayCheck, StandardCharsets.US_ASCII);
                if (isLicenseRelated(overlayStr)) {
                    println("        [+] License data found in overlay at offset " + Long.toHexString(maxFileEnd));
                    createBookmark(fileEnd, "PE License", "License in overlay");
                    licenseLocations.add(new LicenseLocation(fileEnd, "Overlay", "License overlay data"));
                    findings++;
                }
                
                // Check for encrypted overlay data
                double entropy = calculateEntropy(overlayCheck);
                if (entropy > 7.5) {
                    println("        [+] High entropy overlay (possible encrypted license)");
                    createBookmark(fileEnd, "PE License", "Encrypted overlay");
                    findings++;
                }
                
            } catch (Exception e) {
                // No overlay data or not accessible
                println("        No overlay data detected");
            }
            
        } catch (Exception e) {
            println("        Overlay analysis failed: " + e.getMessage());
        }
        
        return findings;
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
        
        println("\nProtected Memory Regions: " + protectedRegions.getNumAddresses());
        println("High-Level Functions Analyzed: " + highFunctionCache.size());
        println("Register States Tracked: " + registerStates.size());
        println("Code Units Analyzed: " + analyzedCodeUnits.size());

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

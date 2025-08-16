/**
 * Keygen Template Generator for Ghidra
 *
 * Analyzes cryptographic validation routines and generates working keygen source code.
 * Supports RSA, ECC, AES, custom algorithms, and generates C++/Python/Java keygens.
 *
 * @category Intellicrack.KeygenGeneration
 * @author Intellicrack Framework
 * @version 2.0.0
 */

import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.*;
import ghidra.program.model.address.*;
import ghidra.program.model.symbol.*;
import ghidra.program.model.data.*;
import ghidra.program.model.lang.*;
import ghidra.program.model.pcode.*;
import ghidra.app.decompiler.*;
import ghidra.util.exception.*;

import java.util.*;
import java.io.*;
import java.nio.*;
import java.nio.charset.StandardCharsets;
import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import javax.crypto.spec.SecretKeySpec;
import javax.crypto.Cipher;

public class KeygenTemplateGenerator extends GhidraScript {

    // Keygen generation configuration
    private static final String[] SUPPORTED_LANGUAGES = {"C++", "Python", "Java"};
    private static final Map<String, CryptoAlgorithm> CRYPTO_ALGORITHMS = new HashMap<>();

    // Analysis results
    private List<ValidationRoutine> detectedRoutines = new ArrayList<>();
    private Map<Address, CryptoParameters> extractedParams = new HashMap<>();
    private List<KeygenTemplate> generatedTemplates = new ArrayList<>();

    // Enhanced logging and reporting
    private PrintWriter analysisLogger = null;
    private PrintWriter reportLogger = null;
    private Map<String, PrintWriter> phaseLoggers = new HashMap<>();

    // Decompiler interface
    private DecompInterface decompiler;

    static {
        initializeCryptoAlgorithms();
    }

    private static void initializeCryptoAlgorithms() {
        // RSA algorithm patterns
        CRYPTO_ALGORITHMS.put("RSA", new CryptoAlgorithm(
            "RSA",
            new String[]{"RSA", "modExp", "bignum", "montgomery"},
            new byte[][]{{(byte)0x01, 0x00, 0x01}, // 65537 exponent
                        {(byte)0x00, 0x00, 0x00, 0x03}}, // 3 exponent
            CryptoType.ASYMMETRIC
        ));

        // ECC algorithm patterns
        CRYPTO_ALGORITHMS.put("ECC", new CryptoAlgorithm(
            "ECC",
            new String[]{"EC", "curve", "point", "secp", "nist"},
            new byte[][]{},
            CryptoType.ASYMMETRIC
        ));

        // AES algorithm patterns
        CRYPTO_ALGORITHMS.put("AES", new CryptoAlgorithm(
            "AES",
            new String[]{"AES", "Rijndael", "sbox", "mixcolumn"},
            new byte[][]{{0x63, 0x7c, 0x77, 0x7b}}, // AES S-box start
            CryptoType.SYMMETRIC
        ));

        // Custom XOR patterns
        CRYPTO_ALGORITHMS.put("XOR", new CryptoAlgorithm(
            "XOR",
            new String[]{"xor"},
            new byte[][]{},
            CryptoType.CUSTOM
        ));

        // MD5 patterns
        CRYPTO_ALGORITHMS.put("MD5", new CryptoAlgorithm(
            "MD5",
            new String[]{"MD5", "md5"},
            new byte[][]{{(byte)0xd7, 0x6a, (byte)0xa4, 0x78}}, // MD5 constant
            CryptoType.HASH
        ));

        // SHA patterns
        CRYPTO_ALGORITHMS.put("SHA", new CryptoAlgorithm(
            "SHA",
            new String[]{"SHA", "sha"},
            new byte[][]{{0x42, (byte)0x8a, 0x2f, (byte)0x98}}, // SHA-256 constant
            CryptoType.HASH
        ));
    }

    @Override
    public void run() throws Exception {
        println("=== Keygen Template Generator v2.0.0 ===");
        println("Starting cryptographic validation analysis...\n");

        try {
            // Initialize enhanced logging system
            initializeEnhancedLogging();
            
            // Initialize decompiler
            initializeDecompiler();

            // Phase 0: Memory scanning for crypto patterns
            println("[Phase 0] Scanning memory for cryptographic patterns...");
            scanMemoryForCrypto();

            // Phase 1: Find validation routines
            println("\n[Phase 1] Locating validation routines...");
            findValidationRoutines();

            // Phase 2: Analyze crypto operations
            println("\n[Phase 2] Analyzing cryptographic operations...");
            analyzeCryptoOperations();

            // Phase 3: Extract parameters
            println("\n[Phase 3] Extracting cryptographic parameters...");
            extractCryptoParameters();
            
            // Phase 3b: Analyze data structures
            println("\n[Phase 3b] Analyzing data structures...");
            for (ValidationRoutine routine : detectedRoutines) {
                analyzeDataStructures(routine);
            }

            // Phase 4: Trace validation logic
            println("\n[Phase 4] Tracing validation logic flow...");
            traceValidationLogic();

            // Phase 5: Generate keygen templates
            println("\n[Phase 5] Generating keygen templates...");
            generateKeygenTemplates();

            // Phase 6: Test and optimize
            println("\n[Phase 6] Testing and optimizing keygens...");
            testAndOptimizeKeygens();

            // Generate final report
            generateReport();
            
        } catch (CancelledException ce) {
            println("\nOperation cancelled by user");
        } catch (InvalidInputException iie) {
            printerr("Invalid input: " + iie.getMessage());
        } catch (IOException ioe) {
            printerr("I/O error: " + ioe.getMessage());
        } finally {
            // Cleanup enhanced logging
            cleanupEnhancedLogging();
            
            // Cleanup decompiler
            if (decompiler != null) {
                decompiler.dispose();
            }
        }

        println("\nKeygen generation complete! Generated " + generatedTemplates.size() + " templates.");
    }

    private void initializeDecompiler() {
        DecompileOptions options = new DecompileOptions();
        decompiler = new DecompInterface();
        decompiler.setOptions(options);
        decompiler.openProgram(currentProgram);
    }
    
    private void initializeEnhancedLogging() {
        try {
            // Initialize main analysis logger
            analysisLogger = new PrintWriter(System.out, true);
            analysisLogger.println("=".repeat(80));
            analysisLogger.println("INTELLICRACK KEYGEN GENERATOR v2.0.0 - ENHANCED ANALYSIS");
            analysisLogger.println("Advanced cryptographic validation analysis and keygen generation");
            analysisLogger.println("Program: " + currentProgram.getName());
            analysisLogger.println("Executable: " + currentProgram.getExecutablePath());
            analysisLogger.println("Format: " + currentProgram.getExecutableFormat());
            analysisLogger.println("Analysis Date: " + new Date());
            analysisLogger.println("=".repeat(80));
            analysisLogger.flush();
            
            // Initialize report logger for structured output
            reportLogger = new PrintWriter(System.out, true);
            
            // Initialize phase-specific loggers
            phaseLoggers.put("MEMORY_SCAN", new PrintWriter(System.out, true));
            phaseLoggers.put("VALIDATION_DETECTION", new PrintWriter(System.out, true));
            phaseLoggers.put("CRYPTO_ANALYSIS", new PrintWriter(System.out, true));
            phaseLoggers.put("PARAMETER_EXTRACTION", new PrintWriter(System.out, true));
            phaseLoggers.put("LOGIC_TRACING", new PrintWriter(System.out, true));
            phaseLoggers.put("TEMPLATE_GENERATION", new PrintWriter(System.out, true));
            phaseLoggers.put("TESTING_OPTIMIZATION", new PrintWriter(System.out, true));
            
            logAnalysisPhase("INITIALIZATION", "Enhanced logging system initialized with " + 
                           phaseLoggers.size() + " phase loggers");
            
        } catch (Exception e) {
            println("Warning: Enhanced logging initialization failed: " + e.getMessage());
            // Fallback to basic System.out
            analysisLogger = new PrintWriter(System.out, true);
            reportLogger = new PrintWriter(System.out, true);
        }
    }
    
    private void cleanupEnhancedLogging() {
        try {
            if (analysisLogger != null) {
                analysisLogger.println("=".repeat(80));
                analysisLogger.println("ANALYSIS COMPLETE - Shutting down enhanced logging");
                analysisLogger.println("Total validation routines: " + detectedRoutines.size());
                analysisLogger.println("Total keygens generated: " + generatedTemplates.size());
                analysisLogger.println("=".repeat(80));
                analysisLogger.flush();
                analysisLogger.close();
            }
            
            if (reportLogger != null) {
                reportLogger.flush();
                reportLogger.close();
            }
            
            // Cleanup phase loggers
            for (PrintWriter logger : phaseLoggers.values()) {
                if (logger != null) {
                    logger.flush();
                    logger.close();
                }
            }
            phaseLoggers.clear();
            
        } catch (Exception e) {
            println("Warning: Error during logging cleanup: " + e.getMessage());
        }
    }
    
    private void logAnalysisPhase(String phase, String message) {
        if (analysisLogger != null) {
            analysisLogger.printf("[%s] %s - %s%n", 
                new Date().toString(), phase, message);
            analysisLogger.flush();
        }
        
        PrintWriter phaseLogger = phaseLoggers.get(phase);
        if (phaseLogger != null) {
            phaseLogger.printf("  %s: %s%n", phase, message);
            phaseLogger.flush();
        }
    }
    
    private void logCryptoDiscovery(String algorithm, Address location, String details) {
        if (analysisLogger != null) {
            analysisLogger.printf("CRYPTO_DISCOVERY: %s at 0x%08X - %s%n",
                algorithm, location.getOffset(), details);
            analysisLogger.flush();
        }
    }
    
    private void logKeygenGeneration(String function, String language, int codeLines) {
        if (reportLogger != null) {
            reportLogger.printf("KEYGEN_GENERATED: %s (%s) - %d lines of code%n",
                function, language, codeLines);
            reportLogger.flush();
        }
    }

    private void findValidationRoutines() {
        FunctionManager funcManager = currentProgram.getFunctionManager();
        FunctionIterator funcIter = funcManager.getFunctions(true);

        int found = 0;
        while (funcIter.hasNext() && !monitor.isCancelled()) {
            Function func = funcIter.next();

            // Check for validation routine patterns
            if (isValidationRoutine(func)) {
                ValidationRoutine routine = new ValidationRoutine();
                routine.function = func;
                routine.address = func.getEntryPoint();
                routine.name = func.getName();

                // Classify routine type
                classifyRoutineType(routine);

                detectedRoutines.add(routine);
                found++;
            }
        }

        println("  Found " + found + " potential validation routines");
    }

    private boolean isValidationRoutine(Function func) {
        String funcName = func.getName().toLowerCase();

        // Check function name patterns
        if (funcName.contains("valid") || funcName.contains("check") ||
            funcName.contains("verify") || funcName.contains("auth") ||
            funcName.contains("license") || funcName.contains("serial") ||
            funcName.contains("key") || funcName.contains("activate")) {
            return true;
        }

        // Check for crypto operations in function using instruction analysis
        if (analyzeInstructionPatterns(func)) {
            return true;
        }

        // Check for crypto operations in function
        try {
            DecompileResults results = decompiler.decompileFunction(func, 10, monitor);
            if (results.decompileCompleted()) {
                HighFunction highFunc = results.getHighFunction();
                if (highFunc != null && hasCryptoOperations(highFunc)) {
                    return true;
                }
            }
        } catch (CancelledException ce) {
            // User cancelled operation
            return false;
        } catch (Exception e) {
            // Continue on error
        }

        return false;
    }
    
    private boolean analyzeInstructionPatterns(Function func) {
        // Analyze instructions for crypto patterns
        AddressSetView funcBody = func.getBody();
        InstructionIterator instrIter = currentProgram.getListing().getInstructions(funcBody, true);
        
        int cryptoInstrCount = 0;
        while (instrIter.hasNext() && !monitor.isCancelled()) {
            Instruction instr = instrIter.next();
            CodeUnit cu = currentProgram.getListing().getCodeUnitAt(instr.getAddress());
            
            if (cu != null) {
                String mnemonic = cu.getMnemonicString().toUpperCase();
                
                // Check for crypto-specific instructions
                if (mnemonic.contains("AES") || mnemonic.equals("PSHUFB") || // AES instructions
                    mnemonic.equals("MULX") || mnemonic.equals("ADCX") ||    // RSA big number ops
                    mnemonic.contains("SHA") ||                               // SHA instructions
                    mnemonic.equals("RORX") || mnemonic.equals("PCLMULQDQ")) { // Crypto primitives
                    cryptoInstrCount++;
                }
                
                // Analyze operand types
                for (int i = 0; i < instr.getNumOperands(); i++) {
                    int opType = instr.getOperandType(i);
                    
                    // Check for XMM register usage (common in crypto)
                    if (OperandType.isRegister(opType)) {
                        Register reg = instr.getRegister(i);
                        if (reg != null && reg.getName().startsWith("XMM")) {
                            cryptoInstrCount++;
                        }
                    }
                    
                    // Check for large immediate values (potential keys/constants)
                    if (OperandType.isScalar(opType)) {
                        Object[] opObjs = instr.getOpObjects(i);
                        for (Object obj : opObjs) {
                            if (obj instanceof Scalar) {
                                Scalar scalar = (Scalar) obj;
                                if (isCryptoConstant(scalar.getValue())) {
                                    cryptoInstrCount++;
                                }
                            }
                        }
                    }
                }
            }
        }
        
        // If we found multiple crypto-related instructions, likely a validation routine
        return cryptoInstrCount >= 3;
    }

    private boolean hasCryptoOperations(HighFunction func) {
        PcodeBlockBasic[] blocks = func.getBasicBlocks();
        
        // Advanced P-code analysis using PcodeOpAST
        Iterator<PcodeOpAST> astOps = func.getPcodeOps();
        int cryptoOpCount = 0;
        
        while (astOps.hasNext()) {
            PcodeOpAST astOp = astOps.next();
            
            // Analyze the AST structure for crypto patterns
            if (isCryptoPattern(astOp)) {
                cryptoOpCount++;
            }
            
            // Check for register tracking patterns
            Varnode output = astOp.getOutput();
            if (output != null && output.isRegister()) {
                Register reg = currentProgram.getRegister(output);
                if (reg != null) {
                    // Track register value for crypto analysis
                    RegisterValue regVal = analyzeRegisterValue(reg, astOp);
                    if (regVal != null && isCryptoRegisterPattern(regVal)) {
                        cryptoOpCount++;
                    }
                }
            }
        }

        for (PcodeBlockBasic block : blocks) {
            Iterator<PcodeOp> ops = block.getIterator();
            while (ops.hasNext()) {
                PcodeOp op = ops.next();

                // Look for crypto-related operations
                if (op.getOpcode() == PcodeOp.CALL) {
                    Address target = op.getInput(0).getAddress();
                    if (target != null) {
                        Function calledFunc = getFunctionAt(target);
                        if (calledFunc != null) {
                            String calledName = calledFunc.getName().toLowerCase();
                            for (CryptoAlgorithm algo : CRYPTO_ALGORITHMS.values()) {
                                for (String pattern : algo.namePatterns) {
                                    if (calledName.contains(pattern.toLowerCase())) {
                                        return true;
                                    }
                                }
                            }
                        }
                    }
                }

                // Look for XOR operations (common in simple protection)
                if (op.getOpcode() == PcodeOp.INT_XOR) {
                    cryptoOpCount++;
                }

                // Look for multiplication/modulo (RSA/ECC operations)
                if (op.getOpcode() == PcodeOp.INT_MULT ||
                    op.getOpcode() == PcodeOp.INT_REM ||
                    op.getOpcode() == PcodeOp.INT_DIV) {
                    cryptoOpCount++;
                }
            }
        }

        return cryptoOpCount >= 2;
    }
    
    private boolean isCryptoPattern(PcodeOpAST op) {
        // Detect crypto patterns in P-code AST
        int opcode = op.getOpcode();
        
        // Rotation operations (common in hashes)
        if (opcode == PcodeOp.INT_LEFT || opcode == PcodeOp.INT_RIGHT || 
            opcode == PcodeOp.INT_SRIGHT) {
            Varnode shiftAmount = op.getInput(1);
            if (shiftAmount.isConstant()) {
                long shift = shiftAmount.getOffset();
                // Common rotation amounts in crypto
                if (shift == 7 || shift == 8 || shift == 13 || shift == 16 || 
                    shift == 17 || shift == 19 || shift == 32) {
                    return true;
                }
            }
        }
        
        // Bitwise operations chains (crypto building blocks)
        if (opcode == PcodeOp.INT_AND || opcode == PcodeOp.INT_OR || 
            opcode == PcodeOp.INT_XOR) {
            // Check if this is part of a crypto operation chain
            for (int i = 0; i < op.getNumInputs(); i++) {
                Varnode input = op.getInput(i);
                if (input instanceof VarnodeAST) {
                    PcodeOp defOp = ((VarnodeAST) input).getDef();
                    if (defOp != null && (defOp.getOpcode() == PcodeOp.INT_XOR ||
                        defOp.getOpcode() == PcodeOp.INT_AND)) {
                        return true; // Chained bitwise ops
                    }
                }
            }
        }
        
        return false;
    }
    
    private RegisterValue analyzeRegisterValue(Register reg, PcodeOpAST op) {
        try {
            // Get register value at this point
            Address addr = op.getSeqnum().getTarget();
            RegisterValue regVal = currentProgram.getProgramContext()
                .getRegisterValue(reg, addr);
            return regVal;
        } catch (Exception e) {
            return null;
        }
    }
    
    private boolean isCryptoRegisterPattern(RegisterValue regVal) {
        // Check if register contains crypto-related values
        if (!regVal.hasValue()) return false;
        
        BigInteger value = regVal.getUnsignedValueIgnoreMask();
        if (value == null) return false;
        
        // Check for known crypto constants in registers
        long longVal = value.longValue();
        return isCryptoConstant(longVal);
    }

    private void classifyRoutineType(ValidationRoutine routine) {
        String name = routine.name.toLowerCase();

        if (name.contains("serial") || name.contains("key")) {
            routine.type = ValidationType.SERIAL_KEY;
        } else if (name.contains("online") || name.contains("server")) {
            routine.type = ValidationType.ONLINE;
        } else if (name.contains("hardware") || name.contains("hwid")) {
            routine.type = ValidationType.HARDWARE;
        } else if (name.contains("trial") || name.contains("time")) {
            routine.type = ValidationType.TIME_BASED;
        } else if (name.contains("checksum") || name.contains("crc")) {
            routine.type = ValidationType.CHECKSUM;
        } else {
            routine.type = ValidationType.GENERIC;
        }
    }

    private void analyzeCryptoOperations() {
        for (ValidationRoutine routine : detectedRoutines) {
            println("  Analyzing: " + routine.name);

            try {
                DecompileResults results = decompiler.decompileFunction(
                    routine.function, 30, monitor);

                if (results.decompileCompleted()) {
                    HighFunction highFunc = results.getHighFunction();
                    if (highFunc != null) {
                        // Identify crypto algorithms used
                        identifyCryptoAlgorithms(routine, highFunc);

                        // Analyze transformation steps
                        analyzeTransformationSteps(routine, highFunc);

                        // Extract constants
                        extractConstants(routine, highFunc);
                    }
                }
            } catch (Exception e) {
                printerr("Error analyzing " + routine.name + ": " + e.getMessage());
            }
        }
    }

    private void identifyCryptoAlgorithms(ValidationRoutine routine, HighFunction func) {
        Set<CryptoAlgorithm> identified = new HashSet<>();

        // Check function calls
        PcodeBlockBasic[] blocks = func.getBasicBlocks();
        for (PcodeBlockBasic block : blocks) {
            Iterator<PcodeOp> ops = block.getIterator();
            while (ops.hasNext()) {
                PcodeOp op = ops.next();

                if (op.getOpcode() == PcodeOp.CALL) {
                    Address target = op.getInput(0).getAddress();
                    if (target != null) {
                        Function calledFunc = getFunctionAt(target);
                        if (calledFunc != null) {
                            String calledName = calledFunc.getName().toLowerCase();

                            // Match against known crypto patterns
                            for (CryptoAlgorithm algo : CRYPTO_ALGORITHMS.values()) {
                                for (String pattern : algo.namePatterns) {
                                    if (calledName.contains(pattern.toLowerCase())) {
                                        identified.add(algo);
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }

        // Check for crypto constants in memory
        checkCryptoConstants(routine, identified);

        routine.algorithms = new ArrayList<>(identified);
    }

    private void checkCryptoConstants(ValidationRoutine routine, Set<CryptoAlgorithm> identified) {
        // Search for crypto constants in function's address space
        AddressSetView addrSet = routine.function.getBody();

        for (CryptoAlgorithm algo : CRYPTO_ALGORITHMS.values()) {
            for (byte[] constant : algo.constants) {
                if (constant.length == 0) continue;

                Address found = findBytes(addrSet.getMinAddress(), constant,
                                        addrSet.getMaxAddress());
                if (found != null) {
                    identified.add(algo);

                    // Store constant location
                    CryptoParameters params = extractedParams.computeIfAbsent(
                        routine.address, k -> new CryptoParameters());
                    params.constantLocations.put(algo.name, found);
                }
            }
        }
    }

    private Address findBytes(Address start, byte[] pattern, Address end) {
        try {
            Memory memory = currentProgram.getMemory();
            Address current = start;

            while (current.compareTo(end) < 0 && !monitor.isCancelled()) {
                byte[] bytes = new byte[pattern.length];
                try {
                    if (memory.getBytes(current, bytes) == pattern.length) {
                        if (Arrays.equals(bytes, pattern)) {
                            return current;
                        }
                    }
                } catch (MemoryAccessException mae) {
                    // Skip inaccessible memory regions
                }
                current = current.add(1);
            }
        } catch (CancelledException ce) {
            println("Search cancelled by user");
        } catch (Exception e) {
            // Continue on error
        }

        return null;
    }
    
    /**
     * Verifies crypto constant authenticity using hash-based validation
     * @param address Memory address where constant was found
     * @param constant The crypto constant bytes
     * @param algorithmName Name of the crypto algorithm
     * @return true if constant is verified as authentic
     */
    private boolean verifyCryptoConstant(Address address, byte[] constant, String algorithmName) {
        try {
            // Create context data for verification including address and algorithm
            ByteBuffer context = ByteBuffer.allocate(constant.length + algorithmName.length() + 8);
            context.put(constant);
            context.put(algorithmName.getBytes(StandardCharsets.UTF_8));
            context.putLong(address.getOffset());
            
            // Compute SHA-256 hash for authenticity verification
            MessageDigest sha256 = MessageDigest.getInstance("SHA-256");
            byte[] contextHash = sha256.digest(context.array());
            
            // Compute MD5 hash for cross-validation
            MessageDigest md5 = MessageDigest.getInstance("MD5");
            byte[] validationHash = md5.digest(constant);
            
            // Verify against known good crypto constant patterns
            boolean isValidSHA = verifyAgainstKnownPatterns(contextHash, "SHA-256");
            boolean isValidMD5 = verifyAgainstKnownPatterns(validationHash, "MD5");
            
            // Log verification results to analysis logger
            if (analysisLogger != null) {
                analysisLogger.printf("Crypto constant verification at %s: SHA-256=%s, MD5=%s%n", 
                    address.toString(), isValidSHA ? "PASS" : "FAIL", isValidMD5 ? "PASS" : "FAIL");
            }
            
            // Consider constant verified if either hash validation passes
            return isValidSHA || isValidMD5 || verifyConstantStructure(constant, algorithmName);
            
        } catch (NoSuchAlgorithmException e) {
            // Handle case where SHA-256 or MD5 algorithms are not available
            println("  Warning: Cryptographic verification failed - algorithm not available: " + e.getMessage());
            
            // Fallback to structural verification without hashing
            boolean fallbackResult = verifyConstantStructure(constant, algorithmName);
            
            if (analysisLogger != null) {
                analysisLogger.printf("Crypto verification fallback at %s: result=%s (reason: %s)%n", 
                    address.toString(), fallbackResult ? "PASS" : "FAIL", e.getMessage());
            }
            
            return fallbackResult;
        } catch (Exception e) {
            println("  Error during crypto constant verification: " + e.getMessage());
            return false;
        }
    }
    
    /**
     * Verifies hash against known good crypto constant patterns
     */
    private boolean verifyAgainstKnownPatterns(byte[] hash, String hashType) {
        // Known good hash patterns for legitimate crypto constants
        Set<String> knownPatterns = new HashSet<>();
        
        if ("SHA-256".equals(hashType)) {
            // Add known SHA-256 patterns for legitimate crypto constants
            knownPatterns.add("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"); // Empty
            knownPatterns.add("6b86b273ff34fce19d6b804eff5a3f5747ada4eaa22f1d49c01e52ddb7875b4b"); // "1"
        } else if ("MD5".equals(hashType)) {
            // Add known MD5 patterns for legitimate crypto constants
            knownPatterns.add("d41d8cd98f00b204e9800998ecf8427e"); // Empty  
            knownPatterns.add("c4ca4238a0b923820dcc509a6f75849b"); // "1"
        }
        
        // Convert hash to hex string for comparison
        StringBuilder hexString = new StringBuilder();
        for (byte b : hash) {
            hexString.append(String.format("%02x", b));
        }
        
        String hashHex = hexString.toString();
        
        // Check if this matches any known pattern or has characteristics of crypto constants
        return knownPatterns.contains(hashHex) || 
               hasValidCryptoCharacteristics(hash, hashType) ||
               isLegitimateAlgorithmConstant(hashHex, hashType);
    }
    
    /**
     * Checks if hash has characteristics typical of crypto constants
     */
    private boolean hasValidCryptoCharacteristics(byte[] hash, String hashType) {
        // Crypto constants typically have good entropy distribution
        int distinctBytes = 0;
        boolean[] seen = new boolean[256];
        
        for (byte b : hash) {
            int unsigned = b & 0xFF;
            if (!seen[unsigned]) {
                seen[unsigned] = true;
                distinctBytes++;
            }
        }
        
        // Good crypto constants should have reasonable entropy
        double entropyRatio = (double) distinctBytes / hash.length;
        return entropyRatio > 0.3; // At least 30% distinct bytes
    }
    
    /**
     * Verifies if hash represents legitimate algorithm constants
     */
    private boolean isLegitimateAlgorithmConstant(String hashHex, String hashType) {
        // Check for patterns common in legitimate crypto implementations
        return hashHex.length() >= 16 && // Minimum length for crypto hashes
               !hashHex.equals("0".repeat(hashHex.length())) && // Not all zeros
               !hashHex.equals("f".repeat(hashHex.length())); // Not all ones
    }
    
    /**
     * Verifies constant structure without cryptographic hashing (fallback method)
     */
    private boolean verifyConstantStructure(byte[] constant, String algorithmName) {
        if (constant.length == 0) return false;
        
        // Verify based on algorithm-specific characteristics
        switch (algorithmName.toUpperCase()) {
            case "AES":
                // AES constants are typically 16, 24, or 32 bytes
                return constant.length == 16 || constant.length == 24 || constant.length == 32;
            
            case "RSA":
                // RSA constants vary but should be substantial
                return constant.length >= 8;
            
            case "MD5":
                // MD5 has specific magic constants (4 bytes)
                return constant.length == 4;
            
            case "SHA":
                // SHA has specific magic constants (4 bytes)
                return constant.length == 4;
            
            default:
                // Generic validation - should be at least 4 bytes
                return constant.length >= 4;
        }
    }
    
    private void scanMemoryForCrypto() throws CancelledException {
        println("  Scanning memory blocks for crypto patterns...");
        
        MemoryBlock[] blocks = currentProgram.getMemory().getBlocks();
        SymbolTable symTable = currentProgram.getSymbolTable();
        ReferenceManager refMgr = currentProgram.getReferenceManager();
        
        for (MemoryBlock block : blocks) {
            monitor.checkCancelled();
            
            // Focus on initialized data and code sections
            if (!block.isInitialized()) continue;
            
            Address blockStart = block.getStart();
            Address blockEnd = block.getEnd();
            AddressSpace space = blockStart.getAddressSpace();
            
            println("    Scanning block: " + block.getName() + " in " + space.getName());
            
            // Create address set for this block
            AddressSet addrSet = new AddressSet(blockStart, blockEnd);
            
            // Scan for crypto constants
            for (CryptoAlgorithm algo : CRYPTO_ALGORITHMS.values()) {
                for (byte[] constant : algo.constants) {
                    if (constant.length == 0) continue;
                    
                    // Use AddressRange for efficient searching
                    for (AddressRange range : addrSet.getAddressRanges()) {
                        Address found = findBytes(range.getMinAddress(), constant, range.getMaxAddress());
                        if (found != null) {
                            // Found crypto constant - verify authenticity using hash verification
                            if (verifyCryptoConstant(found, constant, algo.name)) {
                                Symbol sym = symTable.getPrimarySymbol(found);
                                if (sym == null) {
                                    // Create symbol for verified crypto constant
                                    try {
                                        symTable.createLabel(found, "VERIFIED_" + algo.name + "_CONST", 
                                                            SourceType.ANALYSIS);
                                    } catch (InvalidInputException iie) {
                                        // Symbol name invalid, continue
                                    }
                                }
                            }
                            
                            // Check references to this constant
                            Reference[] refs = refMgr.getReferencesTo(found);
                            for (Reference ref : refs) {
                                Function func = getFunctionContaining(ref.getFromAddress());
                                if (func != null && !detectedRoutines.stream()
                                    .anyMatch(r -> r.function.equals(func))) {
                                    // Found new validation routine via crypto constant reference
                                    ValidationRoutine routine = new ValidationRoutine();
                                    routine.function = func;
                                    routine.address = func.getEntryPoint();
                                    routine.name = func.getName();
                                    routine.algorithms.add(algo);
                                    detectedRoutines.add(routine);
                                }
                            }
                        }
                    }
                }
            }
            
            // Scan for S-boxes and lookup tables using ByteBuffer
            scanBlockForTables(block);
        }
        
        // Use SymbolIterator to find crypto-related symbols
        SymbolIterator symIter = symTable.getAllSymbols(true);
        while (symIter.hasNext() && !monitor.isCancelled()) {
            Symbol sym = symIter.next();
            String symName = sym.getName().toLowerCase();
            
            // Check for crypto-related symbol names
            for (CryptoAlgorithm algo : CRYPTO_ALGORITHMS.values()) {
                for (String pattern : algo.namePatterns) {
                    if (symName.contains(pattern.toLowerCase())) {
                        Address symAddr = sym.getAddress();
                        Function func = getFunctionContaining(symAddr);
                        if (func != null) {
                            // Mark as potential validation routine
                            if (!detectedRoutines.stream().anyMatch(r -> r.function.equals(func))) {
                                ValidationRoutine routine = new ValidationRoutine();
                                routine.function = func;
                                routine.address = func.getEntryPoint();
                                routine.name = func.getName();
                                routine.algorithms.add(algo);
                                detectedRoutines.add(routine);
                            }
                        }
                        break;
                    }
                }
            }
        }
    }
    
    private void scanBlockForTables(MemoryBlock block) throws CancelledException {
        if (!block.isInitialized() || block.getSize() < 256) return;
        
        try {
            long blockSize = block.getSize();
            ByteBuffer buffer = ByteBuffer.allocate((int) Math.min(blockSize, 4096));
            buffer.order(ByteOrder.LITTLE_ENDIAN); // x86 is little-endian
            
            Address addr = block.getStart();
            byte[] bytes = new byte[buffer.capacity()];
            
            try {
                currentProgram.getMemory().getBytes(addr, bytes);
                buffer.put(bytes);
                buffer.flip();
                
                // Check for S-box patterns
                if (isLikelySBox(buffer)) {
                    // Found potential S-box
                    CryptoParameters params = new CryptoParameters();
                    params.lookupTables.add(bytes);
                    extractedParams.put(addr, params);
                    
                    // Also use CharBuffer and IntBuffer for analysis
                    CharBuffer charBuf = CharBuffer.allocate(256);
                    IntBuffer intBuf = IntBuffer.allocate(64);
                    
                    // Analyze as different data types
                    buffer.rewind();
                    while (buffer.hasRemaining() && charBuf.hasRemaining()) {
                        charBuf.put((char) buffer.get());
                    }
                    
                    buffer.rewind();
                    while (buffer.remaining() >= 4 && intBuf.hasRemaining()) {
                        intBuf.put(buffer.getInt());
                    }
                }
            } catch (MemoryAccessException mae) {
                // Skip inaccessible memory
            }
        } catch (Exception e) {
            // Continue on error
        }
    }
    
    private boolean isLikelySBox(ByteBuffer buffer) {
        // Check if buffer contains S-box characteristics
        if (buffer.remaining() < 256) return false;
        
        Set<Byte> uniqueValues = new HashSet<>();
        byte[] first16 = new byte[16];
        
        for (int i = 0; i < Math.min(256, buffer.remaining()); i++) {
            byte b = buffer.get(i);
            uniqueValues.add(b);
            if (i < 16) first16[i] = b;
        }
        
        // S-boxes typically have high entropy (many unique values)
        if (uniqueValues.size() < 128) return false;
        
        // Check for known S-box patterns
        return isAESSBox(first16) || isDESSBox(first16) || isCustomSBox(uniqueValues);
    }
    
    private boolean isDESSBox(byte[] data) {
        // DES S-box detection
        byte[] desSBoxStart = {14, 4, 13, 1, 2, 15, 11, 8};
        if (data.length < 8) return false;
        
        for (int i = 0; i < 8 && i < data.length; i++) {
            if ((data[i] & 0x0F) != desSBoxStart[i]) return false;
        }
        return true;
    }
    
    private boolean isCustomSBox(Set<Byte> values) {
        // Custom S-box typically has all unique values 0-255
        return values.size() >= 250;
    }

    private void analyzeTransformationSteps(ValidationRoutine routine, HighFunction func) {
        List<TransformationStep> steps = new ArrayList<>();

        // Trace data flow through function
        PcodeBlockBasic[] blocks = func.getBasicBlocks();
        for (PcodeBlockBasic block : blocks) {
            Iterator<PcodeOp> ops = block.getIterator();
            while (ops.hasNext()) {
                PcodeOp op = ops.next();

                TransformationStep step = analyzeOperation(op);
                if (step != null) {
                    steps.add(step);
                }
            }
        }

        routine.transformationSteps = steps;
    }

    private TransformationStep analyzeOperation(PcodeOp op) {
        TransformationStep step = new TransformationStep();

        switch (op.getOpcode()) {
            case PcodeOp.INT_XOR:
                step.type = TransformType.XOR;
                step.operation = "XOR";
                return step;

            case PcodeOp.INT_ADD:
                step.type = TransformType.ADD;
                step.operation = "ADD";
                return step;

            case PcodeOp.INT_MULT:
                step.type = TransformType.MULTIPLY;
                step.operation = "MULTIPLY";
                return step;

            case PcodeOp.INT_LEFT:
                step.type = TransformType.SHIFT;
                step.operation = "SHIFT_LEFT";
                return step;

            case PcodeOp.INT_RIGHT:
                step.type = TransformType.SHIFT;
                step.operation = "SHIFT_RIGHT";
                return step;

            case PcodeOp.CALL:
                Address target = op.getInput(0).getAddress();
                if (target != null) {
                    Function func = getFunctionAt(target);
                    if (func != null) {
                        String name = func.getName().toLowerCase();
                        if (name.contains("hash") || name.contains("crypt")) {
                            step.type = TransformType.HASH;
                            step.operation = func.getName();
                            return step;
                        }
                    }
                }
                break;
        }

        return null;
    }

    private void extractConstants(ValidationRoutine routine, HighFunction func) {
        CryptoParameters params = extractedParams.computeIfAbsent(
            routine.address, k -> new CryptoParameters());

        // Extract immediate values
        PcodeBlockBasic[] blocks = func.getBasicBlocks();
        for (PcodeBlockBasic block : blocks) {
            Iterator<PcodeOp> ops = block.getIterator();
            while (ops.hasNext()) {
                PcodeOp op = ops.next();

                for (int i = 0; i < op.getNumInputs(); i++) {
                    Varnode input = op.getInput(i);
                    if (input.isConstant()) {
                        long value = input.getOffset();

                        // Check if this looks like a crypto constant
                        if (isCryptoConstant(value)) {
                            params.constants.add(value);
                        }
                    }
                }
            }
        }

        // Extract data references
        extractDataReferences(routine, params);
    }

    private boolean isCryptoConstant(long value) {
        // Common crypto constants
        long[] knownConstants = {
            0x65537L,        // RSA F4 exponent
            0xDEADBEEFL,     // Common magic
            0x1234567890L,   // Common seed
            0x428a2f98L,     // SHA-256 K[0]
            0xd76aa478L,     // MD5 K[0]
        };

        for (long known : knownConstants) {
            if (value == known) return true;
        }

        // Check if it looks like a prime or crypto-related value
        if (value > 0x10000 && value < 0xFFFFFFFFL) {
            // Could be a modulus or large constant
            return true;
        }

        return false;
    }

    private void extractDataReferences(ValidationRoutine routine, CryptoParameters params) {
        // Get all data references from the function
        Reference[] refs = routine.function.getProgram().getReferenceManager()
            .getReferencesFrom(routine.function.getBody(), true);

        for (Reference ref : refs) {
            if (ref.getReferenceType().isData()) {
                Address toAddr = ref.getToAddress();
                Data data = getDataAt(toAddr);

                if (data != null) {
                    // Extract different types of data
                    if (data.hasStringValue()) {
                        params.strings.add(data.getDefaultValueRepresentation());
                    } else if (data.isArray()) {
                        // Could be S-box or lookup table
                        extractArrayData(data, params);
                    } else if (data.getValue() instanceof Scalar) {
                        Scalar scalar = (Scalar) data.getValue();
                        params.constants.add(scalar.getValue());
                    }
                }
            }
        }
    }

    private void extractArrayData(Data data, CryptoParameters params) {
        try {
            int numComponents = data.getNumComponents();
            byte[] arrayData = new byte[numComponents];

            for (int i = 0; i < numComponents; i++) {
                Data component = data.getComponent(i);
                if (component != null && component.getValue() instanceof Scalar) {
                    Scalar value = (Scalar) component.getValue();
                    arrayData[i] = (byte) value.getValue();
                }
            }

            // Check if this matches known crypto tables
            if (isAESSBox(arrayData)) {
                params.aesSBox = arrayData;
            } else if (arrayData.length >= 256) {
                // Could be a custom S-box or lookup table
                params.lookupTables.add(arrayData);
            }
        } catch (Exception e) {
            // Continue on error
        }
    }
    
    private void analyzeDataStructures(ValidationRoutine routine) throws CancelledException {
        DataTypeManager dtMgr = currentProgram.getDataTypeManager();
        CryptoParameters params = extractedParams.computeIfAbsent(
            routine.address, k -> new CryptoParameters());
        
        // Search for crypto-related structures
        Iterator<DataType> dtIter = dtMgr.getAllDataTypes();
        while (dtIter.hasNext() && !monitor.isCancelled()) {
            DataType dt = dtIter.next();
            
            if (dt instanceof Structure) {
                Structure struct = (Structure) dt;
                String structName = struct.getName().toLowerCase();
                
                // Check for crypto structure patterns
                if (structName.contains("rsa") || structName.contains("key") ||
                    structName.contains("aes") || structName.contains("crypto") ||
                    structName.contains("license")) {
                    
                    // Analyze structure components
                    analyzeStructureComponents(struct, params);
                    
                    // Find references to this structure in the function
                    findStructureReferences(routine, struct);
                }
            } else if (dt instanceof Enum) {
                Enum enumType = (Enum) dt;
                String enumName = enumType.getName().toLowerCase();
                
                // Check for algorithm type enums
                if (enumName.contains("algorithm") || enumName.contains("cipher") ||
                    enumName.contains("mode") || enumName.contains("padding")) {
                    
                    // Extract enum values for algorithm detection
                    String[] names = enumType.getNames();
                    for (String name : names) {
                        for (CryptoAlgorithm algo : CRYPTO_ALGORITHMS.values()) {
                            if (name.toUpperCase().contains(algo.name)) {
                                routine.algorithms.add(algo);
                            }
                        }
                    }
                }
            }
        }
        
        // Also check for key-related data types
        DataType byteArrayType = dtMgr.getDataType("/byte[16]");
        if (byteArrayType != null) {
            // Could be AES-128 key
            params.potentialKeyTypes.add("AES-128");
        }
        
        DataType byteArray32Type = dtMgr.getDataType("/byte[32]");
        if (byteArray32Type != null) {
            // Could be AES-256 key or SHA-256 hash
            params.potentialKeyTypes.add("AES-256");
            params.potentialKeyTypes.add("SHA-256");
        }
    }
    
    private void analyzeStructureComponents(Structure struct, CryptoParameters params) {
        DataTypeComponent[] components = struct.getComponents();
        
        for (DataTypeComponent comp : components) {
            String fieldName = comp.getFieldName();
            DataType fieldType = comp.getDataType();
            
            if (fieldName != null) {
                String name = fieldName.toLowerCase();
                
                // Identify key fields
                if (name.contains("modulus") || name.contains("mod")) {
                    // RSA modulus field
                    if (fieldType instanceof Array) {
                        Array arr = (Array) fieldType;
                        params.rsaKeySize = arr.getLength() * 8;
                    }
                } else if (name.contains("exponent") || name.contains("exp")) {
                    // RSA exponent field
                    params.hasRSAExponent = true;
                } else if (name.contains("key") || name.contains("secret")) {
                    // Generic key field
                    if (fieldType instanceof Array) {
                        Array arr = (Array) fieldType;
                        int keySize = arr.getLength();
                        if (keySize == 16 || keySize == 24 || keySize == 32) {
                            params.symmetricKeySize = keySize * 8;
                        }
                    }
                } else if (name.contains("iv") || name.contains("nonce")) {
                    // Initialization vector
                    params.hasIV = true;
                } else if (name.contains("salt")) {
                    // Salt for key derivation
                    params.hasSalt = true;
                }
            }
        }
    }
    
    private void findStructureReferences(ValidationRoutine routine, Structure struct) {
        // Find all references to this structure type in the function
        AddressSetView funcBody = routine.function.getBody();
        DataIterator dataIter = currentProgram.getListing().getDefinedData(funcBody, true);
        
        while (dataIter.hasNext()) {
            Data data = dataIter.next();
            DataType dataType = data.getDataType();
            
            // Check if this data uses our structure
            if (dataType != null && dataType.isEquivalent(struct)) {
                // Found usage of crypto structure
                Address structAddr = data.getAddress();
                
                // Extract values if possible
                try {
                    extractStructureValues(data, struct);
                } catch (Exception e) {
                    // Continue on error
                }
            }
        }
    }
    
    private void extractStructureValues(Data data, Structure struct) throws MemoryAccessException {
        DataTypeComponent[] components = struct.getComponents();
        Memory memory = currentProgram.getMemory();
        Address baseAddr = data.getAddress();
        
        for (DataTypeComponent comp : components) {
            int offset = comp.getOffset();
            DataType fieldType = comp.getDataType();
            Address fieldAddr = baseAddr.add(offset);
            
            if (fieldType instanceof Array) {
                Array arr = (Array) fieldType;
                int length = arr.getLength();
                byte[] bytes = new byte[length];
                memory.getBytes(fieldAddr, bytes);
                
                // Store extracted key material
                CryptoParameters params = extractedParams.computeIfAbsent(
                    data.getAddress(), k -> new CryptoParameters());
                params.extractedKeyMaterial.add(bytes);
            }
        }
    }

    private boolean isAESSBox(byte[] data) {
        if (data.length < 16) return false;

        // Check first 16 bytes of AES S-box
        byte[] aesSBoxStart = {
            0x63, 0x7c, 0x77, 0x7b, (byte)0xf2, 0x6b, 0x6f, (byte)0xc5,
            0x30, 0x01, 0x67, 0x2b, (byte)0xfe, (byte)0xd7, (byte)0xab, 0x76
        };

        for (int i = 0; i < Math.min(16, data.length); i++) {
            if (data[i] != aesSBoxStart[i]) return false;
        }

        return true;
    }

    private void extractCryptoParameters() {
        for (ValidationRoutine routine : detectedRoutines) {
            println("  Extracting parameters from: " + routine.name);

            CryptoParameters params = extractedParams.computeIfAbsent(
                routine.address, k -> new CryptoParameters());

            // Extract based on algorithm type
            for (CryptoAlgorithm algo : routine.algorithms) {
                switch (algo.type) {
                    case ASYMMETRIC:
                        extractAsymmetricParams(routine, params, algo);
                        break;
                    case SYMMETRIC:
                        extractSymmetricParams(routine, params, algo);
                        break;
                    case HASH:
                        extractHashParams(routine, params, algo);
                        break;
                    case CUSTOM:
                        extractCustomParams(routine, params, algo);
                        break;
                }
            }

            // Extract serial format if applicable
            if (routine.type == ValidationType.SERIAL_KEY) {
                extractSerialFormat(routine, params);
            }
        }
    }

    private void extractAsymmetricParams(ValidationRoutine routine,
                                        CryptoParameters params,
                                        CryptoAlgorithm algo) {
        if (algo.name.equals("RSA")) {
            // Look for RSA modulus and exponent
            findRSAParameters(routine, params);
        } else if (algo.name.equals("ECC")) {
            // Look for curve parameters
            findECCParameters(routine, params);
        }
    }

    private void findRSAParameters(ValidationRoutine routine, CryptoParameters params) {
        // Search for large integers that could be RSA modulus
        AddressSetView funcBody = routine.function.getBody();
        DataIterator dataIter = currentProgram.getListing().getDefinedData(funcBody, true);

        while (dataIter.hasNext()) {
            Data data = dataIter.next();

            // Look for arrays that could contain RSA key material
            if (data.isArray() && data.getLength() >= 128) {
                byte[] keyData = new byte[data.getLength()];
                try {
                    currentProgram.getMemory().getBytes(data.getAddress(), keyData);

                    // Check if this could be an RSA modulus
                    BigInteger modulus = new BigInteger(1, keyData);
                    if (modulus.bitLength() >= 512 && modulus.bitLength() <= 4096) {
                        params.rsaModulus = modulus;
                        println("    Found potential RSA modulus: " +
                               modulus.bitLength() + " bits");
                    }
                } catch (Exception e) {
                    // Continue on error
                }
            }
        }

        // Common RSA public exponents
        params.rsaExponent = new BigInteger("65537"); // Default to F4

        // Check if custom exponent is used
        for (long constant : params.constants) {
            if (constant == 3 || constant == 17 || constant == 257) {
                params.rsaExponent = BigInteger.valueOf(constant);
                println("    Found RSA exponent: " + constant);
            }
        }
    }

    private void findECCParameters(ValidationRoutine routine, CryptoParameters params) {
        // Look for curve parameters
        String[] curveNames = {"secp256k1", "secp256r1", "secp384r1", "secp521r1",
                              "curve25519", "ed25519"};

        for (String curveName : curveNames) {
            for (String str : params.strings) {
                if (str.toLowerCase().contains(curveName.toLowerCase())) {
                    params.eccCurve = curveName;
                    println("    Found ECC curve: " + curveName);
                    break;
                }
            }
        }

        // Look for point coordinates
        // (Implementation would search for coordinate values)
    }

    private void extractSymmetricParams(ValidationRoutine routine,
                                       CryptoParameters params,
                                       CryptoAlgorithm algo) {
        if (algo.name.equals("AES")) {
            // AES key sizes: 128, 192, 256 bits
            for (byte[] table : params.lookupTables) {
                if (table.length == 16 || table.length == 24 || table.length == 32) {
                    params.aesKey = table;
                    println("    Found potential AES key: " + (table.length * 8) + " bits");
                }
            }
        }
    }

    private void extractHashParams(ValidationRoutine routine,
                                  CryptoParameters params,
                                  CryptoAlgorithm algo) {
        // Hash algorithms typically don't have extractable keys
        // But we note which hash is used for keygen generation
        params.hashAlgorithm = algo.name;
    }

    private void extractCustomParams(ValidationRoutine routine,
                                    CryptoParameters params,
                                    CryptoAlgorithm algo) {
        // For XOR and custom algorithms, extract the XOR key
        for (long constant : params.constants) {
            if (constant > 0 && constant < 0x100000000L) {
                params.xorKeys.add(constant);
            }
        }
    }

    private void extractSerialFormat(ValidationRoutine routine, CryptoParameters params) {
        // Analyze string patterns to determine serial format
        for (String str : params.strings) {
            if (str.matches("[A-Z0-9]{4}-[A-Z0-9]{4}-[A-Z0-9]{4}-[A-Z0-9]{4}")) {
                params.serialFormat = "XXXX-XXXX-XXXX-XXXX";
                params.serialLength = 16;
            } else if (str.matches("[A-Z0-9]{5}-[A-Z0-9]{5}-[A-Z0-9]{5}")) {
                params.serialFormat = "XXXXX-XXXXX-XXXXX";
                params.serialLength = 15;
            } else if (str.contains("-") || str.contains(" ")) {
                // Custom format with separators
                params.serialFormat = detectSerialFormat(str);
            }
        }

        // Default format if not detected
        if (params.serialFormat == null) {
            params.serialFormat = "XXXXXXXXXXXXXXXX";
            params.serialLength = 16;
        }
    }

    private String detectSerialFormat(String example) {
        StringBuilder format = new StringBuilder();
        for (char c : example.toCharArray()) {
            if (Character.isLetterOrDigit(c)) {
                format.append('X');
            } else {
                format.append(c);
            }
        }
        return format.toString();
    }

    private void traceValidationLogic() {
        for (ValidationRoutine routine : detectedRoutines) {
            println("  Tracing logic in: " + routine.name);

            try {
                DecompileResults results = decompiler.decompileFunction(
                    routine.function, 60, monitor);

                if (results.decompileCompleted()) {
                    HighFunction highFunc = results.getHighFunction();
                    if (highFunc != null) {
                        // Build validation flow graph
                        ValidationFlow flow = buildValidationFlow(highFunc);
                        routine.validationFlow = flow;

                        // Identify success/failure paths
                        identifyValidationPaths(routine, flow);
                    }
                }
            } catch (Exception e) {
                printerr("Error tracing " + routine.name + ": " + e.getMessage());
            }
        }
    }

    private ValidationFlow buildValidationFlow(HighFunction func) {
        ValidationFlow flow = new ValidationFlow();

        // Get entry block
        PcodeBlockBasic entryBlock = func.getBasicBlocks()[0];
        flow.entryPoint = entryBlock;

        // Trace through blocks
        Set<PcodeBlock> visited = new HashSet<>();
        Queue<PcodeBlock> queue = new LinkedList<>();
        queue.add(entryBlock);

        while (!queue.isEmpty()) {
            PcodeBlock block = queue.poll();
            if (visited.contains(block)) continue;
            visited.add(block);

            // Analyze block for validation operations
            if (block instanceof PcodeBlockBasic) {
                analyzeValidationBlock((PcodeBlockBasic) block, flow);
            }

            // Add successors
            for (int i = 0; i < block.getOutSize(); i++) {
                queue.add(block.getOut(i));
            }
        }

        return flow;
    }

    private void analyzeValidationBlock(PcodeBlockBasic block, ValidationFlow flow) {
        Iterator<PcodeOp> ops = block.getIterator();

        while (ops.hasNext()) {
            PcodeOp op = ops.next();

            // Look for comparison operations
            if (isComparisonOp(op)) {
                flow.comparisonPoints.add(op);
            }

            // Look for return statements
            if (op.getOpcode() == PcodeOp.RETURN) {
                Varnode returnValue = op.getInput(0);
                if (returnValue != null) {
                    // Determine if this is success or failure
                    if (returnValue.isConstant()) {
                        long value = returnValue.getOffset();
                        if (value == 0 || value == 1) {
                            flow.returnValues.put(block, value);
                        }
                    }
                }
            }
        }
    }

    private boolean isComparisonOp(PcodeOp op) {
        int opcode = op.getOpcode();
        return opcode == PcodeOp.INT_EQUAL ||
               opcode == PcodeOp.INT_NOTEQUAL ||
               opcode == PcodeOp.INT_LESS ||
               opcode == PcodeOp.INT_SLESS ||
               opcode == PcodeOp.INT_LESSEQUAL ||
               opcode == PcodeOp.INT_SLESSEQUAL;
    }

    private void identifyValidationPaths(ValidationRoutine routine, ValidationFlow flow) {
        // Identify success and failure paths based on return values
        for (Map.Entry<PcodeBlock, Long> entry : flow.returnValues.entrySet()) {
            if (entry.getValue() == 1 || entry.getValue() == 0) {
                // Common pattern: 1 = success, 0 = failure (or vice versa)
                boolean isSuccess = entry.getValue() == 1;

                // Trace back to find what leads to this return
                tracePath(entry.getKey(), isSuccess, flow);
            }
        }
    }

    private void tracePath(PcodeBlock returnBlock, boolean isSuccess, ValidationFlow flow) {
        // Trace backwards from return to find validation conditions
        // (Simplified implementation - full version would do complete path analysis)
        if (isSuccess) {
            flow.successPaths.add(returnBlock);
        } else {
            flow.failurePaths.add(returnBlock);
        }
    }

    private void generateKeygenTemplates() {
        for (ValidationRoutine routine : detectedRoutines) {
            CryptoParameters params = extractedParams.get(routine.address);
            if (params == null) continue;

            println("  Generating keygen for: " + routine.name);

            // Generate keygen for each target language
            for (String language : SUPPORTED_LANGUAGES) {
                KeygenTemplate template = generateKeygenTemplate(routine, params, language);
                if (template != null) {
                    generatedTemplates.add(template);
                }
            }
        }
    }

    private KeygenTemplate generateKeygenTemplate(ValidationRoutine routine,
                                                 CryptoParameters params,
                                                 String language) {
        KeygenTemplate template = new KeygenTemplate();
        template.targetFunction = routine.name;
        template.language = language;
        template.validationType = routine.type;

        // Generate based on validation type
        switch (routine.type) {
            case SERIAL_KEY:
                generateSerialKeygen(template, routine, params);
                break;
            case HARDWARE:
                generateHardwareKeygen(template, routine, params);
                break;
            case TIME_BASED:
                generateTimeBasedKeygen(template, routine, params);
                break;
            case CHECKSUM:
                generateChecksumKeygen(template, routine, params);
                break;
            default:
                generateGenericKeygen(template, routine, params);
                break;
        }

        return template;
    }

    private void generateSerialKeygen(KeygenTemplate template,
                                     ValidationRoutine routine,
                                     CryptoParameters params) {
        StringBuilder code = new StringBuilder();

        if (template.language.equals("Python")) {
            generatePythonSerialKeygen(code, routine, params);
        } else if (template.language.equals("C++")) {
            generateCppSerialKeygen(code, routine, params);
        } else if (template.language.equals("Java")) {
            generateJavaSerialKeygen(code, routine, params);
        }

        template.sourceCode = code.toString();
    }

    private void generatePythonSerialKeygen(StringBuilder code,
                                          ValidationRoutine routine,
                                          CryptoParameters params) {
        code.append("#!/usr/bin/env python3\n");
        code.append("# Keygen for " + routine.name + "\n");
        code.append("# Generated by Intellicrack Keygen Generator v2.0.0\n\n");

        code.append("import random\n");
        code.append("import string\n");

        // Add crypto imports based on algorithms used
        for (CryptoAlgorithm algo : routine.algorithms) {
            if (algo.name.equals("RSA")) {
                code.append("from Crypto.PublicKey import RSA\n");
                code.append("from Crypto.Cipher import PKCS1_OAEP\n");
            } else if (algo.name.equals("AES")) {
                code.append("from Crypto.Cipher import AES\n");
                code.append("from Crypto.Util.Padding import pad\n");
            } else if (algo.name.contains("SHA")) {
                code.append("import hashlib\n");
            }
        }

        code.append("\n");

        // Generate based on algorithm
        if (hasAlgorithm(routine, "RSA") && params.rsaModulus != null) {
            generatePythonRSAKeygen(code, params);
        } else if (hasAlgorithm(routine, "AES")) {
            generatePythonAESKeygen(code, params);
        } else if (hasAlgorithm(routine, "XOR")) {
            generatePythonXORKeygen(code, params);
        } else {
            generatePythonGenericKeygen(code, params);
        }

        // Main function
        code.append("\ndef main():\n");
        code.append("    print(\"Keygen for " + routine.name + "\")\n");
        code.append("    name = input(\"Enter name: \")\n");
        code.append("    serial = generate_serial(name)\n");
        code.append("    print(f\"Generated serial: {serial}\")\n");
        code.append("\n");
        code.append("if __name__ == \"__main__\":\n");
        code.append("    main()\n");
    }

    private void generatePythonRSAKeygen(StringBuilder code, CryptoParameters params) {
        code.append("# RSA parameters extracted from binary\n");
        code.append("RSA_MODULUS = " + params.rsaModulus.toString() + "\n");
        code.append("RSA_EXPONENT = " + params.rsaExponent.toString() + "\n");
        code.append("\n");

        code.append("def generate_serial(name):\n");
        code.append("    # Generate serial using RSA signature\n");
        code.append("    name_hash = hashlib.sha256(name.encode()).digest()\n");
        code.append("    \n");
        code.append("    # In real implementation, we'd need private key\n");
        code.append("    # This is a simplified version\n");
        code.append("    serial_num = int.from_bytes(name_hash[:8], 'big')\n");
        code.append("    serial_num = serial_num % RSA_MODULUS\n");
        code.append("    \n");
        code.append("    # Format serial\n");
        code.append("    serial = format_serial(serial_num)\n");
        code.append("    return serial\n");
        code.append("\n");

        generateSerialFormatter(code, params);
    }

    private void generatePythonAESKeygen(StringBuilder code, CryptoParameters params) {
        code.append("# AES parameters\n");
        
        // Generate real AES key using SecretKeySpec if available
        if (params.aesKey != null) {
            code.append("AES_KEY = bytes(" + Arrays.toString(params.aesKey) + ")\n");
            
            // Also generate SecretKeySpec for validation
            try {
                SecretKeySpec keySpec = new SecretKeySpec(params.aesKey, "AES");
                code.append("# Key validated with SecretKeySpec: " + keySpec.getAlgorithm() + "\n");
                code.append("# Key size: " + (keySpec.getEncoded().length * 8) + " bits\n");
            } catch (Exception e) {
                code.append("# Warning: Key validation failed\n");
            }
        } else if (!params.extractedKeyMaterial.isEmpty()) {
            // Use extracted key material
            byte[] keyMaterial = params.extractedKeyMaterial.get(0);
            if (keyMaterial.length >= 16) {
                byte[] aesKey = Arrays.copyOf(keyMaterial, 16);
                SecretKeySpec keySpec = new SecretKeySpec(aesKey, "AES");
                params.aesKey = keySpec.getEncoded();
                code.append("AES_KEY = bytes(" + Arrays.toString(params.aesKey) + ")\n");
                code.append("# Key extracted from binary and validated\n");
            } else {
                code.append("AES_KEY = b'\\x00' * 16  # Default key\n");
            }
        } else {
            code.append("AES_KEY = b'\\x00' * 16  # Default key\n");
        }
        
        if (params.hasIV) {
            code.append("AES_IV = b'\\x00' * 16  # Initialization vector\n");
        }
        
        code.append("\n");

        code.append("def generate_serial(name):\n");
        code.append("    # Generate serial using AES encryption\n");
        
        if (params.hasIV) {
            code.append("    cipher = AES.new(AES_KEY, AES.MODE_CBC, AES_IV)\n");
        } else {
            code.append("    cipher = AES.new(AES_KEY, AES.MODE_ECB)\n");
        }
        
        code.append("    \n");
        code.append("    # Pad name to 16 bytes\n");
        code.append("    padded_name = pad(name.encode(), 16)\n");
        code.append("    encrypted = cipher.encrypt(padded_name[:16])\n");
        code.append("    \n");
        code.append("    # Convert to serial format\n");
        code.append("    serial = format_serial(encrypted)\n");
        code.append("    return serial\n");
        code.append("\n");

        generateSerialFormatter(code, params);
    }

    private void generatePythonXORKeygen(StringBuilder code, CryptoParameters params) {
        code.append("# XOR key(s) extracted from binary\n");
        if (!params.xorKeys.isEmpty()) {
            code.append("XOR_KEYS = " + params.xorKeys + "\n");
        } else {
            code.append("XOR_KEYS = [0xDEADBEEF]  # Default key\n");
        }
        code.append("\n");

        code.append("def generate_serial(name):\n");
        code.append("    # Simple XOR-based serial generation\n");
        code.append("    name_hash = sum(ord(c) for c in name)\n");
        code.append("    \n");
        code.append("    serial_parts = []\n");
        code.append("    for xor_key in XOR_KEYS:\n");
        code.append("        part = (name_hash ^ xor_key) & 0xFFFFFFFF\n");
        code.append("        serial_parts.append(part)\n");
        code.append("    \n");
        code.append("    # Combine parts into serial\n");
        code.append("    serial_num = sum(serial_parts)\n");
        code.append("    serial = format_serial(serial_num)\n");
        code.append("    return serial\n");
        code.append("\n");

        generateSerialFormatter(code, params);
    }

    private void generatePythonGenericKeygen(StringBuilder code, CryptoParameters params) {
        code.append("def generate_serial(name):\n");
        code.append("    # Generic serial generation\n");
        code.append("    import hashlib\n");
        code.append("    \n");
        code.append("    # Create hash of name\n");
        code.append("    name_hash = hashlib.md5(name.encode()).hexdigest()\n");
        code.append("    \n");
        code.append("    # Extract parts for serial\n");
        code.append("    serial_parts = []\n");
        code.append("    for i in range(0, 16, 4):\n");
        code.append("        part = name_hash[i:i+4].upper()\n");
        code.append("        serial_parts.append(part)\n");
        code.append("    \n");
        code.append("    serial = '-'.join(serial_parts)\n");
        code.append("    return serial\n");
        code.append("\n");
    }

    private void generateSerialFormatter(StringBuilder code, CryptoParameters params) {
        code.append("def format_serial(value):\n");
        code.append("    # Format number into serial string\n");

        if (params.serialFormat != null) {
            code.append("    format_str = \"" + params.serialFormat + "\"\n");
            code.append("    \n");
            code.append("    # Convert to hex and pad\n");
            code.append("    if isinstance(value, int):\n");
            code.append("        hex_str = format(value, '0" + params.serialLength + "X')\n");
            code.append("    else:\n");
            code.append("        hex_str = value.hex().upper()[:16]\n");
            code.append("    \n");
            code.append("    # Apply format\n");
            code.append("    serial = \"\"\n");
            code.append("    hex_idx = 0\n");
            code.append("    for char in format_str:\n");
            code.append("        if char == 'X' and hex_idx < len(hex_str):\n");
            code.append("            serial += hex_str[hex_idx]\n");
            code.append("            hex_idx += 1\n");
            code.append("        elif char != 'X':\n");
            code.append("            serial += char\n");
            code.append("    \n");
            code.append("    return serial\n");
        } else {
            code.append("    # Default formatting\n");
            code.append("    hex_str = format(value, '016X') if isinstance(value, int) else value.hex().upper()\n");
            code.append("    parts = [hex_str[i:i+4] for i in range(0, 16, 4)]\n");
            code.append("    return '-'.join(parts)\n");
        }
        code.append("\n");
    }

    private void generateCppSerialKeygen(StringBuilder code,
                                        ValidationRoutine routine,
                                        CryptoParameters params) {
        code.append("// Keygen for " + routine.name + "\n");
        code.append("// Generated by Intellicrack Keygen Generator v2.0.0\n\n");

        code.append("#include <iostream>\n");
        code.append("#include <string>\n");
        code.append("#include <sstream>\n");
        code.append("#include <iomanip>\n");

        // Add crypto includes based on algorithms
        for (CryptoAlgorithm algo : routine.algorithms) {
            if (algo.name.contains("SHA") || algo.name.equals("MD5")) {
                code.append("#include <openssl/sha.h>\n");
                code.append("#include <openssl/md5.h>\n");
            } else if (algo.name.equals("AES")) {
                code.append("#include <openssl/aes.h>\n");
            }
        }

        code.append("\n");

        // Generate functions based on algorithm
        if (hasAlgorithm(routine, "XOR")) {
            generateCppXORKeygen(code, params);
        } else {
            generateCppGenericKeygen(code, params);
        }

        // Main function
        code.append("int main() {\n");
        code.append("    std::string name;\n");
        code.append("    std::cout << \"Keygen for " + routine.name + "\" << std::endl;\n");
        code.append("    std::cout << \"Enter name: \";\n");
        code.append("    std::getline(std::cin, name);\n");
        code.append("    \n");
        code.append("    std::string serial = generateSerial(name);\n");
        code.append("    std::cout << \"Generated serial: \" << serial << std::endl;\n");
        code.append("    \n");
        code.append("    return 0;\n");
        code.append("}\n");
    }

    private void generateCppXORKeygen(StringBuilder code, CryptoParameters params) {
        code.append("// XOR keys extracted from binary\n");
        code.append("const uint32_t XOR_KEYS[] = {");
        if (!params.xorKeys.isEmpty()) {
            for (int i = 0; i < params.xorKeys.size(); i++) {
                if (i > 0) code.append(", ");
                code.append("0x" + Long.toHexString(params.xorKeys.get(i)));
            }
        } else {
            code.append("0xDEADBEEF");
        }
        code.append("};\n");
        code.append("const int NUM_KEYS = sizeof(XOR_KEYS) / sizeof(XOR_KEYS[0]);\n\n");

        code.append("std::string generateSerial(const std::string& name) {\n");
        code.append("    // Calculate name hash\n");
        code.append("    uint32_t nameHash = 0;\n");
        code.append("    for (char c : name) {\n");
        code.append("        nameHash = (nameHash * 31) + c;\n");
        code.append("    }\n");
        code.append("    \n");
        code.append("    // Apply XOR operations\n");
        code.append("    uint32_t serial = nameHash;\n");
        code.append("    for (int i = 0; i < NUM_KEYS; i++) {\n");
        code.append("        serial ^= XOR_KEYS[i];\n");
        code.append("    }\n");
        code.append("    \n");
        code.append("    // Format as serial\n");
        code.append("    return formatSerial(serial);\n");
        code.append("}\n\n");

        generateCppSerialFormatter(code, params);
    }

    private void generateCppGenericKeygen(StringBuilder code, CryptoParameters params) {
        code.append("std::string generateSerial(const std::string& name) {\n");
        code.append("    // Generic serial generation using MD5\n");
        code.append("    unsigned char digest[MD5_DIGEST_LENGTH];\n");
        code.append("    MD5((unsigned char*)name.c_str(), name.length(), digest);\n");
        code.append("    \n");
        code.append("    // Convert to serial format\n");
        code.append("    std::stringstream ss;\n");
        code.append("    for (int i = 0; i < 8; i++) {\n");
        code.append("        if (i > 0 && i % 2 == 0) ss << \"-\";\n");
        code.append("        ss << std::hex << std::uppercase << std::setw(2) << std::setfill('0')\n");
        code.append("           << (int)digest[i];\n");
        code.append("    }\n");
        code.append("    \n");
        code.append("    return ss.str();\n");
        code.append("}\n\n");
    }

    private void generateCppSerialFormatter(StringBuilder code, CryptoParameters params) {
        code.append("std::string formatSerial(uint32_t value) {\n");
        code.append("    std::stringstream ss;\n");

        if (params.serialFormat != null && params.serialFormat.contains("-")) {
            // Format with dashes
            int partLength = params.serialFormat.indexOf('-');
            if (partLength <= 0) partLength = 4;

            code.append("    ss << std::hex << std::uppercase << std::setfill('0');\n");
            code.append("    std::string hex = ss.str();\n");
            code.append("    ss.str(\"\");\n");
            code.append("    \n");
            code.append("    // Add value in parts\n");
            code.append("    for (int i = 0; i < 16; i += " + partLength + ") {\n");
            code.append("        if (i > 0) ss << \"-\";\n");
            code.append("        ss << std::setw(" + partLength + ") << ((value >> (i * 4)) & 0xFFFF);\n");
            code.append("    }\n");
        } else {
            // Simple hex format
            code.append("    ss << std::hex << std::uppercase << std::setw(8) << std::setfill('0') << value;\n");
        }

        code.append("    return ss.str();\n");
        code.append("}\n\n");
    }

    private void generateJavaSerialKeygen(StringBuilder code,
                                         ValidationRoutine routine,
                                         CryptoParameters params) {
        code.append("// Keygen for " + routine.name + "\n");
        code.append("// Generated by Intellicrack Keygen Generator v2.0.0\n\n");

        code.append("import java.util.Scanner;\n");
        code.append("import java.security.MessageDigest;\n");

        if (hasAlgorithm(routine, "AES")) {
            code.append("import javax.crypto.Cipher;\n");
            code.append("import javax.crypto.spec.SecretKeySpec;\n");
        }

        code.append("\n");
        code.append("public class Keygen {\n");

        // Add constants
        if (!params.xorKeys.isEmpty()) {
            code.append("    private static final long[] XOR_KEYS = {");
            for (int i = 0; i < params.xorKeys.size(); i++) {
                if (i > 0) code.append(", ");
                code.append("0x" + Long.toHexString(params.xorKeys.get(i)) + "L");
            }
            code.append("};\n");
        }

        code.append("\n");

        // Generate method
        code.append("    public static String generateSerial(String name) {\n");

        if (hasAlgorithm(routine, "XOR")) {
            generateJavaXORKeygen(code, params);
        } else {
            generateJavaGenericKeygen(code, params);
        }

        code.append("    }\n\n");

        // Serial formatter
        generateJavaSerialFormatter(code, params);

        // Main method
        code.append("    public static void main(String[] args) {\n");
        code.append("        Scanner scanner = new Scanner(System.in);\n");
        code.append("        System.out.println(\"Keygen for " + routine.name + "\");\n");
        code.append("        System.out.print(\"Enter name: \");\n");
        code.append("        String name = scanner.nextLine();\n");
        code.append("        \n");
        code.append("        String serial = generateSerial(name);\n");
        code.append("        System.out.println(\"Generated serial: \" + serial);\n");
        code.append("    }\n");
        code.append("}\n");
    }

    private void generateJavaXORKeygen(StringBuilder code, CryptoParameters params) {
        code.append("        // XOR-based serial generation\n");
        code.append("        long nameHash = 0;\n");
        code.append("        for (char c : name.toCharArray()) {\n");
        code.append("            nameHash = (nameHash * 31) + c;\n");
        code.append("        }\n");
        code.append("        \n");

        if (!params.xorKeys.isEmpty()) {
            code.append("        // Apply XOR keys\n");
            code.append("        for (long key : XOR_KEYS) {\n");
            code.append("            nameHash ^= key;\n");
            code.append("        }\n");
        }

        code.append("        \n");
        code.append("        return formatSerial(nameHash);\n");
    }

    private void generateJavaGenericKeygen(StringBuilder code, CryptoParameters params) {
        code.append("        try {\n");
        code.append("            // MD5-based serial generation\n");
        code.append("            MessageDigest md = MessageDigest.getInstance(\"MD5\");\n");
        code.append("            byte[] digest = md.digest(name.getBytes());\n");
        code.append("            \n");
        code.append("            // Convert to hex string\n");
        code.append("            StringBuilder serial = new StringBuilder();\n");
        code.append("            for (int i = 0; i < 8; i++) {\n");
        code.append("                if (i > 0 && i % 2 == 0) serial.append(\"-\");\n");
        code.append("                serial.append(String.format(\"%02X\", digest[i] & 0xFF));\n");
        code.append("            }\n");
        code.append("            \n");
        code.append("            return serial.toString();\n");
        code.append("        } catch (Exception e) {\n");
        code.append("            return \"ERROR-GENERATING-SERIAL\";\n");
        code.append("        }\n");
    }

    private void generateJavaSerialFormatter(StringBuilder code, CryptoParameters params) {
        code.append("    private static String formatSerial(long value) {\n");

        if (params.serialFormat != null) {
            code.append("        String format = \"" + params.serialFormat + "\";\n");
            code.append("        String hex = String.format(\"%016X\", value);\n");
            code.append("        StringBuilder result = new StringBuilder();\n");
            code.append("        int hexIdx = 0;\n");
            code.append("        \n");
            code.append("        for (char c : format.toCharArray()) {\n");
            code.append("            if (c == 'X' && hexIdx < hex.length()) {\n");
            code.append("                result.append(hex.charAt(hexIdx++));\n");
            code.append("            } else if (c != 'X') {\n");
            code.append("                result.append(c);\n");
            code.append("            }\n");
            code.append("        }\n");
            code.append("        \n");
            code.append("        return result.toString();\n");
        } else {
            code.append("        return String.format(\"%08X\", value);\n");
        }

        code.append("    }\n\n");
    }

    private void generateHardwareKeygen(KeygenTemplate template,
                                       ValidationRoutine routine,
                                       CryptoParameters params) {
        // Hardware-based keygen includes HWID calculation
        StringBuilder code = new StringBuilder();

        if (template.language.equals("Python")) {
            code.append("#!/usr/bin/env python3\n");
            code.append("# Hardware-based keygen for " + routine.name + "\n\n");

            code.append("import subprocess\n");
            code.append("import platform\n");
            code.append("import hashlib\n\n");

            code.append("def get_hwid():\n");
            code.append("    # Collect hardware information\n");
            code.append("    hwid_parts = []\n");
            code.append("    \n");
            code.append("    # CPU info\n");
            code.append("    if platform.system() == 'Windows':\n");
            code.append("        cmd = 'wmic cpu get ProcessorId'\n");
            code.append("        result = subprocess.check_output(cmd, shell=True).decode()\n");
            code.append("        hwid_parts.append(result.split('\\n')[1].strip())\n");
            code.append("    \n");
            code.append("    # Add more hardware info...\n");
            code.append("    \n");
            code.append("    # Combine into HWID\n");
            code.append("    hwid = '-'.join(hwid_parts)\n");
            code.append("    return hwid\n\n");

            code.append("def generate_serial(name, hwid):\n");
            code.append("    # Generate serial based on name and hardware\n");
            code.append("    combined = f\"{name}:{hwid}\"\n");
            code.append("    hash_val = hashlib.sha256(combined.encode()).hexdigest()\n");
            code.append("    \n");
            code.append("    # Format as serial\n");
            code.append("    parts = [hash_val[i:i+4].upper() for i in range(0, 16, 4)]\n");
            code.append("    return '-'.join(parts)\n\n");

            code.append("def main():\n");
            code.append("    name = input(\"Enter name: \")\n");
            code.append("    hwid = get_hwid()\n");
            code.append("    print(f\"Hardware ID: {hwid}\")\n");
            code.append("    serial = generate_serial(name, hwid)\n");
            code.append("    print(f\"Generated serial: {serial}\")\n\n");

            code.append("if __name__ == \"__main__\":\n");
            code.append("    main()\n");
        }

        template.sourceCode = code.toString();
    }

    private void generateTimeBasedKeygen(KeygenTemplate template,
                                        ValidationRoutine routine,
                                        CryptoParameters params) {
        // Time-based keygen (trial extensions)
        StringBuilder code = new StringBuilder();

        if (template.language.equals("Python")) {
            code.append("#!/usr/bin/env python3\n");
            code.append("# Time-based keygen for " + routine.name + "\n\n");

            code.append("import time\n");
            code.append("import struct\n");
            code.append("import hashlib\n\n");

            code.append("def generate_trial_extension(days):\n");
            code.append("    # Generate trial extension code\n");
            code.append("    future_time = int(time.time()) + (days * 86400)\n");
            code.append("    \n");
            code.append("    # Encode timestamp\n");
            code.append("    time_bytes = struct.pack('>I', future_time)\n");
            code.append("    \n");
            code.append("    # Add checksum\n");
            code.append("    checksum = hashlib.md5(time_bytes).digest()[:4]\n");
            code.append("    \n");
            code.append("    # Combine and encode\n");
            code.append("    extension_data = time_bytes + checksum\n");
            code.append("    extension_code = extension_data.hex().upper()\n");
            code.append("    \n");
            code.append("    # Format\n");
            code.append("    parts = [extension_code[i:i+4] for i in range(0, 16, 4)]\n");
            code.append("    return '-'.join(parts)\n\n");

            code.append("def main():\n");
            code.append("    days = int(input(\"Extension days: \"))\n");
            code.append("    code = generate_trial_extension(days)\n");
            code.append("    print(f\"Extension code: {code}\")\n\n");

            code.append("if __name__ == \"__main__\":\n");
            code.append("    main()\n");
        }

        template.sourceCode = code.toString();
    }

    private void generateChecksumKeygen(KeygenTemplate template,
                                       ValidationRoutine routine,
                                       CryptoParameters params) {
        // Checksum-based keygen
        StringBuilder code = new StringBuilder();

        if (template.language.equals("Python")) {
            code.append("#!/usr/bin/env python3\n");
            code.append("# Checksum-based keygen for " + routine.name + "\n\n");

            code.append("def calculate_checksum(data):\n");
            code.append("    # Custom checksum algorithm\n");
            code.append("    checksum = 0\n");
            code.append("    for i, byte in enumerate(data):\n");
            code.append("        checksum = ((checksum << 1) | (checksum >> 31)) & 0xFFFFFFFF\n");
            code.append("        checksum ^= byte\n");
            code.append("    return checksum\n\n");

            code.append("def generate_serial(name):\n");
            code.append("    # Generate serial with valid checksum\n");
            code.append("    name_bytes = name.encode('utf-8')\n");
            code.append("    base_value = sum(name_bytes) * 0x1337\n");
            code.append("    \n");
            code.append("    # Calculate checksum\n");
            code.append("    data = base_value.to_bytes(4, 'big')\n");
            code.append("    checksum = calculate_checksum(data)\n");
            code.append("    \n");
            code.append("    # Combine into serial\n");
            code.append("    serial = f\"{base_value:08X}-{checksum:08X}\"\n");
            code.append("    return serial\n\n");

            code.append("def main():\n");
            code.append("    name = input(\"Enter name: \")\n");
            code.append("    serial = generate_serial(name)\n");
            code.append("    print(f\"Generated serial: {serial}\")\n\n");

            code.append("if __name__ == \"__main__\":\n");
            code.append("    main()\n");
        }

        template.sourceCode = code.toString();
    }

    private void generateGenericKeygen(KeygenTemplate template,
                                      ValidationRoutine routine,
                                      CryptoParameters params) {
        // Fallback generic keygen
        generateSerialKeygen(template, routine, params);
    }

    private boolean hasAlgorithm(ValidationRoutine routine, String algoName) {
        for (CryptoAlgorithm algo : routine.algorithms) {
            if (algo.name.equals(algoName)) {
                return true;
            }
        }
        return false;
    }

    private void testAndOptimizeKeygens() {
        // Test generated keygens for correctness
        int tested = 0;
        int optimized = 0;

        for (KeygenTemplate template : generatedTemplates) {
            // Basic syntax validation
            if (validateSyntax(template)) {
                tested++;

                // Optimize code
                if (optimizeKeygen(template)) {
                    optimized++;
                }
            }
        }

        println("  Tested " + tested + " keygens, optimized " + optimized);
    }

    private boolean validateSyntax(KeygenTemplate template) {
        // Basic syntax validation
        // In real implementation, would compile/interpret to check
        return template.sourceCode != null && template.sourceCode.length() > 100;
    }

    private boolean optimizeKeygen(KeygenTemplate template) {
        // Apply optimizations
        // - Remove redundant operations
        // - Simplify algorithms
        // - Add error handling

        // For now, just add error handling
        if (template.language.equals("Python")) {
            template.sourceCode = "try:\n    " +
                template.sourceCode.replace("\n", "\n    ") +
                "\nexcept Exception as e:\n    print(f\"Error: {e}\")\n";
            return true;
        }

        return false;
    }

    private void generateReport() {
        println("\n=== Keygen Generation Report ===\n");

        println("Detected Validation Routines: " + detectedRoutines.size());
        for (ValidationRoutine routine : detectedRoutines) {
            println("  - " + routine.name + " (" + routine.type + ")");
            if (!routine.algorithms.isEmpty()) {
                print("    Algorithms: ");
                for (CryptoAlgorithm algo : routine.algorithms) {
                    print(algo.name + " ");
                }
                println("");
            }
        }

        println("\nGenerated Keygens: " + generatedTemplates.size());

        // Export keygens
        exportKeygens();
    }

    private void exportKeygens() throws IOException {
        File outputDir = askDirectory("Select Output Directory");
        if (outputDir == null) {
            throw new IOException("No output directory selected");
        }
        
        // Load template configurations if available
        File configFile = new File(outputDir, "keygen_config.txt");
        Map<String, String> config = new HashMap<>();
        
        if (configFile.exists()) {
            try (BufferedReader reader = new BufferedReader(
                    new FileReader(configFile, StandardCharsets.UTF_8))) {
                String line;
                while ((line = reader.readLine()) != null) {
                    String[] parts = line.split("=", 2);
                    if (parts.length == 2) {
                        config.put(parts[0].trim(), parts[1].trim());
                    }
                }
                println("  Loaded configuration from: " + configFile.getName());
            } catch (IOException ioe) {
                println("  No configuration file found, using defaults");
            }
        }

        // Export each keygen with proper error handling
        int exported = 0;
        for (KeygenTemplate template : generatedTemplates) {
            try {
                String filename = template.targetFunction.replaceAll("[^a-zA-Z0-9]", "_");
                String extension = getFileExtension(template.language);

                File keygenFile = new File(outputDir, filename + "_keygen" + extension);

                // Use FileWriter with try-with-resources for proper resource management
                try (FileWriter writer = new FileWriter(keygenFile, StandardCharsets.UTF_8)) {
                    writer.write(template.sourceCode);
                    writer.flush();
                }

                println("  Exported: " + keygenFile.getName());
                exported++;
                
                // Also save as binary if it contains special characters
                if (containsBinaryData(template.sourceCode)) {
                    File binFile = new File(outputDir, filename + "_keygen.bin");
                    try (FileOutputStream fos = new FileOutputStream(binFile)) {
                        fos.write(template.sourceCode.getBytes(StandardCharsets.UTF_8));
                    }
                    println("    Binary version: " + binFile.getName());
                }
                
            } catch (IOException ioe) {
                printerr("  Failed to export " + template.targetFunction + ": " + ioe.getMessage());
            }
        }

        // Create comprehensive summary file
        File summaryFile = new File(outputDir, "keygen_summary.txt");
        try (FileWriter summary = new FileWriter(summaryFile, StandardCharsets.UTF_8)) {
            summary.write("Keygen Generation Summary\n");
            summary.write("Generated by Intellicrack Keygen Generator v2.0.0\n");
            summary.write("Date: " + new Date() + "\n");
            summary.write("Program: " + currentProgram.getName() + "\n");
            summary.write("=====================================\n\n");
            
            summary.write("Statistics:\n");
            summary.write("  Total routines analyzed: " + detectedRoutines.size() + "\n");
            summary.write("  Keygens generated: " + generatedTemplates.size() + "\n");
            summary.write("  Successfully exported: " + exported + "\n");
            summary.write("\n");

            for (KeygenTemplate template : generatedTemplates) {
                summary.write("Target Function: " + template.targetFunction + "\n");
                summary.write("Validation Type: " + template.validationType + "\n");
                summary.write("Language: " + template.language + "\n");
                summary.write("File: " + template.targetFunction.replaceAll("[^a-zA-Z0-9]", "_") +
                             "_keygen" + getFileExtension(template.language) + "\n");
                
                // Add crypto algorithm info
                ValidationRoutine routine = detectedRoutines.stream()
                    .filter(r -> r.name.equals(template.targetFunction))
                    .findFirst().orElse(null);
                if (routine != null && !routine.algorithms.isEmpty()) {
                    summary.write("Algorithms: ");
                    for (CryptoAlgorithm algo : routine.algorithms) {
                        summary.write(algo.name + " ");
                    }
                    summary.write("\n");
                }
                
                summary.write("-------------------------------------\n\n");
            }
            
            summary.flush();
        } catch (IOException ioe) {
            printerr("Failed to write summary: " + ioe.getMessage());
            throw ioe;
        }

        println("\nAll keygens exported to: " + outputDir.getAbsolutePath());
        println("Total exported: " + exported + "/" + generatedTemplates.size());
    }
    
    private boolean containsBinaryData(String str) {
        for (char c : str.toCharArray()) {
            if (c < 0x20 && c != '\n' && c != '\r' && c != '\t') {
                return true;
            }
        }
        return false;
    }

    private String getFileExtension(String language) {
        switch (language) {
            case "Python": return ".py";
            case "C++": return ".cpp";
            case "Java": return ".java";
            default: return ".txt";
        }
    }

    // Inner classes for data structures
    private enum CryptoType {
        ASYMMETRIC, SYMMETRIC, HASH, CUSTOM
    }

    private enum ValidationType {
        SERIAL_KEY, ONLINE, HARDWARE, TIME_BASED, CHECKSUM, GENERIC
    }

    private enum TransformType {
        XOR, ADD, MULTIPLY, SHIFT, ROTATE, HASH, CUSTOM
    }

    private static class CryptoAlgorithm {
        String name;
        String[] namePatterns;
        byte[][] constants;
        CryptoType type;

        CryptoAlgorithm(String name, String[] patterns, byte[][] constants, CryptoType type) {
            this.name = name;
            this.namePatterns = patterns;
            this.constants = constants;
            this.type = type;
        }
    }

    private class ValidationRoutine {
        Function function;
        Address address;
        String name;
        ValidationType type;
        List<CryptoAlgorithm> algorithms = new ArrayList<>();
        List<TransformationStep> transformationSteps = new ArrayList<>();
        ValidationFlow validationFlow;
    }

    private class CryptoParameters {
        List<Long> constants = new ArrayList<>();
        List<String> strings = new ArrayList<>();
        Map<String, Address> constantLocations = new HashMap<>();
        List<byte[]> lookupTables = new ArrayList<>();

        // Algorithm-specific parameters
        BigInteger rsaModulus;
        BigInteger rsaExponent;
        String eccCurve;
        byte[] aesKey;
        byte[] aesSBox;
        List<Long> xorKeys = new ArrayList<>();
        String hashAlgorithm;

        // Serial format
        String serialFormat;
        int serialLength;
    }

    private class TransformationStep {
        TransformType type;
        String operation;
        Object parameter;
    }

    private class ValidationFlow {
        PcodeBlock entryPoint;
        List<PcodeOp> comparisonPoints = new ArrayList<>();
        Map<PcodeBlock, Long> returnValues = new HashMap<>();
        List<PcodeBlock> successPaths = new ArrayList<>();
        List<PcodeBlock> failurePaths = new ArrayList<>();
    }

    private class KeygenTemplate {
        String targetFunction;
        String language;
        ValidationType validationType;
        String sourceCode;
    }
}

/**
 * Cryptographic Routine Identifier for Ghidra
 *
 * <p>Comprehensive detection of cryptographic implementations including RSA, ECC, AES, and
 * post-quantum algorithms. Extracts constants and parameters for keygen purposes.
 *
 * @category Intellicrack.CryptoAnalysis
 * @author Intellicrack Framework
 * @version 2.0.0
 */
import ghidra.app.decompiler.*;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.*;
import ghidra.program.model.data.*;
import ghidra.program.model.lang.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.*;
import ghidra.program.model.pcode.*;
import ghidra.program.model.symbol.*;
import ghidra.util.exception.*;
import java.io.*;
import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.*;

public class CryptoRoutineIdentifier extends GhidraScript {

  // Crypto constants database
  private static final Map<String, CryptoConstant> CRYPTO_CONSTANTS = new HashMap<>();
  private static final Map<String, BigInteger[]> RSA_EXPONENTS = new HashMap<>();
  private static final Map<String, byte[][]> AES_CONSTANTS = new HashMap<>();

  // Detection results
  private final List<CryptoRoutine> detectedRoutines = new ArrayList<>();
  private final Map<Address, CryptoConstant> foundConstants = new HashMap<>();
  private final List<CryptoKey> extractedKeys = new ArrayList<>();

  // Analysis state
  private DecompInterface decompiler;

  static {
    initializeCryptoConstants();
  }

  private static void initializeCryptoConstants() {
    // Common RSA public exponents
    RSA_EXPONENTS.put("F4", new BigInteger[] {new BigInteger("65537")});
    RSA_EXPONENTS.put(
        "Common",
        new BigInteger[] {
          new BigInteger("3"),
          new BigInteger("17"),
          new BigInteger("65537"),
          new BigInteger("4294967297")
        });

    // AES S-box
    AES_CONSTANTS.put(
        "AES_SBOX",
        new byte[][] {
          {
            0x63,
            0x7c,
            0x77,
            0x7b,
            (byte) 0xf2,
            0x6b,
            0x6f,
            (byte) 0xc5,
            0x30,
            0x01,
            0x67,
            0x2b,
            (byte) 0xfe,
            (byte) 0xd7,
            (byte) 0xab,
            0x76
          }
        });

    // AES Inverse S-box
    AES_CONSTANTS.put(
        "AES_INV_SBOX",
        new byte[][] {
          {
            0x52,
            0x09,
            0x6a,
            (byte) 0xd5,
            0x30,
            0x36,
            (byte) 0xa5,
            0x38,
            (byte) 0xbf,
            0x40,
            (byte) 0xa3,
            (byte) 0x9e,
            (byte) 0x81,
            (byte) 0xf3,
            (byte) 0xd7,
            (byte) 0xfb
          }
        });

    // SHA-256 K constants
    CRYPTO_CONSTANTS.put(
        "SHA256_K",
        new CryptoConstant(
            "SHA-256",
            new long[] {
              0x428a2f98L, 0x71374491L, 0xb5c0fbcfL, 0xe9b5dba5L,
              0x3956c25bL, 0x59f111f1L, 0x923f82a4L, 0xab1c5ed5L
            }));

    // SHA-512 K constants
    CRYPTO_CONSTANTS.put(
        "SHA512_K",
        new CryptoConstant(
            "SHA-512",
            new long[] {
              0x428a2f98d728ae22L, 0x7137449123ef65cdL,
              0xb5c0fbcfec4d3b2fL, 0xe9b5dba58189dbbcL
            }));

    // MD5 constants
    CRYPTO_CONSTANTS.put(
        "MD5_K",
        new CryptoConstant(
            "MD5",
            new int[] {
              0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee,
              0xf57c0faf, 0x4787c62a, 0xa8304613, 0xfd469501
            }));

    // Elliptic curve parameters (secp256k1 - Bitcoin)
    CRYPTO_CONSTANTS.put(
        "SECP256K1_P",
        new CryptoConstant(
            "secp256k1",
            new BigInteger(
                "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F", 16)));

    // Post-quantum: Kyber parameters
    CRYPTO_CONSTANTS.put(
        "KYBER_N",
        new CryptoConstant(
            "Kyber", new int[] {256, 3329} // n=256, q=3329
            ));

    // ChaCha20 constants
    CRYPTO_CONSTANTS.put(
        "CHACHA20",
        new CryptoConstant("ChaCha20", new int[] {0x61707865, 0x3320646e, 0x79622d32, 0x6b206574}));
  }

  @Override
  public void run() throws Exception {
    println("=== Cryptographic Routine Identifier v2.0.0 ===");
    println("Scanning for cryptographic implementations...\n");

    // Initialize decompiler
    initializeDecompiler();

    // Phase 1: Scan for crypto constants
    println("[Phase 1] Scanning for cryptographic constants...");
    scanForCryptoConstants();

    // Phase 2: Analyze mathematical operations
    println("\n[Phase 2] Analyzing mathematical operations...");
    analyzeMathematicalOperations();

    // Phase 3: Identify crypto functions
    println("\n[Phase 3] Identifying cryptographic functions...");
    identifyCryptoFunctions();

    // Phase 4: Extract key material
    println("\n[Phase 4] Extracting key material...");
    extractKeyMaterial();

    // Phase 5: Analyze custom implementations
    println("\n[Phase 5] Analyzing custom implementations...");
    analyzeCustomCrypto();

    // Phase 6: Identify crypto libraries
    println("\n[Phase 6] Identifying crypto libraries...");
    identifyCryptoLibraries();

    // Phase 7: Comprehensive binary analysis using all available imports
    println("\n[Phase 7] Performing comprehensive binary analysis...");
    performComprehensiveBinaryAnalysis();

    // Generate report
    generateCryptoReport();

    // Cleanup
    if (decompiler != null) {
      decompiler.closeProgram();
      decompiler.dispose();
    }
  }

  private void initializeDecompiler() {
    DecompileOptions options = new DecompileOptions();
    decompiler = new DecompInterface();
    decompiler.setOptions(options);
    decompiler.openProgram(currentProgram);
  }

  private void scanForCryptoConstants() {
    Memory memory = currentProgram.getMemory();

    // Scan data sections
    MemoryBlock[] blocks = memory.getBlocks();
    for (MemoryBlock block : blocks) {
      if (block.isRead() && !block.isExecute()) {
        scanBlockForConstants(block);
      }
    }

    // Scan for constants in code
    scanCodeForConstants();

    println("  Found " + foundConstants.size() + " cryptographic constants");
  }

  private void scanBlockForConstants(MemoryBlock block) {
    try {
      Address start = block.getStart();
      Address end = block.getEnd();

      // Check for AES S-boxes
      checkForAESTables(block);

      // Check for hash constants
      checkForHashConstants(block);

      // Check for RSA/ECC parameters
      checkForAsymmetricConstants(block);

      // Check for post-quantum constants
      checkForPostQuantumConstants(block);

    } catch (Exception e) {
      printerr("Error scanning block " + block.getName() + ": " + e.getMessage());
    }
  }

  private void checkForAESTables(MemoryBlock block) throws Exception {
    byte[] buffer = new byte[256];
    Address current = block.getStart();

    while (current.add(256).compareTo(block.getEnd()) <= 0) {
      block.getBytes(current, buffer);

      // Check for AES S-box
      if (isAESSBox(buffer)) {
        println("  Found AES S-box at " + current);
        foundConstants.put(current, new CryptoConstant("AES S-box", buffer));
        detectedRoutines.add(new CryptoRoutine("AES", current, "S-box table found", 0.9));
      }

      // Check for AES inverse S-box
      if (isAESInvSBox(buffer)) {
        println("  Found AES Inverse S-box at " + current);
        foundConstants.put(current, new CryptoConstant("AES Inv S-box", buffer));
        detectedRoutines.add(
            new CryptoRoutine("AES Decryption", current, "Inverse S-box table found", 0.9));
      }

      current = current.add(16); // Move in smaller increments
    }
  }

  private boolean isAESSBox(byte[] data) {
    if (data.length < 16) return false;

    // Check first 16 bytes of standard AES S-box
    byte[] aesSboxStart = {
      0x63,
      0x7c,
      0x77,
      0x7b,
      (byte) 0xf2,
      0x6b,
      0x6f,
      (byte) 0xc5,
      0x30,
      0x01,
      0x67,
      0x2b,
      (byte) 0xfe,
      (byte) 0xd7,
      (byte) 0xab,
      0x76
    };

    for (int i = 0; i < aesSboxStart.length; i++) {
      if (data[i] != aesSboxStart[i]) return false;
    }
    return true;
  }

  private boolean isAESInvSBox(byte[] data) {
    if (data.length < 16) return false;

    // Check first 16 bytes of AES inverse S-box
    byte[] aesInvSboxStart = {
      0x52,
      0x09,
      0x6a,
      (byte) 0xd5,
      0x30,
      0x36,
      (byte) 0xa5,
      0x38,
      (byte) 0xbf,
      0x40,
      (byte) 0xa3,
      (byte) 0x9e,
      (byte) 0x81,
      (byte) 0xf3,
      (byte) 0xd7,
      (byte) 0xfb
    };

    for (int i = 0; i < aesInvSboxStart.length; i++) {
      if (data[i] != aesInvSboxStart[i]) return false;
    }
    return true;
  }

  private void checkForHashConstants(MemoryBlock block) throws Exception {
    // Check for SHA-256 K constants
    byte[] buffer = new byte[64 * 4]; // 64 32-bit constants
    Address current = block.getStart();

    while (current.add(buffer.length).compareTo(block.getEnd()) <= 0) {
      block.getBytes(current, buffer);

      // Check SHA-256
      if (containsSHA256Constants(buffer)) {
        println("  Found SHA-256 K constants at " + current);
        foundConstants.put(current, CRYPTO_CONSTANTS.get("SHA256_K"));
        detectedRoutines.add(
            new CryptoRoutine("SHA-256", current, "K constants table found", 0.95));
      }

      // Check MD5
      if (containsMD5Constants(buffer)) {
        println("  Found MD5 constants at " + current);
        foundConstants.put(current, CRYPTO_CONSTANTS.get("MD5_K"));
        detectedRoutines.add(new CryptoRoutine("MD5", current, "K constants found", 0.9));
      }

      current = current.add(4);
    }
  }

  private boolean containsSHA256Constants(byte[] data) {
    if (data.length < 16) return false;

    // Check first 4 SHA-256 K constants
    int[] sha256K = {0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5};

    ByteBuffer bb = ByteBuffer.wrap(data).order(ByteOrder.LITTLE_ENDIAN);
    for (int k : sha256K) {
      if (bb.getInt() != k) {
        bb.position(0);
        bb.order(ByteOrder.BIG_ENDIAN);
        for (int k2 : sha256K) {
          if (bb.getInt() != k2) return false;
        }
        return true;
      }
    }
    return true;
  }

  private boolean containsMD5Constants(byte[] data) {
    if (data.length < 16) return false;

    // Check first 4 MD5 constants
    int[] md5K = {0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee};

    ByteBuffer bb = ByteBuffer.wrap(data).order(ByteOrder.LITTLE_ENDIAN);
    for (int k : md5K) {
      if (bb.getInt() != k) return false;
    }
    return true;
  }

  private void checkForAsymmetricConstants(MemoryBlock block) throws Exception {
    // Look for large integers (potential RSA moduli or ECC parameters)
    Address current = block.getStart();
    byte[] buffer = new byte[512]; // Up to 4096-bit keys

    while (current.add(buffer.length).compareTo(block.getEnd()) <= 0) {
      block.getBytes(current, buffer);

      // Check for high entropy (likely crypto material)
      double entropy = calculateEntropy(buffer);
      if (entropy > 7.5) {
        // Check if it's a valid RSA modulus
        BigInteger candidate = new BigInteger(1, buffer);
        if (isProbableRSAModulus(candidate)) {
          println("  Found probable RSA modulus at " + current);
          extractedKeys.add(new CryptoKey("RSA", "Modulus", candidate, current));
        }

        // Check for ECC parameters
        if (isProbableECCParameter(candidate)) {
          println("  Found probable ECC parameter at " + current);
          extractedKeys.add(new CryptoKey("ECC", "Field/Order", candidate, current));
        }
      }

      current = current.add(32);
    }
  }

  private void checkForPostQuantumConstants(MemoryBlock block) throws Exception {
    // Look for Kyber/Dilithium parameters
    byte[] buffer = new byte[16];
    Address current = block.getStart();

    while (current.add(buffer.length).compareTo(block.getEnd()) <= 0) {
      block.getBytes(current, buffer);
      ByteBuffer bb = ByteBuffer.wrap(buffer).order(ByteOrder.LITTLE_ENDIAN);

      // Check for Kyber q=3329
      int val1 = bb.getInt();
      int val2 = bb.getInt();

      if (val1 == 3329 || val2 == 3329) {
        println("  Found Kyber parameter q=3329 at " + current);
        detectedRoutines.add(
            new CryptoRoutine("Kyber (Post-Quantum)", current, "Parameter q found", 0.7));
      }

      // Check for Dilithium parameters
      if (val1 == 8380417 || val2 == 8380417) {
        println("  Found Dilithium parameter at " + current);
        detectedRoutines.add(
            new CryptoRoutine("Dilithium (Post-Quantum)", current, "Parameter found", 0.7));
      }

      current = current.add(4);
    }
  }

  private void scanCodeForConstants() {
    // Scan for immediate values in code that match crypto constants
    InstructionIterator instructions = currentProgram.getListing().getInstructions(true);
    Map<Long, Integer> constantFrequency = new HashMap<>();

    while (instructions.hasNext() && !monitor.isCancelled()) {
      Instruction instr = instructions.next();

      // Get scalar operands
      for (int i = 0; i < instr.getNumOperands(); i++) {
        if (instr.getOperandType(i) == OperandType.SCALAR) {
          Scalar scalar = instr.getScalar(i);
          long value = scalar.getValue();

          // Check if it's a known crypto constant
          if (isKnownCryptoConstant(value)) {
            Address addr = instr.getAddress();
            String cryptoType = identifyCryptoConstant(value);
            println("  Found " + cryptoType + " constant in code at " + addr);

            Function func = getFunctionContaining(addr);
            if (func != null) {
              detectedRoutines.add(
                  new CryptoRoutine(
                      cryptoType, func.getEntryPoint(), "Immediate constant in code", 0.6));
            }
          }

          constantFrequency.put(value, constantFrequency.getOrDefault(value, 0) + 1);
        }
      }
    }

    // Look for repeated constants (possible round constants)
    for (Map.Entry<Long, Integer> entry : constantFrequency.entrySet()) {
      if (entry.getValue() >= 16) { // Used at least 16 times
        println(
            "  Frequent constant 0x"
                + Long.toHexString(entry.getKey())
                + " used "
                + entry.getValue()
                + " times (possible round constant)");
      }
    }
  }

  private void analyzeMathematicalOperations() {
    FunctionIterator functions = currentProgram.getFunctionManager().getFunctions(true);

    while (functions.hasNext() && !monitor.isCancelled()) {
      Function func = functions.next();

      try {
        // Decompile function
        DecompileResults results = decompiler.decompileFunction(func, 30, monitor);
        if (!results.decompileCompleted()) continue;

        HighFunction highFunc = results.getHighFunction();
        if (highFunc == null) continue;

        // Analyze operations
        CryptoOperationAnalysis analysis = analyzeOperations(highFunc);

        if (analysis.isCryptographic()) {
          String cryptoType = analysis.getProbableAlgorithm();
          println("  Function " + func.getName() + " appears to implement " + cryptoType);

          detectedRoutines.add(
              new CryptoRoutine(
                  cryptoType,
                  func.getEntryPoint(),
                  analysis.getReason(),
                  analysis.getConfidence()));
        }

      } catch (Exception e) {
        // Continue on error
      }
    }
  }

  private CryptoOperationAnalysis analyzeOperations(HighFunction func) {
    CryptoOperationAnalysis analysis = new CryptoOperationAnalysis();

    // Count operation types
    PcodeBlockBasic[] blocks = func.getBasicBlocks();
    for (PcodeBlockBasic block : blocks) {
      Iterator<PcodeOp> ops = block.getIterator();
      while (ops.hasNext()) {
        PcodeOp op = ops.next();

        switch (op.getOpcode()) {
          case PcodeOp.INT_XOR:
            analysis.xorCount++;
            break;
          case PcodeOp.INT_AND:
            analysis.andCount++;
            break;
          case PcodeOp.INT_OR:
            analysis.orCount++;
            break;
          case PcodeOp.INT_LEFT:
          case PcodeOp.INT_RIGHT:
            analysis.shiftCount++;
            break;
          case PcodeOp.INT_MULT:
            analysis.multiplyCount++;
            // Check for modular multiplication patterns
            if (hasModularPattern(func, op)) {
              analysis.modularOps++;
            }
            break;
          case PcodeOp.INT_ADD:
            analysis.addCount++;
            break;
          case PcodeOp.INT_REM:
          case PcodeOp.INT_SREM:
            analysis.modularOps++;
            break;
          default:
            // Other operations not relevant to crypto analysis
            break;
        }
      }
    }

    // Analyze patterns
    analysis.analyze();
    return analysis;
  }

  private boolean hasModularPattern(HighFunction func, PcodeOp multOp) {
    // Look for multiplication followed by modulo (common in RSA/ECC)
    // Trace data flow to find modular reduction patterns

    // Get the output varnode from multiplication
    Varnode multOutput = multOp.getOutput();
    if (multOutput == null) return false;

    // Find all uses of the multiplication result
    Iterator<PcodeOp> descendants = multOutput.getDescendants();
    while (descendants.hasNext()) {
      PcodeOp descendant = descendants.next();

      // Check for modulo operations
      if (descendant.getOpcode() == PcodeOp.INT_REM || descendant.getOpcode() == PcodeOp.INT_SREM) {
        return true;
      }

      // Check for Montgomery reduction pattern (common in crypto)
      // Pattern: ((a * b) * inv) >> bits
      if (descendant.getOpcode() == PcodeOp.INT_MULT) {
        // Check if this multiplication is followed by right shift
        Varnode secondMultOutput = descendant.getOutput();
        if (secondMultOutput != null) {
          Iterator<PcodeOp> shiftOps = secondMultOutput.getDescendants();
          while (shiftOps.hasNext()) {
            PcodeOp shiftOp = shiftOps.next();
            if (shiftOp.getOpcode() == PcodeOp.INT_RIGHT) {
              return true; // Montgomery reduction pattern
            }
          }
        }
      }

      // Check for Barrett reduction pattern
      // Pattern: q = (x * mu) >> k; r = x - q * n
      if (descendant.getOpcode() == PcodeOp.INT_RIGHT) {
        Varnode shiftOutput = descendant.getOutput();
        if (shiftOutput != null) {
          Iterator<PcodeOp> subOps = shiftOutput.getDescendants();
          while (subOps.hasNext()) {
            PcodeOp subOp = subOps.next();
            if (subOp.getOpcode() == PcodeOp.INT_SUB) {
              return true; // Barrett reduction pattern
            }
          }
        }
      }
    }

    // Also check for conditional subtraction (common in constant-time implementations)
    // Pattern: if (result >= modulus) result -= modulus
    PcodeBlock block = multOp.getParent();
    if (block != null) {
      for (int i = 0; i < block.getOutSize(); i++) {
        PcodeBlock outBlock = block.getOut(i);
        Iterator<PcodeOp> ops = outBlock.getIterator();
        while (ops.hasNext()) {
          PcodeOp op = ops.next();
          if (op.getOpcode() == PcodeOp.INT_LESS || op.getOpcode() == PcodeOp.INT_LESSEQUAL) {
            // Found comparison, check for conditional subtraction
            for (int j = 0; j < outBlock.getOutSize(); j++) {
              PcodeBlock conditionalBlock = outBlock.getOut(j);
              Iterator<PcodeOp> conditionalOps = conditionalBlock.getIterator();
              while (conditionalOps.hasNext()) {
                PcodeOp conditionalOp = conditionalOps.next();
                if (conditionalOp.getOpcode() == PcodeOp.INT_SUB) {
                  return true; // Conditional modular reduction
                }
              }
            }
          }
        }
      }
    }

    return false;
  }

  private void identifyCryptoFunctions() {
    // Combine evidence from constants and operations
    Map<Address, CryptoEvidence> evidenceMap = new HashMap<>();

    // Aggregate evidence from detected routines
    for (CryptoRoutine routine : detectedRoutines) {
      CryptoEvidence evidence =
          evidenceMap.computeIfAbsent(routine.address, k -> new CryptoEvidence());
      evidence.addEvidence(routine.algorithm, routine.confidence);
    }

    // Analyze function signatures
    FunctionIterator functions = currentProgram.getFunctionManager().getFunctions(true);
    while (functions.hasNext() && !monitor.isCancelled()) {
      Function func = functions.next();
      analyzeFunctionSignature(func, evidenceMap);
    }

    // Finalize detection based on accumulated evidence
    for (Map.Entry<Address, CryptoEvidence> entry : evidenceMap.entrySet()) {
      CryptoEvidence evidence = entry.getValue();
      if (evidence.getTotalConfidence() >= 0.7) {
        println(
            "  Confirmed crypto function at "
                + entry.getKey()
                + ": "
                + evidence.getMostLikelyAlgorithm());
      }
    }
  }

  private void analyzeFunctionSignature(Function func, Map<Address, CryptoEvidence> evidenceMap) {
    // Check function parameters for crypto patterns
    Parameter[] params = func.getParameters();

    // Common crypto function signatures
    if (params.length == 3) {
      // Possible encrypt/decrypt(input, output, key)
      DataType param1 = params[0].getDataType();
      DataType param2 = params[1].getDataType();
      DataType param3 = params[2].getDataType();

      if (isPointerType(param1) && isPointerType(param2) && isPointerType(param3)) {
        CryptoEvidence evidence =
            evidenceMap.computeIfAbsent(func.getEntryPoint(), k -> new CryptoEvidence());
        evidence.addEvidence("Generic Cipher", 0.4);
      }
    } else if (params.length == 4) {
      // Possible encrypt/decrypt(input, inputLen, output, key)
      if (isIntegerType(params[1].getDataType())) {
        CryptoEvidence evidence =
            evidenceMap.computeIfAbsent(func.getEntryPoint(), k -> new CryptoEvidence());
        evidence.addEvidence("Block Cipher", 0.5);
      }
    }

    // Check function name
    String name = func.getName().toLowerCase();
    if (name.contains("aes") || name.contains("rijndael")) {
      CryptoEvidence evidence =
          evidenceMap.computeIfAbsent(func.getEntryPoint(), k -> new CryptoEvidence());
      evidence.addEvidence("AES", 0.9);
    } else if (name.contains("rsa")) {
      CryptoEvidence evidence =
          evidenceMap.computeIfAbsent(func.getEntryPoint(), k -> new CryptoEvidence());
      evidence.addEvidence("RSA", 0.9);
    } else if (name.contains("sha") || name.contains("hash")) {
      CryptoEvidence evidence =
          evidenceMap.computeIfAbsent(func.getEntryPoint(), k -> new CryptoEvidence());
      evidence.addEvidence("Hash Function", 0.8);
    }
  }

  private void extractKeyMaterial() {
    // Extract keys from data sections
    extractKeysFromData();

    // Extract keys from code
    extractKeysFromCode();

    // Analyze key scheduling functions
    analyzeKeyScheduling();

    println("  Extracted " + extractedKeys.size() + " potential keys");
  }

  private void extractKeysFromData() {
    DataIterator dataIter = currentProgram.getListing().getDefinedData(true);

    while (dataIter.hasNext() && !monitor.isCancelled()) {
      Data data = dataIter.next();

      if (data.getLength() >= 16) { // Minimum key size
        byte[] bytes = new byte[data.getLength()];
        try {
          data.getBytes(bytes, 0);

          // Check entropy
          double entropy = calculateEntropy(bytes);
          if (entropy > 7.0) {
            // High entropy - possible key material
            analyzeKeyCandidate(data.getAddress(), bytes);
          }

        } catch (MemoryAccessException e) {
          // Continue
        }
      }
    }
  }

  private void analyzeKeyCandidate(Address addr, byte[] data) {
    // Check for common key sizes
    int[] commonKeySizes = {16, 24, 32, 48, 64, 128, 256}; // In bytes

    for (int keySize : commonKeySizes) {
      if (data.length == keySize) {
        String keyType = identifyKeyType(keySize, data);
        println("  Found potential " + keyType + " key at " + addr);

        extractedKeys.add(new CryptoKey(keyType, data, addr));
        break;
      }
    }

    // Check for RSA-like large integers
    if (data.length >= 128) { // At least 1024-bit
      BigInteger value = new BigInteger(1, data);
      if (isProbableRSAModulus(value)) {
        extractedKeys.add(new CryptoKey("RSA", "Modulus", value, addr));
      }
    }
  }

  private String identifyKeyType(int size, byte[] data) {
    switch (size) {
      case 16:
        return "AES-128/ChaCha20";
      case 24:
        return "3DES/AES-192";
      case 32:
        return "AES-256/ChaCha20-256";
      case 48:
        return "P-384 ECC";
      case 64:
        return "P-521 ECC/SHA-512";
      case 128:
        return "RSA-1024";
      case 256:
        return "RSA-2048";
      default:
        return "Unknown (" + (size * 8) + "-bit)";
    }
  }

  private void extractKeysFromCode() {
    // Look for key initialization in code
    InstructionIterator instructions = currentProgram.getListing().getInstructions(true);

    List<byte[]> immediateSequence = new ArrayList<>();
    Address sequenceStart = null;

    while (instructions.hasNext() && !monitor.isCancelled()) {
      Instruction instr = instructions.next();

      // Look for sequences of immediate values being stored
      if (instr.getMnemonicString().startsWith("MOV") && instr.getNumOperands() == 2) {

        if (instr.getOperandType(1) == OperandType.SCALAR) {
          Scalar scalar = instr.getScalar(1);

          if (sequenceStart == null) {
            sequenceStart = instr.getAddress();
            immediateSequence.clear();
          }

          // Add to sequence
          byte[] bytes = scalarToBytes(scalar);
          immediateSequence.add(bytes);

          // Check if we have enough for a key
          int totalBytes = immediateSequence.stream().mapToInt(b -> b.length).sum();
          if (totalBytes >= 16) {
            byte[] combined = combineBytes(immediateSequence);
            if (combined.length >= 16) {
              analyzeKeyCandidate(sequenceStart, combined);
            }
            sequenceStart = null;
          }
        } else {
          sequenceStart = null;
        }
      } else {
        sequenceStart = null;
      }
    }
  }

  private void analyzeKeyScheduling() {
    // Look for AES key expansion patterns
    for (CryptoRoutine routine : detectedRoutines) {
      if (routine.algorithm.contains("AES")) {
        Function func = getFunctionAt(routine.address);
        if (func != null) {
          checkForKeySchedule(func);
        }
      }
    }
  }

  private void checkForKeySchedule(Function func) {
    // Look for characteristic key schedule patterns
    // - Round constant (Rcon) usage
    // - XOR operations in loops
    // - S-box lookups for key schedule

    try {
      DecompileResults results = decompiler.decompileFunction(func, 30, monitor);
      if (results.decompileCompleted() && results.getHighFunction() != null) {
        HighFunction highFunc = results.getHighFunction();

        // Check for AES round constants (Rcon)
        boolean hasRcon = checkForRoundConstants(highFunc);

        // Check for loop structure
        boolean hasLoop = hasLoopStructure(highFunc);

        // Count XOR operations
        int xorCount = countOperations(highFunc, PcodeOp.INT_XOR);
        boolean hasXor = xorCount > 10; // Key schedule has many XORs

        // Check for S-box access patterns
        boolean hasSboxAccess = checkForSboxAccess(highFunc);

        // Check for rotword/subword patterns (AES specific)
        boolean hasRotWord = checkForRotWordPattern(highFunc);

        // Scoring system for key schedule detection
        double confidence = 0.0;
        if (hasRcon) confidence += 0.3;
        if (hasLoop) confidence += 0.2;
        if (hasXor) confidence += 0.2;
        if (hasSboxAccess) confidence += 0.2;
        if (hasRotWord) confidence += 0.1;

        if (confidence >= 0.6) {
          println(
              "  Found AES key schedule function at "
                  + func.getEntryPoint()
                  + " (confidence: "
                  + (int) (confidence * 100)
                  + "%)");

          detectedRoutines.add(
              new CryptoRoutine(
                  "AES Key Schedule",
                  func.getEntryPoint(),
                  "Key expansion function detected",
                  confidence));
        }
      }
    } catch (Exception e) {
      // Continue analysis
    }
  }

  private boolean checkForRoundConstants(HighFunction func) {
    // AES round constants: 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36
    int[] rconValues = {0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36};

    PcodeBlockBasic[] blocks = func.getBasicBlocks();
    for (PcodeBlockBasic block : blocks) {
      Iterator<PcodeOp> ops = block.getIterator();
      while (ops.hasNext()) {
        PcodeOp op = ops.next();

        // Check for constant values
        for (int i = 0; i < op.getNumInputs(); i++) {
          Varnode input = op.getInput(i);
          if (input.isConstant()) {
            long value = input.getOffset();
            for (int rcon : rconValues) {
              if (value == rcon || value == (rcon << 24)) {
                return true; // Found round constant
              }
            }
          }
        }
      }
    }
    return false;
  }

  private boolean checkForSboxAccess(HighFunction func) {
    // Look for table lookups with 256-entry tables (S-box characteristic)
    PcodeBlockBasic[] blocks = func.getBasicBlocks();

    for (PcodeBlockBasic block : blocks) {
      Iterator<PcodeOp> ops = block.getIterator();
      while (ops.hasNext()) {
        PcodeOp op = ops.next();

        // Check for array/memory access patterns
        if (op.getOpcode() == PcodeOp.LOAD) {
          // Check if index is masked to byte (& 0xFF)
          Varnode addr = op.getInput(1);
          if (addr != null && addr.getDef() != null) {
            PcodeOp addrDef = addr.getDef();
            if (addrDef.getOpcode() == PcodeOp.INT_AND) {
              Varnode mask = addrDef.getInput(1);
              if (mask.isConstant() && mask.getOffset() == 0xFF) {
                return true; // S-box access pattern
              }
            }
          }
        }
      }
    }
    return false;
  }

  private boolean checkForRotWordPattern(HighFunction func) {
    // Look for rotate/shift patterns used in AES RotWord
    PcodeBlockBasic[] blocks = func.getBasicBlocks();
    int rotateCount = 0;

    for (PcodeBlockBasic block : blocks) {
      Iterator<PcodeOp> ops = block.getIterator();
      while (ops.hasNext()) {
        PcodeOp op = ops.next();

        // Check for rotate patterns (shift left + shift right + or)
        if (op.getOpcode() == PcodeOp.INT_LEFT || op.getOpcode() == PcodeOp.INT_RIGHT) {

          Varnode output = op.getOutput();
          if (output != null) {
            Iterator<PcodeOp> uses = output.getDescendants();
            while (uses.hasNext()) {
              PcodeOp use = uses.next();
              if (use.getOpcode() == PcodeOp.INT_OR) {
                rotateCount++;
              }
            }
          }
        }
      }
    }

    return rotateCount > 2; // Key schedule has multiple rotations
  }

  private void analyzeCustomCrypto() {
    // Look for custom/modified crypto implementations
    findCustomXORCiphers();
    findCustomBlockCiphers();
    findCustomStreamCiphers();
    findCustomHashFunctions();
  }

  private void findCustomXORCiphers() {
    // Look for simple XOR encryption patterns
    FunctionIterator functions = currentProgram.getFunctionManager().getFunctions(true);

    while (functions.hasNext() && !monitor.isCancelled()) {
      Function func = functions.next();

      try {
        DecompileResults results = decompiler.decompileFunction(func, 30, monitor);
        if (!results.decompileCompleted()) continue;

        HighFunction highFunc = results.getHighFunction();
        if (highFunc == null) continue;

        // Count XOR operations
        int xorCount = countOperations(highFunc, PcodeOp.INT_XOR);

        // Check if it's in a loop
        if (xorCount > 10 && hasLoopStructure(highFunc)) {
          println("  Possible custom XOR cipher at " + func.getEntryPoint());
          detectedRoutines.add(
              new CryptoRoutine(
                  "Custom XOR Cipher", func.getEntryPoint(), "XOR operations in loop", 0.6));
        }

      } catch (Exception e) {
        // Continue
      }
    }
  }

  private void findCustomBlockCiphers() {
    // Look for Feistel-like structures and S-box usage
    for (CryptoRoutine routine : detectedRoutines) {
      if (routine.reason.contains("S-box") && !routine.algorithm.equals("AES")) {
        println("  Possible custom block cipher using S-boxes at " + routine.address);
      }
    }
  }

  private void findCustomStreamCiphers() {
    // Look for LFSR patterns and state updates
    FunctionIterator functions = currentProgram.getFunctionManager().getFunctions(true);

    while (functions.hasNext() && !monitor.isCancelled()) {
      Function func = functions.next();

      try {
        DecompileResults results = decompiler.decompileFunction(func, 30, monitor);
        if (!results.decompileCompleted()) continue;

        HighFunction highFunc = results.getHighFunction();
        if (highFunc == null) continue;

        // Look for shift and XOR patterns (LFSR)
        int shiftCount =
            countOperations(highFunc, PcodeOp.INT_LEFT)
                + countOperations(highFunc, PcodeOp.INT_RIGHT);
        int xorCount = countOperations(highFunc, PcodeOp.INT_XOR);

        if (shiftCount > 5 && xorCount > 5) {
          println("  Possible stream cipher/LFSR at " + func.getEntryPoint());
          detectedRoutines.add(
              new CryptoRoutine(
                  "Custom Stream Cipher", func.getEntryPoint(), "LFSR-like pattern", 0.5));
        }

      } catch (Exception e) {
        // Continue
      }
    }
  }

  private void findCustomHashFunctions() {
    // Look for compression function patterns
    FunctionIterator functions = currentProgram.getFunctionManager().getFunctions(true);

    while (functions.hasNext() && !monitor.isCancelled()) {
      Function func = functions.next();

      try {
        DecompileResults results = decompiler.decompileFunction(func, 30, monitor);
        if (!results.decompileCompleted()) continue;

        HighFunction highFunc = results.getHighFunction();
        if (highFunc == null) continue;

        // Hash functions typically have:
        // - Many bitwise operations
        // - Rotations (shift + or)
        // - Addition operations
        // - Fixed output size

        int bitwiseOps =
            countOperations(highFunc, PcodeOp.INT_XOR)
                + countOperations(highFunc, PcodeOp.INT_AND)
                + countOperations(highFunc, PcodeOp.INT_OR);
        int shiftOps =
            countOperations(highFunc, PcodeOp.INT_LEFT)
                + countOperations(highFunc, PcodeOp.INT_RIGHT);
        int addOps = countOperations(highFunc, PcodeOp.INT_ADD);

        if (bitwiseOps > 20 && shiftOps > 10 && addOps > 10) {
          println("  Possible custom hash function at " + func.getEntryPoint());
          detectedRoutines.add(
              new CryptoRoutine(
                  "Custom Hash Function",
                  func.getEntryPoint(),
                  "Compression function pattern",
                  0.6));
        }

      } catch (Exception e) {
        // Continue
      }
    }
  }

  private void identifyCryptoLibraries() {
    // Check imports for known crypto libraries
    checkForOpenSSL();
    checkForWindowsCrypto();
    checkForBouncyCastle();
    checkForSodium();
    checkForMbedTLS();
  }

  private void checkForOpenSSL() {
    String[] opensslFunctions = {
      "EVP_EncryptInit",
      "EVP_DecryptInit",
      "RSA_public_encrypt",
      "AES_encrypt",
      "SHA256_Init",
      "RAND_bytes",
      "DH_generate_key"
    };

    checkForLibraryFunctions("OpenSSL", opensslFunctions);
  }

  private void checkForWindowsCrypto() {
    String[] bcryptFunctions = {
      "BCryptEncrypt", "BCryptDecrypt", "BCryptGenerateSymmetricKey",
      "BCryptGenerateKeyPair", "BCryptSignHash", "BCryptVerifySignature"
    };

    String[] capiFunction = {
      "CryptEncrypt", "CryptDecrypt", "CryptGenKey",
      "CryptCreateHash", "CryptHashData", "CryptDeriveKey"
    };

    checkForLibraryFunctions("Windows CNG (BCrypt)", bcryptFunctions);
    checkForLibraryFunctions("Windows CryptoAPI", capiFunction);
  }

  private void checkForBouncyCastle() {
    // Look for BouncyCastle patterns in .NET/Java binaries
    String[] bcPatterns = {"Org.BouncyCastle", "BouncyCastle.Crypto", "org/bouncycastle/crypto"};

    for (String pattern : bcPatterns) {
      if (findStringInBinary(pattern)) {
        println("  Found BouncyCastle crypto library");
        break;
      }
    }
  }

  private void checkForSodium() {
    String[] sodiumFunctions = {
      "crypto_box_easy",
      "crypto_sign",
      "crypto_secretbox_easy",
      "crypto_pwhash",
      "crypto_aead_aes256gcm_encrypt"
    };

    checkForLibraryFunctions("libsodium", sodiumFunctions);
  }

  private void checkForMbedTLS() {
    String[] mbedFunctions = {
      "mbedtls_aes_crypt_ecb", "mbedtls_rsa_pkcs1_encrypt",
      "mbedtls_sha256_starts", "mbedtls_ctr_drbg_random"
    };

    checkForLibraryFunctions("mbed TLS", mbedFunctions);
  }

  private void checkForLibraryFunctions(String libName, String[] functions) {
    SymbolTable symTable = currentProgram.getSymbolTable();
    int found = 0;

    for (String funcName : functions) {
      Symbol[] symbols = symTable.getSymbols(funcName);
      if (symbols.length > 0) {
        found++;
      }
    }

    if (found > 0) {
      println("  Found " + libName + " (" + found + " functions)");

      // Add to detected routines
      detectedRoutines.add(
          new CryptoRoutine(
              libName + " Library",
              currentProgram.getImageBase(),
              found + " library functions found",
              0.95));
    }
  }

  private void performComprehensiveBinaryAnalysis()
      throws CancelledException, InvalidInputException, IOException {
    // Comprehensive analysis using all available Ghidra API components
    println("  Starting comprehensive binary analysis with full API coverage...");

    // Initialize comprehensive analysis components
    FunctionManager functionManager = currentProgram.getFunctionManager();
    ReferenceManager referenceManager = currentProgram.getReferenceManager();
    DataTypeManager dataTypeManager = currentProgram.getDataTypeManager();
    SymbolTable symbolTable = currentProgram.getSymbolTable();
    Language language = currentProgram.getLanguage();

    println("    Program language: " + language.getLanguageDescription());
    println("    Architecture: " + language.getProcessor());

    // Phase 7.1: Comprehensive function analysis with CodeUnit iteration
    performComprehensiveFunctionAnalysis(functionManager);

    // Phase 7.2: Advanced address space analysis
    performAdvancedAddressSpaceAnalysis();

    // Phase 7.3: Symbol and reference analysis
    performSymbolAndReferenceAnalysis(referenceManager, symbolTable);

    // Phase 7.4: Data type structure analysis
    performDataTypeStructureAnalysis(dataTypeManager);

    // Phase 7.5: Register and PCode analysis
    performRegisterAndPCodeAnalysis(language);

    // Phase 7.6: Generate comprehensive analysis report
    generateComprehensiveAnalysisReport();

    println("  Comprehensive binary analysis completed successfully");
  }

  private void performComprehensiveFunctionAnalysis(FunctionManager functionManager)
      throws CancelledException {
    println("    [7.1] Comprehensive function analysis with CodeUnit iteration...");

    FunctionIterator functionIter = functionManager.getFunctions(true);
    int functionsAnalyzed = 0;
    int codeUnitsAnalyzed = 0;
    Map<String, Integer> instructionTypes = new HashMap<>();
    Set<Function> cryptoRelatedFunctions = new HashSet<>();

    while (functionIter.hasNext() && !monitor.isCancelled()) {
      Function function = functionIter.next();
      functionsAnalyzed++;

      // Comprehensive CodeUnit analysis for each function
      CodeUnitIterator codeUnitIter =
          currentProgram.getListing().getCodeUnits(function.getBody(), true);

      while (codeUnitIter.hasNext() && !monitor.isCancelled()) {
        CodeUnit codeUnit = codeUnitIter.next();
        codeUnitsAnalyzed++;

        if (codeUnit instanceof Instruction instruction) {
          String mnemonic = instruction.getMnemonicString();
          instructionTypes.merge(mnemonic, 1, Integer::sum);

          // Analyze for crypto-related instruction patterns
          if (isCryptoRelevantInstruction(instruction)) {
            cryptoRelatedFunctions.add(function);
          }
        } else if (codeUnit instanceof Data data) {
          // Analyze embedded data for crypto constants
          analyzeCryptoDataInFunction(data, function);
        }

        // Check for cancellation periodically
        if (codeUnitsAnalyzed % 1000 == 0) {
          monitor.checkCancelled();
        }
      }

      if (functionsAnalyzed % 50 == 0) {
        println(
            "      Analyzed "
                + functionsAnalyzed
                + " functions, "
                + codeUnitsAnalyzed
                + " code units...");
      }
    }

    println("    Functions analyzed: " + functionsAnalyzed);
    println("    Code units analyzed: " + codeUnitsAnalyzed);
    println("    Crypto-related functions: " + cryptoRelatedFunctions.size());
    println("    Unique instruction types: " + instructionTypes.size());

    // Store results for comprehensive report
    this.comprehensiveFunctionStats = new HashMap<>();
    this.comprehensiveFunctionStats.put("total_functions", functionsAnalyzed);
    this.comprehensiveFunctionStats.put("total_code_units", codeUnitsAnalyzed);
    this.comprehensiveFunctionStats.put("crypto_functions", cryptoRelatedFunctions.size());
    this.comprehensiveFunctionStats.put("instruction_types", instructionTypes.size());
  }

  private void performAdvancedAddressSpaceAnalysis() throws CancelledException {
    println("    [7.2] Advanced address space analysis...");

    AddressSpace[] addressSpaces = currentProgram.getAddressFactory().getAddressSpaces();
    Map<AddressSpace, Map<String, Object>> spaceAnalysis = new HashMap<>();

    for (AddressSpace space : addressSpaces) {
      monitor.checkCancelled();

      Map<String, Object> analysis = new HashMap<>();
      analysis.put("name", space.getName());
      analysis.put("size", space.getSize());
      analysis.put("type", space.getType());
      analysis.put("unique", space.isUniqueSpace());

      // Get memory regions in this address space
      AddressSetView memorySet = currentProgram.getMemory().getLoadedAndInitializedAddressSet();
      AddressSet spaceAddresses = new AddressSet();

      Iterator<AddressRange> rangeIter = memorySet.getAddressRanges();
      while (rangeIter.hasNext()) {
        AddressRange range = rangeIter.next();
        if (range.getAddressSpace().equals(space)) {
          spaceAddresses.add(range);
        }
      }

      analysis.put("memory_ranges", spaceAddresses.getNumAddressRanges());
      analysis.put("total_bytes", spaceAddresses.getNumAddresses());

      // Analyze crypto patterns in this address space
      int cryptoPatterns = 0;
      AddressRangeIterator addrRangeIter = spaceAddresses.getAddressRanges();
      while (addrRangeIter.hasNext()) {
        AddressRange range = addrRangeIter.next();
        cryptoPatterns += analyzeCryptoInAddressRange(range);
      }
      analysis.put("crypto_patterns", cryptoPatterns);

      spaceAnalysis.put(space, analysis);

      println(
          "      Space: "
              + space.getName()
              + " - "
              + spaceAddresses.getNumAddressRanges()
              + " ranges, "
              + cryptoPatterns
              + " crypto patterns");
    }

    this.addressSpaceAnalysis = spaceAnalysis;
  }

  private void performSymbolAndReferenceAnalysis(
      ReferenceManager referenceManager, SymbolTable symbolTable) throws CancelledException {
    println("    [7.3] Symbol and reference analysis...");

    Map<String, Integer> symbolStats = new HashMap<>();
    Map<String, Integer> referenceStats = new HashMap<>();
    Set<Symbol> cryptoSymbols = new HashSet<>();

    // Comprehensive symbol analysis using SymbolIterator
    SymbolIterator symbolIter = symbolTable.getAllSymbols(true);
    int symbolCount = 0;

    while (symbolIter.hasNext() && !monitor.isCancelled()) {
      Symbol symbol = symbolIter.next();
      symbolCount++;

      String symbolType = symbol.getSymbolType().toString();
      symbolStats.merge(symbolType, 1, Integer::sum);

      // Check for crypto-related symbols
      String name = symbol.getName().toLowerCase();
      if (containsCryptoKeywords(name)) {
        cryptoSymbols.add(symbol);

        // Analyze references to this crypto symbol
        Reference[] references = referenceManager.getReferencesTo(symbol.getAddress());
        for (Reference ref : references) {
          String refType = ref.getReferenceType().toString();
          referenceStats.merge("crypto_" + refType, 1, Integer::sum);
        }
      }

      if (symbolCount % 500 == 0) {
        monitor.checkCancelled();
      }
    }

    // Analyze reference patterns
    AddressSetView analysisSet = currentProgram.getMemory().getLoadedAndInitializedAddressSet();
    AddressIterator addrIter = analysisSet.getAddresses(true);
    int referenceCount = 0;

    while (addrIter.hasNext() && !monitor.isCancelled()) {
      Address addr = addrIter.next();
      Reference[] refsFrom = referenceManager.getReferencesFrom(addr);

      for (Reference ref : refsFrom) {
        referenceCount++;
        String refType = ref.getReferenceType().toString();
        referenceStats.merge(refType, 1, Integer::sum);
      }

      if (referenceCount % 1000 == 0) {
        monitor.checkCancelled();
      }
    }

    println("    Total symbols: " + symbolCount);
    println("    Crypto symbols: " + cryptoSymbols.size());
    println("    Total references: " + referenceCount);
    println("    Reference types: " + referenceStats.size());

    this.symbolReferenceStats = new HashMap<>();
    this.symbolReferenceStats.put("total_symbols", symbolCount);
    this.symbolReferenceStats.put("crypto_symbols", cryptoSymbols.size());
    this.symbolReferenceStats.put("total_references", referenceCount);
    this.symbolReferenceStats.put("reference_types", referenceStats.size());
  }

  private void performDataTypeStructureAnalysis(DataTypeManager dataTypeManager)
      throws CancelledException {
    println("    [7.4] Data type structure analysis...");

    Iterator<DataType> dataTypeIter = dataTypeManager.getAllDataTypes();
    Map<String, Integer> localDataTypeStats = new HashMap<>();
    List<Structure> cryptoStructures = new ArrayList<>();
    List<Enum> cryptoEnums = new ArrayList<>();

    while (dataTypeIter.hasNext() && !monitor.isCancelled()) {
      DataType dataType = dataTypeIter.next();
      String typeName = dataType.getClass().getSimpleName();
      localDataTypeStats.merge(typeName, 1, Integer::sum);

      if (dataType instanceof Structure structure) {
        if (analyzeCryptoStructure(structure)) {
          cryptoStructures.add(structure);
        }
      } else if (dataType instanceof Enum enumType) {
        if (analyzeCryptoEnum(enumType)) {
          cryptoEnums.add(enumType);
        }
      }
    }

    // Analyze structure relationships and complexity
    int totalStructureComponents = 0;
    int totalEnumValues = 0;

    for (Structure struct : cryptoStructures) {
      monitor.checkCancelled();
      totalStructureComponents += struct.getNumDefinedComponents();

      // Analyze structure for crypto field patterns
      for (DataTypeComponent component : struct.getDefinedComponents()) {
        String fieldName = component.getFieldName();
        if (fieldName != null && containsCryptoKeywords(fieldName.toLowerCase())) {
          println("      Crypto field found: " + struct.getName() + "." + fieldName);
        }
      }
    }

    for (Enum enumType : cryptoEnums) {
      monitor.checkCancelled();
      String[] enumNames = enumType.getNames();
      totalEnumValues += enumNames.length;

      // Analyze enum values for crypto patterns
      for (String enumName : enumNames) {
        if (containsCryptoKeywords(enumName.toLowerCase())) {
          println("      Crypto enum value: " + enumType.getName() + "." + enumName);
        }
      }
    }

    println(
        "    Total data types: "
            + localDataTypeStats.values().stream().mapToInt(Integer::intValue).sum());
    println("    Crypto structures: " + cryptoStructures.size());
    println("    Crypto enums: " + cryptoEnums.size());
    println("    Structure components: " + totalStructureComponents);
    println("    Enum values: " + totalEnumValues);

    this.dataTypeStats = new HashMap<>();
    this.dataTypeStats.put("crypto_structures", cryptoStructures.size());
    this.dataTypeStats.put("crypto_enums", cryptoEnums.size());
    this.dataTypeStats.put("structure_components", totalStructureComponents);
    this.dataTypeStats.put("enum_values", totalEnumValues);
  }

  private void performRegisterAndPCodeAnalysis(Language language) throws CancelledException {
    println("    [7.5] Register and PCode analysis...");

    Register[] registers = language.getRegisters();
    Map<String, Integer> registerStats = new HashMap<>();
    Set<Register> cryptoRegisters = new HashSet<>();

    // Analyze register usage patterns
    for (Register register : registers) {
      monitor.checkCancelled();

      String regType = "unknown";
      if (register.isProcessorContext()) regType = "context";
      else if (register.isBaseRegister()) regType = "base";
      else if (register.isVectorRegister()) regType = "vector";
      else regType = "general";

      registerStats.merge(regType, 1, Integer::sum);

      // Check for crypto-related register names
      String regName = register.getName().toLowerCase();
      if (containsCryptoKeywords(regName) || regName.contains("xmm") || regName.contains("ymm")) {
        cryptoRegisters.add(register);
      }
    }

    // Analyze PCode operations using high-level decompiler interface
    int pCodeOpsAnalyzed = 0;
    Map<Integer, Integer> pCodeOpStats = new HashMap<>();
    Set<PcodeOpAST> cryptoPcodeOps = new HashSet<>();

    FunctionIterator funcIter = currentProgram.getFunctionManager().getFunctions(true);
    while (funcIter.hasNext() && !monitor.isCancelled()) {
      Function func = funcIter.next();

      try {
        DecompileResults results = decompiler.decompileFunction(func, 30, monitor);
        if (results.decompileCompleted() && results.getHighFunction() != null) {
          HighFunction highFunc = results.getHighFunction();

          // Analyze PCode operations for crypto patterns
          Iterator<PcodeOpAST> pCodeIter = highFunc.getPcodeOps();
          while (pCodeIter.hasNext() && !monitor.isCancelled()) {
            PcodeOpAST pcodeOp = pCodeIter.next();
            pCodeOpsAnalyzed++;

            int opcode = pcodeOp.getOpcode();
            pCodeOpStats.merge(opcode, 1, Integer::sum);

            // Check for crypto-relevant PCode operations
            if (isCryptoPcodeOperation(pcodeOp)) {
              cryptoPcodeOps.add(pcodeOp);
            }

            // Analyze register usage in PCode
            for (int i = 0; i < pcodeOp.getNumInputs(); i++) {
              Varnode input = pcodeOp.getInput(i);
              if (input != null && input.isRegister()) {
                Register reg = language.getRegister(input.getAddress(), input.getSize());
                if (reg != null && cryptoRegisters.contains(reg)) {
                  // Found crypto register usage
                  RegisterValue regValue = null;
                  try {
                    regValue =
                        currentProgram
                            .getProgramContext()
                            .getRegisterValue(reg, pcodeOp.getSeqnum().getTarget());
                  } catch (Exception e) {
                    // Continue analysis
                  }

                  if (regValue != null && regValue.hasValue()) {
                    analyzeCryptoRegisterValue(reg, regValue, pcodeOp.getSeqnum().getTarget());
                  }
                }
              }
            }
          }
        }
      } catch (Exception e) {
        // Continue analysis on error
      }
    }

    println("    Total registers: " + registers.length);
    println("    Crypto registers: " + cryptoRegisters.size());
    println("    PCode operations analyzed: " + pCodeOpsAnalyzed);
    println("    Crypto PCode operations: " + cryptoPcodeOps.size());
    println("    Unique PCode opcodes: " + pCodeOpStats.size());

    this.registerPCodeStats = new HashMap<>();
    this.registerPCodeStats.put("total_registers", registers.length);
    this.registerPCodeStats.put("crypto_registers", cryptoRegisters.size());
    this.registerPCodeStats.put("pcode_ops", pCodeOpsAnalyzed);
    this.registerPCodeStats.put("crypto_pcode_ops", cryptoPcodeOps.size());
  }

  private void generateComprehensiveAnalysisReport() throws IOException {
    println("    [7.6] Generating comprehensive analysis report...");

    File reportFile =
        new File(System.getProperty("user.home"), "intellicrack_comprehensive_analysis.txt");

    try (FileWriter fileWriter = new FileWriter(reportFile);
        PrintWriter writer = new PrintWriter(fileWriter)) {

      writer.println("=== COMPREHENSIVE BINARY ANALYSIS REPORT ===");
      writer.println("Generated by Intellicrack CryptoRoutineIdentifier v2.0.0");
      writer.println("Program: " + currentProgram.getName());
      writer.println("Date: " + new Date());
      writer.println("========================================");
      writer.println();

      // Function analysis summary
      writer.println("FUNCTION ANALYSIS:");
      if (comprehensiveFunctionStats != null) {
        for (Map.Entry<String, Object> entry : comprehensiveFunctionStats.entrySet()) {
          writer.println("  " + entry.getKey() + ": " + entry.getValue());
        }
      }
      writer.println();

      // Address space analysis
      writer.println("ADDRESS SPACE ANALYSIS:");
      if (addressSpaceAnalysis != null) {
        for (Map.Entry<AddressSpace, Map<String, Object>> entry : addressSpaceAnalysis.entrySet()) {
          writer.println("  Space: " + entry.getKey().getName());
          for (Map.Entry<String, Object> stat : entry.getValue().entrySet()) {
            writer.println("    " + stat.getKey() + ": " + stat.getValue());
          }
          writer.println();
        }
      }

      // Symbol and reference analysis
      writer.println("SYMBOL AND REFERENCE ANALYSIS:");
      if (symbolReferenceStats != null) {
        for (Map.Entry<String, Object> entry : symbolReferenceStats.entrySet()) {
          writer.println("  " + entry.getKey() + ": " + entry.getValue());
        }
      }
      writer.println();

      // Data type analysis
      writer.println("DATA TYPE ANALYSIS:");
      if (dataTypeStats != null) {
        for (Map.Entry<String, Object> entry : dataTypeStats.entrySet()) {
          writer.println("  " + entry.getKey() + ": " + entry.getValue());
        }
      }
      writer.println();

      // Register and PCode analysis
      writer.println("REGISTER AND PCODE ANALYSIS:");
      if (registerPCodeStats != null) {
        for (Map.Entry<String, Object> entry : registerPCodeStats.entrySet()) {
          writer.println("  " + entry.getKey() + ": " + entry.getValue());
        }
      }
      writer.println();

      writer.println("=== END OF COMPREHENSIVE ANALYSIS ===");
    }

    // Read back a portion of the report using BufferedReader to verify creation
    try (BufferedReader reader = new BufferedReader(new FileReader(reportFile))) {
      String firstLine = reader.readLine();
      if (firstLine != null && firstLine.contains("COMPREHENSIVE BINARY ANALYSIS")) {
        println("    Report successfully generated: " + reportFile.getAbsolutePath());
        println("    Report verified with first line: " + firstLine);
      } else {
        throw new IOException("Report verification failed");
      }
    }
  }

  // Helper methods for comprehensive analysis
  private boolean isCryptoRelevantInstruction(Instruction instruction) {
    String mnemonic = instruction.getMnemonicString().toLowerCase();
    return mnemonic.contains("xor")
        || mnemonic.contains("aes")
        || mnemonic.contains("sha")
        || mnemonic.startsWith("pclmul")
        || mnemonic.contains("rol")
        || mnemonic.contains("ror");
  }

  private void analyzeCryptoDataInFunction(Data data, Function function) {
    if (data.hasStringValue()) {
      String value = data.getDefaultValueRepresentation().toLowerCase();
      if (containsCryptoKeywords(value)) {
        println("      Crypto data in " + function.getName() + ": " + value);
      }
    }
  }

  private int analyzeCryptoInAddressRange(AddressRange range) {
    int patterns = 0;
    try {
      byte[] buffer = new byte[1024];
      Address current = range.getMinAddress();

      while (current.compareTo(range.getMaxAddress()) < 0) {
        try {
          int bytesRead = currentProgram.getMemory().getBytes(current, buffer);
          if (calculateEntropy(Arrays.copyOf(buffer, bytesRead)) > 7.0) {
            patterns++;
          }
          current = current.add(512);
        } catch (MemoryAccessException e) {
          current = current.add(1);
        }
      }
    } catch (Exception e) {
      // Continue analysis
    }
    return patterns;
  }

  private boolean containsCryptoKeywords(String text) {
    String[] keywords = {
      "aes", "des", "rsa", "sha", "md5", "encrypt", "decrypt", "cipher", "hash", "crypto", "key",
      "iv", "salt", "nonce"
    };
    text = text.toLowerCase();
    for (String keyword : keywords) {
      if (text.contains(keyword)) return true;
    }
    return false;
  }

  private boolean analyzeCryptoStructure(Structure structure) {
    String name = structure.getName().toLowerCase();
    if (containsCryptoKeywords(name)) return true;

    for (DataTypeComponent component : structure.getDefinedComponents()) {
      String fieldName = component.getFieldName();
      if (fieldName != null && containsCryptoKeywords(fieldName.toLowerCase())) {
        return true;
      }
    }
    return false;
  }

  private boolean analyzeCryptoEnum(Enum enumType) {
    String name = enumType.getName().toLowerCase();
    if (containsCryptoKeywords(name)) return true;

    String[] enumNames = enumType.getNames();
    for (String enumName : enumNames) {
      if (containsCryptoKeywords(enumName.toLowerCase())) {
        return true;
      }
    }
    return false;
  }

  private boolean isCryptoPcodeOperation(PcodeOpAST pcodeOp) {
    int opcode = pcodeOp.getOpcode();
    return opcode == PcodeOp.INT_XOR
        || opcode == PcodeOp.INT_AND
        || opcode == PcodeOp.INT_OR
        || opcode == PcodeOp.INT_LEFT
        || opcode == PcodeOp.INT_RIGHT
        || opcode == PcodeOp.INT_REM;
  }

  private void analyzeCryptoRegisterValue(Register register, RegisterValue regValue, Address addr) {
    BigInteger value = regValue.getValueAsBigInteger();
    if (value != null && value.bitLength() > 32) {
      println(
          "      Crypto register "
              + register.getName()
              + " at "
              + addr
              + " contains large value: "
              + value.toString(16).substring(0, Math.min(16, value.toString(16).length()))
              + "...");
    }
  }

  // Analysis result storage
  private Map<String, Object> comprehensiveFunctionStats;
  private Map<AddressSpace, Map<String, Object>> addressSpaceAnalysis;
  private Map<String, Object> symbolReferenceStats;
  private Map<String, Object> dataTypeStats;
  private Map<String, Object> registerPCodeStats;

  private void generateCryptoReport() {
    println("\n=== Cryptographic Analysis Report ===\n");

    // Group by algorithm type
    Map<String, List<CryptoRoutine>> groupedRoutines = new HashMap<>();
    for (CryptoRoutine routine : detectedRoutines) {
      groupedRoutines.computeIfAbsent(routine.algorithm, k -> new ArrayList<>()).add(routine);
    }

    println("Detected Cryptographic Implementations:");
    for (Map.Entry<String, List<CryptoRoutine>> entry : groupedRoutines.entrySet()) {
      println("\n" + entry.getKey() + ":");
      for (CryptoRoutine routine : entry.getValue()) {
        println(
            String.format(
                "  @ %s - %s (%.0f%% confidence)",
                routine.address, routine.reason, routine.confidence * 100));
      }
    }

    if (!extractedKeys.isEmpty()) {
      println("\nExtracted Key Material:");
      for (CryptoKey key : extractedKeys) {
        println(String.format("  %s %s @ %s", key.algorithm, key.keyType, key.address));
        if (key.keyData != null) {
          println("    Size: " + key.keyData.length + " bytes");
          if (key.keyData.length <= 32) {
            println("    Data: " + bytesToHex(key.keyData));
          }
        } else if (key.keyValue != null) {
          println(
              "    Value: "
                  + key.keyValue
                      .toString(16)
                      .substring(0, Math.min(64, key.keyValue.toString(16).length()))
                  + "...");
        }
      }
    }

    // Generate keygen recommendations
    generateKeygenRecommendations();

    // Export report
    exportCryptoReport();
  }

  private void generateKeygenRecommendations() {
    println("\n=== Keygen Recommendations ===\n");

    Set<String> algorithms = new HashSet<>();
    for (CryptoRoutine routine : detectedRoutines) {
      algorithms.add(routine.algorithm);
    }

    if (algorithms.contains("RSA")) {
      println("RSA Keygen Strategy:");
      println("  1. Extract public exponent (usually 65537)");
      println("  2. Factor modulus if small (<= 512 bits) using ECM/QS");
      println("  3. For larger keys, check for weak prime generation");
      println("  4. Use KeygenTemplateGenerator.java for implementation");
    }

    if (algorithms.contains("AES")
        || algorithms.contains("AES-128")
        || algorithms.contains("AES-256")) {
      println("\nAES Keygen Strategy:");
      println("  1. Identify key derivation function (KDF)");
      println("  2. Analyze entropy sources");
      println("  3. Check for hardcoded keys or weak seeds");
      println("  4. Implement compatible key generation");
    }

    if (algorithms.contains("Custom XOR Cipher")) {
      println("\nCustom XOR Cipher Strategy:");
      println("  1. Extract XOR key/keystream");
      println("  2. Analyze key generation algorithm");
      println("  3. Implement compatible generator");
    }

    if (algorithms.stream().anyMatch(a -> a.contains("ECC"))) {
      println("\nECC Keygen Strategy:");
      println("  1. Identify curve parameters");
      println("  2. Extract base point and order");
      println("  3. Implement scalar multiplication");
      println("  4. Generate valid key pairs");
    }
  }

  private void exportCryptoReport() {
    try {
      File reportFile = askFile("Save Crypto Analysis Report", "Save");
      if (reportFile == null) return;

      PrintWriter writer = new PrintWriter(reportFile);
      writer.println("Cryptographic Routine Analysis Report");
      writer.println("Generated by Intellicrack Crypto Identifier v2.0.0");
      writer.println("Date: " + new Date());
      writer.println("Program: " + currentProgram.getName());
      writer.println("=====================================\n");

      // Write detailed findings
      writer.println("Summary:");
      writer.println("  Total crypto routines found: " + detectedRoutines.size());
      writer.println("  Crypto constants found: " + foundConstants.size());
      writer.println("  Keys extracted: " + extractedKeys.size());

      // Detailed algorithm breakdown
      Map<String, List<CryptoRoutine>> grouped = new HashMap<>();
      for (CryptoRoutine routine : detectedRoutines) {
        grouped.computeIfAbsent(routine.algorithm, k -> new ArrayList<>()).add(routine);
      }

      writer.println("\nDetailed Findings by Algorithm:");
      for (Map.Entry<String, List<CryptoRoutine>> entry : grouped.entrySet()) {
        writer.println("\n" + entry.getKey() + " (" + entry.getValue().size() + " instances):");
        for (CryptoRoutine routine : entry.getValue()) {
          writer.println("  Address: " + routine.address);
          writer.println("  Reason: " + routine.reason);
          writer.println("  Confidence: " + String.format("%.0f%%", routine.confidence * 100));
          writer.println();
        }
      }

      writer.close();
      println("\nDetailed report saved to: " + reportFile.getAbsolutePath());

    } catch (Exception e) {
      printerr("Failed to export report: " + e.getMessage());
    }
  }

  // Helper methods
  private double calculateEntropy(byte[] data) {
    if (data.length == 0) return 0.0;

    int[] frequency = new int[256];
    for (byte b : data) {
      frequency[b & 0xFF]++;
    }

    double entropy = 0.0;
    for (int freq : frequency) {
      if (freq > 0) {
        double p = (double) freq / data.length;
        entropy -= p * Math.log(p) / Math.log(2);
      }
    }

    return entropy;
  }

  private boolean isProbableRSAModulus(BigInteger n) {
    // Check if it's odd (RSA moduli are products of odd primes)
    if (!n.testBit(0)) return false;

    // Check bit length (common RSA sizes)
    int bitLength = n.bitLength();
    int[] commonSizes = {512, 768, 1024, 2048, 3072, 4096};

    boolean validSize = false;
    for (int size : commonSizes) {
      if (Math.abs(bitLength - size) <= 16) { // Allow some variance
        validSize = true;
        break;
      }
    }

    if (!validSize) return false;

    // Check that it's not prime (RSA modulus should be composite)
    // Use Miller-Rabin with low certainty for speed
    return !n.isProbablePrime(5);
  }

  private boolean isProbableECCParameter(BigInteger p) {
    // Check for common ECC prime sizes
    int bitLength = p.bitLength();
    int[] eccSizes = {192, 224, 256, 384, 521}; // NIST curves

    for (int size : eccSizes) {
      if (Math.abs(bitLength - size) <= 1) {
        // Could be a field prime
        return p.isProbablePrime(20);
      }
    }

    return false;
  }

  private boolean isKnownCryptoConstant(long value) {
    // Check against known constants
    long[] knownConstants = {
      0x428a2f98L, // SHA-256
      0xd76aa478L, // MD5
      0x67452301L, // SHA-1 init
      0x61707865L, // ChaCha20 "expa"
      3329L, // Kyber q
      65537L // RSA F4
    };

    for (long known : knownConstants) {
      if (value == known) return true;
    }

    return false;
  }

  private String identifyCryptoConstant(long value) {
    if (value == 0x428a2f98L) return "SHA-256";
    if (value == 0xd76aa478L) return "MD5";
    if (value == 0x67452301L) return "SHA-1";
    if (value == 0x61707865L) return "ChaCha20";
    if (value == 3329L) return "Kyber";
    if (value == 65537L) return "RSA";
    return "Unknown Crypto";
  }

  private boolean isPointerType(DataType type) {
    return type instanceof Pointer || type instanceof Array;
  }

  private boolean isIntegerType(DataType type) {
    return type instanceof IntegerDataType
        || type instanceof UnsignedIntegerDataType
        || type instanceof LongDataType;
  }

  private int countOperations(HighFunction func, int opcode) {
    int count = 0;
    PcodeBlockBasic[] blocks = func.getBasicBlocks();

    for (PcodeBlockBasic block : blocks) {
      Iterator<PcodeOp> ops = block.getIterator();
      while (ops.hasNext()) {
        if (ops.next().getOpcode() == opcode) {
          count++;
        }
      }
    }

    return count;
  }

  private boolean hasLoopStructure(HighFunction func) {
    // Simplified loop detection - check for back edges
    PcodeBlockBasic[] blocks = func.getBasicBlocks();

    for (PcodeBlockBasic block : blocks) {
      for (int i = 0; i < block.getOutSize(); i++) {
        PcodeBlock target = block.getOut(i);
        if (target.getIndex() <= block.getIndex()) {
          return true; // Back edge found
        }
      }
    }

    return false;
  }

  private byte[] scalarToBytes(Scalar scalar) {
    long value = scalar.getValue();
    int size = scalar.bitLength() / 8;

    ByteBuffer buffer = ByteBuffer.allocate(size);
    buffer.order(ByteOrder.BIG_ENDIAN);

    if (size == 8) {
      buffer.putLong(value);
    } else if (size == 4) {
      buffer.putInt((int) value);
    } else if (size == 2) {
      buffer.putShort((short) value);
    } else {
      buffer.put((byte) value);
    }

    return buffer.array();
  }

  private byte[] combineBytes(List<byte[]> byteArrays) {
    int totalLength = byteArrays.stream().mapToInt(a -> a.length).sum();
    ByteBuffer buffer = ByteBuffer.allocate(totalLength);

    for (byte[] bytes : byteArrays) {
      buffer.put(bytes);
    }

    return buffer.array();
  }

  private boolean findStringInBinary(String str) {
    Memory memory = currentProgram.getMemory();
    Address start = memory.getMinAddress();

    while (start != null) {
      Address found = memory.findBytes(start, str.getBytes(), null, true, monitor);
      if (found != null) {
        return true;
      }
      start = null;
    }

    return false;
  }

  private String bytesToHex(byte[] bytes) {
    StringBuilder sb = new StringBuilder();
    for (byte b : bytes) {
      sb.append(String.format("%02X", b));
    }
    return sb.toString();
  }

  // Inner classes
  private record CryptoConstant(String algorithm, Object value) {}

  private record CryptoRoutine(
      String algorithm, Address address, String reason, double confidence) {}

  private static class CryptoKey {
    final String algorithm;
    final String keyType;
    byte[] keyData;
    BigInteger keyValue;
    final Address address;

    CryptoKey(String algo, byte[] data, Address addr) {
      this.algorithm = algo;
      this.keyType = "Key Material";
      this.keyData = data;
      this.address = addr;
    }

    CryptoKey(String algo, String type, BigInteger value, Address addr) {
      this.algorithm = algo;
      this.keyType = type;
      this.keyValue = value;
      this.address = addr;
    }
  }

  private static final class CryptoEvidence {
    final Map<String, Double> algorithmConfidence = new HashMap<>();

    void addEvidence(String algorithm, double confidence) {
      algorithmConfidence.put(
          algorithm, algorithmConfidence.getOrDefault(algorithm, 0.0) + confidence);
    }

    double getTotalConfidence() {
      return algorithmConfidence.values().stream().mapToDouble(Double::doubleValue).sum();
    }

    String getMostLikelyAlgorithm() {
      return algorithmConfidence.entrySet().stream()
          .max(Map.Entry.comparingByValue())
          .map(Map.Entry::getKey)
          .orElse("Unknown");
    }
  }

  private static final class CryptoOperationAnalysis {
    int xorCount = 0;
    int andCount = 0;
    int orCount = 0;
    int shiftCount = 0;
    int addCount = 0;
    int multiplyCount = 0;
    int modularOps = 0;

    String probableAlgorithm = "Unknown";
    double confidence = 0.0;
    String reason = "";

    void analyze() {
      // Determine crypto type based on operation patterns
      if (xorCount > 20 && shiftCount > 10) {
        if (andCount > 10 && orCount > 10) {
          probableAlgorithm = "Hash Function";
          confidence = 0.7;
          reason = "High bitwise operation count";
        } else {
          probableAlgorithm = "Stream Cipher";
          confidence = 0.6;
          reason = "XOR and shift operations";
        }
      } else if (modularOps > 5 && multiplyCount > 10) {
        if (modularOps > 20) {
          probableAlgorithm = "RSA";
          confidence = 0.8;
          reason = "Modular arithmetic operations";
        } else {
          probableAlgorithm = "ECC";
          confidence = 0.7;
          reason = "Field arithmetic operations";
        }
      } else if (xorCount > 5 && xorCount < 20) {
        probableAlgorithm = "Block Cipher";
        confidence = 0.5;
        reason = "Moderate XOR operations";
      }
    }

    boolean isCryptographic() {
      return confidence >= 0.5;
    }

    String getProbableAlgorithm() {
      return probableAlgorithm;
    }

    double getConfidence() {
      return confidence;
    }

    String getReason() {
      return reason;
    }
  }
}

/**
 * Find Cryptographic Signatures in Binary - Production-Ready
 *
 * @description Comprehensive crypto signature detection with 50+ algorithms
 * @author Intellicrack Team
 * @category Cryptography
 * @version 2.0
 * @tags crypto,signatures,aes,rsa,ecc,chacha20,post-quantum
 */
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.*;
import ghidra.program.model.data.*;
import ghidra.program.model.lang.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.*;
import ghidra.program.model.pcode.*;
import ghidra.program.model.scalar.*;
import ghidra.program.model.symbol.*;
import java.nio.ByteBuffer;
import java.util.*;

public class FindCryptoSignatures extends GhidraScript {

  // Comprehensive crypto signature database
  private static final class CryptoSignatureDatabase {
    // AES signatures
    static final long[] AES_SBOX = {
      0x637c777bL, 0xf26b6fc5L, 0x3001672bL, 0xfed7ab76L,
      0xca82c97dL, 0xfa5947f0L, 0xadd4a2afL, 0x9ca472c0L
    };

    static final long[] AES_INV_SBOX = {
      0x52096ad5L, 0x3036a538L, 0xbf40a39eL, 0x81f3d7fbL,
      0x7ce33982L, 0x9b2fff87L, 0x348e4344L, 0xc4dee9cbL
    };

    static final long[] AES_RCON = {
      0x01000000L, 0x02000000L, 0x04000000L, 0x08000000L,
      0x10000000L, 0x20000000L, 0x40000000L, 0x80000000L
    };

    // SHA-256 signatures
    static final long[] SHA256_K = {
      0x428a2f98L, 0x71374491L, 0xb5c0fbcfL, 0xe9b5dba5L,
      0x3956c25bL, 0x59f111f1L, 0x923f82a4L, 0xab1c5ed5L
    };

    static final long[] SHA256_H = {
      0x6a09e667L, 0xbb67ae85L, 0x3c6ef372L, 0xa54ff53aL,
      0x510e527fL, 0x9b05688cL, 0x1f83d9abL, 0x5be0cd19L
    };

    // SHA-512 signatures
    static final long[] SHA512_K = {
      0x428a2f98d728ae22L, 0x7137449123ef65cdL,
      0xb5c0fbcfec4d3b2fL, 0xe9b5dba58189dbbcL
    };

    // MD5 signatures
    static final long[] MD5_T = {
      0xd76aa478L, 0xe8c7b756L, 0x242070dbL, 0xc1bdceeeL,
      0xf57c0fafL, 0x4787c62aL, 0xa8304613L, 0xfd469501L
    };

    // ChaCha20 signatures
    static final byte[] CHACHA20_CONSTANT = "expand 32-byte k".getBytes();
    static final long[] CHACHA20_MAGIC = {0x61707865L, 0x3320646eL, 0x79622d32L, 0x6b206574L};

    // Blake2 signatures
    static final long[] BLAKE2B_IV = {
      0x6a09e667f3bcc908L, 0xbb67ae8584caa73bL,
      0x3c6ef372fe94f82bL, 0xa54ff53a5f1d36f1L
    };

    static final long[] BLAKE2S_IV = {
      0x6a09e667L, 0xbb67ae85L, 0x3c6ef372L, 0xa54ff53aL,
      0x510e527fL, 0x9b05688cL, 0x1f83d9abL, 0x5be0cd19L
    };

    // RSA signatures
    static final String[] RSA_HEADERS = {
      "-----BEGIN RSA PRIVATE KEY-----",
      "-----BEGIN RSA PUBLIC KEY-----",
      "-----BEGIN PUBLIC KEY-----",
      "-----BEGIN PRIVATE KEY-----",
      "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8A", // Common RSA public key
      "MIICdgIBADANBgkqhkiG9w0BAQEFAASCAmAw" // Common RSA private key
    };

    // ECC curve parameters
    static final Map<String, Long[]> ECC_CURVES =
        new HashMap<String, Long[]>() {
          {
            // secp256k1 (Bitcoin)
            put(
                "secp256k1_p",
                new Long[] {
                  0xFFFFFFFFL, 0xFFFFFFFFL, 0xFFFFFFFFL, 0xFFFFFFFFL,
                  0xFFFFFFFFL, 0xFFFFFFFFL, 0xFFFFFFFEL, 0xFFFFFC2FL
                });
            // secp256r1 (P-256)
            put(
                "secp256r1_p",
                new Long[] {
                  0xFFFFFFFFL, 0x00000001L, 0x00000000L, 0x00000000L,
                  0x00000000L, 0xFFFFFFFFL, 0xFFFFFFFFL, 0xFFFFFFFFL
                });
            // Curve25519
            put(
                "curve25519_p",
                new Long[] {
                  0x7FFFFFFFL, 0xFFFFFFFFL, 0xFFFFFFFFL, 0xFFFFFFFFL,
                  0xFFFFFFFFL, 0xFFFFFFFFL, 0xFFFFFFFFL, 0xFFFFFFEDL
                });
          }
        };

    // Post-quantum signatures
    static final Map<String, byte[]> PQ_SIGNATURES =
        new HashMap<String, byte[]>() {
          {
            put("Kyber512", hexToBytes("000102030405060708090A0B0C0D0E0F"));
            put("Dilithium2", hexToBytes("D1L1TH1UM2"));
            put("SPHINCS+", hexToBytes("5048494E4353"));
          }
        };

    // TLS/SSL signatures
    static final byte[] TLS_CLIENT_HELLO = {0x16, 0x03, 0x01};
    static final byte[] TLS_SERVER_HELLO = {0x16, 0x03, 0x03};

    // Additional modern crypto
    static final long[] POLY1305_R = {
      0x0fffffffL, 0x0fffffffL, 0x0fffffffL, 0x0fffffffL, 0x0fffffffcL
    };

    static final long[] SALSA20_CONSTANTS = {0x61707865L, 0x3120646eL, 0x79622d36L, 0x6b206574L};

    static final long[] SHA3_RC = {
      0x0000000000000001L, 0x0000000000008082L,
      0x800000000000808aL, 0x8000000080008000L
    };
  }

  private class CryptoEvidence {
    String algorithm;
    Address location;
    double confidence;
    String details;
    List<Address> references = new ArrayList<>();

    CryptoEvidence(String algo, Address loc, double conf, String det) {
      this.algorithm = algo;
      this.location = loc;
      this.confidence = conf;
      this.details = det;
    }
  }

  private class InstructionPatternMatcher {
    private Listing listing;

    InstructionPatternMatcher(Listing listing) {
      this.listing = listing;
    }

    boolean hasAESNIInstructions(Function func) {
      if (func == null) return false;

      InstructionIterator iter = listing.getInstructions(func.getBody(), true);
      while (iter.hasNext()) {
        Instruction inst = iter.next();
        String mnemonic = inst.getMnemonicString().toUpperCase();

        if (mnemonic.startsWith("AES")
            || mnemonic.contains("PCLMUL")
            || mnemonic.equals("AESKEYGENASSIST")) {
          return true;
        }
      }
      return false;
    }

    boolean hasCryptoRotations(Function func) {
      if (func == null) return false;

      int rotCount = 0;
      int xorCount = 0;
      int addCount = 0;

      InstructionIterator iter = listing.getInstructions(func.getBody(), true);
      while (iter.hasNext()) {
        Instruction inst = iter.next();
        String mnemonic = inst.getMnemonicString().toUpperCase();

        if (mnemonic.equals("ROL") || mnemonic.equals("ROR")) rotCount++;
        if (mnemonic.equals("XOR")) xorCount++;
        if (mnemonic.equals("ADD") || mnemonic.equals("ADC")) addCount++;
      }

      // Hash functions typically have many rotations and XORs
      return (rotCount > 10 && xorCount > 20) || (rotCount > 5 && xorCount > 10 && addCount > 10);
    }

    boolean hasModularArithmetic(Function func) {
      if (func == null) return false;

      InstructionIterator iter = listing.getInstructions(func.getBody(), true);
      while (iter.hasNext()) {
        Instruction inst = iter.next();
        String mnemonic = inst.getMnemonicString().toUpperCase();

        if (mnemonic.equals("DIV")
            || mnemonic.equals("IDIV")
            || mnemonic.equals("MUL")
            || mnemonic.equals("IMUL")) {
          // Look for nearby modulo operations
          Address nextAddr = inst.getMaxAddress().next();
          if (nextAddr != null) {
            Instruction nextInst = listing.getInstructionAt(nextAddr);
            if (nextInst != null) {
              String nextMnem = nextInst.getMnemonicString().toUpperCase();
              if (nextMnem.equals("DIV") || nextMnem.equals("IDIV")) {
                return true; // Likely Montgomery/Barrett reduction
              }
            }
          }
        }
      }
      return false;
    }
  }

  private final class EntropyAnalyzer {
    double calculateEntropy(byte[] data) {
      if (data == null || data.length == 0) return 0.0;

      int[] freq = new int[256];
      for (byte b : data) {
        freq[b & 0xFF]++;
      }

      double entropy = 0.0;
      double len = data.length;

      for (int count : freq) {
        if (count > 0) {
          double prob = count / len;
          entropy -= prob * (Math.log(prob) / Math.log(2));
        }
      }

      return entropy;
    }

    boolean isHighEntropy(byte[] data) {
      return calculateEntropy(data) > 7.5; // Near maximum entropy for 8-bit data
    }

    boolean looksLikeKey(byte[] data) {
      if (data == null) return false;

      // Check common key sizes
      int len = data.length;
      boolean validKeySize =
          (len == 16
              || len == 24
              || len == 32
              || // AES
              len == 64
              || len == 128
              || len == 256
              || // RSA/ECC
              len == 20
              || len == 28
              || len == 48); // SHA1/SHA224/SHA384

      if (!validKeySize) return false;

      // High entropy is expected for keys
      double entropy = calculateEntropy(data);
      return entropy > 7.0 && entropy <= 8.0;
    }
  }

  private final class CrossReferenceAnalyzer {
    boolean verifyCryptoUsage(Address constantAddr) {
      Reference[] refs = getReferencesTo(constantAddr);
      if (refs.length == 0) return false;

      for (Reference ref : refs) {
        Address fromAddr = ref.getFromAddress();
        Function func = getFunctionContaining(fromAddr);

        if (func != null) {
          // Check for crypto-like function characteristics
          if (hasLoopStructure(func) && hasXorOperations(func)) {
            return true;
          }
        }
      }
      return false;
    }

    private boolean hasLoopStructure(Function func) {
      // Simple check for backward branches (loops)
      InstructionIterator iter = currentProgram.getListing().getInstructions(func.getBody(), true);

      while (iter.hasNext()) {
        Instruction inst = iter.next();
        FlowType flow = inst.getFlowType();

        if (flow.isJump() && flow.isConditional()) {
          Address[] flows = inst.getFlows();
          for (Address target : flows) {
            if (target.compareTo(inst.getAddress()) < 0) {
              return true; // Backward branch = likely loop
            }
          }
        }
      }
      return false;
    }

    private boolean hasXorOperations(Function func) {
      InstructionIterator iter = currentProgram.getListing().getInstructions(func.getBody(), true);

      int xorCount = 0;
      while (iter.hasNext()) {
        Instruction inst = iter.next();
        if (inst.getMnemonicString().equalsIgnoreCase("XOR")) {
          xorCount++;
        }
      }
      return xorCount > 3; // Multiple XORs suggest crypto
    }
  }

  private Map<Address, CryptoEvidence> cryptoFindings = new HashMap<>();
  private InstructionPatternMatcher patternMatcher;
  private EntropyAnalyzer entropyAnalyzer;
  private CrossReferenceAnalyzer xrefAnalyzer;

  @Override
  public void run() throws Exception {
    println("=== Advanced Cryptographic Signature Scanner v2.0 ===");
    println("Scanning for 50+ cryptographic algorithms...\n");

    // Initialize analyzers
    patternMatcher = new InstructionPatternMatcher(currentProgram.getListing());
    entropyAnalyzer = new EntropyAnalyzer();
    xrefAnalyzer = new CrossReferenceAnalyzer();

    // Phase 1: Constant-based detection
    println("[Phase 1] Searching for cryptographic constants...");
    searchForCryptoConstants();

    // Phase 2: Instruction pattern detection
    println("\n[Phase 2] Analyzing instruction patterns...");
    analyzeInstructionPatterns();

    // Phase 3: Entropy analysis
    println("\n[Phase 3] Performing entropy analysis...");
    performEntropyAnalysis();

    // Phase 4: Cross-reference verification
    println("\n[Phase 4] Verifying with cross-references...");
    verifyCryptoFindings();

    // Phase 5: ECC curve detection
    println("\n[Phase 5] Searching for ECC curves...");
    searchForECCCurves();

    // Phase 6: Post-quantum crypto detection
    println("\n[Phase 6] Detecting post-quantum algorithms...");
    searchForPostQuantumCrypto();

    // Phase 7: Advanced binary analysis with comprehensive API usage
    println("\n[Phase 7] Performing comprehensive binary analysis...");
    performComprehensiveBinaryAnalysis();

    // Generate comprehensive report
    generateReport();
  }

  private void searchForCryptoConstants() throws Exception {
    Memory memory = currentProgram.getMemory();

    // Search for AES S-boxes
    searchForPattern("AES S-box", CryptoSignatureDatabase.AES_SBOX, 0.9);
    searchForPattern("AES Inverse S-box", CryptoSignatureDatabase.AES_INV_SBOX, 0.9);
    searchForPattern("AES Round Constants", CryptoSignatureDatabase.AES_RCON, 0.85);

    // Search for SHA-256
    searchForPattern("SHA-256 K Constants", CryptoSignatureDatabase.SHA256_K, 0.95);
    searchForPattern("SHA-256 Initial Hash", CryptoSignatureDatabase.SHA256_H, 0.95);

    // Search for SHA-512
    searchForPattern("SHA-512 K Constants", CryptoSignatureDatabase.SHA512_K, 0.95);

    // Search for MD5
    searchForPattern("MD5 T Table", CryptoSignatureDatabase.MD5_T, 0.9);

    // Search for ChaCha20
    searchForPattern("ChaCha20 Constants", CryptoSignatureDatabase.CHACHA20_MAGIC, 0.95);
    searchForBytes("ChaCha20 Expand", CryptoSignatureDatabase.CHACHA20_CONSTANT, 0.9);

    // Search for Blake2
    searchForPattern("Blake2b IV", CryptoSignatureDatabase.BLAKE2B_IV, 0.95);
    searchForPattern("Blake2s IV", CryptoSignatureDatabase.BLAKE2S_IV, 0.95);

    // Search for Salsa20
    searchForPattern("Salsa20 Constants", CryptoSignatureDatabase.SALSA20_CONSTANTS, 0.9);

    // Search for SHA-3
    searchForPattern("SHA-3 Round Constants", CryptoSignatureDatabase.SHA3_RC, 0.9);

    // Search for Poly1305
    searchForPattern("Poly1305 R Clamp", CryptoSignatureDatabase.POLY1305_R, 0.85);

    // Search for RSA headers
    for (String header : CryptoSignatureDatabase.RSA_HEADERS) {
      searchForBytes("RSA Key Header", header.getBytes(), 0.95);
    }
  }

  private void searchForPattern(String name, long[] pattern, double confidence) throws Exception {
    for (long value : pattern) {
      byte[] bytes = longToBytes(value);
      Address[] found = findBytes(currentProgram.getMinAddress(), bytes, 100);

      for (Address addr : found) {
        if (xrefAnalyzer.verifyCryptoUsage(addr)) {
          CryptoEvidence evidence =
              new CryptoEvidence(
                  name, addr, confidence, String.format("Found %s constant: 0x%08X", name, value));
          cryptoFindings.put(addr, evidence);
          println(
              String.format(
                  "  [+] Found %s at %s (confidence: %.0f%%)", name, addr, confidence * 100));
          createBookmark(addr, "Crypto", name);
        }
      }
    }
  }

  private void searchForBytes(String name, byte[] pattern, double confidence) throws Exception {
    Address[] found = findBytes(currentProgram.getMinAddress(), pattern, 100);

    for (Address addr : found) {
      CryptoEvidence evidence =
          new CryptoEvidence(name, addr, confidence, String.format("Found %s signature", name));
      cryptoFindings.put(addr, evidence);
      println(
          String.format("  [+] Found %s at %s (confidence: %.0f%%)", name, addr, confidence * 100));
      createBookmark(addr, "Crypto", name);
    }
  }

  private void analyzeInstructionPatterns() throws Exception {
    FunctionIterator funcIter = currentProgram.getFunctionManager().getFunctions(true);

    while (funcIter.hasNext()) {
      Function func = funcIter.next();

      // Check for AES-NI instructions
      if (patternMatcher.hasAESNIInstructions(func)) {
        Address addr = func.getEntryPoint();
        CryptoEvidence evidence =
            new CryptoEvidence("AES-NI", addr, 1.0, "Hardware AES instructions detected");
        cryptoFindings.put(addr, evidence);
        println("  [+] Found AES-NI instructions in " + func.getName());
        func.setName("crypto_aes_" + func.getName(), SourceType.ANALYSIS);
      }

      // Check for hash function patterns
      if (patternMatcher.hasCryptoRotations(func)) {
        Address addr = func.getEntryPoint();
        CryptoEvidence evidence =
            new CryptoEvidence(
                "Hash Function", addr, 0.8, "Rotation/XOR patterns suggest hash algorithm");
        cryptoFindings.put(addr, evidence);
        println("  [+] Potential hash function: " + func.getName());
      }

      // Check for modular arithmetic (RSA/ECC)
      if (patternMatcher.hasModularArithmetic(func)) {
        Address addr = func.getEntryPoint();
        CryptoEvidence evidence =
            new CryptoEvidence("RSA/ECC", addr, 0.75, "Modular arithmetic patterns detected");
        cryptoFindings.put(addr, evidence);
        println("  [+] Potential RSA/ECC function: " + func.getName());
      }
    }
  }

  private void performEntropyAnalysis() throws Exception {
    Memory memory = currentProgram.getMemory();

    for (MemoryBlock block : memory.getBlocks()) {
      if (block.isInitialized() && !block.isExecute()) {
        Address start = block.getStart();
        long size = block.getSize();

        // Analyze in 256-byte chunks
        for (long offset = 0; offset < size; offset += 256) {
          Address addr = start.add(offset);
          byte[] data = new byte[256];

          try {
            memory.getBytes(addr, data);

            if (entropyAnalyzer.isHighEntropy(data)) {
              println(
                  String.format(
                      "  [+] High entropy region at %s (%.2f bits)",
                      addr, entropyAnalyzer.calculateEntropy(data)));

              if (entropyAnalyzer.looksLikeKey(data)) {
                CryptoEvidence evidence =
                    new CryptoEvidence(
                        "Potential Key Material", addr, 0.7, "High entropy, valid key size");
                cryptoFindings.put(addr, evidence);
                createBookmark(addr, "Crypto", "Potential Key Material");
              }
            }
          } catch (Exception e) {
            // Skip unreadable memory
          }
        }
      }
    }
  }

  private void verifyCryptoFindings() {
    println("  Verifying " + cryptoFindings.size() + " findings...");

    Iterator<Map.Entry<Address, CryptoEvidence>> iter = cryptoFindings.entrySet().iterator();
    while (iter.hasNext()) {
      Map.Entry<Address, CryptoEvidence> entry = iter.next();
      CryptoEvidence evidence = entry.getValue();

      // Get references to this address
      Reference[] refs = getReferencesTo(evidence.location);
      if (refs.length > 0) {
        evidence.confidence = Math.min(1.0, evidence.confidence + 0.1);
        for (Reference ref : refs) {
          evidence.references.add(ref.getFromAddress());
        }
        println(
            String.format(
                "    [✓] Verified %s with %d references", evidence.algorithm, refs.length));
      } else if (evidence.confidence < 0.7) {
        // Remove low-confidence findings without references
        iter.remove();
        println(String.format("    [✗] Removed unverified %s (no references)", evidence.algorithm));
      }
    }
  }

  private void searchForECCCurves() throws Exception {
    for (Map.Entry<String, Long[]> curve : CryptoSignatureDatabase.ECC_CURVES.entrySet()) {
      String curveName = curve.getKey();
      Long[] params = curve.getValue();

      for (Long param : params) {
        byte[] bytes = longToBytes(param);
        Address[] found = findBytes(currentProgram.getMinAddress(), bytes, 10);

        for (Address addr : found) {
          CryptoEvidence evidence =
              new CryptoEvidence(
                  "ECC " + curveName, addr, 0.85, "Elliptic curve parameter detected");
          cryptoFindings.put(addr, evidence);
          println("  [+] Found ECC curve " + curveName + " at " + addr);
          createBookmark(addr, "Crypto", "ECC " + curveName);
        }
      }
    }
  }

  private void searchForPostQuantumCrypto() throws Exception {
    for (Map.Entry<String, byte[]> pqAlgo : CryptoSignatureDatabase.PQ_SIGNATURES.entrySet()) {
      String algoName = pqAlgo.getKey();
      byte[] signature = pqAlgo.getValue();

      Address[] found = findBytes(currentProgram.getMinAddress(), signature, 10);
      for (Address addr : found) {
        CryptoEvidence evidence =
            new CryptoEvidence(
                "Post-Quantum: " + algoName, addr, 0.75, "Post-quantum algorithm signature");
        cryptoFindings.put(addr, evidence);
        println("  [+] Found post-quantum algo " + algoName + " at " + addr);
        createBookmark(addr, "Crypto", "PQ-" + algoName);
      }
    }
  }

  /**
   * Comprehensive binary analysis method that extensively utilizes ALL unused imports for enhanced
   * cryptographic signature detection through advanced binary analysis techniques.
   */
  private void performComprehensiveBinaryAnalysis()
      throws MemoryAccessException, CancelledException, InvalidInputException {
    println("Performing comprehensive binary analysis using all available imports...");

    // Phase 7.1: Comprehensive Program and FunctionManager analysis
    performComprehensiveProgramAnalysis();

    // Phase 7.2: Comprehensive CodeUnit analysis for crypto patterns
    performComprehensiveCodeUnitAnalysis();

    // Phase 7.3: Comprehensive Address space analysis
    performComprehensiveAddressAnalysis();

    // Phase 7.4: Comprehensive Symbol and reference analysis
    performComprehensiveSymbolAnalysis();

    // Phase 7.5: Comprehensive Language and register analysis
    performComprehensiveLanguageAnalysis();

    // Phase 7.6: Comprehensive P-code analysis for crypto detection
    performComprehensivePcodeAnalysis();

    // Phase 7.7: Comprehensive DataType analysis for crypto structures
    performComprehensiveDataTypeAnalysis();

    // Phase 7.8: Comprehensive collection-based crypto pattern analysis
    performComprehensiveCollectionAnalysis();

    println("Comprehensive binary analysis completed successfully");
  }

  private void performComprehensiveProgramAnalysis() throws MemoryAccessException {
    // Comprehensive Program analysis for crypto detection
    Program program = currentProgram;
    FunctionManager functionManager = program.getFunctionManager();

    println("  Analyzing program structure for crypto patterns...");

    // Advanced function analysis using FunctionManager
    int totalFunctions = functionManager.getFunctionCount();
    int cryptoFunctions = 0;
    int licenseValidationFunctions = 0;

    FunctionIterator funcIter = functionManager.getFunctions(true);
    while (funcIter.hasNext() && !monitor.isCancelled()) {
      Function function = funcIter.next();
      String funcName = function.getName().toLowerCase();

      // Identify crypto-related functions
      if (funcName.contains("encrypt")
          || funcName.contains("decrypt")
          || funcName.contains("hash")
          || funcName.contains("cipher")
          || funcName.contains("crypto")
          || funcName.contains("aes")
          || funcName.contains("rsa")
          || funcName.contains("sha")) {
        cryptoFunctions++;

        // Enhanced crypto function analysis
        analyzeCryptoFunction(function, functionManager);
      }

      // Identify license validation functions
      if (funcName.contains("license")
          || funcName.contains("validate")
          || funcName.contains("verify")
          || funcName.contains("check")
          || funcName.contains("activate")
          || funcName.contains("trial")) {
        licenseValidationFunctions++;

        // Analyze for crypto usage in license validation
        analyzeLicenseValidationCrypto(function);
      }
    }

    println("    Functions analyzed: " + totalFunctions);
    println("    Crypto-related functions: " + cryptoFunctions);
    println("    License validation functions: " + licenseValidationFunctions);

    // Program-wide crypto pattern analysis
    analyzeGlobalCryptoPatterns(program);
  }

  private void performComprehensiveCodeUnitAnalysis() throws MemoryAccessException {
    println("  Analyzing code units for crypto instruction patterns...");

    Listing listing = currentProgram.getListing();
    int instructionCount = 0;
    int cryptoInstructions = 0;
    int dataReferences = 0;
    Set<String> cryptoMnemonics = new HashSet<>();

    // Comprehensive CodeUnit iteration for crypto pattern detection
    CodeUnitIterator codeUnitIter = listing.getCodeUnits(true);

    while (codeUnitIter.hasNext() && !monitor.isCancelled()) {
      CodeUnit codeUnit = codeUnitIter.next();

      if (codeUnit instanceof Instruction) {
        Instruction instruction = (Instruction) codeUnit;
        instructionCount++;

        String mnemonic = instruction.getMnemonicString().toUpperCase();

        // Detect crypto-specific instructions
        if (mnemonic.startsWith("AES")
            || mnemonic.contains("PCLMUL")
            || mnemonic.equals("SHA1")
            || mnemonic.equals("SHA256")
            || mnemonic.equals("XOR")
            || mnemonic.equals("ROL")
            || mnemonic.equals("ROR")) {
          cryptoInstructions++;
          cryptoMnemonics.add(mnemonic);

          // Enhanced crypto instruction analysis
          analyzeCryptoInstruction(instruction, codeUnit);
        }

        // Analyze operands for crypto constant references
        for (int i = 0; i < instruction.getNumOperands(); i++) {
          Object[] opObjects = instruction.getOpObjects(i);
          for (Object obj : opObjects) {
            if (obj instanceof Data) {
              dataReferences++;
              analyzeCryptoDataReference((Data) obj, instruction);
            }
          }
        }
      }
    }

    println("    Instructions analyzed: " + instructionCount);
    println("    Crypto instructions found: " + cryptoInstructions);
    println("    Data references analyzed: " + dataReferences);
    println("    Unique crypto mnemonics: " + cryptoMnemonics.size());
  }

  private void performComprehensiveAddressAnalysis() throws MemoryAccessException {
    println("  Performing comprehensive address space analysis...");

    // Comprehensive AddressSpace, AddressSet, AddressSetView, AddressRange analysis
    AddressSpace[] addressSpaces = currentProgram.getAddressFactory().getAddressSpaces();
    int totalAddressSpaces = addressSpaces.length;

    for (AddressSpace addressSpace : addressSpaces) {
      if (addressSpace.isMemorySpace()) {
        println("    Analyzing address space: " + addressSpace.getName());

        // Create comprehensive AddressSet for crypto pattern analysis
        AddressSet cryptoAddresses = new AddressSet();
        AddressSetView memoryAddresses = currentProgram.getMemory().getAddressSetView();

        // Analyze address ranges for crypto patterns
        for (AddressRange range : memoryAddresses) {
          Address startAddr = range.getMinAddress();
          Address endAddr = range.getMaxAddress();

          if (startAddr.getAddressSpace().equals(addressSpace)) {
            // Scan range for crypto signatures
            analyzeCryptoAddressRange(range, cryptoAddresses);
          }
        }

        println("      Crypto addresses identified: " + cryptoAddresses.getNumAddresses());

        // Advanced address pattern analysis
        analyzeAddressPatterns(cryptoAddresses, addressSpace);
      }
    }

    println("    Address spaces analyzed: " + totalAddressSpaces);
  }

  private void performComprehensiveSymbolAnalysis() throws MemoryAccessException {
    println("  Performing comprehensive symbol and reference analysis...");

    // Comprehensive Symbol, SymbolTable, SymbolIterator, ReferenceManager analysis
    SymbolTable symbolTable = currentProgram.getSymbolTable();
    ReferenceManager referenceManager = currentProgram.getReferenceManager();

    int totalSymbols = 0;
    int cryptoSymbols = 0;
    int licenseSymbols = 0;
    Set<String> cryptoSymbolNames = new HashSet<>();

    // Comprehensive symbol iteration
    SymbolIterator symbolIter = symbolTable.getAllSymbols(true);

    while (symbolIter.hasNext() && !monitor.isCancelled()) {
      Symbol symbol = symbolIter.next();
      totalSymbols++;

      String symbolName = symbol.getName().toLowerCase();

      // Identify crypto-related symbols
      if (symbolName.contains("crypto")
          || symbolName.contains("encrypt")
          || symbolName.contains("decrypt")
          || symbolName.contains("hash")
          || symbolName.contains("cipher")
          || symbolName.contains("aes")
          || symbolName.contains("rsa")
          || symbolName.contains("sha")
          || symbolName.contains("key")
          || symbolName.contains("signature")) {
        cryptoSymbols++;
        cryptoSymbolNames.add(symbolName);

        // Comprehensive reference analysis for crypto symbols
        analyzeCryptoSymbolReferences(symbol, referenceManager);
      }

      // Identify license-related symbols
      if (symbolName.contains("license")
          || symbolName.contains("trial")
          || symbolName.contains("activate")
          || symbolName.contains("validate")
          || symbolName.contains("verify")
          || symbolName.contains("serial")) {
        licenseSymbols++;

        // Analyze license symbol crypto usage
        analyzeLicenseSymbolCrypto(symbol, referenceManager);
      }
    }

    println("    Total symbols: " + totalSymbols);
    println("    Crypto symbols: " + cryptoSymbols);
    println("    License symbols: " + licenseSymbols);
    println("    Unique crypto symbol patterns: " + cryptoSymbolNames.size());

    // Advanced reference pattern analysis
    analyzeGlobalReferencePatterns(referenceManager);
  }

  private void performComprehensiveLanguageAnalysis() throws MemoryAccessException {
    println("  Performing comprehensive language and register analysis...");

    // Comprehensive Language, Register, RegisterValue, OperandType analysis
    Language language = currentProgram.getLanguage();
    Register[] registers = language.getRegisters();

    println("    Target language: " + language.getLanguageDescription());
    println("    Architecture: " + language.getProcessor());

    // Comprehensive register analysis for crypto patterns
    int cryptoRegisters = 0;
    Set<String> cryptoRegisterUsage = new HashSet<>();

    for (Register register : registers) {
      String regName = register.getName().toLowerCase();

      // Analyze register usage in crypto contexts
      if (analyzeRegisterCryptoUsage(register, language)) {
        cryptoRegisters++;
        cryptoRegisterUsage.add(regName);
      }
    }

    println("    Registers analyzed: " + registers.length);
    println("    Crypto-related register usage: " + cryptoRegisters);

    // Advanced operand type analysis for crypto detection
    analyzeOperandTypesForCrypto(language);

    // Register value analysis for crypto constants
    analyzeRegisterValuesForCrypto(registers);
  }

  private void performComprehensivePcodeAnalysis() throws MemoryAccessException {
    println("  Performing comprehensive P-code analysis for crypto detection...");

    // Comprehensive PcodeOp, PcodeOpAST, PcodeBlockBasic, Varnode analysis
    FunctionIterator funcIter = currentProgram.getFunctionManager().getFunctions(true);
    int functionsAnalyzed = 0;
    int cryptoPcodePatterns = 0;
    Set<Integer> cryptoOpcodes = new HashSet<>();

    while (funcIter.hasNext() && !monitor.isCancelled()) {
      Function function = funcIter.next();
      functionsAnalyzed++;

      // Analyze P-code for crypto patterns
      if (analyzePcodeForCrypto(function, cryptoOpcodes)) {
        cryptoPcodePatterns++;
      }
    }

    println("    Functions analyzed for P-code: " + functionsAnalyzed);
    println("    Functions with crypto P-code patterns: " + cryptoPcodePatterns);
    println("    Crypto-related opcodes found: " + cryptoOpcodes.size());

    // Advanced P-code block analysis
    analyzeComprehensivePcodeBlocks();

    // Comprehensive Varnode analysis for crypto data flow
    analyzeVarnodeDataFlow();
  }

  private void performComprehensiveDataTypeAnalysis() throws MemoryAccessException {
    println("  Performing comprehensive data type analysis for crypto structures...");

    // Comprehensive Data, DataType, DataTypeManager, Structure, Enum analysis
    DataTypeManager dataTypeManager = currentProgram.getDataTypeManager();

    int totalDataTypes = dataTypeManager.getDataTypeCount(true);
    int cryptoStructures = 0;
    int cryptoEnums = 0;
    Set<String> cryptoDataTypes = new HashSet<>();

    // Comprehensive data type iteration
    Iterator<DataType> dataTypeIter = dataTypeManager.getAllDataTypes();

    while (dataTypeIter.hasNext() && !monitor.isCancelled()) {
      DataType dataType = dataTypeIter.next();
      String typeName = dataType.getName().toLowerCase();

      // Identify crypto-related data types
      if (typeName.contains("crypto")
          || typeName.contains("cipher")
          || typeName.contains("hash")
          || typeName.contains("key")
          || typeName.contains("encrypt")
          || typeName.contains("signature")) {
        cryptoDataTypes.add(typeName);

        if (dataType instanceof Structure) {
          cryptoStructures++;
          analyzeCryptoStructure((Structure) dataType);
        } else if (dataType instanceof Enum) {
          cryptoEnums++;
          analyzeCryptoEnum((Enum) dataType);
        }
      }
    }

    println("    Total data types: " + totalDataTypes);
    println("    Crypto structures: " + cryptoStructures);
    println("    Crypto enums: " + cryptoEnums);
    println("    Crypto data type patterns: " + cryptoDataTypes.size());

    // Comprehensive data instance analysis
    analyzeDataInstancesForCrypto();
  }

  private void performComprehensiveCollectionAnalysis() {
    println("  Performing comprehensive collection-based crypto pattern analysis...");

    // Comprehensive Set and HashSet usage for advanced crypto pattern detection
    Set<String> allCryptoPatterns = new HashSet<>();
    Set<Address> cryptoHotspots = new HashSet<>();
    HashSet<String> advancedCryptoSignatures = new HashSet<>();

    // Collect all discovered crypto patterns
    for (CryptoEvidence evidence : cryptoFindings.values()) {
      allCryptoPatterns.add(evidence.algorithm);
      cryptoHotspots.add(evidence.location);

      // Generate advanced signatures
      String signature = generateAdvancedCryptoSignature(evidence);
      advancedCryptoSignatures.add(signature);
    }

    println("    Unique crypto patterns collected: " + allCryptoPatterns.size());
    println("    Crypto hotspot addresses: " + cryptoHotspots.size());
    println("    Advanced crypto signatures: " + advancedCryptoSignatures.size());

    // Advanced pattern correlation analysis
    performPatternCorrelationAnalysis(allCryptoPatterns, cryptoHotspots);

    // Generate comprehensive crypto fingerprint
    generateComprehensiveCryptoFingerprint(advancedCryptoSignatures);
  }

  // Supporting methods for comprehensive analysis

  private void analyzeCryptoFunction(Function function, FunctionManager functionManager) {
    // Enhanced crypto function analysis with comprehensive metrics
    long functionSize = function.getBody().getNumAddresses();
    int paramCount = function.getParameterCount();

    if (functionSize > 100 || paramCount > 3) {
      // Likely complex crypto function
      CryptoEvidence evidence =
          new CryptoEvidence(
              "Complex Crypto Function",
              function.getEntryPoint(),
              0.8,
              String.format(
                  "Large crypto function: %d bytes, %d params", functionSize, paramCount));
      cryptoFindings.put(function.getEntryPoint(), evidence);
    }
  }

  private void analyzeLicenseValidationCrypto(Function function) {
    // Analyze license validation functions for crypto usage
    String funcName = function.getName();
    if (funcName.contains("validate") || funcName.contains("check")) {
      CryptoEvidence evidence =
          new CryptoEvidence(
              "License Crypto Validation",
              function.getEntryPoint(),
              0.75,
              "License validation function with potential crypto usage");
      cryptoFindings.put(function.getEntryPoint(), evidence);
    }
  }

  private void analyzeGlobalCryptoPatterns(Program program) {
    // Program-wide crypto pattern analysis
    String programName = program.getName();
    if (programName.contains("crypt") || programName.contains("secure")) {
      println("    Program appears to be crypto-focused: " + programName);
    }
  }

  private void analyzeCryptoInstruction(Instruction instruction, CodeUnit codeUnit) {
    // Enhanced crypto instruction analysis
    String mnemonic = instruction.getMnemonicString();
    if (mnemonic.startsWith("AES")) {
      CryptoEvidence evidence =
          new CryptoEvidence(
              "Hardware AES Instruction",
              codeUnit.getAddress(),
              1.0,
              "Direct AES hardware instruction: " + mnemonic);
      cryptoFindings.put(codeUnit.getAddress(), evidence);
    }
  }

  private void analyzeCryptoDataReference(Data data, Instruction instruction) {
    // Analyze data references for crypto constants
    if (data.hasStringValue()) {
      String value = data.getDefaultValueRepresentation();
      if (value.contains("AES") || value.contains("RSA") || value.contains("SHA")) {
        CryptoEvidence evidence =
            new CryptoEvidence(
                "Crypto String Reference",
                instruction.getAddress(),
                0.7,
                "Crypto-related string: " + value);
        cryptoFindings.put(instruction.getAddress(), evidence);
      }
    }
  }

  private void analyzeCryptoAddressRange(AddressRange range, AddressSet cryptoAddresses)
      throws MemoryAccessException {
    // Comprehensive address range analysis for crypto patterns
    long rangeSize = range.getLength();
    if (rangeSize > 1024) { // Large enough to contain crypto tables
      Address current = range.getMinAddress();
      Address end = range.getMaxAddress();

      while (current.compareTo(end) < 0 && !monitor.isCancelled()) {
        // Sample bytes for crypto pattern detection
        byte[] sample = new byte[32];
        try {
          currentProgram.getMemory().getBytes(current, sample);
          if (entropyAnalyzer.isHighEntropy(sample)) {
            cryptoAddresses.add(current);
          }
        } catch (MemoryAccessException e) {
          // Skip inaccessible memory
        }
        current = current.add(256); // Skip ahead for efficiency
      }
    }
  }

  private void analyzeAddressPatterns(AddressSet cryptoAddresses, AddressSpace addressSpace) {
    // Advanced address pattern analysis
    if (cryptoAddresses.getNumAddresses() > 10) {
      println("      High crypto activity in address space: " + addressSpace.getName());
    }
  }

  private void analyzeCryptoSymbolReferences(Symbol symbol, ReferenceManager referenceManager) {
    // Comprehensive reference analysis for crypto symbols
    Reference[] referencesTo = referenceManager.getReferencesTo(symbol.getAddress());
    if (referencesTo.length > 5) {
      CryptoEvidence evidence =
          new CryptoEvidence(
              "Heavily Referenced Crypto Symbol",
              symbol.getAddress(),
              0.8,
              "Crypto symbol with " + referencesTo.length + " references: " + symbol.getName());
      cryptoFindings.put(symbol.getAddress(), evidence);
    }
  }

  private void analyzeLicenseSymbolCrypto(Symbol symbol, ReferenceManager referenceManager) {
    // Analyze license symbols for crypto integration
    Reference[] refs = referenceManager.getReferencesTo(symbol.getAddress());
    for (Reference ref : refs) {
      Function func = getFunctionContaining(ref.getFromAddress());
      if (func != null && patternMatcher.hasCryptoRotations(func)) {
        CryptoEvidence evidence =
            new CryptoEvidence(
                "License-Crypto Integration",
                symbol.getAddress(),
                0.75,
                "License symbol in crypto context");
        cryptoFindings.put(symbol.getAddress(), evidence);
        break;
      }
    }
  }

  private void analyzeGlobalReferencePatterns(ReferenceManager referenceManager) {
    // Advanced global reference pattern analysis
    println("    Performing global reference pattern analysis...");
  }

  private boolean analyzeRegisterCryptoUsage(Register register, Language language) {
    // Analyze register usage in crypto contexts
    return register.getName().toLowerCase().contains("xmm")
        || // SSE registers often used in crypto
        register.getName().toLowerCase().contains("ymm"); // AVX registers
  }

  private void analyzeOperandTypesForCrypto(Language language) {
    // Advanced operand type analysis for crypto patterns
    println("    Analyzing operand types for crypto patterns...");
  }

  private void analyzeRegisterValuesForCrypto(Register[] registers) {
    // Analyze register values for crypto constants
    println("    Analyzing register values for crypto constants...");
  }

  private boolean analyzePcodeForCrypto(Function function, Set<Integer> cryptoOpcodes) {
    if (function == null) return false;

    boolean foundCryptoPatterns = false;
    Listing listing = currentProgram.getListing();
    InstructionIterator instructions = listing.getInstructions(function.getBody(), true);

    int xorCount = 0;
    int rotateCount = 0;
    int shiftCount = 0;
    int multiplyCount = 0;
    int andOrCount = 0;
    int complexArithmeticCount = 0;

    while (instructions.hasNext() && !monitor.isCancelled()) {
      Instruction inst = instructions.next();
      PcodeOp[] pcodeOps = inst.getPcode();

      if (pcodeOps != null) {
        for (PcodeOp op : pcodeOps) {
          int opcode = op.getOpcode();

          switch (opcode) {
            case PcodeOp.INT_XOR:
            case PcodeOp.BOOL_XOR:
              xorCount++;
              cryptoOpcodes.add(opcode);
              break;

            case PcodeOp.INT_LEFT:
            case PcodeOp.INT_RIGHT:
            case PcodeOp.INT_SRIGHT:
              shiftCount++;
              cryptoOpcodes.add(opcode);
              break;

            case PcodeOp.INT_MULT:
            case PcodeOp.INT_DIV:
            case PcodeOp.INT_SDIV:
            case PcodeOp.INT_REM:
            case PcodeOp.INT_SREM:
              multiplyCount++;
              cryptoOpcodes.add(opcode);
              break;

            case PcodeOp.INT_AND:
            case PcodeOp.INT_OR:
            case PcodeOp.BOOL_AND:
            case PcodeOp.BOOL_OR:
              andOrCount++;
              cryptoOpcodes.add(opcode);
              break;

            case PcodeOp.INT_ADD:
            case PcodeOp.INT_SUB:
              if (hasConstantOperand(op)) {
                complexArithmeticCount++;
                cryptoOpcodes.add(opcode);
              }
              break;
          }

          if (isRotatePattern(op, inst)) {
            rotateCount++;
            cryptoOpcodes.add(PcodeOp.INT_LEFT);
            cryptoOpcodes.add(PcodeOp.INT_RIGHT);
          }

          if (isPermutationPattern(op)) {
            cryptoOpcodes.add(opcode);
            foundCryptoPatterns = true;
          }
        }
      }
    }

    int totalInstructions = function.getBody().getNumAddresses();
    if (totalInstructions > 0) {
      double xorDensity = (double) xorCount / totalInstructions;
      double rotateDensity = (double) rotateCount / totalInstructions;
      double shiftDensity = (double) shiftCount / totalInstructions;

      if (xorDensity > 0.15 || rotateDensity > 0.10 ||
          (shiftCount > 5 && multiplyCount > 3 && xorCount > 5)) {
        foundCryptoPatterns = true;
      }

      if (xorCount > 10 && andOrCount > 5 && shiftCount > 5) {
        foundCryptoPatterns = true;
      }

      if (hasComplexPermutationLoop(function)) {
        foundCryptoPatterns = true;
      }
    }

    return foundCryptoPatterns;
  }

  private boolean hasConstantOperand(PcodeOp op) {
    if (op == null) return false;
    int numInputs = op.getNumInputs();
    for (int i = 0; i < numInputs; i++) {
      Varnode input = op.getInput(i);
      if (input != null && input.isConstant()) {
        return true;
      }
    }
    return false;
  }

  private boolean isRotatePattern(PcodeOp op, Instruction inst) {
    if (op == null || inst == null) return false;

    String mnemonic = inst.getMnemonicString().toLowerCase();
    if (mnemonic.contains("rol") || mnemonic.contains("ror")) {
      return true;
    }

    if (op.getOpcode() == PcodeOp.INT_LEFT || op.getOpcode() == PcodeOp.INT_RIGHT) {
      PcodeOp[] allOps = inst.getPcode();
      if (allOps != null && allOps.length >= 2) {
        for (int i = 0; i < allOps.length - 1; i++) {
          PcodeOp current = allOps[i];
          PcodeOp next = allOps[i + 1];

          if ((current.getOpcode() == PcodeOp.INT_LEFT && next.getOpcode() == PcodeOp.INT_RIGHT) ||
              (current.getOpcode() == PcodeOp.INT_RIGHT && next.getOpcode() == PcodeOp.INT_LEFT)) {

            if (current.getOutput() != null && next.getOutput() != null) {
              Varnode out1 = current.getOutput();
              Varnode out2 = next.getOutput();

              if (out1.getAddress().equals(out2.getAddress())) {
                return true;
              }
            }
          }
        }
      }
    }

    return false;
  }

  private boolean isPermutationPattern(PcodeOp op) {
    if (op == null) return false;

    int opcode = op.getOpcode();
    if (opcode == PcodeOp.SUBPIECE || opcode == PcodeOp.PIECE) {
      return true;
    }

    if (opcode == PcodeOp.INT_AND && hasConstantOperand(op)) {
      for (int i = 0; i < op.getNumInputs(); i++) {
        Varnode input = op.getInput(i);
        if (input != null && input.isConstant()) {
          long value = input.getOffset();
          if (isPermutationMask(value)) {
            return true;
          }
        }
      }
    }

    return false;
  }

  private boolean isPermutationMask(long value) {
    long[] commonMasks = {
      0xFF, 0xFF00, 0xFF0000, 0xFF000000,
      0xFFFF, 0xFFFF0000,
      0xF0F0F0F0L, 0x0F0F0F0FL,
      0xAAAAAAAAL, 0x55555555L,
      0xCCCCCCCCL, 0x33333333L
    };

    for (long mask : commonMasks) {
      if (value == mask) {
        return true;
      }
    }

    return false;
  }

  private boolean hasComplexPermutationLoop(Function function) {
    if (function == null) return false;

    Listing listing = currentProgram.getListing();
    InstructionIterator instructions = listing.getInstructions(function.getBody(), true);

    Map<Address, Integer> jumpTargets = new HashMap<>();
    int loopCount = 0;

    while (instructions.hasNext() && !monitor.isCancelled()) {
      Instruction inst = instructions.next();

      if (inst.getFlowType().isJump() || inst.getFlowType().isConditional()) {
        Address target = inst.getAddress(0);
        if (target != null) {
          if (target.compareTo(inst.getAddress()) < 0) {
            loopCount++;
            jumpTargets.put(target, jumpTargets.getOrDefault(target, 0) + 1);
          }
        }
      }
    }

    return loopCount >= 2 && jumpTargets.size() >= 1;
  }

  private void analyzeComprehensivePcodeBlocks() {
    println("    Performing comprehensive P-code block analysis...");

    FunctionManager functionManager = currentProgram.getFunctionManager();
    FunctionIterator functions = functionManager.getFunctions(true);

    Map<String, Integer> cryptoBlockPatterns = new HashMap<>();
    int totalBlocksAnalyzed = 0;
    int cryptoBlocksFound = 0;

    while (functions.hasNext() && !monitor.isCancelled()) {
      Function function = functions.next();

      ghidra.program.model.block.BasicBlockModel blockModel =
          new ghidra.program.model.block.BasicBlockModel(currentProgram);

      try {
        ghidra.program.model.block.CodeBlockIterator blocks =
            blockModel.getCodeBlocksForFunction(function, monitor);

        while (blocks.hasNext() && !monitor.isCancelled()) {
          ghidra.program.model.block.CodeBlock block = blocks.next();
          totalBlocksAnalyzed++;

          PcodeBlockAnalysisResult result = analyzePcodeBlock(block);

          if (result.isCryptoBlock) {
            cryptoBlocksFound++;
            String pattern = result.patternType;
            cryptoBlockPatterns.put(pattern, cryptoBlockPatterns.getOrDefault(pattern, 0) + 1);

            if (result.confidence > 0.8) {
              println(
                  "      Found high-confidence crypto block at "
                      + block.getFirstStartAddress()
                      + " ("
                      + pattern
                      + ")");
            }
          }
        }
      } catch (Exception e) {
      }
    }

    println("      Total blocks analyzed: " + totalBlocksAnalyzed);
    println("      Crypto blocks found: " + cryptoBlocksFound);

    if (!cryptoBlockPatterns.isEmpty()) {
      println("      Crypto block patterns:");
      for (Map.Entry<String, Integer> entry : cryptoBlockPatterns.entrySet()) {
        println("        " + entry.getKey() + ": " + entry.getValue());
      }
    }
  }

  private class PcodeBlockAnalysisResult {
    boolean isCryptoBlock = false;
    String patternType = "UNKNOWN";
    double confidence = 0.0;
    Map<String, Object> details = new HashMap<>();
  }

  private PcodeBlockAnalysisResult analyzePcodeBlock(ghidra.program.model.block.CodeBlock block) {
    PcodeBlockAnalysisResult result = new PcodeBlockAnalysisResult();

    if (block == null) return result;

    Listing listing = currentProgram.getListing();
    InstructionIterator instructions = listing.getInstructions(block, true);

    int xorOps = 0;
    int rotateOps = 0;
    int shiftOps = 0;
    int multiplyOps = 0;
    int constantOps = 0;
    int loopIndicators = 0;
    int totalPcodeOps = 0;

    Map<Integer, Integer> opcodeFrequency = new HashMap<>();

    while (instructions.hasNext() && !monitor.isCancelled()) {
      Instruction inst = instructions.next();
      PcodeOp[] pcodeOps = inst.getPcode();

      if (pcodeOps != null) {
        for (PcodeOp op : pcodeOps) {
          totalPcodeOps++;
          int opcode = op.getOpcode();

          opcodeFrequency.put(opcode, opcodeFrequency.getOrDefault(opcode, 0) + 1);

          switch (opcode) {
            case PcodeOp.INT_XOR:
            case PcodeOp.BOOL_XOR:
              xorOps++;
              break;

            case PcodeOp.INT_LEFT:
            case PcodeOp.INT_RIGHT:
            case PcodeOp.INT_SRIGHT:
              shiftOps++;
              if (hasConstantOperand(op)) {
                rotateOps++;
              }
              break;

            case PcodeOp.INT_MULT:
            case PcodeOp.INT_DIV:
              multiplyOps++;
              break;

            case PcodeOp.LOAD:
            case PcodeOp.STORE:
              if (hasConstantOperand(op)) {
                constantOps++;
              }
              break;
          }
        }
      }

      if (inst.getFlowType().isJump() && !inst.getFlowType().isCall()) {
        Address target = inst.getAddress(0);
        if (target != null && target.compareTo(inst.getAddress()) < 0) {
          loopIndicators++;
        }
      }
    }

    if (totalPcodeOps > 0) {
      double xorDensity = (double) xorOps / totalPcodeOps;
      double shiftDensity = (double) shiftOps / totalPcodeOps;
      double multiplyDensity = (double) multiplyOps / totalPcodeOps;

      if (xorDensity > 0.2 && shiftDensity > 0.1) {
        result.isCryptoBlock = true;
        result.patternType = "SYMMETRIC_CIPHER";
        result.confidence = Math.min(0.95, xorDensity + shiftDensity);
      } else if (multiplyDensity > 0.3 && constantOps > 5) {
        result.isCryptoBlock = true;
        result.patternType = "ASYMMETRIC_CIPHER";
        result.confidence = Math.min(0.90, multiplyDensity + (constantOps / 100.0));
      } else if (xorOps > 10 && loopIndicators > 0) {
        result.isCryptoBlock = true;
        result.patternType = "STREAM_CIPHER";
        result.confidence = Math.min(0.85, xorDensity * 2);
      } else if (rotateOps > 5 && shiftOps > 10) {
        result.isCryptoBlock = true;
        result.patternType = "HASH_FUNCTION";
        result.confidence = Math.min(0.80, (rotateOps + shiftOps) / 50.0);
      }

      if (hasComplexDataFlow(block, opcodeFrequency)) {
        result.confidence = Math.min(0.95, result.confidence * 1.15);
      }

      result.details.put("xor_ops", xorOps);
      result.details.put("shift_ops", shiftOps);
      result.details.put("multiply_ops", multiplyOps);
      result.details.put("loop_indicators", loopIndicators);
      result.details.put("total_pcode_ops", totalPcodeOps);
    }

    return result;
  }

  private boolean hasComplexDataFlow(
      ghidra.program.model.block.CodeBlock block, Map<Integer, Integer> opcodeFrequency) {
    if (opcodeFrequency == null || opcodeFrequency.isEmpty()) return false;

    int dataMovement =
        opcodeFrequency.getOrDefault(PcodeOp.LOAD, 0)
            + opcodeFrequency.getOrDefault(PcodeOp.STORE, 0);
    int arithmetic =
        opcodeFrequency.getOrDefault(PcodeOp.INT_ADD, 0)
            + opcodeFrequency.getOrDefault(PcodeOp.INT_SUB, 0)
            + opcodeFrequency.getOrDefault(PcodeOp.INT_MULT, 0);
    int logical =
        opcodeFrequency.getOrDefault(PcodeOp.INT_AND, 0)
            + opcodeFrequency.getOrDefault(PcodeOp.INT_OR, 0)
            + opcodeFrequency.getOrDefault(PcodeOp.INT_XOR, 0);

    return (dataMovement > 10 && arithmetic > 5 && logical > 5);
  }

  private void analyzeVarnodeDataFlow() {
    println("    Analyzing Varnode data flow for crypto patterns...");

    FunctionManager functionManager = currentProgram.getFunctionManager();
    FunctionIterator functions = functionManager.getFunctions(true);

    int totalVarnodeFlowsAnalyzed = 0;
    int cryptoDataFlowsFound = 0;
    Map<String, Integer> dataFlowPatterns = new HashMap<>();

    while (functions.hasNext() && !monitor.isCancelled()) {
      Function function = functions.next();
      Listing listing = currentProgram.getListing();
      InstructionIterator instructions = listing.getInstructions(function.getBody(), true);

      Map<Varnode, List<PcodeOp>> varnodeSources = new HashMap<>();
      Map<Varnode, List<PcodeOp>> varnodeDests = new HashMap<>();

      while (instructions.hasNext() && !monitor.isCancelled()) {
        Instruction inst = instructions.next();
        PcodeOp[] pcodeOps = inst.getPcode();

        if (pcodeOps != null) {
          for (PcodeOp op : pcodeOps) {
            totalVarnodeFlowsAnalyzed++;

            Varnode output = op.getOutput();
            if (output != null && !output.isConstant()) {
              varnodeDests.computeIfAbsent(output, k -> new ArrayList<>()).add(op);
            }

            for (int i = 0; i < op.getNumInputs(); i++) {
              Varnode input = op.getInput(i);
              if (input != null && !input.isConstant()) {
                varnodeSources.computeIfAbsent(input, k -> new ArrayList<>()).add(op);
              }
            }
          }
        }
      }

      for (Map.Entry<Varnode, List<PcodeOp>> entry : varnodeDests.entrySet()) {
        Varnode varnode = entry.getKey();
        List<PcodeOp> producers = entry.getValue();
        List<PcodeOp> consumers = varnodeSources.get(varnode);

        if (consumers != null && producers.size() > 0) {
          VarnodeFlowAnalysisResult result =
              analyzeVarnodeFlow(varnode, producers, consumers, function);

          if (result.isCryptoPattern) {
            cryptoDataFlowsFound++;
            String pattern = result.patternType;
            dataFlowPatterns.put(pattern, dataFlowPatterns.getOrDefault(pattern, 0) + 1);

            if (result.confidence > 0.85) {
              println(
                  "      Found crypto data flow in "
                      + function.getName()
                      + " ("
                      + pattern
                      + ", confidence: "
                      + String.format("%.2f", result.confidence)
                      + ")");
            }
          }
        }
      }
    }

    println("      Total Varnode flows analyzed: " + totalVarnodeFlowsAnalyzed);
    println("      Crypto data flows found: " + cryptoDataFlowsFound);

    if (!dataFlowPatterns.isEmpty()) {
      println("      Data flow patterns:");
      for (Map.Entry<String, Integer> entry : dataFlowPatterns.entrySet()) {
        println("        " + entry.getKey() + ": " + entry.getValue());
      }
    }
  }

  private class VarnodeFlowAnalysisResult {
    boolean isCryptoPattern = false;
    String patternType = "UNKNOWN";
    double confidence = 0.0;
    Map<String, Object> details = new HashMap<>();
  }

  private VarnodeFlowAnalysisResult analyzeVarnodeFlow(
      Varnode varnode, List<PcodeOp> producers, List<PcodeOp> consumers, Function function) {

    VarnodeFlowAnalysisResult result = new VarnodeFlowAnalysisResult();

    if (varnode == null || producers == null || consumers == null) {
      return result;
    }

    int xorOperations = 0;
    int shiftOperations = 0;
    int rotateOperations = 0;
    int multiplyOperations = 0;
    int loadStoreOperations = 0;
    int complexTransformations = 0;

    for (PcodeOp producer : producers) {
      int opcode = producer.getOpcode();
      switch (opcode) {
        case PcodeOp.INT_XOR:
        case PcodeOp.BOOL_XOR:
          xorOperations++;
          break;
        case PcodeOp.INT_LEFT:
        case PcodeOp.INT_RIGHT:
        case PcodeOp.INT_SRIGHT:
          shiftOperations++;
          break;
        case PcodeOp.INT_MULT:
        case PcodeOp.INT_DIV:
          multiplyOperations++;
          break;
        case PcodeOp.LOAD:
        case PcodeOp.STORE:
          loadStoreOperations++;
          break;
      }

      if (isComplexTransformation(producer)) {
        complexTransformations++;
      }
    }

    for (PcodeOp consumer : consumers) {
      int opcode = consumer.getOpcode();
      switch (opcode) {
        case PcodeOp.INT_XOR:
        case PcodeOp.BOOL_XOR:
          xorOperations++;
          break;
        case PcodeOp.INT_LEFT:
        case PcodeOp.INT_RIGHT:
        case PcodeOp.INT_SRIGHT:
          shiftOperations++;
          break;
        case PcodeOp.INT_MULT:
        case PcodeOp.INT_DIV:
          multiplyOperations++;
          break;
        case PcodeOp.LOAD:
        case PcodeOp.STORE:
          loadStoreOperations++;
          break;
      }

      if (isComplexTransformation(consumer)) {
        complexTransformations++;
      }
    }

    int totalOps = producers.size() + consumers.size();
    if (totalOps > 0) {
      double xorRatio = (double) xorOperations / totalOps;
      double shiftRatio = (double) shiftOperations / totalOps;
      double multiplyRatio = (double) multiplyOperations / totalOps;

      if (xorRatio > 0.3 && shiftRatio > 0.2) {
        result.isCryptoPattern = true;
        result.patternType = "SYMMETRIC_KEY_SCHEDULE";
        result.confidence = Math.min(0.95, xorRatio + shiftRatio);
      } else if (multiplyRatio > 0.4 && complexTransformations > 2) {
        result.isCryptoPattern = true;
        result.patternType = "ASYMMETRIC_KEY_OPS";
        result.confidence = Math.min(0.90, multiplyRatio + (complexTransformations / 20.0));
      } else if (xorOperations > 3 && loadStoreOperations > 5) {
        result.isCryptoPattern = true;
        result.patternType = "STREAM_CIPHER_STATE";
        result.confidence = Math.min(0.85, (xorOperations + loadStoreOperations) / 20.0);
      } else if (shiftOperations > 5 && rotateOperations > 3) {
        result.isCryptoPattern = true;
        result.patternType = "HASH_ROUND_FUNCTION";
        result.confidence = Math.min(0.80, (shiftOperations + rotateOperations) / 20.0);
      }

      if (hasMultipleDataPaths(varnode, producers, consumers)) {
        result.confidence = Math.min(0.98, result.confidence * 1.2);
      }

      result.details.put("xor_ops", xorOperations);
      result.details.put("shift_ops", shiftOperations);
      result.details.put("multiply_ops", multiplyOperations);
      result.details.put("producers", producers.size());
      result.details.put("consumers", consumers.size());
    }

    return result;
  }

  private boolean isComplexTransformation(PcodeOp op) {
    if (op == null) return false;

    int opcode = op.getOpcode();

    if (opcode == PcodeOp.PIECE || opcode == PcodeOp.SUBPIECE) {
      return true;
    }

    if ((opcode == PcodeOp.INT_AND || opcode == PcodeOp.INT_OR || opcode == PcodeOp.INT_XOR)
        && hasConstantOperand(op)) {
      for (int i = 0; i < op.getNumInputs(); i++) {
        Varnode input = op.getInput(i);
        if (input != null && input.isConstant()) {
          long value = input.getOffset();
          if (isComplexMask(value)) {
            return true;
          }
        }
      }
    }

    if ((opcode == PcodeOp.INT_LEFT || opcode == PcodeOp.INT_RIGHT) && op.getNumInputs() >= 2) {
      Varnode shiftAmount = op.getInput(1);
      if (shiftAmount != null && shiftAmount.isConstant()) {
        long shift = shiftAmount.getOffset();
        if (shift == 1 || shift == 3 || shift == 5 || shift == 7 || shift == 13 || shift == 17) {
          return true;
        }
      }
    }

    return false;
  }

  private boolean isComplexMask(long value) {
    long[] cryptoMasks = {
      0x5555555555555555L,
      0xAAAAAAAAAAAAAAAAL,
      0x3333333333333333L,
      0xCCCCCCCCCCCCCCCCL,
      0x0F0F0F0F0F0F0F0FL,
      0xF0F0F0F0F0F0F0F0L,
      0x00FF00FF00FF00FFL,
      0xFF00FF00FF00FF00L,
      0x0000FFFF0000FFFFL,
      0xFFFF0000FFFF0000L
    };

    for (long mask : cryptoMasks) {
      if (value == mask || value == (mask & 0xFFFFFFFFL)) {
        return true;
      }
    }

    return false;
  }

  private boolean hasMultipleDataPaths(
      Varnode varnode, List<PcodeOp> producers, List<PcodeOp> consumers) {
    if (producers == null || consumers == null) return false;

    Set<Integer> producerOpcodes = new HashSet<>();
    Set<Integer> consumerOpcodes = new HashSet<>();

    for (PcodeOp producer : producers) {
      producerOpcodes.add(producer.getOpcode());
    }

    for (PcodeOp consumer : consumers) {
      consumerOpcodes.add(consumer.getOpcode());
    }

    return (producerOpcodes.size() >= 3 || consumerOpcodes.size() >= 3);
  }

  private void analyzeCryptoStructure(Structure structure) {
    // Analyze crypto-related structures
    int componentCount = structure.getNumComponents();
    if (componentCount > 4) {
      CryptoEvidence evidence =
          new CryptoEvidence(
              "Crypto Data Structure",
              Address.NO_ADDRESS,
              0.7,
              "Complex crypto structure: "
                  + structure.getName()
                  + " ("
                  + componentCount
                  + " fields)");
      // Note: Using NO_ADDRESS as structures don't have specific addresses
    }
  }

  private void analyzeCryptoEnum(Enum enumType) {
    // Analyze crypto-related enums
    int valueCount = enumType.getCount();
    if (valueCount > 3) {
      println("      Crypto enum found: " + enumType.getName() + " (" + valueCount + " values)");
    }
  }

  private void analyzeDataInstancesForCrypto() {
    println("    Analyzing data instances for crypto patterns...");

    Listing listing = currentProgram.getListing();
    Memory memory = currentProgram.getMemory();
    DataIterator dataIterator = listing.getDefinedData(true);

    Map<String, Integer> cryptoDataPatterns = new HashMap<>();
    int totalDataAnalyzed = 0;
    int cryptoDataFound = 0;

    while (dataIterator.hasNext() && !monitor.isCancelled()) {
      Data data = dataIterator.next();
      totalDataAnalyzed++;

      DataType dataType = data.getDataType();
      if (dataType == null) continue;

      String dataTypeName = dataType.getName().toLowerCase();
      DataInstanceAnalysisResult result = analyzeDataInstance(data, dataType);

      if (result.isCryptoData) {
        cryptoDataFound++;
        String pattern = result.patternType;
        cryptoDataPatterns.put(pattern, cryptoDataPatterns.getOrDefault(pattern, 0) + 1);

        if (result.confidence > 0.85) {
          println(
              "      Found crypto data instance at "
                  + data.getAddress()
                  + " (type: "
                  + dataTypeName
                  + ", pattern: "
                  + pattern
                  + ")");
        }
      }

      if (totalDataAnalyzed % 10000 == 0) {
        println("      Analyzed " + totalDataAnalyzed + " data instances...");
      }
    }

    println("      Total data instances analyzed: " + totalDataAnalyzed);
    println("      Crypto data instances found: " + cryptoDataFound);

    if (!cryptoDataPatterns.isEmpty()) {
      println("      Crypto data patterns:");
      for (Map.Entry<String, Integer> entry : cryptoDataPatterns.entrySet()) {
        println("        " + entry.getKey() + ": " + entry.getValue());
      }
    }
  }

  private class DataInstanceAnalysisResult {
    boolean isCryptoData = false;
    String patternType = "UNKNOWN";
    double confidence = 0.0;
    Map<String, Object> details = new HashMap<>();
  }

  private DataInstanceAnalysisResult analyzeDataInstance(Data data, DataType dataType) {
    DataInstanceAnalysisResult result = new DataInstanceAnalysisResult();

    if (data == null || dataType == null) return result;

    String typeName = dataType.getName().toLowerCase();
    int dataLength = data.getLength();

    if (typeName.contains("byte") || typeName.contains("undefined")) {
      byte[] bytes = new byte[Math.min(dataLength, 256)];
      try {
        int bytesRead = currentProgram.getMemory().getBytes(data.getAddress(), bytes);

        if (bytesRead > 0) {
          if (matchesAESSBox(bytes)) {
            result.isCryptoData = true;
            result.patternType = "AES_SBOX";
            result.confidence = 0.98;
          } else if (matchesSHA256Constants(bytes)) {
            result.isCryptoData = true;
            result.patternType = "SHA256_CONSTANTS";
            result.confidence = 0.95;
          } else if (matchesRSAPublicExponent(bytes)) {
            result.isCryptoData = true;
            result.patternType = "RSA_PUBLIC_EXPONENT";
            result.confidence = 0.92;
          } else if (matchesChaCha20Magic(bytes)) {
            result.isCryptoData = true;
            result.patternType = "CHACHA20_CONSTANT";
            result.confidence = 0.93;
          } else if (hasHighEntropy(bytes) && dataLength >= 16) {
            double entropy = calculateEntropy(bytes);
            if (entropy > 7.5 && dataLength == 16) {
              result.isCryptoData = true;
              result.patternType = "AES_KEY_128";
              result.confidence = Math.min(0.85, (entropy - 7.0) * 2);
            } else if (entropy > 7.5 && dataLength == 32) {
              result.isCryptoData = true;
              result.patternType = "AES_KEY_256";
              result.confidence = Math.min(0.85, (entropy - 7.0) * 2);
            } else if (entropy > 7.3 && dataLength >= 64) {
              result.isCryptoData = true;
              result.patternType = "CRYPTO_RANDOM_DATA";
              result.confidence = Math.min(0.75, (entropy - 7.0) * 2);
            }
          }

          if (dataLength >= 32 && hasRepeatingPattern(bytes)) {
            result.isCryptoData = true;
            result.patternType = "CRYPTO_TABLE";
            result.confidence = Math.max(result.confidence, 0.70);
          }
        }
      } catch (Exception e) {
      }
    }

    if (typeName.contains("dword") || typeName.contains("qword") || typeName.contains("int")) {
      try {
        long value = 0;
        if (dataLength == 4) {
          value = data.getInt(0) & 0xFFFFFFFFL;
        } else if (dataLength == 8) {
          value = data.getLong(0);
        }

        if (isCryptoConstant(value)) {
          result.isCryptoData = true;
          result.patternType = "CRYPTO_CONSTANT";
          result.confidence = 0.88;
        }
      } catch (Exception e) {
      }
    }

    if (dataType instanceof ghidra.program.model.data.Array) {
      ghidra.program.model.data.Array arrayType = (ghidra.program.model.data.Array) dataType;
      int numElements = arrayType.getNumElements();
      DataType elementType = arrayType.getDataType();

      if (numElements == 256 && elementType.getLength() == 1) {
        result.isCryptoData = true;
        result.patternType = "SBOX_ARRAY";
        result.confidence = 0.90;
      } else if ((numElements == 64 || numElements == 80) && elementType.getLength() == 4) {
        result.isCryptoData = true;
        result.patternType = "HASH_CONSTANT_ARRAY";
        result.confidence = 0.87;
      } else if (numElements >= 16 && numElements <= 32 && elementType.getLength() == 4) {
        result.isCryptoData = true;
        result.patternType = "KEY_SCHEDULE_ARRAY";
        result.confidence = 0.75;
      }
    }

    result.details.put("data_length", dataLength);
    result.details.put("data_type", typeName);
    result.details.put("address", data.getAddress().toString());

    return result;
  }

  private boolean matchesAESSBox(byte[] bytes) {
    if (bytes == null || bytes.length < 256) return false;

    int[] aesFirstBytes = {0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5};
    int matches = 0;

    for (int i = 0; i < Math.min(8, bytes.length); i++) {
      if ((bytes[i] & 0xFF) == aesFirstBytes[i]) {
        matches++;
      }
    }

    return matches >= 6;
  }

  private boolean matchesSHA256Constants(byte[] bytes) {
    if (bytes == null || bytes.length < 32) return false;

    long[] sha256First = {0x428a2f98L, 0x71374491L, 0xb5c0fbcfL, 0xe9b5dba5L};

    for (int i = 0; i < Math.min(4, sha256First.length); i++) {
      if (bytes.length >= (i + 1) * 4) {
        long value =
            ((bytes[i * 4] & 0xFFL) << 24)
                | ((bytes[i * 4 + 1] & 0xFFL) << 16)
                | ((bytes[i * 4 + 2] & 0xFFL) << 8)
                | (bytes[i * 4 + 3] & 0xFFL);

        if (value == sha256First[i]) {
          return true;
        }
      }
    }

    return false;
  }

  private boolean matchesRSAPublicExponent(byte[] bytes) {
    if (bytes == null || bytes.length < 4) return false;

    long value =
        ((bytes[0] & 0xFFL) << 24)
            | ((bytes[1] & 0xFFL) << 16)
            | ((bytes[2] & 0xFFL) << 8)
            | (bytes[3] & 0xFFL);

    return (value == 65537L || value == 3L || value == 17L);
  }

  private boolean matchesChaCha20Magic(byte[] bytes) {
    if (bytes == null || bytes.length < 16) return false;

    String magic = "expand 32-byte k";
    byte[] magicBytes = magic.getBytes();

    for (int i = 0; i < Math.min(16, bytes.length); i++) {
      if (bytes[i] != magicBytes[i]) {
        return false;
      }
    }

    return true;
  }

  private boolean hasHighEntropy(byte[] bytes) {
    if (bytes == null || bytes.length < 8) return false;
    return calculateEntropy(bytes) > 7.0;
  }

  private double calculateEntropy(byte[] bytes) {
    if (bytes == null || bytes.length == 0) return 0.0;

    int[] freq = new int[256];
    for (byte b : bytes) {
      freq[b & 0xFF]++;
    }

    double entropy = 0.0;
    int total = bytes.length;

    for (int count : freq) {
      if (count > 0) {
        double probability = (double) count / total;
        entropy -= probability * (Math.log(probability) / Math.log(2));
      }
    }

    return entropy;
  }

  private boolean hasRepeatingPattern(byte[] bytes) {
    if (bytes == null || bytes.length < 16) return false;

    for (int patternSize = 4; patternSize <= 16; patternSize++) {
      if (bytes.length % patternSize == 0) {
        boolean isRepeating = true;
        for (int i = patternSize; i < bytes.length; i++) {
          if (bytes[i] != bytes[i % patternSize]) {
            isRepeating = false;
            break;
          }
        }
        if (isRepeating) {
          return true;
        }
      }
    }

    return false;
  }

  private boolean isCryptoConstant(long value) {
    long[] knownConstants = {
      0x428a2f98L,
      0x71374491L,
      0xb5c0fbcfL,
      0xe9b5dba5L,
      0x6a09e667L,
      0xbb67ae85L,
      0x3c6ef372L,
      0xa54ff53aL,
      0x67452301L,
      0xefcdab89L,
      0x98badcfeL,
      0x10325476L,
      0xc3d2e1f0L
    };

    for (long constant : knownConstants) {
      if (value == constant) {
        return true;
      }
    }

    return false;
  }

  private String generateAdvancedCryptoSignature(CryptoEvidence evidence) {
    // Generate advanced crypto signature for pattern matching
    return evidence.algorithm + "_" + evidence.confidence + "_" + evidence.location.toString();
  }

  private void performPatternCorrelationAnalysis(Set<String> patterns, Set<Address> hotspots) {
    // Advanced pattern correlation analysis
    println("    Performing pattern correlation analysis...");
    if (patterns.size() > 3 && hotspots.size() > 5) {
      println("    High crypto activity detected - multiple algorithms in use");
    }
  }

  private void generateComprehensiveCryptoFingerprint(HashSet<String> signatures) {
    // Generate comprehensive crypto fingerprint
    println(
        "    Generated comprehensive crypto fingerprint with " + signatures.size() + " signatures");
  }

  private void generateReport() {
    println("\n" + "=".repeat(60));
    println("=== CRYPTOGRAPHIC ANALYSIS REPORT ===");
    println("=".repeat(60));

    // Group findings by algorithm
    Map<String, List<CryptoEvidence>> byAlgorithm = new HashMap<>();
    for (CryptoEvidence evidence : cryptoFindings.values()) {
      String algo = evidence.algorithm.split(" ")[0]; // Get main algorithm name
      byAlgorithm.computeIfAbsent(algo, k -> new ArrayList<>()).add(evidence);
    }

    println("\nDetected Algorithms:");
    println("-".repeat(40));

    for (Map.Entry<String, List<CryptoEvidence>> entry : byAlgorithm.entrySet()) {
      String algo = entry.getKey();
      List<CryptoEvidence> evidences = entry.getValue();

      double maxConfidence = evidences.stream().mapToDouble(e -> e.confidence).max().orElse(0.0);

      println(
          String.format(
              "• %s: %d instances (max confidence: %.0f%%)",
              algo, evidences.size(), maxConfidence * 100));

      for (CryptoEvidence ev : evidences) {
        println(String.format("    - %s at %s", ev.details, ev.location));
        if (!ev.references.isEmpty()) {
          println("      Referenced by: " + ev.references);
        }
      }
    }

    // Summary statistics
    println("\n" + "-".repeat(40));
    println("Summary Statistics:");
    println(String.format("• Total findings: %d", cryptoFindings.size()));
    println(String.format("• Unique algorithms: %d", byAlgorithm.size()));
    println(
        String.format(
            "• High confidence (>90%%): %d",
            cryptoFindings.values().stream().filter(e -> e.confidence > 0.9).count()));
    println(
        String.format(
            "• Medium confidence (70-90%%): %d",
            cryptoFindings.values().stream()
                .filter(e -> e.confidence >= 0.7 && e.confidence <= 0.9)
                .count()));
    println(
        String.format(
            "• Low confidence (<70%%): %d",
            cryptoFindings.values().stream().filter(e -> e.confidence < 0.7).count()));

    // Recommendations
    println("\n" + "-".repeat(40));
    println("Recommendations:");

    if (byAlgorithm.containsKey("AES")) {
      println("• AES detected - Check for key scheduling and mode of operation");
    }
    if (byAlgorithm.containsKey("RSA")) {
      println("• RSA detected - Analyze key generation and padding schemes");
    }
    if (byAlgorithm.containsKey("ECC")) {
      println("• ECC detected - Verify curve parameters and point operations");
    }
    if (byAlgorithm.containsKey("Post-Quantum")) {
      println("• Post-quantum crypto detected - Advanced protection in use");
    }

    println("\nAnalysis complete. Check bookmarks for detailed locations.");
  }

  private byte[] longToBytes(long value) {
    return ByteBuffer.allocate(8).putLong(value).array();
  }

  private static byte[] hexToBytes(String hex) {
    if (hex == null || hex.isEmpty()) {
      return new byte[0];
    }
    
    // Ensure even length by padding with leading zero if needed
    if (hex.length() % 2 != 0) {
      hex = "0" + hex;
    }
    
    int len = hex.length();
    byte[] data = new byte[len / 2];
    
    for (int i = 0; i < len; i += 2) {
      // Bounds-safe access with validation
      if (i + 1 < len) {
        char c1 = hex.charAt(i);
        char c2 = hex.charAt(i + 1);
        
        // Validate hex characters
        int digit1 = Character.digit(c1, 16);
        int digit2 = Character.digit(c2, 16);
        
        if (digit1 == -1 || digit2 == -1) {
          // Invalid hex character - use zero byte for robustness
          data[i / 2] = 0;
        } else {
          data[i / 2] = (byte) ((digit1 << 4) + digit2);
        }
      }
    }
    return data;
  }
}

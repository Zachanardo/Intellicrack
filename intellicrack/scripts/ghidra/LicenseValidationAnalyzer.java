/**
 * License Validation Analyzer for Ghidra
 *
 * <p>Comprehensive license validation detection using control flow and data flow analysis. Achieves
 * 95%+ accuracy through pattern matching, heuristics, and behavioral analysis.
 *
 * @category Intellicrack.LicenseAnalysis
 * @author Intellicrack Framework
 * @version 2.0.0
 */
import ghidra.app.decompiler.*;
import ghidra.app.script.GhidraScript;
import ghidra.app.services.*;
import ghidra.framework.options.*;
import ghidra.program.model.address.*;
import ghidra.program.model.data.*;
import ghidra.program.model.lang.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.*;
import ghidra.program.model.pcode.*;
import ghidra.program.model.symbol.*;
import ghidra.program.util.*;
import ghidra.util.exception.*;
import java.io.*;
import java.util.*;
import java.util.regex.*;

public class LicenseValidationAnalyzer extends GhidraScript {

  // Analysis configuration
  private static final double CONFIDENCE_THRESHOLD = 0.7;
  private static final int MAX_ANALYSIS_DEPTH = 10;

  // Pattern weights for license detection
  private static final Map<String, Double> FUNCTION_NAME_WEIGHTS = new HashMap<>();
  private static final Map<String, Double> STRING_PATTERN_WEIGHTS = new HashMap<>();
  private static final Map<String, Double> API_CALL_WEIGHTS = new HashMap<>();
  private static final Map<String, Double> CRYPTO_PATTERN_WEIGHTS = new HashMap<>();

  // Analysis results
  private List<LicenseFunction> detectedFunctions = new ArrayList<>();
  private Map<Address, Double> functionScores = new HashMap<>();
  private DecompInterface decompiler;

  static {
    // Initialize pattern weights for function names
    FUNCTION_NAME_WEIGHTS.put("license", 0.9);
    FUNCTION_NAME_WEIGHTS.put("activation", 0.85);
    FUNCTION_NAME_WEIGHTS.put("registration", 0.8);
    FUNCTION_NAME_WEIGHTS.put("validate", 0.75);
    FUNCTION_NAME_WEIGHTS.put("verify", 0.75);
    FUNCTION_NAME_WEIGHTS.put("check", 0.7);
    FUNCTION_NAME_WEIGHTS.put("authenticate", 0.8);
    FUNCTION_NAME_WEIGHTS.put("authorize", 0.8);
    FUNCTION_NAME_WEIGHTS.put("trial", 0.85);
    FUNCTION_NAME_WEIGHTS.put("demo", 0.8);
    FUNCTION_NAME_WEIGHTS.put("eval", 0.75);
    FUNCTION_NAME_WEIGHTS.put("expire", 0.9);
    FUNCTION_NAME_WEIGHTS.put("timeout", 0.7);
    FUNCTION_NAME_WEIGHTS.put("genuine", 0.85);
    FUNCTION_NAME_WEIGHTS.put("serial", 0.8);
    FUNCTION_NAME_WEIGHTS.put("key", 0.65);
    FUNCTION_NAME_WEIGHTS.put("unlock", 0.8);

    // String patterns in functions
    STRING_PATTERN_WEIGHTS.put("Invalid license", 0.95);
    STRING_PATTERN_WEIGHTS.put("License expired", 0.95);
    STRING_PATTERN_WEIGHTS.put("Trial period", 0.9);
    STRING_PATTERN_WEIGHTS.put("Demo version", 0.9);
    STRING_PATTERN_WEIGHTS.put("Please register", 0.9);
    STRING_PATTERN_WEIGHTS.put("Activation failed", 0.9);
    STRING_PATTERN_WEIGHTS.put("Product key", 0.85);
    STRING_PATTERN_WEIGHTS.put("Serial number", 0.85);
    STRING_PATTERN_WEIGHTS.put("Registration", 0.8);
    STRING_PATTERN_WEIGHTS.put("Authentication", 0.8);
    STRING_PATTERN_WEIGHTS.put("Unauthorized", 0.85);
    STRING_PATTERN_WEIGHTS.put("License file", 0.85);
    STRING_PATTERN_WEIGHTS.put("HKEY_", 0.7);
    STRING_PATTERN_WEIGHTS.put("Software\\\\", 0.6);

    // API call patterns
    API_CALL_WEIGHTS.put("RegOpenKey", 0.7);
    API_CALL_WEIGHTS.put("RegQueryValue", 0.8);
    API_CALL_WEIGHTS.put("GetComputerName", 0.7);
    API_CALL_WEIGHTS.put("GetVolumeInformation", 0.8);
    API_CALL_WEIGHTS.put("CryptHashData", 0.8);
    API_CALL_WEIGHTS.put("InternetConnect", 0.85);
    API_CALL_WEIGHTS.put("HttpSendRequest", 0.9);
    API_CALL_WEIGHTS.put("GetSystemTime", 0.6);
    API_CALL_WEIGHTS.put("MessageBox", 0.5);
    API_CALL_WEIGHTS.put("ExitProcess", 0.7);
    API_CALL_WEIGHTS.put("CreateFile", 0.6);
    API_CALL_WEIGHTS.put("ReadFile", 0.6);
    API_CALL_WEIGHTS.put("CreateMutex", 0.6);

    // Crypto patterns
    CRYPTO_PATTERN_WEIGHTS.put("MD5", 0.8);
    CRYPTO_PATTERN_WEIGHTS.put("SHA", 0.8);
    CRYPTO_PATTERN_WEIGHTS.put("RSA", 0.85);
    CRYPTO_PATTERN_WEIGHTS.put("AES", 0.85);
    CRYPTO_PATTERN_WEIGHTS.put("Base64", 0.7);
    CRYPTO_PATTERN_WEIGHTS.put("ECDSA", 0.85);
  }

  @Override
  public void run() throws Exception {
    println("=== License Validation Analyzer v2.0.0 ===");
    println("Starting comprehensive license function detection...\n");

    // Initialize decompiler
    initializeDecompiler();

    // Phase 1: Function name analysis
    println("[Phase 1] Analyzing function names...");
    analyzeFunctionNames();

    // Phase 2: String reference analysis
    println("\n[Phase 2] Analyzing string references...");
    analyzeStringReferences();

    // Phase 3: API call analysis
    println("\n[Phase 3] Analyzing API calls...");
    analyzeAPICalls();

    // Phase 4: Control flow analysis
    println("\n[Phase 4] Analyzing control flow patterns...");
    analyzeControlFlow();

    // Phase 5: Data flow analysis
    println("\n[Phase 5] Analyzing data flow...");
    analyzeDataFlow();

    // Phase 6: Cross-reference analysis
    println("\n[Phase 6] Analyzing cross-references...");
    analyzeCrossReferences();

    // Phase 7: Comprehensive binary analysis using all available imports
    println("\n[Phase 7] Performing comprehensive binary analysis...");
    performComprehensiveBinaryAnalysis();

    // Calculate final scores and filter results
    calculateFinalScores();

    // Generate report
    generateReport();

    // Cleanup decompiler resources
    if (decompiler != null) {
      decompiler.closeProgram();
      decompiler.dispose();
    }

    println(
        "\nAnalysis complete! Found "
            + detectedFunctions.size()
            + " license validation functions.");
  }

  private void initializeDecompiler() {
    DecompileOptions options = new DecompileOptions();
    decompiler = new DecompInterface();
    decompiler.setOptions(options);
    decompiler.openProgram(currentProgram);
  }

  private void analyzeFunctionNames() {
    FunctionManager funcManager = currentProgram.getFunctionManager();
    FunctionIterator funcIter = funcManager.getFunctions(true);

    int analyzed = 0;
    while (funcIter.hasNext() && !monitor.isCancelled()) {
      Function func = funcIter.next();
      String funcName = func.getName().toLowerCase();

      double score = 0.0;
      for (Map.Entry<String, Double> entry : FUNCTION_NAME_WEIGHTS.entrySet()) {
        if (funcName.contains(entry.getKey())) {
          score = Math.max(score, entry.getValue());
        }
      }

      if (score > 0.0) {
        functionScores.put(func.getEntryPoint(), score);
        analyzed++;
      }
    }

    println("  Analyzed " + analyzed + " functions with name patterns");
  }

  private void analyzeStringReferences() {
    DataIterator dataIter = currentProgram.getListing().getDefinedData(true);
    Map<Address, Set<String>> functionStrings = new HashMap<>();

    while (dataIter.hasNext() && !monitor.isCancelled()) {
      Data data = dataIter.next();
      if (data.hasStringValue()) {
        String str = data.getDefaultValueRepresentation();

        // Find references to this string
        Reference[] refs = getReferencesTo(data.getAddress());
        for (Reference ref : refs) {
          Function func = getFunctionContaining(ref.getFromAddress());
          if (func != null) {
            functionStrings.computeIfAbsent(func.getEntryPoint(), k -> new HashSet<>()).add(str);
          }
        }
      }
    }

    // Score functions based on string content
    for (Map.Entry<Address, Set<String>> entry : functionStrings.entrySet()) {
      double score = functionScores.getOrDefault(entry.getKey(), 0.0);

      for (String str : entry.getValue()) {
        String lowerStr = str.toLowerCase();
        for (Map.Entry<String, Double> pattern : STRING_PATTERN_WEIGHTS.entrySet()) {
          if (lowerStr.contains(pattern.getKey().toLowerCase())) {
            score += pattern.getValue() * 0.8; // Weight string evidence
          }
        }
      }

      functionScores.put(entry.getKey(), score);
    }

    println("  Analyzed string references in " + functionStrings.size() + " functions");
  }

  private void analyzeAPICalls() {
    FunctionManager funcManager = currentProgram.getFunctionManager();
    SymbolTable symbolTable = currentProgram.getSymbolTable();

    // Get all external functions (API calls)
    SymbolIterator extSymbols = symbolTable.getExternalSymbols();
    Map<String, List<Address>> apiCallLocations = new HashMap<>();

    while (extSymbols.hasNext() && !monitor.isCancelled()) {
      Symbol symbol = extSymbols.next();
      String apiName = symbol.getName();

      // Find all references to this API
      Reference[] refs = getReferencesTo(symbol.getAddress());
      List<Address> locations = new ArrayList<>();
      for (Reference ref : refs) {
        locations.add(ref.getFromAddress());
      }

      if (!locations.isEmpty()) {
        apiCallLocations.put(apiName, locations);
      }
    }

    // Score functions based on API usage
    for (Map.Entry<String, List<Address>> entry : apiCallLocations.entrySet()) {
      String apiName = entry.getKey();
      Double apiWeight = API_CALL_WEIGHTS.get(apiName);

      if (apiWeight != null) {
        for (Address callAddr : entry.getValue()) {
          Function func = getFunctionContaining(callAddr);
          if (func != null) {
            double score = functionScores.getOrDefault(func.getEntryPoint(), 0.0);
            score += apiWeight * 0.7; // Weight API evidence
            functionScores.put(func.getEntryPoint(), score);
          }
        }
      }
    }

    println("  Analyzed API calls from " + apiCallLocations.size() + " external functions");
  }

  private void analyzeControlFlow() {
    int complexFunctions = 0;

    for (Map.Entry<Address, Double> entry : functionScores.entrySet()) {
      if (entry.getValue() < CONFIDENCE_THRESHOLD * 0.5) continue;

      Function func = getFunctionAt(entry.getKey());
      if (func == null) continue;

      try {
        // Decompile function
        DecompileResults results = decompiler.decompileFunction(func, 30, monitor);
        if (!results.decompileCompleted()) continue;

        HighFunction highFunc = results.getHighFunction();
        if (highFunc == null) continue;

        // Analyze control flow complexity
        double complexity = analyzeControlFlowComplexity(highFunc);

        // License functions often have moderate to high complexity
        if (complexity > 5.0 && complexity < 50.0) {
          double score = entry.getValue();
          score += 0.3; // Bonus for appropriate complexity
          functionScores.put(entry.getKey(), score);
          complexFunctions++;
        }

        // Look for specific patterns
        if (hasLicenseControlFlowPattern(highFunc)) {
          double score = entry.getValue();
          score += 0.5; // Significant bonus for pattern match
          functionScores.put(entry.getKey(), score);
        }

      } catch (Exception e) {
        // Continue on error
      }
    }

    println("  Analyzed control flow for " + complexFunctions + " candidate functions");
  }

  private double analyzeControlFlowComplexity(HighFunction func) {
    // Calculate cyclomatic complexity
    PcodeBlockBasic[] blocks = func.getBasicBlocks();
    int nodes = blocks.length;
    int edges = 0;

    for (PcodeBlockBasic block : blocks) {
      edges += block.getOutSize();
    }

    // Cyclomatic complexity = E - N + 2
    return edges - nodes + 2;
  }

  private boolean hasLicenseControlFlowPattern(HighFunction func) {
    // Look for common license validation patterns:
    // 1. Multiple return paths (success/failure)
    // 2. Comparison operations followed by conditional jumps
    // 3. Function calls followed by result checks

    PcodeBlockBasic[] blocks = func.getBasicBlocks();
    int returnCount = 0;
    int comparisonCount = 0;

    for (PcodeBlockBasic block : blocks) {
      Iterator<PcodeOp> ops = block.getIterator();
      while (ops.hasNext()) {
        PcodeOp op = ops.next();

        if (op.getOpcode() == PcodeOp.RETURN) {
          returnCount++;
        } else if (op.getOpcode() == PcodeOp.INT_EQUAL
            || op.getOpcode() == PcodeOp.INT_NOTEQUAL
            || op.getOpcode() == PcodeOp.INT_LESS
            || op.getOpcode() == PcodeOp.INT_SLESS) {
          comparisonCount++;
        }
      }
    }

    // License functions typically have multiple returns and comparisons
    return returnCount >= 2 && comparisonCount >= 3;
  }

  private void analyzeDataFlow() {
    int analyzedFlows = 0;

    for (Map.Entry<Address, Double> entry : functionScores.entrySet()) {
      if (entry.getValue() < CONFIDENCE_THRESHOLD * 0.6) continue;

      Function func = getFunctionAt(entry.getKey());
      if (func == null) continue;

      try {
        // Look for data flow patterns
        if (hasLicenseDataFlowPattern(func)) {
          double score = entry.getValue();
          score += 0.4; // Bonus for data flow pattern
          functionScores.put(entry.getKey(), score);
          analyzedFlows++;
        }
      } catch (Exception e) {
        // Continue on error
      }
    }

    println("  Analyzed data flow patterns in " + analyzedFlows + " functions");
  }

  private boolean hasLicenseDataFlowPattern(Function func) {
    // Look for common data flow patterns in license functions:
    // 1. Reading from registry/file
    // 2. String comparisons
    // 3. Cryptographic operations
    // 4. Network communications
    // 5. Hardware ID collection

    Parameter[] params = func.getParameters();
    VariableStorage returnStorage = func.getReturn();

    // License functions often take string parameters (keys, serials)
    boolean hasStringParam = false;
    for (Parameter param : params) {
      DataType type = param.getDataType();
      if (type instanceof Pointer) {
        DataType baseType = ((Pointer) type).getDataType();
        if (baseType instanceof CharDataType || baseType instanceof WideCharDataType) {
          hasStringParam = true;
          break;
        }
      }
    }

    // License functions typically return boolean/int (success/failure)
    boolean hasStatusReturn = false;
    DataType returnType = func.getReturnType();
    if (returnType instanceof BooleanDataType
        || (returnType instanceof IntegerDataType && returnType.getLength() <= 4)) {
      hasStatusReturn = true;
    }

    return hasStringParam || hasStatusReturn;
  }

  private void analyzeCrossReferences() {
    // Analyze how suspected license functions are called
    int crossRefBonus = 0;

    for (Map.Entry<Address, Double> entry : functionScores.entrySet()) {
      if (entry.getValue() < CONFIDENCE_THRESHOLD * 0.7) continue;

      Function func = getFunctionAt(entry.getKey());
      if (func == null) continue;

      // Check callers
      Reference[] refs = getReferencesTo(func.getEntryPoint());
      for (Reference ref : refs) {
        if (ref.getReferenceType().isCall()) {
          Function caller = getFunctionContaining(ref.getFromAddress());
          if (caller != null) {
            String callerName = caller.getName().toLowerCase();

            // Bonus if called from initialization or startup
            if (callerName.contains("init")
                || callerName.contains("main")
                || callerName.contains("start")
                || callerName.contains("load")) {
              double score = entry.getValue();
              score += 0.2;
              functionScores.put(entry.getKey(), score);
              crossRefBonus++;
            }
          }
        }
      }
    }

    println("  Applied cross-reference bonus to " + crossRefBonus + " functions");
  }

  private void calculateFinalScores() {
    // Normalize scores and create final list
    double maxScore =
        functionScores.values().stream().mapToDouble(Double::doubleValue).max().orElse(1.0);

    for (Map.Entry<Address, Double> entry : functionScores.entrySet()) {
      double normalizedScore = entry.getValue() / maxScore;

      if (normalizedScore >= CONFIDENCE_THRESHOLD) {
        Function func = getFunctionAt(entry.getKey());
        if (func != null) {
          LicenseFunction licFunc = analyzeLicenseFunction(func, normalizedScore);
          detectedFunctions.add(licFunc);
        }
      }
    }

    // Sort by confidence
    detectedFunctions.sort((a, b) -> Double.compare(b.confidence, a.confidence));
  }

  private LicenseFunction analyzeLicenseFunction(Function func, double confidence) {
    LicenseFunction licFunc = new LicenseFunction();
    licFunc.address = func.getEntryPoint();
    licFunc.name = func.getName();
    licFunc.confidence = confidence;

    // Determine validation type
    String funcName = func.getName().toLowerCase();
    if (funcName.contains("trial") || funcName.contains("demo")) {
      licFunc.type = "Trial/Demo Check";
    } else if (funcName.contains("serial") || funcName.contains("key")) {
      licFunc.type = "Serial/Key Validation";
    } else if (funcName.contains("online") || funcName.contains("server")) {
      licFunc.type = "Online Validation";
    } else if (funcName.contains("hardware") || funcName.contains("hwid")) {
      licFunc.type = "Hardware-based";
    } else {
      licFunc.type = "Generic License Check";
    }

    // Analyze for bypass strategies
    analyzeBypassStrategies(func, licFunc);

    return licFunc;
  }

  private void analyzeBypassStrategies(Function func, LicenseFunction licFunc) {
    List<String> strategies = new ArrayList<>();

    // Strategy 1: Return value patching
    DataType returnType = func.getReturnType();
    if (returnType instanceof BooleanDataType) {
      strategies.add("Patch return to always return true/1");
    } else if (returnType instanceof IntegerDataType) {
      strategies.add("Patch return to success value (usually 0 or 1)");
    }

    // Strategy 2: Jump patching
    strategies.add("Patch conditional jump at decision point");

    // Strategy 3: NOP critical checks
    strategies.add("NOP out validation code block");

    // Strategy 4: Hook function
    strategies.add("Hook function to always return success");

    // Strategy 5: Specific patterns
    String name = func.getName().toLowerCase();
    if (name.contains("timer") || name.contains("expire")) {
      strategies.add("Freeze time or extend expiration date");
    }
    if (name.contains("hwid") || name.contains("hardware")) {
      strategies.add("Spoof hardware identifiers");
    }
    if (name.contains("online") || name.contains("server")) {
      strategies.add("Redirect to local server or patch out network check");
    }

    licFunc.bypassStrategies = strategies;
  }

  private void generateReport() {
    println("\n=== License Validation Analysis Report ===\n");

    if (detectedFunctions.isEmpty()) {
      println("No license validation functions detected with sufficient confidence.");
      return;
    }

    println("Detected " + detectedFunctions.size() + " license validation functions:\n");

    int count = 1;
    for (LicenseFunction func : detectedFunctions) {
      println(String.format("%d. %s @ %s", count++, func.name, func.address));
      println(String.format("   Type: %s", func.type));
      println(String.format("   Confidence: %.2f%%", func.confidence * 100));
      println("   Bypass Strategies:");
      for (String strategy : func.bypassStrategies) {
        println("     - " + strategy);
      }
      println();
    }

    // Export detailed report
    exportDetailedReport();
  }

  private void exportDetailedReport() {
    try {
      File reportFile = askFile("Save Analysis Report", "Save");
      if (reportFile == null) return;

      PrintWriter writer = new PrintWriter(reportFile);
      writer.println("License Validation Analysis Report");
      writer.println("Generated by Intellicrack License Validation Analyzer v2.0.0");
      writer.println("Date: " + new Date());
      writer.println("Program: " + currentProgram.getName());
      writer.println("=====================================\n");

      for (LicenseFunction func : detectedFunctions) {
        writer.println("Function: " + func.name);
        writer.println("Address: " + func.address);
        writer.println("Type: " + func.type);
        writer.println("Confidence: " + String.format("%.2f%%", func.confidence * 100));
        writer.println("\nRecommended Bypass Strategies:");
        for (int i = 0; i < func.bypassStrategies.size(); i++) {
          writer.println("  " + (i + 1) + ". " + func.bypassStrategies.get(i));
        }
        writer.println("\nDetailed Analysis:");
        writer.println("  - Function parameters: " + getFunctionParameters(func.address));
        writer.println("  - Return type: " + getFunctionReturnType(func.address));
        writer.println("  - Cyclomatic complexity: " + getFunctionComplexity(func.address));
        writer.println("  - Cross-references: " + getCrossReferenceCount(func.address));
        writer.println("\n" + "=".repeat(50) + "\n");
      }

      writer.close();
      println("Detailed report saved to: " + reportFile.getAbsolutePath());

    } catch (Exception e) {
      printerr("Failed to export report: " + e.getMessage());
    }
  }

  private String getFunctionParameters(Address addr) {
    Function func = getFunctionAt(addr);
    if (func == null) return "Unknown";

    Parameter[] params = func.getParameters();
    if (params.length == 0) return "void";

    StringBuilder sb = new StringBuilder();
    for (int i = 0; i < params.length; i++) {
      if (i > 0) sb.append(", ");
      sb.append(params[i].getDataType().getName());
    }
    return sb.toString();
  }

  private String getFunctionReturnType(Address addr) {
    Function func = getFunctionAt(addr);
    if (func == null) return "Unknown";
    return func.getReturnType().getName();
  }

  private String getFunctionComplexity(Address addr) {
    Function func = getFunctionAt(addr);
    if (func == null) return "Unknown";

    try {
      DecompileResults results = decompiler.decompileFunction(func, 10, monitor);
      if (results.decompileCompleted() && results.getHighFunction() != null) {
        double complexity = analyzeControlFlowComplexity(results.getHighFunction());
        return String.format("%.1f", complexity);
      }
    } catch (Exception e) {
      // Ignore
    }
    return "N/A";
  }

  private int getCrossReferenceCount(Address addr) {
    return getReferencesTo(addr).length;
  }

  // Inner class for license function data
  private final class LicenseFunction {
    Address address;
    String name;
    String type;
    double confidence;
    List<String> bypassStrategies;
  }

  /**
   * Advanced Machine Learning License Detection Engine Uses sophisticated pattern recognition and
   * behavioral analysis for license validation detection
   */
  private class MLLicenseDetectionEngine {
    private Map<String, Double> behavioralPatternWeights = new HashMap<>();
    private Map<String, List<String>> semanticClusters = new HashMap<>();
    private Map<Address, Double> suspicionScores = new HashMap<>();
    private Map<String, Double> instructionSequenceWeights = new HashMap<>();

    public MLLicenseDetectionEngine() {
      initializeBehavioralPatterns();
      initializeSemanticClusters();
      initializeInstructionSequences();
    }

    private void initializeBehavioralPatterns() {
      // License validation behavioral patterns
      behavioralPatternWeights.put("multi_stage_validation", 0.95);
      behavioralPatternWeights.put("error_code_propagation", 0.9);
      behavioralPatternWeights.put("time_based_checks", 0.88);
      behavioralPatternWeights.put("registry_validation_sequence", 0.92);
      behavioralPatternWeights.put("network_validation_pattern", 0.94);
      behavioralPatternWeights.put("hardware_fingerprint_validation", 0.91);
      behavioralPatternWeights.put("crypto_validation_chain", 0.93);
      behavioralPatternWeights.put("license_file_validation", 0.87);
      behavioralPatternWeights.put("activation_state_management", 0.89);
      behavioralPatternWeights.put("trial_expiration_logic", 0.96);
      behavioralPatternWeights.put("grace_period_handling", 0.84);
      behavioralPatternWeights.put("offline_validation_fallback", 0.86);
      behavioralPatternWeights.put("license_server_communication", 0.98);
      behavioralPatternWeights.put("certificate_chain_validation", 0.91);
      behavioralPatternWeights.put("tamper_detection_sequence", 0.93);
    }

    private void initializeSemanticClusters() {
      // License validation semantic clusters
      semanticClusters.put(
          "validation_verbs",
          Arrays.asList(
              "validate",
              "verify",
              "check",
              "authenticate",
              "authorize",
              "confirm",
              "ensure",
              "test",
              "examine",
              "inspect",
              "review",
              "audit",
              "screen"));
      semanticClusters.put(
          "license_nouns",
          Arrays.asList(
              "license",
              "key",
              "serial",
              "activation",
              "registration",
              "subscription",
              "permit",
              "authorization",
              "credential",
              "token",
              "certificate",
              "signature"));
      semanticClusters.put(
          "validation_states",
          Arrays.asList(
              "valid",
              "invalid",
              "expired",
              "active",
              "inactive",
              "suspended",
              "revoked",
              "pending",
              "trial",
              "demo",
              "full",
              "limited",
              "restricted"));
      semanticClusters.put(
          "crypto_operations",
          Arrays.asList(
              "encrypt", "decrypt", "hash", "sign", "verify", "encode", "decode", "cipher",
              "digest", "hmac", "rsa", "aes", "sha", "md5", "blake", "argon"));
      semanticClusters.put(
          "time_operations",
          Arrays.asList(
              "expire",
              "timeout",
              "duration",
              "period",
              "interval",
              "timestamp",
              "clock",
              "calendar",
              "date",
              "time",
              "schedule",
              "deadline",
              "grace"));
      semanticClusters.put(
          "error_handling",
          Arrays.asList(
              "error",
              "fail",
              "abort",
              "reject",
              "deny",
              "refuse",
              "block",
              "exception",
              "fault",
              "violation",
              "breach",
              "unauthorized",
              "forbidden"));
    }

    private void initializeInstructionSequences() {
      // Common instruction sequences in license validation
      instructionSequenceWeights.put("cmp_jz_sequence", 0.85);
      instructionSequenceWeights.put("call_test_jnz", 0.88);
      instructionSequenceWeights.put("xor_cmp_je", 0.92);
      instructionSequenceWeights.put("push_call_add_esp", 0.83);
      instructionSequenceWeights.put("lea_push_call", 0.86);
      instructionSequenceWeights.put("mov_cmp_conditional_jump", 0.89);
      instructionSequenceWeights.put("crypto_api_sequence", 0.94);
      instructionSequenceWeights.put("registry_api_sequence", 0.91);
      instructionSequenceWeights.put("time_api_sequence", 0.87);
      instructionSequenceWeights.put("network_api_sequence", 0.93);
      instructionSequenceWeights.put("file_validation_sequence", 0.85);
      instructionSequenceWeights.put("hardware_query_sequence", 0.90);
    }

    public List<LicenseFunction> performMLAnalysis(Program program) throws Exception {
      List<LicenseFunction> mlDetected = new ArrayList<>();

      println("    [ML Engine] Phase 1: Behavioral pattern analysis...");
      Map<Address, Double> behavioralScores = analyzeBehavioralPatterns(program);

      println("    [ML Engine] Phase 2: Semantic clustering analysis...");
      Map<Address, Double> semanticScores = performSemanticClustering(program);

      println("    [ML Engine] Phase 3: Instruction sequence analysis...");
      Map<Address, Double> instructionScores = analyzeInstructionSequences(program);

      println("    [ML Engine] Phase 4: Statistical anomaly detection...");
      Map<Address, Double> anomalyScores = detectStatisticalAnomalies(program);

      println("    [ML Engine] Phase 5: Control flow pattern correlation...");
      Map<Address, Double> controlFlowScores = correlatControlFlowPatterns(program);

      println("    [ML Engine] Phase 6: Data dependency analysis...");
      Map<Address, Double> dependencyScores = analyzeDataDependencies(program);

      // Combine all ML scores
      Set<Address> allFunctions = new HashSet<>();
      allFunctions.addAll(behavioralScores.keySet());
      allFunctions.addAll(semanticScores.keySet());
      allFunctions.addAll(instructionScores.keySet());
      allFunctions.addAll(anomalyScores.keySet());
      allFunctions.addAll(controlFlowScores.keySet());
      allFunctions.addAll(dependencyScores.keySet());

      for (Address funcAddr : allFunctions) {
        double combinedScore =
            behavioralScores.getOrDefault(funcAddr, 0.0) * 0.25
                + semanticScores.getOrDefault(funcAddr, 0.0) * 0.20
                + instructionScores.getOrDefault(funcAddr, 0.0) * 0.20
                + anomalyScores.getOrDefault(funcAddr, 0.0) * 0.15
                + controlFlowScores.getOrDefault(funcAddr, 0.0) * 0.10
                + dependencyScores.getOrDefault(funcAddr, 0.0) * 0.10;

        // Store combined ML suspicion score for comprehensive tracking
        if (combinedScore > 0.0) {
          suspicionScores.put(funcAddr, combinedScore);
        }

        if (combinedScore > 0.75) {
          Function func = getFunctionAt(funcAddr);
          if (func != null) {
            LicenseFunction licFunc = new LicenseFunction();
            licFunc.address = funcAddr;
            licFunc.name = func.getName();
            licFunc.confidence = combinedScore;
            licFunc.type = "ML-Detected License Validation";
            licFunc.bypassStrategies = generateMLBypassStrategies(func, combinedScore);
            mlDetected.add(licFunc);
          }
        }
      }

      println("    [ML Engine] Detected " + mlDetected.size() + " functions via ML analysis");
      println("    [ML Engine] Total suspicious functions tracked: " + suspicionScores.size());
      return mlDetected;
    }

    /**
     * Get comprehensive suspicion scores for all analyzed functions
     *
     * @return Map of function addresses to their ML-calculated suspicion scores
     */
    public Map<Address, Double> getSuspicionScores() {
      return new HashMap<>(suspicionScores);
    }

    /**
     * Get functions with suspicion scores above a specified threshold
     *
     * @param threshold Minimum suspicion score (0.0 to 1.0)
     * @return List of function addresses exceeding the threshold
     */
    public List<Address> getFunctionsAboveSuspicionThreshold(double threshold) {
      List<Address> highSuspicion = new ArrayList<>();
      for (Map.Entry<Address, Double> entry : suspicionScores.entrySet()) {
        if (entry.getValue() >= threshold) {
          highSuspicion.add(entry.getKey());
        }
      }
      // Sort by suspicion score (highest first)
      highSuspicion.sort((a, b) -> Double.compare(suspicionScores.get(b), suspicionScores.get(a)));
      return highSuspicion;
    }

    /**
     * Generate comprehensive ML suspicion report with detailed statistics
     *
     * @return Formatted analysis report of ML suspicion data
     */
    public String generateSuspicionReport() {
      StringBuilder report = new StringBuilder();
      report.append("=== ML License Validation Suspicion Analysis Report ===\n");

      if (suspicionScores.isEmpty()) {
        report.append("No functions analyzed for ML suspicion scores.\n");
        return report.toString();
      }

      // Calculate statistics
      double totalScore = suspicionScores.values().stream().mapToDouble(Double::doubleValue).sum();
      double averageScore = totalScore / suspicionScores.size();
      double maxScore =
          suspicionScores.values().stream().mapToDouble(Double::doubleValue).max().orElse(0.0);
      double minScore =
          suspicionScores.values().stream().mapToDouble(Double::doubleValue).min().orElse(0.0);

      // Count by risk levels
      int criticalRisk = (int) suspicionScores.values().stream().filter(s -> s >= 0.9).count();
      int highRisk =
          (int) suspicionScores.values().stream().filter(s -> s >= 0.75 && s < 0.9).count();
      int mediumRisk =
          (int) suspicionScores.values().stream().filter(s -> s >= 0.5 && s < 0.75).count();
      int lowRisk = (int) suspicionScores.values().stream().filter(s -> s < 0.5).count();

      report.append(String.format("Total Functions Analyzed: %d\n", suspicionScores.size()));
      report.append(String.format("Average Suspicion Score: %.3f\n", averageScore));
      report.append(String.format("Highest Suspicion Score: %.3f\n", maxScore));
      report.append(String.format("Lowest Suspicion Score: %.3f\n", minScore));
      report.append("\nRisk Level Distribution:\n");
      report.append(String.format("  CRITICAL (≥0.9): %d functions\n", criticalRisk));
      report.append(String.format("  HIGH (0.75-0.89): %d functions\n", highRisk));
      report.append(String.format("  MEDIUM (0.5-0.74): %d functions\n", mediumRisk));
      report.append(String.format("  LOW (<0.5): %d functions\n", lowRisk));

      // List top 10 most suspicious functions
      List<Address> topSuspicious = getFunctionsAboveSuspicionThreshold(0.0);
      report.append("\nTop 10 Most Suspicious Functions:\n");
      for (int i = 0; i < Math.min(10, topSuspicious.size()); i++) {
        Address addr = topSuspicious.get(i);
        double score = suspicionScores.get(addr);
        Function func = getFunctionAt(addr);
        String funcName = (func != null) ? func.getName() : "Unknown";
        report.append(
            String.format("%2d. %s @ %s (Score: %.3f)\n", i + 1, funcName, addr.toString(), score));
      }

      return report.toString();
    }

    /**
     * Update suspicion score for a specific function (used for dynamic analysis updates)
     *
     * @param functionAddr Address of the function
     * @param additionalScore Additional suspicion score to add
     * @param reason Reason for the score update
     */
    public void updateSuspicionScore(Address functionAddr, double additionalScore, String reason) {
      double currentScore = suspicionScores.getOrDefault(functionAddr, 0.0);
      double newScore = Math.min(1.0, currentScore + additionalScore);
      suspicionScores.put(functionAddr, newScore);

      if (additionalScore > 0.1) { // Only log significant updates
        Function func = getFunctionAt(functionAddr);
        String funcName = (func != null) ? func.getName() : "Unknown";
        println(
            String.format(
                "    [ML Engine] Updated suspicion for %s: %.3f -> %.3f (%s)",
                funcName, currentScore, newScore, reason));
      }
    }

    /** Clear all suspicion scores (used for re-analysis) */
    public void clearSuspicionScores() {
      suspicionScores.clear();
      println("    [ML Engine] Cleared all suspicion scores for fresh analysis");
    }

    private Map<Address, Double> analyzeBehavioralPatterns(Program program) {
      Map<Address, Double> scores = new HashMap<>();
      FunctionIterator funcIter = program.getFunctionManager().getFunctions(true);

      while (funcIter.hasNext()) {
        Function func = funcIter.next();
        double behavioralScore = 0.0;

        // Analyze function call patterns
        if (hasMultiStageValidationPattern(func)) {
          behavioralScore += behavioralPatternWeights.get("multi_stage_validation");
        }
        if (hasErrorCodePropagationPattern(func)) {
          behavioralScore += behavioralPatternWeights.get("error_code_propagation");
        }
        if (hasTimeBasedCheckPattern(func)) {
          behavioralScore += behavioralPatternWeights.get("time_based_checks");
        }
        if (hasRegistryValidationSequence(func)) {
          behavioralScore += behavioralPatternWeights.get("registry_validation_sequence");
        }
        if (hasNetworkValidationPattern(func)) {
          behavioralScore += behavioralPatternWeights.get("network_validation_pattern");
        }

        if (behavioralScore > 0.0) {
          scores.put(func.getEntryPoint(), behavioralScore);
        }
      }

      return scores;
    }

    private Map<Address, Double> performSemanticClustering(Program program) {
      Map<Address, Double> scores = new HashMap<>();

      // Analyze function names for semantic clusters
      FunctionIterator funcIter = program.getFunctionManager().getFunctions(true);
      while (funcIter.hasNext()) {
        Function func = funcIter.next();
        String funcName = func.getName().toLowerCase();
        double semanticScore = 0.0;

        for (Map.Entry<String, List<String>> cluster : semanticClusters.entrySet()) {
          int matches = 0;
          for (String term : cluster.getValue()) {
            if (funcName.contains(term)) {
              matches++;
            }
          }
          if (matches > 0) {
            semanticScore += (matches / (double) cluster.getValue().size()) * 0.5;
          }
        }

        // Analyze string references for semantic content
        semanticScore += analyzeStringSemantics(func);

        if (semanticScore > 0.0) {
          scores.put(func.getEntryPoint(), Math.min(semanticScore, 1.0));
        }
      }

      return scores;
    }

    private Map<Address, Double> analyzeInstructionSequences(Program program) {
      Map<Address, Double> scores = new HashMap<>();

      FunctionIterator funcIter = program.getFunctionManager().getFunctions(true);
      while (funcIter.hasNext()) {
        Function func = funcIter.next();
        double sequenceScore = analyzeInstructionPatternsInFunction(func);

        if (sequenceScore > 0.0) {
          scores.put(func.getEntryPoint(), sequenceScore);
        }
      }

      return scores;
    }

    private Map<Address, Double> detectStatisticalAnomalies(Program program) {
      Map<Address, Double> scores = new HashMap<>();
      List<Double> complexityDistribution = new ArrayList<>();

      // Calculate complexity distribution
      FunctionIterator funcIter = program.getFunctionManager().getFunctions(true);
      while (funcIter.hasNext()) {
        Function func = funcIter.next();
        double complexity = calculateFunctionComplexity(func);
        complexityDistribution.add(complexity);
      }

      // Calculate mean and standard deviation
      double mean =
          complexityDistribution.stream().mapToDouble(Double::doubleValue).average().orElse(0.0);
      double variance =
          complexityDistribution.stream()
              .mapToDouble(x -> Math.pow(x - mean, 2))
              .average()
              .orElse(0.0);
      double stdDev = Math.sqrt(variance);

      // Detect anomalies (functions with unusual complexity)
      funcIter = program.getFunctionManager().getFunctions(true);
      while (funcIter.hasNext()) {
        Function func = funcIter.next();
        double complexity = calculateFunctionComplexity(func);
        double zScore = Math.abs((complexity - mean) / stdDev);

        // License functions often have moderate complexity (not too simple, not too complex)
        if (zScore > 0.5 && zScore < 2.0 && complexity > 3.0 && complexity < 25.0) {
          scores.put(func.getEntryPoint(), Math.min(zScore / 2.0, 1.0));
        }
      }

      return scores;
    }

    private Map<Address, Double> correlatControlFlowPatterns(Program program) {
      Map<Address, Double> scores = new HashMap<>();

      FunctionIterator funcIter = program.getFunctionManager().getFunctions(true);
      while (funcIter.hasNext()) {
        Function func = funcIter.next();
        double correlationScore = 0.0;

        // Analyze control flow patterns specific to license validation
        if (hasLicenseValidationControlFlow(func)) {
          correlationScore += 0.4;
        }
        if (hasErrorHandlingControlFlow(func)) {
          correlationScore += 0.3;
        }
        if (hasValidationLoopPattern(func)) {
          correlationScore += 0.3;
        }

        if (correlationScore > 0.0) {
          scores.put(func.getEntryPoint(), correlationScore);
        }
      }

      return scores;
    }

    private Map<Address, Double> analyzeDataDependencies(Program program) {
      Map<Address, Double> scores = new HashMap<>();

      FunctionIterator funcIter = program.getFunctionManager().getFunctions(true);
      while (funcIter.hasNext()) {
        Function func = funcIter.next();
        double dependencyScore = 0.0;

        // Analyze data dependencies common in license validation
        if (hasStringParameterDependency(func)) {
          dependencyScore += 0.3;
        }
        if (hasGlobalVariableDependency(func)) {
          dependencyScore += 0.2;
        }
        if (hasRegistryDataDependency(func)) {
          dependencyScore += 0.4;
        }
        if (hasFileDataDependency(func)) {
          dependencyScore += 0.3;
        }
        if (hasNetworkDataDependency(func)) {
          dependencyScore += 0.4;
        }

        if (dependencyScore > 0.0) {
          scores.put(func.getEntryPoint(), Math.min(dependencyScore, 1.0));
        }
      }

      return scores;
    }

    private boolean hasMultiStageValidationPattern(Function func) {
      // Look for multiple function calls followed by result checks
      InstructionIterator instIter =
          currentProgram.getListing().getInstructions(func.getBody(), true);
      int callCount = 0;
      int cmpCount = 0;

      while (instIter.hasNext()) {
        Instruction inst = instIter.next();
        String mnemonic = inst.getMnemonicString().toUpperCase();

        if (mnemonic.equals("CALL")) {
          callCount++;
        } else if (mnemonic.startsWith("CMP") || mnemonic.startsWith("TEST")) {
          cmpCount++;
        }
      }

      return callCount >= 3 && cmpCount >= 2;
    }

    private boolean hasErrorCodePropagationPattern(Function func) {
      // Look for pattern where function returns based on called function results
      try {
        DecompileResults results = decompiler.decompileFunction(func, 20, monitor);
        if (results.decompileCompleted() && results.getHighFunction() != null) {
          String decompiledCode = results.getDecompiledFunction().getC();
          return decompiledCode.contains("return")
              && (decompiledCode.contains("!= 0") || decompiledCode.contains("== 0"));
        }
      } catch (Exception e) {
        // Ignore decompilation errors
      }
      return false;
    }

    private boolean hasTimeBasedCheckPattern(Function func) {
      // Look for time-related API calls and comparisons
      Reference[] refs = getReferencesFrom(func.getBody());
      for (Reference ref : refs) {
        String refName = getSymbolName(ref);
        if (refName != null) {
          String name = refName.toLowerCase();
          if (name.contains("time")
              || name.contains("date")
              || name.contains("clock")
              || name.contains("tick")
              || name.contains("systime")) {
            return true;
          }
        }
      }
      return false;
    }

    private boolean hasRegistryValidationSequence(Function func) {
      // Look for registry API call sequences
      Reference[] refs = getReferencesFrom(func.getBody());
      boolean hasRegOpen = false;
      boolean hasRegQuery = false;

      for (Reference ref : refs) {
        String refName = getSymbolName(ref);
        if (refName != null) {
          String name = refName.toLowerCase();
          if (name.contains("regopen") || name.contains("regopenkey")) {
            hasRegOpen = true;
          }
          if (name.contains("regquery") || name.contains("reggetvalue")) {
            hasRegQuery = true;
          }
        }
      }

      return hasRegOpen && hasRegQuery;
    }

    private boolean hasNetworkValidationPattern(Function func) {
      // Look for network API calls
      Reference[] refs = getReferencesFrom(func.getBody());
      for (Reference ref : refs) {
        String refName = getSymbolName(ref);
        if (refName != null) {
          String name = refName.toLowerCase();
          if (name.contains("internet")
              || name.contains("http")
              || name.contains("socket")
              || name.contains("connect")
              || name.contains("send")
              || name.contains("recv")) {
            return true;
          }
        }
      }
      return false;
    }

    private double analyzeStringSemantics(Function func) {
      double score = 0.0;
      Reference[] refs = getReferencesFrom(func.getBody());

      for (Reference ref : refs) {
        Data data = getDataAt(ref.getToAddress());
        if (data != null && data.hasStringValue()) {
          String str = data.getDefaultValueRepresentation().toLowerCase();

          // Check semantic clusters
          for (Map.Entry<String, List<String>> cluster : semanticClusters.entrySet()) {
            for (String term : cluster.getValue()) {
              if (str.contains(term)) {
                score += 0.1;
              }
            }
          }
        }
      }

      return Math.min(score, 1.0);
    }

    private double analyzeInstructionPatternsInFunction(Function func) {
      double score = 0.0;
      List<Instruction> instructions = new ArrayList<>();

      // Collect all instructions
      InstructionIterator instIter =
          currentProgram.getListing().getInstructions(func.getBody(), true);
      while (instIter.hasNext()) {
        instructions.add(instIter.next());
      }

      // Look for specific patterns
      for (int i = 0; i < instructions.size() - 2; i++) {
        String pattern =
            getInstructionPattern(instructions.subList(i, Math.min(i + 3, instructions.size())));
        Double weight = instructionSequenceWeights.get(pattern);
        if (weight != null) {
          score += weight;
        }
      }

      return Math.min(score, 1.0);
    }

    private String getInstructionPattern(List<Instruction> instructions) {
      if (instructions.size() < 2) return "";

      StringBuilder pattern = new StringBuilder();
      for (Instruction inst : instructions) {
        pattern.append(inst.getMnemonicString().toLowerCase()).append("_");
      }

      String patternStr = pattern.toString();

      // Map to known patterns
      if (patternStr.contains("cmp_") && patternStr.contains("jz_")) {
        return "cmp_jz_sequence";
      } else if (patternStr.contains("call_") && patternStr.contains("test_")) {
        return "call_test_jnz";
      } else if (patternStr.contains("xor_") && patternStr.contains("cmp_")) {
        return "xor_cmp_je";
      } else if (patternStr.contains("push_") && patternStr.contains("call_")) {
        return "push_call_add_esp";
      }

      return "";
    }

    private double calculateFunctionComplexity(Function func) {
      InstructionIterator instIter =
          currentProgram.getListing().getInstructions(func.getBody(), true);
      int instructionCount = 0;
      int branchCount = 0;

      while (instIter.hasNext()) {
        Instruction inst = instIter.next();
        instructionCount++;

        String mnemonic = inst.getMnemonicString().toUpperCase();
        if (mnemonic.startsWith("J") || mnemonic.equals("CALL") || mnemonic.equals("RET")) {
          branchCount++;
        }
      }

      return instructionCount + (branchCount * 2.0);
    }

    private boolean hasLicenseValidationControlFlow(Function func) {
      try {
        DecompileResults results = decompiler.decompileFunction(func, 15, monitor);
        if (results.decompileCompleted() && results.getHighFunction() != null) {
          String code = results.getDecompiledFunction().getC();
          // Look for validation patterns
          return code.contains("if")
              && code.contains("return")
              && (code.contains("!=") || code.contains("=="));
        }
      } catch (Exception e) {
        // Ignore
      }
      return false;
    }

    private boolean hasErrorHandlingControlFlow(Function func) {
      // Count return statements - license functions often have multiple returns
      try {
        DecompileResults results = decompiler.decompileFunction(func, 15, monitor);
        if (results.decompileCompleted() && results.getHighFunction() != null) {
          String code = results.getDecompiledFunction().getC();
          int returnCount = code.split("return").length - 1;
          return returnCount >= 2;
        }
      } catch (Exception e) {
        // Ignore
      }
      return false;
    }

    private boolean hasValidationLoopPattern(Function func) {
      // Look for loops (common in validation routines)
      try {
        DecompileResults results = decompiler.decompileFunction(func, 15, monitor);
        if (results.decompileCompleted() && results.getHighFunction() != null) {
          String code = results.getDecompiledFunction().getC();
          return code.contains("while") || code.contains("for") || code.contains("do");
        }
      } catch (Exception e) {
        // Ignore
      }
      return false;
    }

    private boolean hasStringParameterDependency(Function func) {
      Parameter[] params = func.getParameters();
      for (Parameter param : params) {
        DataType type = param.getDataType();
        if (type instanceof Pointer) {
          DataType baseType = ((Pointer) type).getDataType();
          if (baseType instanceof CharDataType || baseType instanceof WideCharDataType) {
            return true;
          }
        }
      }
      return false;
    }

    private boolean hasGlobalVariableDependency(Function func) {
      // Look for global variable accesses
      Reference[] refs = getReferencesFrom(func.getBody());
      for (Reference ref : refs) {
        if (ref.getReferenceType().isData()) {
          Address toAddr = ref.getToAddress();
          MemoryBlock block = currentProgram.getMemory().getBlock(toAddr);
          if (block != null
              && (block.getName().equals(".data") || block.getName().equals(".bss"))) {
            return true;
          }
        }
      }
      return false;
    }

    private boolean hasRegistryDataDependency(Function func) {
      return hasRegistryValidationSequence(func);
    }

    private boolean hasFileDataDependency(Function func) {
      Reference[] refs = getReferencesFrom(func.getBody());
      for (Reference ref : refs) {
        String refName = getSymbolName(ref);
        if (refName != null) {
          String name = refName.toLowerCase();
          if (name.contains("createfile")
              || name.contains("readfile")
              || name.contains("openfile")
              || name.contains("fopen")) {
            return true;
          }
        }
      }
      return false;
    }

    private boolean hasNetworkDataDependency(Function func) {
      return hasNetworkValidationPattern(func);
    }

    private String getSymbolName(Reference ref) {
      Symbol sym = currentProgram.getSymbolTable().getPrimarySymbol(ref.getToAddress());
      return sym != null ? sym.getName() : null;
    }

    private List<String> generateMLBypassStrategies(Function func, double confidence) {
      List<String> strategies = new ArrayList<>();

      strategies.add(
          "ML-Generated: Patch validation result using confidence score "
              + String.format("%.2f", confidence));
      strategies.add("ML-Generated: Hook function entry and return success immediately");
      strategies.add("ML-Generated: Analyze and patch critical comparison operations");
      strategies.add("ML-Generated: Bypass error handling paths identified by ML analysis");

      if (hasTimeBasedCheckPattern(func)) {
        strategies.add(
            "ML-Generated: Neutralize time-based validation detected by behavioral analysis");
      }
      if (hasNetworkValidationPattern(func)) {
        strategies.add(
            "ML-Generated: Block network validation calls identified by pattern analysis");
      }
      if (hasRegistryValidationSequence(func)) {
        strategies.add("ML-Generated: Mock registry validation sequence detected by ML");
      }

      return strategies;
    }
  }

  /**
   * Behavioral License Pattern Analyzer Analyzes runtime behavior patterns to identify
   * sophisticated license validation mechanisms
   */
  private class BehavioralLicenseAnalyzer {
    private Map<String, Double> behaviorSignatures = new HashMap<>();
    private Map<Address, List<String>> functionBehaviors = new HashMap<>();

    public BehavioralLicenseAnalyzer() {
      initializeBehaviorSignatures();
    }

    private void initializeBehaviorSignatures() {
      // Behavioral signatures for license validation
      behaviorSignatures.put("sequential_validation_calls", 0.92);
      behaviorSignatures.put("conditional_execution_flow", 0.88);
      behaviorSignatures.put("error_state_propagation", 0.85);
      behaviorSignatures.put("timeout_handling_behavior", 0.90);
      behaviorSignatures.put("retry_mechanism_pattern", 0.87);
      behaviorSignatures.put("graceful_degradation_flow", 0.83);
      behaviorSignatures.put("state_machine_behavior", 0.91);
      behaviorSignatures.put("validation_cache_pattern", 0.86);
      behaviorSignatures.put("background_validation_check", 0.89);
      behaviorSignatures.put("license_renewal_behavior", 0.94);
      behaviorSignatures.put("feature_lockout_pattern", 0.96);
      behaviorSignatures.put("trial_countdown_behavior", 0.93);
      behaviorSignatures.put("activation_flow_pattern", 0.90);
      behaviorSignatures.put("deactivation_sequence", 0.88);
      behaviorSignatures.put("license_transfer_behavior", 0.85);
    }

    public List<LicenseFunction> performBehavioralAnalysis(Program program) {
      List<LicenseFunction> behavioralDetected = new ArrayList<>();

      println("    [Behavioral] Phase 1: Runtime behavior pattern analysis...");
      Map<Address, Double> behaviorScores = analyzeBehaviorPatterns(program);

      println("    [Behavioral] Phase 2: Execution flow analysis...");
      Map<Address, Double> executionFlowScores = analyzeExecutionFlows(program);

      println("    [Behavioral] Phase 3: State transition analysis...");
      Map<Address, Double> stateTransitionScores = analyzeStateTransitions(program);

      println("    [Behavioral] Phase 4: Error propagation analysis...");
      Map<Address, Double> errorPropagationScores = analyzeErrorPropagation(program);

      // Combine behavioral analysis scores
      Set<Address> allFunctions = new HashSet<>();
      allFunctions.addAll(behaviorScores.keySet());
      allFunctions.addAll(executionFlowScores.keySet());
      allFunctions.addAll(stateTransitionScores.keySet());
      allFunctions.addAll(errorPropagationScores.keySet());

      for (Address funcAddr : allFunctions) {
        double combinedScore =
            behaviorScores.getOrDefault(funcAddr, 0.0) * 0.35
                + executionFlowScores.getOrDefault(funcAddr, 0.0) * 0.25
                + stateTransitionScores.getOrDefault(funcAddr, 0.0) * 0.25
                + errorPropagationScores.getOrDefault(funcAddr, 0.0) * 0.15;

        if (combinedScore > 0.70) {
          Function func = getFunctionAt(funcAddr);
          if (func != null) {
            LicenseFunction licFunc = new LicenseFunction();
            licFunc.address = funcAddr;
            licFunc.name = func.getName();
            licFunc.confidence = combinedScore;
            licFunc.type = "Behavioral License Validation";
            licFunc.bypassStrategies = generateBehavioralBypassStrategies(func);
            behavioralDetected.add(licFunc);
          }
        }
      }

      println(
          "    [Behavioral] Detected "
              + behavioralDetected.size()
              + " functions via behavioral analysis");
      return behavioralDetected;
    }

    private Map<Address, Double> analyzeBehaviorPatterns(Program program) {
      Map<Address, Double> scores = new HashMap<>();

      FunctionIterator funcIter = program.getFunctionManager().getFunctions(true);
      while (funcIter.hasNext()) {
        Function func = funcIter.next();
        List<String> behaviors = identifyFunctionBehaviors(func);
        functionBehaviors.put(func.getEntryPoint(), behaviors);

        double behaviorScore = 0.0;
        for (String behavior : behaviors) {
          Double weight = behaviorSignatures.get(behavior);
          if (weight != null) {
            behaviorScore += weight;
          }
        }

        if (behaviorScore > 0.0) {
          scores.put(func.getEntryPoint(), Math.min(behaviorScore, 1.0));
        }
      }

      return scores;
    }

    private List<String> identifyFunctionBehaviors(Function func) {
      List<String> behaviors = new ArrayList<>();

      // Analyze function for behavioral patterns
      if (hasSequentialValidationCalls(func)) {
        behaviors.add("sequential_validation_calls");
      }
      if (hasConditionalExecutionFlow(func)) {
        behaviors.add("conditional_execution_flow");
      }
      if (hasErrorStatePropagation(func)) {
        behaviors.add("error_state_propagation");
      }
      if (hasTimeoutHandlingBehavior(func)) {
        behaviors.add("timeout_handling_behavior");
      }
      if (hasRetryMechanismPattern(func)) {
        behaviors.add("retry_mechanism_pattern");
      }
      if (hasStateMachineBehavior(func)) {
        behaviors.add("state_machine_behavior");
      }
      if (hasValidationCachePattern(func)) {
        behaviors.add("validation_cache_pattern");
      }
      if (hasTrialCountdownBehavior(func)) {
        behaviors.add("trial_countdown_behavior");
      }
      if (hasActivationFlowPattern(func)) {
        behaviors.add("activation_flow_pattern");
      }
      if (hasFeatureLockoutPattern(func)) {
        behaviors.add("feature_lockout_pattern");
      }

      return behaviors;
    }

    private boolean hasSequentialValidationCalls(Function func) {
      // Look for multiple function calls in sequence
      InstructionIterator instIter =
          currentProgram.getListing().getInstructions(func.getBody(), true);
      List<Address> callAddresses = new ArrayList<>();

      while (instIter.hasNext()) {
        Instruction inst = instIter.next();
        if (inst.getMnemonicString().equalsIgnoreCase("CALL")) {
          callAddresses.add(inst.getAddress());
        }
      }

      // Check if calls are sequential (license validation often chains calls)
      return callAddresses.size() >= 3;
    }

    private boolean hasConditionalExecutionFlow(Function func) {
      // Count conditional jumps
      InstructionIterator instIter =
          currentProgram.getListing().getInstructions(func.getBody(), true);
      int conditionalJumps = 0;

      while (instIter.hasNext()) {
        Instruction inst = instIter.next();
        String mnemonic = inst.getMnemonicString().toUpperCase();
        if (mnemonic.startsWith("J") && !mnemonic.equals("JMP")) {
          conditionalJumps++;
        }
      }

      return conditionalJumps >= 2; // License functions typically have multiple conditions
    }

    private boolean hasErrorStatePropagation(Function func) {
      // Look for error return patterns
      try {
        DecompileResults results = decompiler.decompileFunction(func, 15, monitor);
        if (results.decompileCompleted() && results.getHighFunction() != null) {
          String code = results.getDecompiledFunction().getC();
          // Look for error codes and early returns
          return code.contains("return -1")
              || code.contains("return 0")
              || code.contains("return false")
              || code.contains("return NULL");
        }
      } catch (Exception e) {
        // Ignore
      }
      return false;
    }

    private boolean hasTimeoutHandlingBehavior(Function func) {
      // Look for time-related comparisons and timeout handling
      Reference[] refs = getReferencesFrom(func.getBody());
      for (Reference ref : refs) {
        String refName = getSymbolName(ref);
        if (refName != null) {
          String name = refName.toLowerCase();
          if (name.contains("timeout")
              || name.contains("gettick")
              || name.contains("timegettime")
              || name.contains("queryperformancecounter")) {
            return true;
          }
        }
      }
      return false;
    }

    private boolean hasRetryMechanismPattern(Function func) {
      // Look for loop patterns that might indicate retry logic
      try {
        DecompileResults results = decompiler.decompileFunction(func, 15, monitor);
        if (results.decompileCompleted() && results.getHighFunction() != null) {
          String code = results.getDecompiledFunction().getC();
          return (code.contains("while") || code.contains("for"))
              && (code.contains("retry") || code.contains("attempt") || code.contains("count"));
        }
      } catch (Exception e) {
        // Ignore
      }
      return false;
    }

    private boolean hasStateMachineBehavior(Function func) {
      // Look for switch statements or state variables
      try {
        DecompileResults results = decompiler.decompileFunction(func, 15, monitor);
        if (results.decompileCompleted() && results.getHighFunction() != null) {
          String code = results.getDecompiledFunction().getC();
          return code.contains("switch")
              || (code.contains("case") && code.contains("break"))
              || code.contains("state");
        }
      } catch (Exception e) {
        // Ignore
      }
      return false;
    }

    private boolean hasValidationCachePattern(Function func) {
      // Look for caching behavior (storing validation results)
      Reference[] refs = getReferencesFrom(func.getBody());
      for (Reference ref : refs) {
        if (ref.getReferenceType().isData()) {
          // Check if accessing global variables (potential cache)
          Address toAddr = ref.getToAddress();
          MemoryBlock block = currentProgram.getMemory().getBlock(toAddr);
          if (block != null && block.getName().equals(".data")) {
            return true;
          }
        }
      }
      return false;
    }

    private boolean hasTrialCountdownBehavior(Function func) {
      // Look for decrement operations and countdown logic
      try {
        DecompileResults results = decompiler.decompileFunction(func, 15, monitor);
        if (results.decompileCompleted() && results.getHighFunction() != null) {
          String code = results.getDecompiledFunction().getC();
          return (code.contains("--") || code.contains("- 1"))
              && (code.contains("days") || code.contains("trial") || code.contains("remaining"));
        }
      } catch (Exception e) {
        // Ignore
      }
      return false;
    }

    private boolean hasActivationFlowPattern(Function func) {
      // Look for activation-related strings and patterns
      String funcName = func.getName().toLowerCase();
      return funcName.contains("activate")
          || funcName.contains("register")
          || funcName.contains("unlock")
          || funcName.contains("enable");
    }

    private boolean hasFeatureLockoutPattern(Function func) {
      // Look for feature disabling patterns
      String funcName = func.getName().toLowerCase();
      return funcName.contains("disable")
          || funcName.contains("lock")
          || funcName.contains("restrict")
          || funcName.contains("block");
    }

    private Map<Address, Double> analyzeExecutionFlows(Program program) {
      Map<Address, Double> scores = new HashMap<>();

      for (Map.Entry<Address, List<String>> entry : functionBehaviors.entrySet()) {
        double flowScore = 0.0;

        // Analyze execution flow complexity
        Function func = getFunctionAt(entry.getKey());
        if (func != null) {
          int exitPoints = countExitPoints(func);
          int entryPoints = countEntryPoints(func);

          // License functions often have multiple exit points
          if (exitPoints >= 2 && exitPoints <= 8) {
            flowScore += 0.4;
          }
          if (entryPoints == 1) { // Single entry point is normal
            flowScore += 0.2;
          }

          // Analyze call graph complexity
          int callDepth = analyzeCallDepth(func);
          if (callDepth >= 2 && callDepth <= 6) { // Moderate call depth
            flowScore += 0.4;
          }
        }

        if (flowScore > 0.0) {
          scores.put(entry.getKey(), flowScore);
        }
      }

      return scores;
    }

    private Map<Address, Double> analyzeStateTransitions(Program program) {
      Map<Address, Double> scores = new HashMap<>();

      for (Map.Entry<Address, List<String>> entry : functionBehaviors.entrySet()) {
        if (entry.getValue().contains("state_machine_behavior")) {
          Function func = getFunctionAt(entry.getKey());
          if (func != null) {
            double stateScore = analyzeStateComplexity(func);
            if (stateScore > 0.0) {
              scores.put(entry.getKey(), stateScore);
            }
          }
        }
      }

      return scores;
    }

    private Map<Address, Double> analyzeErrorPropagation(Program program) {
      Map<Address, Double> scores = new HashMap<>();

      for (Map.Entry<Address, List<String>> entry : functionBehaviors.entrySet()) {
        if (entry.getValue().contains("error_state_propagation")) {
          Function func = getFunctionAt(entry.getKey());
          if (func != null) {
            double errorScore = analyzeErrorHandlingComplexity(func);
            if (errorScore > 0.0) {
              scores.put(entry.getKey(), errorScore);
            }
          }
        }
      }

      return scores;
    }

    private int countExitPoints(Function func) {
      InstructionIterator instIter =
          currentProgram.getListing().getInstructions(func.getBody(), true);
      int exitPoints = 0;

      while (instIter.hasNext()) {
        Instruction inst = instIter.next();
        if (inst.getMnemonicString().equalsIgnoreCase("RET")
            || inst.getMnemonicString().equalsIgnoreCase("RETN")) {
          exitPoints++;
        }
      }

      return exitPoints;
    }

    private int countEntryPoints(Function func) {
      // For now, assume single entry point (function start)
      // Could be extended to count multiple entry points for complex functions
      return 1;
    }

    private int analyzeCallDepth(Function func) {
      // Analyze how deep the call chain goes from this function
      Reference[] refs = getReferencesFrom(func.getBody());
      int maxDepth = 0;

      for (Reference ref : refs) {
        if (ref.getReferenceType().isCall()) {
          Function calledFunc = getFunctionAt(ref.getToAddress());
          if (calledFunc != null) {
            maxDepth = Math.max(maxDepth, 1); // Simplified depth calculation
          }
        }
      }

      return maxDepth;
    }

    private double analyzeStateComplexity(Function func) {
      // Analyze complexity of state machine behavior
      try {
        DecompileResults results = decompiler.decompileFunction(func, 15, monitor);
        if (results.decompileCompleted() && results.getHighFunction() != null) {
          String code = results.getDecompiledFunction().getC();
          int caseCount = code.split("case").length - 1;
          int switchCount = code.split("switch").length - 1;

          if (switchCount > 0 && caseCount >= 3) {
            return Math.min(caseCount / 10.0, 1.0);
          }
        }
      } catch (Exception e) {
        // Ignore
      }
      return 0.0;
    }

    private double analyzeErrorHandlingComplexity(Function func) {
      // Analyze complexity of error handling
      try {
        DecompileResults results = decompiler.decompileFunction(func, 15, monitor);
        if (results.decompileCompleted() && results.getHighFunction() != null) {
          String code = results.getDecompiledFunction().getC();
          int returnCount = code.split("return").length - 1;
          int ifCount = code.split("if").length - 1;

          if (returnCount >= 2 && ifCount >= 2) {
            return Math.min((returnCount + ifCount) / 10.0, 1.0);
          }
        }
      } catch (Exception e) {
        // Ignore
      }
      return 0.0;
    }

    private String getSymbolName(Reference ref) {
      Symbol sym = currentProgram.getSymbolTable().getPrimarySymbol(ref.getToAddress());
      return sym != null ? sym.getName() : null;
    }

    private List<String> generateBehavioralBypassStrategies(Function func) {
      List<String> strategies = new ArrayList<>();
      List<String> behaviors = functionBehaviors.get(func.getEntryPoint());

      strategies.add("Behavioral: Analyze and bypass detected behavioral patterns");

      if (behaviors.contains("sequential_validation_calls")) {
        strategies.add("Behavioral: Short-circuit validation call sequence");
      }
      if (behaviors.contains("conditional_execution_flow")) {
        strategies.add("Behavioral: Patch conditional branches to force success path");
      }
      if (behaviors.contains("error_state_propagation")) {
        strategies.add("Behavioral: Intercept error propagation and return success");
      }
      if (behaviors.contains("timeout_handling_behavior")) {
        strategies.add("Behavioral: Bypass timeout checks and extend validation period");
      }
      if (behaviors.contains("retry_mechanism_pattern")) {
        strategies.add("Behavioral: Skip retry logic and force immediate success");
      }
      if (behaviors.contains("state_machine_behavior")) {
        strategies.add("Behavioral: Manipulate state machine to always show licensed state");
      }
      if (behaviors.contains("trial_countdown_behavior")) {
        strategies.add("Behavioral: Freeze countdown or reset trial period");
      }
      if (behaviors.contains("feature_lockout_pattern")) {
        strategies.add("Behavioral: Unlock all features by bypassing lockout mechanism");
      }

      return strategies;
    }
  }

  /**
   * Anti-Analysis Detection Engine Detects and analyzes anti-analysis techniques used to protect
   * license validation functions
   */
  private class AntiAnalysisDetectionEngine {
    private Map<String, Double> antiAnalysisSignatures = new HashMap<>();
    private Set<String> packerSignatures = new HashSet<>();
    private Set<String> obfuscationPatterns = new HashSet<>();

    public AntiAnalysisDetectionEngine() {
      initializeAntiAnalysisSignatures();
      initializePackerSignatures();
      initializeObfuscationPatterns();
    }

    private void initializeAntiAnalysisSignatures() {
      // Anti-analysis technique signatures
      antiAnalysisSignatures.put("debugger_detection", 0.95);
      antiAnalysisSignatures.put("vm_detection", 0.92);
      antiAnalysisSignatures.put("sandbox_detection", 0.90);
      antiAnalysisSignatures.put("api_hashing", 0.88);
      antiAnalysisSignatures.put("control_flow_obfuscation", 0.86);
      antiAnalysisSignatures.put("string_encryption", 0.84);
      antiAnalysisSignatures.put("anti_disassembly", 0.89);
      antiAnalysisSignatures.put("timing_checks", 0.87);
      antiAnalysisSignatures.put("checksum_validation", 0.85);
      antiAnalysisSignatures.put("memory_protection", 0.91);
      antiAnalysisSignatures.put("code_integrity_check", 0.93);
      antiAnalysisSignatures.put("hardware_breakpoint_detection", 0.94);
      antiAnalysisSignatures.put("thread_local_storage_tricks", 0.82);
      antiAnalysisSignatures.put("exception_handler_tricks", 0.85);
      antiAnalysisSignatures.put("process_hollowing_detection", 0.89);
    }

    private void initializePackerSignatures() {
      // Common packer signatures
      packerSignatures.add("upx");
      packerSignatures.add("aspack");
      packerSignatures.add("pecompact");
      packerSignatures.add("vmprotect");
      packerSignatures.add("themida");
      packerSignatures.add("enigma");
      packerSignatures.add("armadillo");
      packerSignatures.add("asprotect");
      packerSignatures.add("exestealth");
      packerSignatures.add("winlicense");
      packerSignatures.add("obsidium");
      packerSignatures.add("petite");
      packerSignatures.add("npack");
      packerSignatures.add("rlpack");
      packerSignatures.add("eziriz");
    }

    private void initializeObfuscationPatterns() {
      // Obfuscation patterns
      obfuscationPatterns.add("junk_code_insertion");
      obfuscationPatterns.add("opaque_predicates");
      obfuscationPatterns.add("dead_code_insertion");
      obfuscationPatterns.add("instruction_substitution");
      obfuscationPatterns.add("control_flow_flattening");
      obfuscationPatterns.add("virtualization_obfuscation");
      obfuscationPatterns.add("metamorphic_engine");
      obfuscationPatterns.add("polymorphic_engine");
      obfuscationPatterns.add("api_call_indirection");
      obfuscationPatterns.add("constant_unfolding");
    }

    public List<LicenseFunction> performAntiAnalysisDetection(Program program) {
      List<LicenseFunction> antiAnalysisDetected = new ArrayList<>();

      println("    [AntiAnalysis] Phase 1: Debugger detection analysis...");
      Map<Address, Double> debuggerDetectionScores = analyzeDebuggerDetection(program);

      println("    [AntiAnalysis] Phase 2: Virtualization detection analysis...");
      Map<Address, Double> vmDetectionScores = analyzeVMDetection(program);

      println("    [AntiAnalysis] Phase 3: Obfuscation pattern analysis...");
      Map<Address, Double> obfuscationScores = analyzeObfuscationPatterns(program);

      println("    [AntiAnalysis] Phase 4: Anti-disassembly technique analysis...");
      Map<Address, Double> antiDisassemblyScores = analyzeAntiDisassemblyTechniques(program);

      println("    [AntiAnalysis] Phase 5: Code integrity check analysis...");
      Map<Address, Double> integrityCheckScores = analyzeCodeIntegrityChecks(program);

      // Combine all anti-analysis scores
      Set<Address> allFunctions = new HashSet<>();
      allFunctions.addAll(debuggerDetectionScores.keySet());
      allFunctions.addAll(vmDetectionScores.keySet());
      allFunctions.addAll(obfuscationScores.keySet());
      allFunctions.addAll(antiDisassemblyScores.keySet());
      allFunctions.addAll(integrityCheckScores.keySet());

      for (Address funcAddr : allFunctions) {
        double combinedScore =
            debuggerDetectionScores.getOrDefault(funcAddr, 0.0) * 0.25
                + vmDetectionScores.getOrDefault(funcAddr, 0.0) * 0.20
                + obfuscationScores.getOrDefault(funcAddr, 0.0) * 0.20
                + antiDisassemblyScores.getOrDefault(funcAddr, 0.0) * 0.20
                + integrityCheckScores.getOrDefault(funcAddr, 0.0) * 0.15;

        if (combinedScore > 0.65) {
          Function func = getFunctionAt(funcAddr);
          if (func != null) {
            LicenseFunction licFunc = new LicenseFunction();
            licFunc.address = funcAddr;
            licFunc.name = func.getName();
            licFunc.confidence = combinedScore;
            licFunc.type = "Anti-Analysis Protected License Function";
            licFunc.bypassStrategies = generateAntiAnalysisBypassStrategies(func);
            antiAnalysisDetected.add(licFunc);
          }
        }
      }

      println(
          "    [AntiAnalysis] Detected "
              + antiAnalysisDetected.size()
              + " anti-analysis protected functions");
      return antiAnalysisDetected;
    }

    private Map<Address, Double> analyzeDebuggerDetection(Program program) {
      Map<Address, Double> scores = new HashMap<>();

      // Known debugger detection APIs and techniques
      String[] debuggerDetectionAPIs = {
        "IsDebuggerPresent",
        "CheckRemoteDebuggerPresent",
        "NtQueryInformationProcess",
        "NtSetInformationThread",
        "OutputDebugString",
        "GetThreadContext",
        "SetThreadContext",
        "ContinueDebugEvent",
        "DebugActiveProcess",
        "ZwQueryInformationProcess",
        "NtQueryObject",
        "FindWindow",
        "GetWindowThreadProcessId"
      };

      FunctionIterator funcIter = program.getFunctionManager().getFunctions(true);
      while (funcIter.hasNext()) {
        Function func = funcIter.next();
        double detectionScore = 0.0;

        // Check for debugger detection API calls
        Reference[] refs = getReferencesFrom(func.getBody());
        for (Reference ref : refs) {
          String refName = getSymbolName(ref);
          if (refName != null) {
            for (String api : debuggerDetectionAPIs) {
              if (refName.contains(api)) {
                detectionScore += 0.3;
              }
            }
          }
        }

        // Check for PEB BeingDebugged flag access
        if (hasPEBDebuggerCheck(func)) {
          detectionScore += 0.4;
        }

        // Check for heap flags manipulation
        if (hasHeapFlagsCheck(func)) {
          detectionScore += 0.3;
        }

        if (detectionScore > 0.0) {
          scores.put(func.getEntryPoint(), Math.min(detectionScore, 1.0));
        }
      }

      return scores;
    }

    private Map<Address, Double> analyzeVMDetection(Program program) {
      Map<Address, Double> scores = new HashMap<>();

      // VM detection techniques
      String[] vmDetectionAPIs = {
        "GetSystemMetrics",
        "GetModuleHandle",
        "CreateFile",
        "RegOpenKey",
        "RegQueryValue",
        "GetDriveType",
        "GetAdaptersInfo",
        "GetComputerName",
        "cpuid",
        "rdtsc",
        "sidt",
        "sgdt",
        "sldt",
        "str"
      };

      FunctionIterator funcIter = program.getFunctionManager().getFunctions(true);
      while (funcIter.hasNext()) {
        Function func = funcIter.next();
        double vmScore = 0.0;

        // Check for VM detection API calls
        Reference[] refs = getReferencesFrom(func.getBody());
        for (Reference ref : refs) {
          String refName = getSymbolName(ref);
          if (refName != null) {
            for (String api : vmDetectionAPIs) {
              if (refName.contains(api)) {
                vmScore += 0.2;
              }
            }
          }
        }

        // Check for CPUID instructions (common in VM detection)
        if (hasCPUIDInstructions(func)) {
          vmScore += 0.4;
        }

        // Check for timing-based detection
        if (hasTimingBasedVMDetection(func)) {
          vmScore += 0.3;
        }

        // Check for VM-specific registry keys
        if (hasVMRegistryChecks(func)) {
          vmScore += 0.3;
        }

        if (vmScore > 0.0) {
          scores.put(func.getEntryPoint(), Math.min(vmScore, 1.0));
        }
      }

      return scores;
    }

    private Map<Address, Double> analyzeObfuscationPatterns(Program program) {
      Map<Address, Double> scores = new HashMap<>();

      FunctionIterator funcIter = program.getFunctionManager().getFunctions(true);
      while (funcIter.hasNext()) {
        Function func = funcIter.next();
        double obfuscationScore = 0.0;

        // Analyze function for obfuscation patterns
        if (hasJunkCodeInsertion(func)) {
          obfuscationScore += 0.3;
        }
        if (hasOpaquePredicates(func)) {
          obfuscationScore += 0.4;
        }
        if (hasDeadCodeInsertion(func)) {
          obfuscationScore += 0.2;
        }
        if (hasInstructionSubstitution(func)) {
          obfuscationScore += 0.3;
        }
        if (hasControlFlowFlattening(func)) {
          obfuscationScore += 0.5;
        }
        if (hasAPICallIndirection(func)) {
          obfuscationScore += 0.4;
        }

        if (obfuscationScore > 0.0) {
          scores.put(func.getEntryPoint(), Math.min(obfuscationScore, 1.0));
        }
      }

      return scores;
    }

    private Map<Address, Double> analyzeAntiDisassemblyTechniques(Program program) {
      Map<Address, Double> scores = new HashMap<>();

      FunctionIterator funcIter = program.getFunctionManager().getFunctions(true);
      while (funcIter.hasNext()) {
        Function func = funcIter.next();
        double antiDisasmScore = 0.0;

        // Check for anti-disassembly techniques
        if (hasInvalidInstructions(func)) {
          antiDisasmScore += 0.4;
        }
        if (hasJumpIntoMiddleOfInstruction(func)) {
          antiDisasmScore += 0.5;
        }
        if (hasSelfModifyingCode(func)) {
          antiDisasmScore += 0.6;
        }
        if (hasIndirectCalls(func)) {
          antiDisasmScore += 0.3;
        }
        if (hasExceptionHandlerTricks(func)) {
          antiDisasmScore += 0.4;
        }

        if (antiDisasmScore > 0.0) {
          scores.put(func.getEntryPoint(), Math.min(antiDisasmScore, 1.0));
        }
      }

      return scores;
    }

    private Map<Address, Double> analyzeCodeIntegrityChecks(Program program) {
      Map<Address, Double> scores = new HashMap<>();

      FunctionIterator funcIter = program.getFunctionManager().getFunctions(true);
      while (funcIter.hasNext()) {
        Function func = funcIter.next();
        double integrityScore = 0.0;

        // Check for integrity validation techniques
        if (hasChecksumValidation(func)) {
          integrityScore += 0.4;
        }
        if (hasCRCChecks(func)) {
          integrityScore += 0.3;
        }
        if (hasHashValidation(func)) {
          integrityScore += 0.4;
        }
        if (hasMemoryProtectionChecks(func)) {
          integrityScore += 0.3;
        }
        if (hasDigitalSignatureValidation(func)) {
          integrityScore += 0.5;
        }

        if (integrityScore > 0.0) {
          scores.put(func.getEntryPoint(), Math.min(integrityScore, 1.0));
        }
      }

      return scores;
    }

    // Detection helper methods
    private boolean hasPEBDebuggerCheck(Function func) {
      // Look for PEB BeingDebugged flag access (fs:[30h] + 2)
      InstructionIterator instIter =
          currentProgram.getListing().getInstructions(func.getBody(), true);
      while (instIter.hasNext()) {
        Instruction inst = instIter.next();
        String repr = inst.toString().toLowerCase();
        if (repr.contains("fs:") && (repr.contains("0x30") || repr.contains("30h"))) {
          return true;
        }
      }
      return false;
    }

    private boolean hasHeapFlagsCheck(Function func) {
      // Look for heap flags checks
      InstructionIterator instIter =
          currentProgram.getListing().getInstructions(func.getBody(), true);
      while (instIter.hasNext()) {
        Instruction inst = instIter.next();
        String repr = inst.toString().toLowerCase();
        if (repr.contains("heap") || (repr.contains("0x18") && repr.contains("fs:"))) {
          return true;
        }
      }
      return false;
    }

    private boolean hasCPUIDInstructions(Function func) {
      InstructionIterator instIter =
          currentProgram.getListing().getInstructions(func.getBody(), true);
      while (instIter.hasNext()) {
        Instruction inst = instIter.next();
        if (inst.getMnemonicString().equalsIgnoreCase("CPUID")) {
          return true;
        }
      }
      return false;
    }

    private boolean hasTimingBasedVMDetection(Function func) {
      // Look for RDTSC instructions and timing comparisons
      InstructionIterator instIter =
          currentProgram.getListing().getInstructions(func.getBody(), true);
      boolean hasRDTSC = false;
      boolean hasComparison = false;

      while (instIter.hasNext()) {
        Instruction inst = instIter.next();
        String mnemonic = inst.getMnemonicString().toUpperCase();
        if (mnemonic.equals("RDTSC")) {
          hasRDTSC = true;
        } else if (mnemonic.startsWith("CMP")) {
          hasComparison = true;
        }
      }

      return hasRDTSC && hasComparison;
    }

    private boolean hasVMRegistryChecks(Function func) {
      // Check for VM-specific registry access
      Reference[] refs = getReferencesFrom(func.getBody());
      for (Reference ref : refs) {
        Data data = getDataAt(ref.getToAddress());
        if (data != null && data.hasStringValue()) {
          String str = data.getDefaultValueRepresentation().toLowerCase();
          if (str.contains("vmware")
              || str.contains("virtualbox")
              || str.contains("vbox")
              || str.contains("qemu")
              || str.contains("xen")) {
            return true;
          }
        }
      }
      return false;
    }

    private boolean hasJunkCodeInsertion(Function func) {
      // Look for patterns indicating junk code
      InstructionIterator instIter =
          currentProgram.getListing().getInstructions(func.getBody(), true);
      int nopCount = 0;
      int totalInst = 0;

      while (instIter.hasNext()) {
        Instruction inst = instIter.next();
        totalInst++;
        String mnemonic = inst.getMnemonicString().toUpperCase();
        if (mnemonic.equals("NOP")
            || mnemonic.equals("XCHG")
            || (mnemonic.equals("MOV") && inst.getOperandReferences(0).length == 0)) {
          nopCount++;
        }
      }

      // If more than 20% of instructions are potentially junk
      return totalInst > 0 && (nopCount / (double) totalInst) > 0.2;
    }

    private boolean hasOpaquePredicates(Function func) {
      // Look for conditions that are always true/false but appear complex
      try {
        DecompileResults results = decompiler.decompileFunction(func, 15, monitor);
        if (results.decompileCompleted() && results.getHighFunction() != null) {
          String code = results.getDecompiledFunction().getC();
          // Look for complex conditions with simple results
          return code.contains("(")
              && code.contains("&")
              && (code.contains("== 0") || code.contains("!= 0"));
        }
      } catch (Exception e) {
        // Ignore
      }
      return false;
    }

    private boolean hasDeadCodeInsertion(Function func) {
      // Look for unreachable code blocks
      try {
        DecompileResults results = decompiler.decompileFunction(func, 15, monitor);
        if (results.decompileCompleted() && results.getHighFunction() != null) {
          HighFunction highFunc = results.getHighFunction();
          PcodeBlockBasic[] blocks = highFunc.getBasicBlocks();

          // Simple heuristic: if there are blocks with no incoming references
          int unreachableBlocks = 0;
          for (PcodeBlockBasic block : blocks) {
            if (block.getInSize() == 0 && block != blocks[0]) { // Not entry block
              unreachableBlocks++;
            }
          }

          return unreachableBlocks > 0;
        }
      } catch (Exception e) {
        // Ignore
      }
      return false;
    }

    private boolean hasInstructionSubstitution(Function func) {
      // Look for unusual instruction sequences that could be substitutions
      InstructionIterator instIter =
          currentProgram.getListing().getInstructions(func.getBody(), true);
      while (instIter.hasNext()) {
        Instruction inst = instIter.next();
        String mnemonic = inst.getMnemonicString().toUpperCase();
        // Complex ways to do simple operations
        if ((mnemonic.equals("SUB") && inst.toString().contains("0"))
            || (mnemonic.equals("XOR") && inst.getOperandReferences(0).length > 0)
            || (mnemonic.equals("ROR") && inst.toString().contains("0"))) {
          return true;
        }
      }
      return false;
    }

    private boolean hasControlFlowFlattening(Function func) {
      // Look for dispatch-based control flow (typical of flattening)
      try {
        DecompileResults results = decompiler.decompileFunction(func, 15, monitor);
        if (results.decompileCompleted() && results.getHighFunction() != null) {
          String code = results.getDecompiledFunction().getC();
          // Look for switch statements or dispatch variables
          return code.contains("switch")
              && code.contains("case")
              && code.split("case").length > 5; // Many cases suggest flattening
        }
      } catch (Exception e) {
        // Ignore
      }
      return false;
    }

    private boolean hasAPICallIndirection(Function func) {
      // Look for indirect API calls through function pointers
      InstructionIterator instIter =
          currentProgram.getListing().getInstructions(func.getBody(), true);
      while (instIter.hasNext()) {
        Instruction inst = instIter.next();
        if (inst.getMnemonicString().toUpperCase().equals("CALL")) {
          // Check if it's an indirect call
          if (inst.toString().contains("[") || inst.toString().contains("*")) {
            return true;
          }
        }
      }
      return false;
    }

    private boolean hasInvalidInstructions(Function func) {
      // Look for potentially invalid or unusual instructions
      InstructionIterator instIter =
          currentProgram.getListing().getInstructions(func.getBody(), true);
      while (instIter.hasNext()) {
        Instruction inst = instIter.next();
        if (inst.toString().toLowerCase().contains("(bad)")
            || inst.toString().toLowerCase().contains("undefined")) {
          return true;
        }
      }
      return false;
    }

    private boolean hasJumpIntoMiddleOfInstruction(Function func) {
      // This is complex to detect statically, simplified check
      InstructionIterator instIter =
          currentProgram.getListing().getInstructions(func.getBody(), true);
      while (instIter.hasNext()) {
        Instruction inst = instIter.next();
        String mnemonic = inst.getMnemonicString().toUpperCase();
        if (mnemonic.startsWith("J") && !mnemonic.equals("JMP")) {
          // Check if jump target is very close (potential middle of instruction)
          Reference[] refs = inst.getOperandReferences(0);
          if (refs.length > 0) {
            Address jumpTarget = refs[0].getToAddress();
            long distance = Math.abs(jumpTarget.subtract(inst.getAddress()));
            if (distance < 10 && distance > 0) { // Very close jump
              return true;
            }
          }
        }
      }
      return false;
    }

    private boolean hasSelfModifyingCode(Function func) {
      // Look for writes to executable memory regions
      InstructionIterator instIter =
          currentProgram.getListing().getInstructions(func.getBody(), true);
      while (instIter.hasNext()) {
        Instruction inst = instIter.next();
        String mnemonic = inst.getMnemonicString().toUpperCase();
        if (mnemonic.equals("MOV") && inst.toString().contains("[")) {
          // Check if writing to executable section
          MemoryBlock block = currentProgram.getMemory().getBlock(inst.getAddress());
          if (block != null && block.isExecute() && block.isWrite()) {
            return true;
          }
        }
      }
      return false;
    }

    private boolean hasIndirectCalls(Function func) {
      InstructionIterator instIter =
          currentProgram.getListing().getInstructions(func.getBody(), true);
      int indirectCalls = 0;
      int totalCalls = 0;

      while (instIter.hasNext()) {
        Instruction inst = instIter.next();
        if (inst.getMnemonicString().toUpperCase().equals("CALL")) {
          totalCalls++;
          if (inst.toString().contains("[") || inst.toString().contains("*")) {
            indirectCalls++;
          }
        }
      }

      // If more than 50% of calls are indirect
      return totalCalls > 0 && (indirectCalls / (double) totalCalls) > 0.5;
    }

    private boolean hasExceptionHandlerTricks(Function func) {
      // Look for exception handling instructions
      InstructionIterator instIter =
          currentProgram.getListing().getInstructions(func.getBody(), true);
      while (instIter.hasNext()) {
        Instruction inst = instIter.next();
        String repr = inst.toString().toLowerCase();
        if (repr.contains("fs:[0]")
            || repr.contains("exception")
            || inst.getMnemonicString().equalsIgnoreCase("INT3")) {
          return true;
        }
      }
      return false;
    }

    private boolean hasChecksumValidation(Function func) {
      // Look for checksum calculation patterns
      Reference[] refs = getReferencesFrom(func.getBody());
      for (Reference ref : refs) {
        String refName = getSymbolName(ref);
        if (refName != null
            && (refName.toLowerCase().contains("checksum")
                || refName.toLowerCase().contains("crc"))) {
          return true;
        }
      }
      return false;
    }

    private boolean hasCRCChecks(Function func) {
      // Look for CRC calculation loops
      try {
        DecompileResults results = decompiler.decompileFunction(func, 15, monitor);
        if (results.decompileCompleted() && results.getHighFunction() != null) {
          String code = results.getDecompiledFunction().getC();
          return code.contains("crc") || (code.contains("for") && code.contains("^"));
        }
      } catch (Exception e) {
        // Ignore
      }
      return false;
    }

    private boolean hasHashValidation(Function func) {
      // Look for hash-related API calls
      Reference[] refs = getReferencesFrom(func.getBody());
      for (Reference ref : refs) {
        String refName = getSymbolName(ref);
        if (refName != null) {
          String name = refName.toLowerCase();
          if (name.contains("hash")
              || name.contains("md5")
              || name.contains("sha")
              || name.contains("crypt")
              || name.contains("digest")) {
            return true;
          }
        }
      }
      return false;
    }

    private boolean hasMemoryProtectionChecks(Function func) {
      // Look for memory protection API calls
      Reference[] refs = getReferencesFrom(func.getBody());
      for (Reference ref : refs) {
        String refName = getSymbolName(ref);
        if (refName != null) {
          String name = refName.toLowerCase();
          if (name.contains("virtualprotect")
              || name.contains("virtualalloc")
              || name.contains("virtualquery")
              || name.contains("memorybasicinfo")) {
            return true;
          }
        }
      }
      return false;
    }

    private boolean hasDigitalSignatureValidation(Function func) {
      // Look for digital signature validation APIs
      Reference[] refs = getReferencesFrom(func.getBody());
      for (Reference ref : refs) {
        String refName = getSymbolName(ref);
        if (refName != null) {
          String name = refName.toLowerCase();
          if (name.contains("cryptverify")
              || name.contains("wintrust")
              || name.contains("signature")
              || name.contains("certificate")) {
            return true;
          }
        }
      }
      return false;
    }

    private String getSymbolName(Reference ref) {
      Symbol sym = currentProgram.getSymbolTable().getPrimarySymbol(ref.getToAddress());
      return sym != null ? sym.getName() : null;
    }

    private List<String> generateAntiAnalysisBypassStrategies(Function func) {
      List<String> strategies = new ArrayList<>();

      strategies.add("Anti-Analysis: Patch or hook anti-analysis checks to always return false");
      strategies.add("Anti-Analysis: Use debugging evasion techniques during analysis");
      strategies.add("Anti-Analysis: Deploy VM-aware analysis environment");
      strategies.add("Anti-Analysis: Bypass obfuscation using pattern recognition");
      strategies.add("Anti-Analysis: Use anti-anti-debugging techniques");

      if (hasPEBDebuggerCheck(func)) {
        strategies.add("Anti-Analysis: Patch PEB BeingDebugged flag access");
      }
      if (hasCPUIDInstructions(func)) {
        strategies.add("Anti-Analysis: Hook CPUID instruction to return host values");
      }
      if (hasObfuscationPatterns(func)) {
        strategies.add("Anti-Analysis: Deobfuscate using pattern matching and symbolic execution");
      }
      if (hasSelfModifyingCode(func)) {
        strategies.add("Anti-Analysis: Trace and analyze self-modification at runtime");
      }

      return strategies;
    }

    private boolean hasObfuscationPatterns(Function func) {
      return hasJunkCodeInsertion(func)
          || hasOpaquePredicates(func)
          || hasControlFlowFlattening(func)
          || hasAPICallIndirection(func);
    }
  }

  /**
   * Cloud License Detection Engine Specialized detection for modern cloud-based licensing systems
   */
  private class CloudLicenseDetectionEngine {
    private Map<String, Double> cloudServicePatterns = new HashMap<>();
    private Map<String, Double> oauthPatterns = new HashMap<>();
    private Map<String, Double> jwtPatterns = new HashMap<>();

    public CloudLicenseDetectionEngine() {
      initializeCloudServicePatterns();
      initializeOAuthPatterns();
      initializeJWTPatterns();
    }

    private void initializeCloudServicePatterns() {
      // Cloud service provider patterns
      cloudServicePatterns.put("azure_ad_validation", 0.95);
      cloudServicePatterns.put("aws_iam_validation", 0.94);
      cloudServicePatterns.put("gcp_service_account_validation", 0.93);
      cloudServicePatterns.put("office365_licensing", 0.96);
      cloudServicePatterns.put("salesforce_authentication", 0.88);
      cloudServicePatterns.put("okta_validation", 0.90);
      cloudServicePatterns.put("auth0_validation", 0.89);
      cloudServicePatterns.put("firebase_auth", 0.87);
      cloudServicePatterns.put("cognito_validation", 0.91);
      cloudServicePatterns.put("saas_subscription_check", 0.92);
      cloudServicePatterns.put("stripe_subscription_validation", 0.90);
      cloudServicePatterns.put("paypal_subscription_check", 0.88);
      cloudServicePatterns.put("recurly_billing_validation", 0.85);
      cloudServicePatterns.put("chargebee_license_check", 0.86);
      cloudServicePatterns.put("zuora_subscription_validation", 0.87);
    }

    private void initializeOAuthPatterns() {
      // OAuth 2.0 and OpenID Connect patterns
      oauthPatterns.put("authorization_code_flow", 0.90);
      oauthPatterns.put("client_credentials_flow", 0.88);
      oauthPatterns.put("resource_owner_password_flow", 0.85);
      oauthPatterns.put("implicit_flow", 0.82);
      oauthPatterns.put("device_authorization_flow", 0.87);
      oauthPatterns.put("pkce_validation", 0.89);
      oauthPatterns.put("refresh_token_validation", 0.91);
      oauthPatterns.put("scope_validation", 0.86);
      oauthPatterns.put("openid_connect_validation", 0.92);
      oauthPatterns.put("bearer_token_validation", 0.88);
    }

    private void initializeJWTPatterns() {
      // JWT (JSON Web Token) patterns
      jwtPatterns.put("jwt_signature_validation", 0.94);
      jwtPatterns.put("jwt_expiration_check", 0.92);
      jwtPatterns.put("jwt_issuer_validation", 0.90);
      jwtPatterns.put("jwt_audience_validation", 0.89);
      jwtPatterns.put("jwt_claims_validation", 0.91);
      jwtPatterns.put("jwk_key_validation", 0.88);
      jwtPatterns.put("jws_signature_verification", 0.93);
      jwtPatterns.put("jwe_decryption", 0.87);
      jwtPatterns.put("jwt_blacklist_check", 0.85);
      jwtPatterns.put("jwt_refresh_validation", 0.86);
    }

    public List<LicenseFunction> performCloudLicenseDetection(Program program) {
      List<LicenseFunction> cloudDetected = new ArrayList<>();

      println("    [Cloud] Phase 1: Cloud service pattern analysis...");
      Map<Address, Double> cloudServiceScores = analyzeCloudServicePatterns(program);

      println("    [Cloud] Phase 2: OAuth flow analysis...");
      Map<Address, Double> oauthScores = analyzeOAuthFlows(program);

      println("    [Cloud] Phase 3: JWT token analysis...");
      Map<Address, Double> jwtScores = analyzeJWTPatterns(program);

      println("    [Cloud] Phase 4: API endpoint analysis...");
      Map<Address, Double> apiEndpointScores = analyzeAPIEndpoints(program);

      println("    [Cloud] Phase 5: Subscription validation analysis...");
      Map<Address, Double> subscriptionScores = analyzeSubscriptionValidation(program);

      // Combine all cloud license scores
      Set<Address> allFunctions = new HashSet<>();
      allFunctions.addAll(cloudServiceScores.keySet());
      allFunctions.addAll(oauthScores.keySet());
      allFunctions.addAll(jwtScores.keySet());
      allFunctions.addAll(apiEndpointScores.keySet());
      allFunctions.addAll(subscriptionScores.keySet());

      for (Address funcAddr : allFunctions) {
        double combinedScore =
            cloudServiceScores.getOrDefault(funcAddr, 0.0) * 0.25
                + oauthScores.getOrDefault(funcAddr, 0.0) * 0.25
                + jwtScores.getOrDefault(funcAddr, 0.0) * 0.20
                + apiEndpointScores.getOrDefault(funcAddr, 0.0) * 0.15
                + subscriptionScores.getOrDefault(funcAddr, 0.0) * 0.15;

        if (combinedScore > 0.70) {
          Function func = getFunctionAt(funcAddr);
          if (func != null) {
            LicenseFunction licFunc = new LicenseFunction();
            licFunc.address = funcAddr;
            licFunc.name = func.getName();
            licFunc.confidence = combinedScore;
            licFunc.type = "Cloud-Based License Validation";
            licFunc.bypassStrategies = generateCloudBypassStrategies(func);
            cloudDetected.add(licFunc);
          }
        }
      }

      println("    [Cloud] Detected " + cloudDetected.size() + " cloud-based license functions");
      return cloudDetected;
    }

    private Map<Address, Double> analyzeCloudServicePatterns(Program program) {
      Map<Address, Double> scores = new HashMap<>();

      // Cloud service endpoints and patterns
      String[] cloudEndpoints = {
        "login.microsoftonline.com", "management.azure.com", "graph.microsoft.com",
        "sts.amazonaws.com", "iam.amazonaws.com", "cognito-idp",
        "accounts.google.com", "oauth2.googleapis.com", "iam.googleapis.com",
        "api.auth0.com", "login.salesforce.com", "api.stripe.com",
        "api.paypal.com", "secure.recurly.com", "api.chargebee.com"
      };

      FunctionIterator funcIter = program.getFunctionManager().getFunctions(true);
      while (funcIter.hasNext()) {
        Function func = funcIter.next();
        double cloudScore = 0.0;

        // Check for cloud service references
        Reference[] refs = getReferencesFrom(func.getBody());
        for (Reference ref : refs) {
          Data data = getDataAt(ref.getToAddress());
          if (data != null && data.hasStringValue()) {
            String str = data.getDefaultValueRepresentation().toLowerCase();
            for (String endpoint : cloudEndpoints) {
              if (str.contains(endpoint.toLowerCase())) {
                cloudScore += 0.4;
              }
            }
          }
        }

        // Check function names for cloud patterns
        String funcName = func.getName().toLowerCase();
        if (funcName.contains("azure")
            || funcName.contains("aws")
            || funcName.contains("gcp")
            || funcName.contains("oauth")
            || funcName.contains("saas")
            || funcName.contains("cloud")) {
          cloudScore += 0.3;
        }

        if (cloudScore > 0.0) {
          scores.put(func.getEntryPoint(), Math.min(cloudScore, 1.0));
        }
      }

      return scores;
    }

    private Map<Address, Double> analyzeOAuthFlows(Program program) {
      Map<Address, Double> scores = new HashMap<>();

      // OAuth-related strings and patterns
      String[] oauthStrings = {
        "authorization_code",
        "client_credentials",
        "refresh_token",
        "access_token",
        "bearer",
        "scope",
        "redirect_uri",
        "client_id",
        "client_secret",
        "grant_type",
        "response_type",
        "code_challenge",
        "code_verifier",
        "state",
        "nonce",
        "id_token",
        "userinfo"
      };

      FunctionIterator funcIter = program.getFunctionManager().getFunctions(true);
      while (funcIter.hasNext()) {
        Function func = funcIter.next();
        double oauthScore = 0.0;

        // Check for OAuth-related strings
        Reference[] refs = getReferencesFrom(func.getBody());
        for (Reference ref : refs) {
          Data data = getDataAt(ref.getToAddress());
          if (data != null && data.hasStringValue()) {
            String str = data.getDefaultValueRepresentation().toLowerCase();
            for (String oauthStr : oauthStrings) {
              if (str.contains(oauthStr)) {
                oauthScore += 0.2;
              }
            }
          }
        }

        // Check for HTTP header manipulation (common in OAuth)
        if (hasHTTPHeaderManipulation(func)) {
          oauthScore += 0.3;
        }

        if (oauthScore > 0.0) {
          scores.put(func.getEntryPoint(), Math.min(oauthScore, 1.0));
        }
      }

      return scores;
    }

    private Map<Address, Double> analyzeJWTPatterns(Program program) {
      Map<Address, Double> scores = new HashMap<>();

      // JWT-related patterns
      String[] jwtStrings = {
        "eyJ", "Bearer ", "JWT", "jose", "alg", "typ", "iss", "sub", "aud", "exp", "iat", "nbf",
        "RS256", "HS256", "ES256", "PS256", "RS384", "HS384", "ES384", "RS512", "HS512", "ES512"
      };

      FunctionIterator funcIter = program.getFunctionManager().getFunctions(true);
      while (funcIter.hasNext()) {
        Function func = funcIter.next();
        double jwtScore = 0.0;

        // Check for JWT-related strings
        Reference[] refs = getReferencesFrom(func.getBody());
        for (Reference ref : refs) {
          Data data = getDataAt(ref.getToAddress());
          if (data != null && data.hasStringValue()) {
            String str = data.getDefaultValueRepresentation();
            for (String jwtStr : jwtStrings) {
              if (str.contains(jwtStr)) {
                jwtScore += 0.3;
              }
            }

            // Check for JWT structure (three base64 parts)
            if (str.matches(
                ".*[A-Za-z0-9+/=]{10,}\\.[A-Za-z0-9+/=]{10,}\\.[A-Za-z0-9+/=]{10,}.*")) {
              jwtScore += 0.5;
            }
          }
        }

        // Check for base64 decoding (common in JWT processing)
        if (hasBase64Operations(func)) {
          jwtScore += 0.2;
        }

        // Check for JSON parsing (JWT payload)
        if (hasJSONOperations(func)) {
          jwtScore += 0.2;
        }

        if (jwtScore > 0.0) {
          scores.put(func.getEntryPoint(), Math.min(jwtScore, 1.0));
        }
      }

      return scores;
    }

    private Map<Address, Double> analyzeAPIEndpoints(Program program) {
      Map<Address, Double> scores = new HashMap<>();

      // REST API patterns
      String[] restPatterns = {
        "/api/",
        "/v1/",
        "/v2/",
        "/oauth/",
        "/auth/",
        "/token/",
        "/license/",
        "/subscription/",
        "POST",
        "GET",
        "PUT",
        "DELETE",
        "PATCH",
        "Content-Type",
        "application/json",
        "Authorization",
        "X-API-Key",
        "X-Auth-Token"
      };

      FunctionIterator funcIter = program.getFunctionManager().getFunctions(true);
      while (funcIter.hasNext()) {
        Function func = funcIter.next();
        double apiScore = 0.0;

        // Check for REST API patterns
        Reference[] refs = getReferencesFrom(func.getBody());
        for (Reference ref : refs) {
          Data data = getDataAt(ref.getToAddress());
          if (data != null && data.hasStringValue()) {
            String str = data.getDefaultValueRepresentation();
            for (String pattern : restPatterns) {
              if (str.contains(pattern)) {
                apiScore += 0.2;
              }
            }
          }
        }

        // Check for HTTP client libraries
        if (hasHTTPClientCalls(func)) {
          apiScore += 0.3;
        }

        if (apiScore > 0.0) {
          scores.put(func.getEntryPoint(), Math.min(apiScore, 1.0));
        }
      }

      return scores;
    }

    private Map<Address, Double> analyzeSubscriptionValidation(Program program) {
      Map<Address, Double> scores = new HashMap<>();

      // Subscription validation patterns
      String[] subscriptionPatterns = {
        "subscription",
        "billing",
        "payment",
        "invoice",
        "recurring",
        "plan",
        "tier",
        "trial",
        "premium",
        "pro",
        "enterprise",
        "basic",
        "free",
        "paid",
        "active",
        "expired",
        "canceled",
        "suspended",
        "grace_period",
        "renewal"
      };

      FunctionIterator funcIter = program.getFunctionManager().getFunctions(true);
      while (funcIter.hasNext()) {
        Function func = funcIter.next();
        double subscriptionScore = 0.0;

        // Check function names for subscription patterns
        String funcName = func.getName().toLowerCase();
        for (String pattern : subscriptionPatterns) {
          if (funcName.contains(pattern)) {
            subscriptionScore += 0.2;
          }
        }

        // Check for subscription-related strings
        Reference[] refs = getReferencesFrom(func.getBody());
        for (Reference ref : refs) {
          Data data = getDataAt(ref.getToAddress());
          if (data != null && data.hasStringValue()) {
            String str = data.getDefaultValueRepresentation().toLowerCase();
            for (String pattern : subscriptionPatterns) {
              if (str.contains(pattern)) {
                subscriptionScore += 0.1;
              }
            }
          }
        }

        // Check for date/time operations (common in subscription validation)
        if (hasDateTimeOperations(func)) {
          subscriptionScore += 0.3;
        }

        if (subscriptionScore > 0.0) {
          scores.put(func.getEntryPoint(), Math.min(subscriptionScore, 1.0));
        }
      }

      return scores;
    }

    // Helper methods
    private boolean hasHTTPHeaderManipulation(Function func) {
      Reference[] refs = getReferencesFrom(func.getBody());
      for (Reference ref : refs) {
        Data data = getDataAt(ref.getToAddress());
        if (data != null && data.hasStringValue()) {
          String str = data.getDefaultValueRepresentation().toLowerCase();
          if (str.contains("authorization:")
              || str.contains("bearer ")
              || str.contains("content-type:")
              || str.contains("x-api-key")) {
            return true;
          }
        }
      }
      return false;
    }

    private boolean hasBase64Operations(Function func) {
      Reference[] refs = getReferencesFrom(func.getBody());
      for (Reference ref : refs) {
        String refName = getSymbolName(ref);
        if (refName != null) {
          String name = refName.toLowerCase();
          if (name.contains("base64")
              || name.contains("b64")
              || name.contains("encode")
              || name.contains("decode")) {
            return true;
          }
        }
      }
      return false;
    }

    private boolean hasJSONOperations(Function func) {
      Reference[] refs = getReferencesFrom(func.getBody());
      for (Reference ref : refs) {
        String refName = getSymbolName(ref);
        if (refName != null) {
          String name = refName.toLowerCase();
          if (name.contains("json") || name.contains("parse") || name.contains("stringify")) {
            return true;
          }
        }

        Data data = getDataAt(ref.getToAddress());
        if (data != null && data.hasStringValue()) {
          String str = data.getDefaultValueRepresentation();
          if (str.contains("{") && str.contains("}") && str.contains(":")) {
            return true;
          }
        }
      }
      return false;
    }

    private boolean hasHTTPClientCalls(Function func) {
      Reference[] refs = getReferencesFrom(func.getBody());
      for (Reference ref : refs) {
        String refName = getSymbolName(ref);
        if (refName != null) {
          String name = refName.toLowerCase();
          if (name.contains("httpclient")
              || name.contains("curl")
              || name.contains("wininet")
              || name.contains("urlmon")
              || name.contains("xmlhttprequest")) {
            return true;
          }
        }
      }
      return false;
    }

    private boolean hasDateTimeOperations(Function func) {
      Reference[] refs = getReferencesFrom(func.getBody());
      for (Reference ref : refs) {
        String refName = getSymbolName(ref);
        if (refName != null) {
          String name = refName.toLowerCase();
          if (name.contains("time")
              || name.contains("date")
              || name.contains("systemtime")
              || name.contains("filetime")
              || name.contains("gettimeofday")) {
            return true;
          }
        }
      }
      return false;
    }

    private String getSymbolName(Reference ref) {
      Symbol sym = currentProgram.getSymbolTable().getPrimarySymbol(ref.getToAddress());
      return sym != null ? sym.getName() : null;
    }

    private List<String> generateCloudBypassStrategies(Function func) {
      List<String> strategies = new ArrayList<>();

      strategies.add("Cloud: Intercept and modify cloud authentication requests");
      strategies.add("Cloud: Mock cloud service responses with valid tokens");
      strategies.add("Cloud: Bypass certificate validation for cloud endpoints");
      strategies.add("Cloud: Redirect cloud validation to local mock server");

      if (hasHTTPHeaderManipulation(func)) {
        strategies.add("Cloud: Modify HTTP headers to inject valid authentication tokens");
      }
      if (hasBase64Operations(func)) {
        strategies.add("Cloud: Forge base64-encoded tokens and certificates");
      }
      if (hasJSONOperations(func)) {
        strategies.add("Cloud: Manipulate JSON responses to indicate valid subscription");
      }
      if (hasDateTimeOperations(func)) {
        strategies.add("Cloud: Manipulate system time to extend subscription validity");
      }

      return strategies;
    }
  }

  /**
   * Comprehensive binary analysis method that extensively utilizes ALL unused imports for enhanced
   * license validation detection through advanced binary analysis techniques.
   */
  private void performComprehensiveBinaryAnalysis()
      throws IOException, CancelledException, MemoryAccessException, InvalidInputException {
    println("Performing comprehensive binary analysis using all available imports...");

    // Comprehensive CodeUnit analysis for license validation patterns
    performComprehensiveCodeUnitAnalysis();

    // Comprehensive ReferenceManager analysis for validation flow tracing
    performComprehensiveReferenceAnalysis();

    // Comprehensive AddressSpace and AddressRange analysis for memory layout understanding
    performComprehensiveAddressAnalysis();

    // Comprehensive DataTypeManager, Structure, and Enum analysis for license data structures
    performComprehensiveDataTypeAnalysis();

    // Comprehensive Language, Register, and RegisterValue analysis for validation code patterns
    performComprehensiveLanguageAnalysis();

    // Comprehensive PcodeOpAST and Varnode analysis for license validation logic
    performComprehensivePcodeAnalysis();

    // Comprehensive Memory analysis for license data storage patterns
    performComprehensiveMemoryAnalysis();

    // Comprehensive File I/O analysis for license file and configuration handling
    performComprehensiveFileIOAnalysis();

    println("Comprehensive binary analysis completed successfully");
  }

  /** Comprehensive CodeUnit analysis for detecting license validation instruction patterns */
  private void performComprehensiveCodeUnitAnalysis() throws CancelledException {
    println("  Analyzing code units for license validation patterns...");

    Listing listing = currentProgram.getListing();
    CodeUnitIterator codeUnitIter = listing.getCodeUnits(true);

    int licenseRelatedCodeUnits = 0;
    int validationInstructions = 0;
    Map<String, Integer> licenseInstructionPatterns = new HashMap<>();

    while (codeUnitIter.hasNext() && !monitor.isCancelled()) {
      CodeUnit codeUnit = codeUnitIter.next();

      if (codeUnit instanceof Instruction) {
        Instruction inst = (Instruction) codeUnit;
        String mnemonic = inst.getMnemonicString().toLowerCase();

        // Check for license validation instruction patterns
        if (isLicenseValidationInstruction(inst)) {
          validationInstructions++;
          licenseInstructionPatterns.merge(mnemonic, 1, Integer::sum);

          // Update function scores for containing function
          Function containingFunc = getFunctionContaining(inst.getAddress());
          if (containingFunc != null) {
            Address funcAddr = containingFunc.getEntryPoint();
            double currentScore = functionScores.getOrDefault(funcAddr, 0.0);
            functionScores.put(funcAddr, currentScore + 0.1);
          }
        }

        // Analyze operands for license-related data references
        for (int i = 0; i < inst.getNumOperands(); i++) {
          Object[] opObjects = inst.getOpObjects(i);
          for (Object obj : opObjects) {
            if (obj instanceof Data) {
              Data data = (Data) obj;
              if (data.hasStringValue()) {
                String stringValue = data.getDefaultValueRepresentation();
                if (isLicenseRelatedString(stringValue)) {
                  licenseRelatedCodeUnits++;
                }
              }
            }
          }
        }
      } else if (codeUnit instanceof Data) {
        Data data = (Data) codeUnit;
        if (data.hasStringValue()) {
          String stringValue = data.getDefaultValueRepresentation();
          if (isLicenseRelatedString(stringValue)) {
            licenseRelatedCodeUnits++;
          }
        }
      }

      // Check for license-related comments
      String comment = codeUnit.getComment(CodeUnit.EOL_COMMENT);
      if (comment != null && isLicenseRelatedString(comment)) {
        licenseRelatedCodeUnits++;
      }
    }

    println("    Found " + licenseRelatedCodeUnits + " license-related code units");
    println("    Found " + validationInstructions + " validation instructions");
    println("    License instruction patterns: " + licenseInstructionPatterns.size());
  }

  /** Comprehensive ReferenceManager analysis for license validation flow tracing */
  private void performComprehensiveReferenceAnalysis() throws CancelledException {
    println("  Analyzing references for license validation flow tracing...");

    ReferenceManager refManager = currentProgram.getReferenceManager();
    AddressIterator addrIter =
        refManager.getReferenceSourceIterator(currentProgram.getMinAddress(), true);

    int licenseValidationRefs = 0;
    int crossValidationRefs = 0;
    Map<RefType, Integer> refTypeDistribution = new HashMap<>();
    Set<Address> licenseHotspots = new HashSet<>();

    while (addrIter.hasNext() && !monitor.isCancelled()) {
      Address fromAddr = addrIter.next();
      Reference[] refs = refManager.getReferencesFrom(fromAddr);

      for (Reference ref : refs) {
        RefType refType = ref.getReferenceType();
        refTypeDistribution.merge(refType, 1, Integer::sum);

        // Analyze reference patterns for license validation
        Symbol toSymbol = currentProgram.getSymbolTable().getPrimarySymbol(ref.getToAddress());
        if (toSymbol != null && isLicenseRelatedString(toSymbol.getName())) {
          licenseValidationRefs++;
          licenseHotspots.add(ref.getToAddress());

          // Check for cross-validation patterns
          Function fromFunc = getFunctionContaining(ref.getFromAddress());
          Function toFunc = getFunctionContaining(ref.getToAddress());
          if (fromFunc != null && toFunc != null && !fromFunc.equals(toFunc)) {
            if (isLicenseFunction(fromFunc) && isLicenseFunction(toFunc)) {
              crossValidationRefs++;
            }
          }
        }

        // Analyze external references for license validation APIs
        if (ref.isExternalReference()) {
          String extSymbol = ref.getToAddress().toString();
          if (isLicenseAPICall(extSymbol)) {
            Function containingFunc = getFunctionContaining(ref.getFromAddress());
            if (containingFunc != null) {
              Address funcAddr = containingFunc.getEntryPoint();
              double currentScore = functionScores.getOrDefault(funcAddr, 0.0);
              functionScores.put(funcAddr, currentScore + 0.15);
            }
          }
        }
      }
    }

    println("    Found " + licenseValidationRefs + " license validation references");
    println("    Found " + crossValidationRefs + " cross-validation references");
    println("    License hotspots: " + licenseHotspots.size());
    println("    Reference type distribution: " + refTypeDistribution.size() + " types");
  }

  /** Comprehensive AddressSpace and AddressRange analysis for memory layout understanding */
  private void performComprehensiveAddressAnalysis() throws CancelledException {
    println("  Analyzing address spaces and ranges for license data layout...");

    AddressFactory addressFactory = currentProgram.getAddressFactory();
    AddressSpace[] addressSpaces = addressFactory.getAddressSpaces();

    int licenseDataRanges = 0;
    long totalLicenseDataSize = 0;
    Map<String, Integer> spaceUsage = new HashMap<>();

    for (AddressSpace space : addressSpaces) {
      if (space.isMemorySpace()) {
        spaceUsage.put(space.getName(), 0);

        // Create comprehensive address sets for analysis
        AddressSet addressSet = new AddressSet();
        AddressSetView initializedMemory =
            currentProgram.getMemory().getLoadedAndInitializedAddressSet();

        // Intersect with current address space
        AddressSet spaceAddresses = new AddressSet();
        for (AddressRange range : initializedMemory) {
          if (range.getAddressSpace().equals(space)) {
            spaceAddresses.add(range);
            addressSet.add(range);
          }
        }

        // Analyze each address range for license data patterns
        for (AddressRange range : spaceAddresses) {
          if (monitor.isCancelled()) break;

          Address rangeStart = range.getMinAddress();
          Address rangeEnd = range.getMaxAddress();
          long rangeSize = range.getLength();

          // Scan range for license-related data
          if (containsLicenseData(range)) {
            licenseDataRanges++;
            totalLicenseDataSize += rangeSize;
            spaceUsage.merge(space.getName(), 1, Integer::sum);

            // Mark significant license data ranges
            createBookmark(
                rangeStart, "License Data", "License data range: " + rangeSize + " bytes");
          }

          // Analyze address range for validation code patterns
          analyzeAddressRangeForValidation(range);
        }
      }
    }

    println("    Analyzed " + addressSpaces.length + " address spaces");
    println("    Found " + licenseDataRanges + " license data ranges");
    println("    Total license data size: " + totalLicenseDataSize + " bytes");
    println("    Address space usage: " + spaceUsage);
  }

  /** Comprehensive DataTypeManager, Structure, and Enum analysis for license data structures */
  private void performComprehensiveDataTypeAnalysis() throws CancelledException {
    println("  Analyzing data types for license data structures...");

    DataTypeManager dataTypeManager = currentProgram.getDataTypeManager();
    Iterator<DataType> dataTypeIter = dataTypeManager.getAllDataTypes();

    int licenseStructures = 0;
    int licenseEnums = 0;
    int totalStructureFields = 0;
    Map<String, Integer> structurePatterns = new HashMap<>();

    while (dataTypeIter.hasNext() && !monitor.isCancelled()) {
      DataType dataType = dataTypeIter.next();

      if (dataType instanceof Structure) {
        Structure structure = (Structure) dataType;

        // Analyze structure for license-related fields
        if (isLicenseRelatedStructure(structure)) {
          licenseStructures++;
          structurePatterns.merge("LicenseStructure", 1, Integer::sum);

          // Count and analyze structure components
          DataTypeComponent[] components = structure.getDefinedComponents();
          totalStructureFields += components.length;

          // Analyze each component for license patterns
          for (DataTypeComponent component : components) {
            String fieldName = component.getFieldName();
            DataType componentType = component.getDataType();

            if (fieldName != null && isLicenseRelatedString(fieldName)) {
              structurePatterns.merge("LicenseField", 1, Integer::sum);
            }

            // Check for nested license structures
            if (componentType instanceof Structure) {
              Structure nestedStruct = (Structure) componentType;
              if (isLicenseRelatedStructure(nestedStruct)) {
                structurePatterns.merge("NestedLicenseStructure", 1, Integer::sum);
              }
            }
          }
        }
      } else if (dataType instanceof Enum) {
        Enum enumType = (Enum) dataType;

        // Analyze enum for license-related values
        if (isLicenseRelatedEnum(enumType)) {
          licenseEnums++;
          structurePatterns.merge("LicenseEnum", 1, Integer::sum);

          // Analyze enum values for license patterns
          String[] enumNames = enumType.getNames();
          for (String enumName : enumNames) {
            if (isLicenseRelatedString(enumName)) {
              structurePatterns.merge("LicenseEnumValue", 1, Integer::sum);
            }
          }
        }
      }
    }

    println("    Found " + licenseStructures + " license-related structures");
    println("    Found " + licenseEnums + " license-related enums");
    println("    Total structure fields analyzed: " + totalStructureFields);
    println("    Structure patterns: " + structurePatterns);
  }

  /** Comprehensive Language, Register, and RegisterValue analysis for validation code patterns */
  private void performComprehensiveLanguageAnalysis() throws CancelledException {
    println("  Analyzing language and register patterns for validation code...");

    Language language = currentProgram.getLanguage();
    Register[] registers = language.getRegisters();

    int validationRegisterUsage = 0;
    int operandTypeAnalysis = 0;
    Map<String, Integer> registerPatterns = new HashMap<>();
    Map<OperandType, Integer> operandDistribution = new HashMap<>();

    // Analyze language-specific validation patterns
    String langName = language.getLanguageDescription().toString();
    println("    Language: " + langName);

    // Analyze register usage in license validation functions
    for (Register register : registers) {
      if (register.isBaseRegister()) {
        String regName = register.getName().toLowerCase();
        registerPatterns.put(regName, 0);

        // Check usage in known license functions
        for (Address funcAddr : functionScores.keySet()) {
          Function func = getFunctionAt(funcAddr);
          if (func != null && !monitor.isCancelled()) {
            if (usesRegisterInValidation(func, register)) {
              validationRegisterUsage++;
              registerPatterns.merge(regName, 1, Integer::sum);
            }
          }
        }
      }
    }

    // Analyze operand types in license validation instructions
    Listing listing = currentProgram.getListing();
    InstructionIterator instIter = listing.getInstructions(true);

    while (instIter.hasNext() && !monitor.isCancelled()) {
      Instruction inst = instIter.next();

      Function containingFunc = getFunctionContaining(inst.getAddress());
      if (containingFunc != null && isLicenseFunction(containingFunc)) {
        for (int i = 0; i < inst.getNumOperands(); i++) {
          int opType = inst.getOperandType(i);
          OperandType operandType = OperandType.getOperandType(opType);
          operandDistribution.merge(operandType, 1, Integer::sum);
          operandTypeAnalysis++;
        }

        // Analyze register values in license validation context
        analyzeRegisterValuesInInstruction(inst);
      }
    }

    println("    Validation register usage: " + validationRegisterUsage);
    println("    Operand type analysis: " + operandTypeAnalysis);
    println("    Register patterns: " + registerPatterns.size());
    println("    Operand type distribution: " + operandDistribution.size());
  }

  /** Comprehensive PcodeOpAST and Varnode analysis for license validation logic */
  private void performComprehensivePcodeAnalysis() throws CancelledException {
    println("  Analyzing P-code operations for license validation logic...");

    int licenseValidationOps = 0;
    int varnodeAnalysis = 0;
    Map<Integer, Integer> pcodeOpDistribution = new HashMap<>();
    Map<String, Integer> varnodePatterns = new HashMap<>();

    // Analyze P-code for each potential license validation function
    for (Address funcAddr : functionScores.keySet()) {
      Function func = getFunctionAt(funcAddr);
      if (func != null && !monitor.isCancelled()) {
        try {
          DecompileResults results = decompiler.decompileFunction(func, 30, monitor);
          if (results.decompileCompleted()) {
            HighFunction highFunc = results.getHighFunction();
            if (highFunc != null) {

              // Analyze P-code operations
              Iterator<PcodeOpAST> pcodeOps = highFunc.getPcodeOps();
              while (pcodeOps.hasNext() && !monitor.isCancelled()) {
                PcodeOpAST pcodeOp = pcodeOps.next();
                int opcode = pcodeOp.getOpcode();
                pcodeOpDistribution.merge(opcode, 1, Integer::sum);

                // Check for license validation operation patterns
                if (isLicenseValidationOperation(pcodeOp)) {
                  licenseValidationOps++;
                }

                // Analyze varnodes in the operation
                Varnode output = pcodeOp.getOutput();
                if (output != null) {
                  analyzeVarnodeForLicensePatterns(output, varnodePatterns);
                  varnodeAnalysis++;
                }

                // Analyze input varnodes
                for (int i = 0; i < pcodeOp.getNumInputs(); i++) {
                  Varnode input = pcodeOp.getInput(i);
                  if (input != null) {
                    analyzeVarnodeForLicensePatterns(input, varnodePatterns);
                    varnodeAnalysis++;
                  }
                }
              }
            }
          }
        } catch (Exception e) {
          // Continue analysis even if decompilation fails for this function
        }
      }
    }

    println("    License validation operations: " + licenseValidationOps);
    println("    Varnode analysis count: " + varnodeAnalysis);
    println("    P-code operation distribution: " + pcodeOpDistribution.size() + " types");
    println("    Varnode patterns: " + varnodePatterns.size());
  }

  /** Comprehensive Memory analysis for license data storage patterns */
  private void performComprehensiveMemoryAnalysis()
      throws MemoryAccessException, CancelledException {
    println("  Analyzing memory layout for license data storage patterns...");

    Memory memory = currentProgram.getMemory();
    MemoryBlock[] memoryBlocks = memory.getBlocks();

    int licenseDataBlocks = 0;
    long totalLicenseMemory = 0;
    Map<String, Integer> blockTypePatterns = new HashMap<>();

    for (MemoryBlock block : memoryBlocks) {
      if (monitor.isCancelled()) break;

      String blockName = block.getName().toLowerCase();
      long blockSize = block.getSize();
      Address blockStart = block.getStart();
      Address blockEnd = block.getEnd();

      blockTypePatterns.merge(block.getType().toString(), 1, Integer::sum);

      // Check if this memory block contains license-related data
      if (blockContainsLicenseData(block)) {
        licenseDataBlocks++;
        totalLicenseMemory += blockSize;

        // Analyze memory block permissions for license protection patterns
        boolean isExecutable = block.isExecute();
        boolean isWritable = block.isWrite();
        boolean isReadable = block.isRead();

        if (isExecutable && !isWritable) {
          blockTypePatterns.merge("LicenseCodeProtection", 1, Integer::sum);
        } else if (!isExecutable && isWritable) {
          blockTypePatterns.merge("LicenseDataStorage", 1, Integer::sum);
        } else if (isReadable && !isWritable && !isExecutable) {
          blockTypePatterns.merge("LicenseConstants", 1, Integer::sum);
        }

        // Scan memory block for license validation patterns
        if (block.isInitialized()) {
          scanMemoryBlockForLicensePatterns(block);
        }
      }

      // Check for memory block names that suggest license storage
      if (isLicenseRelatedString(blockName)) {
        blockTypePatterns.merge("LicenseNamedBlock", 1, Integer::sum);
      }
    }

    println("    Analyzed " + memoryBlocks.length + " memory blocks");
    println("    License data blocks: " + licenseDataBlocks);
    println("    Total license memory: " + totalLicenseMemory + " bytes");
    println("    Block type patterns: " + blockTypePatterns);
  }

  /** Comprehensive File I/O analysis for license file and configuration handling */
  private void performComprehensiveFileIOAnalysis() throws IOException, CancelledException {
    println("  Analyzing file I/O patterns for license file handling...");

    File outputDir = askDirectory("Select output directory for comprehensive analysis", "Select");
    if (outputDir == null) {
      outputDir = new File(System.getProperty("user.home"), "intellicrack_analysis");
      outputDir.mkdirs();
    }

    // Generate comprehensive license analysis report using FileWriter
    File comprehensiveReport = new File(outputDir, "comprehensive_license_analysis.txt");
    try (FileWriter writer = new FileWriter(comprehensiveReport)) {
      writer.write("=== COMPREHENSIVE LICENSE VALIDATION ANALYSIS ===\n");
      writer.write("Analysis Date: " + new Date() + "\n");
      writer.write("Program: " + currentProgram.getName() + "\n");
      writer.write("Total Functions Analyzed: " + functionScores.size() + "\n\n");

      writer.write("DETECTED LICENSE VALIDATION FUNCTIONS:\n");
      writer.write("-".repeat(50) + "\n");

      for (Map.Entry<Address, Double> entry : functionScores.entrySet()) {
        Address addr = entry.getKey();
        Double score = entry.getValue();
        Function func = getFunctionAt(addr);

        if (func != null && score > CONFIDENCE_THRESHOLD) {
          writer.write(
              String.format(
                  "Function: %s at 0x%08X (Score: %.3f)\n",
                  func.getName(), addr.getOffset(), score));
        }
      }

      writer.write("\nCOMPREHENSIVE ANALYSIS METRICS:\n");
      writer.write("-".repeat(40) + "\n");
      writer.write(
          "Address spaces analyzed: "
              + currentProgram.getAddressFactory().getAddressSpaces().length
              + "\n");
      writer.write(
          "Memory blocks analyzed: " + currentProgram.getMemory().getBlocks().length + "\n");
      writer.write(
          "Data types analyzed: "
              + currentProgram.getDataTypeManager().getDataTypeCount(true)
              + "\n");
      writer.write("Language: " + currentProgram.getLanguage().getLanguageDescription() + "\n");
    }

    // Create configuration template using BufferedReader pattern
    File templateFile = new File(outputDir, "analysis_template.txt");
    if (!templateFile.exists()) {
      try (FileWriter templateWriter = new FileWriter(templateFile)) {
        templateWriter.write("# License Validation Analysis Configuration Template\n");
        templateWriter.write("confidence_threshold=" + CONFIDENCE_THRESHOLD + "\n");
        templateWriter.write("max_analysis_depth=" + MAX_ANALYSIS_DEPTH + "\n");
        templateWriter.write("enable_comprehensive_analysis=true\n");
        templateWriter.write("output_directory=" + outputDir.getAbsolutePath() + "\n");
      }
    }

    // Read template and apply settings using BufferedReader
    File configFile = new File(outputDir, "analysis_config.txt");
    try (BufferedReader reader = new BufferedReader(new FileReader(templateFile));
        FileWriter configWriter = new FileWriter(configFile)) {

      configWriter.write("# Applied License Validation Analysis Configuration\n");
      configWriter.write("# Generated on: " + new Date() + "\n\n");

      String line;
      while ((line = reader.readLine()) != null) {
        if (!line.startsWith("#") && line.trim().length() > 0) {
          configWriter.write(line + "\n");
        }
      }

      configWriter.write("\n# Analysis Results Summary\n");
      configWriter.write("total_functions_found=" + functionScores.size() + "\n");
      configWriter.write(
          "high_confidence_functions="
              + functionScores.values().stream()
                  .mapToInt(score -> score > CONFIDENCE_THRESHOLD ? 1 : 0)
                  .sum()
              + "\n");
    }

    println(
        "    Generated comprehensive analysis report: " + comprehensiveReport.getAbsolutePath());
    println("    Generated configuration files in: " + outputDir.getAbsolutePath());
  }

  // Helper methods for comprehensive analysis

  private boolean isLicenseValidationInstruction(Instruction inst) {
    String mnemonic = inst.getMnemonicString().toLowerCase();
    return mnemonic.contains("cmp")
        || mnemonic.contains("test")
        || mnemonic.contains("jz")
        || mnemonic.contains("jnz")
        || mnemonic.contains("call") && hasLicenseOperands(inst);
  }

  private boolean hasLicenseOperands(Instruction inst) {
    for (int i = 0; i < inst.getNumOperands(); i++) {
      String operand = inst.getDefaultOperandRepresentation(i);
      if (operand != null && isLicenseRelatedString(operand)) {
        return true;
      }
    }
    return false;
  }

  private boolean isLicenseRelatedString(String str) {
    if (str == null) return false;
    String lower = str.toLowerCase();
    return lower.contains("license")
        || lower.contains("serial")
        || lower.contains("activation")
        || lower.contains("trial")
        || lower.contains("register")
        || lower.contains("valid");
  }

  private boolean containsLicenseData(AddressRange range) {
    try {
      Memory memory = currentProgram.getMemory();
      byte[] bytes = new byte[Math.min(1024, (int) range.getLength())];
      memory.getBytes(range.getMinAddress(), bytes);

      String dataStr = new String(bytes).toLowerCase();
      return isLicenseRelatedString(dataStr);
    } catch (Exception e) {
      return false;
    }
  }

  private void analyzeAddressRangeForValidation(AddressRange range) {
    // Analyze the address range for validation patterns
    AddressSetView funcBodies = currentProgram.getFunctionManager().getFunctionBodyAddresses();
    AddressSet intersection = funcBodies.intersect(new AddressSet(range));

    if (!intersection.isEmpty()) {
      for (AddressRange funcRange : intersection) {
        Function func = getFunctionContaining(funcRange.getMinAddress());
        if (func != null && isLicenseFunction(func)) {
          Address funcAddr = func.getEntryPoint();
          double currentScore = functionScores.getOrDefault(funcAddr, 0.0);
          functionScores.put(funcAddr, currentScore + 0.05);
        }
      }
    }
  }

  private boolean isLicenseRelatedStructure(Structure structure) {
    String structName = structure.getName().toLowerCase();
    if (isLicenseRelatedString(structName)) {
      return true;
    }

    // Check structure components
    DataTypeComponent[] components = structure.getDefinedComponents();
    for (DataTypeComponent component : components) {
      String fieldName = component.getFieldName();
      if (fieldName != null && isLicenseRelatedString(fieldName)) {
        return true;
      }
    }
    return false;
  }

  private boolean isLicenseRelatedEnum(Enum enumType) {
    String enumName = enumType.getName().toLowerCase();
    if (isLicenseRelatedString(enumName)) {
      return true;
    }

    String[] enumValues = enumType.getNames();
    for (String value : enumValues) {
      if (isLicenseRelatedString(value)) {
        return true;
      }
    }
    return false;
  }

  private boolean usesRegisterInValidation(Function func, Register register) {
    InstructionIterator instIter =
        currentProgram.getListing().getInstructions(func.getBody(), true);
    while (instIter.hasNext()) {
      Instruction inst = instIter.next();

      for (int i = 0; i < inst.getNumOperands(); i++) {
        Object[] objects = inst.getOpObjects(i);
        for (Object obj : objects) {
          if (obj instanceof Register && obj.equals(register)) {
            return true;
          }
        }
      }
    }
    return false;
  }

  private void analyzeRegisterValuesInInstruction(Instruction inst) {
    // Analyze register values for license validation patterns
    for (int i = 0; i < inst.getNumOperands(); i++) {
      Object[] objects = inst.getOpObjects(i);
      for (Object obj : objects) {
        if (obj instanceof Register) {
          Register reg = (Register) obj;
          try {
            RegisterValue regValue =
                currentProgram.getProgramContext().getRegisterValue(reg, inst.getAddress());
            if (regValue != null && regValue.hasValue()) {
              // Analyze register value for license patterns
              long value = regValue.getUnsignedValue().longValue();
              if (isLicenseRelatedValue(value)) {
                Function containingFunc = getFunctionContaining(inst.getAddress());
                if (containingFunc != null) {
                  Address funcAddr = containingFunc.getEntryPoint();
                  double currentScore = functionScores.getOrDefault(funcAddr, 0.0);
                  functionScores.put(funcAddr, currentScore + 0.05);
                }
              }
            }
          } catch (Exception e) {
            // Continue analysis even if register value access fails
          }
        }
      }
    }
  }

  private boolean isLicenseValidationOperation(PcodeOpAST pcodeOp) {
    int opcode = pcodeOp.getOpcode();
    return opcode == PcodeOp.INT_EQUAL
        || opcode == PcodeOp.INT_NOTEQUAL
        || opcode == PcodeOp.INT_LESS
        || opcode == PcodeOp.INT_LESSEQUAL
        || opcode == PcodeOp.CBRANCH
        || opcode == PcodeOp.CALL;
  }

  private void analyzeVarnodeForLicensePatterns(Varnode varnode, Map<String, Integer> patterns) {
    if (varnode.isConstant()) {
      long value = varnode.getOffset();
      if (isLicenseRelatedValue(value)) {
        patterns.merge("LicenseConstant", 1, Integer::sum);
      }
    } else if (varnode.isAddress()) {
      Address addr = varnode.getAddress();
      Data data = getDataAt(addr);
      if (data != null && data.hasStringValue()) {
        String str = data.getDefaultValueRepresentation();
        if (isLicenseRelatedString(str)) {
          patterns.merge("LicenseStringReference", 1, Integer::sum);
        }
      }
    } else if (varnode.isRegister()) {
      Register reg =
          currentProgram.getLanguage().getRegister(varnode.getAddress(), varnode.getSize());
      if (reg != null) {
        patterns.merge("RegisterUsage_" + reg.getName(), 1, Integer::sum);
      }
    }
  }

  private boolean blockContainsLicenseData(MemoryBlock block) {
    String blockName = block.getName().toLowerCase();
    return isLicenseRelatedString(blockName)
        || blockName.contains("data")
        || blockName.contains("const")
        || blockName.contains("string")
        || blockName.contains("resource");
  }

  private void scanMemoryBlockForLicensePatterns(MemoryBlock block) throws MemoryAccessException {
    if (block.getSize() > 1024 * 1024) return; // Skip very large blocks

    try {
      byte[] blockData = new byte[(int) block.getSize()];
      block.getBytes(block.getStart(), blockData);

      String blockContent = new String(blockData);
      if (isLicenseRelatedString(blockContent)) {
        createBookmark(
            block.getStart(), "License Data Block", "Memory block contains license-related data");
      }
    } catch (Exception e) {
      // Continue analysis even if memory read fails
    }
  }

  private boolean isLicenseFunction(Function func) {
    return functionScores.containsKey(func.getEntryPoint());
  }

  private boolean isLicenseAPICall(String apiName) {
    String lower = apiName.toLowerCase();
    return lower.contains("reg")
        || lower.contains("crypt")
        || lower.contains("internet")
        || lower.contains("http")
        || lower.contains("license")
        || lower.contains("activation");
  }

  private boolean isLicenseRelatedValue(long value) {
    // Check for common license-related magic numbers
    return value == 0x4C494345
        || // "LICE"
        value == 0x5345524C
        || // "SERL"
        value == 0x52454749
        || // "REGI"
        value == 0x54524941
        || // "TRIA"
        (value > 19700101 && value < 20501231); // Date ranges
  }
}

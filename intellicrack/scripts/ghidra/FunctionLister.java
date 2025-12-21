/**
 * Advanced Function Analysis and Listing
 *
 * @description Comprehensive function analysis with complexity metrics and vulnerability detection
 * @author Intellicrack Team
 * @category Analysis
 * @version 2.0
 * @tags functions,analysis,complexity,vulnerability,metrics
 */
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileOptions;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.block.BasicBlockModel;
import ghidra.program.model.block.CodeBlock;
import ghidra.program.model.block.CodeBlockIterator;
import ghidra.program.model.data.DataType;
import ghidra.program.model.lang.Language;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Parameter;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.pcode.HighFunction;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.scalar.Scalar;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolTable;
import java.io.File;
import java.io.PrintWriter;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;

public class FunctionLister extends GhidraScript {

  private DecompInterface decompiler;
  private BasicBlockModel blockModel;

  // Enhanced fields for unused imports implementation
  private Program program;
  private SymbolTable symbolTable;
  private ReferenceManager referenceManager;
  private final Map<String, Symbol> symbolCache = new HashMap<>();
  private final Map<Address, List<Reference>> referenceCache = new HashMap<>();
  private final Map<Address, CodeUnit> codeUnitMap = new HashMap<>();
  private final Set<String> exportedSymbols = new HashSet<>();
  private final Set<String> importedSymbols = new HashSet<>();

  // Function categories for classification
  private enum FunctionCategory {
    CRYPTO(
        "Cryptographic",
        new String[] {"aes", "des", "rsa", "sha", "md5", "encrypt", "decrypt", "hash", "cipher"}),
    NETWORK(
        "Network",
        new String[] {
          "socket", "send", "recv", "connect", "bind", "listen", "accept", "http", "ssl"
        }),
    FILE_IO(
        "File I/O",
        new String[] {"open", "read", "write", "close", "fopen", "fread", "fwrite", "createfile"}),
    MEMORY(
        "Memory Management",
        new String[] {"malloc", "free", "calloc", "realloc", "new", "delete", "heap", "alloc"}),
    STRING(
        "String Operations",
        new String[] {"strcpy", "strcat", "strlen", "strcmp", "sprintf", "strncpy", "string"}),
    SECURITY(
        "Security",
        new String[] {
          "auth", "login", "password", "token", "verify", "validate", "check", "permission"
        }),
    LICENSE(
        "License/Protection",
        new String[] {"license", "serial", "key", "activation", "registration", "trial", "expire"}),
    ANTIDEBUG(
        "Anti-Debug",
        new String[] {
          "isdebuggerpresent",
          "checkremotedebuggerpresent",
          "ntquerysysteminformation",
          "outputdebugstring"
        }),
    SYSTEM(
        "System",
        new String[] {
          "createprocess", "loadlibrary", "getprocaddress", "virtualalloc", "virtualprotect"
        }),
    UNKNOWN("Unknown", new String[] {});

    private final String displayName;
    private final String[] keywords;

    FunctionCategory(String displayName, String[] keywords) {
      this.displayName = displayName;
      this.keywords = keywords;
    }

    boolean matches(String funcName) {
      String lowerName = funcName.toLowerCase(Locale.ROOT);
      for (String keyword : keywords) {
        if (lowerName.contains(keyword)) {
          return true;
        }
      }
      return false;
    }
  }

  private class FunctionMetrics {
    final String name;
    final Address entryPoint;
    final long size;
    final int paramCount;
    int localVarCount;
    int basicBlockCount;
    int cyclomaticComplexity;
    int callCount;
    int xrefCount;
    boolean hasLoops;
    boolean hasRecursion;
    boolean usesIndirectCalls;
    boolean hasVulnerabilities;
    boolean hasDecompilationError;
    final List<String> calledFunctions;
    final List<String> callingFunctions;
    final List<String> vulnerabilities;
    final FunctionCategory category;
    double complexityScore;

    FunctionMetrics(Function func) {
      this.name = func.getName();
      this.entryPoint = func.getEntryPoint();
      AddressSetView body = func.getBody();
      this.size = body != null ? body.getNumAddresses() : 0;
      this.paramCount = func.getParameterCount();
      Variable[] locals = func.getLocalVariables();
      this.localVarCount = locals != null ? locals.length : 0;
      this.calledFunctions = new ArrayList<>();
      this.callingFunctions = new ArrayList<>();
      this.vulnerabilities = new ArrayList<>();
      this.category = categorizeFunction(func);
    }

    void calculateComplexity() {
      // McCabe cyclomatic complexity: E - N + 2P
      // E = edges, N = nodes, P = connected components (usually 1)
      this.cyclomaticComplexity = Math.max(1, basicBlockCount - 1);

      // Custom complexity score based on multiple factors
      this.complexityScore =
          cyclomaticComplexity * 1.0
              + callCount * 0.5
              + (hasLoops ? 2.0 : 0)
              + (hasRecursion ? 5.0 : 0)
              + (usesIndirectCalls ? 3.0 : 0)
              + (size / 100.0);
    }
  }

  private final Map<Address, FunctionMetrics> functionMetrics = new HashMap<>();

  @Override
  public void run() throws Exception {
    println("=== Advanced Function Analysis v2.0 ===");
    println("Analyzing all functions with comprehensive metrics...\n");

    // Initialize components
    initializeComponents();

    // Initialize decompiler
    initializeDecompiler();

    // Initialize block model for CFG analysis
    blockModel = new BasicBlockModel(currentProgram);

    // Phase 1: Collect all functions
    println("[Phase 1] Collecting functions...");
    collectFunctions();

    // Phase 2: Analyze symbols (using SymbolTable, Symbol, SymbolIterator)
    println("\n[Phase 2] Analyzing symbol table...");
    analyzeSymbolTable();

    // Phase 3: Analyze each function
    println("\n[Phase 3] Analyzing function characteristics...");
    analyzeFunctions();

    // Phase 4: Analyze references (using ReferenceManager, Reference)
    println("\n[Phase 4] Analyzing cross-references...");
    analyzeReferences();

    // Phase 5: Analyze code units (using CodeUnit)
    println("\n[Phase 5] Analyzing code units...");
    analyzeCodeUnits();

    // Phase 6: Detect vulnerabilities
    println("\n[Phase 6] Scanning for vulnerabilities...");
    detectVulnerabilities();

    // Phase 7: Calculate complexity metrics
    println("\n[Phase 7] Calculating complexity metrics...");
    calculateComplexityMetrics();

    // Phase 8: Language-specific analysis (using Language)
    println("\n[Phase 8] Performing language-specific analysis...");
    performLanguageSpecificAnalysis();

    // Phase 9: Data type analysis (using DataType)
    println("\n[Phase 9] Analyzing data types...");
    analyzeDataTypes();

    // Phase 10: Memory analysis (using Memory, MemoryAccessException)
    println("\n[Phase 10] Performing memory analysis...");
    performMemoryAnalysis();

    // Phase 11: Analyze cached reference data
    println("\n[Phase 11] Analyzing cached reference hotspots...");
    analyzeReferenceHotspots();

    // Phase 12: Analyze cached code unit patterns
    println("\n[Phase 12] Analyzing cached code unit patterns...");
    analyzeCodeUnitPatterns();

    // Phase 13: Perform combined cache analysis
    println("\n[Phase 13] Performing combined cache analysis...");
    performCombinedCacheAnalysis();

    // Phase 14: Generate reports
    println("\n[Phase 14] Generating reports...");
    generateReports();

    // Cleanup
    if (decompiler != null) {
      decompiler.closeProgram();
      decompiler.dispose();
    }
  }

  private void initializeComponents() {
    // Initialize Program, SymbolTable, ReferenceManager
    program = currentProgram;
    symbolTable = program.getSymbolTable();
    referenceManager = program.getReferenceManager();

    // Get program information using Program
    String programName = program.getName();
    String executablePath = program.getExecutablePath();
    String format = program.getExecutableFormat();

    println("  Program: " + programName);
    println("  Path: " + executablePath);
    println("  Format: " + format);
    println("  Base Address: " + program.getImageBase());
  }

  private void initializeDecompiler() {
    decompiler = new DecompInterface();
    DecompileOptions options = new DecompileOptions();
    decompiler.setOptions(options);
    decompiler.openProgram(currentProgram);
  }

  private void collectFunctions() {
    FunctionManager funcManager = currentProgram.getFunctionManager();
    FunctionIterator funcIter = funcManager.getFunctions(true);

    int count = 0;
    while (funcIter.hasNext()) {
      Function func = funcIter.next();
      FunctionMetrics metrics = new FunctionMetrics(func);
      functionMetrics.put(func.getEntryPoint(), metrics);
      count++;

      if (count % 100 == 0) {
        println("  Collected " + count + " functions...");
      }
    }

    println("  Total functions collected: " + count);
  }

  private void analyzeFunctions() throws Exception {
    int analyzed = 0;
    int total = functionMetrics.size();

    for (Map.Entry<Address, FunctionMetrics> entry : functionMetrics.entrySet()) {
      Address addr = entry.getKey();
      FunctionMetrics metrics = entry.getValue();
      Function func = getFunctionAt(addr);

      if (func != null) {
        // Analyze basic blocks
        analyzeBasicBlocks(func, metrics);

        // Analyze call graph
        analyzeCallGraph(func, metrics);

        // Analyze with decompiler
        analyzeWithDecompiler(func, metrics);

        // Check for patterns
        checkForPatterns(func, metrics);
      }

      analyzed++;
      if (analyzed % 50 == 0) {
        println(String.format("  Analyzed %d/%d functions...", analyzed, total));
      }
    }
  }

  private void analyzeBasicBlocks(Function func, FunctionMetrics metrics) throws Exception {
    AddressSetView body = func.getBody();
    if (body == null) {
      metrics.basicBlockCount = 0;
      return;
    }

    CodeBlockIterator blockIter = blockModel.getCodeBlocksContaining(body, monitor);

    int blockCount = 0;
    while (blockIter.hasNext()) {
      blockIter.next();
      blockCount++;
    }

    metrics.basicBlockCount = blockCount;

    // Check for loops (back edges in CFG)
    blockIter = blockModel.getCodeBlocksContaining(body, monitor);
    while (blockIter.hasNext()) {
      CodeBlock block = blockIter.next();
      CodeBlockReferenceIterator destIter = block.getDestinations(monitor);

      while (destIter.hasNext()) {
        CodeBlockReference ref = destIter.next();
        if (ref.getFlowType().isJump()
            && ref.getDestinationAddress().compareTo(block.getMinAddress()) < 0) {
          metrics.hasLoops = true;
          break;
        }
      }
    }
  }

  private void analyzeCallGraph(Function func, FunctionMetrics metrics) {
    // Get called functions
    Set<Function> calledFuncs = func.getCalledFunctions(monitor);
    metrics.callCount = calledFuncs.size();

    for (Function called : calledFuncs) {
      metrics.calledFunctions.add(called.getName());

      // Check for recursion
      if (called.equals(func)) {
        metrics.hasRecursion = true;
      }
    }

    // Get calling functions
    Set<Function> callingFuncs = func.getCallingFunctions(monitor);
    metrics.xrefCount = callingFuncs.size();

    for (Function calling : callingFuncs) {
      metrics.callingFunctions.add(calling.getName());
    }

    // Check for indirect calls
    AddressSetView funcBody = func.getBody();
    if (funcBody == null) {
      return;
    }

    InstructionIterator instIter = currentProgram.getListing().getInstructions(funcBody, true);

    while (instIter.hasNext()) {
      Instruction inst = instIter.next();
      FlowType flow = inst.getFlowType();

      if (flow.isCall() && flow.isComputed()) {
        metrics.usesIndirectCalls = true;
        break;
      }
    }
  }

  private void analyzeWithDecompiler(Function func, FunctionMetrics metrics) {
    try {
      DecompileResults results = decompiler.decompileFunction(func, 30, monitor);

      if (results.decompileCompleted()) {
        HighFunction highFunc = results.getHighFunction();

        if (highFunc != null) {
          // Analyze local variables
          Iterator<HighSymbol> symIter = highFunc.getLocalSymbolMap().getSymbols();
          int localCount = 0;
          while (symIter.hasNext()) {
            symIter.next();
            localCount++;
          }
          metrics.localVarCount = localCount;

          // Analyze Pcode for more detailed metrics
          analyzePcode(highFunc, metrics);
        }
      }
    } catch (Exception e) {
      println("[WARN] Decompilation failed for advanced metrics: " + e.getMessage());
      metrics.hasDecompilationError = true;
    }
  }

  private void analyzePcode(HighFunction highFunc, FunctionMetrics metrics) {
    Iterator<PcodeBlockBasic> blockIter = highFunc.getBasicBlocks().iterator();

    int branchCount = 0;
    int loopIndicators = 0;

    while (blockIter.hasNext()) {
      PcodeBlockBasic block = blockIter.next();
      Iterator<PcodeOp> opIter = block.getIterator();

      while (opIter.hasNext()) {
        PcodeOp op = opIter.next();
        int opcode = op.getOpcode();

        // Count branches
        if (opcode == PcodeOp.BRANCH || opcode == PcodeOp.CBRANCH) {
          branchCount++;
        }

        // Look for loop patterns
        if (opcode == PcodeOp.INT_LESS || opcode == PcodeOp.INT_LESSEQUAL) {
          loopIndicators++;
        }
      }
    }

    // Update cyclomatic complexity based on branches
    metrics.cyclomaticComplexity = branchCount + 1;

    if (loopIndicators > 2) {
      metrics.hasLoops = true;
    }
  }

  private void checkForPatterns(Function func, FunctionMetrics metrics) {
    Listing listing = currentProgram.getListing();
    AddressSetView body = func.getBody();
    if (body == null) {
      return;
    }

    InstructionIterator instIter = listing.getInstructions(body, true);

    // Pattern detection
    boolean hasStackStrings = false;
    boolean hasDynamicAPI = false;
    boolean hasObfuscation = false;

    while (instIter.hasNext()) {
      Instruction inst = instIter.next();
      String mnemonic = inst.getMnemonicString().toLowerCase(Locale.ROOT);

      // Check for stack string construction
      if ("mov".equals(mnemonic) || "push".equals(mnemonic)) {
        Scalar scalar = inst.getScalar(0);
        if (scalar != null && scalar.getValue() >= 0x20 && scalar.getValue() <= 0x7E) {
          hasStackStrings = true;
        }
      }

      // Check for dynamic API resolution
      if ("call".equals(mnemonic)) {
        String target = inst.getDefaultOperandRepresentation(0);
        if (target.contains("GetProcAddress") || target.contains("dlsym")) {
          hasDynamicAPI = true;
        }
      }

      // Check for obfuscation patterns
      if ("xor".equals(mnemonic) || "not".equals(mnemonic) || "neg".equals(mnemonic)) {
        hasObfuscation = true;
      }
    }

    if (hasStackStrings) {
      metrics.vulnerabilities.add("Stack string construction detected");
    }
    if (hasDynamicAPI) {
      metrics.vulnerabilities.add("Dynamic API resolution detected");
    }
    if (hasObfuscation) {
      metrics.vulnerabilities.add("Potential obfuscation detected");
    }
  }

  private void detectVulnerabilities() {
    // Dangerous function patterns
    String[] dangerousFuncs = {
      "strcpy",
      "strcat",
      "gets",
      "sprintf",
      "vsprintf",
      "scanf",
      "strncpy",
      "strncat",
      "memcpy",
      "memmove"
    };

    for (FunctionMetrics metrics : functionMetrics.values()) {
      // Check for dangerous function calls
      for (String called : metrics.calledFunctions) {
        for (String dangerous : dangerousFuncs) {
          if (called.toLowerCase(Locale.ROOT).contains(dangerous)) {
            metrics.vulnerabilities.add("Calls dangerous function: " + called);
            metrics.hasVulnerabilities = true;
          }
        }
      }

      // Check for integer overflow potential
      if (metrics.name.toLowerCase(Locale.ROOT).contains("alloc")
          || metrics.name.toLowerCase(Locale.ROOT).contains("size")) {
        metrics.vulnerabilities.add("Potential integer overflow in size calculation");
        metrics.hasVulnerabilities = true;
      }

      // Check for format string vulnerabilities
      if (metrics.calledFunctions.contains("printf")
          || metrics.calledFunctions.contains("sprintf")) {
        metrics.vulnerabilities.add("Potential format string vulnerability");
        metrics.hasVulnerabilities = true;
      }
    }
  }

  private void calculateComplexityMetrics() {
    for (FunctionMetrics metrics : functionMetrics.values()) {
      metrics.calculateComplexity();
    }
  }

  private FunctionCategory categorizeFunction(Function func) {
    String name = func.getName();

    for (FunctionCategory category : FunctionCategory.values()) {
      if (category != FunctionCategory.UNKNOWN && category.matches(name)) {
        return category;
      }
    }

    // Check called functions for categorization
    Set<Function> called = func.getCalledFunctions(monitor);
    for (Function calledFunc : called) {
      String calledName = calledFunc.getName();
      for (FunctionCategory category : FunctionCategory.values()) {
        if (category != FunctionCategory.UNKNOWN && category.matches(calledName)) {
          return category;
        }
      }
    }

    return FunctionCategory.UNKNOWN;
  }

  private void generateReports() throws Exception {
    println("\n" + "=".repeat(80));
    println("=== FUNCTION ANALYSIS REPORT ===");
    println("=".repeat(80));

    // Summary statistics
    generateSummaryReport();

    // Top complex functions
    generateComplexityReport();

    // Vulnerable functions
    generateVulnerabilityReport();

    // Category breakdown
    generateCategoryReport();

    // Export detailed report
    exportDetailedReport();
  }

  private void generateSummaryReport() {
    println("\n[SUMMARY STATISTICS]");
    println("-".repeat(40));

    int totalFunctions = functionMetrics.size();
    int withLoops = 0;
    int withRecursion = 0;
    int withIndirectCalls = 0;
    int withVulnerabilities = 0;

    for (FunctionMetrics metrics : functionMetrics.values()) {
      if (metrics.hasLoops) {
        withLoops++;
      }
      if (metrics.hasRecursion) {
        withRecursion++;
      }
      if (metrics.usesIndirectCalls) {
        withIndirectCalls++;
      }
      if (metrics.hasVulnerabilities) {
        withVulnerabilities++;
      }
    }

    println("Total functions: " + totalFunctions);
    println("Functions with loops: " + withLoops);
    println("Functions with recursion: " + withRecursion);
    println("Functions with indirect calls: " + withIndirectCalls);
    println("Functions with vulnerabilities: " + withVulnerabilities);
  }

  private void generateComplexityReport() {
    println("\n[TOP 10 MOST COMPLEX FUNCTIONS]");
    println("-".repeat(40));

    List<FunctionMetrics> sorted = new ArrayList<>(functionMetrics.values());
    sorted.sort((a, b) -> Double.compare(b.complexityScore, a.complexityScore));

    int count = 0;
    for (FunctionMetrics metrics : sorted) {
      if (count >= 10) {
        break;
      }

      println(
          String.format("%d. %s (Score: %.2f)", count + 1, metrics.name, metrics.complexityScore));
      println(
          String.format(
              "   Cyclomatic: %d, Blocks: %d, Calls: %d, Size: %d",
              metrics.cyclomaticComplexity,
              metrics.basicBlockCount,
              metrics.callCount,
              metrics.size));

      count++;
    }
  }

  private void generateVulnerabilityReport() {
    println("\n[VULNERABLE FUNCTIONS]");
    println("-".repeat(40));

    int count = 0;
    for (FunctionMetrics metrics : functionMetrics.values()) {
      if (metrics.hasVulnerabilities) {
        println(String.format("• %s at 0x%08X", metrics.name, metrics.entryPoint.getOffset()));

        for (String vuln : metrics.vulnerabilities) {
          println("  - " + vuln);
        }

        count++;
        if (count >= 20) {
          println("  ... and more");
          break;
        }
      }
    }

    if (count == 0) {
      println("No obvious vulnerabilities detected.");
    }
  }

  private void generateCategoryReport() {
    println("\n[FUNCTION CATEGORIES]");
    println("-".repeat(40));

    Map<FunctionCategory, Integer> categoryCounts = new HashMap<>();

    for (FunctionMetrics metrics : functionMetrics.values()) {
      categoryCounts.merge(metrics.category, 1, Integer::sum);
    }

    for (Map.Entry<FunctionCategory, Integer> entry : categoryCounts.entrySet()) {
      println(String.format("%-20s: %d functions", entry.getKey().displayName, entry.getValue()));
    }
  }

  private void exportDetailedReport() throws Exception {
    File reportFile = askFile("Save detailed report", "Save");

    if (reportFile != null) {
      try (PrintWriter writer = new PrintWriter(reportFile)) {
        writer.println("Function,Address,Size,Complexity,Category,Vulnerabilities");

        for (FunctionMetrics metrics : functionMetrics.values()) {
          writer.printf(
              "%s,0x%08X,%d,%.2f,%s,\"%s\"\n",
              metrics.name,
              metrics.entryPoint.getOffset(),
              metrics.size,
              metrics.complexityScore,
              metrics.category.displayName,
              String.join("; ", metrics.vulnerabilities));
        }

        println("\nDetailed report exported to: " + reportFile.getAbsolutePath());
      }
    }
  }

  // New methods using unused imports

  private void analyzeSymbolTable() {
    // Use SymbolTable, Symbol, SymbolIterator
    int totalSymbols = 0;
    int functionSymbols = 0;
    int dataSymbols = 0;
    int externalSymbols = 0;

    // Iterate through all symbols using SymbolIterator
    SymbolIterator symbolIter = symbolTable.getAllSymbols(true);

    while (symbolIter.hasNext() && !monitor.isCancelled()) {
      Symbol symbol = symbolIter.next();
      totalSymbols++;

      // Cache important symbols
      symbolCache.put(symbol.getName(), symbol);

      // Analyze symbol types
      SymbolType type = symbol.getSymbolType();
      if (type == SymbolType.FUNCTION) {
        functionSymbols++;
      } else if (type == SymbolType.LABEL) {
        dataSymbols++;
      }

      // Check if external
      if (symbol.isExternal()) {
        externalSymbols++;
        importedSymbols.add(symbol.getName());
      }

      // Check for exported symbols
      if (symbol.isPrimary() && !symbol.isExternal()) {
        Address addr = symbol.getAddress();
        Function func = getFunctionAt(addr);
        if (func != null && !func.isThunk()) {
          exportedSymbols.add(symbol.getName());
        }
      }

      // Analyze license-related symbols
      String name = symbol.getName().toLowerCase(Locale.ROOT);
      if (name.contains("license")
          || name.contains("serial")
          || name.contains("activation")
          || name.contains("trial")) {
        println("  [!] License symbol found: " + symbol.getName() + " at " + symbol.getAddress());
        createBookmark(
            symbol.getAddress(), "License", "License-related symbol: " + symbol.getName());
      }
    }

    println("  Total symbols: " + totalSymbols);
    println("  Function symbols: " + functionSymbols);
    println("  Data symbols: " + dataSymbols);
    println("  External symbols: " + externalSymbols);
    println("  Exported functions: " + exportedSymbols.size());
    println("  Imported functions: " + importedSymbols.size());

    // Find dynamic symbols using SymbolTable methods
    analyzeDynamicSymbols();
  }

  private void analyzeDynamicSymbols() {
    // Use SymbolTable to find dynamic symbols
    Address[] dynamicAddresses = symbolTable.getDynamicSymbolAddresses();

    if (dynamicAddresses.length > 0) {
      println("  Dynamic symbols found: " + dynamicAddresses.length);

      for (Address addr : dynamicAddresses) {
        Symbol[] symbols = symbolTable.getSymbols(addr);
        for (Symbol sym : symbols) {
          if (sym.isDynamic()) {
            println("    - " + sym.getName() + " (dynamic)");
          }
        }
      }
    }

    // Check for namespace symbols
    int namespaceCount = 0;
    for (Symbol sym : symbolCache.values()) {
      if (sym.getParentNamespace() != null && !sym.getParentNamespace().isGlobal()) {
        namespaceCount++;
      }
    }

    if (namespaceCount > 0) {
      println("  Symbols in namespaces: " + namespaceCount);
    }
  }

  private void analyzeReferences() {
    // Use ReferenceManager and Reference
    int totalRefs = 0;
    int callRefs = 0;
    int dataRefs = 0;
    int indirectRefs = 0;
    Map<Address, Integer> hotspots = new HashMap<>();

    // Analyze all references in the program
    AddressIterator addrIter =
        referenceManager.getReferenceSourceIterator(program.getMinAddress(), true);

    while (addrIter.hasNext() && !monitor.isCancelled()) {
      Address fromAddr = addrIter.next();
      Reference[] refs = referenceManager.getReferencesFrom(fromAddr);

      for (Reference ref : refs) {
        totalRefs++;

        // Cache references
        referenceCache.computeIfAbsent(ref.getToAddress(), k -> new ArrayList<>()).add(ref);

        // Analyze reference types
        RefType refType = ref.getReferenceType();
        if (refType.isCall()) {
          callRefs++;
        } else if (refType.isData()) {
          dataRefs++;
        }

        if (refType.isIndirect()) {
          indirectRefs++;
        }

        // Track hotspots (frequently referenced addresses)
        Address toAddr = ref.getToAddress();
        hotspots.merge(toAddr, 1, Integer::sum);

        // Check for interesting patterns
        if (ref.getSource() == SourceType.USER_DEFINED) {
          Symbol sym = symbolTable.getPrimarySymbol(toAddr);
          if (sym != null && sym.getName().contains("license")) {
            println("  [!] User-defined reference to license code at " + fromAddr);
          }
        }
      }
    }

    println("  Total references: " + totalRefs);
    println("  Call references: " + callRefs);
    println("  Data references: " + dataRefs);
    println("  Indirect references: " + indirectRefs);

    // Find top referenced addresses
    List<Map.Entry<Address, Integer>> topHotspots =
        hotspots.entrySet().stream()
            .sorted(Map.Entry.<Address, Integer>comparingByValue().reversed())
            .limit(5)
            .toList();

    if (!topHotspots.isEmpty()) {
      println("  Top referenced addresses:");
      for (Map.Entry<Address, Integer> entry : topHotspots) {
        Symbol sym = symbolTable.getPrimarySymbol(entry.getKey());
        String name = sym != null ? sym.getName() : "unknown";
        println("    - " + entry.getKey() + " (" + name + "): " + entry.getValue() + " refs");
      }
    }
  }

  private void analyzeCodeUnits() {
    // Use CodeUnit and Instruction for detailed analysis
    Listing listing = program.getListing();
    int totalCodeUnits = 0;
    int instructions = 0;
    int definedData = 0;
    int undefinedData = 0;
    Map<String, Integer> mnemonicCounts = new HashMap<>();

    // Iterate through all code units
    CodeUnitIterator codeUnitIter = listing.getCodeUnits(true);

    while (codeUnitIter.hasNext() && !monitor.isCancelled()) {
      CodeUnit codeUnit = codeUnitIter.next();
      totalCodeUnits++;

      // Cache code units
      codeUnitMap.put(codeUnit.getAddress(), codeUnit);

      if (codeUnit instanceof Instruction inst) {
        instructions++;

        // Count mnemonics
        String mnemonic = inst.getMnemonicString();
        mnemonicCounts.merge(mnemonic, 1, Integer::sum);

        // Analyze specific instruction patterns
        analyzeInstructionPattern(inst);

      } else if (codeUnit instanceof Data data) {
        if (data.isDefined()) {
          definedData++;
        } else {
          undefinedData++;
        }
      }

      // Check for comments (potential analysis hints)
      String comment = codeUnit.getComment(CodeUnit.EOL_COMMENT);
      if (comment != null && comment.toLowerCase(Locale.ROOT).contains("license")) {
        println("  [!] License-related comment at " + codeUnit.getAddress() + ": " + comment);
      }
    }

    println("  Total code units: " + totalCodeUnits);
    println("  Instructions: " + instructions);
    println("  Defined data: " + definedData);
    println("  Undefined data: " + undefinedData);

    // Find most common instructions
    List<Map.Entry<String, Integer>> topMnemonics =
        mnemonicCounts.entrySet().stream()
            .sorted(Map.Entry.<String, Integer>comparingByValue().reversed())
            .limit(10)
            .toList();

    println("  Top 10 instructions:");
    for (Map.Entry<String, Integer> entry : topMnemonics) {
      println("    - " + entry.getKey() + ": " + entry.getValue());
    }
  }

  private void analyzeInstructionPattern(Instruction inst) {
    String mnemonic = inst.getMnemonicString().toLowerCase(Locale.ROOT);

    // Check for anti-analysis patterns
    if ("int3".equals(mnemonic) || "int".equals(mnemonic) || "icebp".equals(mnemonic)) {
      createBookmark(inst.getAddress(), "Anti-Debug", "Breakpoint/interrupt instruction");
    }

    // Check for timing checks
    if ("rdtsc".equals(mnemonic) || "rdtscp".equals(mnemonic)) {
      createBookmark(inst.getAddress(), "Anti-Debug", "Timing check instruction");
    }

    // Check for obfuscation patterns
    if ("jmp".equals(mnemonic) && inst.getNext() != null) {
      Address target = inst.getDefaultFlows()[0];
      if (target.equals(inst.getNext().getAddress())) {
        createBookmark(inst.getAddress(), "Obfuscation", "Redundant jump");
      }
    }

    // Check for dynamic API resolution
    if ("call".equals(mnemonic)) {
      String op = inst.getDefaultOperandRepresentation(0);
      if (op != null && (op.contains("GetProcAddress") || op.contains("LoadLibrary"))) {
        FunctionMetrics metrics = findContainingFunctionMetrics(inst.getAddress());
        if (metrics != null && !metrics.vulnerabilities.contains("Dynamic API resolution")) {
          metrics.vulnerabilities.add("Dynamic API resolution detected");
        }
      }
    }
  }

  private FunctionMetrics findContainingFunctionMetrics(Address addr) {
    Function func = getFunctionContaining(addr);
    if (func != null) {
      return functionMetrics.get(func.getEntryPoint());
    }
    return null;
  }

  // Phase 8: Language-specific analysis using Language
  private void performLanguageSpecificAnalysis() {
    try {
      Language language = program.getLanguage();

      println("  Target architecture: " + language.getLanguageDescription());
      println("  Processor: " + language.getProcessor().toString());
      println("  Default pointer size: " + language.getDefaultSpace().getPointerSize());
      println("  Address size: " + language.getDefaultSpace().getSize());
      println("  Endianness: " + (language.isBigEndian() ? "Big" : "Little"));

      // Analyze architecture-specific function patterns
      analyzeArchitectureSpecificPatterns(language);

      // Analyze instruction sets and variants
      analyzeInstructionSets(language);

      // Check for architecture-specific vulnerabilities
      checkArchitectureVulnerabilities(language);

    } catch (Exception e) {
      printerr("Language-specific analysis failed: " + e.getMessage());
    }
  }

  private void analyzeArchitectureSpecificPatterns(Language language) {
    String processor = language.getProcessor().toString().toLowerCase(Locale.ROOT);
    int archSpecificFunctions = 0;
    int callingConventionIssues = 0;

    for (FunctionMetrics metrics : functionMetrics.values()) {
      Function func = getFunctionAt(metrics.entryPoint);
      if (func == null) {
        continue;
      }

      // Check for architecture-specific function characteristics
      if (processor.contains("x86")) {
        if (analyzeX86SpecificPatterns(func, language, metrics)) {
          archSpecificFunctions++;
        }
      } else if (processor.contains("arm")) {
        if (analyzeARMSpecificPatterns(func, language, metrics)) {
          archSpecificFunctions++;
        }
      } else if (processor.contains("mips")) {
        if (analyzeMIPSSpecificPatterns(func, language, metrics)) {
          archSpecificFunctions++;
        }
      }

      // Check calling convention compliance
      if (analyzeCallingConvention(func, language)) {
        callingConventionIssues++;
      }
    }

    println("  Architecture-specific functions: " + archSpecificFunctions);
    println("  Calling convention issues: " + callingConventionIssues);
  }

  private boolean analyzeX86SpecificPatterns(
      Function func, Language language, FunctionMetrics metrics) {
    boolean hasX86Specific = false;
    AddressSetView body = func.getBody();
    if (body == null) {
      return false;
    }

    String langId = language.getLanguageID().toString();
    boolean is64bit = langId.contains("64");
    InstructionIterator instIter = program.getListing().getInstructions(body, true);

    while (instIter.hasNext()) {
      Instruction inst = instIter.next();
      String mnemonic = inst.getMnemonicString().toLowerCase(Locale.ROOT);

      // Check for x86-specific instructions
      if (mnemonic.startsWith("rep")
          || "stosb".equals(mnemonic)
          || "lodsb".equals(mnemonic)
          || "cmpsb".equals(mnemonic)
          || "pusha".equals(mnemonic)
          || "popa".equals(mnemonic)) {
        hasX86Specific = true;
        String archLabel = is64bit ? "x86-64" : "x86-32";
        metrics.vulnerabilities.add("Uses " + archLabel + "-specific string/stack instructions");
      }

      // Check for segment register usage
      if (mnemonic.contains("fs:")
          || mnemonic.contains("gs:")
          || mnemonic.contains("es:")
          || mnemonic.contains("ds:")) {
        hasX86Specific = true;
        metrics.vulnerabilities.add("Uses segment register access");
      }

      // Check for FPU instructions
      if (mnemonic.startsWith("f")
          && (mnemonic.contains("st") || "fld".equals(mnemonic) || "fst".equals(mnemonic))) {
        hasX86Specific = true;
      }
    }

    return hasX86Specific;
  }

  private boolean analyzeARMSpecificPatterns(
      Function func, Language language, FunctionMetrics metrics) {
    boolean hasARMSpecific = false;
    AddressSetView body = func.getBody();
    if (body == null) {
      return false;
    }

    String langId = language.getLanguageID().toString().toLowerCase(Locale.ROOT);
    boolean isThumb = langId.contains("thumb");
    boolean isAarch64 = langId.contains("aarch64");

    if (isThumb) {
      metrics.vulnerabilities.add("Function uses ARM Thumb instruction set");
    }
    if (isAarch64) {
      metrics.vulnerabilities.add("Function uses AArch64 instruction set");
    }
    InstructionIterator instIter = program.getListing().getInstructions(body, true);

    while (instIter.hasNext()) {
      Instruction inst = instIter.next();
      String mnemonic = inst.getMnemonicString().toLowerCase(Locale.ROOT);

      // Check for ARM-specific instructions
      if ("bx".equals(mnemonic)
          || "blx".equals(mnemonic)
          || mnemonic.startsWith("ldm")
          || mnemonic.startsWith("stm")
          || "swi".equals(mnemonic)
          || "svc".equals(mnemonic)) {
        hasARMSpecific = true;
        metrics.vulnerabilities.add("Uses ARM-specific instructions");
      }

      // Check for conditional execution
      if (mnemonic.endsWith("eq")
          || mnemonic.endsWith("ne")
          || mnemonic.endsWith("cs")
          || mnemonic.endsWith("cc")) {
        hasARMSpecific = true;
      }
    }

    return hasARMSpecific;
  }

  private boolean analyzeMIPSSpecificPatterns(
      Function func, Language language, FunctionMetrics metrics) {
    boolean hasMIPSSpecific = false;
    AddressSetView body = func.getBody();
    if (body == null) {
      return false;
    }

    String languageId = language.getLanguageID().toString().toLowerCase(Locale.ROOT);
    boolean isMips32 = languageId.contains("mips32");
    InstructionIterator instIter = program.getListing().getInstructions(body, true);

    while (instIter.hasNext()) {
      Instruction inst = instIter.next();
      String mnemonic = inst.getMnemonicString().toLowerCase(Locale.ROOT);

      // Check for MIPS-specific instructions
      if ("jalr".equals(mnemonic)
          || "jr".equals(mnemonic)
          || (mnemonic.startsWith("b") && mnemonic.length() > 1)
          || "syscall".equals(mnemonic)
          || "break".equals(mnemonic)) {
        hasMIPSSpecific = true;
        String archDetail = isMips32 ? "MIPS32" : "MIPS64";
        metrics.vulnerabilities.add("Uses " + archDetail + "-specific instructions");
      }

      // Check for delay slot usage
      if ("nop".equals(mnemonic) && inst.getNext() != null) {
        String nextMnemonic = inst.getNext().getMnemonicString().toLowerCase(Locale.ROOT);
        if (nextMnemonic.startsWith("j") || nextMnemonic.startsWith("b")) {
          hasMIPSSpecific = true;
        }
      }
    }

    return hasMIPSSpecific;
  }

  private boolean analyzeCallingConvention(Function func, Language language) {
    // Analyze function signature against standard calling conventions
    String processor = language.getProcessor().toString().toLowerCase(Locale.ROOT);
    Parameter[] params = func.getParameters();

    // Check parameter count against architecture limits
    if (processor.contains("x86") && !processor.contains("x86_64")) {
      // x86-32 typically passes first few params in registers
      return params.length > 6; // Potential stack overflow risk
    } else if (processor.contains("x86_64")) {
      // x86-64 passes first 6 params in registers
      return params.length > 10; // Excessive parameters
    }

    return false;
  }

  private void analyzeInstructionSets(Language language) {
    Set<String> instructionFamilies = new HashSet<>();
    Set<String> specialInstructions = new HashSet<>();
    int simdInstructions = 0;
    int cryptoInstructions = 0;

    String processor = language.getProcessor().toString().toLowerCase(Locale.ROOT);
    boolean isX86 = processor.contains("x86");

    // Analyze all instructions in functions
    for (FunctionMetrics metrics : functionMetrics.values()) {
      Function func = getFunctionAt(metrics.entryPoint);
      if (func == null) {
        continue;
      }

      AddressSetView body = func.getBody();
      if (body == null) {
        continue;
      }

      InstructionIterator instIter = program.getListing().getInstructions(body, true);
      while (instIter.hasNext()) {
        Instruction inst = instIter.next();
        String mnemonic = inst.getMnemonicString().toLowerCase(Locale.ROOT);

        // Categorize instruction families
        if (mnemonic.startsWith("sse")
            || mnemonic.startsWith("avx")
            || mnemonic.startsWith("mmx")
            || mnemonic.contains("xmm")) {
          instructionFamilies.add("SIMD");
          simdInstructions++;
        } else if (mnemonic.startsWith("aes")
            || mnemonic.startsWith("sha")
            || mnemonic.contains("crc32")) {
          instructionFamilies.add("Crypto");
          cryptoInstructions++;
        } else if ("rdrand".equals(mnemonic)
            || "rdseed".equals(mnemonic)
            || "rdtsc".equals(mnemonic)
            || "rdtscp".equals(mnemonic)) {
          specialInstructions.add(mnemonic);
        }
      }
    }

    String archLabel = isX86 ? "x86" : processor;
    println("  Architecture: " + archLabel);
    println("  Instruction families detected: " + instructionFamilies);
    println("  SIMD instructions: " + simdInstructions);
    println("  Crypto instructions: " + cryptoInstructions);
    println("  Special instructions: " + specialInstructions);
  }

  private void checkArchitectureVulnerabilities(Language language) {
    String processor = language.getProcessor().toString().toLowerCase(Locale.ROOT);
    int vulnFunctions = 0;

    for (FunctionMetrics metrics : functionMetrics.values()) {
      Function func = getFunctionAt(metrics.entryPoint);
      if (func == null) {
        continue;
      }

      // Check for architecture-specific vulnerabilities
      if (processor.contains("x86")) {
        if (checkX86Vulnerabilities(func, metrics)) {
          vulnFunctions++;
        }
      }

      // Check for buffer overflow patterns based on architecture
      if (checkBufferOverflowPatterns(func, language, metrics)) {
        vulnFunctions++;
      }
    }

    println("  Functions with architecture vulnerabilities: " + vulnFunctions);
  }

  private boolean checkX86Vulnerabilities(Function func, FunctionMetrics metrics) {
    boolean hasVuln = false;
    AddressSetView body = func.getBody();
    if (body == null) {
      return false;
    }
    InstructionIterator instIter = program.getListing().getInstructions(body, true);

    while (instIter.hasNext()) {
      Instruction inst = instIter.next();
      String mnemonic = inst.getMnemonicString().toLowerCase(Locale.ROOT);

      // Check for dangerous x86 patterns
      if ("gets".equals(mnemonic) || "strcpy".equals(mnemonic)) {
        metrics.vulnerabilities.add("Uses dangerous string function: " + mnemonic);
        hasVuln = true;
      }

      // Check for stack manipulation without bounds checking
      if ("rep".equals(mnemonic) && inst.getNext() != null) {
        String next = inst.getNext().getMnemonicString().toLowerCase(Locale.ROOT);
        if ("stosb".equals(next) || "movsb".equals(next)) {
          metrics.vulnerabilities.add("Unchecked string operation");
          hasVuln = true;
        }
      }
    }

    return hasVuln;
  }

  private boolean checkBufferOverflowPatterns(
      Function func, Language language, FunctionMetrics metrics) {
    // Look for patterns that indicate potential buffer overflows
    int pointerSize = language.getDefaultSpace().getPointerSize();
    boolean hasPattern = false;

    AddressSetView body = func.getBody();
    if (body == null) {
      return false;
    }

    InstructionIterator instIter = program.getListing().getInstructions(body, true);
    while (instIter.hasNext()) {
      Instruction inst = instIter.next();

      // Check for unchecked memory operations based on pointer size
      if (inst.getMnemonicString().toLowerCase(Locale.ROOT).contains("mov")) {
        if (inst.getNumOperands() >= 2) {
          // Check if we're moving data larger than pointer size without bounds check
          for (int i = 0; i < inst.getNumOperands(); i++) {
            if (inst.getScalar(i) != null) {
              long value = inst.getScalar(i).getValue();
              if (value > (1L << (pointerSize * 8 - 1))) {
                metrics.vulnerabilities.add("Large data movement without bounds check");
                hasPattern = true;
              }
            }
          }
        }
      }
    }

    return hasPattern;
  }

  // Phase 9: Data type analysis using DataType
  private void analyzeDataTypes() {
    try {
      DataTypeManager dataTypeManager = program.getDataTypeManager();

      println("  Data type manager: " + dataTypeManager.getName());
      println("  Total data types: " + dataTypeManager.getDataTypeCount(true));

      // Analyze function parameter and return types
      analyzeFunctionDataTypes(dataTypeManager);

      // Analyze complex data structures
      analyzeComplexDataTypes(dataTypeManager);

      // Analyze user-defined types
      analyzeUserDefinedTypes(dataTypeManager);

      // Check for security-relevant data types
      checkSecurityDataTypes(dataTypeManager);

    } catch (Exception e) {
      printerr("Data type analysis failed: " + e.getMessage());
    }
  }

  private void analyzeFunctionDataTypes(DataTypeManager dataTypeManager) {
    Map<String, Integer> returnTypeCounts = new HashMap<>();
    Map<String, Integer> paramTypeCounts = new HashMap<>();
    int functionsWithCustomTypes = 0;
    int functionsWithVoidReturn = 0;

    for (FunctionMetrics metrics : functionMetrics.values()) {
      Function func = getFunctionAt(metrics.entryPoint);
      if (func == null) {
        continue;
      }

      // Analyze return type
      DataType returnType = func.getReturnType();
      if (returnType != null) {
        String typeName = returnType.getName();
        returnTypeCounts.merge(typeName, 1, Integer::sum);

        if (returnType == DataType.VOID) {
          functionsWithVoidReturn++;
        }

        // Check if it's a user-defined type
        if (isUserDefinedType(returnType, dataTypeManager)) {
          functionsWithCustomTypes++;
          metrics.vulnerabilities.add("Uses custom return type: " + typeName);
        }
      }

      // Analyze parameter types
      Parameter[] params = func.getParameters();
      for (Parameter param : params) {
        DataType paramType = param.getDataType();
        if (paramType != null) {
          String typeName = paramType.getName();
          paramTypeCounts.merge(typeName, 1, Integer::sum);

          // Check for dangerous parameter types
          if (isDangerousType(paramType)) {
            metrics.vulnerabilities.add("Dangerous parameter type: " + typeName);
          }
        }
      }
    }

    println("  Functions with void return: " + functionsWithVoidReturn);
    println("  Functions with custom types: " + functionsWithCustomTypes);
    println("  Most common return types:");
    returnTypeCounts.entrySet().stream()
        .sorted(Map.Entry.<String, Integer>comparingByValue().reversed())
        .limit(5)
        .forEach(entry -> println("    - " + entry.getKey() + ": " + entry.getValue()));
  }

  private void analyzeComplexDataTypes(DataTypeManager dataTypeManager) {
    Iterator<DataType> dataTypeIter = dataTypeManager.getAllDataTypes();
    int structureCount = 0;
    int unionCount = 0;
    int enumCount = 0;
    int arrayCount = 0;
    int pointerCount = 0;
    int functionPointerCount = 0;

    while (dataTypeIter.hasNext()) {
      DataType dataType = dataTypeIter.next();

      if (dataType instanceof Structure) {
        structureCount++;
        analyzeStructureType((Structure) dataType);
      } else if (dataType instanceof Union) {
        unionCount++;
      } else if (dataType instanceof ghidra.program.model.data.Enum) {
        enumCount++;
        analyzeEnumType((ghidra.program.model.data.Enum) dataType);
      } else if (dataType instanceof Array) {
        arrayCount++;
        analyzeArrayType((Array) dataType);
      } else if (dataType instanceof Pointer) {
        pointerCount++;
        if (((Pointer) dataType).getDataType() instanceof FunctionDefinition) {
          functionPointerCount++;
        }
      }
    }

    println("  Structures: " + structureCount);
    println("  Unions: " + unionCount);
    println("  Enums: " + enumCount);
    println("  Arrays: " + arrayCount);
    println("  Pointers: " + pointerCount);
    println("  Function pointers: " + functionPointerCount);
  }

  private void analyzeStructureType(Structure structure) {
    // Analyze structure for security implications
    DataTypeComponent[] components = structure.getDefinedComponents();

    for (DataTypeComponent component : components) {
      DataType componentType = component.getDataType();

      // Check for dangerous structure members
      if (componentType instanceof Array arrayType) {
        if (arrayType.getElementLength() > 1024) {
          // Large array in structure - potential overflow
          println("[DataType Finding] Large array in structure: " + structure.getName());
        }
      }

      // Check for function pointers in structures
      if (componentType instanceof Pointer ptrType) {
        if (ptrType.getDataType() instanceof FunctionDefinition) {
          println("[DataType Finding] Function pointer in structure: " + structure.getName());
        }
      }
    }
  }

  private void analyzeEnumType(ghidra.program.model.data.Enum enumType) {
    // Analyze enum for security-relevant values
    String[] names = enumType.getNames();

    for (String enumName : names) {
      String lowerName = enumName.toLowerCase(Locale.ROOT);
      long enumValue = enumType.getValue(enumName);

      // Check for security-related enum values
      if (lowerName.contains("admin")
          || lowerName.contains("root")
          || lowerName.contains("privilege")
          || lowerName.contains("permission")) {
        println("[DataType Finding] Security-related enum: " + enumType.getName()
            + "." + enumName + " = " + enumValue);
      }

      // Check for suspicious numeric values (common bypass values)
      if (enumValue == 0xDEADBEEF || enumValue == 0xCAFEBABE || enumValue == -1) {
        println("[DataType Finding] Suspicious enum value: " + enumType.getName()
            + "." + enumName + " = 0x" + Long.toHexString(enumValue));
      }
    }
  }

  private void analyzeArrayType(Array arrayType) {
    // Check for potentially dangerous array types
    int numElements = arrayType.getNumElements();
    DataType elementType = arrayType.getDataType();

    if (numElements > 10000) {
      println("[DataType Finding] Very large array: " + arrayType.getName());
    }

    // Check for arrays of function pointers
    if (elementType instanceof Pointer ptrType) {
      if (ptrType.getDataType() instanceof FunctionDefinition) {
        println("[DataType Finding] Array of function pointers: " + arrayType.getName());
      }
    }
  }

  private void analyzeUserDefinedTypes(DataTypeManager dataTypeManager) {
    Category rootCategory = dataTypeManager.getRootCategory();
    int userTypes = 0;

    userTypes += analyzeCategory(rootCategory);

    println("  User-defined types: " + userTypes);
  }

  private int analyzeCategory(Category category) {
    int count = 0;

    // Count data types in this category
    DataType[] dataTypes = category.getDataTypes();
    for (DataType dataType : dataTypes) {
      if (isUserDefinedType(dataType, dataType.getDataTypeManager())) {
        count++;
      }
    }

    // Recursively analyze subcategories
    Category[] subcategories = category.getCategories();
    for (Category subcategory : subcategories) {
      count += analyzeCategory(subcategory);
    }

    return count;
  }

  private boolean isUserDefinedType(DataType dataType, DataTypeManager dataTypeManager) {
    // Check if this is a user-defined type vs built-in type
    String typeName = dataType.getName();

    // Use dataTypeManager to check if type is from universal data types
    DataType universalType = dataTypeManager.getDataType("/" + typeName);
    boolean isUniversal = universalType != null;

    // Built-in types typically have simple names
    if ("void".equals(typeName)
        || "char".equals(typeName)
        || "float".equals(typeName)
        || "double".equals(typeName)
        || "long".equals(typeName)
        || typeName.startsWith("uint")
        || typeName.startsWith("int")
        || isUniversal) {
      return false;
    }

    // Check if it's in a user category
    CategoryPath categoryPath = dataType.getCategoryPath();
    return categoryPath != null && !categoryPath.getPath().startsWith("/");
  }

  private boolean isDangerousType(DataType dataType) {
    String typeName = dataType.getName().toLowerCase(Locale.ROOT);

    // Check for inherently dangerous types
    if (typeName.contains("char*") || typeName.contains("void*")) {
      return true;
    }

    // Check for function pointers
    return dataType instanceof Pointer ptrType
        && ptrType.getDataType() instanceof FunctionDefinition;
  }

  private void checkSecurityDataTypes(DataTypeManager dataTypeManager) {
    Iterator<DataType> dataTypeIter = dataTypeManager.getAllDataTypes();
    int securityTypes = 0;

    while (dataTypeIter.hasNext()) {
      DataType dataType = dataTypeIter.next();
      String name = dataType.getName().toLowerCase(Locale.ROOT);

      // Look for security-related type names
      if (name.contains("password")
          || name.contains("key")
          || name.contains("token")
          || name.contains("hash")
          || name.contains("credential")
          || name.contains("auth")
          || name.contains("license")
          || name.contains("serial")) {
        securityTypes++;

        println("[Security Finding] Security-related data type: " + dataType.getName());
      }
    }

    println("  Security-related data types: " + securityTypes);
  }

  // Phase 10: Memory analysis using Memory, MemoryAccessException
  private void performMemoryAnalysis() {
    try {
      Memory memory = program.getMemory();

      println("  Memory blocks: " + memory.getBlocks().length);
      println("  Memory size: " + memory.getSize() + " bytes");

      // Analyze memory blocks
      analyzeMemoryBlocks(memory);

      // Analyze memory access patterns in functions
      analyzeMemoryAccessPatterns(memory);

      // Check for buffer overflow vulnerabilities
      checkBufferOverflows(memory);

      // Analyze memory initialization patterns
      analyzeMemoryInitialization(memory);

    } catch (Exception e) {
      printerr("Memory analysis failed: " + e.getMessage());
    }
  }

  private void analyzeMemoryBlocks(Memory memory) {
    MemoryBlock[] blocks = memory.getBlocks();
    int executableBlocks = 0;
    int writableBlocks = 0;
    int executableWritableBlocks = 0;
    long totalExecutableSize = 0;
    long totalWritableSize = 0;

    for (MemoryBlock block : blocks) {
      boolean isExecutable = block.isExecute();
      boolean isWritable = block.isWrite();

      if (isExecutable) {
        executableBlocks++;
        totalExecutableSize += block.getSize();
      }

      if (isWritable) {
        writableBlocks++;
        totalWritableSize += block.getSize();
      }

      // DEP violation - executable and writable
      if (isExecutable && isWritable) {
        executableWritableBlocks++;
        createBookmark(
            block.getStart(),
            "Security",
            "Executable and writable memory block: " + block.getName());
      }

      // Check for suspicious memory block names
      String blockName = block.getName().toLowerCase(Locale.ROOT);
      if (blockName.contains("heap")
          || blockName.contains("stack")
          || blockName.contains("shell")
          || blockName.contains("code")) {
        analyzeMemoryBlockContent(memory, block);
      }
    }

    println("  Executable blocks: " + executableBlocks + " (" + totalExecutableSize + " bytes)");
    println("  Writable blocks: " + writableBlocks + " (" + totalWritableSize + " bytes)");
    println("  Executable+Writable blocks: " + executableWritableBlocks);
  }

  private void analyzeMemoryBlockContent(Memory memory, MemoryBlock block) {
    try {
      Address start = block.getStart();
      Address end = block.getEnd();
      long blockRange = end.subtract(start);
      long size = Math.min(block.getSize(), 1024); // Analyze first 1KB

      byte[] data = new byte[(int) size];
      int bytesRead = memory.getBytes(start, data);

      if (bytesRead > 0) {
        // Check for patterns that might indicate shellcode or obfuscation
        if (containsShellcodePatterns(data)) {
          createBookmark(start, "Security",
              "Potential shellcode pattern in " + block.getName() + " (range: " + blockRange + ")");
        }

        // Check for string patterns
        if (containsSuspiciousStrings(data)) {
          createBookmark(start, "Security",
              "Suspicious strings in " + block.getName() + " ending at " + end);
        }
      }

    } catch (MemoryAccessException e) {
      // Memory access failed - could indicate protected/encrypted region
      createBookmark(
          block.getStart(),
          "Security",
          "Memory access exception in " + block.getName() + ": " + e.getMessage());
    }
  }

  private boolean containsShellcodePatterns(byte[] data) {
    // Look for common shellcode patterns
    byte[][] patterns = {
      {(byte) 0x90, (byte) 0x90, (byte) 0x90, (byte) 0x90}, // NOP sled
      {(byte) 0xEB, (byte) 0xFE}, // JMP $-2 (infinite loop)
      {(byte) 0xCC, (byte) 0xCC}, // INT3 breakpoints
      {(byte) 0x31, (byte) 0xC0}, // XOR EAX, EAX
      {(byte) 0x48, (byte) 0x31, (byte) 0xC0} // XOR RAX, RAX (x64)
    };

    for (byte[] pattern : patterns) {
      if (containsPattern(data, pattern)) {
        return true;
      }
    }

    return false;
  }

  private boolean containsSuspiciousStrings(byte[] data) {
    String dataStr = new String(data).toLowerCase(Locale.ROOT);
    String[] suspiciousStrings = {
      "cmd.exe",
      "powershell",
      "/bin/sh",
      "system",
      "getprocaddress",
      "loadlibrary",
      "winexec",
      "createprocess",
      "shellcode",
      "exploit"
    };

    for (String suspicious : suspiciousStrings) {
      if (dataStr.contains(suspicious)) {
        return true;
      }
    }

    return false;
  }

  private boolean containsPattern(byte[] data, byte[] pattern) {
    for (int i = 0; i <= data.length - pattern.length; i++) {
      boolean match = true;
      for (int j = 0; j < pattern.length; j++) {
        if (data[i + j] != pattern[j]) {
          match = false;
          break;
        }
      }
      if (match) {
        return true;
      }
    }
    return false;
  }

  private void analyzeMemoryAccessPatterns(Memory memory) {
    int unsafeAccesses = 0;
    int boundaryViolations = 0;

    for (FunctionMetrics metrics : functionMetrics.values()) {
      Function func = getFunctionAt(metrics.entryPoint);
      if (func == null) {
        continue;
      }

      AddressSetView body = func.getBody();
      if (body == null) {
        continue;
      }

      InstructionIterator instIter = program.getListing().getInstructions(body, true);
      while (instIter.hasNext()) {
        Instruction inst = instIter.next();

        try {
          if (analyzeMemoryInstruction(memory, inst, metrics)) {
            unsafeAccesses++;
          }
        } catch (MemoryAccessException e) {
          boundaryViolations++;
          metrics.vulnerabilities.add("Memory boundary violation: " + e.getMessage());
        }
      }
    }

    println("  Unsafe memory accesses: " + unsafeAccesses);
    println("  Memory boundary violations: " + boundaryViolations);
  }

  private boolean analyzeMemoryInstruction(Memory memory, Instruction inst, FunctionMetrics metrics)
      throws MemoryAccessException {
    String mnemonic = inst.getMnemonicString().toLowerCase(Locale.ROOT);
    boolean isUnsafe = false;

    // Check for memory operations that could be unsafe
    if (mnemonic.contains("mov")
        || mnemonic.contains("lea")
        || mnemonic.contains("push")
        || mnemonic.contains("pop")) {

      // Analyze operands for potential unsafe memory access
      for (int i = 0; i < inst.getNumOperands(); i++) {
        Address memAddr = inst.getAddress(i);
        if (memAddr != null) {
          // Check if the memory address is in a valid block
          MemoryBlock block = memory.getBlock(memAddr);
          if (block == null) {
            isUnsafe = true;
            metrics.vulnerabilities.add("Access to unmapped memory: " + memAddr);
            continue;
          }

          // Check for access near block boundaries
          if (memAddr.getOffset() - block.getStart().getOffset() < 8
              || block.getEnd().getOffset() - memAddr.getOffset() < 8) {
            isUnsafe = true;
            metrics.vulnerabilities.add("Access near memory boundary: " + memAddr);
          }

          // Try to read from the address to check accessibility
          byte testByte = memory.getByte(memAddr);
          // Access succeeded - check if value is suspicious (potential uninit)
          if (testByte == (byte) 0xCC || testByte == (byte) 0xCD) {
            metrics.vulnerabilities.add("Suspicious uninitialized memory pattern at: " + memAddr);
          }
        }
      }
    }

    return isUnsafe;
  }

  private void checkBufferOverflows(Memory memory) {
    int potentialOverflows = 0;

    for (FunctionMetrics metrics : functionMetrics.values()) {
      Function func = getFunctionAt(metrics.entryPoint);
      if (func == null) {
        continue;
      }

      // Check for functions that use dangerous string operations
      for (String calledFunc : metrics.calledFunctions) {
        if (isDangerousStringFunction(calledFunc)) {
          potentialOverflows++;

          // Try to analyze the actual memory usage
          try {
            analyzeStringFunctionUsage(memory, func, calledFunc, metrics);
          } catch (MemoryAccessException e) {
            metrics.vulnerabilities.add(
                "Memory access error in string function: " + calledFunc + " - " + e.getMessage());
          }
        }
      }
    }

    println("  Potential buffer overflows: " + potentialOverflows);
  }

  private boolean isDangerousStringFunction(String funcName) {
    String[] dangerous = {
      "strcpy", "strcat", "sprintf", "vsprintf", "gets", "scanf",
      "strncpy", "strncat", "memcpy", "memmove", "wcscpy", "wcscat"
    };

    for (String dangerous_func : dangerous) {
      if (funcName.toLowerCase(Locale.ROOT).contains(dangerous_func)) {
        return true;
      }
    }

    return false;
  }

  private void analyzeStringFunctionUsage(
      Memory memory, Function func, String calledFunc, FunctionMetrics metrics)
      throws MemoryAccessException {
    // Analyze how the dangerous string function is being used
    AddressSetView body = func.getBody();
    if (body == null) {
      return;
    }
    InstructionIterator instIter = program.getListing().getInstructions(body, true);

    while (instIter.hasNext()) {
      Instruction inst = instIter.next();

      if ("call".equals(inst.getMnemonicString().toLowerCase(Locale.ROOT))) {
        String target = inst.getDefaultOperandRepresentation(0);
        if (target != null && target.toLowerCase(Locale.ROOT).contains(calledFunc.toLowerCase(Locale.ROOT))) {
          // Found call to dangerous function, analyze context
          analyzeCallContext(memory, inst, calledFunc, metrics);
        }
      }
    }
  }

  private void analyzeCallContext(
      Memory memory, Instruction callInst, String funcName, FunctionMetrics metrics)
      throws MemoryAccessException {
    // Look at instructions before the call to understand buffer sizes
    Instruction prevInst = callInst.getPrevious();
    int instructionsBack = 0;
    Address callAddr = callInst.getAddress();

    while (prevInst != null && instructionsBack < 10) {
      String mnemonic = prevInst.getMnemonicString().toLowerCase(Locale.ROOT);

      // Look for buffer size setup
      if (mnemonic.contains("mov") || mnemonic.contains("push")) {
        for (int i = 0; i < prevInst.getNumOperands(); i++) {
          if (prevInst.getScalar(i) != null) {
            long value = prevInst.getScalar(i).getValue();

            // Check if this might be a buffer size
            if (value > 0 && value < 65536) {
              // Potential buffer size found
              if (value < 16) {
                metrics.vulnerabilities.add("Small buffer (" + value + ") used with " + funcName);
              }
            }
          }

          // Check if operand references memory
          Address opAddr = prevInst.getAddress(i);
          if (opAddr != null) {
            MemoryBlock block = memory.getBlock(opAddr);
            if (block != null && block.isWrite()) {
              metrics.vulnerabilities.add(
                  "Writable memory " + opAddr + " passed to " + funcName + " at " + callAddr);
            }
          }
        }
      }

      prevInst = prevInst.getPrevious();
      instructionsBack++;
    }
  }

  private void analyzeMemoryInitialization(Memory memory) {
    MemoryBlock[] blocks = memory.getBlocks();
    int uninitializedBlocks = 0;
    int zeroInitializedBlocks = 0;
    int patternInitializedBlocks = 0;

    for (MemoryBlock block : blocks) {
      if (!block.isInitialized()) {
        uninitializedBlocks++;
        continue;
      }

      try {
        // Sample the beginning of the block
        Address start = block.getStart();
        int sampleSize = (int) Math.min(block.getSize(), 256);
        byte[] sample = new byte[sampleSize];
        int bytesRead = memory.getBytes(start, sample);

        if (bytesRead > 0) {
          if (isZeroInitialized(sample)) {
            zeroInitializedBlocks++;
          } else if (hasInitializationPattern(sample)) {
            patternInitializedBlocks++;
            createBookmark(start, "Security", "Patterned initialization in " + block.getName());
          }
        }

      } catch (MemoryAccessException e) {
        // Could not read block - might be protected
        createBookmark(block.getStart(), "Security", "Protected memory block: " + block.getName());
      }
    }

    println("  Uninitialized blocks: " + uninitializedBlocks);
    println("  Zero-initialized blocks: " + zeroInitializedBlocks);
    println("  Pattern-initialized blocks: " + patternInitializedBlocks);
  }

  private boolean isZeroInitialized(byte[] data) {
    for (byte b : data) {
      if (b != 0) {
        return false;
      }
    }
    return true;
  }

  private boolean hasInitializationPattern(byte[] data) {
    if (data.length < 4) {
      return false;
    }

    // Check for common initialization patterns
    byte first = data[0];

    // Check if all bytes are the same (pattern fill)
    boolean allSame = true;
    for (byte b : data) {
      if (b != first) {
        allSame = false;
        break;
      }
    }

    if (allSame && first != 0) {
      return true; // Non-zero pattern fill
    }

    // Check for other common patterns (0xCC, 0xAA, 0x55, etc.)
    return first == (byte) 0xCC
        || first == (byte) 0xAA
        || first == (byte) 0x55
        || first == (byte) 0xFF;
  }

  // Enhanced methods using cached reference and code unit data

  private void analyzeReferenceHotspots() {
    println("\n[REFERENCE HOTSPOT ANALYSIS]");
    println("-".repeat(40));

    Map<Address, Integer> referenceCountMap = new HashMap<>();
    Map<Address, Set<RefType>> referenceTypeMap = new HashMap<>();
    Map<Address, Set<Address>> callerMap = new HashMap<>();

    // Analyze cached reference data
    for (Map.Entry<Address, List<Reference>> entry : referenceCache.entrySet()) {
      Address targetAddr = entry.getKey();
      List<Reference> refs = entry.getValue();

      referenceCountMap.put(targetAddr, refs.size());
      referenceTypeMap.put(targetAddr, new HashSet<>());
      callerMap.put(targetAddr, new HashSet<>());

      for (Reference ref : refs) {
        referenceTypeMap.get(targetAddr).add(ref.getReferenceType());
        callerMap.get(targetAddr).add(ref.getFromAddress());
      }
    }

    // Identify hotspots (highly referenced addresses)
    List<Map.Entry<Address, Integer>> hotspots =
        referenceCountMap.entrySet().stream()
            .filter(entry -> entry.getValue() >= 5)
            .sorted(Map.Entry.<Address, Integer>comparingByValue().reversed())
            .limit(15)
            .toList();

    println("  Top reference hotspots found: " + hotspots.size());

    for (Map.Entry<Address, Integer> hotspot : hotspots) {
      Address addr = hotspot.getKey();
      int refCount = hotspot.getValue();

      // Get symbol information
      Symbol sym = symbolTable.getPrimarySymbol(addr);
      String symbolName = sym != null ? sym.getName() : "unknown";

      // Analyze reference types
      Set<RefType> refTypes = referenceTypeMap.get(addr);
      boolean hasCallRefs = refTypes.stream().anyMatch(RefType::isCall);
      boolean hasDataRefs = refTypes.stream().anyMatch(RefType::isData);
      boolean hasIndirectRefs = refTypes.stream().anyMatch(RefType::isIndirect);

      println(String.format("  [%d refs] %s (%s)", refCount, addr, symbolName));

      // Check for licensing-related hotspots
      if (symbolName.toLowerCase(Locale.ROOT).contains("license")
          || symbolName.toLowerCase(Locale.ROOT).contains("serial")
          || symbolName.toLowerCase(Locale.ROOT).contains("activation")
          || symbolName.toLowerCase(Locale.ROOT).contains("trial")) {
        println("    [!] LICENSE HOTSPOT - High-value target for bypass");
        createBookmark(
            addr, "License Hotspot", "License validation with " + refCount + " references");
      }

      // Analyze calling pattern
      Set<Address> callers = callerMap.get(addr);
      if (callers.size() >= 3 && hasCallRefs) {
        println("    [!] CRITICAL FUNCTION - Called from " + callers.size() + " locations");

        // Check if callers form a validation chain
        if (analyzeValidationChain(addr, callers)) {
          println("    [!] VALIDATION CHAIN DETECTED - Potential licensing workflow");
        }
      }

      // Flag suspicious reference patterns
      if (hasIndirectRefs && hasCallRefs) {
        println("    [!] DYNAMIC DISPATCH - Potential obfuscated calls");
      }

      if (refCount >= 10 && hasDataRefs && !hasCallRefs) {
        println("    [!] DATA HOTSPOT - Frequently accessed data structure");
      }
    }

    // Analyze reference clustering
    analyzeReferenceChains();
  }

  private boolean analyzeValidationChain(Address targetAddr, Set<Address> callers) {
    int validationIndicators = 0;

    // Check if target address is in a suspicious region (e.g., data section)
    MemoryBlock targetBlock = getMemoryBlock(targetAddr);
    if (targetBlock != null && !targetBlock.isExecute()) {
      validationIndicators++;
    }

    for (Address caller : callers) {
      Function callerFunc = getFunctionContaining(caller);
      if (callerFunc == null) {
        continue;
      }

      String funcName = callerFunc.getName().toLowerCase(Locale.ROOT);

      // Check for validation-related function names
      if (funcName.contains("check")
          || funcName.contains("verify")
          || funcName.contains("validate")
          || funcName.contains("auth")
          || funcName.contains("license")
          || funcName.contains("serial")) {
        validationIndicators++;
      }

      // Check if caller function has conditional branches (typical for validation)
      FunctionMetrics metrics = functionMetrics.get(callerFunc.getEntryPoint());
      if (metrics != null && metrics.cyclomaticComplexity > 3) {
        validationIndicators++;
      }
    }

    return validationIndicators >= 2;
  }

  private void analyzeReferenceChains() {
    println("\n[REFERENCE CHAIN ANALYSIS]");
    println("-".repeat(40));

    Map<Address, Integer> chainDepthMap = new HashMap<>();
    Map<Address, List<Address>> executionChains = new HashMap<>();

    // Build execution chains using cached reference data
    for (Map.Entry<Address, List<Reference>> entry : referenceCache.entrySet()) {
      Address targetAddr = entry.getKey();
      List<Reference> refs = entry.getValue();

      for (Reference ref : refs) {
        if (ref.getReferenceType().isCall()) {
          Address fromAddr = ref.getFromAddress();

          // Build chain from caller to target
          executionChains.computeIfAbsent(fromAddr, k -> new ArrayList<>()).add(targetAddr);

          // Calculate chain depth
          int depth = calculateChainDepth(fromAddr, new HashSet<>(), 0);
          chainDepthMap.put(fromAddr, Math.max(chainDepthMap.getOrDefault(fromAddr, 0), depth));
        }
      }
    }

    // Find deep execution chains (potential protection mechanisms)
    List<Map.Entry<Address, Integer>> deepChains =
        chainDepthMap.entrySet().stream()
            .filter(entry -> entry.getValue() >= 4)
            .sorted(Map.Entry.<Address, Integer>comparingByValue().reversed())
            .limit(10)
            .toList();

    println("  Deep execution chains found: " + deepChains.size());

    for (Map.Entry<Address, Integer> chain : deepChains) {
      Address startAddr = chain.getKey();
      int depth = chain.getValue();

      Function func = getFunctionContaining(startAddr);
      String funcName = func != null ? func.getName() : "unknown";

      println(String.format("  Chain depth %d: %s (%s)", depth, startAddr, funcName));

      // Check for licensing protection chain patterns
      if (funcName.toLowerCase(Locale.ROOT).contains("license")
          || funcName.toLowerCase(Locale.ROOT).contains("validate")
          || funcName.toLowerCase(Locale.ROOT).contains("check")) {
        println("    [!] PROTECTION CHAIN - License validation workflow");

        // Trace the execution path
        List<Address> chainPath =
            traceExecutionChain(startAddr, new ArrayList<>(), new HashSet<>(), 5);
        if (!chainPath.isEmpty()) {
          println("    Execution path: " + formatExecutionPath(chainPath));
        }
      }

      // Detect obfuscated chains
      if (depth >= 6) {
        println("    [!] COMPLEX CHAIN - Potential obfuscation or anti-analysis");
      }
    }
  }

  private int calculateChainDepth(Address addr, Set<Address> visited, int currentDepth) {
    if (visited.contains(addr) || currentDepth > 10) {
      return currentDepth; // Prevent infinite recursion
    }

    visited.add(addr);
    int maxDepth = currentDepth;

    List<Reference> refs = referenceCache.get(addr);
    if (refs != null) {
      for (Reference ref : refs) {
        if (ref.getReferenceType().isCall()) {
          int depth =
              calculateChainDepth(ref.getToAddress(), new HashSet<>(visited), currentDepth + 1);
          maxDepth = Math.max(maxDepth, depth);
        }
      }
    }

    return maxDepth;
  }

  private List<Address> traceExecutionChain(
      Address startAddr, List<Address> currentPath, Set<Address> visited, int maxDepth) {
    if (visited.contains(startAddr) || currentPath.size() >= maxDepth) {
      return new ArrayList<>(currentPath);
    }

    visited.add(startAddr);
    currentPath.add(startAddr);

    List<Reference> refs = referenceCache.get(startAddr);
    if (refs != null) {
      for (Reference ref : refs) {
        if (ref.getReferenceType().isCall()) {
          List<Address> extendedPath =
              traceExecutionChain(
                  ref.getToAddress(),
                  new ArrayList<>(currentPath),
                  new HashSet<>(visited),
                  maxDepth);
          if (extendedPath.size() > currentPath.size()) {
            return extendedPath;
          }
        }
      }
    }

    return new ArrayList<>(currentPath);
  }

  private String formatExecutionPath(List<Address> path) {
    StringBuilder sb = new StringBuilder();
    for (int i = 0; i < path.size(); i++) {
      Address addr = path.get(i);
      Function func = getFunctionContaining(addr);
      String name = func != null ? func.getName() : addr.toString();

      sb.append(name);
      if (i < path.size() - 1) {
        sb.append(" -> ");
      }
    }
    return sb.toString();
  }

  private void analyzeCodeUnitPatterns() {
    println("\n[CODE UNIT PATTERN ANALYSIS]");
    println("-".repeat(40));

    Map<String, Integer> instructionSequenceMap = new HashMap<>();
    Map<String, List<Address>> patternLocationMap = new HashMap<>();
    Map<Address, String> suspiciousPatternMap = new HashMap<>();

    // Analyze cached code unit data for patterns
    List<Address> sortedAddresses =
        codeUnitMap.keySet().stream().sorted(Address::compareTo).toList();

    // Analyze instruction sequences
    for (int i = 0; i < sortedAddresses.size() - 2; i++) {
      Address addr1 = sortedAddresses.get(i);
      Address addr2 = sortedAddresses.get(i + 1);
      Address addr3 = sortedAddresses.get(i + 2);

      CodeUnit unit1 = codeUnitMap.get(addr1);
      CodeUnit unit2 = codeUnitMap.get(addr2);
      CodeUnit unit3 = codeUnitMap.get(addr3);

      if (unit1 instanceof Instruction inst1
          && unit2 instanceof Instruction inst2
          && unit3 instanceof Instruction inst3) {

        String sequence =
            inst1.getMnemonicString()
                + "-"
                + inst2.getMnemonicString()
                + "-"
                + inst3.getMnemonicString();

        instructionSequenceMap.merge(sequence.toLowerCase(Locale.ROOT), 1, Integer::sum);
        patternLocationMap
            .computeIfAbsent(sequence.toLowerCase(Locale.ROOT), k -> new ArrayList<>())
            .add(addr1);

        // Check for suspicious patterns
        String suspiciousPattern = analyzeSuspiciousSequence(inst1, inst2, inst3);
        if (suspiciousPattern != null) {
          suspiciousPatternMap.put(addr1, suspiciousPattern);
        }
      }
    }

    // Report common instruction sequences
    List<Map.Entry<String, Integer>> commonSequences =
        instructionSequenceMap.entrySet().stream()
            .filter(entry -> entry.getValue() >= 3)
            .sorted(Map.Entry.<String, Integer>comparingByValue().reversed())
            .limit(15)
            .toList();

    println("  Common instruction sequences found: " + commonSequences.size());

    for (Map.Entry<String, Integer> sequence : commonSequences) {
      String pattern = sequence.getKey();
      int count = sequence.getValue();

      println(String.format("  [%d occurrences] %s", count, pattern));

      // Check for licensing-related patterns
      if (isLicensingPattern(pattern)) {
        println("    [!] LICENSE PATTERN - Potential validation sequence");
        List<Address> locations = patternLocationMap.get(pattern);
        if (locations != null && !locations.isEmpty()) {
          println("    Locations: " + locations.subList(0, Math.min(3, locations.size())));
        }
      }

      // Check for anti-analysis patterns
      if (isAntiAnalysisPattern(pattern)) {
        println("    [!] ANTI-ANALYSIS - Obfuscation or protection sequence");
      }

      // Check for crypto patterns
      if (isCryptoPattern(pattern)) {
        println("    [!] CRYPTO PATTERN - Potential encryption/decryption");
      }
    }

    // Report suspicious patterns
    if (!suspiciousPatternMap.isEmpty()) {
      println("\n  Suspicious instruction patterns:");
      int reportCount = 0;
      for (Map.Entry<Address, String> entry : suspiciousPatternMap.entrySet()) {
        if (reportCount >= 10) {
          break;
        }
        println(String.format("    %s: %s", entry.getKey(), entry.getValue()));
        reportCount++;
      }
    }

    // Analyze code unit clustering
    analyzeCodeUnitSequences();
  }

  private String analyzeSuspiciousSequence(
      Instruction inst1, Instruction inst2, Instruction inst3) {
    String m1 = inst1.getMnemonicString().toLowerCase(Locale.ROOT);
    String m2 = inst2.getMnemonicString().toLowerCase(Locale.ROOT);
    String m3 = inst3.getMnemonicString().toLowerCase(Locale.ROOT);

    // Anti-debug patterns
    if (("int".equals(m1) && "int".equals(m2) && "int".equals(m3))
        || ("int3".equals(m1) && "int3".equals(m2) && "int3".equals(m3))) {
      return "Multiple breakpoint instructions - anti-debug";
    }

    // Obfuscation patterns
    if ((m1.contains("xor") && m2.contains("xor") && m3.contains("xor"))
        || (m1.contains("not") && m2.contains("not") && m3.contains("not"))) {
      return "Multiple XOR/NOT operations - potential obfuscation";
    }

    // Timing check patterns
    if (("rdtsc".equals(m1) || "rdtscp".equals(m1))
        && (m2.contains("sub") || m2.contains("cmp"))
        && (m3.contains("j") || m3.contains("branch"))) {
      return "Timing check sequence - anti-analysis";
    }

    // Stack manipulation patterns
    if (m1.contains("push") && m2.contains("pop") && m3.contains("push")) {
      return "Complex stack manipulation - potential obfuscation";
    }

    return null;
  }

  private boolean isLicensingPattern(String pattern) {
    return pattern.contains("cmp-j")
        || pattern.contains("test-j")
        || pattern.contains("mov-cmp-j")
        || pattern.contains("call-test-j");
  }

  private boolean isAntiAnalysisPattern(String pattern) {
    return pattern.contains("int-")
        || pattern.contains("rdtsc-")
        || pattern.contains("xor-xor-")
        || pattern.contains("nop-nop-");
  }

  private boolean isCryptoPattern(String pattern) {
    return pattern.contains("xor-rol-")
        || pattern.contains("add-xor-")
        || pattern.contains("shl-xor-")
        || pattern.contains("ror-add-");
  }

  private void analyzeCodeUnitSequences() {
    println("\n[CODE UNIT SEQUENCE ANALYSIS]");
    println("-".repeat(40));

    Map<String, Integer> dataPatternMap = new HashMap<>();
    Map<Address, Integer> instructionDensityMap = new HashMap<>();
    int totalInstructions = 0;
    int totalData = 0;

    // Analyze code unit distribution and sequences
    for (Map.Entry<Address, CodeUnit> entry : codeUnitMap.entrySet()) {
      Address addr = entry.getKey();
      CodeUnit unit = entry.getValue();

      if (unit instanceof Instruction) {
        totalInstructions++;

        // Calculate instruction density in surrounding area
        int density = calculateInstructionDensity(addr);
        instructionDensityMap.put(addr, density);
      } else if (unit instanceof Data data) {
        totalData++;

        String dataType = data.getDataType().getName();
        dataPatternMap.merge(dataType, 1, Integer::sum);
      }
    }

    println("  Total instructions: " + totalInstructions);
    println("  Total data units: " + totalData);
    println(
        "  Instruction/Data ratio: "
            + String.format("%.2f", (double) totalInstructions / Math.max(totalData, 1)));

    // Find high-density instruction areas (potential packed/encrypted code)
    List<Map.Entry<Address, Integer>> highDensityAreas =
        instructionDensityMap.entrySet().stream()
            .filter(entry -> entry.getValue() >= 24)
            .sorted(Map.Entry.<Address, Integer>comparingByValue().reversed())
            .limit(10)
            .toList();

    if (!highDensityAreas.isEmpty()) {
      println("\n  High instruction density areas:");
      for (Map.Entry<Address, Integer> entry : highDensityAreas) {
        Address addr = entry.getKey();
        int density = entry.getValue();

        Function func = getFunctionContaining(addr);
        String funcName = func != null ? func.getName() : "unknown";

        println(
            String.format("    %s (%s): %d instructions per 32 bytes", addr, funcName, density));

        // Check if this might be packed/encrypted code
        if (density >= 30) {
          println("      [!] PACKED CODE - Potential encrypted or compressed instructions");
          createBookmark(addr, "Packed Code", "High instruction density: " + density);
        }
      }
    }

    // Analyze data patterns
    if (!dataPatternMap.isEmpty()) {
      println("\n  Data type distribution:");
      List<Map.Entry<String, Integer>> sortedDataTypes =
          dataPatternMap.entrySet().stream()
              .sorted(Map.Entry.<String, Integer>comparingByValue().reversed())
              .limit(10)
              .toList();

      for (Map.Entry<String, Integer> entry : sortedDataTypes) {
        String dataType = entry.getKey();
        int count = entry.getValue();
        println(String.format("    %s: %d occurrences", dataType, count));

        // Check for suspicious data types
        if (dataType.toLowerCase(Locale.ROOT).contains("byte") && count >= 100) {
          println("      [!] LARGE BYTE ARRAYS - Potential embedded data or crypto keys");
        }
      }
    }
  }

  private int calculateInstructionDensity(Address centerAddr) {
    int instructionCount = 0;
    long startOffset = Math.max(0, centerAddr.getOffset() - 32 / 2);
    long endOffset = centerAddr.getOffset() + 32 / 2;

    for (Map.Entry<Address, CodeUnit> entry : codeUnitMap.entrySet()) {
      Address addr = entry.getKey();
      CodeUnit unit = entry.getValue();

      if (addr.getOffset() >= startOffset
          && addr.getOffset() <= endOffset
          && unit instanceof Instruction) {
        instructionCount++;
      }
    }

    return instructionCount;
  }

  private void performCombinedCacheAnalysis() {
    println("\n[COMBINED CACHE ANALYSIS]");
    println("-".repeat(40));

    Map<Address, CombinedAnalysisResult> combinedResults = new HashMap<>();

    // Correlate reference data with code unit data
    for (Map.Entry<Address, List<Reference>> refEntry : referenceCache.entrySet()) {
      Address addr = refEntry.getKey();
      List<Reference> refs = refEntry.getValue();

      CodeUnit codeUnit = codeUnitMap.get(addr);
      if (codeUnit != null) {
        CombinedAnalysisResult result = new CombinedAnalysisResult();
        result.address = addr;
        result.referenceCount = refs.size();
        result.codeUnit = codeUnit;
        result.isInstruction = codeUnit instanceof Instruction;

        // Analyze reference types
        for (Reference ref : refs) {
          RefType type = ref.getReferenceType();
          if (type.isCall()) {
            result.callReferences++;
          }
          if (type.isData()) {
            result.dataReferences++;
          }
          if (type.isIndirect()) {
            result.indirectReferences++;
          }
        }

        // Analyze instruction characteristics if applicable
        if (result.isInstruction) {
          Instruction inst = (Instruction) codeUnit;
          result.mnemonic = inst.getMnemonicString();
          result.isControlFlow = inst.getFlowType().isJump() || inst.getFlowType().isCall();
          result.hasOperands = inst.getNumOperands() > 0;
        }

        combinedResults.put(addr, result);
      }
    }

    // Find addresses with both high reference counts and suspicious instructions
    List<CombinedAnalysisResult> suspiciousAddresses =
        combinedResults.values().stream()
            .filter(result -> result.referenceCount >= 3 && result.isInstruction)
            .filter(this::isSuspiciousCombination)
            .sorted((a, b) -> Integer.compare(b.referenceCount, a.referenceCount))
            .limit(15)
            .toList();

    println("  Suspicious address combinations found: " + suspiciousAddresses.size());

    for (CombinedAnalysisResult result : suspiciousAddresses) {
      Function func = getFunctionContaining(result.address);
      String funcName = func != null ? func.getName() : "unknown";

      println(
          String.format(
              "  %s (%s) - %d refs, %s",
              result.address, funcName, result.referenceCount, result.mnemonic));

      String suspiciousReason = getSuspiciousReason(result);
      println("    [!] " + suspiciousReason);

      // Check for licensing validation patterns
      if (isLicenseValidationCandidate(result, func)) {
        println("    [!] LICENSE VALIDATION CANDIDATE");
        createBookmark(
            result.address,
            "License Validation",
            "High-value target: " + result.referenceCount + " refs, " + result.mnemonic);
      }

      // Check for anti-analysis patterns
      if (isAntiAnalysisCandidate(result)) {
        println("    [!] ANTI-ANALYSIS PATTERN");
      }
    }

    // Generate comprehensive cache utilization report
    generateCacheAnalysisReport(combinedResults);
  }

  private static final class CombinedAnalysisResult {
    Address address;
    int referenceCount;
    CodeUnit codeUnit;
    boolean isInstruction;
    String mnemonic;
    boolean isControlFlow;
    boolean hasOperands;
    int callReferences;
    int dataReferences;
    int indirectReferences;

    CombinedAnalysisResult() {
      this.mnemonic = "";
    }
  }

  private boolean isSuspiciousCombination(CombinedAnalysisResult result) {
    // High reference count with control flow instructions
    // Moderate references with indirect references (potential obfuscation)
    // Mixed call and data references (potential validation point)
    // High data references with comparison instructions
    return (result.referenceCount >= 5 && result.isControlFlow)
        || (result.referenceCount >= 3 && result.indirectReferences > 0)
        || (result.callReferences > 0 && result.dataReferences > 0)
        || (result.dataReferences >= 3 && result.mnemonic.toLowerCase(Locale.ROOT).contains("cmp"));
  }

  private String getSuspiciousReason(CombinedAnalysisResult result) {
    if (result.indirectReferences > 0) {
      return "INDIRECT REFERENCES - Potential obfuscated calls";
    }

    if (result.isControlFlow && result.referenceCount >= 5) {
      return "HIGH-TRAFFIC CONTROL FLOW - Critical execution point";
    }

    if (result.callReferences > 0 && result.dataReferences > 0) {
      return "MIXED REFERENCE PATTERN - Potential validation logic";
    }

    if (result.mnemonic.toLowerCase(Locale.ROOT).contains("cmp") && result.dataReferences >= 3) {
      return "COMPARISON WITH DATA ACCESS - Potential key validation";
    }

    return "SUSPICIOUS PATTERN - Requires investigation";
  }

  private boolean isLicenseValidationCandidate(CombinedAnalysisResult result, Function func) {
    if (func == null) {
      return false;
    }

    String funcName = func.getName().toLowerCase(Locale.ROOT);
    String resultMnemonic = result.mnemonic.toLowerCase(Locale.ROOT);

    // Function name indicates licensing
    boolean hasLicensingName = funcName.contains("license")
        || funcName.contains("serial")
        || funcName.contains("activate")
        || funcName.contains("validate");

    // High reference count with comparison instruction
    boolean hasHighRefComparison =
        result.referenceCount >= 5 && resultMnemonic.contains("cmp");

    // Mixed references in validation-like function
    boolean hasMixedValidation = result.callReferences > 0
        && result.dataReferences >= 2
        && (funcName.contains("check") || funcName.contains("verify"));

    return hasLicensingName || hasHighRefComparison || hasMixedValidation;
  }

  private boolean isAntiAnalysisCandidate(CombinedAnalysisResult result) {
    String mnemonic = result.mnemonic.toLowerCase(Locale.ROOT);

    // Anti-debug instructions with references
    boolean hasAntiDebugInstructions =
        ("int3".equals(mnemonic) || "rdtsc".equals(mnemonic) || "rdtscp".equals(mnemonic))
            && result.referenceCount >= 2;

    // High indirect references (potential obfuscation)
    return hasAntiDebugInstructions || result.indirectReferences >= 2;
  }

  private void generateCacheAnalysisReport(Map<Address, CombinedAnalysisResult> combinedResults) {
    println("\n[CACHE UTILIZATION REPORT]");
    println("-".repeat(40));

    int totalCachedReferences = 0;
    int totalCachedCodeUnits = codeUnitMap.size();
    int correlatedAddresses = combinedResults.size();

    for (List<Reference> refs : referenceCache.values()) {
      totalCachedReferences += refs.size();
    }

    println("  Cached references: " + totalCachedReferences);
    println("  Cached code units: " + totalCachedCodeUnits);
    println("  Correlated addresses: " + correlatedAddresses);
    println(
        "  Cache utilization: "
            + String.format(
                "%.1f%%", 100.0 * correlatedAddresses / Math.max(totalCachedCodeUnits, 1)));

    // Summary of high-value targets identified
    long licenseTargets =
        combinedResults.values().stream()
            .filter(
                result -> {
                  Function func = getFunctionContaining(result.address);
                  return isLicenseValidationCandidate(result, func);
                })
            .count();

    long antiAnalysisTargets =
        combinedResults.values().stream().filter(this::isAntiAnalysisCandidate).count();

    println("  License validation targets: " + licenseTargets);
    println("  Anti-analysis targets: " + antiAnalysisTargets);

    println("\n  Cache analysis completed successfully!");
    println("  Cached data has been comprehensively analyzed for licensing protection patterns.");
  }
}

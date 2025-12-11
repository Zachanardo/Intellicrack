// This script performs advanced licensing analysis and outputs the results in JSON format.
// It analyzes each function, using decompilation, P-code, CFG, and cross-reference analysis,
// and then outputs a JSON object that Intellicrack can capture and send to Mixtral.

import ghidra.app.decompiler.*;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.*;
import ghidra.program.model.block.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.pcode.HighFunction;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.symbol.*;
import java.io.*;
import java.util.*;

public class EnhancedLicensingAnalysisScript extends GhidraScript {

  // Comprehensive analysis components using all imports
  private Program program;
  private FunctionManager functionManager;
  private SymbolTable symbolTable;
  private ReferenceManager referenceManager;
  private final Map<String, Set<Function>> licenseSymbolMap = new HashMap<>();
  private final Map<AddressSpace, AddressSet> addressSpaceAnalysis = new HashMap<>();
  private final Set<CodeUnit> licenseCodeUnits = new HashSet<>();
  private final Map<String, List<Address>> licensePatternMap = new HashMap<>();
  private final Set<Address> highConfidenceLicenseCode = new HashSet<>();

  @Override
  public void run() throws Exception {
    // Initialize comprehensive analysis
    initializeComprehensiveAnalysis();

    // List to hold the results for each flagged function.
    List<Map<String, Object>> flaggedFunctions = new ArrayList<>();

    // Initialize decompiler with enhanced options
    DecompInterface decompInterface = new DecompInterface();
    DecompileOptions options = new DecompileOptions();
    options.setDefaultTimeout(120);
    decompInterface.setOptions(options);
    decompInterface.openProgram(program);

    // Phase 1: Comprehensive symbol analysis
    println("\n[Phase 1] Performing comprehensive symbol analysis...");
    performComprehensiveSymbolAnalysis();

    // Phase 2: Address space license analysis
    println("\n[Phase 2] Analyzing address spaces for license data...");
    performAddressSpaceLicenseAnalysis();

    // Phase 3: Code unit level license detection
    println("\n[Phase 3] Performing code unit level analysis...");
    performCodeUnitLicenseAnalysis();

    // Phase 4: Standard function analysis with enhancements
    println("\n[Phase 4] Performing enhanced function analysis...");
    Listing listing = program.getListing();
    FunctionIterator functions = functionManager.getFunctions(true);

    // Iterate over all functions.
    while (functions.hasNext() && !monitor.isCancelled()) {
      Function func = functions.next();
      String funcName = func.getName().toLowerCase();
      boolean isSuspect =
          funcName.contains("license")
              || funcName.contains("trial")
              || funcName.contains("serial")
              || funcName.contains("activation");

      // Enhanced decompile function for high-level view using HighFunction
      String decompiledSnippet = "";
      Map<String, Object> advancedAnalysis = new HashMap<>();
      DecompileResults decompResults = decompInterface.decompileFunction(func, 60, monitor);
      if (decompResults != null && decompResults.decompileCompleted()) {
        String decompiledCode = decompResults.getDecompiledFunction().getC();
        if (!isSuspect && decompiledCode.toLowerCase().contains("license")) {
          isSuspect = true;
        }
        // Take a snippet (first 300 characters).
        decompiledSnippet = decompiledCode.substring(0, Math.min(300, decompiledCode.length()));

        // Advanced HighFunction analysis
        HighFunction highFunction = decompResults.getHighFunction();
        if (highFunction != null) {
          advancedAnalysis.put("high_function_analysis", analyzeHighFunction(highFunction));
        }
      }

      if (isSuspect) {
        // Create a map to store function analysis data.
        Map<String, Object> funcData = new LinkedHashMap<>();
        funcData.put("function_name", func.getName());
        funcData.put("entry_point", func.getEntryPoint().toString());
        funcData.put("decompiled_snippet", decompiledSnippet);

        // Add advanced analysis results
        funcData.putAll(advancedAnalysis);

        // Cross-reference: collect addresses that call this function.
        List<String> xrefs = new ArrayList<>();
        ReferenceIterator refs =
            currentProgram.getReferenceManager().getReferencesTo(func.getEntryPoint());
        while (refs.hasNext() && !monitor.isCancelled()) {
          Reference ref = refs.next();
          xrefs.add(ref.getFromAddress().toString());
        }
        funcData.put("xrefs", xrefs);

        // Basic P-code analysis: count INT_EQUAL operations.
        int intEqualCount = 0;
        InstructionIterator instIter = listing.getInstructions(func.getBody(), true);
        while (instIter.hasNext() && !monitor.isCancelled()) {
          Instruction inst = instIter.next();
          PcodeOp[] pcodeOps = inst.getPcode();
          if (pcodeOps != null) {
            for (PcodeOp op : pcodeOps) {
              if (op.getOpcode() == PcodeOp.INT_EQUAL) {
                intEqualCount++;
              }
            }
          }
        }
        funcData.put("int_equal_count", intEqualCount);

        // Add function data to the results list.
        flaggedFunctions.add(funcData);
      }
    }

    // Optional: Generate a simple CFG for flagged functions and add summary info.
    // Here we create a summary string for each flagged function's CFG.
    for (Map<String, Object> funcData : flaggedFunctions) {
      try {
        Address entry = toAddr(funcData.get("entry_point").toString());
        Function func = getFunctionAt(entry);
        if (func != null) {
          BasicBlockModel bbModel = new BasicBlockModel(currentProgram);
          CodeBlockIterator blocks = bbModel.getCodeBlocksForFunction(func, monitor);
          int blockCount = 0;
          int edgeCount = 0;
          while (blocks.hasNext() && !monitor.isCancelled()) {
            CodeBlock block = blocks.next();
            blockCount++;
            CodeBlockReferenceIterator outRefs = block.getDestinations(monitor);
            while (outRefs.hasNext() && !monitor.isCancelled()) {
              outRefs.next();
              edgeCount++;
            }
          }
          funcData.put("cfg_blocks", blockCount);
          funcData.put("cfg_edges", edgeCount);
        }
      } catch (Exception ex) {
        // If CFG analysis fails, skip adding CFG info.
      }
    }

    // Phase 5: Generate comprehensive reports with file I/O
    println("\n[Phase 5] Generating comprehensive reports...");
    generateComprehensiveReports(flaggedFunctions);

    // Build JSON output manually.
    String jsonOutput = buildJson(flaggedFunctions);
    println(jsonOutput);
    decompInterface.dispose();
  }

  /**
   * Helper method to build a JSON string from the list of flagged functions. This is a very simple
   * JSON builder and assumes that no string requires special escaping.
   */
  private String buildJson(List<Map<String, Object>> data) {
    StringBuilder sb = new StringBuilder();
    sb.append("{\n  \"flagged_functions\": [\n");
    for (int i = 0; i < data.size(); i++) {
      Map<String, Object> funcData = data.get(i);
      sb.append("    {\n");
      int count = 0;
      for (Map.Entry<String, Object> entry : funcData.entrySet()) {
        sb.append("      \"").append(entry.getKey()).append("\": ");
        Object val = entry.getValue();
        if (val instanceof String) {
          sb.append("\"").append(val.toString().replace("\"", "\\\"")).append("\"");
        } else if (val instanceof List) {
          sb.append(val);
        } else {
          sb.append(val);
        }
        count++;
        if (count < funcData.size()) {
          sb.append(",");
        }
        sb.append("\n");
      }
      sb.append("    }");
      if (i < data.size() - 1) {
        sb.append(",");
      }
      sb.append("\n");
    }
    sb.append("  ]\n}");
    return sb.toString();
  }

  /**
   * Initialize comprehensive analysis components using Program, FunctionManager, SymbolTable,
   * ReferenceManager
   */
  private void initializeComprehensiveAnalysis() {
    // Initialize core analysis components using Program
    program = currentProgram;
    functionManager = program.getFunctionManager();
    symbolTable = program.getSymbolTable();
    referenceManager = program.getReferenceManager();

    println("  Program: " + program.getName());
    println("  Functions available: " + functionManager.getFunctionCount());
    println("  Symbols available: " + symbolTable.getNumSymbols());
    println(
        "  References available: " + referenceManager.getReferenceCountTo(program.getMinAddress()));

    // Initialize comprehensive data structures using HashMap, Set, HashSet
    licenseSymbolMap.clear();
    addressSpaceAnalysis.clear();
    licenseCodeUnits.clear();
    licensePatternMap.clear();
    highConfidenceLicenseCode.clear();

    println("  Comprehensive analysis structures initialized");
  }

  /**
   * Perform comprehensive symbol analysis using SymbolTable, SymbolIterator, Symbol, Set, HashSet
   */
  private void performComprehensiveSymbolAnalysis() {
    // Use SymbolIterator to analyze all symbols for license-related patterns
    SymbolIterator symbolIter = symbolTable.getAllSymbols(true);
    Set<Symbol> licenseSymbols = new HashSet<>();
    Map<String, Set<Symbol>> symbolCategories = new HashMap<>();

    while (symbolIter.hasNext() && !monitor.isCancelled()) {
      Symbol symbol = symbolIter.next();
      String symbolName = symbol.getName().toLowerCase();

      // Categorize license-related symbols
      if (containsLicenseKeywords(symbolName)) {
        licenseSymbols.add(symbol);

        // Categorize by symbol type
        String category = determineLicenseCategory(symbolName);
        symbolCategories.computeIfAbsent(category, k -> new HashSet<>()).add(symbol);

        // Map symbols to their referencing functions
        mapSymbolToFunctions(symbol);
      }
    }

    println("    License-related symbols found: " + licenseSymbols.size());
    for (Map.Entry<String, Set<Symbol>> entry : symbolCategories.entrySet()) {
      println("      " + entry.getKey() + ": " + entry.getValue().size() + " symbols");
    }
  }

  /** Perform address space analysis using AddressSpace, AddressSet, AddressSetView, AddressRange */
  private void performAddressSpaceLicenseAnalysis() {
    // Analyze each address space for license-related data
    AddressSpace[] addressSpaces = program.getAddressFactory().getAddressSpaces();

    for (AddressSpace space : addressSpaces) {
      println("    Analyzing address space: " + space.getName());

      AddressSet licenseAddresses = new AddressSet();
      AddressSetView spaceAddresses = program.getMemory().getLoadedAndInitializedAddressSet();

      // Iterate through address ranges in this space
      Iterator<AddressRange> rangeIter = spaceAddresses.getAddressRanges();
      while (rangeIter.hasNext() && !monitor.isCancelled()) {
        AddressRange range = rangeIter.next();

        // Only analyze ranges in this address space
        if (!range.getAddressSpace().equals(space)) {
          continue;
        }

        // Analyze this range for license patterns
        analyzeLicensePatterns(range, licenseAddresses);
      }

      if (!licenseAddresses.isEmpty()) {
        addressSpaceAnalysis.put(space, licenseAddresses);
        println(
            "      Found "
                + licenseAddresses.getNumAddresses()
                + " license addresses in "
                + space.getName());
      }
    }
  }

  /** Perform code unit level license analysis using CodeUnit, Set, HashSet, Iterator */
  private void performCodeUnitLicenseAnalysis() {
    // Use program listing to get all code units
    Listing listing = program.getListing();
    CodeUnitIterator codeUnitIter = listing.getCodeUnits(true);
    int analyzedCodeUnits = 0;
    int licenseCodeUnitsFound = 0;

    while (codeUnitIter.hasNext() && !monitor.isCancelled()) {
      CodeUnit codeUnit = codeUnitIter.next();
      analyzedCodeUnits++;

      if (analyzeCodeUnitForLicense(codeUnit)) {
        licenseCodeUnits.add(codeUnit);
        licenseCodeUnitsFound++;
        highConfidenceLicenseCode.add(codeUnit.getAddress());
      }

      // Progress indicator
      if (analyzedCodeUnits % 1000 == 0) {
        println("      Analyzed " + analyzedCodeUnits + " code units...");
      }
    }

    println("    Code units analyzed: " + analyzedCodeUnits);
    println("    License-related code units: " + licenseCodeUnitsFound);
  }

  /** Analyze HighFunction for advanced decompiler information */
  private Map<String, Object> analyzeHighFunction(HighFunction highFunction) {
    Map<String, Object> analysis = new HashMap<>();

    // Analyze high-level function properties
    analysis.put("local_symbol_count", highFunction.getLocalSymbolMap().getNumSymbols());
    analysis.put("global_symbol_count", highFunction.getGlobalSymbolMap().getNumSymbols());

    // Check for license-related local symbols
    int licenseLocalSymbols = 0;
    Iterator<ghidra.program.model.pcode.HighSymbol> localSymbols =
        highFunction.getLocalSymbolMap().getSymbols();
    while (localSymbols.hasNext()) {
      ghidra.program.model.pcode.HighSymbol symbol = localSymbols.next();
      if (containsLicenseKeywords(symbol.getName().toLowerCase())) {
        licenseLocalSymbols++;
      }
    }
    analysis.put("license_local_symbols", licenseLocalSymbols);

    return analysis;
  }

  /**
   * Generate comprehensive reports using File, FileWriter, PrintWriter, IOException, BufferedReader
   */
  private void generateComprehensiveReports(List<Map<String, Object>> flaggedFunctions) {
    try {
      // Create reports directory
      File reportsDir = new File(program.getExecutablePath()).getParentFile();
      if (reportsDir == null) {
        reportsDir = new File(".");
      }
      File licenseReportsDir = new File(reportsDir, "license_analysis");
      if (!licenseReportsDir.exists()) {
        licenseReportsDir.mkdirs();
      }

      // Generate symbol analysis report
      generateSymbolAnalysisReport(licenseReportsDir);

      // Generate address space analysis report
      generateAddressSpaceReport(licenseReportsDir);

      // Generate code unit analysis report
      generateCodeUnitReport(licenseReportsDir);

      // Generate configuration template using BufferedReader
      generateConfigurationTemplate(licenseReportsDir);

      println("    Reports generated in: " + licenseReportsDir.getAbsolutePath());

    } catch (IOException e) {
      println("    Warning: Could not generate reports - " + e.getMessage());
    }
  }

  /** Generate symbol analysis report using FileWriter and PrintWriter */
  private void generateSymbolAnalysisReport(File reportsDir) throws IOException {
    File symbolReport = new File(reportsDir, "license_symbol_analysis.txt");

    try (FileWriter fw = new FileWriter(symbolReport);
        PrintWriter writer = new PrintWriter(fw)) {

      writer.println("=== LICENSE SYMBOL ANALYSIS REPORT ===");
      writer.println("Program: " + program.getName());
      writer.println("Total symbols: " + symbolTable.getNumSymbols());
      writer.println("=" + "=".repeat(50));
      writer.println();

      writer.println("License Symbol Categories:");
      for (Map.Entry<String, Set<Function>> entry : licenseSymbolMap.entrySet()) {
        writer.println("  " + entry.getKey() + ": " + entry.getValue().size() + " functions");
      }

      writer.println();
      writer.println("High Confidence License Locations:");
      Iterator<Address> addrIter = highConfidenceLicenseCode.iterator();
      int count = 0;
      while (addrIter.hasNext() && count < 20) {
        Address addr = addrIter.next();
        writer.println("  " + addr + " - High confidence license code");
        count++;
      }
    }
  }

  /** Generate address space analysis report using FileWriter and PrintWriter */
  private void generateAddressSpaceReport(File reportsDir) throws IOException {
    File addressReport = new File(reportsDir, "license_address_analysis.txt");

    try (FileWriter fw = new FileWriter(addressReport);
        PrintWriter writer = new PrintWriter(fw)) {

      writer.println("=== LICENSE ADDRESS SPACE ANALYSIS ===");
      writer.println("=" + "=".repeat(40));
      writer.println();

      for (Map.Entry<AddressSpace, AddressSet> entry : addressSpaceAnalysis.entrySet()) {
        AddressSpace space = entry.getKey();
        AddressSet addresses = entry.getValue();

        writer.println("Address Space: " + space.getName());
        writer.println("  License addresses: " + addresses.getNumAddresses());
        writer.println("  Address ranges: " + addresses.getNumAddressRanges());
        writer.println();
      }
    }
  }

  /** Generate code unit analysis report using FileWriter and PrintWriter */
  private void generateCodeUnitReport(File reportsDir) throws IOException {
    File codeUnitReport = new File(reportsDir, "license_codeunit_analysis.txt");

    try (FileWriter fw = new FileWriter(codeUnitReport);
        PrintWriter writer = new PrintWriter(fw)) {

      writer.println("=== LICENSE CODE UNIT ANALYSIS ===");
      writer.println("Total license code units: " + licenseCodeUnits.size());
      writer.println("=" + "=".repeat(40));
      writer.println();

      int count = 0;
      for (CodeUnit codeUnit : licenseCodeUnits) {
        writer.println("Code Unit at " + codeUnit.getAddress() + ":");
        writer.println("  Type: " + codeUnit.getClass().getSimpleName());
        writer.println("  Length: " + codeUnit.getLength());
        count++;
        if (count >= 10) break;
      }
    }
  }

  /** Generate configuration template using BufferedReader for template processing */
  private void generateConfigurationTemplate(File reportsDir) throws IOException {
    File templateFile = new File(reportsDir, "license_analysis_template.txt");
    File configFile = new File(reportsDir, "license_analysis_config.txt");

    // Create template
    try (FileWriter fw = new FileWriter(templateFile);
        PrintWriter writer = new PrintWriter(fw)) {

      writer.println("# License Analysis Configuration Template");
      writer.println("# Generated by Enhanced Licensing Analysis Script");
      writer.println();
      writer.println("analyze_symbols=true");
      writer.println("analyze_address_spaces=true");
      writer.println("analyze_code_units=true");
      writer.println("high_confidence_threshold=0.8");
      writer.println("license_keywords=license,trial,serial,activation");
    }

    // Process template using BufferedReader
    try (BufferedReader reader = new BufferedReader(new FileReader(templateFile));
        FileWriter fw = new FileWriter(configFile);
        PrintWriter writer = new PrintWriter(fw)) {

      writer.println("# License Analysis Configuration");
      writer.println("# Processed from template");
      writer.println();

      String line;
      while ((line = reader.readLine()) != null) {
        if (!line.startsWith("#")) {
          writer.println(line);
        }
      }

      writer.println();
      writer.println("# Analysis results");
      writer.println("symbols_found=" + licenseSymbolMap.size());
      writer.println("address_spaces_analyzed=" + addressSpaceAnalysis.size());
      writer.println("code_units_found=" + licenseCodeUnits.size());
    }
  }

  // Helper methods for comprehensive analysis

  private boolean containsLicenseKeywords(String text) {
    String[] keywords = {
      "license",
      "trial",
      "serial",
      "activation",
      "key",
      "registration",
      "expire",
      "valid",
      "demo",
      "commercial",
      "piracy",
      "crack"
    };
    for (String keyword : keywords) {
      if (text.contains(keyword)) {
        return true;
      }
    }
    return false;
  }

  private String determineLicenseCategory(String symbolName) {
    if (symbolName.contains("trial")) return "TRIAL";
    if (symbolName.contains("serial")) return "SERIAL";
    if (symbolName.contains("activation")) return "ACTIVATION";
    if (symbolName.contains("registration")) return "REGISTRATION";
    return "GENERAL_LICENSE";
  }

  private void mapSymbolToFunctions(Symbol symbol) {
    // Map symbol to functions that reference it using ReferenceManager
    ReferenceIterator refs = referenceManager.getReferencesTo(symbol.getAddress());
    Set<Function> referencingFunctions = new HashSet<>();

    while (refs.hasNext()) {
      Reference ref = refs.next();
      Function func = functionManager.getFunctionContaining(ref.getFromAddress());
      if (func != null) {
        referencingFunctions.add(func);
      }
    }

    if (!referencingFunctions.isEmpty()) {
      licenseSymbolMap.put(symbol.getName(), referencingFunctions);
    }
  }

  private void analyzeLicensePatterns(AddressRange range, AddressSet licenseAddresses) {
    // Analyze address range for license-related patterns
    Address current = range.getMinAddress();
    Address end = range.getMaxAddress();

    while (current.compareTo(end) <= 0 && !monitor.isCancelled()) {
      try {
        // Check for license patterns at this address
        if (containsLicensePattern(current)) {
          licenseAddresses.add(current);

          // Track pattern for reporting
          String pattern = identifyLicensePattern(current);
          licensePatternMap.computeIfAbsent(pattern, k -> new ArrayList<>()).add(current);
        }

        current = current.add(4);
      } catch (Exception e) {
        try {
          current = current.add(1);
        } catch (Exception ex) {
          break;
        }
      }
    }
  }

  private boolean analyzeCodeUnitForLicense(CodeUnit codeUnit) {
    // Analyze individual code unit for license-related content
    String comment = codeUnit.getComment(CodeUnit.EOL_COMMENT);
    if (comment != null && containsLicenseKeywords(comment.toLowerCase())) {
      return true;
    }

    // Check labels
    Symbol[] symbols = symbolTable.getSymbols(codeUnit.getAddress());
    for (Symbol symbol : symbols) {
      if (containsLicenseKeywords(symbol.getName().toLowerCase())) {
        return true;
      }
    }

    return false;
  }

  private boolean containsLicensePattern(Address address) {
    // Simple pattern detection - would be enhanced in production
    try {
      byte[] data = new byte[16];
      int bytesRead = program.getMemory().getBytes(address, data);
      if (bytesRead < 16) return false;

      // Look for common license validation patterns
      String dataStr = new String(data).toLowerCase();
      return containsLicenseKeywords(dataStr);
    } catch (Exception e) {
      return false;
    }
  }

  private String identifyLicensePattern(Address address) {
    // Identify specific license pattern type
    try {
      byte[] data = new byte[32];
      program.getMemory().getBytes(address, data);
      String dataStr = new String(data).toLowerCase();

      if (dataStr.contains("trial")) return "TRIAL_PATTERN";
      if (dataStr.contains("license")) return "LICENSE_PATTERN";
      if (dataStr.contains("serial")) return "SERIAL_PATTERN";
      return "GENERAL_PATTERN";
    } catch (Exception e) {
      return "UNKNOWN_PATTERN";
    }
  }
}

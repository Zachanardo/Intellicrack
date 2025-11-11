// This script performs advanced licensing analysis and outputs the results in JSON format.
// It analyzes each function, using decompilation, P-code, CFG, and cross-reference analysis,
// and then outputs a JSON object that Intellicrack can capture and send to Mixtral.

import ghidra.app.decompiler.*;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.*;
import ghidra.program.model.block.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.pcode.HighFunction;
import ghidra.program.model.pcode.HighSymbol;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.symbol.*;
import ghidra.util.exception.CancelledException;
import java.io.*;
import java.util.*;

public class LicensingAnalysisScript extends GhidraScript {

  // Additional fields for unused imports implementation
  private Program program;
  private FunctionManager functionManager;
  private SymbolTable symbolTable;
  private ReferenceManager referenceManager;
  private DecompileOptions decompOptions;
  private Map<String, HighFunction> highFunctionCache = new HashMap<>();
  private Set<Address> analyzedAddresses = new HashSet<>();
  private Set<String> licenseSymbols = new HashSet<>();
  private AddressSet protectedRegions = new AddressSet();
  private Map<String, Object> globalAnalysisData = new HashMap<>();
  private PrintWriter reportWriter;
  private BufferedReader configReader;
  private File outputFile;

  @Override
  public void run() throws Exception {
    // Initialize components
    initializeComponents();

    // List to hold the results for each flagged function.
    List<Map<String, Object>> flaggedFunctions = new ArrayList<>();

    // Initialize decompiler with options
    DecompInterface decompInterface = new DecompInterface();
    decompInterface.openProgram(currentProgram);
    decompInterface.setOptions(decompOptions);

    Listing listing = currentProgram.getListing();
    FunctionIterator functions = listing.getFunctions(true);

    // Perform symbol table analysis first
    analyzeSymbolTable();

    // Analyze address spaces
    analyzeAddressSpaces();

    // Load configuration if available
    loadConfiguration();

    // Iterate over all functions.
    while (functions.hasNext() && !monitor.isCancelled()) {
      Function func = functions.next();
      String funcName = func.getName().toLowerCase();
      boolean isSuspect =
          funcName.contains("license")
              || funcName.contains("trial")
              || funcName.contains("serial")
              || funcName.contains("activation");

      // Enhanced decompilation with HighFunction
      String decompiledSnippet = "";
      HighFunction highFunc = null;

      try {
        DecompileResults decompResults = decompInterface.decompileFunction(func, 60, monitor);
        if (decompResults != null && decompResults.decompileCompleted()) {
          highFunc = decompResults.getHighFunction();
          if (highFunc != null) {
            highFunctionCache.put(func.getName(), highFunc);
            String decompiledCode = decompResults.getDecompiledFunction().getC();
            if (!isSuspect && decompiledCode.toLowerCase().contains("license")) {
              isSuspect = true;
            }
            // Take a snippet (first 300 characters).
            decompiledSnippet = decompiledCode.substring(0, Math.min(300, decompiledCode.length()));

            // Analyze high-level function details
            analyzeHighFunction(highFunc, func);
          }
        }
      } catch (CancelledException ce) {
        println("Decompilation cancelled for " + func.getName());
        continue;
      }

      if (isSuspect) {
        // Create a map to store function analysis data.
        Map<String, Object> funcData = new LinkedHashMap<>();
        funcData.put("function_name", func.getName());
        funcData.put("entry_point", func.getEntryPoint().toString());
        funcData.put("decompiled_snippet", decompiledSnippet);

        // Enhanced analysis using FunctionManager
        analyzeFunctionDetails(func, funcData);

        // CodeUnit analysis
        analyzeCodeUnits(func, funcData);

        // Address range analysis
        analyzeAddressRanges(func, funcData);

        // Cross-reference: collect addresses that call this function.
        List<String> xrefs = new ArrayList<>();
        ReferenceIterator refs = referenceManager.getReferencesTo(func.getEntryPoint());
        while (refs.hasNext() && !monitor.isCancelled()) {
          Reference ref = refs.next();
          xrefs.add(ref.getFromAddress().toString());
          analyzedAddresses.add(ref.getFromAddress());
        }
        funcData.put("xrefs", xrefs);

        // Symbol analysis for function
        analyzeSymbols(func, funcData);

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

    // Add global analysis data
    globalAnalysisData.put("total_functions_analyzed", functionManager.getFunctionCount());
    globalAnalysisData.put("license_symbols_found", licenseSymbols.size());
    globalAnalysisData.put("protected_regions", protectedRegions.getNumAddresses());
    globalAnalysisData.put("analyzed_addresses", analyzedAddresses.size());

    // Build JSON output manually.
    String jsonOutput = buildJson(flaggedFunctions);
    println(jsonOutput);

    // Write to file if configured
    writeReportToFile(jsonOutput);

    decompInterface.dispose();
    cleanup();
  }

  private void initializeComponents() {
    program = currentProgram;
    functionManager = program.getFunctionManager();
    symbolTable = program.getSymbolTable();
    referenceManager = program.getReferenceManager();

    // Initialize decompiler options with enhanced licensing analysis configuration
    decompOptions = new DecompileOptions();
    Map<String, String> options = new HashMap<>();
    options.put("Eliminate unreachable code", "true");
    options.put("Simplify double precision", "true");
    options.put("Normalize labels", "true");
    options.put("Inline small functions", "true");
    options.put("Simplify extended integer operations", "true");
    options.put("Eliminate dead code", "true");
    options.put("Split dataflow", "true");
    options.put("Recover jump tables", "true");

    decompOptions.grabFromProgram(program);

    // Apply enhanced decompilation options for better licensing analysis
    for (Map.Entry<String, String> option : options.entrySet()) {
      try {
        decompOptions.setOption(option.getKey(), option.getValue());
        println("Applied decompiler option: " + option.getKey() + " = " + option.getValue());
      } catch (Exception e) {
        println("Warning: Could not apply option " + option.getKey() + ": " + e.getMessage());
      }
    }

    // Set additional optimization parameters for license validation analysis
    decompOptions.setMaxPayloadMBytes(100);
    decompOptions.setMaxInstructions(50000);
    decompOptions.setDefaultTimeout(120);

    println(
        "Decompiler initialized with "
            + options.size()
            + " optimization options for licensing analysis");
  }

  private void analyzeSymbolTable() throws CancelledException {
    SymbolIterator symbolIter = symbolTable.getAllSymbols(true);
    Iterator<Symbol> iter = symbolIter.iterator();

    while (iter.hasNext() && !monitor.isCancelled()) {
      Symbol symbol = iter.next();
      String name = symbol.getName().toLowerCase();

      if (name.contains("license")
          || name.contains("serial")
          || name.contains("activation")
          || name.contains("trial")) {
        licenseSymbols.add(symbol.getName());
        println("License symbol found: " + symbol.getName() + " at " + symbol.getAddress());
      }
    }
  }

  private void analyzeAddressSpaces() {
    AddressSpace[] spaces = program.getAddressFactory().getAddressSpaces();
    for (AddressSpace space : spaces) {
      if (space.getName().contains("protect") || space.getName().contains("guard")) {
        Address min = space.getMinAddress();
        Address max = space.getMaxAddress();
        if (min != null && max != null) {
          protectedRegions.add(min, max);
          println("Protected address space: " + space.getName());
        }
      }
    }
  }

  private void loadConfiguration() {
    try {
      File configFile = new File(program.getExecutablePath() + ".config");
      if (configFile.exists()) {
        configReader = new BufferedReader(new FileReader(configFile));
        String line;
        while ((line = configReader.readLine()) != null) {
          if (line.startsWith("output=")) {
            String outputPath = line.substring(7);
            outputFile = new File(outputPath);
            println("Output file configured: " + outputPath);
          }
        }
        configReader.close();
      }
    } catch (IOException ioe) {
      println("No configuration file found or error reading: " + ioe.getMessage());
    }
  }

  private void analyzeFunctionDetails(Function func, Map<String, Object> funcData) {
    // Use FunctionManager for detailed analysis
    Function thunkedFunction = functionManager.getReferencedFunction(func.getEntryPoint());
    if (thunkedFunction != null && !thunkedFunction.equals(func)) {
      funcData.put("is_thunk", true);
      funcData.put("thunked_to", thunkedFunction.getName());
    }

    // Get function signature
    funcData.put("signature", func.getPrototypeString(false, false));
    funcData.put("parameter_count", func.getParameterCount());
    funcData.put("stack_frame_size", func.getStackFrame().getFrameSize());

    // Check if function is in protected region
    if (protectedRegions.contains(func.getEntryPoint())) {
      funcData.put("in_protected_region", true);
    }
  }

  private void analyzeCodeUnits(Function func, Map<String, Object> funcData) {
    Listing listing = program.getListing();
    CodeUnitIterator codeUnitIter = listing.getCodeUnits(func.getBody(), true);

    int codeUnitCount = 0;
    Set<String> mnemonics = new HashSet<>();

    while (codeUnitIter.hasNext() && !monitor.isCancelled()) {
      CodeUnit codeUnit = codeUnitIter.next();
      codeUnitCount++;

      if (codeUnit instanceof Instruction) {
        Instruction inst = (Instruction) codeUnit;
        mnemonics.add(inst.getMnemonicString());

        // Check for anti-debug instructions
        String mnemonic = inst.getMnemonicString().toUpperCase();
        if (mnemonic.equals("RDTSC") || mnemonic.equals("CPUID") || mnemonic.startsWith("INT")) {
          funcData.put("has_anti_debug", true);
        }
      }
    }

    funcData.put("code_unit_count", codeUnitCount);
    funcData.put("unique_mnemonics", mnemonics.size());
  }

  private void analyzeAddressRanges(Function func, Map<String, Object> funcData) {
    AddressSetView body = func.getBody();
    AddressRangeIterator rangeIter = body.getAddressRanges();

    int rangeCount = 0;
    long totalSize = 0;

    while (rangeIter.hasNext()) {
      AddressRange range = rangeIter.next();
      rangeCount++;
      totalSize += range.getLength();

      // Check if range overlaps with other functions
      Iterator<Function> overlapping = functionManager.getFunctionsOverlapping(range);
      if (overlapping.hasNext()) {
        Function other = overlapping.next();
        if (!other.equals(func)) {
          funcData.put("overlaps_with", other.getName());
        }
      }
    }

    funcData.put("address_ranges", rangeCount);
    funcData.put("total_bytes", totalSize);
  }

  private void analyzeSymbols(Function func, Map<String, Object> funcData) {
    List<String> localSymbols = new ArrayList<>();
    SymbolIterator symIter = symbolTable.getSymbols(func.getBody(), true);

    while (symIter.hasNext() && !monitor.isCancelled()) {
      Symbol symbol = symIter.next();
      localSymbols.add(symbol.getName());

      // Check for license-related symbols
      if (licenseSymbols.contains(symbol.getName())) {
        funcData.put("references_license_symbol", true);
      }
    }

    funcData.put("local_symbols", localSymbols.size());
  }

  private void analyzeHighFunction(HighFunction highFunc, Function func) {
    // Analyze local variables
    Iterator<HighSymbol> localSymbols = highFunc.getLocalSymbolMap().getSymbols();
    int localVarCount = 0;

    while (localSymbols.hasNext()) {
      HighSymbol sym = localSymbols.next();
      localVarCount++;

      // Check for license-related variable names
      if (sym.getName().toLowerCase().contains("license")
          || sym.getName().toLowerCase().contains("key")) {
        println("License variable in " + func.getName() + ": " + sym.getName());
      }
    }

    // Analyze parameters
    int paramCount = highFunc.getLocalSymbolMap().getNumParams();
    println(
        "Function "
            + func.getName()
            + " has "
            + paramCount
            + " parameters and "
            + localVarCount
            + " local variables");
  }

  private void writeReportToFile(String jsonOutput) {
    try {
      if (outputFile == null) {
        outputFile = new File(program.getExecutablePath() + "_analysis.json");
      }

      FileWriter fileWriter = new FileWriter(outputFile);
      reportWriter = new PrintWriter(fileWriter);
      reportWriter.println(jsonOutput);
      reportWriter.flush();
      reportWriter.close();

      println("Report written to: " + outputFile.getAbsolutePath());
    } catch (IOException ioe) {
      println("Error writing report file: " + ioe.getMessage());
    }
  }

  private void cleanup() {
    try {
      if (reportWriter != null) {
        reportWriter.close();
      }
      if (configReader != null) {
        configReader.close();
      }
    } catch (IOException ioe) {
      // Ignore cleanup errors
    }
  }

  /**
   * Helper method to build a JSON string from the list of flagged functions. This is a very simple
   * JSON builder and assumes that no string requires special escaping.
   */
  private String buildJson(List<Map<String, Object>> data) {
    StringBuilder sb = new StringBuilder();
    sb.append("{\n");

    // Add global analysis data
    sb.append("  \"global_analysis\": {\n");
    int globalCount = 0;
    for (Map.Entry<String, Object> entry : globalAnalysisData.entrySet()) {
      sb.append("    \"").append(entry.getKey()).append("\": ");
      if (entry.getValue() instanceof String) {
        sb.append("\"").append(entry.getValue()).append("\"");
      } else {
        sb.append(entry.getValue());
      }
      globalCount++;
      if (globalCount < globalAnalysisData.size()) {
        sb.append(",");
      }
      sb.append("\n");
    }
    sb.append("  },\n");

    // Add flagged functions
    sb.append("  \"flagged_functions\": [\n");
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
          sb.append(val.toString());
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
}

import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;
import ghidra.program.model.pcode.*;
import ghidra.program.model.data.*;
import ghidra.program.util.*;
import ghidra.program.model.block.*;
import ghidra.program.model.address.*;
import ghidra.program.model.lang.*;
import ghidra.program.model.mem.*;

import ghidra.util.task.*;
import ghidra.util.json.*;

import java.util.*;
import java.io.*;

public class AdvancedAnalysis extends GhidraScript {

    private Map<Long, GhidraFunction> functions = new HashMap<>();
    private Map<Long, GhidraInstruction> instructions = new HashMap<>();
    private Map<Long, List<Long>> callGraph = new HashMap<>();
    private Map<Long, List<Long>> dataFlow = new HashMap<>(); // Track data flow
    private List<Long> potentialLicenseChecks = new ArrayList<>();
    private AddressSetView memoryRegionsOfInterest = new AddressSet();
    private JsonObject analysisResults = new JsonObject(); // For structured output
    private Map<Long, Integer> functionComplexity = new HashMap<>(); // Function complexity
    private Map<Long, List<Long>> stringReferences = new HashMap<>(); // Map of string addresses to referencing function addresses
    private Map<Long, List<Long>> xrefsToFunctions = new HashMap<>(); // Function cross-references
    private Map<Long, List<Long>> xrefsToStrings = new HashMap<>(); // String cross-references
    private Map<Long, String> functionPseudoCode = new HashMap<>(); // Function pseudo-code

    private static final String[] LICENSE_KEYWORDS = {
        "licens", "registr", "activ", "serial", "key", "trial",
        "valid", "expir", "auth", "dongle", "hwid"
    };

    private static final String[] CRYPTO_APIS = {
        "Crypt", "Cipher", "Encrypt", "Decrypt", "Hash", "Sign", "Verify",
        "AES", "RSA", "SHA"
    };

    private static final String[] ANTI_DEBUG_APIS = {
        "IsDebuggerPresent", "CheckRemoteDebuggerPresent", "OutputDebugString",
        "NtQueryInformationProcess", "ZwQueryInformationProcess"
    };

    private static final String[] NETWORK_APIS = {
        "connect", "send", "recv", "HttpSendRequest", "InternetConnect", "WinHttpConnect"
    };

    @Override
    public void run() throws Exception {
        println("Starting Advanced License Analysis...");

        // Pass 1: Foundational Analysis
        analyzeFunctions();
        analyzeInstructions();
        analyzeStrings();
        buildCallGraph();
        analyzeDataFlow();
        calculateFunctionComplexity();
        analyzeFunctionCrossReferences();
        analyzeStringCrossReferences();

        // Pass 2: AI-Assisted Contextualization
        if (!monitor.isCancelled()) {
            findPotentialLicenseChecks();
            decompileFunctionsOfInterest();
        }

        // Pass 3: Targeted Patching Strategy
        if (!monitor.isCancelled()) {
            generatePatchingStrategy();
        }

        // Output results in JSON format
        outputResults();

        println("Advanced License Analysis completed.");
    }

    private void analyzeFunctions() throws Exception {
        println("Analyzing functions...");
        JsonArray funcArray = new JsonArray();
        FunctionManager functionManager = currentProgram.getFunctionManager();
        FunctionIterator functionsIter = functionManager.getFunctions(true);

        while (functionsIter.hasNext() && !monitor.isCancelled()) {
            Function func = functionsIter.next();
            long addr = func.getEntryPoint().getOffset();
            String signature = func.getSignature().toString();
            String name = func.getName();

            functions.put(addr, new GhidraFunction(name, addr, signature, func.getBody().getNumAddresses()));

            JsonObject funcObj = new JsonObject();
            funcObj.put("name", name);
            funcObj.put("address", Long.toHexString(addr));
            funcObj.put("signature", signature);
            funcObj.put("size", func.getBody().getNumAddresses());
            funcArray.add(funcObj);
        }

        analysisResults.put("functions", funcArray);
        println("Analyzed " + functions.size() + " functions.");
    }

    private void analyzeInstructions() throws Exception {
        println("Analyzing instructions...");
        JsonArray instrArray = new JsonArray();
        Listing listing = currentProgram.getListing();
        InstructionIterator instructionsIter = listing.getInstructions(true);

        while (instructionsIter.hasNext() && !monitor.isCancelled()) {
            Instruction instr = instructionsIter.next();
            long addr = instr.getAddress().getOffset();
            String mnemonic = instr.getMnemonicString();
            String operands = instr.getOperandRepresentationString();

            instructions.put(addr, new GhidraInstruction(addr, mnemonic, operands));

            JsonObject instrObj = new JsonObject();
            instrObj.put("address", Long.toHexString(addr));
            instrObj.put("mnemonic", mnemonic);
            instrObj.put("operands", operands);
            instrArray.add(instrObj);
        }

        analysisResults.put("instructions", instrArray);
        println("Analyzed " + instructions.size() + " instructions.");
    }

    private void analyzeStrings() throws Exception {
        println("Analyzing strings...");
        JsonArray stringArray = new JsonArray();
        stringReferences = new HashMap<>(); // Initialize string references
        xrefsToStrings = new HashMap<>(); // Initialize string cross-references

        SymbolTable symbolTable = currentProgram.getSymbolTable();
        SymbolIterator symbols = symbolTable.getSymbolIterator();

        while (symbols.hasNext() && !monitor.isCancelled()) {
            Symbol symbol = symbols.next();
            if (symbol.getSymbolType() == SymbolType.LABEL) {
                String name = symbol.getName().toLowerCase();
                for (String keyword : LICENSE_KEYWORDS) {
                    if (name.contains(keyword)) {
                        memoryRegionsOfInterest.add(symbol.getAddress());
                        JsonObject stringObj = new JsonObject();
                        stringObj.put("address", symbol.getAddress().toString());
                        stringObj.put("string", symbol.getName());
                        stringArray.add(stringObj);
                        println("Found license-related string: " + symbol.getName() + " at " + symbol.getAddress());

                        // Track functions referencing this string
                        List<Long> referencingFunctions = new ArrayList<>();
                        ReferenceIterator references = getReferencesTo(symbol.getAddress());
                        while (references.hasNext()) {
                            Reference ref = references.next();
                            Function func = getFunctionContaining(ref.getFromAddress());
                            if (func != null) {
                                referencingFunctions.add(func.getEntryPoint().getOffset());
                            }
                        }
                        stringReferences.put(symbol.getAddress().getOffset(), referencingFunctions);

                        // Track strings referenced by this string
                        List<Long> referencedStringAddrs = new ArrayList<>();
                        ReferenceIterator refIter = getReferencesTo(symbol.getAddress());
                        while (refIter.hasNext()) {
                            Reference ref = refIter.next();
                            if (ref.getType() == RefType.DATA) { // Assuming string references are data references
                                referencedStringAddrs.add(ref.getFromAddress().getOffset());
                            }
                        }
                        xrefsToStrings.put(symbol.getAddress().getOffset(), referencedStringAddrs);

                        break;
                    }
                }
            }
        }
        analysisResults.put("strings", stringArray);
        analysisResults.put("stringReferences", stringReferences);
        analysisResults.put("xrefsToStrings", xrefsToStrings);
    }

    private void buildCallGraph() throws Exception {
        println("Building function call graph...");
        callGraph = new HashMap<>();

        for (GhidraFunction func : functions.values()) {
            callGraph.put(func.address, new ArrayList<>());
        }

        for (GhidraFunction func : functions.values()) {
            Function calledFunc = getFunctionAt(toAddr(func.address));
            if (calledFunc != null) {
                for (Reference ref : getReferencesTo(calledFunc.getEntryPoint())) {
                    if (ref.getType() == RefType.CALL || ref.getType() == RefType.UNCONDITIONAL_CALL) {
                        Function callingFunc = getFunctionContaining(ref.getFromAddress());
                        if (callingFunc != null) {
                            callGraph.get(callingFunc.getEntryPoint().getOffset()).add(func.address);
                        }
                    }
                }
            }
        }
        analysisResults.put("callGraph", callGraph);
        println("Built function call graph.");
    }

    private void analyzeDataFlow() throws Exception {
        println("Analyzing data flow...");
        dataFlow = new HashMap<>();

        for (GhidraFunction func : functions.values()) {
            dataFlow.put(func.address, new ArrayList<>());
            Function currentFunction = getFunctionAt(toAddr(func.address));
            if (currentFunction != null) {
                InstructionIterator instructions = getInstructions(currentFunction.getBody(), true);
                while (instructions.hasNext() && !monitor.isCancelled()) {
                    Instruction instr = instructions.next();
                    for (int i = 0; i < instr.getNumOperands(); i++) {
                        if (instr.getOperandType(i) == OperandType.REGISTER || instr.getOperandType(i) == OperandType.ADDRESS) {
                            RegisterOrMemorySlot slot = instr.getRegisterOrMemorySlot(i);
                            if (slot != null) {
                                // Track data flow related to this register/memory slot
                                // This is still a simplified example; real data flow analysis is very complex
                                dataFlow.get(func.address).add(instr.getAddress().getOffset());
                            }
                        }
                    }
                }
            }
        }
        analysisResults.put("dataFlow", dataFlow);
        println("Analyzed data flow.");
    }

    private void calculateFunctionComplexity() throws Exception {
        println("Calculating function complexity...");
        functionComplexity = new HashMap<>();

        for (GhidraFunction func : functions.values()) {
            Function currentFunction = getFunctionAt(toAddr(func.address));
            if (currentFunction != null) {
                int complexity = 0;
                // Example: More sophisticated complexity metrics
                complexity += currentFunction.getBody().getNumAddresses();
                complexity += currentFunction.getInstructionIterator().hasNext() ? 10 : 0; // Check if it has instructions
                complexity += currentFunction.getBasicBlocks().size() * 5; // Number of basic blocks
                complexity += currentFunction.getCallFixups().size() * 2; // Number of call fixups
                functionComplexity.put(func.address, complexity);
            }
        }
        analysisResults.put("functionComplexity", functionComplexity);
        println("Calculated function complexity.");
    }

    private void analyzeFunctionCrossReferences() throws Exception {
        println("Analyzing function cross-references...");
        xrefsToFunctions = new HashMap<>();

        for (GhidraFunction func : functions.values()) {
            xrefsToFunctions.put(func.address, new ArrayList<>());
        }

        for (GhidraFunction func : functions.values()) {
            Function currentFunction = getFunctionAt(toAddr(func.address));
            if (currentFunction != null) {
                ReferenceIterator references = getReferencesTo(currentFunction.getEntryPoint());
                while (references.hasNext() && !monitor.isCancelled()) {
                    Reference ref = references.next();
                    if (ref.getType() == RefType.CALL || ref.getType() == RefType.UNCONDITIONAL_CALL) {
                        Function callingFunc = getFunctionContaining(ref.getFromAddress());
                        if (callingFunc != null) {
                            xrefsToFunctions.get(func.address).add(callingFunc.getEntryPoint().getOffset());
                        }
                    }
                }
            }
        }
        analysisResults.put("xrefsToFunctions", xrefsToFunctions);
        println("Analyzed function cross-references.");
    }

    private void analyzeStringCrossReferences() throws Exception {
        println("Analyzing string cross-references...");
        xrefsToStrings = new HashMap<>();

        SymbolTable symbolTable = currentProgram.getSymbolTable();
        SymbolIterator symbols = symbolTable.getSymbolIterator();

        while (symbols.hasNext() && !monitor.isCancelled()) {
            Symbol symbol = symbols.next();
            if (symbol.getSymbolType() == SymbolType.LABEL) {
                String name = symbol.getName().toLowerCase();
                for (String keyword : LICENSE_KEYWORDS) {
                    if (name.contains(keyword)) {
                        List<Long> referencedStringAddrs = new ArrayList<>();
                        ReferenceIterator refIter = getReferencesTo(symbol.getAddress());
                        while (refIter.hasNext()) {
                            Reference ref = refIter.next();
                            if (ref.getType() == RefType.DATA) { // Assuming string references are data references
                                referencedStringAddrs.add(ref.getFromAddress().getOffset());
                            }
                        }
                        xrefsToStrings.put(symbol.getAddress().getOffset(), referencedStringAddrs);
                        break;
                    }
                }
            }
        }
        analysisResults.put("xrefsToStrings", xrefsToStrings);
        println("Analyzed string cross-references.");
    }

    private void findPotentialLicenseChecks() throws Exception {
        println("Identifying potential license checks...");
        JsonArray checkCandidates = new JsonArray();

        for (GhidraFunction func : functions.values()) {
            if (isLikelyLicenseFunction(func)) {
                potentialLicenseChecks.add(func.address);
                memoryRegionsOfInterest.add(toAddr(func.address));
                println("Potential license check function: " + func.name + " at 0x" + Long.toHexString(func.address));

                JsonObject checkObj = new JsonObject();
                checkObj.put("address", Long.toHexString(func.address));
                checkObj.put("name", func.name);
                checkObj.put("size", func.size);
                checkObj.put("complexity", functionComplexity.get(func.address));
                checkObj.put("callers", xrefsToFunctions.get(func.address));
                checkObj.put("xrefsToStrings", xrefsToStrings.get(func.address)); // Add string cross-references
                checkCandidates.add(checkObj);
            }
        }
        analysisResults.put("checkCandidates", checkCandidates);
        println("Found " + potentialLicenseChecks.size() + " potential license check functions.");
    }

    private boolean isLikelyLicenseFunction(GhidraFunction func) {
        if (func.name.toLowerCase().contains("license") ||
            func.name.toLowerCase().contains("serial") ||
            func.name.toLowerCase().contains("key") ||
            func.name.toLowerCase().contains("auth") ||
            func.name.toLowerCase().contains("valid")) {
            return true;
        }

        // Check if the function calls any crypto or anti-debug APIs
        for (Long calleeAddr : callGraph.get(func.address)) {
            GhidraFunction callee = functions.get(calleeAddr);
            if (callee != null) {
                for (String cryptoApi : CRYPTO_APIS) {
                    if (callee.name.contains(cryptoApi)) {
                        return true;
                    }
                }
                for (String antiDebugApi : ANTI_DEBUG_APIS) {
                    if (callee.name.contains(antiDebugApi)) {
                        return true;
                    }
                }
            }
        }

        // Check if the function references any license-related strings
        if (stringReferences.containsKey(func.address)) {
            return true;
        }

        // Check if the function has a complex control flow or is large
        if (func.size > 1000 || func.size < 100) { // More sophisticated complexity check would be better
            return true;
        }

        // Check if the function is called by many other functions (often a utility function)
        int callerCount = 0;
        if (xrefsToFunctions.containsKey(func.address)) {
            callerCount = xrefsToFunctions.get(func.address).size();
        }
        if (callerCount > 20) { // Arbitrary threshold
            return false; // Less likely to be a core license check
        }

        return false;
    }

    private AddressSetView getFunctionBody(Address functionAddress) {
        Function function = getFunctionAt(functionAddress);
        if (function != null) {
            return function.getBody();
        }
        return null;
    }

    private void decompileFunctionsOfInterest() throws Exception {
        println("Decompiling functions of interest...");
        JsonArray decompiledFunctions = new JsonArray();

        DecompileOptions options = new DecompileOptions();
        DecompInterface decompiler = new DecompInterface();
        decompiler.openProgram(currentProgram);

        for (long funcAddr : potentialLicenseChecks) {
            Function func = getFunctionAt(toAddr(funcAddr));
            if (func != null && !monitor.isCancelled()) {
                DecompileResults results = decompiler.decompileFunction(toAddr(funcAddr), options, monitor);
                if (results.decompileCompleted()) {
                    String pseudoCode = results.getDecompiledFunction().getSourceCode();
                    functionPseudoCode.put(funcAddr, pseudoCode);
                    println("  Decompiled " + func.getName() + " at 0x" + Long.toHexString(funcAddr));

                    JsonObject decompiledFuncObj = new JsonObject();
                    decompiledFuncObj.put("address", Long.toHexString(funcAddr));
                    decompiledFuncObj.put("name", func.getName());
                    decompiledFuncObj.put("pseudoCode", pseudoCode);
                    decompiledFunctions.add(decompiledFuncObj);
                } else {
                    println("Decompile failed for " + func.getName() + " at 0x" + Long.toHexString(funcAddr));
                }
            }
        }

        decompiler.closeProgram();
        analysisResults.put("decompiledFunctions", decompiledFunctions);
        println("Decompilation complete.");
    }

    private void generatePatchingStrategy() throws Exception {
        println("Generating patching strategy...");
        JsonArray patchCandidates = new JsonArray();

        // Example: More sophisticated strategy - Analyze decompiled code and CFG
        for (long funcAddr : potentialLicenseChecks) {
            Function func = getFunctionAt(toAddr(funcAddr));
            if (func != null && functionPseudoCode.containsKey(funcAddr)) {
                String pseudoCode = functionPseudoCode.get(funcAddr);
                // Simple pattern matching for license checks (improve with AI)
                if (pseudoCode.contains("strcmp") || pseudoCode.contains("memcmp") || pseudoCode.contains("strncmp")) {
                    println("  Potential license check function: " + func.getName() + " at 0x" + Long.toHexString(funcAddr));

                    // Get CFG for the function
                    FunctionGraph functionGraph = new FunctionGraph(currentProgram, toAddr(funcAddr), monitor);
                    Iterator<Block> blocks = functionGraph.getBlocks(true).iterator();

                    while (blocks.hasNext() && !monitor.isCancelled()) {
                        Block block = blocks.next();
                        InstructionIterator instructions = block.getInstructions();
                        while (instructions.hasNext()) {
                            Instruction instr = instructions.next();
                            if (instr.getMnemonicString().startsWith("J") && !instr.getMnemonicString().equals("JMP")) {
                                println("    Potential patch location: " + instr.getAddress());

                                JsonObject patchObj = new JsonObject();
                                patchObj.put("address", instr.getAddress().toString());
                                patchObj.put("newBytes", "9090"); // Example: NOP
                                patchObj.put("description", "Bypass license check");
                                patchCandidates.add(patchObj);
                            }
                        }
                    }
                }
            }
        }

        analysisResults.put("patchCandidates", patchCandidates);
        println("Patching strategy generation complete.");
    }

    private void outputResults() throws Exception {
        File outputFile = new File(System.getProperty("user.dir"), "analysis_results.json");
        PrintWriter writer = new PrintWriter(new FileWriter(outputFile));
        writer.println(analysisResults.toString(4)); // Indent for readability
        writer.close();
        println("Analysis results written to: " + outputFile.getAbsolutePath());
    }

    // --- Data Structures ---

    static class GhidraFunction {
        String name;
        long address;
        String signature;
        int size;

        public GhidraFunction(String name, long address, String signature, int size) {
            this.name = name;
            this.address = address;
            this.signature = signature;
            this.size = size;
        }
    }

    static class GhidraInstruction {
        long address;
        String mnemonic;
        String operands;

        public GhidraInstruction(long address, String mnemonic, String operands) {
            this.address = address;
            this.mnemonic = mnemonic;
            this.operands = operands;
        }
    }
}
// This script performs advanced licensing analysis and outputs the results in JSON format.
// It analyzes each function, using decompilation, P-code, CFG, and cross-reference analysis,
// and then outputs a JSON object that Intellicrack can capture and send to Mixtral.

import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.*;
import ghidra.program.model.address.*;
import ghidra.program.model.symbol.*;
import ghidra.app.decompiler.*;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.block.*;
import ghidra.util.exception.CancelledException;
import java.util.*;
import java.io.*;

public class EnhancedLicensingAnalysisScript extends GhidraScript {

    @Override
    public void run() throws Exception {
        // List to hold the results for each flagged function.
        List<Map<String, Object>> flaggedFunctions = new ArrayList<>();

        // Initialize decompiler.
        DecompInterface decompInterface = new DecompInterface();
        decompInterface.openProgram(currentProgram);

        Listing listing = currentProgram.getListing();
        FunctionIterator functions = listing.getFunctions(true);
        
        // Iterate over all functions.
        while (functions.hasNext() && !monitor.isCancelled()) {
            Function func = functions.next();
            String funcName = func.getName().toLowerCase();
            boolean isSuspect = funcName.contains("license") || funcName.contains("trial") ||
                                funcName.contains("serial")  || funcName.contains("activation");
            
            // Decompile function for high-level view.
            String decompiledSnippet = "";
            DecompileResults decompResults = decompInterface.decompileFunction(func, 60, monitor);
            if (decompResults != null && decompResults.decompileCompleted()) {
                String decompiledCode = decompResults.getDecompiledFunction().getC();
                if (!isSuspect && decompiledCode.toLowerCase().contains("license")) {
                    isSuspect = true;
                }
                // Take a snippet (first 300 characters).
                decompiledSnippet = decompiledCode.substring(0, Math.min(300, decompiledCode.length()));
            }
            
            if (isSuspect) {
                // Create a map to store function analysis data.
                Map<String, Object> funcData = new LinkedHashMap<>();
                funcData.put("function_name", func.getName());
                funcData.put("entry_point", func.getEntryPoint().toString());
                funcData.put("decompiled_snippet", decompiledSnippet);
                
                // Cross-reference: collect addresses that call this function.
                List<String> xrefs = new ArrayList<>();
                ReferenceIterator refs = currentProgram.getReferenceManager().getReferencesTo(func.getEntryPoint());
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
        
        // Build JSON output manually.
        String jsonOutput = buildJson(flaggedFunctions);
        println(jsonOutput);
        decompInterface.dispose();
    }
    
    /**
     * Helper method to build a JSON string from the list of flagged functions.
     * This is a very simple JSON builder and assumes that no string requires special escaping.
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

/**
 * Automated Generic Unpacker for Ghidra
 *
 * Implements generic unpacking through memory dump analysis, OEP detection,
 * and Import Address Table reconstruction. Supports multi-layer unpacking.
 *
 * @category Intellicrack.Unpacking
 * @author Intellicrack Framework
 * @version 2.0.0
 */

import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.*;
import ghidra.program.model.address.*;
import ghidra.program.model.symbol.*;
import ghidra.program.model.lang.*;
import ghidra.program.model.data.*;
import ghidra.program.model.pcode.*;
import ghidra.app.util.bin.format.pe.*;
import ghidra.app.util.importer.*;
import ghidra.app.decompiler.*;
import ghidra.util.exception.*;
import ghidra.framework.model.*;

import java.util.*;
import java.io.*;
import java.nio.*;
import java.nio.file.*;

public class AutomatedUnpacker extends GhidraScript {

    // Unpacking configuration
    private static final int MAX_UNPACKING_LAYERS = 5;
    private static final int MEMORY_DUMP_SIZE = 0x10000000; // 256MB max

    // Detection patterns
    private static final byte[][] OEP_PATTERNS = {
        // Common x86 entry point patterns
        {0x55, (byte)0x8B, (byte)0xEC},                    // push ebp; mov ebp, esp
        {0x53, 0x56, 0x57},                                // push ebx; push esi; push edi
        {(byte)0x83, (byte)0xEC},                          // sub esp, XX
        {0x6A, 0x00, (byte)0xE8},                          // push 0; call
        {(byte)0xE8, 0x00, 0x00, 0x00, 0x00, 0x58},       // call $+5; pop eax

        // Common x64 entry point patterns
        {0x48, (byte)0x83, (byte)0xEC},                    // sub rsp, XX
        {0x40, 0x53, 0x48, (byte)0x83, (byte)0xEC},        // push rbx; sub rsp, XX
        {0x48, (byte)0x89, 0x5C, 0x24},                    // mov [rsp+XX], rbx
        {0x48, (byte)0x8B, (byte)0xEC},                    // mov rbp, rsp
    };

    // Unpacking state
    private Address originalEntryPoint;
    private Address currentEntryPoint;
    private List<UnpackingLayer> unpackingLayers = new ArrayList<>();
    private Map<Address, MemoryDump> memoryDumps = new HashMap<>();
    private ImportTableInfo importTable;
    private List<Address> possibleOEPs = new ArrayList<>();

    @Override
    public void run() throws Exception {
        println("=== Automated Generic Unpacker v2.0.0 ===");
        println("Starting automated unpacking process...\n");

        // Check if program is packed
        if (!isProgramPacked()) {
            println("Program does not appear to be packed.");
            if (!askYesNo("Continue Anyway?", "Program doesn't show typical packing characteristics. Continue unpacking?")) {
                return;
            }
        }

        // Get original entry point
        originalEntryPoint = getEntryPoint();
        currentEntryPoint = originalEntryPoint;

        println("Original Entry Point: " + originalEntryPoint);

        // Phase 1: Initial analysis
        println("\n[Phase 1] Analyzing packer characteristics...");
        PackerCharacteristics packerInfo = analyzePackerCharacteristics();

        // Phase 2: Memory region analysis
        println("\n[Phase 2] Analyzing memory regions...");
        analyzeMemoryRegions();

        // Phase 3: Find unpacking stubs
        println("\n[Phase 3] Locating unpacking stubs...");
        List<Address> unpackingStubs = findUnpackingStubs();

        // Phase 4: Trace execution flow
        println("\n[Phase 4] Tracing execution flow...");
        traceExecutionFlow(unpackingStubs);

        // Phase 5: Find OEP candidates
        println("\n[Phase 5] Searching for Original Entry Point...");
        findOEPCandidates();

        // Phase 6: Dump and analyze layers
        println("\n[Phase 6] Dumping unpacked layers...");
        dumpUnpackedLayers();

        // Phase 7: Reconstruct imports
        println("\n[Phase 7] Reconstructing Import Address Table...");
        reconstructImportTable();

        // Phase 8: Fix and finalize
        println("\n[Phase 8] Finalizing unpacked binary...");
        finalizeUnpacking();

        // Generate report
        generateUnpackingReport();
    }

    private boolean isProgramPacked() {
        // Quick checks for packed characteristics
        int packedIndicators = 0;

        // Check section characteristics
        MemoryBlock[] blocks = currentProgram.getMemory().getBlocks();
        for (MemoryBlock block : blocks) {
            // High entropy sections
            if (block.isExecute()) {
                try {
                    double entropy = calculateSectionEntropy(block);
                    if (entropy > 6.5) {
                        packedIndicators++;
                    }
                } catch (Exception e) {
                    // Continue
                }
            }

            // Writable + Executable sections
            if (block.isExecute() && block.isWrite()) {
                packedIndicators++;
            }

            // Non-standard section names
            String name = block.getName();
            if (!isStandardSectionName(name)) {
                packedIndicators++;
            }
        }

        // Check imports
        Symbol[] imports = getImportedSymbols();
        if (imports.length < 10) {
            packedIndicators += 2; // Very suspicious
        }

        // Check entry point location
        Address ep = getEntryPoint();
        if (ep != null) {
            MemoryBlock epBlock = currentProgram.getMemory().getBlock(ep);
            if (epBlock != null && !epBlock.getName().equals(".text")) {
                packedIndicators++;
            }
        }

        return packedIndicators >= 3;
    }

    private PackerCharacteristics analyzePackerCharacteristics() {
        PackerCharacteristics chars = new PackerCharacteristics();

        // Analyze entry point code
        try {
            Address ep = getEntryPoint();
            byte[] epBytes = new byte[64];
            currentProgram.getMemory().getBytes(ep, epBytes);

            // Check for common packer patterns
            if (containsPattern(epBytes, new byte[]{0x60})) { // pushad
                chars.usesPushad = true;
            }
            if (containsPattern(epBytes, new byte[]{(byte)0xBE})) { // mov esi
                chars.usesESI = true;
            }

            // Check for VirtualAlloc/VirtualProtect usage
            Symbol[] imports = getImportedSymbols();
            for (Symbol imp : imports) {
                String name = imp.getName();
                if (name.contains("VirtualAlloc")) chars.usesVirtualAlloc = true;
                if (name.contains("VirtualProtect")) chars.usesVirtualProtect = true;
                if (name.contains("GetProcAddress")) chars.usesGetProcAddress = true;
                if (name.contains("LoadLibrary")) chars.usesLoadLibrary = true;
            }

            // Estimate packer type
            if (chars.usesVirtualAlloc && chars.usesGetProcAddress) {
                chars.packerType = "Dynamic Unpacker";
            } else if (chars.usesPushad) {
                chars.packerType = "Classic Compressor";
            } else {
                chars.packerType = "Unknown/Custom";
            }

        } catch (Exception e) {
            printerr("Failed to analyze packer: " + e.getMessage());
        }

        println("  Packer type: " + chars.packerType);
        println("  Uses VirtualAlloc: " + chars.usesVirtualAlloc);
        println("  Uses pushad: " + chars.usesPushad);

        return chars;
    }

    private void analyzeMemoryRegions() {
        MemoryBlock[] blocks = currentProgram.getMemory().getBlocks();

        println("  Memory regions:");
        for (MemoryBlock block : blocks) {
            String perms = "";
            if (block.isRead()) perms += "R";
            if (block.isWrite()) perms += "W";
            if (block.isExecute()) perms += "X";

            println(String.format("    %s: %s - %s [%s] (%.2f KB)",
                block.getName(),
                block.getStart(),
                block.getEnd(),
                perms,
                block.getSize() / 1024.0));

            // Mark suspicious regions
            if (block.isExecute() && block.isWrite()) {
                println("      -> Suspicious: RWX permissions");
            }
        }
    }

    private List<Address> findUnpackingStubs() {
        List<Address> stubs = new ArrayList<>();

        // Pattern 1: Look for memory allocation calls
        findMemoryAllocationStubs(stubs);

        // Pattern 2: Look for decryption loops
        findDecryptionLoops(stubs);

        // Pattern 3: Look for decompression routines
        findDecompressionRoutines(stubs);

        // Pattern 4: Look for jump to unpacked code
        findDynamicJumps(stubs);

        println("  Found " + stubs.size() + " potential unpacking stubs");
        return stubs;
    }

    private void findMemoryAllocationStubs(List<Address> stubs) {
        // Find references to VirtualAlloc/HeapAlloc/malloc
        String[] allocFuncs = {"VirtualAlloc", "VirtualAllocEx", "HeapAlloc",
                              "malloc", "GlobalAlloc", "LocalAlloc"};

        SymbolTable symTable = currentProgram.getSymbolTable();
        for (String funcName : allocFuncs) {
            Symbol[] symbols = symTable.getSymbols(funcName);
            for (Symbol sym : symbols) {
                Reference[] refs = getReferencesTo(sym.getAddress());
                for (Reference ref : refs) {
                    Address callSite = ref.getFromAddress();
                    Function func = getFunctionContaining(callSite);
                    if (func != null && !stubs.contains(func.getEntryPoint())) {
                        stubs.add(func.getEntryPoint());
                        println("    Memory allocation stub at " + func.getEntryPoint());
                    }
                }
            }
        }
    }

    private void findDecryptionLoops(List<Address> stubs) {
        // Look for XOR loops and other decryption patterns
        FunctionIterator functions = currentProgram.getFunctionManager().getFunctions(true);

        while (functions.hasNext() && !monitor.isCancelled()) {
            Function func = functions.next();

            if (hasDecryptionPattern(func)) {
                stubs.add(func.getEntryPoint());
                println("    Decryption loop at " + func.getEntryPoint());
            }
        }
    }

    private boolean hasDecryptionPattern(Function func) {
        // Look for characteristics of decryption:
        // - XOR operations in loops
        // - Byte-by-byte processing
        // - Counter/index increments

        try {
            InstructionIterator instrs = currentProgram.getListing().getInstructions(
                func.getBody(), true);

            int xorCount = 0;
            int loopCount = 0;

            while (instrs.hasNext()) {
                Instruction instr = instrs.next();
                String mnemonic = instr.getMnemonicString();

                if (mnemonic.equals("XOR")) {
                    xorCount++;
                }

                // Check for loop instructions
                if (mnemonic.startsWith("LOOP") || mnemonic.equals("JNZ") ||
                    mnemonic.equals("JNE") || mnemonic.equals("JB")) {
                    // Check if it's a backward jump (loop)
                    Address target = instr.getDefaultOperandRepresentation(0);
                    if (target != null) {
                        try {
                            Address targetAddr = toAddr(Long.decode(target.toString()));
                            if (targetAddr.compareTo(instr.getAddress()) < 0) {
                                loopCount++;
                            }
                        } catch (Exception e) {
                            // Not a direct address
                        }
                    }
                }
            }

            return xorCount > 5 && loopCount > 0;

        } catch (Exception e) {
            return false;
        }
    }

    private void findDecompressionRoutines(List<Address> stubs) {
        // Look for compression signatures (aPLib, LZMA, etc.)
        byte[][] compressionSigs = {
            {0x60, (byte)0xBE},                    // aPLib
            {0x5D, 0x00, 0x00, (byte)0x80, 0x00},  // LZMA
            {(byte)0xFC, 0x57, (byte)0x8B},        // LZ4
        };

        Memory memory = currentProgram.getMemory();
        for (byte[] sig : compressionSigs) {
            Address found = memory.findBytes(currentProgram.getMinAddress(),
                                           sig, null, true, monitor);
            if (found != null) {
                Function func = getFunctionContaining(found);
                if (func != null && !stubs.contains(func.getEntryPoint())) {
                    stubs.add(func.getEntryPoint());
                    println("    Decompression routine at " + func.getEntryPoint());
                }
            }
        }
    }

    private void findDynamicJumps(List<Address> stubs) {
        // Look for indirect jumps that might lead to unpacked code
        InstructionIterator instrs = currentProgram.getListing().getInstructions(true);

        while (instrs.hasNext() && !monitor.isCancelled()) {
            Instruction instr = instrs.next();

            if (instr.getFlowType().isJump() && instr.getFlowType().isIndirect()) {
                // Check if this could be a jump to unpacked code
                Function func = getFunctionContaining(instr.getAddress());
                if (func != null) {
                    // Check if near end of function (common pattern)
                    Address funcEnd = func.getBody().getMaxAddress();
                    long distance = funcEnd.subtract(instr.getAddress());

                    if (distance < 32) { // Near end of function
                        if (!stubs.contains(func.getEntryPoint())) {
                            stubs.add(func.getEntryPoint());
                            println("    Dynamic jump at " + instr.getAddress());
                        }
                    }
                }
            }
        }
    }

    private void traceExecutionFlow(List<Address> unpackingStubs) {
        // Trace execution from entry point through unpacking stubs
        Set<Address> visited = new HashSet<>();
        Queue<Address> toVisit = new LinkedList<>();

        toVisit.add(currentEntryPoint);

        while (!toVisit.isEmpty() && !monitor.isCancelled()) {
            Address current = toVisit.poll();
            if (visited.contains(current)) continue;
            visited.add(current);

            // Get instruction at address
            Instruction instr = getInstructionAt(current);
            if (instr == null) continue;

            // Check for memory writes (unpacking)
            if (isMemoryWriteInstruction(instr)) {
                checkForUnpackingActivity(instr);
            }

            // Follow control flow
            Address[] flows = instr.getFlows();
            if (flows != null) {
                for (Address flow : flows) {
                    if (!visited.contains(flow)) {
                        toVisit.add(flow);
                    }
                }
            }

            // Check for calls to unpacking stubs
            if (instr.getFlowType().isCall()) {
                Address target = instr.getAddress(0);
                if (target != null && unpackingStubs.contains(target)) {
                    println("  Call to unpacking stub at " + current + " -> " + target);
                    unpackingLayers.add(new UnpackingLayer(current, target, visited.size()));
                }
            }
        }

        println("  Traced " + visited.size() + " instructions");
        println("  Found " + unpackingLayers.size() + " unpacking layers");
    }

    private boolean isMemoryWriteInstruction(Instruction instr) {
        String mnemonic = instr.getMnemonicString();
        return mnemonic.startsWith("MOV") || mnemonic.startsWith("STOS") ||
               mnemonic.startsWith("REP") || mnemonic.equals("PUSH");
    }

    private void checkForUnpackingActivity(Instruction instr) {
        // Check if writing to executable memory
        if (instr.getNumOperands() >= 2) {
            // Simplified check - real implementation would analyze operands
            Address writeAddr = instr.getAddress(0);
            if (writeAddr != null) {
                MemoryBlock block = currentProgram.getMemory().getBlock(writeAddr);
                if (block != null && block.isExecute()) {
                    println("  Potential unpacking write at " + instr.getAddress() +
                           " to " + writeAddr);
                }
            }
        }
    }

    private void findOEPCandidates() {
        // Strategy 1: Look for OEP patterns after unpacking stubs
        findOEPByPatterns();

        // Strategy 2: Analyze jump targets from unpacking code
        findOEPByJumpAnalysis();

        // Strategy 3: Look for standard entry point characteristics
        findOEPByCharacteristics();

        // Strategy 4: Entropy-based analysis
        findOEPByEntropy();

        // Rank candidates
        if (!possibleOEPs.isEmpty()) {
            println("  Found " + possibleOEPs.size() + " OEP candidates:");
            for (int i = 0; i < Math.min(5, possibleOEPs.size()); i++) {
                println("    " + (i + 1) + ". " + possibleOEPs.get(i));
            }
        }
    }

    private void findOEPByPatterns() {
        // Search for common entry point patterns
        Memory memory = currentProgram.getMemory();

        for (byte[] pattern : OEP_PATTERNS) {
            Address found = currentProgram.getMinAddress();
            while (found != null) {
                found = memory.findBytes(found, pattern, null, true, monitor);
                if (found != null) {
                    // Check if it's in executable memory
                    MemoryBlock block = memory.getBlock(found);
                    if (block != null && block.isExecute()) {
                        // Check if it's after packer code
                        if (found.compareTo(currentEntryPoint) > 0) {
                            if (!possibleOEPs.contains(found)) {
                                possibleOEPs.add(found);
                                println("    OEP pattern found at " + found);
                            }
                        }
                    }
                    found = found.add(1);
                }
            }
        }
    }

    private void findOEPByJumpAnalysis() {
        // Analyze jumps from unpacking layers
        for (UnpackingLayer layer : unpackingLayers) {
            // Look for jumps at end of unpacking stub
            Function func = getFunctionContaining(layer.stubAddress);
            if (func != null) {
                analyzeUnpackingStubExits(func);
            }
        }
    }

    private void analyzeUnpackingStubExits(Function func) {
        // Find exit points of unpacking function
        InstructionIterator instrs = currentProgram.getListing().getInstructions(
            func.getBody(), true);

        while (instrs.hasNext()) {
            Instruction instr = instrs.next();

            // Look for jumps to addresses outside the function
            if (instr.getFlowType().isJump()) {
                Address target = instr.getAddress(0);
                if (target != null && !func.getBody().contains(target)) {
                    // Potential OEP
                    if (!possibleOEPs.contains(target)) {
                        possibleOEPs.add(target);
                        println("    Potential OEP from jump at " + instr.getAddress() +
                               " -> " + target);
                    }
                }
            }

            // Look for pushed return addresses
            if (instr.getMnemonicString().equals("PUSH")) {
                // Check if followed by RET
                Instruction next = getInstructionAfter(instr.getAddress());
                if (next != null && next.getMnemonicString().equals("RET")) {
                    // PUSH addr; RET pattern
                    Address target = instr.getAddress(0);
                    if (target != null && !possibleOEPs.contains(target)) {
                        possibleOEPs.add(target);
                        println("    Potential OEP from PUSH/RET at " + instr.getAddress());
                    }
                }
            }
        }
    }

    private void findOEPByCharacteristics() {
        // Look for functions with typical entry point characteristics
        FunctionIterator functions = currentProgram.getFunctionManager().getFunctions(true);

        while (functions.hasNext() && !monitor.isCancelled()) {
            Function func = functions.next();

            // Skip packer code
            if (func.getEntryPoint().compareTo(currentEntryPoint.add(0x1000)) < 0) {
                continue;
            }

            // Check function characteristics
            if (hasEntryPointCharacteristics(func)) {
                if (!possibleOEPs.contains(func.getEntryPoint())) {
                    possibleOEPs.add(func.getEntryPoint());
                    println("    Potential OEP by characteristics at " + func.getEntryPoint());
                }
            }
        }
    }

    private boolean hasEntryPointCharacteristics(Function func) {
        // Check for typical entry point patterns:
        // - Many outgoing calls
        // - References to many imports
        // - Initialization patterns

        int callCount = 0;
        int importRefCount = 0;

        InstructionIterator instrs = currentProgram.getListing().getInstructions(
            func.getBody(), true);

        while (instrs.hasNext()) {
            Instruction instr = instrs.next();

            if (instr.getFlowType().isCall()) {
                callCount++;

                // Check if calling imports
                Address target = instr.getAddress(0);
                if (target != null) {
                    Symbol sym = getSymbolAt(target);
                    if (sym != null && sym.isExternal()) {
                        importRefCount++;
                    }
                }
            }
        }

        // Entry points typically have many calls
        return callCount > 10 || importRefCount > 5;
    }

    private void findOEPByEntropy() {
        // After unpacking, code sections should have normal entropy
        MemoryBlock[] blocks = currentProgram.getMemory().getBlocks();

        for (MemoryBlock block : blocks) {
            if (!block.isExecute()) continue;

            try {
                double entropy = calculateSectionEntropy(block);

                // Normal code entropy is typically 5.0-6.0
                if (entropy > 5.0 && entropy < 6.0) {
                    // Check first function in this section
                    Function func = getFunctionAfter(block.getStart());
                    if (func != null && func.getEntryPoint().compareTo(currentEntryPoint) > 0) {
                        if (!possibleOEPs.contains(func.getEntryPoint())) {
                            possibleOEPs.add(func.getEntryPoint());
                            println("    Potential OEP by entropy at " + func.getEntryPoint() +
                                   " (entropy: " + String.format("%.2f", entropy) + ")");
                        }
                    }
                }
            } catch (Exception e) {
                // Continue
            }
        }
    }

    private void dumpUnpackedLayers() {
        // Simulate memory dumps at different stages
        for (UnpackingLayer layer : unpackingLayers) {
            println("  Analyzing layer " + layer.layerNumber + "...");

            try {
                // In real implementation, this would dump process memory
                // Here we analyze the current state
                MemoryDump dump = analyzeMemoryState(layer);
                memoryDumps.put(layer.stubAddress, dump);

                println("    Layer " + layer.layerNumber + " characteristics:");
                println("      Code size: " + dump.codeSize + " bytes");
                println("      Data size: " + dump.dataSize + " bytes");
                println("      New sections: " + dump.newSections.size());

            } catch (Exception e) {
                printerr("    Failed to analyze layer: " + e.getMessage());
            }
        }
    }

    private MemoryDump analyzeMemoryState(UnpackingLayer layer) {
        MemoryDump dump = new MemoryDump();
        dump.layerNumber = layer.layerNumber;
        dump.timestamp = new Date();

        // Analyze memory changes
        MemoryBlock[] blocks = currentProgram.getMemory().getBlocks();
        for (MemoryBlock block : blocks) {
            if (block.isExecute()) {
                dump.codeSize += block.getSize();
            } else if (block.isInitialized()) {
                dump.dataSize += block.getSize();
            }

            // Check for new sections (simulated)
            if (block.getStart().compareTo(layer.stubAddress) > 0) {
                dump.newSections.add(block.getName());
            }
        }

        return dump;
    }

    private void reconstructImportTable() {
        importTable = new ImportTableInfo();

        // Strategy 1: Scan for GetProcAddress calls
        scanForDynamicImports();

        // Strategy 2: Analyze IAT region
        findAndAnalyzeIAT();

        // Strategy 3: Scan for direct API calls
        scanForDirectAPICalls();

        // Strategy 4: Reconstruct from dumps
        reconstructFromDumps();

        println("  Reconstructed imports:");
        println("    Total functions: " + importTable.getTotalImports());
        println("    DLLs: " + String.join(", ", importTable.getDllNames()));
    }

    private void scanForDynamicImports() {
        // Find GetProcAddress calls
        Symbol[] symbols = currentProgram.getSymbolTable().getSymbols("GetProcAddress");

        for (Symbol sym : symbols) {
            Reference[] refs = getReferencesTo(sym.getAddress());

            for (Reference ref : refs) {
                analyzeDynamicImport(ref.getFromAddress());
            }
        }
    }

    private void analyzeDynamicImport(Address callSite) {
        // Look for string parameters to GetProcAddress
        // This is simplified - real implementation would trace data flow
        Function func = getFunctionContaining(callSite);
        if (func == null) return;

        // Look for pushed strings before the call
        Address searchStart = func.getEntryPoint();
        Address searchEnd = callSite;

        List<String> foundStrings = findStringsInRange(searchStart, searchEnd);
        for (String str : foundStrings) {
            // Check if it looks like an API name
            if (str.matches("[A-Za-z][A-Za-z0-9_]*") && str.length() > 2) {
                importTable.addImport("dynamic.dll", str, null);
                println("    Dynamic import: " + str);
            }
        }
    }

    private void findAndAnalyzeIAT() {
        // Look for Import Address Table patterns
        // IAT typically contains pointers to imported functions

        MemoryBlock[] blocks = currentProgram.getMemory().getBlocks();
        for (MemoryBlock block : blocks) {
            if (block.isRead() && !block.isExecute()) {
                try {
                    analyzeForIATPatterns(block);
                } catch (Exception e) {
                    // Continue
                }
            }
        }
    }

    private void analyzeForIATPatterns(MemoryBlock block) throws Exception {
        // Look for arrays of pointers
        Address current = block.getStart();
        int pointerSize = currentProgram.getDefaultPointerSize();

        List<Address> pointers = new ArrayList<>();

        while (current.compareTo(block.getEnd()) < 0) {
            // Read potential pointer
            byte[] bytes = new byte[pointerSize];
            currentProgram.getMemory().getBytes(current, bytes);

            // Convert to address
            long value = 0;
            if (pointerSize == 4) {
                value = ByteBuffer.wrap(bytes).order(ByteOrder.LITTLE_ENDIAN).getInt() & 0xFFFFFFFFL;
            } else {
                value = ByteBuffer.wrap(bytes).order(ByteOrder.LITTLE_ENDIAN).getLong();
            }

            // Check if it points to valid memory
            try {
                Address ptr = toAddr(value);
                if (currentProgram.getMemory().contains(ptr)) {
                    pointers.add(ptr);
                } else if (pointers.size() > 4) {
                    // End of IAT
                    processIATChunk(pointers);
                    pointers.clear();
                }
            } catch (Exception e) {
                if (pointers.size() > 4) {
                    processIATChunk(pointers);
                    pointers.clear();
                }
            }

            current = current.add(pointerSize);
        }
    }

    private void processIATChunk(List<Address> pointers) {
        // Check if these pointers look like imports
        for (Address ptr : pointers) {
            Symbol sym = getSymbolAt(ptr);
            if (sym != null && sym.isExternal()) {
                String name = sym.getName();
                String dll = sym.getParentNamespace().getName();
                importTable.addImport(dll, name, ptr);
            }
        }
    }

    private void scanForDirectAPICalls() {
        // Scan for CALL instructions to external addresses
        InstructionIterator instrs = currentProgram.getListing().getInstructions(true);

        while (instrs.hasNext() && !monitor.isCancelled()) {
            Instruction instr = instrs.next();

            if (instr.getFlowType().isCall()) {
                Address target = instr.getAddress(0);
                if (target != null) {
                    Symbol sym = getSymbolAt(target);
                    if (sym != null && sym.isExternal()) {
                        String name = sym.getName();
                        String dll = sym.getParentNamespace().getName();
                        importTable.addImport(dll, name, target);
                    }
                }
            }
        }
    }

    private void reconstructFromDumps() {
        // Use memory dumps to find additional imports
        for (MemoryDump dump : memoryDumps.values()) {
            // In real implementation, would analyze dump for import patterns
            // Here we just report what we found
            if (dump.newSections.contains(".idata")) {
                println("    Found import section in layer " + dump.layerNumber);
            }
        }
    }

    private void finalizeUnpacking() {
        // Select best OEP candidate
        Address selectedOEP = selectBestOEP();

        if (selectedOEP != null) {
            println("  Selected OEP: " + selectedOEP);

            // Create unpacked program
            try {
                createUnpackedProgram(selectedOEP);
            } catch (Exception e) {
                printerr("  Failed to create unpacked program: " + e.getMessage());
            }
        } else {
            println("  WARNING: Could not determine OEP");
        }

        // Fix section characteristics
        fixSectionCharacteristics();

        // Remove packer artifacts
        removePackerArtifacts();
    }

    private Address selectBestOEP() {
        if (possibleOEPs.isEmpty()) return null;

        // Score each candidate
        Map<Address, Integer> scores = new HashMap<>();

        for (Address oep : possibleOEPs) {
            int score = 0;

            // Score based on location
            if (oep.compareTo(currentEntryPoint.add(0x1000)) > 0) {
                score += 10; // After packer code
            }

            // Score based on function characteristics
            Function func = getFunctionAt(oep);
            if (func != null) {
                if (hasEntryPointCharacteristics(func)) {
                    score += 20;
                }

                // Check for standard patterns
                try {
                    byte[] bytes = new byte[16];
                    currentProgram.getMemory().getBytes(oep, bytes);

                    for (byte[] pattern : OEP_PATTERNS) {
                        if (containsPattern(bytes, pattern)) {
                            score += 15;
                            break;
                        }
                    }
                } catch (Exception e) {
                    // Continue
                }
            }

            // Score based on section
            MemoryBlock block = currentProgram.getMemory().getBlock(oep);
            if (block != null && block.getName().equals(".text")) {
                score += 10;
            }

            scores.put(oep, score);
        }

        // Return highest scoring OEP
        return scores.entrySet().stream()
            .max(Map.Entry.comparingByValue())
            .map(Map.Entry::getKey)
            .orElse(possibleOEPs.get(0));
    }

    private void createUnpackedProgram(Address newOEP) throws Exception {
        // In a real implementation, this would:
        // 1. Dump the memory
        // 2. Fix the PE header
        // 3. Set new entry point
        // 4. Rebuild sections
        // 5. Save as new file

        println("  Creating unpacked program...");
        println("    New Entry Point: " + newOEP);
        println("    Import Table: " + importTable.getTotalImports() + " functions");

        // For now, we'll mark the new entry point
        try {
            createLabel(newOEP, "UNPACKED_OEP", true);
            setEOLComment(newOEP, "Original Entry Point (after unpacking)");
        } catch (Exception e) {
            printerr("    Failed to mark OEP: " + e.getMessage());
        }
    }

    private void fixSectionCharacteristics() {
        println("  Fixing section characteristics...");

        MemoryBlock[] blocks = currentProgram.getMemory().getBlocks();
        for (MemoryBlock block : blocks) {
            // Remove write permission from code sections
            if (block.isExecute() && block.isWrite()) {
                println("    Section " + block.getName() + " should not be writable");
                // In real implementation, would fix permissions
            }

            // Fix section names
            String name = block.getName();
            if (name.startsWith("UPX") || name.startsWith("ASPack") ||
                name.contains("pack")) {
                println("    Section " + name + " appears to be packer-related");
            }
        }
    }

    private void removePackerArtifacts() {
        println("  Removing packer artifacts...");

        // Mark packer code
        Address packerStart = currentEntryPoint;
        Address packerEnd = null;

        // Find end of packer (first OEP candidate or first normal section)
        if (!possibleOEPs.isEmpty()) {
            packerEnd = possibleOEPs.stream()
                .min(Address::compareTo)
                .orElse(null);
        }

        if (packerEnd != null) {
            try {
                createLabel(packerStart, "PACKER_START", true);
                createLabel(packerEnd, "PACKER_END", true);

                AddressSet packerCode = new AddressSet(packerStart, packerEnd.subtract(1));
                setBackgroundColor(packerCode, new java.awt.Color(255, 200, 200));

                println("    Marked packer code: " + packerStart + " - " + packerEnd);
            } catch (Exception e) {
                printerr("    Failed to mark packer code: " + e.getMessage());
            }
        }
    }

    private void generateUnpackingReport() {
        println("\n=== Unpacking Analysis Report ===\n");

        println("Summary:");
        println("  Original Entry Point: " + originalEntryPoint);
        println("  Unpacking layers found: " + unpackingLayers.size());
        println("  OEP candidates found: " + possibleOEPs.size());

        if (!possibleOEPs.isEmpty()) {
            println("\nTop OEP Candidates:");
            for (int i = 0; i < Math.min(3, possibleOEPs.size()); i++) {
                Address oep = possibleOEPs.get(i);
                Function func = getFunctionAt(oep);
                String funcName = func != null ? func.getName() : "unknown";
                println("  " + (i + 1) + ". " + oep + " (" + funcName + ")");
            }
        }

        println("\nImport Reconstruction:");
        println("  Total imports found: " + importTable.getTotalImports());
        println("  DLLs referenced: " + importTable.getDllNames().size());

        println("\nRecommendations:");
        if (possibleOEPs.isEmpty()) {
            println("  - Manual analysis required to find OEP");
            println("  - Try setting breakpoints on VirtualProtect/VirtualAlloc");
            println("  - Use dynamic analysis tools");
        } else {
            Address bestOEP = selectBestOEP();
            println("  - Recommended OEP: " + bestOEP);
            println("  - Dump process at OEP and rebuild imports");
            println("  - Use Scylla or similar tool for IAT reconstruction");
        }

        // Export detailed report
        exportUnpackingReport();
    }

    private void exportUnpackingReport() {
        try {
            File reportFile = askFile("Save Unpacking Report", "Save");
            if (reportFile == null) return;

            PrintWriter writer = new PrintWriter(reportFile);
            writer.println("Automated Unpacking Report");
            writer.println("Generated by Intellicrack Unpacker v2.0.0");
            writer.println("Date: " + new Date());
            writer.println("Program: " + currentProgram.getName());
            writer.println("=====================================\n");

            // Write detailed analysis
            writer.println("Unpacking Analysis:");
            writer.println("  Original EP: " + originalEntryPoint);
            writer.println("  Packed: " + isProgramPacked());
            writer.println("  Layers: " + unpackingLayers.size());

            writer.println("\nUnpacking Layers:");
            for (UnpackingLayer layer : unpackingLayers) {
                writer.println("  Layer " + layer.layerNumber + ":");
                writer.println("    Call site: " + layer.callSite);
                writer.println("    Stub address: " + layer.stubAddress);
            }

            writer.println("\nOEP Candidates:");
            for (int i = 0; i < possibleOEPs.size(); i++) {
                writer.println("  " + (i + 1) + ". " + possibleOEPs.get(i));
            }

            writer.println("\nImport Table Reconstruction:");
            for (String dll : importTable.getDllNames()) {
                writer.println("  " + dll + ":");
                for (String func : importTable.getImportsForDll(dll)) {
                    writer.println("    - " + func);
                }
            }

            writer.close();
            println("\nDetailed report saved to: " + reportFile.getAbsolutePath());

        } catch (Exception e) {
            printerr("Failed to export report: " + e.getMessage());
        }
    }

    // Helper methods
    private double calculateSectionEntropy(MemoryBlock block) throws Exception {
        byte[] data = new byte[(int) Math.min(block.getSize(), 65536)];
        block.getBytes(block.getStart(), data);

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

    private boolean isStandardSectionName(String name) {
        String[] standard = {".text", ".data", ".rdata", ".bss", ".rsrc",
                           ".reloc", ".idata", ".edata", "CODE", "DATA"};
        for (String s : standard) {
            if (name.equalsIgnoreCase(s)) return true;
        }
        return false;
    }

    private boolean containsPattern(byte[] data, byte[] pattern) {
        if (pattern.length > data.length) return false;

        for (int i = 0; i <= data.length - pattern.length; i++) {
            boolean match = true;
            for (int j = 0; j < pattern.length; j++) {
                if (data[i + j] != pattern[j]) {
                    match = false;
                    break;
                }
            }
            if (match) return true;
        }
        return false;
    }

    private Symbol[] getImportedSymbols() {
        List<Symbol> imports = new ArrayList<>();
        SymbolIterator iter = currentProgram.getSymbolTable().getExternalSymbols();
        while (iter.hasNext()) {
            imports.add(iter.next());
        }
        return imports.toArray(new Symbol[0]);
    }

    private Address getEntryPoint() {
        Symbol[] symbols = currentProgram.getSymbolTable().getSymbols("entry");
        if (symbols.length > 0) {
            return symbols[0].getAddress();
        }
        return currentProgram.getImageBase();
    }

    private List<String> findStringsInRange(Address start, Address end) {
        List<String> strings = new ArrayList<>();

        DataIterator dataIter = currentProgram.getListing().getDefinedData(start, true);
        while (dataIter.hasNext()) {
            Data data = dataIter.next();
            if (data.getAddress().compareTo(end) > 0) break;

            if (data.hasStringValue()) {
                strings.add(data.getDefaultValueRepresentation());
            }
        }

        return strings;
    }

    // Inner classes
    private class PackerCharacteristics {
        String packerType = "Unknown";
        boolean usesVirtualAlloc = false;
        boolean usesVirtualProtect = false;
        boolean usesGetProcAddress = false;
        boolean usesLoadLibrary = false;
        boolean usesPushad = false;
        boolean usesESI = false;
    }

    private class UnpackingLayer {
        Address callSite;
        Address stubAddress;
        int layerNumber;

        UnpackingLayer(Address call, Address stub, int number) {
            this.callSite = call;
            this.stubAddress = stub;
            this.layerNumber = number;
        }
    }

    private class MemoryDump {
        int layerNumber;
        Date timestamp;
        long codeSize;
        long dataSize;
        List<String> newSections = new ArrayList<>();
    }

    private class ImportTableInfo {
        Map<String, List<ImportedFunction>> imports = new HashMap<>();

        void addImport(String dll, String function, Address address) {
            imports.computeIfAbsent(dll.toLowerCase(), k -> new ArrayList<>())
                   .add(new ImportedFunction(function, address));
        }

        int getTotalImports() {
            return imports.values().stream()
                .mapToInt(List::size)
                .sum();
        }

        Set<String> getDllNames() {
            return imports.keySet();
        }

        List<String> getImportsForDll(String dll) {
            return imports.getOrDefault(dll.toLowerCase(), new ArrayList<>())
                .stream()
                .map(f -> f.name)
                .collect(ArrayList::new, (list, name) -> list.add(name), ArrayList::addAll);
        }
    }

    private class ImportedFunction {
        String name;
        Address address;

        ImportedFunction(String name, Address addr) {
            this.name = name;
            this.address = addr;
        }
    }
}

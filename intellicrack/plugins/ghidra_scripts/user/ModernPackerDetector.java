/**
 * Modern Packer Detector for Ghidra
 * 
 * Comprehensive packer detection including Themida, VMProtect, Enigma, and others.
 * Uses entropy analysis, PE header anomaly detection, and signature matching.
 * 
 * @category Intellicrack.PackerAnalysis
 * @author Intellicrack Framework
 * @version 2.0.0
 */

import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.*;
import ghidra.program.model.address.*;
import ghidra.program.model.symbol.*;
import ghidra.program.model.lang.*;
import ghidra.util.exception.*;
import ghidra.app.util.bin.format.pe.*;
import ghidra.app.util.bin.*;
import ghidra.app.util.opinion.*;

import java.util.*;
import java.io.*;
import java.nio.*;
import java.security.MessageDigest;

public class ModernPackerDetector extends GhidraScript {
    
    // Packer signatures database
    private static final Map<String, PackerSignature> PACKER_SIGNATURES = new HashMap<>();
    
    // Detection results
    private List<PackerDetection> detectedPackers = new ArrayList<>();
    private Map<String, Double> sectionEntropy = new HashMap<>();
    private List<PEAnomaly> peAnomalies = new ArrayList<>();
    
    // Analysis configuration
    private static final double HIGH_ENTROPY_THRESHOLD = 7.0;
    private static final double PACKED_ENTROPY_THRESHOLD = 6.5;
    
    static {
        // Initialize packer signatures
        initializePackerSignatures();
    }
    
    private static void initializePackerSignatures() {
        // Themida signatures
        PACKER_SIGNATURES.put("Themida_v2.x", new PackerSignature(
            "Themida 2.x",
            new byte[]{(byte)0xB8, 0x00, 0x00, 0x00, 0x00, 0x60, 0x0B, (byte)0xC0, 0x74, 0x68},
            Arrays.asList(".themida", ".WProtect"),
            Arrays.asList("Themida", "WProtect", "SecureEngine"),
            new PECharacteristics(true, true, true)
        ));
        
        // VMProtect signatures
        PACKER_SIGNATURES.put("VMProtect_v3.x", new PackerSignature(
            "VMProtect 3.x",
            new byte[]{0x68, 0x00, 0x00, 0x00, 0x00, (byte)0xE8, 0x00, 0x00, 0x00, 0x00},
            Arrays.asList(".vmp0", ".vmp1", ".vmp2"),
            Arrays.asList("VMProtectBegin", "VMProtectEnd"),
            new PECharacteristics(true, true, false)
        ));
        
        // Enigma Protector
        PACKER_SIGNATURES.put("Enigma_v4.x", new PackerSignature(
            "Enigma Protector 4.x",
            new byte[]{0x60, (byte)0xE8, 0x00, 0x00, 0x00, 0x00, 0x5D, (byte)0x83, (byte)0xED, 0x06},
            Arrays.asList(".enigma1", ".enigma2"),
            Arrays.asList("EP_RegHardware", "EP_CheckupCopy"),
            new PECharacteristics(true, false, true)
        ));
        
        // ASProtect
        PACKER_SIGNATURES.put("ASProtect_v2.x", new PackerSignature(
            "ASProtect 2.x",
            new byte[]{0x60, (byte)0xE8, 0x03, 0x00, 0x00, 0x00, (byte)0xE9, (byte)0xEB, 0x04},
            Arrays.asList(".aspr", ".adata", ".aspack"),
            Arrays.asList("ASProtect"),
            new PECharacteristics(true, true, true)
        ));
        
        // Obsidium
        PACKER_SIGNATURES.put("Obsidium_v1.x", new PackerSignature(
            "Obsidium 1.x",
            new byte[]{(byte)0xEB, 0x02, 0x00, 0x00, (byte)0xE8, 0x25, 0x00, 0x00, 0x00},
            Arrays.asList(".obsidium"),
            Arrays.asList("Obsidium"),
            new PECharacteristics(true, false, false)
        ));
        
        // Code Virtualizer
        PACKER_SIGNATURES.put("CodeVirtualizer", new PackerSignature(
            "Code Virtualizer",
            new byte[]{(byte)0x9C, 0x60, (byte)0xE8, 0x00, 0x00, 0x00, 0x00, 0x5D, 0x81},
            Arrays.asList(".cv"),
            Arrays.asList("VirtualizerStart", "VirtualizerEnd"),
            new PECharacteristics(true, true, true)
        ));
        
        // UPX (for comparison)
        PACKER_SIGNATURES.put("UPX", new PackerSignature(
            "UPX",
            new byte[]{0x60, (byte)0xBE, 0x00, 0x00, 0x00, 0x00, (byte)0x8D, (byte)0xBE},
            Arrays.asList("UPX0", "UPX1", "UPX2"),
            Arrays.asList("UPX"),
            new PECharacteristics(false, false, true)
        ));
        
        // PECompact
        PACKER_SIGNATURES.put("PECompact", new PackerSignature(
            "PECompact",
            new byte[]{(byte)0xB8, 0x00, 0x00, 0x00, 0x00, 0x50, 0x64, (byte)0xFF, 0x35},
            Arrays.asList(".pec2"),
            Arrays.asList("PECompact"),
            new PECharacteristics(false, false, true)
        ));
    }
    
    @Override
    public void run() throws Exception {
        println("=== Modern Packer Detector v2.0.0 ===");
        println("Analyzing for advanced packers and protectors...\n");
        
        // Phase 1: PE Header Analysis
        println("[Phase 1] Analyzing PE headers...");
        analyzePEHeaders();
        
        // Phase 2: Entropy Analysis
        println("\n[Phase 2] Performing entropy analysis...");
        performEntropyAnalysis();
        
        // Phase 3: Signature Scanning
        println("\n[Phase 3] Scanning for packer signatures...");
        scanForPackerSignatures();
        
        // Phase 4: Import Table Analysis
        println("\n[Phase 4] Analyzing import table...");
        analyzeImportTable();
        
        // Phase 5: Section Analysis
        println("\n[Phase 5] Analyzing section characteristics...");
        analyzeSections();
        
        // Phase 6: Entry Point Analysis
        println("\n[Phase 6] Analyzing entry point...");
        analyzeEntryPoint();
        
        // Phase 7: Heuristic Analysis
        println("\n[Phase 7] Running heuristic analysis...");
        performHeuristicAnalysis();
        
        // Generate final report
        generatePackerReport();
    }
    
    private void analyzePEHeaders() {
        try {
            Memory memory = currentProgram.getMemory();
            Address imageBase = currentProgram.getImageBase();
            
            // Read DOS header
            byte[] dosHeader = new byte[64];
            memory.getBytes(imageBase, dosHeader);
            
            if (dosHeader[0] != 'M' || dosHeader[1] != 'Z') {
                println("  Warning: Invalid DOS header");
                peAnomalies.add(new PEAnomaly("Invalid DOS Signature", "Critical"));
                return;
            }
            
            // Get PE header offset
            int peOffset = ByteBuffer.wrap(dosHeader, 60, 4).order(ByteOrder.LITTLE_ENDIAN).getInt();
            
            // Read PE header
            Address peAddress = imageBase.add(peOffset);
            byte[] peSignature = new byte[4];
            memory.getBytes(peAddress, peSignature);
            
            if (peSignature[0] != 'P' || peSignature[1] != 'E') {
                println("  Warning: Invalid PE header");
                peAnomalies.add(new PEAnomaly("Invalid PE Signature", "Critical"));
                return;
            }
            
            // Analyze COFF header
            Address coffAddress = peAddress.add(4);
            byte[] coffHeader = new byte[20];
            memory.getBytes(coffAddress, coffHeader);
            
            ByteBuffer coff = ByteBuffer.wrap(coffHeader).order(ByteOrder.LITTLE_ENDIAN);
            short machine = coff.getShort();
            short numberOfSections = coff.getShort();
            int timeDateStamp = coff.getInt();
            
            // Check for anomalies
            if (timeDateStamp == 0) {
                peAnomalies.add(new PEAnomaly("Zero timestamp (anti-forensics)", "Suspicious"));
            }
            
            if (numberOfSections > 20) {
                peAnomalies.add(new PEAnomaly("Excessive number of sections: " + numberOfSections, "Suspicious"));
            }
            
            // Analyze Optional Header
            Address optHeaderAddress = coffAddress.add(20);
            byte[] optHeader = new byte[224]; // Standard PE32 optional header size
            memory.getBytes(optHeaderAddress, optHeader);
            
            ByteBuffer opt = ByteBuffer.wrap(optHeader).order(ByteOrder.LITTLE_ENDIAN);
            short magic = opt.getShort();
            
            if (magic == 0x10b) {
                println("  PE32 format detected");
            } else if (magic == 0x20b) {
                println("  PE32+ format detected");
            } else {
                peAnomalies.add(new PEAnomaly("Unknown PE magic: " + String.format("0x%04X", magic), "Suspicious"));
            }
            
            // Check subsystem
            opt.position(68); // Subsystem offset
            short subsystem = opt.getShort();
            
            // Check DLL characteristics
            short dllCharacteristics = opt.getShort();
            if ((dllCharacteristics & 0x0040) != 0) { // DYNAMIC_BASE
                println("  ASLR enabled");
            }
            if ((dllCharacteristics & 0x0100) != 0) { // NX_COMPAT
                println("  DEP enabled");
            }
            
            // Check size of headers
            opt.position(60);
            int sizeOfHeaders = opt.getInt();
            if (sizeOfHeaders > 0x1000) {
                peAnomalies.add(new PEAnomaly("Unusually large headers: " + sizeOfHeaders, "Suspicious"));
            }
            
            println("  PE header analysis complete");
            
        } catch (Exception e) {
            printerr("PE header analysis failed: " + e.getMessage());
        }
    }
    
    private void performEntropyAnalysis() {
        try {
            MemoryBlock[] blocks = currentProgram.getMemory().getBlocks();
            
            for (MemoryBlock block : blocks) {
                if (!block.isExecute()) continue;
                
                String sectionName = block.getName();
                double entropy = calculateEntropy(block);
                sectionEntropy.put(sectionName, entropy);
                
                println(String.format("  Section %s: %.2f bits", sectionName, entropy));
                
                if (entropy > HIGH_ENTROPY_THRESHOLD) {
                    println("    -> HIGH ENTROPY: Likely packed/encrypted");
                    detectedPackers.add(new PackerDetection(
                        "High Entropy Section",
                        "Section " + sectionName + " shows signs of packing/encryption",
                        0.8,
                        "Entropy: " + String.format("%.2f", entropy)
                    ));
                } else if (entropy > PACKED_ENTROPY_THRESHOLD) {
                    println("    -> Moderate entropy: Possibly compressed");
                }
            }
            
        } catch (Exception e) {
            printerr("Entropy analysis failed: " + e.getMessage());
        }
    }
    
    private double calculateEntropy(MemoryBlock block) throws Exception {
        byte[] data = new byte[(int)Math.min(block.getSize(), 65536)]; // Sample first 64KB
        block.getBytes(block.getStart(), data);
        
        // Calculate byte frequency
        int[] frequency = new int[256];
        for (byte b : data) {
            frequency[b & 0xFF]++;
        }
        
        // Calculate entropy
        double entropy = 0.0;
        int total = data.length;
        
        for (int freq : frequency) {
            if (freq > 0) {
                double probability = (double) freq / total;
                entropy -= probability * Math.log(probability) / Math.log(2);
            }
        }
        
        return entropy;
    }
    
    private void scanForPackerSignatures() {
        Memory memory = currentProgram.getMemory();
        Address entryPoint = getEntryPoint();
        
        if (entryPoint == null) {
            println("  Warning: Could not determine entry point");
            return;
        }
        
        try {
            // Read bytes around entry point
            byte[] entryBytes = new byte[1024];
            memory.getBytes(entryPoint, entryBytes);
            
            // Check each signature
            for (Map.Entry<String, PackerSignature> entry : PACKER_SIGNATURES.entrySet()) {
                PackerSignature sig = entry.getValue();
                
                // Check byte pattern
                if (sig.signature != null && containsSignature(entryBytes, sig.signature)) {
                    println("  Detected: " + sig.name + " (signature match at entry point)");
                    detectedPackers.add(new PackerDetection(
                        sig.name,
                        "Signature match at entry point",
                        0.9,
                        "Pattern: " + bytesToHex(sig.signature)
                    ));
                }
                
                // Check section names
                for (String sectionName : sig.sectionNames) {
                    if (hasSectionWithName(sectionName)) {
                        println("  Detected: " + sig.name + " (section name: " + sectionName + ")");
                        detectedPackers.add(new PackerDetection(
                            sig.name,
                            "Characteristic section name found",
                            0.8,
                            "Section: " + sectionName
                        ));
                        break;
                    }
                }
                
                // Check imports
                for (String importName : sig.importNames) {
                    if (hasImport(importName)) {
                        println("  Possible: " + sig.name + " (import: " + importName + ")");
                        detectedPackers.add(new PackerDetection(
                            sig.name,
                            "Characteristic import found",
                            0.6,
                            "Import: " + importName
                        ));
                        break;
                    }
                }
            }
            
            // Advanced signature scanning
            performAdvancedSignatureScanning(memory);
            
        } catch (Exception e) {
            printerr("Signature scanning failed: " + e.getMessage());
        }
    }
    
    private void performAdvancedSignatureScanning(Memory memory) throws Exception {
        // Scan for VM handlers (VMProtect/Themida)
        scanForVMHandlers(memory);
        
        // Scan for obfuscated jumps
        scanForObfuscatedJumps(memory);
        
        // Scan for API redirection
        scanForAPIRedirection(memory);
    }
    
    private void scanForVMHandlers(Memory memory) throws Exception {
        // Look for characteristic VM handler patterns
        byte[][] vmPatterns = {
            // VMProtect handler pattern
            {(byte)0x9C, 0x60, (byte)0x8B, 0x74, 0x24, 0x24, (byte)0x8B, 0x7C, 0x24, 0x28},
            // Themida VM pattern
            {(byte)0x8B, 0x45, 0x00, (byte)0x8B, 0x4D, 0x04, (byte)0xFF, 0x60, 0x00},
            // Code Virtualizer pattern
            {0x50, 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57, (byte)0x9C}
        };
        
        Address textSection = getTextSectionStart();
        if (textSection == null) return;
        
        byte[] buffer = new byte[4096];
        Address current = textSection;
        
        while (memory.contains(current)) {
            try {
                int bytesRead = memory.getBytes(current, buffer);
                
                for (byte[] pattern : vmPatterns) {
                    if (containsSignature(buffer, pattern)) {
                        println("  Found VM handler pattern at " + current);
                        detectedPackers.add(new PackerDetection(
                            "VM-based Protector",
                            "Virtual machine handler detected",
                            0.85,
                            "Address: " + current
                        ));
                        return;
                    }
                }
                
                current = current.add(buffer.length);
                if (!memory.contains(current)) break;
                
            } catch (Exception e) {
                break;
            }
        }
    }
    
    private void scanForObfuscatedJumps(Memory memory) throws Exception {
        // Look for obfuscated control flow patterns
        Listing listing = currentProgram.getListing();
        InstructionIterator instructions = listing.getInstructions(true);
        
        int obfuscatedJumps = 0;
        int totalJumps = 0;
        
        while (instructions.hasNext() && !monitor.isCancelled()) {
            Instruction instr = instructions.next();
            
            if (instr.getFlowType().isJump()) {
                totalJumps++;
                
                // Check for indirect jumps
                if (instr.getFlowType().isIndirect()) {
                    obfuscatedJumps++;
                }
                
                // Check for jump to register
                String mnemonic = instr.getMnemonicString();
                if (mnemonic.equals("JMP") && instr.getNumOperands() == 1) {
                    Object[] opObjects = instr.getOpObjects(0);
                    if (opObjects.length > 0 && opObjects[0] instanceof Register) {
                        obfuscatedJumps++;
                    }
                }
            }
        }
        
        if (totalJumps > 0) {
            double obfuscationRatio = (double) obfuscatedJumps / totalJumps;
            if (obfuscationRatio > 0.3) {
                println("  High control flow obfuscation detected: " + 
                        String.format("%.1f%%", obfuscationRatio * 100));
                detectedPackers.add(new PackerDetection(
                    "Control Flow Obfuscation",
                    "High ratio of obfuscated jumps",
                    0.7,
                    String.format("%.1f%% indirect jumps", obfuscationRatio * 100)
                ));
            }
        }
    }
    
    private void scanForAPIRedirection(Memory memory) throws Exception {
        // Check if imports are redirected through a single function
        Symbol[] imports = getImportedSymbols();
        Map<Address, Integer> importTargets = new HashMap<>();
        
        for (Symbol imp : imports) {
            Reference[] refs = getReferencesTo(imp.getAddress());
            for (Reference ref : refs) {
                Address target = ref.getFromAddress();
                importTargets.put(target, importTargets.getOrDefault(target, 0) + 1);
            }
        }
        
        // Check if most imports go through few functions (API wrapping)
        int totalImports = imports.length;
        for (Map.Entry<Address, Integer> entry : importTargets.entrySet()) {
            if (entry.getValue() > totalImports * 0.5) {
                println("  API redirection detected at " + entry.getKey());
                detectedPackers.add(new PackerDetection(
                    "API Redirection",
                    "Imports redirected through wrapper",
                    0.75,
                    "Wrapper at: " + entry.getKey()
                ));
                break;
            }
        }
    }
    
    private void analyzeImportTable() {
        try {
            Symbol[] imports = getImportedSymbols();
            
            println("  Total imports: " + imports.length);
            
            if (imports.length < 10) {
                println("  -> Suspiciously few imports");
                peAnomalies.add(new PEAnomaly("Very few imports (" + imports.length + ")", "Highly Suspicious"));
                detectedPackers.add(new PackerDetection(
                    "Import Hiding",
                    "Abnormally low import count suggests hidden imports",
                    0.85,
                    "Import count: " + imports.length
                ));
            }
            
            // Check for common packer imports
            Set<String> suspiciousImports = new HashSet<>();
            for (Symbol imp : imports) {
                String name = imp.getName();
                if (name.contains("VirtualAlloc") || name.contains("VirtualProtect") ||
                    name.contains("LoadLibrary") || name.contains("GetProcAddress")) {
                    suspiciousImports.add(name);
                }
            }
            
            if (suspiciousImports.size() >= 3) {
                println("  -> Dynamic loading pattern detected");
                detectedPackers.add(new PackerDetection(
                    "Dynamic Import Resolution",
                    "Common unpacker APIs found",
                    0.6,
                    "APIs: " + String.join(", ", suspiciousImports)
                ));
            }
            
            // Check for single import from kernel32/ntdll
            Map<String, Integer> dllImportCount = new HashMap<>();
            for (Symbol imp : imports) {
                String dll = imp.getParentNamespace().getName();
                dllImportCount.put(dll, dllImportCount.getOrDefault(dll, 0) + 1);
            }
            
            for (Map.Entry<String, Integer> entry : dllImportCount.entrySet()) {
                if (entry.getValue() == 1 && 
                    (entry.getKey().toLowerCase().contains("kernel32") || 
                     entry.getKey().toLowerCase().contains("ntdll"))) {
                    println("  -> Single import from " + entry.getKey() + " (likely packed)");
                    peAnomalies.add(new PEAnomaly("Single import from " + entry.getKey(), "Suspicious"));
                }
            }
            
        } catch (Exception e) {
            printerr("Import analysis failed: " + e.getMessage());
        }
    }
    
    private void analyzeSections() {
        MemoryBlock[] blocks = currentProgram.getMemory().getBlocks();
        
        for (MemoryBlock block : blocks) {
            String name = block.getName();
            
            // Check for unusual section names
            if (!isStandardSectionName(name)) {
                println("  Non-standard section: " + name);
                
                // Check if it matches known packer sections
                for (PackerSignature sig : PACKER_SIGNATURES.values()) {
                    if (sig.sectionNames.contains(name)) {
                        detectedPackers.add(new PackerDetection(
                            sig.name,
                            "Characteristic section name",
                            0.85,
                            "Section: " + name
                        ));
                    }
                }
            }
            
            // Check section characteristics
            if (block.isExecute() && block.isWrite()) {
                peAnomalies.add(new PEAnomaly(
                    "Section " + name + " is both writable and executable",
                    "Suspicious"
                ));
            }
            
            // Check for sections with high entropy
            Double entropy = sectionEntropy.get(name);
            if (entropy != null && entropy > PACKED_ENTROPY_THRESHOLD) {
                if (block.isExecute()) {
                    peAnomalies.add(new PEAnomaly(
                        "Executable section " + name + " has high entropy",
                        "Likely Packed"
                    ));
                }
            }
        }
    }
    
    private void analyzeEntryPoint() {
        Address entryPoint = getEntryPoint();
        if (entryPoint == null) return;
        
        // Check which section contains entry point
        MemoryBlock entryBlock = currentProgram.getMemory().getBlock(entryPoint);
        if (entryBlock != null) {
            String sectionName = entryBlock.getName();
            
            if (!sectionName.equals(".text") && !sectionName.equals("CODE")) {
                println("  Entry point in non-standard section: " + sectionName);
                peAnomalies.add(new PEAnomaly(
                    "Entry point in section: " + sectionName,
                    "Suspicious"
                ));
                
                // High confidence if entry is in last section
                MemoryBlock[] blocks = currentProgram.getMemory().getBlocks();
                if (blocks[blocks.length - 1].equals(entryBlock)) {
                    detectedPackers.add(new PackerDetection(
                        "Generic Packer",
                        "Entry point in last section",
                        0.8,
                        "Section: " + sectionName
                    ));
                }
            }
            
            // Check entry point offset
            long epOffset = entryPoint.subtract(entryBlock.getStart());
            if (epOffset > entryBlock.getSize() * 0.9) {
                println("  Entry point near end of section");
                peAnomalies.add(new PEAnomaly(
                    "Entry point at end of section",
                    "Suspicious"
                ));
            }
        }
    }
    
    private void performHeuristicAnalysis() {
        // Combine all indicators for final detection
        
        // Check for multiple strong indicators
        int strongIndicators = 0;
        
        // High entropy executable sections
        for (MemoryBlock block : currentProgram.getMemory().getBlocks()) {
            if (block.isExecute()) {
                Double entropy = sectionEntropy.get(block.getName());
                if (entropy != null && entropy > HIGH_ENTROPY_THRESHOLD) {
                    strongIndicators++;
                }
            }
        }
        
        // Import table anomalies
        if (getImportedSymbols().length < 10) {
            strongIndicators++;
        }
        
        // PE anomalies
        for (PEAnomaly anomaly : peAnomalies) {
            if (anomaly.severity.equals("Highly Suspicious") || 
                anomaly.severity.equals("Likely Packed")) {
                strongIndicators++;
            }
        }
        
        // Entry point anomalies
        Address ep = getEntryPoint();
        if (ep != null) {
            MemoryBlock epBlock = currentProgram.getMemory().getBlock(ep);
            if (epBlock != null && !epBlock.getName().equals(".text")) {
                strongIndicators++;
            }
        }
        
        // Make final determination
        if (strongIndicators >= 3) {
            println("\n  -> CONCLUSION: Binary is highly likely packed/protected");
            
            // Try to determine specific packer
            PackerDetection bestMatch = null;
            double highestConfidence = 0.0;
            
            for (PackerDetection detection : detectedPackers) {
                if (detection.confidence > highestConfidence) {
                    bestMatch = detection;
                    highestConfidence = detection.confidence;
                }
            }
            
            if (bestMatch != null && highestConfidence >= 0.7) {
                println("  -> Most likely packer: " + bestMatch.packerName);
            } else {
                println("  -> Specific packer unknown (custom or heavily modified)");
            }
        } else if (strongIndicators >= 1) {
            println("\n  -> CONCLUSION: Binary shows some packing/protection characteristics");
        } else {
            println("\n  -> CONCLUSION: Binary appears to be unpacked");
        }
    }
    
    private void generatePackerReport() {
        println("\n=== Packer Detection Report ===\n");
        
        // Sort detections by confidence
        detectedPackers.sort((a, b) -> Double.compare(b.confidence, a.confidence));
        
        if (!detectedPackers.isEmpty()) {
            println("Detected Packers/Protectors:");
            for (PackerDetection detection : detectedPackers) {
                println(String.format("  %s (%.0f%% confidence)",
                    detection.packerName, detection.confidence * 100));
                println("    Reason: " + detection.reason);
                println("    Details: " + detection.details);
            }
        }
        
        if (!peAnomalies.isEmpty()) {
            println("\nPE Anomalies:");
            for (PEAnomaly anomaly : peAnomalies) {
                println("  " + anomaly.description + " [" + anomaly.severity + "]");
            }
        }
        
        println("\nSection Entropy Analysis:");
        for (Map.Entry<String, Double> entry : sectionEntropy.entrySet()) {
            println(String.format("  %s: %.2f bits", entry.getKey(), entry.getValue()));
        }
        
        // Provide unpacking recommendations
        println("\n=== Unpacking Recommendations ===\n");
        
        if (!detectedPackers.isEmpty()) {
            PackerDetection primary = detectedPackers.get(0);
            
            if (primary.packerName.contains("Themida")) {
                println("For Themida:");
                println("  1. Use Scylla to dump process from OEP");
                println("  2. Fix imports with Scylla's IAT autosearch");
                println("  3. Consider using ThemidaUnpacker plugin");
                println("  4. Manual: Set hardware breakpoints on VirtualProtect");
            } else if (primary.packerName.contains("VMProtect")) {
                println("For VMProtect:");
                println("  1. Use VMUnpacker or similar tools");
                println("  2. Trace through VM handlers to find OEP");
                println("  3. Devirtualize critical functions manually");
                println("  4. Consider using Ghidra's P-Code for VM analysis");
            } else if (primary.packerName.contains("Enigma")) {
                println("For Enigma Protector:");
                println("  1. Find OEP using hardware breakpoints");
                println("  2. Dump at OEP and reconstruct imports");
                println("  3. Patch registration checks if needed");
                println("  4. Handle anti-debugging with ScyllaHide");
            } else if (primary.packerName.contains("UPX")) {
                println("For UPX:");
                println("  1. Use 'upx -d' for standard unpacking");
                println("  2. For modified UPX, trace to OEP manually");
                println("  3. Set breakpoint on common OEP patterns");
            } else {
                println("For Unknown/Generic Packer:");
                println("  1. Find OEP using ESP trick or hardware breakpoints");
                println("  2. Dump process memory at OEP");
                println("  3. Reconstruct import table with Scylla");
                println("  4. Fix section characteristics if needed");
            }
            
            println("\nGeneral Tips:");
            println("  - Use x64dbg with ScyllaHide for anti-debugging bypass");
            println("  - Monitor VirtualAlloc/VirtualProtect for unpacking");
            println("  - Check for multiple packing layers");
            println("  - Consider behavioral analysis if static unpacking fails");
        }
        
        // Export detailed report
        exportDetailedReport();
    }
    
    private void exportDetailedReport() {
        try {
            File reportFile = askFile("Save Packer Analysis Report", "Save");
            if (reportFile == null) return;
            
            PrintWriter writer = new PrintWriter(reportFile);
            writer.println("Modern Packer Detection Report");
            writer.println("Generated by Intellicrack Packer Detector v2.0.0");
            writer.println("Date: " + new Date());
            writer.println("Program: " + currentProgram.getName());
            writer.println("=====================================\n");
            
            // Write all findings
            writer.println("Summary:");
            writer.println("  Total detections: " + detectedPackers.size());
            writer.println("  PE anomalies: " + peAnomalies.size());
            writer.println("  High entropy sections: " + 
                sectionEntropy.values().stream().filter(e -> e > HIGH_ENTROPY_THRESHOLD).count());
            
            writer.println("\nDetailed Findings:");
            for (PackerDetection detection : detectedPackers) {
                writer.println("\n" + detection.packerName);
                writer.println("  Confidence: " + String.format("%.0f%%", detection.confidence * 100));
                writer.println("  Reason: " + detection.reason);
                writer.println("  Details: " + detection.details);
            }
            
            writer.close();
            println("\nDetailed report saved to: " + reportFile.getAbsolutePath());
            
        } catch (Exception e) {
            printerr("Failed to export report: " + e.getMessage());
        }
    }
    
    // Helper methods
    private Address getEntryPoint() {
        SymbolTable symTable = currentProgram.getSymbolTable();
        Symbol[] symbols = symTable.getSymbols("entry");
        if (symbols.length > 0) {
            return symbols[0].getAddress();
        }
        
        // Try alternative names
        String[] entryNames = {"_start", "mainCRTStartup", "WinMainCRTStartup", "DllMain"};
        for (String name : entryNames) {
            symbols = symTable.getSymbols(name);
            if (symbols.length > 0) {
                return symbols[0].getAddress();
            }
        }
        
        return null;
    }
    
    private Address getTextSectionStart() {
        MemoryBlock textBlock = currentProgram.getMemory().getBlock(".text");
        if (textBlock != null) {
            return textBlock.getStart();
        }
        
        // Try alternative names
        textBlock = currentProgram.getMemory().getBlock("CODE");
        if (textBlock != null) {
            return textBlock.getStart();
        }
        
        return null;
    }
    
    private boolean containsSignature(byte[] data, byte[] signature) {
        if (signature.length > data.length) return false;
        
        for (int i = 0; i <= data.length - signature.length; i++) {
            boolean match = true;
            for (int j = 0; j < signature.length; j++) {
                if (signature[j] != 0x00 && data[i + j] != signature[j]) {
                    match = false;
                    break;
                }
            }
            if (match) return true;
        }
        return false;
    }
    
    private boolean hasSectionWithName(String name) {
        MemoryBlock[] blocks = currentProgram.getMemory().getBlocks();
        for (MemoryBlock block : blocks) {
            if (block.getName().equalsIgnoreCase(name)) {
                return true;
            }
        }
        return false;
    }
    
    private boolean hasImport(String importName) {
        Symbol[] imports = getImportedSymbols();
        for (Symbol imp : imports) {
            if (imp.getName().contains(importName)) {
                return true;
            }
        }
        return false;
    }
    
    private Symbol[] getImportedSymbols() {
        List<Symbol> imports = new ArrayList<>();
        SymbolTable symTable = currentProgram.getSymbolTable();
        SymbolIterator iter = symTable.getExternalSymbols();
        
        while (iter.hasNext()) {
            imports.add(iter.next());
        }
        
        return imports.toArray(new Symbol[0]);
    }
    
    private boolean isStandardSectionName(String name) {
        String[] standard = {".text", ".data", ".rdata", ".bss", ".rsrc", 
                           ".reloc", ".idata", ".edata", ".pdata", ".xdata",
                           "CODE", "DATA", "BSS", ".code", ".const"};
        
        for (String std : standard) {
            if (name.equalsIgnoreCase(std)) {
                return true;
            }
        }
        return false;
    }
    
    private String bytesToHex(byte[] bytes) {
        StringBuilder result = new StringBuilder();
        for (byte b : bytes) {
            result.append(String.format("%02X ", b));
        }
        return result.toString().trim();
    }
    
    // Inner classes
    private static class PackerSignature {
        String name;
        byte[] signature;
        List<String> sectionNames;
        List<String> importNames;
        PECharacteristics characteristics;
        
        PackerSignature(String name, byte[] signature, List<String> sections, 
                       List<String> imports, PECharacteristics chars) {
            this.name = name;
            this.signature = signature;
            this.sectionNames = sections;
            this.importNames = imports;
            this.characteristics = chars;
        }
    }
    
    private static class PECharacteristics {
        boolean hasAntiDebug;
        boolean hasAntiVM;
        boolean hasCompression;
        
        PECharacteristics(boolean antiDebug, boolean antiVM, boolean compression) {
            this.hasAntiDebug = antiDebug;
            this.hasAntiVM = antiVM;
            this.hasCompression = compression;
        }
    }
    
    private static class PackerDetection {
        String packerName;
        String reason;
        double confidence;
        String details;
        
        PackerDetection(String name, String reason, double confidence, String details) {
            this.packerName = name;
            this.reason = reason;
            this.confidence = confidence;
            this.details = details;
        }
    }
    
    private static class PEAnomaly {
        String description;
        String severity;
        
        PEAnomaly(String desc, String severity) {
            this.description = desc;
            this.severity = severity;
        }
    }
}
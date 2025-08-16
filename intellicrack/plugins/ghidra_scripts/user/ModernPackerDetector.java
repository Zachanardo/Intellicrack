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
    private Map<String, String> sectionHashes = new HashMap<>();
    private List<FunctionAnomaly> functionAnomalies = new ArrayList<>();

    // Analysis configuration
    private static final double HIGH_ENTROPY_THRESHOLD = 7.0;
    private static final double PACKED_ENTROPY_THRESHOLD = 6.5;
    private BufferedReader configReader = null;
    private FileWriter reportWriter = null;
    private PrintWriter consoleLogger = null;
    private int totalPhases = 8;
    private int currentPhase = 0;

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
        // Initialize enhanced console logging
        initializeConsoleLogger();
        
        consoleLogger.println("=== Modern Packer Detector v2.0.0 ===");
        consoleLogger.println("Analyzing for advanced packers and protectors...");
        consoleLogger.println("Program: " + currentProgram.getName());
        consoleLogger.printf("Image Base: 0x%08X%n", currentProgram.getImageBase().getOffset());
        consoleLogger.printf("Total Phases: %d%n%n", totalPhases);
        consoleLogger.flush();

        try {
            // Load configuration if available
            loadConfiguration();

            // Phase 1: PE Header Analysis
            currentPhase = 1;
            logPhaseStart("PE Header Analysis", "Examining DOS, PE, and COFF headers");
            analyzePEHeaders();
            logPhaseComplete();

            // Phase 2: Entropy Analysis
            currentPhase = 2;
            logPhaseStart("Entropy Analysis", "Calculating section entropy for packing detection");
            performEntropyAnalysis();
            logPhaseComplete();

            // Phase 3: Signature Scanning
            currentPhase = 3;
            logPhaseStart("Signature Scanning", "Detecting known packer signatures and patterns");
            scanForPackerSignatures();
            logPhaseComplete();

            // Phase 4: Import Table Analysis
            currentPhase = 4;
            logPhaseStart("Import Table Analysis", "Examining import characteristics and anomalies");
            analyzeImportTable();
            logPhaseComplete();

            // Phase 5: Section Analysis
            currentPhase = 5;
            logPhaseStart("Section Analysis", "Analyzing section characteristics and permissions");
            analyzeSections();
            logPhaseComplete();

            // Phase 6: Entry Point Analysis
            currentPhase = 6;
            logPhaseStart("Entry Point Analysis", "Examining entry point location and characteristics");
            analyzeEntryPoint();
            logPhaseComplete();

            // Phase 7: Function Analysis (NEW)
            currentPhase = 7;
            logPhaseStart("Function Analysis", "Analyzing function patterns and VM dispatchers");
            analyzeFunctions();
            logPhaseComplete();

            // Phase 8: Heuristic Analysis
            currentPhase = 8;
            logPhaseStart("Heuristic Analysis", "Combining indicators for final determination");
            performHeuristicAnalysis();
            logPhaseComplete();

            // Generate final report
            generatePackerReport();

        } catch (CancelledException ce) {
            println("Analysis cancelled by user");
            throw ce;
        } catch (InvalidInputException iie) {
            printerr("Invalid input: " + iie.getMessage());
            throw iie;
        } finally {
            cleanup();
        }
        
        consoleLogger.println("\n" + "=".repeat(50));
        consoleLogger.println("Analysis completed successfully!");
        consoleLogger.printf("Total detections: %d%n", detectedPackers.size());
        consoleLogger.printf("PE anomalies found: %d%n", peAnomalies.size());
        consoleLogger.printf("Function anomalies: %d%n", functionAnomalies.size());
        consoleLogger.println("=".repeat(50));
        consoleLogger.flush();
    }

    private void loadConfiguration() {
        try {
            File configFile = new File(currentProgram.getExecutablePath(), ".packer_config");
            if (configFile.exists()) {
                configReader = new BufferedReader(new FileReader(configFile));
                String line;
                while ((line = configReader.readLine()) != null) {
                    if (line.startsWith("entropy_threshold=")) {
                        // Parse configuration
                        println("  Loaded config: " + line);
                    }
                }
                configReader.close();
            }
        } catch (IOException ioe) {
            println("  No configuration file found, using defaults");
        }
    }

    private void initializeConsoleLogger() {
        try {
            // Create PrintWriter for enhanced console output
            consoleLogger = new PrintWriter(System.out, true);
            
            // Print analysis header with timestamp
            consoleLogger.println("Analysis started at: " + new java.util.Date());
            consoleLogger.println("Packer Detection Engine initialized");
            consoleLogger.println("-".repeat(50));
            consoleLogger.flush();
            
        } catch (Exception e) {
            // Fallback to standard println if PrintWriter fails
            println("Warning: Enhanced logging initialization failed: " + e.getMessage());
            // Create a dummy PrintWriter that writes to System.out
            consoleLogger = new PrintWriter(System.out, true);
        }
    }
    
    private void logPhaseStart(String phaseName, String description) {
        consoleLogger.printf("%n[Phase %d/%d] %s%n", currentPhase, totalPhases, phaseName);
        consoleLogger.println("  Description: " + description);
        consoleLogger.println("  Status: Starting...");
        consoleLogger.flush();
    }
    
    private void logPhaseComplete() {
        double progress = (double) currentPhase / totalPhases * 100;
        consoleLogger.printf("  Status: ✓ Complete (%.1f%% total progress)%n", progress);
        
        // Print progress bar
        int barLength = 30;
        int filled = (int) (progress / 100.0 * barLength);
        StringBuilder bar = new StringBuilder("  Progress: [");
        for (int i = 0; i < barLength; i++) {
            if (i < filled) {
                bar.append("=");
            } else if (i == filled) {
                bar.append(">");
            } else {
                bar.append(" ");
            }
        }
        bar.append(String.format("] %.1f%%", progress));
        consoleLogger.println(bar.toString());
        consoleLogger.flush();
    }
    
    private void logDetection(String packerName, double confidence, String details) {
        consoleLogger.printf("  [DETECTION] %s (%.0f%% confidence)%n", packerName, confidence * 100);
        consoleLogger.println("    " + details);
        consoleLogger.flush();
    }
    
    private void logAnomaly(String anomaly, String severity) {
        String severityIndicator;
        switch (severity) {
            case "Critical":
                severityIndicator = "[!!!]";
                break;
            case "Highly Suspicious":
                severityIndicator = "[!!]";
                break;
            case "Suspicious":
                severityIndicator = "[!]";
                break;
            default:
                severityIndicator = "[?]";
        }
        consoleLogger.printf("  %s %s%n", severityIndicator, anomaly);
        consoleLogger.flush();
    }
    
    private void cleanup() {
        try {
            if (configReader != null) configReader.close();
            if (reportWriter != null) reportWriter.close();
            if (consoleLogger != null) {
                consoleLogger.println("\nCleaning up resources...");
                consoleLogger.flush();
                consoleLogger.close();
            }
        } catch (IOException e) {
            // Ignore cleanup errors
        }
    }

    private void analyzePEHeaders() {
        try {
            Memory memory = currentProgram.getMemory();
            Address imageBase = currentProgram.getImageBase();

            // Read DOS header
            byte[] dosHeader = new byte[64];
            memory.getBytes(imageBase, dosHeader);

            if (dosHeader[0] != 'M' || dosHeader[1] != 'Z') {
                logAnomaly("Invalid DOS header signature", "Critical");
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
                logAnomaly("Invalid PE header signature", "Critical");
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
                logAnomaly("Zero timestamp detected (anti-forensics)", "Suspicious");
                peAnomalies.add(new PEAnomaly("Zero timestamp (anti-forensics)", "Suspicious"));
            }

            if (numberOfSections > 20) {
                logAnomaly("Excessive number of sections: " + numberOfSections, "Suspicious");
                peAnomalies.add(new PEAnomaly("Excessive number of sections: " + numberOfSections, "Suspicious"));
            }

            // Analyze Optional Header
            Address optHeaderAddress = coffAddress.add(20);
            byte[] optHeader = new byte[224]; // Standard PE32 optional header size
            memory.getBytes(optHeaderAddress, optHeader);

            ByteBuffer opt = ByteBuffer.wrap(optHeader).order(ByteOrder.LITTLE_ENDIAN);
            short magic = opt.getShort();

            if (magic == 0x10b) {
                consoleLogger.println("  ✓ PE32 format detected");
            } else if (magic == 0x20b) {
                consoleLogger.println("  ✓ PE32+ format detected");
            } else {
                logAnomaly("Unknown PE magic: " + String.format("0x%04X", magic), "Suspicious");
                peAnomalies.add(new PEAnomaly("Unknown PE magic: " + String.format("0x%04X", magic), "Suspicious"));
            }

            // Check subsystem
            opt.position(68); // Subsystem offset
            short subsystem = opt.getShort();

            // Check DLL characteristics
            short dllCharacteristics = opt.getShort();
            if ((dllCharacteristics & 0x0040) != 0) { // DYNAMIC_BASE
                consoleLogger.println("  ✓ ASLR enabled");
            }
            if ((dllCharacteristics & 0x0100) != 0) { // NX_COMPAT
                consoleLogger.println("  ✓ DEP enabled");
            }

            // Check size of headers
            opt.position(60);
            int sizeOfHeaders = opt.getInt();
            if (sizeOfHeaders > 0x1000) {
                logAnomaly("Unusually large headers: " + sizeOfHeaders, "Suspicious");
                peAnomalies.add(new PEAnomaly("Unusually large headers: " + sizeOfHeaders, "Suspicious"));
            }

            consoleLogger.printf("  ✓ Headers analyzed - %d sections, %d anomalies found%n", numberOfSections, peAnomalies.size());

        } catch (Exception e) {
            printerr("PE header analysis failed: " + e.getMessage());
        }
    }

    private void performEntropyAnalysis() {
        try {
            MemoryBlock[] blocks = currentProgram.getMemory().getBlocks();
            MessageDigest md = MessageDigest.getInstance("SHA-256");

            for (MemoryBlock block : blocks) {
                if (!block.isExecute()) continue;

                String sectionName = block.getName();
                double entropy = calculateEntropy(block);
                sectionEntropy.put(sectionName, entropy);

                // Calculate section hash for signature matching
                try {
                    byte[] sectionData = new byte[(int)Math.min(block.getSize(), 4096)];
                    block.getBytes(block.getStart(), sectionData);
                    md.reset();
                    byte[] hash = md.digest(sectionData);
                    String hashStr = bytesToHex(hash);
                    sectionHashes.put(sectionName, hashStr);
                } catch (MemoryAccessException mae) {
                    println("    Warning: Cannot hash section " + sectionName + ": " + mae.getMessage());
                }

                consoleLogger.printf("  Section %s: %.2f bits", sectionName, entropy);

                if (entropy > HIGH_ENTROPY_THRESHOLD) {
                    consoleLogger.println(" -> HIGH ENTROPY: Likely packed/encrypted");
                    logDetection("High Entropy Section", 0.8, "Section " + sectionName + " entropy: " + String.format("%.2f", entropy));
                    detectedPackers.add(new PackerDetection(
                        "High Entropy Section",
                        "Section " + sectionName + " shows signs of packing/encryption",
                        0.8,
                        "Entropy: " + String.format("%.2f", entropy)
                    ));
                } else if (entropy > PACKED_ENTROPY_THRESHOLD) {
                    consoleLogger.println(" -> Moderate entropy: Possibly compressed");
                } else {
                    consoleLogger.println(" -> Normal entropy");
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
                    logDetection(sig.name, 0.9, "Signature match at entry point");
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
                        logDetection(sig.name, 0.8, "Characteristic section: " + sectionName);
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

        // Use NIO buffers for efficient pattern matching
        byte[] rawBuffer = new byte[8192];
        ByteBuffer buffer = ByteBuffer.allocate(8192);
        IntBuffer intView = buffer.asIntBuffer();
        CharBuffer charView = buffer.asCharBuffer();
        
        Address current = textSection;
        
        // Create AddressSetView for text section
        MemoryBlock textBlock = memory.getBlock(textSection);
        AddressSetView textView = new AddressSet(textBlock.getStart(), textBlock.getEnd());

        while (memory.contains(current)) {
            try {
                int bytesRead = memory.getBytes(current, rawBuffer);
                buffer.clear();
                buffer.put(rawBuffer, 0, bytesRead);
                buffer.flip();
                
                // Check for VM patterns using ByteBuffer
                for (byte[] pattern : vmPatterns) {
                    if (containsPatternInBuffer(buffer, pattern)) {
                        println("  Found VM handler pattern at " + current);
                        detectedPackers.add(new PackerDetection(
                            "VM-based Protector",
                            "Virtual machine handler detected",
                            0.85,
                            "Address: " + current
                        ));
                        
                        // Check for additional VM characteristics using IntBuffer
                        intView.rewind();
                        int vmOpcodeCount = 0;
                        while (intView.hasRemaining()) {
                            int value = intView.get();
                            // Check for VM opcode patterns (common values in VM handlers)
                            if ((value & 0xFF) >= 0x80 && (value & 0xFF) <= 0xFF) {
                                vmOpcodeCount++;
                            }
                        }
                        
                        if (vmOpcodeCount > 20) {
                            println("    High VM opcode density detected");
                        }
                        return;
                    }
                }
                
                // Analyze character patterns for string obfuscation
                charView.rewind();
                int obfuscatedChars = 0;
                while (charView.hasRemaining()) {
                    char c = charView.get();
                    if (c >= 0x100 && c <= 0x1FF) {
                        obfuscatedChars++;
                    }
                }
                
                if (obfuscatedChars > charView.capacity() * 0.3) {
                    println("  Obfuscated strings detected at " + current);
                }

                current = current.add(buffer.capacity());
                if (!memory.contains(current)) break;

            } catch (MemoryAccessException mae) {
                println("  Memory access error at " + current + ": " + mae.getMessage());
                current = current.add(0x1000); // Skip to next page
            } catch (Exception e) {
                break;
            }
        }
    }
    
    private boolean containsPatternInBuffer(ByteBuffer buffer, byte[] pattern) {
        if (pattern.length > buffer.remaining()) return false;
        
        int originalPos = buffer.position();
        
        while (buffer.remaining() >= pattern.length) {
            boolean match = true;
            int startPos = buffer.position();
            
            for (byte b : pattern) {
                if (b != 0x00 && buffer.get() != b) {
                    match = false;
                    break;
                }
            }
            
            if (match) {
                buffer.position(originalPos);
                return true;
            }
            
            buffer.position(startPos + 1);
        }
        
        buffer.position(originalPos);
        return false;
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
        ReferenceManager refMgr = currentProgram.getReferenceManager();
        
        // Create address set for import region analysis
        AddressSet importAddresses = new AddressSet();
        
        for (Symbol imp : imports) {
            Address impAddr = imp.getAddress();
            importAddresses.add(impAddr);
            
            // Use ReferenceManager for better reference tracking
            ReferenceIterator refIter = refMgr.getReferencesTo(impAddr);
            while (refIter.hasNext()) {
                Reference ref = refIter.next();
                Address target = ref.getFromAddress();
                AddressSpace space = target.getAddressSpace();
                
                // Only consider references from executable space
                if (space.isExecutableSpace()) {
                    importTargets.put(target, importTargets.getOrDefault(target, 0) + 1);
                }
            }
        }
        
        // Analyze import address ranges for anomalies
        for (AddressRange range : importAddresses.getAddressRanges()) {
            long rangeSize = range.getLength();
            if (rangeSize < 0x100 && imports.length > 50) {
                // Too many imports in small range - likely obfuscated
                println("  Import table compression detected");
                detectedPackers.add(new PackerDetection(
                    "Import Table Obfuscation",
                    "Compressed import address range",
                    0.7,
                    String.format("Range: %s (size: 0x%X)", range, rangeSize)
                ));
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

    private void analyzeFunctions() {
        try {
            FunctionManager funcMgr = currentProgram.getFunctionManager();
            Language lang = currentProgram.getLanguage();
            int totalFunctions = funcMgr.getFunctionCount();
            
            println("  Total functions: " + totalFunctions);
            
            if (totalFunctions < 5) {
                functionAnomalies.add(new FunctionAnomaly("Very few functions", "Highly Suspicious"));
                detectedPackers.add(new PackerDetection(
                    "Function Hiding",
                    "Abnormally low function count",
                    0.85,
                    "Function count: " + totalFunctions
                ));
            }
            
            // Analyze functions for VM entry patterns
            Iterator<Function> funcIter = funcMgr.getFunctions(true);
            int vmEntries = 0;
            int obfuscatedPrologues = 0;
            
            while (funcIter.hasNext() && !monitor.isCancelled()) {
                Function func = funcIter.next();
                
                // Check function prologue for obfuscation
                if (analyzeFunctionPrologue(func, lang)) {
                    obfuscatedPrologues++;
                }
                
                // Check for VM dispatcher patterns
                if (isVMDispatcher(func)) {
                    vmEntries++;
                    println("    VM dispatcher found at: " + func.getEntryPoint());
                }
            }
            
            if (vmEntries > 0) {
                detectedPackers.add(new PackerDetection(
                    "VM-based Protection",
                    "Virtual machine dispatchers detected",
                    0.9,
                    "VM dispatchers: " + vmEntries
                ));
            }
            
            if (obfuscatedPrologues > totalFunctions * 0.3) {
                detectedPackers.add(new PackerDetection(
                    "Function Obfuscation",
                    "Many obfuscated function prologues",
                    0.75,
                    String.format("%.1f%% obfuscated", (double)obfuscatedPrologues/totalFunctions * 100)
                ));
            }
            
        } catch (Exception e) {
            printerr("Function analysis failed: " + e.getMessage());
        }
    }
    
    private boolean analyzeFunctionPrologue(Function func, Language lang) throws CancelledException {
        monitor.checkCancelled();
        
        AddressSetView funcBody = func.getBody();
        InstructionIterator instrIter = currentProgram.getListing().getInstructions(funcBody, true);
        
        // Get first few instructions
        int count = 0;
        boolean hasStandardPrologue = false;
        Register frameReg = lang.getDefaultStackPointerRegister();
        
        while (instrIter.hasNext() && count < 5) {
            Instruction instr = instrIter.next();
            CodeUnit cu = currentProgram.getListing().getCodeUnitAt(instr.getAddress());
            
            if (cu != null) {
                String mnemonic = cu.getMnemonicString();
                
                // Check for standard prologue patterns
                if (count == 0 && mnemonic.equals("PUSH") && instr.getNumOperands() == 1) {
                    // Check if pushing frame pointer
                    Object[] ops = instr.getOpObjects(0);
                    if (ops.length > 0 && ops[0] instanceof Register) {
                        Register reg = (Register) ops[0];
                        if (reg.getName().contains("BP") || reg.getName().contains("bp")) {
                            hasStandardPrologue = true;
                        }
                    }
                }
                
                // Check operand types for obfuscation
                for (int i = 0; i < instr.getNumOperands(); i++) {
                    int opType = instr.getOperandType(i);
                    if ((opType & OperandType.DYNAMIC) != 0) {
                        // Dynamic operand suggests obfuscation
                        return true;
                    }
                }
            }
            count++;
        }
        
        return !hasStandardPrologue && count > 0;
    }
    
    private boolean isVMDispatcher(Function func) throws CancelledException {
        monitor.checkCancelled();
        
        // Check for dispatcher characteristics
        AddressSetView body = func.getBody();
        long size = body.getNumAddresses();
        
        // VM dispatchers are typically large
        if (size < 100) return false;
        
        // Count jumps and switches
        InstructionIterator instrIter = currentProgram.getListing().getInstructions(body, true);
        int jumpCount = 0;
        int indirectJumps = 0;
        
        while (instrIter.hasNext() && !monitor.isCancelled()) {
            Instruction instr = instrIter.next();
            
            if (instr.getFlowType().isJump()) {
                jumpCount++;
                if (instr.getFlowType().isIndirect()) {
                    indirectJumps++;
                }
            }
            
            // Check for switch-like patterns
            if (instr.getMnemonicString().equals("JMP") && instr.getNumOperands() == 1) {
                Object[] ops = instr.getOpObjects(0);
                if (ops.length > 0 && ops[0] instanceof Register) {
                    // Jump to register (typical in VM)
                    RegisterValue rv = new RegisterValue(
                        currentProgram.getProgramContext().getRegister(((Register)ops[0]).getName())
                    );
                    // VM pattern detected
                    if (indirectJumps > 5) {
                        return true;
                    }
                }
            }
        }
        
        // High ratio of jumps suggests dispatcher
        return jumpCount > 20 && indirectJumps > jumpCount * 0.3;
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

            reportWriter = new FileWriter(reportFile);
            reportWriter.write("Modern Packer Detection Report\n");
            reportWriter.write("Generated by Intellicrack Packer Detector v2.0.0\n");
            reportWriter.write("Date: " + new Date() + "\n");
            reportWriter.write("Program: " + currentProgram.getName() + "\n");
            reportWriter.write("=====================================\n\n");

            // Write all findings
            reportWriter.write("Summary:\n");
            reportWriter.write("  Total detections: " + detectedPackers.size() + "\n");
            reportWriter.write("  PE anomalies: " + peAnomalies.size() + "\n");
            reportWriter.write("  Function anomalies: " + functionAnomalies.size() + "\n");
            reportWriter.write("  High entropy sections: " +
                sectionEntropy.values().stream().filter(e -> e > HIGH_ENTROPY_THRESHOLD).count() + "\n");

            reportWriter.write("\nSection Hashes:\n");
            for (Map.Entry<String, String> entry : sectionHashes.entrySet()) {
                reportWriter.write("  " + entry.getKey() + ": " + entry.getValue().substring(0, 16) + "...\n");
            }

            reportWriter.write("\nDetailed Findings:\n");
            for (PackerDetection detection : detectedPackers) {
                reportWriter.write("\n" + detection.packerName + "\n");
                reportWriter.write("  Confidence: " + String.format("%.0f%%", detection.confidence * 100) + "\n");
                reportWriter.write("  Reason: " + detection.reason + "\n");
                reportWriter.write("  Details: " + detection.details + "\n");
            }

            reportWriter.write("\nFunction Anomalies:\n");
            for (FunctionAnomaly anomaly : functionAnomalies) {
                reportWriter.write("  " + anomaly.description + " [" + anomaly.severity + "]\n");
            }

            reportWriter.close();
            reportWriter = null;
            println("\nDetailed report saved to: " + reportFile.getAbsolutePath());

        } catch (IOException ioe) {
            printerr("Failed to export report: " + ioe.getMessage());
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

    private static class FunctionAnomaly {
        String description;
        String severity;

        FunctionAnomaly(String desc, String severity) {
            this.description = desc;
            this.severity = severity;
        }
    }
}

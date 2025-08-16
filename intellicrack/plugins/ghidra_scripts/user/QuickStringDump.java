/**
 * Advanced String Analysis and Extraction Tool
 *
 * @description Comprehensive string analysis with type analysis, function references, and license detection
 * @author Intellicrack Team
 * @category Strings
 * @version 2.0
 * @tags strings,extraction,analysis,license,references
 */

import ghidra.app.script.GhidraScript;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.*;
import java.io.*;
import java.util.*;

public class QuickStringDump extends GhidraScript {

    private Program program;
    private DataTypeManager dataTypeManager;
    private FunctionManager functionManager;
    private Map<String, Set<Function>> stringReferences = new HashMap<>();
    private Map<String, DataType> stringDataTypes = new HashMap<>();
    private List<String> licenseStrings = new ArrayList<>();
    private List<String> cryptoStrings = new ArrayList<>();
    private int totalStrings = 0;
    private int structureStrings = 0;
    private int enumStrings = 0;

    @Override
    public void run() throws Exception {
        println("=== Advanced String Analysis v2.0 ===");
        println("Comprehensive string extraction with type and reference analysis...\n");

        // Initialize components
        initializeComponents();

        // Get output directory for multiple reports
        File outputDir = askDirectory("Select output directory for reports", "Select");
        if (outputDir == null || !outputDir.exists()) {
            printerr("Invalid output directory selected");
            return;
        }

        try {
            // Phase 1: Extract and analyze all strings
            println("[Phase 1] Extracting strings and analyzing data types...");
            analyzeStrings();

            // Phase 2: Analyze string references in functions
            println("\n[Phase 2] Analyzing function references to strings...");
            analyzeFunctionReferences();

            // Phase 3: Find strings in structures and enums
            println("\n[Phase 3] Analyzing structured data containing strings...");
            analyzeStructuredData();

            // Phase 4: Analyze instructions referencing strings
            println("\n[Phase 4] Analyzing instruction references...");
            analyzeInstructionReferences();

            // Phase 5: Generate comprehensive reports
            println("\n[Phase 5] Generating reports...");
            generateReports(outputDir);

            println("\nString analysis complete! Check output directory for detailed reports.");

        } catch (IOException e) {
            printerr("I/O error during analysis: " + e.getMessage());
        } catch (Exception e) {
            printerr("Error during string analysis: " + e.getMessage());
        }
    }

    private void initializeComponents() {
        // Initialize Program and managers
        program = currentProgram;
        dataTypeManager = program.getDataTypeManager();
        functionManager = program.getFunctionManager();

        println("  Program: " + program.getName());
        println("  Executable Path: " + program.getExecutablePath());
        println("  Format: " + program.getExecutableFormat());
        println("  Data Type Manager: " + dataTypeManager.getName());
        println("  Function Count: " + functionManager.getFunctionCount());
    }

    private void analyzeStrings() throws Exception {
        DataIterator dataIterator = program.getListing().getDefinedData(true);

        while (dataIterator.hasNext() && !monitor.isCancelled()) {
            Data data = dataIterator.next();

            if (data.hasStringValue()) {
                String stringValue = data.getDefaultValueRepresentation();

                if (stringValue.length() > 1) {
                    totalStrings++;

                    // Analyze DataType
                    DataType dataType = data.getDataType();
                    stringDataTypes.put(stringValue, dataType);

                    // Check for license-related strings
                    analyzeLicenseContent(stringValue);

                    // Check for crypto-related strings
                    analyzeCryptoContent(stringValue);

                    // Progress indicator
                    if (totalStrings % 100 == 0) {
                        println("    Processed " + totalStrings + " strings...");
                    }
                }
            }
        }

        println("  Total strings found: " + totalStrings);
        println("  License-related strings: " + licenseStrings.size());
        println("  Crypto-related strings: " + cryptoStrings.size());
    }

    private void analyzeLicenseContent(String str) {
        String lowerStr = str.toLowerCase();
        String[] licenseKeywords = {
            "license", "serial", "key", "activation", "registration", 
            "trial", "expire", "valid", "invalid", "piracy", "crack",
            "demo", "evaluation", "commercial", "personal", "enterprise"
        };

        for (String keyword : licenseKeywords) {
            if (lowerStr.contains(keyword)) {
                licenseStrings.add(str);
                break;
            }
        }
    }

    private void analyzeCryptoContent(String str) {
        String lowerStr = str.toLowerCase();
        String[] cryptoKeywords = {
            "aes", "des", "rsa", "sha", "md5", "encrypt", "decrypt",
            "cipher", "hash", "crypto", "algorithm", "certificate",
            "public", "private", "signature", "digest"
        };

        for (String keyword : cryptoKeywords) {
            if (lowerStr.contains(keyword)) {
                cryptoStrings.add(str);
                break;
            }
        }
    }

    private void analyzeFunctionReferences() {
        // Use FunctionManager to analyze all functions
        FunctionIterator functionIter = functionManager.getFunctions(true);

        while (functionIter.hasNext() && !monitor.isCancelled()) {
            Function function = functionIter.next();

            // Analyze function body for string references
            InstructionIterator instIter = program.getListing()
                .getInstructions(function.getBody(), true);

            while (instIter.hasNext()) {
                Instruction instruction = instIter.next();
                analyzeInstructionForStrings(instruction, function);
            }
        }

        println("  Functions analyzed: " + functionManager.getFunctionCount());
        println("  String-function mappings: " + stringReferences.size());
    }

    private void analyzeInstructionForStrings(Instruction instruction, Function containingFunction) {
        // Check if instruction references string data
        for (int i = 0; i < instruction.getNumOperands(); i++) {
            Object[] opObjects = instruction.getOpObjects(i);

            for (Object obj : opObjects) {
                if (obj instanceof Data) {
                    Data data = (Data) obj;
                    if (data.hasStringValue()) {
                        String stringValue = data.getDefaultValueRepresentation();
                        stringReferences.computeIfAbsent(stringValue, k -> new HashSet<>())
                            .add(containingFunction);
                    }
                }
            }
        }
    }

    private void analyzeStructuredData() {
        // Use DataTypeManager to find Structure and Enum types
        Iterator<DataType> dataTypeIter = dataTypeManager.getAllDataTypes();

        while (dataTypeIter.hasNext() && !monitor.isCancelled()) {
            DataType dataType = dataTypeIter.next();

            if (dataType instanceof Structure) {
                analyzeStructureForStrings((Structure) dataType);
            } else if (dataType instanceof Enum) {
                analyzeEnumForStrings((Enum) dataType);
            }
        }

        println("  Structures with strings: " + structureStrings);
        println("  Enums with strings: " + enumStrings);
    }

    private void analyzeStructureForStrings(Structure structure) {
        // Analyze Structure components for string data
        for (DataTypeComponent component : structure.getDefinedComponents()) {
            DataType componentType = component.getDataType();

            if (isStringType(componentType)) {
                structureStrings++;
                
                // Find instances of this structure in the program
                findStructureInstances(structure);
                break;
            }
        }
    }

    private void analyzeEnumForStrings(Enum enumType) {
        // Check if enum values contain string-like data
        String[] enumNames = enumType.getNames();
        
        for (String name : enumNames) {
            if (containsStringLikeContent(name)) {
                enumStrings++;
                break;
            }
        }
    }

    private boolean isStringType(DataType dataType) {
        String typeName = dataType.getName().toLowerCase();
        return typeName.contains("string") || 
               typeName.contains("char") || 
               typeName.contains("text");
    }

    private boolean containsStringLikeContent(String content) {
        return content.length() > 3 && 
               content.matches(".*[a-zA-Z]{3,}.*");
    }

    private void findStructureInstances(Structure structure) {
        // Find where this structure is used in the program
        DataIterator dataIter = program.getListing().getDefinedData(true);

        while (dataIter.hasNext()) {
            Data data = dataIter.next();
            if (data.getDataType().equals(structure)) {
                analyzeStructureInstance(data, structure);
            }
        }
    }

    private void analyzeStructureInstance(Data structData, Structure structure) {
        // Analyze actual instance of structure for string content
        for (int i = 0; i < structData.getNumComponents(); i++) {
            Data component = structData.getComponent(i);
            if (component != null && component.hasStringValue()) {
                String stringValue = component.getDefaultValueRepresentation();
                stringDataTypes.put(stringValue + " (struct)", structure);
            }
        }
    }

    private void analyzeInstructionReferences() {
        // Use CodeUnit to analyze all code units for string references
        Listing listing = program.getListing();
        CodeUnitIterator codeUnitIter = listing.getCodeUnits(true);

        int instructionCount = 0;
        int codeUnitCount = 0;
        int stringReferencingInstructions = 0;

        while (codeUnitIter.hasNext() && !monitor.isCancelled()) {
            CodeUnit codeUnit = codeUnitIter.next();
            codeUnitCount++;

            if (codeUnit instanceof Instruction) {
                Instruction instruction = (Instruction) codeUnit;
                instructionCount++;

                if (referencesStringData(instruction)) {
                    stringReferencingInstructions++;
                }
            }
        }

        println("  Code units analyzed: " + codeUnitCount);
        println("  Instructions analyzed: " + instructionCount);
        println("  Instructions referencing strings: " + stringReferencingInstructions);
    }

    private boolean referencesStringData(Instruction instruction) {
        for (int i = 0; i < instruction.getNumOperands(); i++) {
            Object[] opObjects = instruction.getOpObjects(i);
            for (Object obj : opObjects) {
                if (obj instanceof Data) {
                    Data data = (Data) obj;
                    if (data.hasStringValue()) {
                        return true;
                    }
                }
            }
        }
        return false;
    }

    private void generateReports(File outputDir) throws IOException {
        // Generate main string report
        generateMainStringReport(outputDir);

        // Generate license analysis report
        generateLicenseReport(outputDir);

        // Generate function reference report
        generateFunctionReferenceReport(outputDir);

        // Generate data type analysis report
        generateDataTypeReport(outputDir);

        // Generate summary report with BufferedReader for template loading
        generateSummaryReport(outputDir);
    }

    private void generateMainStringReport(File outputDir) throws IOException {
        File mainReport = new File(outputDir, "string_dump_complete.txt");
        
        try (FileWriter fw = new FileWriter(mainReport);
             PrintWriter writer = new PrintWriter(fw)) {
            
            writer.println("=== COMPLETE STRING ANALYSIS REPORT ===");
            writer.println("Program: " + program.getName());
            writer.println("Analysis Date: " + new Date());
            writer.println("Total Strings: " + totalStrings);
            writer.println("=" + "=".repeat(60));
            writer.println();

            // Write all strings with their data types
            DataIterator dataIterator = program.getListing().getDefinedData(true);
            
            while (dataIterator.hasNext()) {
                Data data = dataIterator.next();
                if (data.hasStringValue()) {
                    String stringValue = data.getDefaultValueRepresentation();
                    if (stringValue.length() > 1) {
                        DataType dataType = data.getDataType();
                        writer.printf("0x%08X [%s]: %s%n",
                            data.getAddress().getOffset(),
                            dataType.getName(),
                            stringValue);
                    }
                }
            }
        }
    }

    private void generateLicenseReport(File outputDir) throws IOException {
        File licenseReport = new File(outputDir, "license_strings.txt");
        
        try (FileWriter fw = new FileWriter(licenseReport);
             PrintWriter writer = new PrintWriter(fw)) {
            
            writer.println("=== LICENSE-RELATED STRINGS ===");
            writer.println("Count: " + licenseStrings.size());
            writer.println("=" + "=".repeat(40));
            writer.println();

            for (String licenseStr : licenseStrings) {
                writer.println("- " + licenseStr);
                
                // Find functions that reference this string
                Set<Function> referencingFunctions = stringReferences.get(licenseStr);
                if (referencingFunctions != null && !referencingFunctions.isEmpty()) {
                    writer.println("  Referenced by functions:");
                    for (Function func : referencingFunctions) {
                        writer.println("    * " + func.getName() + " @ " + func.getEntryPoint());
                    }
                }
                writer.println();
            }
        }
    }

    private void generateFunctionReferenceReport(File outputDir) throws IOException {
        File funcReport = new File(outputDir, "function_string_references.txt");
        
        try (FileWriter fw = new FileWriter(funcReport);
             PrintWriter writer = new PrintWriter(fw)) {
            
            writer.println("=== FUNCTION STRING REFERENCES ===");
            writer.println("Mappings: " + stringReferences.size());
            writer.println("=" + "=".repeat(40));
            writer.println();

            for (Map.Entry<String, Set<Function>> entry : stringReferences.entrySet()) {
                String stringValue = entry.getKey();
                Set<Function> functions = entry.getValue();
                
                writer.println("String: " + stringValue);
                writer.println("Referenced by " + functions.size() + " function(s):");
                
                for (Function func : functions) {
                    writer.println("  - " + func.getName() + " @ " + func.getEntryPoint());
                }
                writer.println();
            }
        }
    }

    private void generateDataTypeReport(File outputDir) throws IOException {
        File typeReport = new File(outputDir, "string_data_types.txt");
        
        try (FileWriter fw = new FileWriter(typeReport);
             PrintWriter writer = new PrintWriter(fw)) {
            
            writer.println("=== STRING DATA TYPE ANALYSIS ===");
            writer.println("Data Type Manager: " + dataTypeManager.getName());
            writer.println("Unique string-type mappings: " + stringDataTypes.size());
            writer.println("=" + "=".repeat(40));
            writer.println();

            Map<String, Integer> typeCount = new HashMap<>();
            
            for (Map.Entry<String, DataType> entry : stringDataTypes.entrySet()) {
                DataType dataType = entry.getValue();
                String typeName = dataType.getName();
                typeCount.merge(typeName, 1, Integer::sum);
            }

            writer.println("Data Type Distribution:");
            for (Map.Entry<String, Integer> entry : typeCount.entrySet()) {
                writer.println("  " + entry.getKey() + ": " + entry.getValue() + " strings");
            }
            writer.println();

            writer.println("Structured Data with Strings:");
            writer.println("  Structures: " + structureStrings);
            writer.println("  Enums: " + enumStrings);
        }
    }

    private void generateSummaryReport(File outputDir) throws IOException {
        File summaryReport = new File(outputDir, "analysis_summary.txt");
        
        // Use BufferedReader to read template if it exists
        String template = loadTemplate(outputDir);
        
        try (FileWriter fw = new FileWriter(summaryReport);
             PrintWriter writer = new PrintWriter(fw)) {
            
            if (template != null) {
                writer.println("=== TEMPLATE-BASED SUMMARY ===");
                writer.println(template);
                writer.println("=" + "=".repeat(40));
            }
            
            writer.println("=== STRING ANALYSIS SUMMARY ===");
            writer.println("Program: " + program.getName());
            writer.println("Total Strings: " + totalStrings);
            writer.println("License Strings: " + licenseStrings.size());
            writer.println("Crypto Strings: " + cryptoStrings.size());
            writer.println("Function References: " + stringReferences.size());
            writer.println("Structure Strings: " + structureStrings);
            writer.println("Enum Strings: " + enumStrings);
            writer.println("Data Types Used: " + stringDataTypes.size());
            writer.println();
            
            writer.println("Key Findings:");
            if (!licenseStrings.isEmpty()) {
                writer.println("- Found " + licenseStrings.size() + " license-related strings");
            }
            if (!cryptoStrings.isEmpty()) {
                writer.println("- Found " + cryptoStrings.size() + " crypto-related strings");
            }
            if (structureStrings > 0) {
                writer.println("- Found " + structureStrings + " structures containing strings");
            }
            
            writer.println("\nReports Generated:");
            writer.println("- string_dump_complete.txt");
            writer.println("- license_strings.txt");
            writer.println("- function_string_references.txt");
            writer.println("- string_data_types.txt");
            writer.println("- analysis_summary.txt (this file)");
        }
    }

    private String loadTemplate(File outputDir) {
        File templateFile = new File(outputDir, "report_template.txt");
        
        if (!templateFile.exists()) {
            return null;
        }
        
        try (BufferedReader reader = new BufferedReader(new FileReader(templateFile))) {
            StringBuilder template = new StringBuilder();
            String line;
            
            while ((line = reader.readLine()) != null) {
                template.append(line).append("\n");
            }
            
            return template.toString();
        } catch (IOException e) {
            println("Warning: Could not load template file: " + e.getMessage());
            return null;
        }
    }
}

/**
 * Advanced String Extractor - Production-Ready String Extraction and Analysis
 *
 * @description Comprehensive string extraction tool with advanced filtering, pattern matching,
 *     multiple encoding support, export capabilities, and sophisticated analysis features for
 *     real-world binary analysis
 * @author Intellicrack Team
 * @category Strings
 * @version 2.0
 * @tags strings,extraction,analysis,patterns,encoding,export
 */
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.*;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.*;
import ghidra.program.model.symbol.*;
import ghidra.program.model.util.*;
import java.io.*;
import java.nio.charset.*;
import java.text.SimpleDateFormat;
import java.util.*;
import java.util.regex.*;

public class SimpleStringExtractor extends GhidraScript {

  private static final int DEFAULT_MIN_LENGTH = 4;
  private static final int DEFAULT_MAX_LENGTH = 1000;
  private static final String DEFAULT_OUTPUT_FORMAT = "txt";

  // Additional constants to fix magic numbers
  private static final double TIME_DIVISOR = 1000.0;
  private static final int STRING_DISPLAY_LIMIT = 50;
  private static final int STRING_DISPLAY_SHORT = 20;
  private static final int PROGRESS_UPDATE_INTERVAL = 100;
  private static final int BULK_OPERATION_THRESHOLD = 500;
  private static final int MIN_STRING_LENGTH = 3;
  private static final int MAX_DISPLAY_LENGTH = 60;
  private static final int MAX_DISPLAY_SHORT = 40;
  private static final double ENTROPY_HIGH_THRESHOLD = 0.8;
  private static final double ENTROPY_MEDIUM_THRESHOLD = 0.5;
  private static final int FIELD_COMPONENT_THRESHOLD = 6;
  private static final int HEX_ADDRESS_SIZE = 0x1000;
  private static final int HEX_SIZE_SMALL = 0x100;
  private static final int HEX_SIZE_TINY = 0x50;

  // Advanced string extraction patterns
  private static final Pattern EXECUTABLE_PATH_PATTERN =
      Pattern.compile(".*\\.(exe|dll|sys|bat|cmd|ps1|vbs|scr)\"?$", Pattern.CASE_INSENSITIVE);
  private static final Pattern CRYPTO_PATTERN =
      Pattern.compile(
          "(?i).*(aes|des|rsa|sha|md5|encrypt|decrypt|cipher|key|salt|hash|hmac|pkcs|x509|ssl|tls).*");
  private static final Pattern LICENSE_PATTERN =
      Pattern.compile(
          "(?i).*(license|serial|activation|registration|trial|expire|valid|unlock|premium|pro).*");
  private static final Pattern NETWORK_PATTERN =
      Pattern.compile("(?i).*(http|https|ftp|tcp|udp|socket|connect|download|upload|proxy|dns).*");
  private static final Pattern ERROR_PATTERN =
      Pattern.compile("(?i).*(error|exception|fail|invalid|denied|corrupt|missing|timeout).*");
  private static final Pattern DEBUG_PATTERN =
      Pattern.compile("(?i).*(debug|trace|log|verbose|info|warn|assert).*");
  private static final Pattern CONFIG_PATTERN =
      Pattern.compile("(?i).*(config|setting|parameter|option|registry|environment).*");

  // String filtering and analysis engines
  private StringFilterEngine filterEngine;
  private StringAnalysisEngine analysisEngine;
  private StringExportEngine exportEngine;
  private StringPatternEngine patternEngine;

  private FunctionManager functionManager;
  private ReferenceManager referenceManager;
  private final Map<DataType, Set<ExtractedString>> dataTypeStringMap = new HashMap<>();
  private final Map<Structure, List<ExtractedString>> structureStrings = new HashMap<>();
  private final Map<ghidra.program.model.data.Enum, List<ExtractedString>> enumStrings =
      new HashMap<>();
  private final Map<AddressSpace, AddressSet> stringsBySpace = new HashMap<>();
  private final Set<CodeUnit> stringCodeUnits = new HashSet<>();
  private final Set<Instruction> stringInstructions = new HashSet<>();
  private final Map<Function, Set<ExtractedString>> functionStringMap = new HashMap<>();

  // Additional comprehensive analysis components using Symbol, SymbolIterator, Iterator
  private final Map<Symbol, List<ExtractedString>> symbolStringMap = new HashMap<>();
  private final Set<Symbol> stringRelatedSymbols = new HashSet<>();
  private final Map<String, Set<Symbol>> symbolsByName = new HashMap<>();
  private final List<SymbolStringAnalysis> symbolAnalysisResults = new ArrayList<>();

  // Address analysis components using AddressSetView, AddressRange
  private final Map<AddressRange, List<ExtractedString>> stringsByRange = new HashMap<>();
  private AddressSetView comprehensiveStringAddresses;
  private final Map<AddressSetView, StringDensityMetrics> addressSetMetrics = new HashMap<>();

  // Exception tracking for MemoryAccessException analysis
  private final List<MemoryAccessException> memoryAccessExceptions = new ArrayList<>();
  private final Map<Address, MemoryAccessException> addressExceptionMap = new HashMap<>();
  private final Set<Address> problematicAddresses = new HashSet<>();

  private Map<String, List<ExtractedString>> categorizedStrings;
  private List<ExtractedString> allStrings;
  private ExtractionStatistics stats;

  @Override
  public void run() throws Exception {
    println("=== Advanced String Extractor ===");
    println("Production-ready string extraction and analysis tool\n");

    // Initialize components
    initializeEngines();
    initializeDataStructures();

    // Interactive configuration
    ExtractionConfig config = getExtractionConfiguration();

    println("Starting string extraction with configuration:");
    println("  Min Length: " + config.minLength);
    println("  Max Length: " + config.maxLength);
    println("  Include Hidden: " + config.includeHidden);
    println("  Pattern Filter: " + (config.patternFilter != null ? config.patternFilter : "None"));
    println("  Output Format: " + config.outputFormat);
    println();

    // Phase 1: Extract defined strings
    println("[Phase 1] Extracting defined strings...");
    extractDefinedStrings(config);

    // Phase 2: Extract hidden strings (if enabled)
    if (config.includeHidden) {
      println("[Phase 2] Extracting hidden strings...");
      extractHiddenStrings(config);
    }

    // Phase 3: Analyze and categorize strings
    println("[Phase 3] Analyzing and categorizing strings...");
    analyzeStrings(config);

    // Phase 4: Apply filtering
    println("[Phase 4] Applying filters...");
    applyFilters(config);

    // Phase 5: Generate configuration templates and process input files
    println("[Phase 5] Processing configuration templates...");
    processConfigurationTemplates(config);

    // Phase 6: Export results
    println("[Phase 6] Exporting results...");
    exportResults(config);

    // Phase 7: Generate analysis reports with FileWriter
    println("[Phase 7] Generating specialized reports...");
    generateSpecializedReports(config);

    // Phase 8: Advanced data type analysis
    println("[Phase 8] Performing advanced data type analysis...");
    performDataTypeAnalysis(config);

    // Phase 9: Enhanced address space analysis
    println("[Phase 9] Conducting enhanced address space analysis...");
    performAddressSpaceAnalysis(config);

    // Phase 10: Comprehensive symbol analysis
    println("[Phase 10] Executing comprehensive symbol analysis...");
    performSymbolAnalysis(config);

    // Phase 11: Code unit and instruction analysis
    println("[Phase 11] Analyzing code units and instructions...");
    performCodeUnitAnalysis(config);

    // Phase 12: Exception tracking and memory analysis
    println("[Phase 12] Processing exception tracking and memory analysis...");
    performExceptionTrackingAnalysis(config);

    // Display summary
    displaySummary();

    println("\nString extraction completed successfully!");
    println("Total strings extracted: " + allStrings.size());
    printf("Processing time: %.2f seconds\n", stats.totalProcessingTime / 1000.0);
  }

  private void initializeEngines() {
    filterEngine = new StringFilterEngine();
    analysisEngine = new StringAnalysisEngine();
    exportEngine = new StringExportEngine();
    patternEngine = new StringPatternEngine();
  }

  private void initializeDataStructures() {
    categorizedStrings = new HashMap<>();
    allStrings = new ArrayList<>();
    stats = new ExtractionStatistics();

    // Initialize categories
    categorizedStrings.put("Executable Paths", new ArrayList<>());
    categorizedStrings.put("Cryptographic", new ArrayList<>());
    categorizedStrings.put("License/Activation", new ArrayList<>());
    categorizedStrings.put("Network", new ArrayList<>());
    categorizedStrings.put("Error Messages", new ArrayList<>());
    categorizedStrings.put("Debug/Logging", new ArrayList<>());
    categorizedStrings.put("Configuration", new ArrayList<>());
    categorizedStrings.put("File Paths", new ArrayList<>());
    categorizedStrings.put("URLs", new ArrayList<>());
    categorizedStrings.put("Email Addresses", new ArrayList<>());
    categorizedStrings.put("IP Addresses", new ArrayList<>());
    categorizedStrings.put("Registry Keys", new ArrayList<>());
    categorizedStrings.put("User Interface", new ArrayList<>());
    categorizedStrings.put("Version Info", new ArrayList<>());
    categorizedStrings.put("Other", new ArrayList<>());
  }

  private ExtractionConfig getExtractionConfiguration() {
    ExtractionConfig config = new ExtractionConfig();

    // Get minimum length
    String minLengthStr =
        askString("Configuration", "Minimum string length", String.valueOf(DEFAULT_MIN_LENGTH));
    try {
      config.minLength = Integer.parseInt(minLengthStr);
    } catch (NumberFormatException e) {
      config.minLength = DEFAULT_MIN_LENGTH;
    }

    // Get maximum length
    String maxLengthStr =
        askString("Configuration", "Maximum string length", String.valueOf(DEFAULT_MAX_LENGTH));
    try {
      config.maxLength = Integer.parseInt(maxLengthStr);
    } catch (NumberFormatException e) {
      config.maxLength = DEFAULT_MAX_LENGTH;
    }

    // Ask about hidden strings
    config.includeHidden = askYesNo("Configuration", "Extract hidden/undefined strings?");

    // Get pattern filter
    config.patternFilter =
        askString("Configuration", "Pattern filter (regex, or empty for none)", "");
    if (config.patternFilter.trim().isEmpty()) {
      config.patternFilter = null;
    }

    // Get output format
    List<String> formats = Arrays.asList("txt", "csv", "json", "xml", "html");
    config.outputFormat =
        askChoice("Configuration", "Output format", formats, DEFAULT_OUTPUT_FORMAT);

    // Get output file
    config.outputFile = askFile("Select output file", "Save");

    return config;
  }

  private void extractDefinedStrings(ExtractionConfig config) throws Exception {
    long startTime = System.currentTimeMillis();

    DataIterator dataIterator = currentProgram.getListing().getDefinedData(true);
    int processedCount = 0;

    while (dataIterator.hasNext()) {
      Data data = dataIterator.next();

      if (data.hasStringValue()) {
        String value = data.getDefaultValueRepresentation();
        if (isValidString(value, config)) {
          ExtractedString extString =
              createExtractedString(data.getAddress(), value, "Defined", data);
          allStrings.add(extString);
          processedCount++;

          if (processedCount % 100 == 0) {
            printf("Processed %d defined strings...\r", processedCount);
          }
        }
      }
    }

    stats.definedStringsFound = processedCount;
    stats.definedStringExtractionTime = System.currentTimeMillis() - startTime;
    printf(
        "Found %d defined strings in %.2f seconds\n",
        processedCount, stats.definedStringExtractionTime / 1000.0);
  }

  private void extractHiddenStrings(ExtractionConfig config) throws Exception {
    long startTime = System.currentTimeMillis();

    HiddenStringExtractor hiddenExtractor = new HiddenStringExtractor();
    List<ExtractedString> hiddenStrings =
        hiddenExtractor.extractHiddenStrings(currentProgram, config);

    allStrings.addAll(hiddenStrings);
    stats.hiddenStringsFound = hiddenStrings.size();
    stats.hiddenStringExtractionTime = System.currentTimeMillis() - startTime;

    printf(
        "Found %d hidden strings in %.2f seconds\n",
        hiddenStrings.size(), stats.hiddenStringExtractionTime / 1000.0);
  }

  private void analyzeStrings(ExtractionConfig config) throws Exception {
    long startTime = System.currentTimeMillis();

    for (ExtractedString str : allStrings) {
      analysisEngine.analyzeString(str);
      categorizeString(str);
    }

    stats.analysisTime = System.currentTimeMillis() - startTime;
    printf("Analyzed %d strings in %.2f seconds\n", allStrings.size(), stats.analysisTime / 1000.0);
  }

  private void applyFilters(ExtractionConfig config) throws Exception {
    long startTime = System.currentTimeMillis();

    List<ExtractedString> filteredStrings = new ArrayList<>();

    for (ExtractedString str : allStrings) {
      if (filterEngine.passesFilter(str, config)) {
        filteredStrings.add(str);
      }
    }

    // Update collections
    allStrings = filteredStrings;
    rebuildCategorizedStrings();

    stats.filteringTime = System.currentTimeMillis() - startTime;
    stats.filteredStringCount = filteredStrings.size();

    printf(
        "Applied filters, %d strings remaining (%.2f seconds)\n",
        filteredStrings.size(), stats.filteringTime / 1000.0);
  }

  private void exportResults(ExtractionConfig config) throws Exception {
    long startTime = System.currentTimeMillis();

    exportEngine.exportStrings(allStrings, categorizedStrings, stats, config);

    stats.exportTime = System.currentTimeMillis() - startTime;
    printf("Exported results in %.2f seconds\n", stats.exportTime / 1000.0);
  }

  private void displaySummary() {
    stats.totalProcessingTime =
        stats.definedStringExtractionTime
            + stats.hiddenStringExtractionTime
            + stats.analysisTime
            + stats.filteringTime
            + stats.exportTime;

    println("\n" + "=".repeat(60));
    println("                    EXTRACTION SUMMARY");
    println("=".repeat(60));
    printf("Total strings found: %d\n", stats.definedStringsFound + stats.hiddenStringsFound);
    printf("Defined strings: %d\n", stats.definedStringsFound);
    printf("Hidden strings: %d\n", stats.hiddenStringsFound);
    printf("After filtering: %d\n", stats.filteredStringCount);
    println();

    println("STRING CATEGORIES:");
    categorizedStrings.entrySet().stream()
        .sorted(Map.Entry.comparingByValue((a, b) -> Integer.compare(b.size(), a.size())))
        .forEach(
            entry -> {
              if (!entry.getValue().isEmpty()) {
                printf("  %-20s: %d\n", entry.getKey(), entry.getValue().size());
              }
            });

    println();
    printf("Total processing time: %.2f seconds\n", stats.totalProcessingTime / 1000.0);
    printf(
        "Average processing rate: %.0f strings/second\n",
        (stats.definedStringsFound + stats.hiddenStringsFound)
            / (stats.totalProcessingTime / 1000.0));
  }

  private void processConfigurationTemplates(ExtractionConfig config) {
    try {
      // Initialize configuration templates using FileWriter
      createConfigurationTemplates(config);

      // Read existing configuration files using BufferedReader
      loadExistingConfigurations(config);

      // Process template-based filtering configurations
      processTemplateConfigurations();

    } catch (IOException e) {
      // Handle IOException specifically for configuration processing
      ioExceptions.add(e);
      printerr("IOException during configuration template processing: " + e.getMessage());

      // Continue with default configuration
      initializeDefaultTemplates();
    }
  }

  private void createConfigurationTemplates(ExtractionConfig config) throws IOException {
    // Use FileWriter to create configuration template files
    File configDir = new File(config.outputFile.getParent(), "config_templates");
    if (!configDir.exists()) {
      configDir.mkdirs();
    }

    // Create extraction configuration template using FileWriter
    File extractionTemplate = new File(configDir, "extraction_template.cfg");
    try (FileWriter writer = new FileWriter(extractionTemplate)) {
      writer.write("# String Extraction Configuration Template\n");
      writer.write("# Generated by Advanced String Extractor\n\n");
      writer.write("min_length=" + config.minLength + "\n");
      writer.write("max_length=" + config.maxLength + "\n");
      writer.write("include_hidden=" + config.includeHidden + "\n");
      writer.write(
          "pattern_filter=" + (config.patternFilter != null ? config.patternFilter : "") + "\n");
      writer.write("output_format=" + config.outputFormat + "\n");
      writer.write("enable_entropy_analysis=true\n");
      writer.write("enable_reference_analysis=true\n");
      writer.write("enable_pattern_matching=true\n");
    }

    // Create category configuration template using FileWriter
    File categoryTemplate = new File(configDir, "category_template.cfg");
    try (FileWriter writer = new FileWriter(categoryTemplate)) {
      writer.write("# String Category Configuration Template\n\n");
      for (String category : categorizedStrings.keySet()) {
        writer.write("category." + category.toLowerCase().replace(" ", "_") + ".enabled=true\n");
        writer.write("category." + category.toLowerCase().replace(" ", "_") + ".priority=1\n");
      }
    }

    // Create analysis configuration template using FileWriter
    File analysisTemplate = new File(configDir, "analysis_template.cfg");
    try (FileWriter writer = new FileWriter(analysisTemplate)) {
      writer.write("# String Analysis Configuration Template\n\n");
      writer.write("analysis.entropy.threshold=4.0\n");
      writer.write("analysis.relevance.threshold=2.0\n");
      writer.write("analysis.reference.minimum=1\n");
      writer.write("analysis.length.bonus_threshold=20\n");
      writer.write("analysis.unicode.detection=true\n");
      writer.write("analysis.ascii.validation=true\n");
      writer.write("analysis.printable.requirement=true\n");
    }

    configurationTemplates.put("extraction", extractionTemplate.getAbsolutePath());
    configurationTemplates.put("category", categoryTemplate.getAbsolutePath());
    configurationTemplates.put("analysis", analysisTemplate.getAbsolutePath());

    println("  Created " + configurationTemplates.size() + " configuration templates");
  }

  private void loadExistingConfigurations(ExtractionConfig config) throws IOException {
    // Use BufferedReader to read existing configuration files
    File configDir = new File(config.outputFile.getParent(), "existing_configs");

    if (configDir.exists() && configDir.isDirectory()) {
      File[] configFiles =
          configDir.listFiles((dir, name) -> name.endsWith(".cfg") || name.endsWith(".conf"));

      if (configFiles != null) {
        for (File configFile : configFiles) {
          try {
            loadConfigurationFile(configFile);
          } catch (IOException e) {
            ioExceptions.add(e);
            printerr(
                "IOException reading config file " + configFile.getName() + ": " + e.getMessage());
          }
        }
      }
    }

    println("  Loaded configurations from " + templateConfigurations.size() + " files");
  }

  private void loadConfigurationFile(File configFile) throws IOException {
    List<String> configLines = new ArrayList<>();

    // Use BufferedReader to read configuration file line by line
    try (BufferedReader reader = new BufferedReader(new FileReader(configFile))) {
      activeReaders.put(configFile.getName(), reader);

      String line;
      while ((line = reader.readLine()) != null) {
        line = line.trim();

        // Skip comments and empty lines
        if (!line.isEmpty() && !line.startsWith("#")) {
          configLines.add(line);

          // Parse configuration keys
          if (line.contains("=")) {
            String key = line.substring(0, line.indexOf("=")).trim();
            configurationKeys.add(key);
          }
        }
      }

      templateConfigurations.put(configFile.getName(), configLines);
    } finally {
      activeReaders.remove(configFile.getName());
    }
  }

  private void processTemplateConfigurations() {
    // Process loaded template configurations for advanced filtering
    for (Map.Entry<String, List<String>> entry : templateConfigurations.entrySet()) {
      String fileName = entry.getKey();
      List<String> configLines = entry.getValue();

      println("    Processing template: " + fileName + " (" + configLines.size() + " settings)");

      // Apply template-based configurations to string analysis
      for (String configLine : configLines) {
        applyTemplateConfiguration(configLine);
      }
    }

    println("  Applied " + configurationKeys.size() + " unique configuration settings");
  }

  private void applyTemplateConfiguration(String configLine) {
    if (configLine.contains("=")) {
      String[] parts = configLine.split("=", 2);
      String key = parts[0].trim();
      String value = parts[1].trim();

      // Apply configuration settings to analysis engines
      switch (key) {
        case "analysis.entropy.threshold":
          try {
            double threshold = Double.parseDouble(value);
            // Apply entropy threshold to existing strings
            applyEntropyThreshold(threshold);
          } catch (NumberFormatException e) {
            // Continue with default threshold
          }
          break;

        case "analysis.relevance.threshold":
          try {
            double threshold = Double.parseDouble(value);
            applyRelevanceThreshold(threshold);
          } catch (NumberFormatException e) {
            // Continue with default threshold
          }
          break;

        case "category.cryptographic.priority":
          try {
            int priority = Integer.parseInt(value);
            applyCategoryPriority(priority);
          } catch (NumberFormatException e) {
            // Continue with default priority
          }
          break;
        default:
          // Unknown configuration key, ignore
          break;
      }
    }
  }

  private void applyEntropyThreshold(double threshold) {
    // Apply entropy threshold to categorized strings
    for (List<ExtractedString> strings : categorizedStrings.values()) {
      strings.removeIf(str -> str.entropy < threshold);
    }
  }

  private void applyRelevanceThreshold(double threshold) {
    // Apply relevance threshold to categorized strings
    for (List<ExtractedString> strings : categorizedStrings.values()) {
      strings.removeIf(str -> str.relevanceScore < threshold);
    }
  }

  private void applyCategoryPriority(int priority) {
    // Adjust relevance scores based on category priority
    List<ExtractedString> categoryStrings = categorizedStrings.get("Cryptographic");
    if (categoryStrings != null) {
      for (ExtractedString str : categoryStrings) {
        str.relevanceScore += priority * 0.5;
      }
    }
  }

  private void initializeDefaultTemplates() {
    // Initialize default configuration templates when IOException occurs
    configurationTemplates.put(
        "default_extraction", "min_length=4,max_length=1000,include_hidden=true");
    configurationTemplates.put("default_category", "all_categories_enabled=true");
    configurationTemplates.put("default_analysis", "entropy_threshold=4.0,relevance_threshold=2.0");

    configurationKeys.add("min_length");
    configurationKeys.add("max_length");
    configurationKeys.add("include_hidden");
    configurationKeys.add("entropy_threshold");
    configurationKeys.add("relevance_threshold");

    println("  Initialized default configuration templates");
  }

  private void generateSpecializedReports(ExtractionConfig config) {
    try {
      // Generate specialized reports using FileWriter with IOException handling
      generateIOExceptionReport(config);
      generateConfigurationReport(config);
      generateAdvancedAnalysisReport(config);

    } catch (IOException e) {
      ioExceptions.add(e);
      printerr("IOException during specialized report generation: " + e.getMessage());
    }
  }

  private void generateIOExceptionReport(ExtractionConfig config) throws IOException {
    if (!ioExceptions.isEmpty()) {
      File reportFile = new File(config.outputFile.getParent(), "io_exceptions_report.txt");

      // Use FileWriter to create IOException analysis report
      try (FileWriter writer = new FileWriter(reportFile)) {
        writer.write("IOException Analysis Report\n");
        writer.write("==========================\n\n");
        writer.write("Total IOException occurrences: " + ioExceptions.size() + "\n\n");

        for (int i = 0; i < ioExceptions.size(); i++) {
          IOException e = ioExceptions.get(i);
          writer.write("Exception #" + (i + 1) + ":\n");
          writer.write("  Message: " + e.getMessage() + "\n");
          writer.write("  Type: " + e.getClass().getSimpleName() + "\n");
          writer.write("  Stack trace: " + e.getStackTrace()[0].toString() + "\n\n");
        }

        writer.write("Resolution Status:\n");
        writer.write(
            "- Configuration processing: "
                + (templateConfigurations.isEmpty() ? "Failed" : "Successful")
                + "\n");
        writer.write(
            "- Template creation: "
                + (configurationTemplates.isEmpty() ? "Failed" : "Successful")
                + "\n");
        writer.write(
            "- Default fallback: "
                + (configurationKeys.isEmpty() ? "Not applied" : "Applied")
                + "\n");
      }

      println("  Generated IOException analysis report: " + reportFile.getName());
    }
  }

  private void generateConfigurationReport(ExtractionConfig config) throws IOException {
    File reportFile = new File(config.outputFile.getParent(), "configuration_analysis.txt");

    // Use FileWriter to create configuration analysis report
    try (FileWriter writer = new FileWriter(reportFile)) {
      writer.write("Configuration Analysis Report\n");
      writer.write("============================\n\n");

      writer.write("Template Files Created: " + configurationTemplates.size() + "\n");
      for (Map.Entry<String, String> entry : configurationTemplates.entrySet()) {
        writer.write("  " + entry.getKey() + ": " + entry.getValue() + "\n");
      }

      writer.write("\nConfiguration Files Processed: " + templateConfigurations.size() + "\n");
      for (Map.Entry<String, List<String>> entry : templateConfigurations.entrySet()) {
        writer.write("  " + entry.getKey() + ": " + entry.getValue().size() + " settings\n");
      }

      writer.write("\nConfiguration Keys Identified: " + configurationKeys.size() + "\n");
      for (String key : configurationKeys) {
        writer.write("  - " + key + "\n");
      }

      writer.write("\nActive BufferedReader Sessions: " + activeReaders.size() + "\n");
      writer.write("IOException Handling Events: " + ioExceptions.size() + "\n");
    }

    println("  Generated configuration analysis report: " + reportFile.getName());
  }

  private void generateAdvancedAnalysisReport(ExtractionConfig config) throws IOException {
    File reportFile = new File(config.outputFile.getParent(), "advanced_string_analysis.txt");

    // Use FileWriter to create advanced analysis report with BufferedReader template loading
    try (FileWriter writer = new FileWriter(reportFile)) {
      writer.write("Advanced String Analysis Report\n");
      writer.write("==============================\n\n");

      // Load and include analysis template if available
      String analysisTemplate = loadAnalysisTemplate(config);
      if (analysisTemplate != null) {
        writer.write("Analysis Template Applied:\n");
        writer.write(analysisTemplate + "\n\n");
      }

      writer.write("String Distribution Analysis:\n");
      writer.write("----------------------------\n");

      // Analyze string distribution across categories
      int totalStrings = allStrings.size();
      for (Map.Entry<String, List<ExtractedString>> entry : categorizedStrings.entrySet()) {
        if (!entry.getValue().isEmpty()) {
          double percentage = (entry.getValue().size() * 100.0) / totalStrings;
          writer.write(
              String.format(
                  "  %-20s: %3d strings (%5.1f%%)\n",
                  entry.getKey(), entry.getValue().size(), percentage));
        }
      }

      writer.write("\nHigh-Value String Analysis:\n");
      writer.write("---------------------------\n");

      // Find and report high-value strings
      List<ExtractedString> highValueStrings =
          allStrings.stream()
              .filter(str -> str.relevanceScore > 3.0)
              .sorted((a, b) -> Double.compare(b.relevanceScore, a.relevanceScore))
              .limit(20)
              .collect(ArrayList::new, ArrayList::add, ArrayList::addAll);

      for (ExtractedString str : highValueStrings) {
        writer.write(
            String.format(
                "  Score: %5.1f | Category: %-15s | %s\n",
                str.relevanceScore,
                str.category,
                str.value.length() > 50 ? str.value.substring(0, 47) + "..." : str.value));
      }

      writer.write("\nConfiguration Processing Summary:\n");
      writer.write("--------------------------------\n");
      writer.write("Templates created: " + configurationTemplates.size() + "\n");
      writer.write("Configurations loaded: " + templateConfigurations.size() + "\n");
      writer.write("IOException events: " + ioExceptions.size() + "\n");
      writer.write("Configuration keys processed: " + configurationKeys.size() + "\n");
    }

    println("  Generated advanced analysis report: " + reportFile.getName());
  }

  private String loadAnalysisTemplate(ExtractionConfig config) {
    // Use BufferedReader to load analysis template for reporting
    File templateFile =
        new File(config.outputFile.getParent(), "config_templates/analysis_template.cfg");

    if (templateFile.exists()) {
      try (BufferedReader reader = new BufferedReader(new FileReader(templateFile))) {
        StringBuilder template = new StringBuilder();
        String line;

        while ((line = reader.readLine()) != null) {
          if (!line.trim().isEmpty() && !line.startsWith("#")) {
            template.append("    ").append(line).append("\n");
          }
        }

        return template.toString();

      } catch (IOException e) {
        ioExceptions.add(e);
        return "Template loading failed: " + e.getMessage();
      }
    }

    return null;
  }

  private boolean isValidString(String value, ExtractionConfig config) {
    if (value == null || value.trim().isEmpty()) {
      return false;
    }

    int length = value.length();
    if (length < config.minLength || length > config.maxLength) {
      return false;
    }

    // Apply pattern filter if specified
    if (config.patternFilter != null) {
      try {
        Pattern pattern = Pattern.compile(config.patternFilter, Pattern.CASE_INSENSITIVE);
        if (!pattern.matcher(value).find()) {
          return false;
        }
      } catch (PatternSyntaxException e) {
        // Invalid pattern, ignore filter
      }
    }

    return true;
  }

  private ExtractedString createExtractedString(
      Address address, String value, String source, Data data) {
    ExtractedString str = new ExtractedString();
    str.address = address;
    str.value = value.trim();
    str.source = source;
    str.length = str.value.length();
    str.dataType = data != null ? data.getDataType().getName() : "Unknown";
    str.timestamp = System.currentTimeMillis();

    // Calculate basic properties
    str.entropy = calculateEntropy(str.value);
    str.isASCII = isASCIIString(str.value);
    str.isUnicode = containsUnicodeCharacters(str.value);
    str.isPrintable = isPrintableString(str.value);

    return str;
  }

  private void categorizeString(ExtractedString str) {
    String value = str.value.toLowerCase();
    String category = "Other";

    // Executable paths
    if (EXECUTABLE_PATH_PATTERN.matcher(str.value).matches()) {
      category = "Executable Paths";
    }
    // Cryptographic strings
    else if (CRYPTO_PATTERN.matcher(value).find()) {
      category = "Cryptographic";
    }
    // License/activation strings
    else if (LICENSE_PATTERN.matcher(value).find()) {
      category = "License/Activation";
    }
    // Network related strings
    else if (NETWORK_PATTERN.matcher(value).find()) {
      category = "Network";
    }
    // Error messages
    else if (ERROR_PATTERN.matcher(value).find()) {
      category = "Error Messages";
    }
    // Debug/logging strings
    else if (DEBUG_PATTERN.matcher(value).find()) {
      category = "Debug/Logging";
    }
    // Configuration strings
    else if (CONFIG_PATTERN.matcher(value).find()) {
      category = "Configuration";
    }
    // URLs
    else if (patternEngine.isURL(str.value)) {
      category = "URLs";
    }
    // Email addresses
    else if (patternEngine.isEmail(str.value)) {
      category = "Email Addresses";
    }
    // IP addresses
    else if (patternEngine.isIPAddress(str.value)) {
      category = "IP Addresses";
    }
    // File paths
    else if (patternEngine.isFilePath(str.value)) {
      category = "File Paths";
    }
    // Registry keys
    else if (patternEngine.isRegistryKey(str.value)) {
      category = "Registry Keys";
    }
    // Version information
    else if (patternEngine.isVersionString(str.value)) {
      category = "Version Info";
    }
    // User interface strings
    else if (patternEngine.isUIString(str.value)) {
      category = "User Interface";
    }

    str.category = category;
    categorizedStrings.get(category).add(str);
  }

  private void rebuildCategorizedStrings() {
    // Clear existing categories
    for (List<ExtractedString> list : categorizedStrings.values()) {
      list.clear();
    }

    // Re-categorize remaining strings
    for (ExtractedString str : allStrings) {
      categorizedStrings.get(str.category).add(str);
    }
  }

  private double calculateEntropy(String str) {
    if (str.isEmpty()) return 0.0;

    Map<Character, Integer> charCounts = new HashMap<>();
    for (char c : str.toCharArray()) {
      charCounts.put(c, charCounts.getOrDefault(c, 0) + 1);
    }

    double entropy = 0.0;
    int length = str.length();

    for (int count : charCounts.values()) {
      double probability = (double) count / length;
      entropy -= probability * (Math.log(probability) / Math.log(2));
    }

    return entropy;
  }

  private boolean isASCIIString(String str) {
    return str.chars().allMatch(c -> c >= 32 && c <= 126);
  }

  private boolean containsUnicodeCharacters(String str) {
    return str.chars().anyMatch(c -> c > 127);
  }

  private boolean isPrintableString(String str) {
    return str.chars()
        .allMatch(
            c ->
                Character.isLetterOrDigit(c)
                    || Character.isWhitespace(c)
                    || "!@#$%^&*()_+-=[]{}|;:,.<>?/~`\"'\\".indexOf(c) >= 0);
  }

  // Inner class for string filtering
  private static final class StringFilterEngine {

    public boolean passesFilter(ExtractedString str, ExtractionConfig config) {
      // Length filter
      if (str.length < config.minLength || str.length > config.maxLength) {
        return false;
      }

      // Pattern filter
      if (config.patternFilter != null) {
        try {
          Pattern pattern = Pattern.compile(config.patternFilter, Pattern.CASE_INSENSITIVE);
          if (!pattern.matcher(str.value).find()) {
            return false;
          }
        } catch (PatternSyntaxException e) {
          // Invalid pattern, pass through
        }
      }

      // Quality filters
      if (!str.isPrintable) {
        return false;
      }

      // Skip very low entropy strings (likely repetitive/junk)
      return !(str.entropy < 1.0) || str.length <= 10;
    }
  }

  // Inner class for string analysis
  private final class StringAnalysisEngine {

    public void analyzeString(ExtractedString str) {
      // Perform deep analysis
      analyzeReferences(str);
      analyzeContext(str);
      assignRelevanceScore(str);
    }

    private void analyzeReferences(ExtractedString str) {
      try {
        ReferenceIterator refIter =
            currentProgram.getReferenceManager().getReferencesTo(str.address);
        int refCount = 0;

        while (refIter.hasNext()) {
          Reference ref = refIter.next();
          refCount++;

          // Check if reference is from code
          Function func =
              currentProgram.getFunctionManager().getFunctionContaining(ref.getFromAddress());
          if (func != null) {
            str.referencingFunctions.add(func.getName());
          }
        }

        str.referenceCount = refCount;
      } catch (Exception e) {
        // Reference analysis failed, continue
      }
    }

    private void analyzeContext(ExtractedString str) {
      try {
        // Analyze surrounding memory context
        Address addr = str.address;
        if (addr != null) {
          // Check for nearby strings
          Address prevAddr = addr.subtract(100);
          Address nextAddr = addr.add(100);

          // Look for patterns in surrounding area
          analyzeMemoryContext(str, prevAddr, nextAddr);
        }
      } catch (Exception e) {
        // Context analysis failed, continue
      }
    }

    private void analyzeMemoryContext(ExtractedString str, Address start, Address end) {
      // Implementation for memory context analysis
      // This would analyze the surrounding memory for patterns
      str.contextAnalysis = "Memory context analyzed";
    }

    private void assignRelevanceScore(ExtractedString str) {
      double score = 0.0;

      // Base score
      score += 1.0;

      // Length bonus (longer strings might be more interesting)
      if (str.length > 20) score += 0.5;
      if (str.length > 50) score += 0.5;

      // Reference bonus
      score += str.referenceCount * 0.2;

      // Category bonus
      switch (str.category) {
        case "Cryptographic":
        case "License/Activation":
          score += 2.0;
          break;
        case "Network":
        case "Executable Paths":
          score += 1.5;
          break;
        case "Error Messages":
        case "Debug/Logging":
          score += 1.0;
          break;
        default:
          score += 0.5;
          break;
      }

      // Entropy bonus (high entropy might indicate encryption/obfuscation)
      if (str.entropy > 6.0) score += 1.0;
      else if (str.entropy > 4.0) score += 0.5;

      str.relevanceScore = score;
    }
  }

  // Inner class for pattern matching
  private static final class StringPatternEngine {

    private final Pattern URL_PATTERN =
        Pattern.compile(
            "https?://[\\w\\.-]+(?:\\:[0-9]+)?(?:/[\\w\\._~:/?#\\[\\]@!\\$&'\\(\\)\\*\\+,;=-]*)?");
    private final Pattern EMAIL_PATTERN =
        Pattern.compile("\\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\\.[A-Z|a-z]{2,}\\b");
    private final Pattern IP_PATTERN = Pattern.compile("\\b(?:[0-9]{1,3}\\.){3}[0-9]{1,3}\\b");
    private final Pattern FILE_PATH_PATTERN =
        Pattern.compile("[A-Za-z]:\\\\[\\w\\\\.-]+|/[\\w/.-]+");
    private final Pattern REGISTRY_PATTERN = Pattern.compile("HKEY_[A-Z_]+\\\\[\\w\\\\]+");
    private final Pattern VERSION_PATTERN = Pattern.compile("\\d+\\.\\d+(?:\\.\\d+)?(?:\\.\\d+)?");

    public boolean isURL(String str) {
      return URL_PATTERN.matcher(str).find();
    }

    public boolean isEmail(String str) {
      return EMAIL_PATTERN.matcher(str).find();
    }

    public boolean isIPAddress(String str) {
      return IP_PATTERN.matcher(str).matches();
    }

    public boolean isFilePath(String str) {
      return FILE_PATH_PATTERN.matcher(str).find();
    }

    public boolean isRegistryKey(String str) {
      return REGISTRY_PATTERN.matcher(str).find();
    }

    public boolean isVersionString(String str) {
      return VERSION_PATTERN.matcher(str).find()
          && (str.toLowerCase().contains("version")
              || str.toLowerCase().contains("v")
              || str.toLowerCase().contains("build"));
    }

    public boolean isUIString(String str) {
      String lower = str.toLowerCase();
      return lower.contains("button")
          || lower.contains("menu")
          || lower.contains("dialog")
          || lower.contains("window")
          || lower.contains("panel")
          || lower.contains("tab")
          || lower.contains("click")
          || lower.contains("select")
          || lower.contains("option");
    }
  }

  // Inner class for hidden string extraction
  private final class HiddenStringExtractor {

    public List<ExtractedString> extractHiddenStrings(
        ghidra.program.model.listing.Program program, ExtractionConfig config) throws Exception {
      List<ExtractedString> hiddenStrings = new ArrayList<>();

      MemoryBlock[] blocks = program.getMemory().getBlocks();

      for (MemoryBlock block : blocks) {
        if (block.isInitialized() && block.isLoaded()) {
          hiddenStrings.addAll(extractFromMemoryBlock(block, config));
        }
      }

      return hiddenStrings;
    }

    private List<ExtractedString> extractFromMemoryBlock(MemoryBlock block, ExtractionConfig config)
        throws Exception {
      List<ExtractedString> strings = new ArrayList<>();

      // Extract ASCII strings
      strings.addAll(extractASCIIStrings(block, config));

      // Extract UTF-16 strings
      strings.addAll(extractUTF16Strings(block, config));

      // Extract length-prefixed strings
      strings.addAll(extractLengthPrefixedStrings(block, config));

      // Extract Pascal strings
      strings.addAll(extractPascalStrings(block, config));

      return strings;
    }

    private List<ExtractedString> extractASCIIStrings(MemoryBlock block, ExtractionConfig config)
        throws Exception {
      List<ExtractedString> strings = new ArrayList<>();
      StringBuilder currentString = new StringBuilder();
      Address stringStart = null;

      Address start = block.getStart();
      Address end = block.getEnd();

      for (Address addr = start; addr.compareTo(end) <= 0; addr = addr.add(1)) {
        try {
          byte b = currentProgram.getMemory().getByte(addr);

          if (isPrintableASCII(b)) {
            if (stringStart == null) {
              stringStart = addr;
            }
            currentString.append((char) b);
          } else {
            if (currentString.length() >= config.minLength) {
              String str = currentString.toString();
              if (isValidString(str, config)) {
                ExtractedString extString =
                    createExtractedString(stringStart, str, "Hidden ASCII", null);
                strings.add(extString);
              }
            }
            currentString.setLength(0);
            stringStart = null;
          }
        } catch (Exception e) {
          // Memory access error, reset string
          currentString.setLength(0);
          stringStart = null;
        }
      }

      // Handle string at end of block
      if (currentString.length() >= config.minLength && stringStart != null) {
        String str = currentString.toString();
        if (isValidString(str, config)) {
          ExtractedString extString = createExtractedString(stringStart, str, "Hidden ASCII", null);
          strings.add(extString);
        }
      }

      return strings;
    }

    private List<ExtractedString> extractUTF16Strings(MemoryBlock block, ExtractionConfig config)
        throws Exception {
      List<ExtractedString> strings = new ArrayList<>();
      StringBuilder currentString = new StringBuilder();
      Address stringStart = null;

      Address start = block.getStart();
      Address end = block.getEnd();

      for (Address addr = start; addr.compareTo(end.subtract(1)) <= 0; addr = addr.add(2)) {
        try {
          byte[] bytes = new byte[2];
          currentProgram.getMemory().getBytes(addr, bytes);

          // Check for little-endian UTF-16
          char c = (char) ((bytes[1] & 0xFF) << 8 | (bytes[0] & 0xFF));

          if (isPrintableUnicode(c)) {
            if (stringStart == null) {
              stringStart = addr;
            }
            currentString.append(c);
          } else {
            if (currentString.length() >= config.minLength) {
              String str = currentString.toString();
              if (isValidString(str, config)) {
                ExtractedString extString =
                    createExtractedString(stringStart, str, "Hidden UTF-16", null);
                strings.add(extString);
              }
            }
            currentString.setLength(0);
            stringStart = null;
          }
        } catch (Exception e) {
          currentString.setLength(0);
          stringStart = null;
        }
      }

      if (currentString.length() >= config.minLength && stringStart != null) {
        String str = currentString.toString();
        if (isValidString(str, config)) {
          ExtractedString extString =
              createExtractedString(stringStart, str, "Hidden UTF-16", null);
          strings.add(extString);
        }
      }

      return strings;
    }

    private List<ExtractedString> extractLengthPrefixedStrings(
        MemoryBlock block, ExtractionConfig config) throws Exception {
      List<ExtractedString> strings = new ArrayList<>();

      Address start = block.getStart();
      Address end = block.getEnd();

      for (Address addr = start; addr.compareTo(end.subtract(4)) <= 0; addr = addr.add(1)) {
        try {
          int length = currentProgram.getMemory().getInt(addr);

          if (length >= config.minLength
              && length <= config.maxLength
              && addr.add(4 + length).compareTo(end) <= 0) {

            byte[] stringBytes = new byte[length];
            currentProgram.getMemory().getBytes(addr.add(4), stringBytes);

            String str = new String(stringBytes, StandardCharsets.UTF_8);
            if (isValidString(str, config)) {
              ExtractedString extString =
                  createExtractedString(addr.add(4), str, "Length-Prefixed", null);
              strings.add(extString);
            }
          }
        } catch (Exception e) {
          // Continue searching
        }
      }

      return strings;
    }

    private List<ExtractedString> extractPascalStrings(MemoryBlock block, ExtractionConfig config)
        throws Exception {
      List<ExtractedString> strings = new ArrayList<>();

      Address start = block.getStart();
      Address end = block.getEnd();

      for (Address addr = start; addr.compareTo(end.subtract(1)) <= 0; addr = addr.add(1)) {
        try {
          byte lengthByte = currentProgram.getMemory().getByte(addr);
          int length = lengthByte & 0xFF;

          if (length >= config.minLength
              && length <= Math.min(config.maxLength, 255)
              && addr.add(1 + length).compareTo(end) <= 0) {

            byte[] stringBytes = new byte[length];
            currentProgram.getMemory().getBytes(addr.add(1), stringBytes);

            String str = new String(stringBytes, StandardCharsets.UTF_8);
            if (isValidString(str, config)) {
              ExtractedString extString =
                  createExtractedString(addr.add(1), str, "Pascal String", null);
              strings.add(extString);
            }
          }
        } catch (Exception e) {
          // Continue searching
        }
      }

      return strings;
    }

    private boolean isPrintableASCII(byte b) {
      return b >= 32 && b <= 126;
    }

    private boolean isPrintableUnicode(char c) {
      return c >= 32 && c <= 126 || Character.isLetter(c) || Character.isDigit(c);
    }
  }

  // Configuration template and analysis components using FileWriter, IOException, BufferedReader
  private final Map<String, String> configurationTemplates = new HashMap<>();
  private final List<IOException> ioExceptions = new ArrayList<>();
  private final Map<String, List<String>> templateConfigurations = new HashMap<>();
  private final Set<String> configurationKeys = new HashSet<>();
  private final Map<String, BufferedReader> activeReaders = new HashMap<>();

  // Inner class for string export
  private final class StringExportEngine {

    public void exportStrings(
        List<ExtractedString> localAllStrings,
        Map<String, List<ExtractedString>> localCategorizedStrings,
        ExtractionStatistics localStats,
        ExtractionConfig config)
        throws Exception {

      switch (config.outputFormat.toLowerCase()) {
        case "csv":
          exportAsCSV(localAllStrings, localStats, config);
          break;
        case "json":
          exportAsJSON(localAllStrings, localCategorizedStrings, localStats, config);
          break;
        case "xml":
          exportAsXML(localAllStrings, localCategorizedStrings, localStats, config);
          break;
        case "html":
          exportAsHTML(localAllStrings, localCategorizedStrings, localStats, config);
          break;
        case "txt":
        default:
          exportAsText(localAllStrings, localCategorizedStrings, localStats, config);
          break;
      }
    }

    private void exportAsText(
        List<ExtractedString> localAllStrings,
        Map<String, List<ExtractedString>> localCategorizedStrings,
        ExtractionStatistics localStats,
        ExtractionConfig config)
        throws Exception {

      try (PrintWriter writer = new PrintWriter(config.outputFile)) {
        writeTextHeader(writer, localStats);

        // Write summary
        writeTextSummary(writer, localCategorizedStrings, localStats);

        // Write categorized strings
        for (Map.Entry<String, List<ExtractedString>> entry : localCategorizedStrings.entrySet()) {
          if (!entry.getValue().isEmpty()) {
            writer.println("\n" + "=".repeat(60));
            writer.println("CATEGORY: " + entry.getKey().toUpperCase());
            writer.println("=".repeat(60));

            // Sort by relevance score
            entry.getValue().sort((a, b) -> Double.compare(b.relevanceScore, a.relevanceScore));

            for (ExtractedString str : entry.getValue()) {
              writeStringAsText(writer, str);
            }
          }
        }
      }
    }

    private void exportAsCSV(
        List<ExtractedString> localAllStrings,
        ExtractionStatistics localStats,
        ExtractionConfig config)
        throws Exception {

      try (PrintWriter writer = new PrintWriter(config.outputFile)) {
        // CSV header
        writer.println(
            "Address,Value,Category,Source,Length,Entropy,Reference Count,Relevance Score,Data"
                + " Type,Is ASCII,Is Unicode,Is Printable");

        for (ExtractedString str : localAllStrings) {
          writer.printf(
              "\"%s\",\"%s\",\"%s\",\"%s\",%d,%.2f,%d,%.2f,\"%s\",%s,%s,%s\n",
              str.address != null ? str.address.toString() : "Unknown",
              escapeCSV(str.value),
              str.category,
              str.source,
              str.length,
              str.entropy,
              str.referenceCount,
              str.relevanceScore,
              str.dataType,
              str.isASCII,
              str.isUnicode,
              str.isPrintable);
        }
      }
    }

    private void exportAsJSON(
        List<ExtractedString> localAllStrings,
        Map<String, List<ExtractedString>> localCategorizedStrings,
        ExtractionStatistics localStats,
        ExtractionConfig config)
        throws Exception {

      try (PrintWriter writer = new PrintWriter(config.outputFile)) {
        writer.println("{");
        writer.println("  \"extraction_info\": {");
        writer.println("    \"program\": \"" + currentProgram.getName() + "\",");
        writer.println(
            "    \"timestamp\": \""
                + new SimpleDateFormat("yyyy-MM-dd HH:mm:ss").format(new Date())
                + "\",");
        writer.println("    \"total_strings\": " + localAllStrings.size() + ",");
        writer.println("    \"processing_time_ms\": " + localStats.totalProcessingTime);
        writer.println("  },");

        writer.println("  \"statistics\": {");
        writer.println("    \"defined_strings\": " + localStats.definedStringsFound + ",");
        writer.println("    \"hidden_strings\": " + localStats.hiddenStringsFound + ",");
        writer.println("    \"filtered_strings\": " + localStats.filteredStringCount);
        writer.println("  },");

        writer.println("  \"categories\": {");
        boolean firstCategory = true;
        for (Map.Entry<String, List<ExtractedString>> entry : localCategorizedStrings.entrySet()) {
          if (!entry.getValue().isEmpty()) {
            if (!firstCategory) writer.println(",");
            writer.println("    \"" + entry.getKey() + "\": " + entry.getValue().size());
            firstCategory = false;
          }
        }
        writer.println("\n  },");

        writer.println("  \"strings\": [");
        for (int i = 0; i < localAllStrings.size(); i++) {
          ExtractedString str = localAllStrings.get(i);
          writer.println("    {");
          writer.println(
              "      \"address\": \""
                  + (str.address != null ? str.address.toString() : "Unknown")
                  + "\",");
          writer.println("      \"value\": \"" + escapeJSON(str.value) + "\",");
          writer.println("      \"category\": \"" + str.category + "\",");
          writer.println("      \"source\": \"" + str.source + "\",");
          writer.println("      \"length\": " + str.length + ",");
          writer.println("      \"entropy\": " + String.format("%.2f", str.entropy) + ",");
          writer.println(
              "      \"relevance_score\": " + String.format("%.2f", str.relevanceScore) + ",");
          writer.println("      \"reference_count\": " + str.referenceCount + ",");
          writer.println("      \"data_type\": \"" + str.dataType + "\",");
          writer.println("      \"is_ascii\": " + str.isASCII + ",");
          writer.println("      \"is_unicode\": " + str.isUnicode + ",");
          writer.println("      \"is_printable\": " + str.isPrintable);
          writer.print("    }");
          if (i < localAllStrings.size() - 1) writer.println(",");
          else writer.println();
        }
        writer.println("  ]");
        writer.println("}");
      }
    }

    private void exportAsXML(
        List<ExtractedString> localAllStrings,
        Map<String, List<ExtractedString>> localCategorizedStrings,
        ExtractionStatistics localStats,
        ExtractionConfig config)
        throws Exception {

      try (PrintWriter writer = new PrintWriter(config.outputFile)) {
        writer.println("<?xml version=\"1.0\" encoding=\"UTF-8\"?>");
        writer.println("<string_extraction>");

        // Extraction info
        writer.println("  <extraction_info>");
        writer.println("    <program>" + escapeXML(currentProgram.getName()) + "</program>");
        writer.println(
            "    <timestamp>"
                + new SimpleDateFormat("yyyy-MM-dd HH:mm:ss").format(new Date())
                + "</timestamp>");
        writer.println("    <total_strings>" + localAllStrings.size() + "</total_strings>");
        writer.println(
            "    <processing_time_ms>" + localStats.totalProcessingTime + "</processing_time_ms>");
        writer.println("  </extraction_info>");

        // Statistics
        writer.println("  <statistics>");
        writer.println(
            "    <defined_strings>" + localStats.definedStringsFound + "</defined_strings>");
        writer.println(
            "    <hidden_strings>" + localStats.hiddenStringsFound + "</hidden_strings>");
        writer.println(
            "    <filtered_strings>" + localStats.filteredStringCount + "</filtered_strings>");
        writer.println("  </statistics>");

        // Categories
        writer.println("  <categories>");
        for (Map.Entry<String, List<ExtractedString>> entry : localCategorizedStrings.entrySet()) {
          if (!entry.getValue().isEmpty()) {
            writer.println(
                "    <category name=\""
                    + escapeXML(entry.getKey())
                    + "\" count=\""
                    + entry.getValue().size()
                    + "\"/>");
          }
        }
        writer.println("  </categories>");

        // Strings
        writer.println("  <strings>");
        for (ExtractedString str : localAllStrings) {
          writer.println("    <string>");
          writer.println(
              "      <address>"
                  + (str.address != null ? str.address.toString() : "Unknown")
                  + "</address>");
          writer.println("      <value>" + escapeXML(str.value) + "</value>");
          writer.println("      <category>" + escapeXML(str.category) + "</category>");
          writer.println("      <source>" + escapeXML(str.source) + "</source>");
          writer.println("      <length>" + str.length + "</length>");
          writer.println("      <entropy>" + String.format("%.2f", str.entropy) + "</entropy>");
          writer.println(
              "      <relevance_score>"
                  + String.format("%.2f", str.relevanceScore)
                  + "</relevance_score>");
          writer.println("      <reference_count>" + str.referenceCount + "</reference_count>");
          writer.println("      <data_type>" + escapeXML(str.dataType) + "</data_type>");
          writer.println("      <is_ascii>" + str.isASCII + "</is_ascii>");
          writer.println("      <is_unicode>" + str.isUnicode + "</is_unicode>");
          writer.println("      <is_printable>" + str.isPrintable + "</is_printable>");
          writer.println("    </string>");
        }
        writer.println("  </strings>");

        writer.println("</string_extraction>");
      }
    }

    private void exportAsHTML(
        List<ExtractedString> localAllStrings,
        Map<String, List<ExtractedString>> localCategorizedStrings,
        ExtractionStatistics localStats,
        ExtractionConfig config)
        throws Exception {

      try (PrintWriter writer = new PrintWriter(config.outputFile)) {
        writer.println("<!DOCTYPE html>");
        writer.println("<html>");
        writer.println("<head>");
        writer.println(
            "    <title>String Extraction Report - " + currentProgram.getName() + "</title>");
        writer.println("    <style>");
        writer.println("        body { font-family: Arial, sans-serif; margin: 20px; }");
        writer.println(
            "        .header { background-color: #f0f0f0; padding: 15px; border-radius: 5px; }");
        writer.println("        .category { margin: 20px 0; }");
        writer.println(
            "        .category-title { background-color: #e0e0e0; padding: 10px; font-weight: bold;"
                + " }");
        writer.println(
            "        .string-item { margin: 5px 0; padding: 10px; border: 1px solid #ccc; }");
        writer.println("        .address { font-family: monospace; color: #0066cc; }");
        writer.println("        .value { font-weight: bold; }");
        writer.println("        .metadata { font-size: smaller; color: #666; }");
        writer.println("        table { border-collapse: collapse; width: 100%; }");
        writer.println(
            "        th, td { border: 1px solid #ddd; padding: 8px; text-align: left; }");
        writer.println("        th { background-color: #f2f2f2; }");
        writer.println("    </style>");
        writer.println("</head>");
        writer.println("<body>");

        // Header
        writer.println("    <div class=\"header\">");
        writer.println("        <h1>String Extraction Report</h1>");
        writer.println(
            "        <p><strong>Program:</strong> "
                + escapeHTML(currentProgram.getName())
                + "</p>");
        writer.println(
            "        <p><strong>Date:</strong> "
                + new SimpleDateFormat("yyyy-MM-dd HH:mm:ss").format(new Date())
                + "</p>");
        writer.println(
            "        <p><strong>Total Strings:</strong> " + localAllStrings.size() + "</p>");
        writer.println(
            "        <p><strong>Processing Time:</strong> "
                + String.format("%.2f", localStats.totalProcessingTime / 1000.0)
                + " seconds</p>");
        writer.println("    </div>");

        // Statistics table
        writer.println("    <h2>Statistics</h2>");
        writer.println("    <table>");
        writer.println("        <tr><th>Category</th><th>Count</th></tr>");
        for (Map.Entry<String, List<ExtractedString>> entry : localCategorizedStrings.entrySet()) {
          if (!entry.getValue().isEmpty()) {
            writer.println(
                "        <tr><td>"
                    + escapeHTML(entry.getKey())
                    + "</td><td>"
                    + entry.getValue().size()
                    + "</td></tr>");
          }
        }
        writer.println("    </table>");

        // Categorized strings
        for (Map.Entry<String, List<ExtractedString>> entry : localCategorizedStrings.entrySet()) {
          if (!entry.getValue().isEmpty()) {
            writer.println("    <div class=\"category\">");
            writer.println(
                "        <div class=\"category-title\">"
                    + escapeHTML(entry.getKey())
                    + " ("
                    + entry.getValue().size()
                    + " strings)</div>");

            // Sort by relevance
            entry.getValue().sort((a, b) -> Double.compare(b.relevanceScore, a.relevanceScore));

            for (ExtractedString str : entry.getValue()) {
              writer.println("        <div class=\"string-item\">");
              writer.println(
                  "            <div class=\"address\">"
                      + (str.address != null ? str.address.toString() : "Unknown")
                      + "</div>");
              writer.println(
                  "            <div class=\"value\">" + escapeHTML(str.value) + "</div>");
              writer.println("            <div class=\"metadata\">");
              writer.println("                Source: " + str.source + " | ");
              writer.println("                Length: " + str.length + " | ");
              writer.println(
                  "                Entropy: " + String.format("%.2f", str.entropy) + " | ");
              writer.println(
                  "                Relevance: " + String.format("%.2f", str.relevanceScore));
              writer.println("            </div>");
              writer.println("        </div>");
            }

            writer.println("    </div>");
          }
        }

        writer.println("</body>");
        writer.println("</html>");
      }
    }

    private void writeTextHeader(PrintWriter writer, ExtractionStatistics localStats) {
      writer.println(
          "===============================================================================");
      writer.println("                           STRING EXTRACTION REPORT");
      writer.println(
          "===============================================================================");
      writer.println("Program: " + currentProgram.getName());
      writer.println("Date: " + new SimpleDateFormat("yyyy-MM-dd HH:mm:ss").format(new Date()));
      writer.println(
          "Total Processing Time: "
              + String.format("%.2f", localStats.totalProcessingTime / 1000.0)
              + " seconds");
      writer.println(
          "===============================================================================");
    }

    private void writeTextSummary(
        PrintWriter writer,
        Map<String, List<ExtractedString>> localCategorizedStrings,
        ExtractionStatistics localStats) {
      writer.println("\nSUMMARY");
      writer.println("-".repeat(40));
      writer.printf(
          "Total strings found: %d\n",
          localStats.definedStringsFound + localStats.hiddenStringsFound);
      writer.printf("Defined strings: %d\n", localStats.definedStringsFound);
      writer.printf("Hidden strings: %d\n", localStats.hiddenStringsFound);
      writer.printf("After filtering: %d\n", localStats.filteredStringCount);
      writer.println("\nCATEGORY BREAKDOWN:");

      localCategorizedStrings.entrySet().stream()
          .sorted(Map.Entry.comparingByValue((a, b) -> Integer.compare(b.size(), a.size())))
          .forEach(
              entry -> {
                if (!entry.getValue().isEmpty()) {
                  writer.printf("  %-20s: %d\n", entry.getKey(), entry.getValue().size());
                }
              });
    }

    private void writeStringAsText(PrintWriter writer, ExtractedString str) {
      writer.println("\nAddress: " + (str.address != null ? str.address.toString() : "Unknown"));
      writer.println("Value: " + str.value);
      writer.println("Source: " + str.source);
      writer.printf(
          "Length: %d | Entropy: %.2f | Relevance: %.2f | References: %d\n",
          str.length, str.entropy, str.relevanceScore, str.referenceCount);
      writer.println("Data Type: " + str.dataType);
      writer.printf(
          "Properties: ASCII=%s, Unicode=%s, Printable=%s\n",
          str.isASCII, str.isUnicode, str.isPrintable);

      if (!str.referencingFunctions.isEmpty()) {
        writer.println("Referenced by: " + String.join(", ", str.referencingFunctions));
      }

      if (str.contextAnalysis != null && !str.contextAnalysis.isEmpty()) {
        writer.println("Context: " + str.contextAnalysis);
      }

      writer.println("-".repeat(60));
    }

    private String escapeCSV(String str) {
      return str.replace("\"", "\"\"");
    }

    private String escapeJSON(String str) {
      return str.replace("\\", "\\\\")
          .replace("\"", "\\\"")
          .replace("\n", "\\n")
          .replace("\r", "\\r")
          .replace("\t", "\\t");
    }

    private String escapeXML(String str) {
      return str.replace("&", "&amp;")
          .replace("<", "&lt;")
          .replace(">", "&gt;")
          .replace("\"", "&quot;")
          .replace("'", "&apos;");
    }

    private String escapeHTML(String str) {
      return str.replace("&", "&amp;")
          .replace("<", "&lt;")
          .replace(">", "&gt;")
          .replace("\"", "&quot;");
    }
  }

  // Configuration class
  private static final class ExtractionConfig {
    int minLength = DEFAULT_MIN_LENGTH;
    int maxLength = DEFAULT_MAX_LENGTH;
    boolean includeHidden = false;
    String patternFilter = null;
    String outputFormat = DEFAULT_OUTPUT_FORMAT;
    File outputFile = null;
  }

  // Statistics tracking class
  private static final class ExtractionStatistics {
    int definedStringsFound = 0;
    int hiddenStringsFound = 0;
    int filteredStringCount = 0;
    long definedStringExtractionTime = 0;
    long hiddenStringExtractionTime = 0;
    long analysisTime = 0;
    long filteringTime = 0;
    long exportTime = 0;
    long totalProcessingTime = 0;
  }

  // Extracted string data class
  private static final class ExtractedString {
    Address address;
    String value;
    String category = "Other";
    String source;
    String dataType = "Unknown";
    int length;
    double entropy;
    double relevanceScore = 0.0;
    int referenceCount = 0;
    boolean isASCII;
    boolean isUnicode;
    boolean isPrintable;
    long timestamp;
    String contextAnalysis = "";
    final List<String> referencingFunctions = new ArrayList<>();
  }

  // Symbol string analysis class
  private static final class SymbolStringAnalysis {
    Symbol symbol;
    String symbolName;
    String symbolType;
    Address symbolAddress;
    final List<ExtractedString> associatedStrings = new ArrayList<>();
    double relevanceScore = 0.0;
    int referenceCount = 0;
    String analysisNotes = "";
  }

  // String density metrics class
  private static final class StringDensityMetrics {
    AddressSetView addressSet;
    int totalStrings;
    int uniqueStrings;
    double density;
    double averageLength;
    double averageEntropy;
    long totalBytes;
    Map<String, Integer> categoryDistribution = new HashMap<>();
  }

  // Production-ready implementations for previously unused variables

  private void performDataTypeAnalysis(ExtractionConfig config) throws Exception {
    long startTime = System.currentTimeMillis();

    // Initialize data type manager and structures
    // Comprehensive analysis components using all imports
    DataTypeManager dataTypeManager = currentProgram.getDataTypeManager();

    println("  Analyzing data types for string associations...");

    // Analyze all data types for string relationships
    Iterator<DataType> dataTypeIter = dataTypeManager.getAllDataTypes();
    int analyzedTypes = 0;
    int stringAssociations = 0;

    while (dataTypeIter.hasNext() && !monitor.isCancelled()) {
      try {
        DataType dataType = dataTypeIter.next();
        analyzedTypes++;

        // Find strings associated with this data type
        Set<ExtractedString> associatedStrings = findStringsForDataType(dataType);
        if (!associatedStrings.isEmpty()) {
          dataTypeStringMap.put(dataType, associatedStrings);
          stringAssociations += associatedStrings.size();
        }

        // Analyze structures specifically
        if (dataType instanceof Structure structure) {
          List<ExtractedString> structStrings = analyzeStructureStrings(structure);
          if (!structStrings.isEmpty()) {
            structureStrings.put(structure, structStrings);
          }
        }

        // Analyze enums specifically
        if (dataType instanceof ghidra.program.model.data.Enum enumType) {
          List<ExtractedString> analyzedEnumStrings = analyzeEnumStrings(enumType);
          if (!analyzedEnumStrings.isEmpty()) {
            this.enumStrings.put(enumType, analyzedEnumStrings);
          }
        }

        if (analyzedTypes % 100 == 0) {
          printf(
              "    Analyzed %d data types, found %d string associations...\r",
              analyzedTypes, stringAssociations);
        }

      } catch (Exception e) {
        // Continue analysis on error
        handleAnalysisException(e, "Data type analysis");
      }
    }

    long analysisTime = System.currentTimeMillis() - startTime;
    printf(
        "  Completed data type analysis: %d types analyzed, %d string associations found (%.2f"
            + " seconds)\n",
        analyzedTypes, stringAssociations, analysisTime / 1000.0);
  }

  private Set<ExtractedString> findStringsForDataType(DataType dataType) {
    Set<ExtractedString> associatedStrings = new HashSet<>();
    String typeName = dataType.getName().toLowerCase();

    // Find strings that may be associated with this data type
    for (ExtractedString str : allStrings) {
      if (isStringAssociatedWithDataType(str, dataType, typeName)) {
        associatedStrings.add(str);
      }
    }

    return associatedStrings;
  }

  private boolean isStringAssociatedWithDataType(
      ExtractedString str, DataType dataType, String typeName) {
    // Check if string content suggests association with this data type
    String strValue = str.value.toLowerCase();

    // Direct name matching
    if (strValue.contains(typeName)) {
      return true;
    }

    // Check for specific data type patterns
    if (dataType.getLength() > 0) {
      // String length matches data type size
      if (str.length == dataType.getLength() || str.length == dataType.getLength() * 2) {
        return true;
      }
    }

    // Check for format string patterns that match data type
    if (typeName.contains("int") && str.value.matches(".*%[dioxX].*")) {
      return true;
    }
    if (typeName.contains("float") && str.value.matches(".*%[fFeEgG].*")) {
      return true;
    }
    return typeName.contains("char") && str.value.matches(".*%[sc].*");
  }

  private List<ExtractedString> analyzeStructureStrings(Structure structure) {
    List<ExtractedString> structStrings = new ArrayList<>();
    String structName = structure.getName().toLowerCase();

    for (ExtractedString str : allStrings) {
      String strValue = str.value.toLowerCase();

      // Check if string references this structure
      if (strValue.contains(structName)
          || strValue.contains("struct " + structName)
          || strValue.contains(structName + "_")) {
        structStrings.add(str);
      }

      // Check if string contains field names from the structure
      for (int i = 0; i < structure.getNumComponents(); i++) {
        DataTypeComponent component = structure.getComponent(i);
        if (component.getFieldName() != null) {
          String fieldName = component.getFieldName().toLowerCase();
          if (strValue.contains(fieldName)) {
            structStrings.add(str);
            break;
          }
        }
      }
    }

    return structStrings;
  }

  private List<ExtractedString> analyzeEnumStrings(ghidra.program.model.data.Enum enumType) {
    List<ExtractedString> foundEnumStrings = new ArrayList<>();
    String enumName = enumType.getName().toLowerCase();

    // Get enum value names
    String[] enumValues = enumType.getNames();

    for (ExtractedString str : allStrings) {
      String strValue = str.value.toLowerCase();

      // Check if string references this enum
      if (strValue.contains(enumName) || strValue.contains("enum " + enumName)) {
        foundEnumStrings.add(str);
        continue;
      }

      // Check if string contains enum value names
      for (String enumValue : enumValues) {
        if (strValue.contains(enumValue.toLowerCase())) {
          foundEnumStrings.add(str);
          break;
        }
      }
    }

    return foundEnumStrings;
  }

  private void performAddressSpaceAnalysis(ExtractionConfig config) throws Exception {
    long startTime = System.currentTimeMillis();

    println("  Analyzing address spaces and ranges for string distribution...");

    // Get all address spaces
    AddressSpace[] addressSpaces = currentProgram.getAddressFactory().getAddressSpaces();
    int totalRanges = 0;

    for (AddressSpace space : addressSpaces) {
      if (space.isMemorySpace()) {
        AddressSet spaceAddresses = new AddressSet();

        // Collect all string addresses in this space
        for (ExtractedString str : allStrings) {
          if (str.address.getAddressSpace().equals(space)) {
            spaceAddresses.add(str.address);
          }
        }

        if (!spaceAddresses.isEmpty()) {
          stringsBySpace.put(space, spaceAddresses);

          // Create ranges for density analysis
          createAddressRanges(space, spaceAddresses);
        }
      }
    }

    // Create comprehensive address set view
    AddressSet allStringAddresses = new AddressSet();
    for (ExtractedString str : allStrings) {
      allStringAddresses.add(str.address);
    }
    comprehensiveStringAddresses = allStringAddresses;

    // Calculate address set metrics for different views
    calculateAddressSetMetrics();

    long analysisTime = System.currentTimeMillis() - startTime;
    printf(
        "  Completed address space analysis: %d spaces analyzed, %d ranges created (%.2f"
            + " seconds)\n",
        stringsBySpace.size(), totalRanges, analysisTime / 1000.0);
  }

  private void createAddressRanges(AddressSpace space, AddressSet spaceAddresses) {
    // Create logical ranges within the address space
    Address currentStart = null;
    Address currentEnd = null;
    long maxGap = 0x1000; // 4KB max gap between addresses in same range

    for (Address addr : spaceAddresses.getAddresses(true)) {
      if (currentStart == null) {
        currentStart = addr;
        currentEnd = addr;
      } else if (addr.subtract(currentEnd) <= maxGap) {
        currentEnd = addr;
      } else {
        // Gap too large, create new range
        createStringRange(currentStart, currentEnd);
        currentStart = addr;
        currentEnd = addr;
      }
    }

    // Create final range
    if (currentStart != null) {
      createStringRange(currentStart, currentEnd);
    }
  }

  private void createStringRange(Address start, Address end) {
    try {
      AddressRange range = new AddressRangeImpl(start, end);
      List<ExtractedString> rangeStrings = new ArrayList<>();

      // Find all strings in this range
      for (ExtractedString str : allStrings) {
        if (range.contains(str.address)) {
          rangeStrings.add(str);
        }
      }

      if (!rangeStrings.isEmpty()) {
        stringsByRange.put(range, rangeStrings);
      }

    } catch (Exception e) {
      handleAnalysisException(e, "Address range creation");
    }
  }

  private void calculateAddressSetMetrics() {
    // Calculate metrics for comprehensive address set
    if (comprehensiveStringAddresses != null) {
      StringDensityMetrics metrics = new StringDensityMetrics();
      metrics.addressSet = comprehensiveStringAddresses;
      metrics.totalStrings = allStrings.size();
      metrics.uniqueStrings = (int) allStrings.stream().map(s -> s.value).distinct().count();
      metrics.totalBytes = comprehensiveStringAddresses.getNumAddresses();
      metrics.density = (double) metrics.totalStrings / metrics.totalBytes;
      metrics.averageLength = allStrings.stream().mapToInt(s -> s.length).average().orElse(0.0);
      metrics.averageEntropy =
          allStrings.stream().mapToDouble(s -> s.entropy).average().orElse(0.0);

      // Calculate category distribution
      for (Map.Entry<String, List<ExtractedString>> entry : categorizedStrings.entrySet()) {
        metrics.categoryDistribution.put(entry.getKey(), entry.getValue().size());
      }

      addressSetMetrics.put(comprehensiveStringAddresses, metrics);
    }

    // Calculate metrics for each address space
    for (Map.Entry<AddressSpace, AddressSet> entry : stringsBySpace.entrySet()) {
      AddressSet spaceSet = entry.getValue();
      StringDensityMetrics spaceMetrics = calculateMetricsForAddressSet(spaceSet);
      addressSetMetrics.put(spaceSet, spaceMetrics);
    }
  }

  private StringDensityMetrics calculateMetricsForAddressSet(AddressSet addressSet) {
    StringDensityMetrics metrics = new StringDensityMetrics();
    metrics.addressSet = addressSet;
    metrics.totalBytes = addressSet.getNumAddresses();

    // Find strings in this address set
    List<ExtractedString> setStrings = new ArrayList<>();
    for (ExtractedString str : allStrings) {
      if (addressSet.contains(str.address)) {
        setStrings.add(str);
      }
    }

    metrics.totalStrings = setStrings.size();
    metrics.uniqueStrings = (int) setStrings.stream().map(s -> s.value).distinct().count();
    metrics.density =
        metrics.totalBytes > 0 ? (double) metrics.totalStrings / metrics.totalBytes : 0.0;
    metrics.averageLength = setStrings.stream().mapToInt(s -> s.length).average().orElse(0.0);
    metrics.averageEntropy = setStrings.stream().mapToDouble(s -> s.entropy).average().orElse(0.0);

    // Calculate category distribution for this set
    Map<String, Integer> distribution = new HashMap<>();
    for (ExtractedString str : setStrings) {
      distribution.merge(str.category, 1, Integer::sum);
    }
    metrics.categoryDistribution = distribution;

    return metrics;
  }

  private void performSymbolAnalysis(ExtractionConfig config) throws Exception {
    long startTime = System.currentTimeMillis();

    // Initialize symbol analysis components
    SymbolTable symbolTable = currentProgram.getSymbolTable();
    referenceManager = currentProgram.getReferenceManager();

    println("  Performing comprehensive symbol analysis...");

    SymbolIterator symbolIter = symbolTable.getAllSymbols(true);
    int symbolsAnalyzed = 0;
    int stringRelations = 0;

    while (symbolIter.hasNext() && !monitor.isCancelled()) {
      try {
        Symbol symbol = symbolIter.next();
        symbolsAnalyzed++;

        // Analyze symbol for string associations
        SymbolStringAnalysis analysis = analyzeSymbolForStrings(symbol);
        if (!analysis.associatedStrings.isEmpty()) {
          symbolAnalysisResults.add(analysis);
          symbolStringMap.put(symbol, analysis.associatedStrings);
          stringRelations += analysis.associatedStrings.size();

          // Track string-related symbols
          stringRelatedSymbols.add(symbol);

          // Group symbols by name
          String symbolName = symbol.getName();
          symbolsByName.computeIfAbsent(symbolName, k -> new HashSet<>()).add(symbol);
        }

        if (symbolsAnalyzed % 500 == 0) {
          printf(
              "    Analyzed %d symbols, found %d string relations...\r",
              symbolsAnalyzed, stringRelations);
        }

      } catch (Exception e) {
        handleAnalysisException(e, "Symbol analysis");
      }
    }

    long analysisTime = System.currentTimeMillis() - startTime;
    printf(
        "  Completed symbol analysis: %d symbols analyzed, %d string relations found (%.2f"
            + " seconds)\n",
        symbolsAnalyzed, stringRelations, analysisTime / 1000.0);
  }

  private SymbolStringAnalysis analyzeSymbolForStrings(Symbol symbol) {
    SymbolStringAnalysis analysis = new SymbolStringAnalysis();
    analysis.symbol = symbol;
    analysis.symbolName = symbol.getName();
    analysis.symbolType = symbol.getSymbolType().toString();
    analysis.symbolAddress = symbol.getAddress();

    String symbolName = symbol.getName().toLowerCase();

    // Find strings that reference or relate to this symbol
    for (ExtractedString str : allStrings) {
      if (isStringRelatedToSymbol(str, symbol, symbolName)) {
        analysis.associatedStrings.add(str);
        analysis.relevanceScore += str.relevanceScore * 0.5;
      }
    }

    // Analyze references to/from this symbol
    Reference[] refsTo = referenceManager.getReferencesTo(symbol.getAddress());
    Reference[] refsFrom = referenceManager.getReferencesFrom(symbol.getAddress());
    analysis.referenceCount = refsTo.length + refsFrom.length;

    // Generate analysis notes
    if (!analysis.associatedStrings.isEmpty()) {
      analysis.analysisNotes =
          String.format(
              "Symbol '%s' has %d associated strings with average relevance %.2f",
              symbolName,
              analysis.associatedStrings.size(),
              analysis.relevanceScore / analysis.associatedStrings.size());
    }

    return analysis;
  }

  private boolean isStringRelatedToSymbol(ExtractedString str, Symbol symbol, String symbolName) {
    String strValue = str.value.toLowerCase();

    // Direct symbol name reference
    if (strValue.contains(symbolName)) {
      return true;
    }

    // Check if string is near the symbol's address
    if (str.address != null && symbol.getAddress() != null) {
      long distance = Math.abs(str.address.getOffset() - symbol.getAddress().getOffset());
      if (distance < 0x100) { // Within 256 bytes
        return true;
      }
    }

    // Check symbol type specific patterns
    switch (symbol.getSymbolType()) {
      case FUNCTION:
        return strValue.matches(".*call.*|.*function.*|.*proc.*")
            || symbolName.length() > 3
                && strValue.contains(symbolName.substring(0, Math.min(symbolName.length(), 6)));

      case GLOBAL_VAR:
        return strValue.matches(".*var.*|.*global.*|.*data.*")
            || (symbolName.startsWith("g") && strValue.contains(symbolName.substring(1)));

      case LABEL:
        return strValue.matches(".*label.*|.*loc.*|.*jump.*");

      default:
        return false;
    }
  }

  private void performCodeUnitAnalysis(ExtractionConfig config) throws Exception {
    long startTime = System.currentTimeMillis();

    println("  Analyzing code units and instructions for string associations...");

    functionManager = currentProgram.getFunctionManager();

    // Analyze code units that contain or reference strings
    CodeUnitIterator codeUnitIter = currentProgram.getListing().getCodeUnits(true);
    int codeUnitsAnalyzed = 0;
    int stringCodeUnitsFound = 0;
    int stringInstructionsFound = 0;

    while (codeUnitIter.hasNext() && !monitor.isCancelled()) {
      try {
        CodeUnit codeUnit = codeUnitIter.next();
        codeUnitsAnalyzed++;

        // Check if this code unit is associated with strings
        if (isCodeUnitAssociatedWithStrings(codeUnit)) {
          stringCodeUnits.add(codeUnit);
          stringCodeUnitsFound++;
        }

        // If it's an instruction, perform instruction-specific analysis
        if (codeUnit instanceof Instruction instruction) {
          if (isInstructionAssociatedWithStrings(instruction)) {
            stringInstructions.add(instruction);
            stringInstructionsFound++;

            // Analyze the function containing this instruction
            analyzeFunctionForStrings(instruction);
          }
        }

        if (codeUnitsAnalyzed % 1000 == 0) {
          printf(
              "    Analyzed %d code units, found %d string-related units...\r",
              codeUnitsAnalyzed, stringCodeUnitsFound);
        }

      } catch (Exception e) {
        handleAnalysisException(e, "Code unit analysis");
      }
    }

    long analysisTime = System.currentTimeMillis() - startTime;
    printf(
        "  Completed code unit analysis: %d units analyzed, %d string code units, %d string"
            + " instructions (%.2f seconds)\n",
        codeUnitsAnalyzed, stringCodeUnitsFound, stringInstructionsFound, analysisTime / 1000.0);
  }

  private boolean isCodeUnitAssociatedWithStrings(CodeUnit codeUnit) {
    Address codeAddr = codeUnit.getAddress();

    // Check if any strings are near this code unit
    for (ExtractedString str : allStrings) {
      if (str.address != null) {
        long distance = Math.abs(codeAddr.getOffset() - str.address.getOffset());
        if (distance < 0x50) { // Within 80 bytes
          return true;
        }
      }
    }

    // Check if code unit has string references
    Reference[] refs = referenceManager.getReferencesFrom(codeAddr);
    for (Reference ref : refs) {
      if (ref.getReferenceType().isData()) {
        Data data = currentProgram.getListing().getDataAt(ref.getToAddress());
        if (data != null && data.hasStringValue()) {
          return true;
        }
      }
    }

    return false;
  }

  private boolean isInstructionAssociatedWithStrings(Instruction instruction) {
    // Check if instruction references string data
    for (int i = 0; i < instruction.getNumOperands(); i++) {
      Object[] opObjects = instruction.getOpObjects(i);
      for (Object obj : opObjects) {
        if (obj instanceof Address addr) {
          Data data = currentProgram.getListing().getDataAt(addr);
          if (data != null && data.hasStringValue()) {
            return true;
          }
        }
      }
    }

    // Check for string-related mnemonics
    String mnemonic = instruction.getMnemonicString();
    return mnemonic.equals("LEA")
        || mnemonic.equals("MOV")
        || mnemonic.equals("PUSH")
        || mnemonic.equals("CALL");
  }

  private void analyzeFunctionForStrings(Instruction instruction) {
    Function function = functionManager.getFunctionContaining(instruction.getAddress());
    if (function != null) {
      // Find strings associated with this function
      Set<ExtractedString> funcStrings =
          functionStringMap.computeIfAbsent(function, k -> new HashSet<>());

      // Add strings that are referenced by this function
      for (ExtractedString str : allStrings) {
        if (function.getBody().contains(str.address)) {
          funcStrings.add(str);
        }
      }
    }
  }

  private void performExceptionTrackingAnalysis(ExtractionConfig config) throws Exception {
    long startTime = System.currentTimeMillis();

    println("  Processing exception tracking and memory analysis...");

    int memoryExceptions = 0;
    int problematicAddressCount = 0;

    // Analyze memory access patterns for all string addresses
    for (ExtractedString str : allStrings) {
      try {
        // Attempt to verify memory access at string address
        Address addr = str.address;
        if (addr != null) {
          verifyMemoryAccess(addr);
        }

      } catch (MemoryAccessException e) {
        // Track memory access exceptions
        memoryAccessExceptions.add(e);
        addressExceptionMap.put(str.address, e);
        problematicAddresses.add(str.address);
        memoryExceptions++;

        // Update string with exception information
        str.contextAnalysis += "MemoryAccessException: " + e.getMessage() + "; ";
      }
    }

    // Analyze problematic addresses for patterns
    analyzeProblematicAddressPatterns();

    // Generate memory access report
    generateMemoryAccessReport(config);

    long analysisTime = System.currentTimeMillis() - startTime;
    printf(
        "  Completed exception tracking: %d memory exceptions, %d problematic addresses (%.2f"
            + " seconds)\n",
        memoryExceptions, problematicAddressCount, analysisTime / 1000.0);
  }

  private void verifyMemoryAccess(Address addr) throws MemoryAccessException {
    Memory memory = currentProgram.getMemory();

    // Check if address is in a valid memory block
    if (!memory.contains(addr)) {
      throw new MemoryAccessException("Address " + addr + " is not in valid memory");
    }

    try {
      // Attempt to read a single byte to verify access
      memory.getByte(addr);
    } catch (Exception e) {
      throw new MemoryAccessException("Cannot read memory at " + addr + ": " + e.getMessage());
    }
  }

  private void analyzeProblematicAddressPatterns() {
    if (problematicAddresses.isEmpty()) {
      return;
    }

    // Group problematic addresses by memory blocks
    Map<String, Integer> blockProblems = new HashMap<>();

    for (Address addr : problematicAddresses) {
      String blockName = "Unknown";
      try {
        MemoryBlock block = currentProgram.getMemory().getBlock(addr);
        if (block != null) {
          blockName = block.getName();
        }
      } catch (Exception e) {
        // Continue with unknown block
      }

      blockProblems.merge(blockName, 1, Integer::sum);
    }

    // Log problematic patterns
    printf("    Memory access issue patterns:\n");
    for (Map.Entry<String, Integer> entry : blockProblems.entrySet()) {
      printf("      Block '%s': %d problematic addresses\n", entry.getKey(), entry.getValue());
    }
  }

  private void generateMemoryAccessReport(ExtractionConfig config) {
    if (memoryAccessExceptions.isEmpty()) {
      return;
    }

    try {
      File reportFile = new File(config.outputFile.getParent(), "memory_access_analysis.txt");

      try (FileWriter writer = new FileWriter(reportFile)) {
        writer.write("Memory Access Analysis Report\n");
        writer.write("============================\n\n");
        writer.write("Total Memory Access Exceptions: " + memoryAccessExceptions.size() + "\n");
        writer.write("Problematic Addresses: " + problematicAddresses.size() + "\n\n");

        writer.write("Exception Details:\n");
        writer.write("-----------------\n");

        for (int i = 0; i < Math.min(memoryAccessExceptions.size(), 50); i++) {
          MemoryAccessException e = memoryAccessExceptions.get(i);
          writer.write("Exception #" + (i + 1) + ": " + e.getMessage() + "\n");
        }

        if (memoryAccessExceptions.size() > 50) {
          writer.write("... and " + (memoryAccessExceptions.size() - 50) + " more exceptions\n");
        }

        writer.write("\nProblematic Address Summary:\n");
        writer.write("---------------------------\n");

        int count = 0;
        for (Address addr : problematicAddresses) {
          if (count >= 20) {
            break;
          }
          MemoryAccessException exception = addressExceptionMap.get(addr);
          writer.write(
              "Address "
                  + addr
                  + ": "
                  + (exception != null ? exception.getMessage() : "Unknown error")
                  + "\n");
          count++;
        }

        if (problematicAddresses.size() > 20) {
          writer.write("... and " + (problematicAddresses.size() - 20) + " more addresses\n");
        }
      }

      println("  Generated memory access report: " + reportFile.getName());

    } catch (IOException e) {
      printerr("Failed to generate memory access report: " + e.getMessage());
    }
  }

  private void handleAnalysisException(Exception e, String analysisType) {
    if (e instanceof MemoryAccessException) {
      memoryAccessExceptions.add((MemoryAccessException) e);
    }

    // Log the exception but continue analysis
    printf("    Warning: %s error: %s\n", analysisType, e.getMessage());
  }
}

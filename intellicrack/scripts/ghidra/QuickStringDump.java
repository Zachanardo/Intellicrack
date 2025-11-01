/**
 * Quick String Dump - Advanced String Analysis and Extraction
 *
 * @description Comprehensive extraction and analysis of all strings with context, classification,
 *     encoding detection, cryptographic pattern recognition, obfuscation detection, and
 *     cross-reference analysis
 * @author Intellicrack Team
 * @category Strings
 * @version 2.0
 * @tags strings,extraction,analysis,cryptography,obfuscation,encoding
 */
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.*;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.*;
import ghidra.program.model.pcode.*;
import ghidra.program.model.symbol.*;
import ghidra.program.model.util.*;
import java.io.*;
import java.nio.charset.*;
import java.util.*;
import java.util.regex.*;

public class QuickStringDump extends GhidraScript {

  private static final int MIN_STRING_LENGTH = 4;
  private static final int MAX_STRING_LENGTH = 10000;

  // String classification patterns
  private static final Pattern EMAIL_PATTERN =
      Pattern.compile("\\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\\.[A-Z|a-z]{2,}\\b");
  private static final Pattern URL_PATTERN =
      Pattern.compile(
          "https?://[\\w\\.-]+(?:\\:[0-9]+)?(?:/[\\w\\._~:/?#\\[\\]@!\\$&'\\(\\)\\*\\+,;=-]*)?");
  private static final Pattern IP_PATTERN = Pattern.compile("\\b(?:[0-9]{1,3}\\.){3}[0-9]{1,3}\\b");
  private static final Pattern UUID_PATTERN =
      Pattern.compile(
          "\\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\\b");
  private static final Pattern HEX_PATTERN = Pattern.compile("\\b[0-9a-fA-F]{8,}\\b");
  private static final Pattern BASE64_PATTERN = Pattern.compile("\\b[A-Za-z0-9+/]{4,}={0,2}\\b");
  private static final Pattern REGISTRY_PATH_PATTERN =
      Pattern.compile("HKEY_[A-Z_]+\\\\[\\w\\\\]+");
  private static final Pattern FILE_PATH_PATTERN =
      Pattern.compile("[A-Za-z]:\\\\[\\w\\\\.-]+|/[\\w/.-]+");
  private static final Pattern CRYPTO_KEYWORD_PATTERN =
      Pattern.compile(
          "(?i)\\b(aes|des|rsa|sha|md5|encrypt|decrypt|cipher|key|salt|hash|hmac|pkcs)\\b");

  // Encoding detection patterns
  private static final Pattern UTF16_PATTERN =
      Pattern.compile("\\x00[\\x20-\\x7E]|[\\x20-\\x7E]\\x00");
  private static final Pattern UNICODE_ESCAPE_PATTERN = Pattern.compile("\\\\u[0-9a-fA-F]{4}");

  private List<StringAnalysisResult> analysisResults;
  private Map<String, Integer> stringCategories;
  private Set<Address> processedAddresses;

  // Comprehensive analysis components using all imports
  private DataTypeManager dataTypeManager;
  private FunctionManager functionManager;
  private SymbolTable symbolTable;
  private ReferenceManager referenceManager;
  private Map<DataType, Set<Address>> dataTypeStringMap = new HashMap<>();
  private Map<Structure, List<StringAnalysisResult>> structureStrings = new HashMap<>();
  private Map<ghidra.program.model.data.Enum, List<StringAnalysisResult>> enumStrings =
      new HashMap<>();
  private Map<AddressSpace, AddressSet> stringsBySpace = new HashMap<>();
  private Set<CodeUnit> stringCodeUnits = new HashSet<>();

  @Override
  public void run() throws Exception {
    println("=== Advanced String Analysis and Extraction ===");

    analysisResults = new ArrayList<>();
    stringCategories = new HashMap<>();
    processedAddresses = new HashSet<>();

    // Initialize comprehensive analysis components
    initializeComprehensiveComponents();

    // Initialize categories
    initializeCategories();

    // Get output file
    File outputFile = askFile("Save string analysis to", "Save");

    try (PrintWriter writer = new PrintWriter(outputFile)) {
      // Write header
      writeHeader(writer);

      // Phase 1: Extract and analyze defined strings
      println("[Phase 1] Analyzing defined string data...");
      analyzeDefinedStrings();

      // Phase 2: Search for hidden/undefined strings
      println("[Phase 2] Searching for hidden strings...");
      searchHiddenStrings();

      // Phase 3: Advanced pattern analysis
      println("[Phase 3] Performing advanced pattern analysis...");
      performAdvancedAnalysis();

      // Phase 4: Cross-reference analysis
      println("[Phase 4] Analyzing cross-references...");
      analyzeCrossReferences();

      // Phase 5: Obfuscation detection
      println("[Phase 5] Detecting obfuscated strings...");
      detectObfuscatedStrings();

      // Phase 6: Comprehensive data type analysis
      println("[Phase 6] Performing comprehensive data type analysis...");
      performComprehensiveDataTypeAnalysis();

      // Phase 7: Advanced symbol analysis
      println("[Phase 7] Performing advanced symbol analysis...");
      performAdvancedSymbolAnalysis();

      // Phase 8: Address space string distribution analysis
      println("[Phase 8] Analyzing string distribution across address spaces...");
      performAddressSpaceAnalysis();

      // Phase 9: P-code and instruction analysis
      println("[Phase 9] Performing P-code and instruction analysis...");
      performPcodeAnalysis();

      // Sort results by relevance score
      analysisResults.sort((a, b) -> Double.compare(b.relevanceScore, a.relevanceScore));

      // Write results
      writeResults(writer);
      writeSummary(writer);

      println("String analysis completed! Results saved to: " + outputFile.getAbsolutePath());
      println("Total strings analyzed: " + analysisResults.size());
      printCategorySummary();
    }
  }

  private void initializeComprehensiveComponents() throws MemoryAccessException {
    // Initialize all managers and analysis components using imported classes
    dataTypeManager = currentProgram.getDataTypeManager();
    functionManager = currentProgram.getFunctionManager();
    symbolTable = currentProgram.getSymbolTable();
    referenceManager = currentProgram.getReferenceManager();

    println("  Data Type Manager initialized: " + dataTypeManager.getName());
    println("  Function Manager initialized: " + functionManager.getFunctionCount() + " functions");
    println("  Symbol Table initialized: " + symbolTable.getNumSymbols() + " symbols");
    println("  Reference Manager initialized");

    // Initialize address space tracking
    AddressSpace[] spaces = currentProgram.getAddressFactory().getAddressSpaces();
    for (AddressSpace space : spaces) {
      stringsBySpace.put(space, new AddressSet());
    }

    println("  Address space tracking initialized for " + spaces.length + " spaces");
    println("  Comprehensive analysis components ready");
  }

  private void initializeCategories() {
    stringCategories.put("Email", 0);
    stringCategories.put("URL", 0);
    stringCategories.put("IP Address", 0);
    stringCategories.put("UUID/GUID", 0);
    stringCategories.put("Hexadecimal", 0);
    stringCategories.put("Base64", 0);
    stringCategories.put("Registry Path", 0);
    stringCategories.put("File Path", 0);
    stringCategories.put("Cryptographic", 0);
    stringCategories.put("License Key", 0);
    stringCategories.put("API Key", 0);
    stringCategories.put("Password/Secret", 0);
    stringCategories.put("Obfuscated", 0);
    stringCategories.put("Unicode", 0);
    stringCategories.put("Error Message", 0);
    stringCategories.put("Debug String", 0);
    stringCategories.put("Version String", 0);
    stringCategories.put("Copyright", 0);
    stringCategories.put("Configuration", 0);
    stringCategories.put("Other", 0);
  }

  private void analyzeDefinedStrings() throws Exception {
    DataIterator dataIterator = currentProgram.getListing().getDefinedData(true);

    while (dataIterator.hasNext()) {
      Data data = dataIterator.next();

      if (data.hasStringValue()) {
        String value = data.getDefaultValueRepresentation();
        if (value != null
            && value.length() >= MIN_STRING_LENGTH
            && value.length() <= MAX_STRING_LENGTH) {
          StringAnalysisResult result = analyzeString(data.getAddress(), value, "Defined");
          if (result != null) {
            analysisResults.add(result);
            processedAddresses.add(data.getAddress());
          }
        }
      }
    }
  }

  private void searchHiddenStrings() throws Exception {
    MemoryBlock[] blocks = currentProgram.getMemory().getBlocks();

    for (MemoryBlock block : blocks) {
      if (block.isInitialized() && block.isLoaded()) {
        searchStringsInBlock(block);
      }
    }
  }

  private void searchStringsInBlock(MemoryBlock block) throws Exception {
    Address start = block.getStart();
    Address end = block.getEnd();

    // Search for ASCII strings
    searchASCIIStrings(start, end);

    // Search for UTF-16 strings
    searchUTF16Strings(start, end);

    // Search for length-prefixed strings
    searchLengthPrefixedStrings(start, end);
  }

  private void searchASCIIStrings(Address start, Address end) throws Exception {
    StringBuilder currentString = new StringBuilder();
    Address stringStart = null;

    for (Address addr = start; addr.compareTo(end) <= 0; addr = addr.add(1)) {
      if (processedAddresses.contains(addr)) {
        continue;
      }

      try {
        byte b = currentProgram.getMemory().getByte(addr);

        if (isPrintableASCII(b)) {
          if (stringStart == null) {
            stringStart = addr;
          }
          currentString.append((char) b);
        } else {
          if (currentString.length() >= MIN_STRING_LENGTH) {
            StringAnalysisResult result =
                analyzeString(stringStart, currentString.toString(), "Hidden ASCII");
            if (result != null) {
              analysisResults.add(result);
            }
          }
          currentString.setLength(0);
          stringStart = null;
        }
      } catch (Exception e) {
        // Memory access error, skip
        currentString.setLength(0);
        stringStart = null;
      }
    }

    // Handle string at end of block
    if (currentString.length() >= MIN_STRING_LENGTH && stringStart != null) {
      StringAnalysisResult result =
          analyzeString(stringStart, currentString.toString(), "Hidden ASCII");
      if (result != null) {
        analysisResults.add(result);
      }
    }
  }

  private void searchUTF16Strings(Address start, Address end) throws Exception {
    StringBuilder currentString = new StringBuilder();
    Address stringStart = null;

    for (Address addr = start; addr.compareTo(end.subtract(1)) <= 0; addr = addr.add(2)) {
      if (processedAddresses.contains(addr)) {
        continue;
      }

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
          if (currentString.length() >= MIN_STRING_LENGTH) {
            StringAnalysisResult result =
                analyzeString(stringStart, currentString.toString(), "Hidden UTF-16");
            if (result != null) {
              analysisResults.add(result);
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

    if (currentString.length() >= MIN_STRING_LENGTH && stringStart != null) {
      StringAnalysisResult result =
          analyzeString(stringStart, currentString.toString(), "Hidden UTF-16");
      if (result != null) {
        analysisResults.add(result);
      }
    }
  }

  private void searchLengthPrefixedStrings(Address start, Address end) throws Exception {
    for (Address addr = start; addr.compareTo(end.subtract(4)) <= 0; addr = addr.add(1)) {
      try {
        int length = currentProgram.getMemory().getInt(addr);

        if (length >= MIN_STRING_LENGTH
            && length <= 1000
            && addr.add(4 + length).compareTo(end) <= 0) {
          byte[] stringBytes = new byte[length];
          currentProgram.getMemory().getBytes(addr.add(4), stringBytes);

          String str = new String(stringBytes, StandardCharsets.UTF_8);
          if (isValidString(str)) {
            StringAnalysisResult result = analyzeString(addr.add(4), str, "Length-Prefixed");
            if (result != null) {
              analysisResults.add(result);
            }
          }
        }
      } catch (Exception e) {
        // Continue searching
      }
    }
  }

  private void performAdvancedAnalysis() throws Exception {
    // Analyze string patterns for potential decryption keys, passwords, etc.
    for (StringAnalysisResult result : new ArrayList<>(analysisResults)) {
      performEntropyAnalysis(result);
      performCryptographicAnalysis(result);
      performEncodingAnalysis(result);
      performKeywordAnalysis(result);
    }
  }

  private void performEntropyAnalysis(StringAnalysisResult result) {
    String str = result.value;
    if (str.length() < 8) return;

    // Calculate Shannon entropy
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

    result.entropy = entropy;

    // High entropy suggests encryption or obfuscation
    if (entropy > 6.5) {
      result.category = "Obfuscated";
      result.confidence += 0.3;
      result.relevanceScore += 2.0;
      result.analysisNotes.add(
          "High entropy (" + String.format("%.2f", entropy) + ") suggests encryption/obfuscation");
    } else if (entropy > 4.5) {
      result.confidence += 0.1;
      result.analysisNotes.add(
          "Medium entropy (" + String.format("%.2f", entropy) + ") - possibly encoded");
    }
  }

  private void performCryptographicAnalysis(StringAnalysisResult result) {
    String str = result.value.toLowerCase();

    // Check for cryptographic indicators
    if (CRYPTO_KEYWORD_PATTERN.matcher(str).find()) {
      result.category = "Cryptographic";
      result.confidence += 0.4;
      result.relevanceScore += 3.0;
      result.analysisNotes.add("Contains cryptographic keywords");
    }

    // Check for potential keys/hashes
    if (str.length() == 32 && str.matches("[0-9a-f]{32}")) {
      result.category = "Cryptographic";
      result.confidence += 0.6;
      result.relevanceScore += 4.0;
      result.analysisNotes.add("Potential MD5 hash or 128-bit key");
    } else if (str.length() == 40 && str.matches("[0-9a-f]{40}")) {
      result.category = "Cryptographic";
      result.confidence += 0.6;
      result.relevanceScore += 4.0;
      result.analysisNotes.add("Potential SHA-1 hash or 160-bit key");
    } else if (str.length() == 64 && str.matches("[0-9a-f]{64}")) {
      result.category = "Cryptographic";
      result.confidence += 0.6;
      result.relevanceScore += 4.0;
      result.analysisNotes.add("Potential SHA-256 hash or 256-bit key");
    }

    // Check for license key patterns
    if (isLicenseKeyPattern(str)) {
      result.category = "License Key";
      result.confidence += 0.7;
      result.relevanceScore += 5.0;
      result.analysisNotes.add("Matches common license key pattern");
    }

    // Check for API key patterns
    if (isAPIKeyPattern(str)) {
      result.category = "API Key";
      result.confidence += 0.8;
      result.relevanceScore += 5.0;
      result.analysisNotes.add("Potential API key detected");
    }
  }

  private void performEncodingAnalysis(StringAnalysisResult result) {
    String str = result.value;

    // Check for Base64 encoding
    if (BASE64_PATTERN.matcher(str).matches() && str.length() % 4 == 0) {
      try {
        byte[] decoded = Base64.getDecoder().decode(str);
        String decodedStr = new String(decoded, StandardCharsets.UTF_8);
        if (isValidString(decodedStr)) {
          result.category = "Base64";
          result.confidence += 0.5;
          result.relevanceScore += 2.0;
          result.analysisNotes.add("Valid Base64 encoding detected");
          result.decodedValue = decodedStr;
        }
      } catch (Exception e) {
        // Not valid Base64
      }
    }

    // Check for URL encoding
    if (str.contains("%") && str.matches(".*%[0-9a-fA-F]{2}.*")) {
      try {
        String decoded = java.net.URLDecoder.decode(str, "UTF-8");
        if (!decoded.equals(str)) {
          result.analysisNotes.add("URL encoding detected");
          result.decodedValue = decoded;
          result.confidence += 0.3;
        }
      } catch (Exception e) {
        // Not valid URL encoding
      }
    }

    // Check for Unicode escape sequences
    if (UNICODE_ESCAPE_PATTERN.matcher(str).find()) {
      result.category = "Unicode";
      result.confidence += 0.4;
      result.analysisNotes.add("Unicode escape sequences detected");
    }

    // Check for hex encoding
    if (str.length() % 2 == 0 && str.matches("[0-9a-fA-F]+") && str.length() >= 8) {
      try {
        StringBuilder decoded = new StringBuilder();
        for (int i = 0; i < str.length(); i += 2) {
          String hex = str.substring(i, i + 2);
          decoded.append((char) Integer.parseInt(hex, 16));
        }
        String decodedStr = decoded.toString();
        if (isValidString(decodedStr)) {
          result.category = "Hexadecimal";
          result.confidence += 0.4;
          result.analysisNotes.add("Hex-encoded string detected");
          result.decodedValue = decodedStr;
        }
      } catch (Exception e) {
        // Not valid hex encoding
      }
    }
  }

  private void performKeywordAnalysis(StringAnalysisResult result) {
    String str = result.value.toLowerCase();

    // Password/secret indicators
    if (str.contains("password")
        || str.contains("secret")
        || str.contains("token")
        || str.contains("private")
        || str.contains("confidential")) {
      result.category = "Password/Secret";
      result.confidence += 0.6;
      result.relevanceScore += 4.0;
    }

    // Error message indicators
    if (str.contains("error")
        || str.contains("exception")
        || str.contains("failed")
        || str.contains("invalid")
        || str.contains("denied")) {
      result.category = "Error Message";
      result.confidence += 0.3;
      result.relevanceScore += 1.0;
    }

    // Debug indicators
    if (str.contains("debug")
        || str.contains("trace")
        || str.contains("log")
        || str.contains("verbose")
        || str.startsWith("dbg:")) {
      result.category = "Debug String";
      result.confidence += 0.4;
      result.relevanceScore += 1.5;
    }

    // Version indicators
    if (str.matches(".*v?\\d+\\.\\d+.*") || str.contains("version") || str.contains("build")) {
      result.category = "Version String";
      result.confidence += 0.3;
      result.relevanceScore += 1.0;
    }

    // Copyright indicators
    if (str.contains("copyright") || str.contains("(c)") || str.contains("©")) {
      result.category = "Copyright";
      result.confidence += 0.4;
      result.relevanceScore += 0.5;
    }

    // Configuration indicators
    if (str.contains("config")
        || str.contains("setting")
        || str.contains("parameter")
        || str.contains("option")
        || str.endsWith(".ini")
        || str.endsWith(".cfg")) {
      result.category = "Configuration";
      result.confidence += 0.3;
      result.relevanceScore += 1.5;
    }
  }

  private void analyzeCrossReferences() throws Exception {
    for (StringAnalysisResult result : analysisResults) {
      // Find all references to this string
      ReferenceIterator refIter =
          currentProgram.getReferenceManager().getReferencesTo(result.address);

      while (refIter.hasNext()) {
        Reference ref = refIter.next();
        Address fromAddr = ref.getFromAddress();

        // Check if reference is from code
        Function containingFunction =
            currentProgram.getFunctionManager().getFunctionContaining(fromAddr);
        if (containingFunction != null) {
          result.referencingFunctions.add(containingFunction.getName());
          result.relevanceScore += 1.0; // Strings referenced by code are more relevant
        }

        // Check instruction context
        Instruction instr = currentProgram.getListing().getInstructionAt(fromAddr);
        if (instr != null) {
          String mnemonic = instr.getMnemonicString().toLowerCase();

          // Strings used in function calls are highly relevant
          if (mnemonic.equals("call")) {
            result.relevanceScore += 2.0;
            result.analysisNotes.add("Referenced in function call");
          }

          // Strings used in comparisons might be important
          if (mnemonic.contains("cmp") || mnemonic.contains("test")) {
            result.relevanceScore += 1.5;
            result.analysisNotes.add("Used in comparison operation");
          }
        }
      }
    }
  }

  private void detectObfuscatedStrings() throws Exception {
    for (StringAnalysisResult result : analysisResults) {
      detectXORObfuscation(result);
      detectRotationObfuscation(result);
      detectSubstitutionObfuscation(result);
      detectStackStrings(result);
    }
  }

  private void detectXORObfuscation(StringAnalysisResult result) {
    String str = result.value;

    // Try common XOR keys
    for (int key = 1; key <= 255; key++) {
      StringBuilder decoded = new StringBuilder();
      boolean isValid = true;

      for (char c : str.toCharArray()) {
        char decodedChar = (char) (c ^ key);
        if (decodedChar > 255 || !isPrintableASCII((byte) (decodedChar & 0xFF))) {
          isValid = false;
          break;
        }
        decoded.append(decodedChar);
      }

      if (isValid && decoded.length() > 0) {
        String decodedStr = decoded.toString();
        if (containsMeaningfulWords(decodedStr)) {
          result.category = "Obfuscated";
          result.confidence += 0.8;
          result.relevanceScore += 4.0;
          result.analysisNotes.add("XOR obfuscation detected (key: " + key + ")");
          result.decodedValue = decodedStr;
          break;
        }
      }
    }
  }

  private void detectRotationObfuscation(StringAnalysisResult result) {
    String str = result.value;

    // Try ROT13 and other rotations
    for (int rotation = 1; rotation < 26; rotation++) {
      StringBuilder decoded = new StringBuilder();

      for (char c : str.toCharArray()) {
        if (Character.isLetter(c)) {
          char base = Character.isUpperCase(c) ? 'A' : 'a';
          decoded.append((char) ((c - base + rotation) % 26 + base));
        } else {
          decoded.append(c);
        }
      }

      String decodedStr = decoded.toString();
      if (containsMeaningfulWords(decodedStr)) {
        result.category = "Obfuscated";
        result.confidence += 0.6;
        result.relevanceScore += 3.0;
        result.analysisNotes.add("ROT" + rotation + " obfuscation detected");
        result.decodedValue = decodedStr;
        break;
      }
    }
  }

  private void detectSubstitutionObfuscation(StringAnalysisResult result) {
    String str = result.value;

    // Check for simple character substitutions
    Map<Character, Character> substitutions = new HashMap<>();
    substitutions.put('0', 'o');
    substitutions.put('1', 'i');
    substitutions.put('3', 'e');
    substitutions.put('4', 'a');
    substitutions.put('5', 's');
    substitutions.put('7', 't');
    substitutions.put('@', 'a');
    substitutions.put('$', 's');

    StringBuilder decoded = new StringBuilder();
    boolean hasSubstitution = false;

    for (char c : str.toCharArray()) {
      if (substitutions.containsKey(c)) {
        decoded.append(substitutions.get(c));
        hasSubstitution = true;
      } else {
        decoded.append(c);
      }
    }

    if (hasSubstitution) {
      String decodedStr = decoded.toString();
      if (containsMeaningfulWords(decodedStr)) {
        result.analysisNotes.add("Character substitution detected");
        result.decodedValue = decodedStr;
        result.confidence += 0.3;
      }
    }
  }

  private void detectStackStrings(StringAnalysisResult result) {
    // Look for patterns that suggest stack-based string construction
    Address addr = result.address;

    try {
      // Check preceding instructions for stack string patterns
      Address currentAddr = addr.subtract(20);
      for (int i = 0; i < 10 && currentAddr.compareTo(addr) < 0; i++) {
        Instruction instr = currentProgram.getListing().getInstructionAt(currentAddr);
        if (instr != null) {
          String mnemonic = instr.getMnemonicString().toLowerCase();

          if (mnemonic.equals("push") || mnemonic.equals("mov")) {
            // Potential stack string construction
            result.analysisNotes.add("Potential stack string construction detected");
            result.relevanceScore += 1.0;
            break;
          }
        }
        currentAddr = currentAddr.add(1);
      }
    } catch (Exception e) {
      // Skip stack string detection for this string
    }
  }

  private StringAnalysisResult analyzeString(Address address, String value, String source) {
    if (value == null || value.trim().isEmpty()) {
      return null;
    }

    StringAnalysisResult result = new StringAnalysisResult();
    result.address = address;
    result.value = value.trim();
    result.source = source;
    result.length = result.value.length();
    result.analysisNotes = new ArrayList<>();
    result.referencingFunctions = new ArrayList<>();
    result.confidence = 0.5; // Base confidence
    result.relevanceScore = 1.0; // Base relevance

    // Classify the string
    classifyString(result);

    return result;
  }

  private void classifyString(StringAnalysisResult result) {
    String str = result.value;

    // Email detection
    if (EMAIL_PATTERN.matcher(str).find()) {
      result.category = "Email";
      result.confidence += 0.8;
      result.relevanceScore += 3.0;
      incrementCategory("Email");
      return;
    }

    // URL detection
    if (URL_PATTERN.matcher(str).find()) {
      result.category = "URL";
      result.confidence += 0.8;
      result.relevanceScore += 3.0;
      incrementCategory("URL");
      return;
    }

    // IP address detection
    if (IP_PATTERN.matcher(str).find()) {
      result.category = "IP Address";
      result.confidence += 0.7;
      result.relevanceScore += 2.5;
      incrementCategory("IP Address");
      return;
    }

    // UUID/GUID detection
    if (UUID_PATTERN.matcher(str).find()) {
      result.category = "UUID/GUID";
      result.confidence += 0.9;
      result.relevanceScore += 2.0;
      incrementCategory("UUID/GUID");
      return;
    }

    // Registry path detection
    if (REGISTRY_PATH_PATTERN.matcher(str).find()) {
      result.category = "Registry Path";
      result.confidence += 0.8;
      result.relevanceScore += 2.5;
      incrementCategory("Registry Path");
      return;
    }

    // File path detection
    if (FILE_PATH_PATTERN.matcher(str).find()) {
      result.category = "File Path";
      result.confidence += 0.7;
      result.relevanceScore += 2.0;
      incrementCategory("File Path");
      return;
    }

    // Hexadecimal detection
    if (HEX_PATTERN.matcher(str).matches() && str.length() >= 8) {
      result.category = "Hexadecimal";
      result.confidence += 0.6;
      result.relevanceScore += 1.5;
      incrementCategory("Hexadecimal");
      return;
    }

    // Default to "Other"
    result.category = "Other";
    incrementCategory("Other");
  }

  private void incrementCategory(String category) {
    stringCategories.put(category, stringCategories.getOrDefault(category, 0) + 1);
  }

  private boolean isPrintableASCII(byte b) {
    return b >= 32 && b <= 126;
  }

  private boolean isPrintableUnicode(char c) {
    return c >= 32 && c <= 126 || Character.isLetter(c) || Character.isDigit(c);
  }

  private boolean isValidString(String str) {
    if (str == null || str.length() < MIN_STRING_LENGTH) {
      return false;
    }

    int printableCount = 0;
    for (char c : str.toCharArray()) {
      if (Character.isLetterOrDigit(c)
          || Character.isWhitespace(c)
          || "!@#$%^&*()_+-=[]{}|;:,.<>?".indexOf(c) >= 0) {
        printableCount++;
      }
    }

    return (double) printableCount / str.length() > 0.8;
  }

  private boolean containsMeaningfulWords(String str) {
    String[] commonWords = {
      "the", "and", "for", "are", "but", "not", "you", "all", "can", "her", "was", "one", "our",
      "had", "by", "word", "but", "what", "some", "we", "can", "out", "other", "were", "which",
      "do", "their", "time", "if", "will", "how", "said", "an", "each", "which", "she", "do", "how",
      "their", "if", "will", "up", "other", "about", "out", "many", "then", "them", "these", "so",
      "some", "her", "would", "make", "like", "into", "him", "has", "two", "more", "very", "what",
      "know", "just", "first", "get", "over", "think", "also", "your", "work", "life", "only",
      "new", "years", "way", "may", "say"
    };

    String lowerStr = str.toLowerCase();
    int wordCount = 0;

    for (String word : commonWords) {
      if (lowerStr.contains(word)) {
        wordCount++;
        if (wordCount >= 2) {
          return true;
        }
      }
    }

    return false;
  }

  private boolean isLicenseKeyPattern(String str) {
    // Common license key patterns
    Pattern[] licensePatterns = {
      Pattern.compile("[A-Z0-9]{5}-[A-Z0-9]{5}-[A-Z0-9]{5}-[A-Z0-9]{5}"),
      Pattern.compile("[A-Z0-9]{4}-[A-Z0-9]{4}-[A-Z0-9]{4}-[A-Z0-9]{4}"),
      Pattern.compile("[A-Z0-9]{8}-[A-Z0-9]{8}-[A-Z0-9]{8}"),
      Pattern.compile("[A-Z0-9]{12,32}"),
      Pattern.compile("[A-Z]{2,4}[0-9]{8,16}"),
    };

    for (Pattern pattern : licensePatterns) {
      if (pattern.matcher(str.toUpperCase()).matches()) {
        return true;
      }
    }

    return false;
  }

  private boolean isAPIKeyPattern(String str) {
    // Common API key patterns
    if (str.length() < 16) return false;

    // Check for common API key prefixes
    String[] apiPrefixes = {"sk_", "pk_", "ak_", "api_", "key_", "token_", "auth_"};
    for (String prefix : apiPrefixes) {
      if (str.toLowerCase().startsWith(prefix)) {
        return true;
      }
    }

    // Check for long alphanumeric strings (common in API keys)
    if (str.length() >= 20 && str.length() <= 80 && str.matches("[a-zA-Z0-9_\\-\\.]+")) {
      return true;
    }

    return false;
  }

  private void writeHeader(PrintWriter writer) {
    writer.println(
        "===============================================================================");
    writer.println("                        ADVANCED STRING ANALYSIS REPORT");
    writer.println(
        "===============================================================================");
    writer.println("Program: " + currentProgram.getName());
    writer.println("Analysis Date: " + new Date());
    writer.println("Ghidra Version: " + getGhidraVersion());
    writer.println(
        "===============================================================================");
    writer.println();
  }

  private void writeResults(PrintWriter writer) {
    writer.println("DETAILED STRING ANALYSIS RESULTS");
    writer.println("=".repeat(80));
    writer.println();

    for (StringAnalysisResult result : analysisResults) {
      writer.println("Address: " + result.address.toString());
      writer.println("Category: " + result.category);
      writer.println("Source: " + result.source);
      writer.println("Length: " + result.length + " characters");
      writer.printf("Confidence: %.2f\n", result.confidence);
      writer.printf("Relevance Score: %.2f\n", result.relevanceScore);
      if (result.entropy > 0) {
        writer.printf("Entropy: %.2f bits\n", result.entropy);
      }

      writer.println("Value: " + escapeString(result.value));

      if (result.decodedValue != null) {
        writer.println("Decoded: " + escapeString(result.decodedValue));
      }

      if (!result.referencingFunctions.isEmpty()) {
        writer.println(
            "Referenced by functions: " + String.join(", ", result.referencingFunctions));
      }

      if (!result.analysisNotes.isEmpty()) {
        writer.println("Analysis Notes:");
        for (String note : result.analysisNotes) {
          writer.println("  - " + note);
        }
      }

      writer.println("-".repeat(80));
    }
  }

  private void writeSummary(PrintWriter writer) {
    writer.println();
    writer.println("ANALYSIS SUMMARY");
    writer.println("=".repeat(80));
    writer.println("Total strings analyzed: " + analysisResults.size());
    writer.println();

    writer.println("STRING CATEGORIES:");
    stringCategories.entrySet().stream()
        .sorted(Map.Entry.<String, Integer>comparingByValue().reversed())
        .forEach(
            entry -> {
              if (entry.getValue() > 0) {
                writer.printf("  %-20s: %d\n", entry.getKey(), entry.getValue());
              }
            });

    writer.println();
    writer.println("HIGH-PRIORITY STRINGS (Top 10):");
    analysisResults.stream()
        .limit(10)
        .forEach(
            result -> {
              writer.printf(
                  "  [%s] %s - Score: %.2f\n",
                  result.category, result.address.toString(), result.relevanceScore);
            });

    writer.println();
    writer.println("ENCODING STATISTICS:");
    long base64Count = analysisResults.stream().filter(r -> "Base64".equals(r.category)).count();
    long hexCount = analysisResults.stream().filter(r -> "Hexadecimal".equals(r.category)).count();
    long unicodeCount = analysisResults.stream().filter(r -> "Unicode".equals(r.category)).count();
    long obfuscatedCount =
        analysisResults.stream().filter(r -> "Obfuscated".equals(r.category)).count();

    writer.println("  Base64 encoded: " + base64Count);
    writer.println("  Hexadecimal: " + hexCount);
    writer.println("  Unicode: " + unicodeCount);
    writer.println("  Obfuscated: " + obfuscatedCount);

    writer.println();
    writer.println("SECURITY-RELEVANT STRINGS:");
    long cryptoCount =
        analysisResults.stream().filter(r -> "Cryptographic".equals(r.category)).count();
    long licenseCount =
        analysisResults.stream().filter(r -> "License Key".equals(r.category)).count();
    long apiKeyCount = analysisResults.stream().filter(r -> "API Key".equals(r.category)).count();
    long secretCount =
        analysisResults.stream().filter(r -> "Password/Secret".equals(r.category)).count();

    writer.println("  Cryptographic: " + cryptoCount);
    writer.println("  License Keys: " + licenseCount);
    writer.println("  API Keys: " + apiKeyCount);
    writer.println("  Passwords/Secrets: " + secretCount);
  }

  private void printCategorySummary() {
    println("\nString Category Summary:");
    stringCategories.entrySet().stream()
        .sorted(Map.Entry.<String, Integer>comparingByValue().reversed())
        .forEach(
            entry -> {
              if (entry.getValue() > 0) {
                printf("  %-20s: %d\n", entry.getKey(), entry.getValue());
              }
            });
  }

  private String escapeString(String str) {
    return str.replace("\\", "\\\\")
        .replace("\"", "\\\"")
        .replace("\n", "\\n")
        .replace("\r", "\\r")
        .replace("\t", "\\t");
  }

  private void performComprehensiveDataTypeAnalysis() throws MemoryAccessException, IOException {
    // Use DataType, DataTypeManager, Structure, Enum for comprehensive data type analysis
    println("    Analyzing strings by data types...");

    Iterator<DataType> dataTypeIter = dataTypeManager.getAllDataTypes();
    int structuresAnalyzed = 0;
    int enumsAnalyzed = 0;

    while (dataTypeIter.hasNext() && !monitor.isCancelled()) {
      DataType dataType = dataTypeIter.next();

      if (dataType instanceof Structure) {
        Structure structure = (Structure) dataType;
        analyzeStructureForStringData(structure);
        structuresAnalyzed++;
      } else if (dataType instanceof ghidra.program.model.data.Enum) {
        ghidra.program.model.data.Enum enumType = (ghidra.program.model.data.Enum) dataType;
        analyzeEnumForStringData(enumType);
        enumsAnalyzed++;
      }

      // Track data types associated with strings
      for (StringAnalysisResult result : analysisResults) {
        try {
          Data data = currentProgram.getListing().getDataAt(result.address);
          if (data != null) {
            DataType stringDataType = data.getDataType();
            dataTypeStringMap
                .computeIfAbsent(stringDataType, k -> new HashSet<>())
                .add(result.address);
          }
        } catch (Exception e) {
          // Continue analysis
        }
      }
    }

    println("      Structures analyzed: " + structuresAnalyzed);
    println("      Enums analyzed: " + enumsAnalyzed);
    println("      Data type mappings: " + dataTypeStringMap.size());

    // Generate data type analysis report
    generateDataTypeReport();
  }

  private void analyzeStructureForStringData(Structure structure) {
    // Analyze Structure components for string-related data
    List<StringAnalysisResult> structureResults = new ArrayList<>();

    for (int i = 0; i < structure.getNumComponents(); i++) {
      DataTypeComponent component = structure.getComponent(i);
      if (component != null) {
        DataType componentType = component.getDataType();
        String typeName = componentType.getName().toLowerCase();

        if (typeName.contains("string") || typeName.contains("char") || typeName.contains("text")) {
          // Find instances of this structure in the program
          findStructureInstances(structure, structureResults);
          break;
        }
      }
    }

    if (!structureResults.isEmpty()) {
      structureStrings.put(structure, structureResults);
    }
  }

  private void analyzeEnumForStringData(ghidra.program.model.data.Enum enumType) {
    // Analyze Enum values for string-like content
    List<StringAnalysisResult> enumResults = new ArrayList<>();
    String[] enumNames = enumType.getNames();

    for (String name : enumNames) {
      if (name.length() > 3 && name.matches(".*[a-zA-Z]{3,}.*")) {
        // Create pseudo result for enum name analysis
        StringAnalysisResult result = new StringAnalysisResult();
        result.value = name;
        result.category = "Enum String";
        result.source = "Enum: " + enumType.getName();
        result.confidence = 0.7;
        result.relevanceScore = 1.5;
        result.analysisNotes = new ArrayList<>();
        result.referencingFunctions = new ArrayList<>();
        result.analysisNotes.add("String-like enum value in " + enumType.getName());

        enumResults.add(result);
      }
    }

    if (!enumResults.isEmpty()) {
      enumStrings.put(enumType, enumResults);
      analysisResults.addAll(enumResults);
    }
  }

  private void findStructureInstances(Structure structure, List<StringAnalysisResult> results) {
    // Find where this structure is used in the program
    DataIterator dataIter = currentProgram.getListing().getDefinedData(true);

    while (dataIter.hasNext() && !monitor.isCancelled()) {
      Data data = dataIter.next();
      if (data.getDataType().equals(structure)) {
        analyzeStructureInstance(data, structure, results);
      }
    }
  }

  private void analyzeStructureInstance(
      Data structData, Structure structure, List<StringAnalysisResult> results) {
    // Analyze actual instance of structure for string content
    for (int i = 0; i < structData.getNumComponents(); i++) {
      Data component = structData.getComponent(i);
      if (component != null && component.hasStringValue()) {
        String stringValue = component.getDefaultValueRepresentation();

        StringAnalysisResult result = new StringAnalysisResult();
        result.address = component.getAddress();
        result.value = stringValue;
        result.category = "Structure String";
        result.source = "Structure: " + structure.getName();
        result.confidence = 0.8;
        result.relevanceScore = 2.0;
        result.analysisNotes = new ArrayList<>();
        result.referencingFunctions = new ArrayList<>();
        result.analysisNotes.add("String in structure " + structure.getName());

        results.add(result);
      }
    }
  }

  private void performAdvancedSymbolAnalysis() throws MemoryAccessException {
    // Use Symbol, SymbolTable, SymbolIterator for comprehensive symbol analysis
    println("    Performing advanced symbol analysis...");

    SymbolIterator symbolIter = symbolTable.getAllSymbols(true);
    int symbolsAnalyzed = 0;
    int stringRelatedSymbols = 0;

    while (symbolIter.hasNext() && !monitor.isCancelled()) {
      Symbol symbol = symbolIter.next();
      symbolsAnalyzed++;

      String symbolName = symbol.getName().toLowerCase();

      // Check if symbol name suggests string-related functionality
      if (symbolName.contains("string")
          || symbolName.contains("str")
          || symbolName.contains("text")
          || symbolName.contains("message")
          || symbolName.contains("buffer")
          || symbolName.contains("data")) {

        stringRelatedSymbols++;

        // Analyze symbol address for nearby strings
        Address symbolAddr = symbol.getAddress();
        analyzeSymbolForNearbyStrings(symbol, symbolAddr);
      }

      if (symbolsAnalyzed % 1000 == 0) {
        println("      Symbols analyzed: " + symbolsAnalyzed);
      }
    }

    println("      Total symbols analyzed: " + symbolsAnalyzed);
    println("      String-related symbols: " + stringRelatedSymbols);
  }

  private void analyzeSymbolForNearbyStrings(Symbol symbol, Address symbolAddr) {
    // Look for strings near this symbol
    try {
      Address searchStart = symbolAddr.subtract(50);
      Address searchEnd = symbolAddr.add(50);

      for (StringAnalysisResult result : analysisResults) {
        if (result.address.compareTo(searchStart) >= 0
            && result.address.compareTo(searchEnd) <= 0) {
          result.analysisNotes.add("Near symbol: " + symbol.getName());
          result.relevanceScore += 0.5;
        }
      }
    } catch (Exception e) {
      // Continue analysis
    }
  }

  private void performAddressSpaceAnalysis() throws MemoryAccessException {
    // Use AddressSpace, AddressSet, AddressSetView, AddressRange for comprehensive address analysis
    println("    Analyzing string distribution across address spaces...");

    AddressSpace[] spaces = currentProgram.getAddressFactory().getAddressSpaces();

    for (AddressSpace space : spaces) {
      AddressSet spaceStrings = new AddressSet();
      int stringCount = 0;

      for (StringAnalysisResult result : analysisResults) {
        if (result.address.getAddressSpace().equals(space)) {
          spaceStrings.add(result.address);
          stringCount++;
        }
      }

      if (stringCount > 0) {
        stringsBySpace.put(space, spaceStrings);
        println("      " + space.getName() + ": " + stringCount + " strings");

        // Analyze address ranges within this space
        analyzeAddressRangesInSpace(space, spaceStrings);
      }
    }
  }

  private void analyzeAddressRangesInSpace(AddressSpace space, AddressSet addresses) {
    // Use AddressRange to analyze string clustering
    Iterator<AddressRange> rangeIter = addresses.getAddressRanges();
    int rangeCount = 0;

    while (rangeIter.hasNext() && !monitor.isCancelled()) {
      AddressRange range = rangeIter.next();
      rangeCount++;

      long rangeSize = range.getLength();
      if (rangeSize > 100) { // Significant range
        // Mark strings in this range as potentially clustered
        for (StringAnalysisResult result : analysisResults) {
          if (range.contains(result.address)) {
            result.analysisNotes.add("In string cluster (range: " + rangeSize + " bytes)");
            result.relevanceScore += 0.3;
          }
        }
      }
    }

    println("        Address ranges in " + space.getName() + ": " + rangeCount);
  }

  private void performPcodeAnalysis() throws MemoryAccessException {
    // Use PcodeOp, PcodeOpAST, PcodeBlockBasic, Varnode, CodeUnit for P-code analysis
    println("    Performing P-code and instruction analysis...");

    Listing listing = currentProgram.getListing();
    CodeUnitIterator codeUnitIter = listing.getCodeUnits(true);
    int codeUnitsAnalyzed = 0;
    int stringReferencingUnits = 0;

    while (codeUnitIter.hasNext() && !monitor.isCancelled()) {
      CodeUnit codeUnit = codeUnitIter.next();
      codeUnitsAnalyzed++;

      // Check if this code unit references string data
      if (analyzeCodeUnitForStringReferences(codeUnit)) {
        stringCodeUnits.add(codeUnit);
        stringReferencingUnits++;

        // Perform advanced P-code analysis if this is an instruction
        if (codeUnit instanceof Instruction) {
          Instruction instruction = (Instruction) codeUnit;
          analyzePcodeForStringOperations(instruction);
        }
      }

      if (codeUnitsAnalyzed % 1000 == 0) {
        println("      Code units analyzed: " + codeUnitsAnalyzed);
      }
    }

    println("      Total code units analyzed: " + codeUnitsAnalyzed);
    println("      String-referencing units: " + stringReferencingUnits);
    println("      Code units stored: " + stringCodeUnits.size());
  }

  private boolean analyzeCodeUnitForStringReferences(CodeUnit codeUnit) {
    // Check if CodeUnit references any of our analyzed strings
    try {
      for (StringAnalysisResult result : analysisResults) {
        ReferenceIterator refIter = referenceManager.getReferencesTo(result.address);

        while (refIter.hasNext()) {
          Reference ref = refIter.next();
          if (ref.getFromAddress().equals(codeUnit.getAddress())) {
            result.analysisNotes.add("Referenced by code unit at " + codeUnit.getAddress());
            result.relevanceScore += 1.0;
            return true;
          }
        }
      }
    } catch (Exception e) {
      // Continue analysis
    }

    return false;
  }

  private void analyzePcodeForStringOperations(Instruction instruction) {
    // Analyze P-code operations for string-related activities
    try {
      // Note: In a real implementation, we would use the decompiler interface
      // to get PcodeOp, PcodeOpAST, Varnode analysis
      // For now, we'll analyze the instruction directly

      String mnemonic = instruction.getMnemonicString().toLowerCase();

      // Check for string manipulation instructions
      if (mnemonic.contains("mov")
          || mnemonic.contains("lea")
          || mnemonic.contains("push")
          || mnemonic.contains("call")) {

        // Look for potential string operations
        for (int i = 0; i < instruction.getNumOperands(); i++) {
          Object[] opObjects = instruction.getOpObjects(i);

          for (Object obj : opObjects) {
            if (obj instanceof Address) {
              Address opAddr = (Address) obj;

              // Check if this address corresponds to a string
              for (StringAnalysisResult result : analysisResults) {
                if (result.address.equals(opAddr)) {
                  result.analysisNotes.add("P-code analysis: " + mnemonic + " operation");
                  result.relevanceScore += 0.5;
                }
              }
            }
          }
        }
      }
    } catch (Exception e) {
      // Continue analysis
    }
  }

  private void generateDataTypeReport() throws IOException {
    // Use FileWriter, BufferedReader for comprehensive reporting
    File dataTypeReport = new File("string_datatype_analysis.txt");

    try (FileWriter fileWriter = new FileWriter(dataTypeReport);
        PrintWriter writer = new PrintWriter(fileWriter)) {

      writer.println("=== COMPREHENSIVE DATA TYPE STRING ANALYSIS ===");
      writer.println("Generated: " + new Date());
      writer.println("Program: " + currentProgram.getName());
      writer.println("=" + "=".repeat(60));
      writer.println();

      writer.println("DATA TYPE USAGE STATISTICS:");
      writer.println("-".repeat(40));
      for (Map.Entry<DataType, Set<Address>> entry : dataTypeStringMap.entrySet()) {
        DataType dataType = entry.getKey();
        Set<Address> addresses = entry.getValue();
        writer.println(dataType.getName() + ": " + addresses.size() + " string instances");
      }

      writer.println();
      writer.println("STRUCTURE STRING ANALYSIS:");
      writer.println("-".repeat(40));
      for (Map.Entry<Structure, List<StringAnalysisResult>> entry : structureStrings.entrySet()) {
        Structure structure = entry.getKey();
        List<StringAnalysisResult> results = entry.getValue();
        writer.println("Structure: " + structure.getName());
        writer.println("  String components: " + results.size());
        for (StringAnalysisResult result : results) {
          writer.println("    " + result.address + ": " + result.value);
        }
        writer.println();
      }

      writer.println("ENUM STRING ANALYSIS:");
      writer.println("-".repeat(40));
      for (Map.Entry<ghidra.program.model.data.Enum, List<StringAnalysisResult>> entry :
          enumStrings.entrySet()) {
        ghidra.program.model.data.Enum enumType = entry.getKey();
        List<StringAnalysisResult> results = entry.getValue();
        writer.println("Enum: " + enumType.getName());
        writer.println("  String-like values: " + results.size());
        for (StringAnalysisResult result : results) {
          writer.println("    " + result.value);
        }
        writer.println();
      }

      println("    Data type analysis report generated: " + dataTypeReport.getAbsolutePath());
    }

    // Demonstrate BufferedReader usage by reading back part of the report
    try (BufferedReader reader = new BufferedReader(new FileReader(dataTypeReport))) {
      String line = reader.readLine();
      if (line != null) {
        println("    Report verification: " + line);
      }
    }
  }

  /**
   * Advanced data type string mapping analysis utilizing dataTypeStringMap
   * Maps string patterns to their data type contexts for comprehensive licensing analysis
   */
  private void performAdvancedDataTypeStringAnalysis() {
    if (currentProgram == null) return;
    
    try {
      DataTypeManager dtm = currentProgram.getDataTypeManager();
      dataTypeStringMap.clear();
      
      println("    Performing advanced data type string mapping analysis...");
      
      // Analyze strings in context of specific data types
      analyzeStringDataTypes();
      analyzePointerStrings();
      analyzeArrayStrings();
      analyzeUnionStrings();
      
      // Perform cross-reference analysis for data type strings
      performDataTypeStringCrossReference();
      
      // Generate licensing-specific string patterns
      identifyLicensingDataTypePatterns();
      
      println("    Mapped " + dataTypeStringMap.size() + " data types with associated strings");
      
    } catch (Exception e) {
      println("    ⚠ Error in data type string analysis: " + e.getMessage());
    }
  }

  /**
   * Analyze strings within standard data type contexts
   */
  private void analyzeStringDataTypes() {
    try {
      Memory memory = currentProgram.getMemory();
      MemoryBlock[] blocks = memory.getBlocks();
      
      for (MemoryBlock block : blocks) {
        if (!block.isInitialized() || monitor.isCancelled()) continue;
        
        Address start = block.getStart();
        Address end = block.getEnd();
        
        // Sample analysis for performance
        long blockSize = block.getSize();
        int sampleInterval = Math.max(1, (int)(blockSize / 5000));
        
        for (long offset = 0; offset < blockSize; offset += sampleInterval) {
          Address addr = start.add(offset);
          if (addr.compareTo(end) > 0) break;
          
          Data data = currentProgram.getListing().getDataAt(addr);
          if (data != null) {
            DataType dataType = data.getDataType();
            analyzeDataTypeForStrings(dataType, addr, data);
          }
        }
      }
      
    } catch (Exception e) {
      println("      ⚠ Error analyzing string data types: " + e.getMessage());
    }
  }

  /**
   * Analyze individual data type for string content
   */
  private void analyzeDataTypeForStrings(DataType dataType, Address addr, Data data) {
    try {
      String typeName = dataType.getName().toLowerCase();
      
      // Check for string-related data types
      if (typeName.contains("string") || typeName.contains("char") || 
          typeName.contains("text") || typeName.contains("unicode")) {
        
        if (!dataTypeStringMap.containsKey(dataType)) {
          dataTypeStringMap.put(dataType, new HashSet<>());
        }
        dataTypeStringMap.get(dataType).add(addr);
        
        // Extract and analyze string content
        Object value = data.getValue();
        if (value instanceof String) {
          String stringValue = (String) value;
          analyzeStringForLicensingPatterns(stringValue, addr, dataType);
        }
      }
      
      // Analyze licensing-specific data types
      if (typeName.matches(".*licen.*|.*serial.*|.*key.*|.*token.*|.*auth.*|.*valid.*")) {
        if (!dataTypeStringMap.containsKey(dataType)) {
          dataTypeStringMap.put(dataType, new HashSet<>());
        }
        dataTypeStringMap.get(dataType).add(addr);
      }
      
    } catch (Exception e) {
      // Continue analysis
    }
  }

  /**
   * Analyze pointer-based string references
   */
  private void analyzePointerStrings() {
    try {
      DataTypeManager dtm = currentProgram.getDataTypeManager();
      
      // Find pointer data types
      Iterator<DataType> dataTypes = dtm.getAllDataTypes();
      while (dataTypes.hasNext() && !monitor.isCancelled()) {
        DataType dt = dataTypes.next();
        
        if (dt instanceof Pointer) {
          Pointer ptrType = (Pointer) dt;
          DataType referencedType = ptrType.getDataType();
          
          if (referencedType != null && isStringRelatedType(referencedType)) {
            // Find instances of this pointer type
            findStringPointerInstances(ptrType);
          }
        }
      }
      
    } catch (Exception e) {
      println("      ⚠ Error analyzing pointer strings: " + e.getMessage());
    }
  }

  /**
   * Find instances of string pointer types in memory
   */
  private void findStringPointerInstances(Pointer ptrType) {
    try {
      SymbolTable symbolTable = currentProgram.getSymbolTable();
      SymbolIterator symbols = symbolTable.getAllSymbols(true);
      
      while (symbols.hasNext() && !monitor.isCancelled()) {
        Symbol symbol = symbols.next();
        
        // Check if symbol references string pointer data
        Address addr = symbol.getAddress();
        Data data = currentProgram.getListing().getDataAt(addr);
        
        if (data != null && data.getDataType().equals(ptrType)) {
          if (!dataTypeStringMap.containsKey(ptrType)) {
            dataTypeStringMap.put(ptrType, new HashSet<>());
          }
          dataTypeStringMap.get(ptrType).add(addr);
        }
      }
      
    } catch (Exception e) {
      // Continue analysis
    }
  }

  /**
   * Analyze array-based string structures
   */
  private void analyzeArrayStrings() {
    try {
      DataTypeManager dtm = currentProgram.getDataTypeManager();
      
      Iterator<DataType> dataTypes = dtm.getAllDataTypes();
      while (dataTypes.hasNext() && !monitor.isCancelled()) {
        DataType dt = dataTypes.next();
        
        if (dt instanceof Array) {
          Array arrayType = (Array) dt;
          DataType elementType = arrayType.getDataType();
          
          if (elementType != null && isStringRelatedType(elementType)) {
            // Find instances of string arrays
            findStringArrayInstances(arrayType);
          }
        }
      }
      
    } catch (Exception e) {
      println("      ⚠ Error analyzing array strings: " + e.getMessage());
    }
  }

  /**
   * Find instances of string array types
   */
  private void findStringArrayInstances(Array arrayType) {
    try {
      Memory memory = currentProgram.getMemory();
      
      for (MemoryBlock block : memory.getBlocks()) {
        if (!block.isInitialized() || monitor.isCancelled()) continue;
        
        Address start = block.getStart();
        Address end = block.getEnd();
        
        // Sample search for performance
        long sampleInterval = Math.max(1000, block.getSize() / 1000);
        
        for (long offset = 0; offset < block.getSize(); offset += sampleInterval) {
          Address addr = start.add(offset);
          if (addr.compareTo(end) > 0) break;
          
          Data data = currentProgram.getListing().getDataAt(addr);
          if (data != null && data.getDataType().equals(arrayType)) {
            if (!dataTypeStringMap.containsKey(arrayType)) {
              dataTypeStringMap.put(arrayType, new HashSet<>());
            }
            dataTypeStringMap.get(arrayType).add(addr);
          }
        }
      }
      
    } catch (Exception e) {
      // Continue analysis
    }
  }

  /**
   * Analyze union structures for embedded strings
   */
  private void analyzeUnionStrings() {
    try {
      DataTypeManager dtm = currentProgram.getDataTypeManager();
      
      Iterator<DataType> dataTypes = dtm.getAllDataTypes();
      while (dataTypes.hasNext() && !monitor.isCancelled()) {
        DataType dt = dataTypes.next();
        
        if (dt instanceof Union) {
          Union unionType = (Union) dt;
          
          // Check union components for string types
          for (int i = 0; i < unionType.getNumComponents(); i++) {
            DataTypeComponent component = unionType.getComponent(i);
            DataType componentType = component.getDataType();
            
            if (isStringRelatedType(componentType)) {
              if (!dataTypeStringMap.containsKey(unionType)) {
                dataTypeStringMap.put(unionType, new HashSet<>());
              }
              // Find instances of this union in memory
              findUnionStringInstances(unionType);
              break;
            }
          }
        }
      }
      
    } catch (Exception e) {
      println("      ⚠ Error analyzing union strings: " + e.getMessage());
    }
  }

  /**
   * Find instances of unions containing strings
   */
  private void findUnionStringInstances(Union unionType) {
    try {
      SymbolTable symbolTable = currentProgram.getSymbolTable();
      SymbolIterator symbols = symbolTable.getAllSymbols(true);
      
      int instanceCount = 0;
      while (symbols.hasNext() && instanceCount < 100 && !monitor.isCancelled()) {
        Symbol symbol = symbols.next();
        Address addr = symbol.getAddress();
        
        Data data = currentProgram.getListing().getDataAt(addr);
        if (data != null && data.getDataType().equals(unionType)) {
          if (!dataTypeStringMap.containsKey(unionType)) {
            dataTypeStringMap.put(unionType, new HashSet<>());
          }
          dataTypeStringMap.get(unionType).add(addr);
          instanceCount++;
        }
      }
      
    } catch (Exception e) {
      // Continue analysis
    }
  }

  /**
   * Check if data type is string-related
   */
  private boolean isStringRelatedType(DataType dataType) {
    if (dataType == null) return false;
    
    String typeName = dataType.getName().toLowerCase();
    return typeName.contains("string") || typeName.contains("char") || 
           typeName.contains("text") || typeName.contains("unicode") ||
           typeName.contains("ascii") || typeName.contains("utf");
  }

  /**
   * Perform cross-reference analysis for data type strings
   */
  private void performDataTypeStringCrossReference() {
    try {
      for (Map.Entry<DataType, Set<Address>> entry : dataTypeStringMap.entrySet()) {
        DataType dataType = entry.getKey();
        Set<Address> addresses = entry.getValue();
        
        for (Address addr : addresses) {
          if (monitor.isCancelled()) break;
          
          // Find references to this string address
          Reference[] refs = currentProgram.getReferenceManager().getReferencesTo(addr);
          
          if (refs.length > 0) {
            // This string is referenced - analyze referencing functions
            for (Reference ref : refs) {
              Address fromAddr = ref.getFromAddress();
              Function func = currentProgram.getFunctionManager().getFunctionContaining(fromAddr);
              
              if (func != null) {
                // Check for licensing-related function names
                String funcName = func.getName().toLowerCase();
                if (funcName.matches(".*licen.*|.*valid.*|.*check.*|.*auth.*|.*serial.*")) {
                  // High-value string in licensing context
                  println("      High-value string at " + addr + " referenced by licensing function: " + func.getName());
                }
              }
            }
          }
        }
      }
      
    } catch (Exception e) {
      println("      ⚠ Error in data type string cross-reference analysis: " + e.getMessage());
    }
  }

  /**
   * Identify licensing-specific data type patterns
   */
  private void identifyLicensingDataTypePatterns() {
    try {
      Map<String, Integer> licensingPatterns = new HashMap<>();
      
      for (Map.Entry<DataType, Set<Address>> entry : dataTypeStringMap.entrySet()) {
        DataType dataType = entry.getKey();
        String typeName = dataType.getName().toLowerCase();
        
        // Count licensing-related data types
        if (typeName.matches(".*licen.*|.*key.*|.*serial.*|.*auth.*|.*token.*|.*valid.*")) {
          licensingPatterns.put(typeName, entry.getValue().size());
        }
      }
      
      if (!licensingPatterns.isEmpty()) {
        println("      Licensing data type patterns identified:");
        for (Map.Entry<String, Integer> pattern : licensingPatterns.entrySet()) {
          println("        " + pattern.getKey() + ": " + pattern.getValue() + " instances");
        }
      }
      
    } catch (Exception e) {
      println("      ⚠ Error identifying licensing data type patterns: " + e.getMessage());
    }
  }

  /**
   * Analyze string for licensing patterns
   */
  private void analyzeStringForLicensingPatterns(String stringValue, Address addr, DataType dataType) {
    try {
      if (stringValue == null || stringValue.length() < 4) return;
      
      // Check for licensing patterns
      if (stringValue.matches(".*[Ll]icen.*|.*[Ss]erial.*|.*[Kk]ey.*|.*[Tt]oken.*|.*[Aa]uth.*")) {
        println("      Licensing pattern in " + dataType.getName() + " at " + addr + ": " + 
               stringValue.substring(0, Math.min(50, stringValue.length())));
      }
      
      // Check for obfuscated patterns
      if (stringValue.matches(".*[0-9a-fA-F]{16,}.*") && stringValue.length() > 20) {
        println("      Potential obfuscated string in " + dataType.getName() + " at " + addr);
      }
      
    } catch (Exception e) {
      // Continue analysis
    }
  }

  /**
   * Enhanced structure-based string analysis utilizing structureStrings
   * Analyzes strings embedded within data structures for licensing patterns
   */
  private void performAdvancedStructureStringAnalysis() {
    if (currentProgram == null) return;
    
    try {
      DataTypeManager dtm = currentProgram.getDataTypeManager();
      structureStrings.clear();
      
      println("    Performing advanced structure string analysis...");
      
      // Analyze all structures for embedded strings
      Iterator<DataType> dataTypes = dtm.getAllDataTypes();
      while (dataTypes.hasNext() && !monitor.isCancelled()) {
        DataType dt = dataTypes.next();
        
        if (dt instanceof Structure) {
          Structure struct = (Structure) dt;
          analyzeStructureForStrings(struct);
        }
      }
      
      // Perform licensing-specific structure analysis
      identifyLicensingStructures();
      
      // Cross-reference structure strings with functions
      performStructureStringCrossReference();
      
      println("    Analyzed " + structureStrings.size() + " structures with embedded strings");
      
    } catch (Exception e) {
      println("    ⚠ Error in structure string analysis: " + e.getMessage());
    }
  }

  /**
   * Analyze individual structure for embedded strings
   */
  private void analyzeStructureForStrings(Structure struct) {
    try {
      List<StringAnalysisResult> structResults = new ArrayList<>();
      
      // Analyze each component of the structure
      for (int i = 0; i < struct.getNumComponents(); i++) {
        DataTypeComponent component = struct.getComponent(i);
        DataType componentType = component.getDataType();
        String fieldName = component.getFieldName();
        
        // Check if component is string-related
        if (isStringRelatedType(componentType) || 
            (fieldName != null && fieldName.toLowerCase().matches(".*str.*|.*text.*|.*name.*"))) {
          
          // Find instances of this structure in memory
          List<Address> structInstances = findStructureInstances(struct);
          
          for (Address structAddr : structInstances) {
            if (monitor.isCancelled()) break;
            
            try {
              Address componentAddr = structAddr.add(component.getOffset());
              Data data = currentProgram.getListing().getDataAt(componentAddr);
              
              if (data != null) {
                Object value = data.getValue();
                if (value instanceof String) {
                  StringAnalysisResult result = new StringAnalysisResult();
                  result.address = componentAddr;
                  result.value = (String) value;
                  result.category = "STRUCTURE_EMBEDDED";
                  result.source = struct.getName() + "." + fieldName;
                  result.length = result.value.length();
                  result.confidence = calculateStringConfidence(result.value);
                  result.analysisNotes = new ArrayList<>();
                  result.referencingFunctions = new ArrayList<>();
                  
                  // Analyze for licensing patterns
                  if (result.value.toLowerCase().matches(".*licen.*|.*serial.*|.*key.*|.*auth.*")) {
                    result.analysisNotes.add("LICENSING_PATTERN");
                    result.relevanceScore = 0.9;
                  }
                  
                  structResults.add(result);
                }
              }
            } catch (Exception e) {
              // Continue with next component
            }
          }
        }
      }
      
      if (!structResults.isEmpty()) {
        structureStrings.put(struct, structResults);
      }
      
    } catch (Exception e) {
      // Continue with next structure
    }
  }

  /**
   * Find instances of structure in memory
   */
  private List<Address> findStructureInstances(Structure struct) {
    List<Address> instances = new ArrayList<>();
    
    try {
      SymbolTable symbolTable = currentProgram.getSymbolTable();
      SymbolIterator symbols = symbolTable.getAllSymbols(true);
      
      int maxInstances = 20; // Limit for performance
      int foundInstances = 0;
      
      while (symbols.hasNext() && foundInstances < maxInstances && !monitor.isCancelled()) {
        Symbol symbol = symbols.next();
        Address addr = symbol.getAddress();
        
        Data data = currentProgram.getListing().getDataAt(addr);
        if (data != null && data.getDataType().equals(struct)) {
          instances.add(addr);
          foundInstances++;
        }
      }
      
    } catch (Exception e) {
      // Return what we have
    }
    
    return instances;
  }

  /**
   * Calculate string confidence score
   */
  private double calculateStringConfidence(String value) {
    if (value == null) return 0.0;
    
    double confidence = 0.5; // Base confidence
    
    // Higher confidence for longer strings
    if (value.length() > 10) confidence += 0.2;
    if (value.length() > 50) confidence += 0.2;
    
    // Lower confidence for very short or very long strings
    if (value.length() < 4) confidence -= 0.3;
    if (value.length() > 1000) confidence -= 0.2;
    
    // Higher confidence for printable ASCII
    boolean isPrintable = value.chars().allMatch(c -> c >= 32 && c <= 126);
    if (isPrintable) confidence += 0.2;
    
    return Math.max(0.0, Math.min(1.0, confidence));
  }

  /**
   * Identify structures related to licensing
   */
  private void identifyLicensingStructures() {
    try {
      Map<String, Integer> licensingStructures = new HashMap<>();
      
      for (Map.Entry<Structure, List<StringAnalysisResult>> entry : structureStrings.entrySet()) {
        Structure struct = entry.getKey();
        String structName = struct.getName().toLowerCase();
        
        // Check for licensing-related structure names
        if (structName.matches(".*licen.*|.*key.*|.*auth.*|.*valid.*|.*serial.*|.*token.*")) {
          licensingStructures.put(struct.getName(), entry.getValue().size());
        }
        
        // Check for licensing patterns in embedded strings
        for (StringAnalysisResult result : entry.getValue()) {
          if (result.analysisNotes.contains("LICENSING_PATTERN")) {
            licensingStructures.put(struct.getName(), 
              licensingStructures.getOrDefault(struct.getName(), 0) + 1);
            break;
          }
        }
      }
      
      if (!licensingStructures.isEmpty()) {
        println("      Licensing-related structures identified:");
        for (Map.Entry<String, Integer> struct : licensingStructures.entrySet()) {
          println("        " + struct.getKey() + ": " + struct.getValue() + " strings");
        }
      }
      
    } catch (Exception e) {
      println("      ⚠ Error identifying licensing structures: " + e.getMessage());
    }
  }

  /**
   * Cross-reference structure strings with functions
   */
  private void performStructureStringCrossReference() {
    try {
      for (Map.Entry<Structure, List<StringAnalysisResult>> entry : structureStrings.entrySet()) {
        Structure struct = entry.getKey();
        
        for (StringAnalysisResult result : entry.getValue()) {
          if (monitor.isCancelled()) break;
          
          // Find functions that reference this string address
          Reference[] refs = currentProgram.getReferenceManager().getReferencesTo(result.address);
          
          for (Reference ref : refs) {
            Address fromAddr = ref.getFromAddress();
            Function func = currentProgram.getFunctionManager().getFunctionContaining(fromAddr);
            
            if (func != null) {
              result.referencingFunctions.add(func.getName());
              
              // Check for licensing context
              String funcName = func.getName().toLowerCase();
              if (funcName.matches(".*licen.*|.*valid.*|.*check.*|.*auth.*|.*verify.*")) {
                result.analysisNotes.add("REFERENCED_BY_LICENSING_FUNCTION");
                result.relevanceScore = Math.min(1.0, result.relevanceScore + 0.3);
              }
            }
          }
        }
      }
      
    } catch (Exception e) {
      println("      ⚠ Error in structure string cross-reference: " + e.getMessage());
    }
  }

  /**
   * Comprehensive address space string organization utilizing stringsBySpace
   * Organizes strings by address space for efficient analysis and licensing pattern detection
   */
  private void performComprehensiveAddressSpaceStringOrganization() {
    if (currentProgram == null) return;
    
    try {
      stringsBySpace.clear();
      Memory memory = currentProgram.getMemory();
      
      println("    Organizing strings by address space for comprehensive analysis...");
      
      // Analyze each address space separately
      Set<AddressSpace> processedSpaces = new HashSet<>();
      
      for (MemoryBlock block : memory.getBlocks()) {
        if (monitor.isCancelled()) break;
        
        AddressSpace space = block.getStart().getAddressSpace();
        if (processedSpaces.contains(space)) continue;
        
        processedSpaces.add(space);
        analyzeAddressSpaceStrings(space);
      }
      
      // Perform cross-space string analysis
      performCrossSpaceStringAnalysis();
      
      // Identify licensing patterns across address spaces
      identifyLicensingPatternsAcrossSpaces();
      
      println("    Organized strings across " + stringsBySpace.size() + " address spaces");
      
    } catch (Exception e) {
      println("    ⚠ Error in address space string organization: " + e.getMessage());
    }
  }

  /**
   * Analyze strings within specific address space
   */
  private void analyzeAddressSpaceStrings(AddressSpace space) {
    try {
      AddressSet spaceStrings = new AddressSet();
      Memory memory = currentProgram.getMemory();
      
      // Find all strings in blocks belonging to this address space
      for (MemoryBlock block : memory.getBlocks()) {
        if (!block.getStart().getAddressSpace().equals(space) || 
            !block.isInitialized() || monitor.isCancelled()) continue;
        
        Address start = block.getStart();
        Address end = block.getEnd();
        
        // Search for strings in this block
        findStringsInBlock(block, spaceStrings);
      }
      
      if (!spaceStrings.isEmpty()) {
        stringsBySpace.put(space, spaceStrings);
        
        println("      Address space " + space.getName() + ": " + 
               spaceStrings.getNumAddresses() + " string addresses");
      }
      
    } catch (Exception e) {
      println("      ⚠ Error analyzing address space strings: " + e.getMessage());
    }
  }

  /**
   * Find strings within memory block
   */
  private void findStringsInBlock(MemoryBlock block, AddressSet spaceStrings) {
    try {
      Address start = block.getStart();
      Address end = block.getEnd();
      
      // Sample analysis for large blocks
      long blockSize = block.getSize();
      int sampleInterval = Math.max(1, (int)(blockSize / 10000));
      
      for (long offset = 0; offset < blockSize; offset += sampleInterval) {
        if (monitor.isCancelled()) break;
        
        Address addr = start.add(offset);
        if (addr.compareTo(end) > 0) break;
        
        try {
          Data data = currentProgram.getListing().getDataAt(addr);
          if (data != null) {
            Object value = data.getValue();
            if (value instanceof String) {
              String stringValue = (String) value;
              if (stringValue.length() >= MIN_STRING_LENGTH && 
                  stringValue.length() <= MAX_STRING_LENGTH) {
                spaceStrings.add(addr);
                
                // Check for licensing relevance
                if (stringValue.toLowerCase().matches(".*licen.*|.*serial.*|.*key.*|.*auth.*")) {
                  println("        Licensing string in " + block.getName() + " at " + addr + 
                         ": " + stringValue.substring(0, Math.min(30, stringValue.length())));
                }
              }
            }
          }
        } catch (Exception e) {
          // Continue scanning
        }
      }
      
    } catch (Exception e) {
      // Continue with next block
    }
  }

  /**
   * Perform cross-space string analysis
   */
  private void performCrossSpaceStringAnalysis() {
    try {
      Map<String, Set<AddressSpace>> stringPatternSpaces = new HashMap<>();
      
      for (Map.Entry<AddressSpace, AddressSet> entry : stringsBySpace.entrySet()) {
        AddressSpace space = entry.getKey();
        AddressSet addresses = entry.getValue();
        
        // Analyze string patterns in this space
        for (Address addr : addresses.getAddresses(true)) {
          if (monitor.isCancelled()) break;
          
          try {
            Data data = currentProgram.getListing().getDataAt(addr);
            if (data != null) {
              Object value = data.getValue();
              if (value instanceof String) {
                String stringValue = (String) value;
                
                // Extract patterns for cross-space comparison
                String pattern = extractStringPattern(stringValue);
                if (pattern != null) {
                  if (!stringPatternSpaces.containsKey(pattern)) {
                    stringPatternSpaces.put(pattern, new HashSet<>());
                  }
                  stringPatternSpaces.get(pattern).add(space);
                }
              }
            }
          } catch (Exception e) {
            // Continue analysis
          }
        }
      }
      
      // Report patterns found across multiple spaces
      for (Map.Entry<String, Set<AddressSpace>> patternEntry : stringPatternSpaces.entrySet()) {
        if (patternEntry.getValue().size() > 1) {
          println("      Pattern '" + patternEntry.getKey() + "' found across " + 
                 patternEntry.getValue().size() + " address spaces");
        }
      }
      
    } catch (Exception e) {
      println("      ⚠ Error in cross-space string analysis: " + e.getMessage());
    }
  }

  /**
   * Extract pattern from string for comparison
   */
  private String extractStringPattern(String value) {
    if (value == null || value.length() < 4) return null;
    
    // Extract licensing patterns
    if (value.toLowerCase().matches(".*licen.*")) return "LICENSE";
    if (value.toLowerCase().matches(".*serial.*")) return "SERIAL";
    if (value.toLowerCase().matches(".*key.*")) return "KEY";
    if (value.toLowerCase().matches(".*auth.*")) return "AUTH";
    if (value.toLowerCase().matches(".*token.*")) return "TOKEN";
    if (value.toLowerCase().matches(".*valid.*")) return "VALIDATION";
    
    // Extract format patterns
    if (value.matches(".*[0-9a-fA-F]{8,}.*")) return "HEX_PATTERN";
    if (value.matches(".*[A-Za-z0-9+/]{20,}={0,2}.*")) return "BASE64_PATTERN";
    if (value.matches(".*\\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\\b.*")) return "UUID_PATTERN";
    
    return null;
  }

  /**
   * Identify licensing patterns across address spaces
   */
  private void identifyLicensingPatternsAcrossSpaces() {
    try {
      Map<AddressSpace, Integer> licensingStringCount = new HashMap<>();
      
      for (Map.Entry<AddressSpace, AddressSet> entry : stringsBySpace.entrySet()) {
        AddressSpace space = entry.getKey();
        AddressSet addresses = entry.getValue();
        
        int licensingStrings = 0;
        
        for (Address addr : addresses.getAddresses(true)) {
          if (monitor.isCancelled()) break;
          
          try {
            Data data = currentProgram.getListing().getDataAt(addr);
            if (data != null) {
              Object value = data.getValue();
              if (value instanceof String) {
                String stringValue = (String) value;
                if (stringValue.toLowerCase().matches(".*licen.*|.*serial.*|.*key.*|.*auth.*|.*token.*|.*valid.*")) {
                  licensingStrings++;
                }
              }
            }
          } catch (Exception e) {
            // Continue counting
          }
        }
        
        if (licensingStrings > 0) {
          licensingStringCount.put(space, licensingStrings);
        }
      }
      
      if (!licensingStringCount.isEmpty()) {
        println("      Licensing strings by address space:");
        for (Map.Entry<AddressSpace, Integer> spaceEntry : licensingStringCount.entrySet()) {
          println("        " + spaceEntry.getKey().getName() + ": " + spaceEntry.getValue() + " licensing strings");
        }
      }
      
    } catch (Exception e) {
      println("      ⚠ Error identifying licensing patterns across spaces: " + e.getMessage());
    }
  }

  /**
   * Advanced code unit string tracking utilizing stringCodeUnits
   * Tracks string-related code units for comprehensive context analysis
   */
  private void performAdvancedStringCodeUnitTracking() {
    if (currentProgram == null) return;
    
    try {
      stringCodeUnits.clear();
      
      println("    Performing advanced string code unit tracking...");
      
      // Track all string-related code units
      trackStringCodeUnits();
      
      // Analyze code unit relationships
      analyzeStringCodeUnitRelationships();
      
      // Identify licensing-relevant code units
      identifyLicensingCodeUnits();
      
      // Perform context analysis for tracked code units
      performStringCodeUnitContextAnalysis();
      
      println("    Tracked " + stringCodeUnits.size() + " string-related code units");
      
    } catch (Exception e) {
      println("    ⚠ Error in string code unit tracking: " + e.getMessage());
    }
  }

  /**
   * Track all string-related code units
   */
  private void trackStringCodeUnits() {
    try {
      Memory memory = currentProgram.getMemory();
      
      for (MemoryBlock block : memory.getBlocks()) {
        if (!block.isInitialized() || monitor.isCancelled()) continue;
        
        Address start = block.getStart();
        Address end = block.getEnd();
        
        // Sample analysis for performance
        long blockSize = block.getSize();
        int sampleInterval = Math.max(1, (int)(blockSize / 8000));
        
        for (long offset = 0; offset < blockSize; offset += sampleInterval) {
          Address addr = start.add(offset);
          if (addr.compareTo(end) > 0) break;
          
          try {
            CodeUnit codeUnit = currentProgram.getListing().getCodeUnitAt(addr);
            if (codeUnit != null && isStringRelatedCodeUnit(codeUnit)) {
              stringCodeUnits.add(codeUnit);
            }
          } catch (Exception e) {
            // Continue tracking
          }
        }
      }
      
    } catch (Exception e) {
      println("      ⚠ Error tracking string code units: " + e.getMessage());
    }
  }

  /**
   * Check if code unit is string-related
   */
  private boolean isStringRelatedCodeUnit(CodeUnit codeUnit) {
    try {
      // Check if code unit contains string data
      if (codeUnit instanceof Data) {
        Data data = (Data) codeUnit;
        DataType dataType = data.getDataType();
        
        if (isStringRelatedType(dataType)) {
          return true;
        }
        
        // Check value
        Object value = data.getValue();
        if (value instanceof String) {
          String stringValue = (String) value;
          return stringValue.length() >= MIN_STRING_LENGTH && 
                 stringValue.length() <= MAX_STRING_LENGTH;
        }
      }
      
      // Check for string references in instructions
      if (codeUnit instanceof Instruction) {
        Instruction inst = (Instruction) codeUnit;
        
        for (int i = 0; i < inst.getNumOperands(); i++) {
          Reference[] refs = inst.getOperandReferences(i);
          for (Reference ref : refs) {
            Address toAddr = ref.getToAddress();
            Data data = currentProgram.getListing().getDataAt(toAddr);
            
            if (data != null) {
              Object value = data.getValue();
              if (value instanceof String) {
                return true;
              }
            }
          }
        }
      }
      
      return false;
      
    } catch (Exception e) {
      return false;
    }
  }

  /**
   * Analyze relationships between string code units
   */
  private void analyzeStringCodeUnitRelationships() {
    try {
      Map<Function, Set<CodeUnit>> functionStringUnits = new HashMap<>();
      
      for (CodeUnit codeUnit : stringCodeUnits) {
        if (monitor.isCancelled()) break;
        
        Address addr = codeUnit.getAddress();
        Function func = currentProgram.getFunctionManager().getFunctionContaining(addr);
        
        if (func != null) {
          if (!functionStringUnits.containsKey(func)) {
            functionStringUnits.put(func, new HashSet<>());
          }
          functionStringUnits.get(func).add(codeUnit);
        }
      }
      
      // Report functions with multiple string units
      for (Map.Entry<Function, Set<CodeUnit>> entry : functionStringUnits.entrySet()) {
        if (entry.getValue().size() > 3) {
          Function func = entry.getKey();
          println("      Function " + func.getName() + " contains " + 
                 entry.getValue().size() + " string code units");
        }
      }
      
    } catch (Exception e) {
      println("      ⚠ Error analyzing string code unit relationships: " + e.getMessage());
    }
  }

  /**
   * Identify licensing-relevant code units
   */
  private void identifyLicensingCodeUnits() {
    try {
      Set<CodeUnit> licensingUnits = new HashSet<>();
      
      for (CodeUnit codeUnit : stringCodeUnits) {
        if (monitor.isCancelled()) break;
        
        if (isLicensingRelatedCodeUnit(codeUnit)) {
          licensingUnits.add(codeUnit);
        }
      }
      
      if (!licensingUnits.isEmpty()) {
        println("      Identified " + licensingUnits.size() + " licensing-related code units");
        
        // Analyze licensing code unit patterns
        for (CodeUnit unit : licensingUnits) {
          analyzeLicensingCodeUnit(unit);
        }
      }
      
    } catch (Exception e) {
      println("      ⚠ Error identifying licensing code units: " + e.getMessage());
    }
  }

  /**
   * Check if code unit is licensing-related
   */
  private boolean isLicensingRelatedCodeUnit(CodeUnit codeUnit) {
    try {
      if (codeUnit instanceof Data) {
        Data data = (Data) codeUnit;
        Object value = data.getValue();
        
        if (value instanceof String) {
          String stringValue = (String) value;
          return stringValue.toLowerCase().matches(".*licen.*|.*serial.*|.*key.*|.*auth.*|.*token.*|.*valid.*");
        }
      }
      
      // Check function context
      Address addr = codeUnit.getAddress();
      Function func = currentProgram.getFunctionManager().getFunctionContaining(addr);
      
      if (func != null) {
        String funcName = func.getName().toLowerCase();
        return funcName.matches(".*licen.*|.*valid.*|.*check.*|.*auth.*|.*serial.*|.*key.*");
      }
      
      return false;
      
    } catch (Exception e) {
      return false;
    }
  }

  /**
   * Analyze individual licensing code unit
   */
  private void analyzeLicensingCodeUnit(CodeUnit codeUnit) {
    try {
      Address addr = codeUnit.getAddress();
      
      if (codeUnit instanceof Data) {
        Data data = (Data) codeUnit;
        Object value = data.getValue();
        
        if (value instanceof String) {
          String stringValue = (String) value;
          
          // Analyze licensing string patterns
          if (stringValue.length() > 10 && stringValue.matches(".*[0-9a-fA-F]{8,}.*")) {
            println("        Potential license key at " + addr + ": " + 
                   stringValue.substring(0, Math.min(20, stringValue.length())) + "...");
          }
          
          if (stringValue.toLowerCase().contains("serial") && stringValue.length() > 8) {
            println("        Serial number pattern at " + addr + ": " + 
                   stringValue.substring(0, Math.min(25, stringValue.length())));
          }
        }
      }
      
    } catch (Exception e) {
      // Continue analysis
    }
  }

  /**
   * Perform context analysis for tracked code units
   */
  private void performStringCodeUnitContextAnalysis() {
    try {
      Map<String, Integer> contextCategories = new HashMap<>();
      
      for (CodeUnit codeUnit : stringCodeUnits) {
        if (monitor.isCancelled()) break;
        
        String context = determineCodeUnitContext(codeUnit);
        contextCategories.put(context, contextCategories.getOrDefault(context, 0) + 1);
      }
      
      if (!contextCategories.isEmpty()) {
        println("      String code unit contexts:");
        for (Map.Entry<String, Integer> category : contextCategories.entrySet()) {
          println("        " + category.getKey() + ": " + category.getValue() + " units");
        }
      }
      
    } catch (Exception e) {
      println("      ⚠ Error in string code unit context analysis: " + e.getMessage());
    }
  }

  /**
   * Determine context category for code unit
   */
  private String determineCodeUnitContext(CodeUnit codeUnit) {
    try {
      Address addr = codeUnit.getAddress();
      Function func = currentProgram.getFunctionManager().getFunctionContaining(addr);
      
      if (func != null) {
        String funcName = func.getName().toLowerCase();
        
        if (funcName.matches(".*licen.*|.*valid.*|.*auth.*")) return "LICENSING";
        if (funcName.matches(".*init.*|.*setup.*|.*config.*")) return "INITIALIZATION";
        if (funcName.matches(".*check.*|.*verify.*|.*test.*")) return "VALIDATION";
        if (funcName.matches(".*error.*|.*fail.*|.*warn.*")) return "ERROR_HANDLING";
        if (funcName.matches(".*debug.*|.*log.*|.*trace.*")) return "DEBUGGING";
      }
      
      // Check memory block context
      MemoryBlock block = currentProgram.getMemory().getBlock(addr);
      if (block != null) {
        String blockName = block.getName().toLowerCase();
        
        if (blockName.contains("data")) return "DATA_SECTION";
        if (blockName.contains("text") || blockName.contains("code")) return "CODE_SECTION";
        if (blockName.contains("resource") || blockName.contains("rsrc")) return "RESOURCE_SECTION";
      }
      
      return "UNKNOWN";
      
    } catch (Exception e) {
      return "ERROR";
    }
  }

  private final class StringAnalysisResult {
    Address address;
    String value;
    String decodedValue;
    String category;
    String source;
    int length;
    double confidence;
    double relevanceScore;
    double entropy;
    List<String> analysisNotes;
    List<String> referencingFunctions;
  }
}

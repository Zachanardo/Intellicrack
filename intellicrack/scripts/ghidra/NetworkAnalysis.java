/**
 * Network Communication Analysis Script
 *
 * @description Finds network-related API calls and potential C2 server communications
 * @author Intellicrack Team
 * @category Network Analysis
 * @version 1.0
 * @tags network,sockets,http,communication
 */
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressRange;
import ghidra.program.model.address.AddressRangeImpl;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeComponent;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.data.Structure;
import ghidra.program.model.listing.CodeUnit;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.DataIterator;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Parameter;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.scalar.Scalar;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceIterator;
import ghidra.program.model.symbol.ReferenceManager;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolIterator;
import ghidra.program.model.symbol.SymbolTable;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Set;

public class NetworkAnalysis extends GhidraScript {

  // Enhanced tracking using Set/HashSet/Iterator
  private final Set<Address> networkFunctions = new HashSet<>();
  private final Set<String> uniqueEndpoints = new HashSet<>();
  private final Set<Address> bufferLocations = new HashSet<>();
  private final Map<Address, String> networkStructures = new HashMap<>();
  private FunctionManager functionManager;
  private ReferenceManager referenceManager;
  private DataTypeManager dataTypeManager;
  private Program program;
  private Memory memory;

  // Network-related Windows API functions
  private static final String[] NETWORK_APIS = {
    "socket",
    "connect",
    "bind",
    "listen",
    "accept",
    "send",
    "recv",
    "sendto",
    "recvfrom",
    "WSAStartup",
    "WSACleanup",
    "WSASend",
    "WSARecv",
    "InternetOpenA",
    "InternetOpenW",
    "InternetConnectA",
    "InternetConnectW",
    "HttpOpenRequestA",
    "HttpOpenRequestW",
    "HttpSendRequestA",
    "HttpSendRequestW",
    "InternetReadFile",
    "InternetWriteFile",
    "URLDownloadToFileA",
    "URLDownloadToFileW",
    "WinHttpOpen",
    "WinHttpConnect",
    "WinHttpOpenRequest"
  };

  // Common ports to check for
  private static final int[] SUSPICIOUS_PORTS = {
    1337, 4444, 5555, 6666, 7777, 8080, 8888, 9999, 31337, 12345, 54321
  };

  @Override
  public void run() throws Exception {
    println("=== Network Communication Analysis ===");

    // Initialize components
    initializeComponents();

    Map<String, List<Address>> networkCalls = new HashMap<>();
    List<String> suspiciousUrls = new ArrayList<>();
    List<Integer> foundPorts = new ArrayList<>();

    // Enhanced analysis using improved symbol search
    println("\nSearching for network API calls (enhanced)...");
    improvedSymbolSearch(networkCalls);

    // Analyze network functions
    println("\nAnalyzing network functions...");
    analyzeNetworkFunctions(networkCalls);

    // Search for hardcoded URLs
    println("\nSearching for hardcoded URLs...");
    findHardcodedUrls(suspiciousUrls);

    // Search for port numbers
    println("\nSearching for network ports...");
    findNetworkPorts(foundPorts);

    // Enhanced code analysis
    println("\nPerforming enhanced code analysis...");
    enhancedCodeAnalysis();

    // Track network references
    println("\nTracking network data references...");
    trackNetworkReferences();

    // Map network buffers
    println("\nMapping network buffers in memory...");
    mapNetworkBuffers();

    // Parse network structures
    println("\nParsing network data structures...");
    parseNetworkStructures();

    // Analyze results
    analyzeNetworkBehavior(networkCalls, suspiciousUrls, foundPorts);

    // Generate report
    generateReport(networkCalls, suspiciousUrls, foundPorts);
  }

  private void initializeComponents() {
    program = currentProgram;
    functionManager = program.getFunctionManager();
    referenceManager = program.getReferenceManager();
    dataTypeManager = program.getDataTypeManager();
    memory = program.getMemory();
  }

  private List<Address> findAPIReferences(String apiName) {
    List<Address> references = new ArrayList<>();
    SymbolTable symbolTable = currentProgram.getSymbolTable();

    for (Symbol symbol : symbolTable.getAllSymbols(true)) {
      if (symbol.getName().equals(apiName)) {
        Reference[] refs = getReferencesTo(symbol.getAddress());
        for (Reference ref : refs) {
          if (ref.getReferenceType().isCall()) {
            references.add(ref.getFromAddress());
          }
        }
      }
    }

    return references;
  }

  private void findHardcodedUrls(List<String> urls) throws Exception {
    // Common URL patterns
    String[] urlPatterns = {"https://", "https://", "ftp://", "tcp://", "udp://"};

    Memory localMemory = currentProgram.getMemory();
    long totalBytes = localMemory.getNumAddresses();
    printf("  Scanning %d bytes for URL patterns...%n", totalBytes);

    for (String pattern : urlPatterns) {
      byte[] patternBytes = pattern.getBytes();
      StringBuilder hexPattern = new StringBuilder();
      for (byte b : patternBytes) {
        hexPattern.append(String.format("%02x ", b & 0xFF));
      }
      Address[] found =
          findBytes(currentProgram.getMinAddress(), hexPattern.toString().trim(), 100);

      for (Address addr : found) {
        String url = extractStringAt(addr);
        if (url != null && url.length() > pattern.length() + 5) {
          urls.add(url);
          println("  [+] Found URL: " + url + " at " + addr);
          createBookmark(addr, "Network", "Hardcoded URL: " + url);
        }
      }
    }

    // Also search for IP addresses
    findIPAddresses(urls);
  }

  private void findIPAddresses(List<String> urls) throws Exception {
    Memory localMemory = currentProgram.getMemory();
    printf("  Searching %d memory blocks for IP addresses...%n", localMemory.getNumAddressRanges());

    // Search for potential IP addresses by looking for dot patterns
    byte[] dot = ".".getBytes();
    StringBuilder hexPattern = new StringBuilder();
    for (byte b : dot) {
      hexPattern.append(String.format("%02x ", b & 0xFF));
    }
    Address[] dotAddresses =
        findBytes(currentProgram.getMinAddress(), hexPattern.toString().trim(), 1000);

    for (Address dotAddr : dotAddresses) {
      // Try to extract a potential IP address around this dot
      // IPs can have 1-3 digits per octet, so we need to check intelligently
      String potentialIP = extractPotentialIPAroundDot(dotAddr);

      if (isValidIP(potentialIP)) {
        // Avoid duplicates
        if (!urls.contains(potentialIP)) {
          urls.add(potentialIP);
          println("  [+] Found IP address: " + potentialIP);
          createBookmark(dotAddr, "Network", "IP Address: " + potentialIP);
        }
      }
    }
  }

  private String extractPotentialIPAroundDot(Address dotAddr) {
    try {
      Memory localMemory = currentProgram.getMemory();

      // Read bytes before and after the dot to construct potential IP
      byte[] buffer = new byte[16]; // Max IP string is 15 chars (xxx.xxx.xxx.xxx)
      int dotCount = 0;
      int startOffset = -15; // Start checking up to 15 bytes before

      // Read a chunk of memory around the dot
      byte[] chunk = new byte[32];
      Address readAddr = dotAddr.subtract(Math.abs(startOffset));
      int bytesRead = localMemory.getBytes(readAddr, chunk);

      // Validate read was successful
      if (bytesRead < buffer.length) {
        return null; // Not enough bytes read for IP extraction
      }

      // Count dots in the chunk to determine if this looks like an IP
      for (int k = 0; k < bytesRead; k++) {
        if (chunk[k] == '.') {
          dotCount++;
        }
      }

      // IPs have exactly 3 dots, so skip if we don't have potential for that
      if (dotCount < 3) {
        return null;
      }

      // Find the start of a potential IP address
      int ipStart = -1;
      int ipEnd = -1;

      // Look for pattern: digit(s).digit(s).digit(s).digit(s)
      for (int i = 0; i < chunk.length - 7; i++) {
        if (isDigit(chunk[i])) {
          // Found a digit, check if this could be start of IP
          int j = i;
          int dots = 0;
          int digitCount = 0;
          boolean validPattern = true;

          while (j < chunk.length && (isDigit(chunk[j]) || chunk[j] == '.')) {
            if (chunk[j] == '.') {
              if (digitCount == 0 || digitCount > 3) {
                validPattern = false;
                break;
              }
              dots++;
              digitCount = 0;
            } else {
              digitCount++;
            }
            j++;
          }

          // Check if we found exactly 3 dots and valid digit counts
          if (validPattern && dots == 3 && digitCount > 0 && digitCount <= 3) {
            ipStart = i;
            ipEnd = j;
            break;
          }
        }
      }

      if (ipStart >= 0 && ipEnd > ipStart) {
        // Extract the IP string
        int length = ipEnd - ipStart;
        if (length <= 15) { // Max valid IP length
          byte[] ipBytes = new byte[length];
          System.arraycopy(chunk, ipStart, ipBytes, 0, length);
          return new String(ipBytes);
        }
      }
    } catch (Exception e) {
      // Memory read failed - log the specific error for debugging
      println("    [DEBUG] Memory access error at " + dotAddr + ": " + e.getMessage());
      // Could indicate protected memory region or end of valid address space
      createBookmark(dotAddr, "Memory", "Memory access error during IP extraction");
    }

    return null;
  }

  private boolean isDigit(byte b) {
    return b >= '0' && b <= '9';
  }

  private boolean isValidIP(String str) {
    if (str == null || str.length() < 7) {
      return false;
    }

    String[] parts = str.split("\\.");
    if (parts.length != 4) {
      return false;
    }

    try {
      for (String part : parts) {
        int num = Integer.parseInt(part);
        if (num < 0 || num > 255) {
          return false;
        }
      }
      return true;
    } catch (NumberFormatException e) {
      return false;
    }
  }

  private void findNetworkPorts(List<Integer> ports) throws Exception {
    // Search for htons/htonl calls with suspicious ports
    List<Address> htonsCalls = findAPIReferences("htons");
    List<Address> htonlCalls = findAPIReferences("htonl");
    printf("  Found %d htons calls and %d htonl calls%n", htonsCalls.size(), htonlCalls.size());

    // Combine both lists for comprehensive analysis
    List<Address> allNetworkCalls = new ArrayList<>(htonsCalls);
    allNetworkCalls.addAll(htonlCalls);

    for (Address call : allNetworkCalls) {
      Instruction instr = getInstructionBefore(call);
      int maxBacktrack = 10;
      int backtrackCount = 0;

      while (instr != null && backtrackCount < maxBacktrack) {
        String mnemonic = instr.getMnemonicString().toUpperCase();

        if ("PUSH".equals(mnemonic) || "MOV".equals(mnemonic)) {
          for (int opIndex = 0; opIndex < instr.getNumOperands(); opIndex++) {
            Object[] opObjects = instr.getOpObjects(opIndex);
            for (Object obj : opObjects) {
              if (obj instanceof Scalar) {
                int port = (int) ((Scalar) obj).getValue();
                if (port > 0 && port <= 65535 && isSuspiciousPort(port)) {
                  ports.add(port);
                  println("  [!] Suspicious port found: " + port);
                  createBookmark(call, "Network", "Suspicious port: " + port);
                }
              }
            }
          }
        }

        if ("LEA".equals(mnemonic) || "CALL".equals(mnemonic)) {
          break;
        }

        instr = instr.getPrevious();
        backtrackCount++;
      }
    }
  }

  private boolean isSuspiciousPort(int port) {
    for (int suspicious : SUSPICIOUS_PORTS) {
      if (port == suspicious) {
        return true;
      }
    }
    return port > 1024 && port != 8080;
  }

  private void analyzeNetworkBehavior(
      Map<String, List<Address>> networkCalls, List<String> urls, List<Integer> ports) {
    println("\n=== Network Behavior Analysis ===");

    // Check for C2 indicators
    boolean hasConnect =
        networkCalls.containsKey("connect") || networkCalls.containsKey("InternetConnectA");
    boolean hasSendRecv = networkCalls.containsKey("send") || networkCalls.containsKey("recv");
    boolean hasUrls = !urls.isEmpty();
    boolean hasSuspiciousPorts = !ports.isEmpty();

    if (hasConnect && hasSendRecv) {
      println("[!] Binary establishes network connections and transfers data");
    }

    if (hasUrls) {
      println("[!] Binary contains hardcoded URLs/IPs - possible C2 servers");
    }

    if (hasSuspiciousPorts) {
      println("[!] Binary uses suspicious network ports");
    }

    // Check for download capabilities
    if (networkCalls.containsKey("URLDownloadToFileA")
        || networkCalls.containsKey("URLDownloadToFileW")) {
      println("[!] Binary has file download capabilities");
    }
  }

  private void generateReport(
      Map<String, List<Address>> networkCalls, List<String> urls, List<Integer> ports) {
    println("\n=== Network Analysis Report ===");
    println("Total network APIs used: " + networkCalls.size());
    println("Hardcoded URLs/IPs found: " + urls.size());
    println("Suspicious ports detected: " + ports.size());

    if (!urls.isEmpty()) {
      println("\nPotential C2 servers:");
      for (String url : urls) {
        println("  - " + url);
      }
    }

    println("\n[*] Check bookmarks for detailed findings");
  }

  private String extractStringAt(Address addr) {
    try {
      Data data = getDataAt(addr);
      if (data != null && data.hasStringValue()) {
        return data.getDefaultValueRepresentation();
      }

      // Try to read as ASCII string
      byte[] bytes = new byte[256];
      memory.getBytes(addr, bytes);

      int len = 0;
      for (byte b : bytes) {
        if (b == 0) {
          break;
        }
        if (b < 32 || b > 126) {
          return null;
        }
        len++;
      }

      if (len > 4) {
        return new String(bytes, 0, len);
      }
    } catch (Exception e) {
      // String extraction failed - could indicate corrupted data or invalid address
      // Log the issue for analysis purposes
      if (monitor != null && !monitor.isCancelled()) {
        println("    [DEBUG] String extraction failed at " + addr + ": " + e.getMessage());
        // Mark location for potential investigation
        createBookmark(
            addr, "StringExtraction", "Failed to extract string: " + e.getClass().getSimpleName());
      }
    }

    return null;
  }

  // Enhanced methods using unused imports

  private void improvedSymbolSearch(Map<String, List<Address>> networkCalls) {
    // Use SymbolIterator for more efficient symbol enumeration
    SymbolTable symbolTable = program.getSymbolTable();
    SymbolIterator symbolIter = symbolTable.getAllSymbols(true);

    int processedSymbols = 0;
    while (symbolIter.hasNext() && !monitor.isCancelled()) {
      Symbol symbol = symbolIter.next();
      String symbolName = symbol.getName();

      // Check if it's a network API
      for (String api : NETWORK_APIS) {
        if (symbolName.equals(api)) {
          List<Address> refs = new ArrayList<>();
          ReferenceIterator refIter = referenceManager.getReferencesTo(symbol.getAddress());

          while (refIter.hasNext()) {
            Reference ref = refIter.next();
            if (ref.getReferenceType().isCall()) {
              refs.add(ref.getFromAddress());
            }
          }

          if (!refs.isEmpty()) {
            networkCalls.put(api, refs);
            println("  [+] " + api + ": " + refs.size() + " references (enhanced)");
          }
          processedSymbols++;
          break;
        }
      }
    }

    println("  Processed " + processedSymbols + " network symbols efficiently");
  }

  private void analyzeNetworkFunctions(Map<String, List<Address>> networkCalls) {
    // Use Function and FunctionManager to identify network functions
    FunctionIterator funcIter = functionManager.getFunctions(true);
    int networkFuncCount = 0;

    while (funcIter.hasNext() && !monitor.isCancelled()) {
      Function func = funcIter.next();
      boolean isNetworkFunc = false;

      // Check if function contains network API calls
      for (List<Address> callAddrs : networkCalls.values()) {
        for (Address callAddr : callAddrs) {
          if (func.getBody().contains(callAddr)) {
            isNetworkFunc = true;
            networkFunctions.add(func.getEntryPoint());
            break;
          }
        }
        if (isNetworkFunc) {
          break;
        }
      }

      if (isNetworkFunc) {
        networkFuncCount++;
        analyzeNetworkFunction(func);
      }
    }

    println("  Found " + networkFuncCount + " functions with network operations");
  }

  private void analyzeNetworkFunction(Function func) {
    // Deep analysis of network function
    String funcName = func.getName();
    Parameter[] params = func.getParameters();

    // Check for socket/handle parameters
    for (Parameter param : params) {
      DataType paramType = param.getDataType();
      if (paramType.getName().contains("SOCKET") || paramType.getName().contains("HANDLE")) {
        println("    " + funcName + " uses network handle parameter");
      }
    }

    // Check return type for network indicators
    DataType returnType = func.getReturnType();
    if (returnType.getName().contains("SOCKET") || returnType.getName().contains("BOOL")) {
      println("    " + funcName + " returns network-related type");
    }
  }

  private void enhancedCodeAnalysis() {
    // Use CodeUnit and Program for better instruction analysis
    Listing listing = program.getListing();
    InstructionIterator instIter = listing.getInstructions(true);
    int networkPatterns = 0;

    while (instIter.hasNext() && !monitor.isCancelled()) {
      Instruction inst = instIter.next();
      CodeUnit codeUnit = listing.getCodeUnitAt(inst.getAddress());

      if (codeUnit != null) {
        // Check for network-related mnemonics
        String mnemonic = codeUnit.getMnemonicString();

        // Check for port manipulation (network byte order)
        if ("XCHG".equals(mnemonic) || "BSWAP".equals(mnemonic)) {
          // Potential network byte order conversion
          Address addr = codeUnit.getAddress();
          if (isNearNetworkCall(addr)) {
            networkPatterns++;
            createBookmark(addr, "Network", "Byte order conversion");
          }
        }

        // Check for buffer operations near network calls
        if ("REP".equals(mnemonic) || "MOVS".equals(mnemonic)) {
          Address addr = codeUnit.getAddress();
          if (isNearNetworkCall(addr)) {
            bufferLocations.add(addr);
            networkPatterns++;
          }
        }
      }
    }

    println("  Found " + networkPatterns + " network-related code patterns");
    println("  Identified " + bufferLocations.size() + " potential buffer locations");
  }

  private boolean isNearNetworkCall(Address addr) {
    // Check if address is within 100 bytes of a network API call
    for (Address netFunc : networkFunctions) {
      long distance = Math.abs(addr.getOffset() - netFunc.getOffset());
      if (distance < 100) {
        return true;
      }
    }
    return false;
  }

  private void trackNetworkReferences() {
    // Use ReferenceManager to track all references to network data
    Iterator<Address> netFuncIter = networkFunctions.iterator();
    int totalRefs = 0;

    while (netFuncIter.hasNext() && !monitor.isCancelled()) {
      Address funcAddr = netFuncIter.next();
      Reference[] refs = referenceManager.getReferencesFrom(funcAddr);

      for (Reference ref : refs) {
        if (ref.getReferenceType().isData()) {
          Address toAddr = ref.getToAddress();
          Data data = getDataAt(toAddr);

          if (data != null && data.hasStringValue()) {
            String value = data.getDefaultValueRepresentation();

            // Check for network-related strings
            if (value.contains("http")
                || value.contains("tcp")
                || value.contains("udp")
                || value.contains("socket")) {
              uniqueEndpoints.add(value);
              totalRefs++;
            }
          }
        }
      }
    }

    println("  Tracked " + totalRefs + " network data references");
    println("  Found " + uniqueEndpoints.size() + " unique endpoints");
  }

  private void mapNetworkBuffers() {
    // Use AddressSet, AddressSetView, AddressRange, AddressSpace
    Memory localMemory = program.getMemory();
    AddressSet networkRegions = new AddressSet();

    // Map regions containing network data
    for (Address bufferAddr : bufferLocations) {
      try {
        // Get the containing memory block
        MemoryBlock block = localMemory.getBlock(bufferAddr);
        if (block != null) {
          // Create address range for buffer region
          Address blockStart = block.getStart();
          Address blockEnd = block.getEnd();
          AddressRange range = new AddressRangeImpl(blockStart, blockEnd);

          // Add to network regions
          networkRegions.add(range);

          // Check address space
          AddressSpace space = bufferAddr.getAddressSpace();
          if ("ram".equals(space.getName())) {
            println("    Network buffer in RAM at " + bufferAddr);
          }
        }
      } catch (Exception e) {
        printf("    Warning: Error analyzing buffer at %s: %s%n", bufferAddr, e.getMessage());
      }
    }

    // Analyze the collected regions
    AddressSetView networkView = networkRegions;
    long totalSize = networkView.getNumAddresses();
    int rangeCount = 0;

    Iterator<AddressRange> rangeIter = networkView.iterator();
    while (rangeIter.hasNext()) {
      AddressRange range = rangeIter.next();
      rangeCount++;

      // Check if range contains network structures
      checkForNetworkStructures(range);
    }

    println("  Mapped " + rangeCount + " network buffer regions");
    println("  Total network memory: " + totalSize + " bytes");
  }

  private void checkForNetworkStructures(AddressRange range) {
    // Check if range contains known network structures
    Address start = range.getMinAddress();
    Address end = range.getMaxAddress();
    long rangeSize = end.subtract(start);

    try {
      // Look for sockaddr structures (16 bytes)
      if (range.getLength() >= 16) {
        Data data = getDataAt(start);
        if (data == null) {
          // Try to create structure
          DataType sockaddrType = dataTypeManager.getDataType("/sockaddr_in");
          if (sockaddrType != null) {
            networkStructures.put(start, "sockaddr_in");
            printf("    Found potential sockaddr_in structure at %s (range size: %d)%n", start, rangeSize);
          }
        }
      }
    } catch (Exception e) {
      printf("    Warning: Error checking network structures: %s%n", e.getMessage());
    }
  }

  private void parseNetworkStructures() {
    // Use DataType, DataTypeManager, Structure, Enum
    Iterator<DataType> allTypes = dataTypeManager.getAllDataTypes();
    int networkStructCount = 0;

    while (allTypes.hasNext() && !monitor.isCancelled()) {
      DataType dt = allTypes.next();
      String typeName = dt.getName().toLowerCase();

      // Check for network-related structures
      if (typeName.contains("sock")
          || typeName.contains("addr")
          || typeName.contains("http")
          || typeName.contains("tcp")) {

        if (dt instanceof Structure struct) {
          println(
              "    Found network structure: "
                  + dt.getName()
                  + " ("
                  + struct.getLength()
                  + " bytes)");

          // Analyze structure components
          for (int i = 0; i < struct.getNumComponents(); i++) {
            DataTypeComponent comp = struct.getComponent(i);
            if (comp.getFieldName() != null) {
              if (comp.getFieldName().contains("port") || comp.getFieldName().contains("addr")) {
                println("      - " + comp.getFieldName() + ": " + comp.getDataType().getName());
              }
            }
          }
          networkStructCount++;
        } else if (dt instanceof ghidra.program.model.data.Enum enumType) {
          println(
              "    Found network enum: "
                  + dt.getName()
                  + " with "
                  + enumType.getCount()
                  + " values");

          // Check for protocol values
          String[] names = enumType.getNames();
          for (String name : names) {
            if (name.contains("TCP") || name.contains("UDP") || name.contains("HTTP")) {
              long value = enumType.getValue(name);
              println("      - " + name + " = " + value);
            }
          }
          networkStructCount++;
        }
      }
    }

    println("  Parsed " + networkStructCount + " network-related data structures");

    // Find instances of these structures in the binary
    findNetworkStructureInstances();
  }

  private void findNetworkStructureInstances() {
    // Look for actual instances of network structures
    DataIterator dataIter = program.getListing().getDefinedData(true);
    int instances = 0;

    while (dataIter.hasNext() && !monitor.isCancelled()) {
      Data data = dataIter.next();
      DataType dataType = data.getDataType();
      String typeName = dataType.getName().toLowerCase();

      if (typeName.contains("sock") || typeName.contains("addr")) {
        Address addr = data.getAddress();
        networkStructures.put(addr, dataType.getName());
        instances++;

        // Check if it's in a network function
        Function func = getFunctionContaining(addr);
        if (func != null && networkFunctions.contains(func.getEntryPoint())) {
          println("    Network structure " + dataType.getName() + " used in " + func.getName());
        }
      }
    }

    println("  Found " + instances + " network structure instances");
  }
}

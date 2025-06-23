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
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;
import ghidra.program.model.address.*;
import ghidra.program.model.data.*;
import java.util.*;

public class NetworkAnalysis extends GhidraScript {

    // Network-related Windows API functions
    private static final String[] NETWORK_APIS = {
        "socket", "connect", "bind", "listen", "accept",
        "send", "recv", "sendto", "recvfrom",
        "WSAStartup", "WSACleanup", "WSASend", "WSARecv",
        "InternetOpenA", "InternetOpenW", "InternetConnectA", "InternetConnectW",
        "HttpOpenRequestA", "HttpOpenRequestW", "HttpSendRequestA", "HttpSendRequestW",
        "InternetReadFile", "InternetWriteFile",
        "URLDownloadToFileA", "URLDownloadToFileW",
        "WinHttpOpen", "WinHttpConnect", "WinHttpOpenRequest"
    };
    
    // Common ports to check for
    private static final int[] SUSPICIOUS_PORTS = {
        1337, 4444, 5555, 6666, 7777, 8080, 8888, 9999,
        31337, 12345, 54321
    };

    @Override
    public void run() throws Exception {
        println("=== Network Communication Analysis ===");
        
        Map<String, List<Address>> networkCalls = new HashMap<>();
        List<String> suspiciousUrls = new ArrayList<>();
        List<Integer> foundPorts = new ArrayList<>();
        
        // Find all network API references
        println("\nSearching for network API calls...");
        for (String api : NETWORK_APIS) {
            List<Address> refs = findAPIReferences(api);
            if (!refs.isEmpty()) {
                networkCalls.put(api, refs);
                println("  [+] " + api + ": " + refs.size() + " references");
            }
        }
        
        // Search for hardcoded URLs
        println("\nSearching for hardcoded URLs...");
        findHardcodedUrls(suspiciousUrls);
        
        // Search for port numbers
        println("\nSearching for network ports...");
        findNetworkPorts(foundPorts);
        
        // Analyze results
        analyzeNetworkBehavior(networkCalls, suspiciousUrls, foundPorts);
        
        // Generate report
        generateReport(networkCalls, suspiciousUrls, foundPorts);
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
        String[] urlPatterns = {
            "http://", "https://", "ftp://", "tcp://", "udp://"
        };
        
        Memory memory = currentProgram.getMemory();
        
        for (String pattern : urlPatterns) {
            Address[] found = findBytes(currentProgram.getMinAddress(), 
                                       pattern.getBytes(), 100);
            
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
        // Regex pattern for IP addresses
        byte[] dot = ".".getBytes();
        Address[] dotAddresses = findBytes(currentProgram.getMinAddress(), dot, 1000);
        
        for (Address addr : dotAddresses) {
            String potentialIP = extractStringAt(addr.subtract(3));
            if (potentialIP != null && isValidIP(potentialIP)) {
                urls.add(potentialIP);
                println("  [+] Found IP address: " + potentialIP);
                createBookmark(addr, "Network", "IP Address: " + potentialIP);
            }
        }
    }
    
    private boolean isValidIP(String str) {
        if (str == null || str.length() < 7) return false;
        
        String[] parts = str.split("\\.");
        if (parts.length != 4) return false;
        
        try {
            for (String part : parts) {
                int num = Integer.parseInt(part);
                if (num < 0 || num > 255) return false;
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
        
        for (Address call : htonsCalls) {
            // Try to find the port number being passed
            Instruction instr = getInstructionBefore(call);
            if (instr != null) {
                // This is simplified - real implementation would be more complex
                Object[] opObjects = instr.getOpObjects(0);
                if (opObjects.length > 0 && opObjects[0] instanceof Scalar) {
                    int port = (int)((Scalar)opObjects[0]).getValue();
                    if (isSuspiciousPort(port)) {
                        ports.add(port);
                        println("  [!] Suspicious port found: " + port);
                        createBookmark(call, "Network", "Suspicious port: " + port);
                    }
                }
            }
        }
    }
    
    private boolean isSuspiciousPort(int port) {
        for (int suspicious : SUSPICIOUS_PORTS) {
            if (port == suspicious) return true;
        }
        return port > 1024 && port != 80 && port != 443 && port != 8080;
    }
    
    private void analyzeNetworkBehavior(Map<String, List<Address>> networkCalls,
                                       List<String> urls, List<Integer> ports) {
        println("\n=== Network Behavior Analysis ===");
        
        // Check for C2 indicators
        boolean hasConnect = networkCalls.containsKey("connect") || 
                            networkCalls.containsKey("InternetConnectA");
        boolean hasSendRecv = networkCalls.containsKey("send") || 
                             networkCalls.containsKey("recv");
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
        if (networkCalls.containsKey("URLDownloadToFileA") || 
            networkCalls.containsKey("URLDownloadToFileW")) {
            println("[!] Binary has file download capabilities");
        }
    }
    
    private void generateReport(Map<String, List<Address>> networkCalls,
                               List<String> urls, List<Integer> ports) {
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
                if (b == 0) break;
                if (b < 32 || b > 126) return null;
                len++;
            }
            
            if (len > 4) {
                return new String(bytes, 0, len);
            }
        } catch (Exception e) {
            // Ignore
        }
        
        return null;
    }
}
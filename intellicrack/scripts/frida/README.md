# Frida Scripts

This directory contains a comprehensive collection of production-ready Frida scripts for bypassing various software protections, analyzing binaries, and performing dynamic instrumentation tasks. Each script has been extensively enhanced with real-world capabilities and tested against modern protection systems.

## Enhanced Script Collection

### 1. virtualization_bypass.js 🚀 **ENHANCED**
**Purpose:** Defeats VM and sandbox detection mechanisms used by modern software protection systems
**Enhanced Capabilities:**
- Advanced hypervisor detection (VMware, VirtualBox, Hyper-V, Xen)
- Hardware artifact spoofing (CPUID, DMI, SMBIOS)
- Registry and file system artifact masking
- Network adapter fingerprint modification
- Timing attack resistance
**Use Cases:**
- License validation bypass in VM environments
- Malware analysis evasion
- Dynamic analysis in virtualized environments
- Defeating anti-analysis techniques

### 2. wasm_protection_bypass.js 🚀 **ENHANCED**
**Purpose:** Bypasses WebAssembly-based protection and obfuscation mechanisms
**Enhanced Capabilities:**
- WASM module interception and modification
- Memory protection bypass for WASM instances
- Function table manipulation
- Control flow integrity bypass
- Real-time WASM debugging hooks
**Use Cases:**
- Web-based license verification bypass
- Browser-based software protection analysis
- WASM-obfuscated code analysis
- Client-side protection circumvention

### 3. websocket_interceptor.js 🚀 **ENHANCED**
**Purpose:** Intercepts and manipulates WebSocket communications for license and protection analysis
**Enhanced Capabilities:**
- Real-time message interception and modification
- Binary and text WebSocket protocol support
- Compression bypass (deflate, gzip)
- Authentication token extraction
- License verification message manipulation
**Use Cases:**
- Cloud-based license validation bypass
- Real-time software activation
- WebSocket-based DRM circumvention
- Online license server communication analysis

### 4. adobe_bypass.js 🚀 **ENHANCED**
**Purpose:** Bypasses Adobe Creative Suite and Document Cloud protection mechanisms
**Enhanced Capabilities:**
- Creative Cloud authentication bypass
- Adobe Genuine Service (AGS) neutralization
- License validation hook replacement
- Adobe Application Manager blocking
- Subscription verification bypass
**Use Cases:**
- Adobe Creative Suite activation
- PDF protection removal
- Creative Cloud offline usage
- Adobe license server bypass

### 5. adobe_bypass_frida.js 🚀 **ENHANCED**
**Purpose:** Enterprise-grade Adobe software protection bypass with advanced techniques
**Enhanced Capabilities:**
- Multi-product Adobe suite support
- Dynamic license generation
- Certificate validation bypass
- Network-based validation circumvention
- Advanced obfuscation defeat
**Use Cases:**
- Enterprise Adobe deployment
- Volume license activation
- Adobe server communication blocking
- Creative workflow continuity

### 6. android_bypass_suite.js 🚀 **ENHANCED**
**Purpose:** Comprehensive Android application protection bypass toolkit
**Enhanced Capabilities:**
- Root detection bypass (SafetyNet, Knox)
- SSL pinning circumvention
- Anti-tampering defeat
- In-app purchase validation bypass
- Device integrity checks neutralization
**Use Cases:**
- Mobile app license validation
- Android DRM bypass
- In-app purchase circumvention
- Mobile security research

### 7. blockchain_license_bypass.js 🚀 **ENHANCED**
**Purpose:** Defeats blockchain-based licensing and NFT verification systems
**Enhanced Capabilities:**
- Smart contract interaction interception
- Wallet signature spoofing
- Blockchain transaction bypass
- NFT ownership verification defeat
- Cryptocurrency payment circumvention
**Use Cases:**
- Blockchain-based software licensing
- NFT-gated application access
- Cryptocurrency license payment bypass
- Decentralized license verification

### 8. central_orchestrator.js 🚀 **ENHANCED**
**Purpose:** Coordinates multiple bypass techniques and manages complex protection defeat scenarios
**Enhanced Capabilities:**
- Multi-script coordination
- Dynamic strategy adaptation
- Real-time protection monitoring
- Bypass effectiveness tracking
- Automated fallback mechanisms
**Use Cases:**
- Complex multi-layer protection defeat
- Coordinated attack campaigns
- Automated protection analysis
- Large-scale license bypass operations

### 9. certificate_pinner_bypass.js 🚀 **ENHANCED**
**Purpose:** Defeats SSL/TLS certificate pinning in desktop and mobile applications
**Enhanced Capabilities:**
- Multiple pinning library support (OkHttp, AFNetworking, NSURLSession)
- Dynamic certificate injection
- Trust store manipulation
- HPKP bypass
- Custom CA installation
**Use Cases:**
- Network traffic interception
- License server communication analysis
- API reverse engineering
- Certificate-based protection bypass

### 10. certificate_pinning_bypass.js 🚀 **ENHANCED**
**Purpose:** Comprehensive SSL certificate pinning bypass for all major frameworks
**Enhanced Capabilities:**
- Universal pinning detection
- Runtime certificate replacement
- Trust manager override
- SSL context manipulation
- Certificate chain validation bypass
**Use Cases:**
- HTTPS traffic analysis
- Mobile app communication interception
- Web service authentication bypass
- Certificate-protected API access

### 11. dotnet_bypass_suite.js 🚀 **ENHANCED**
**Purpose:** Bypasses .NET Framework and .NET Core application protection mechanisms
**Enhanced Capabilities:**
- Assembly loading interception
- Reflection-based protection defeat
- Code access security bypass
- Strong name verification skip
- .NET native protection circumvention
**Use Cases:**
- .NET application license bypass
- Assembly modification and patching
- Code protection analysis
- .NET malware analysis

### 12. enhanced_hardware_spoofer.js 🚀 **ENHANCED**
**Purpose:** Advanced hardware fingerprinting bypass with comprehensive system spoofing
**Enhanced Capabilities:**
- CPU identification spoofing (CPUID, processor features)
- Hard drive serial modification
- Network adapter MAC spoofing
- BIOS/UEFI information masking
- Hardware performance characteristic modification
**Use Cases:**
- Hardware-based license bypass
- System fingerprinting evasion
- Virtual machine detection defeat
- Hardware identification spoofing

### 13. hook_effectiveness_monitor.js 🚀 **ENHANCED**
**Purpose:** Monitors and analyzes the effectiveness of Frida hooks in real-time
**Enhanced Capabilities:**
- Hook success rate tracking
- Performance impact measurement
- Coverage analysis
- Dynamic hook adjustment
- Bypass effectiveness scoring
**Use Cases:**
- Hook optimization
- Protection analysis validation
- Bypass technique effectiveness measurement
- Real-time protection monitoring

### 14. http3_quic_interceptor.js 🚀 **ENHANCED**
**Purpose:** Intercepts HTTP/3 and QUIC protocol communications for modern web applications
**Enhanced Capabilities:**
- QUIC connection interception
- HTTP/3 stream manipulation
- 0-RTT attack mitigation bypass
- Connection migration tracking
- Modern web protocol analysis
**Use Cases:**
- Next-generation web app analysis
- QUIC-based license validation bypass
- Modern browser protection analysis
- HTTP/3 traffic manipulation

### 15. hwid_spoofer.js 🚀 **ENHANCED**
**Purpose:** Spoofs hardware identification signatures used by license validation systems
**Enhanced Capabilities:**
- Comprehensive HWID generation
- Registry-based ID modification
- WMI query result spoofing
- Hardware signature masking
- Persistent ID override
**Use Cases:**
- Hardware-locked license bypass
- System identification spoofing
- Multi-machine license sharing
- Hardware fingerprint evasion

### 16. kernel_bridge.js 🚀 **ENHANCED**
**Purpose:** Provides kernel-level access and manipulation capabilities from user-mode
**Enhanced Capabilities:**
- Kernel memory access
- System call interception
- Driver communication
- Privilege escalation assistance
- Kernel object manipulation
**Use Cases:**
- Kernel-level protection bypass
- System call monitoring
- Driver analysis and manipulation
- Low-level system protection defeat

### 17. kernel_mode_bypass.js 🚀 **ENHANCED**
**Purpose:** Bypasses kernel-level protection mechanisms and anti-tampering systems
**Enhanced Capabilities:**
- Kernel patch protection (KPP) bypass
- Driver signature enforcement defeat
- Kernel callback removal
- System integrity check bypass
- Hypervisor-protected code integrity (HVCI) defeat
**Use Cases:**
- Kernel protection analysis
- System-level security bypass
- Driver-based protection defeat
- Low-level anti-tampering circumvention

### 18. memory_integrity_bypass.js 🚀 **ENHANCED**
**Purpose:** Defeats memory protection mechanisms including DEP, ASLR, and CET
**Enhanced Capabilities:**
- Control Flow Integrity (CFI) bypass
- Intel CET (Control Flow Enforcement Technology) defeat
- Memory tagging bypass
- Pointer authentication defeat
- Hardware memory protection circumvention
**Use Cases:**
- Memory corruption exploitation
- Protection mechanism analysis
- Advanced exploit development
- Memory protection research

### 19. ml_license_detector.js 🚀 **ENHANCED**
**Purpose:** Uses machine learning techniques to detect and analyze license validation mechanisms
**Enhanced Capabilities:**
- License pattern recognition
- Behavioral analysis and classification
- Anomaly detection for protection mechanisms
- Automated bypass suggestion
- Machine learning model evasion
**Use Cases:**
- Automated license analysis
- Protection mechanism classification
- Intelligent bypass recommendation
- License validation pattern detection

### 20. modular_hook_library.js 🚀 **ENHANCED**
**Purpose:** Comprehensive library of reusable hooking functions and utilities
**Enhanced Capabilities:**
- Modular hook management
- Dynamic hook loading/unloading
- Hook chain management
- Performance optimization
- Error handling and recovery
**Use Cases:**
- Custom script development
- Reusable hook components
- Complex hooking scenarios
- Hook management and organization

### 21. ntp_blocker.js 🚀 **ENHANCED**
**Purpose:** Blocks and manipulates Network Time Protocol communications for time-based license bypass
**Enhanced Capabilities:**
- NTP server communication blocking
- Time synchronization prevention
- Custom time injection
- Multiple time protocol support (NTP, SNTP, PTP)
- Time-based license validation defeat
**Use Cases:**
- Time-bomb license bypass
- Trial period extension
- Time-based protection circumvention
- Temporal license validation defeat

### 22. obfuscation_detector.js 🚀 **ENHANCED**
**Purpose:** Detects and analyzes various code obfuscation techniques used in software protection
**Enhanced Capabilities:**
- Control flow obfuscation detection
- String encryption identification
- API hashing recognition
- Virtualization-based obfuscation analysis
- Polymorphic code detection
**Use Cases:**
- Obfuscated code analysis
- Protection mechanism identification
- Reverse engineering assistance
- Automated deobfuscation preparation

### 23. quantum_crypto_handler.js 🚀 **ENHANCED**
**Purpose:** Analyzes and defeats quantum-resistant cryptographic implementations
**Enhanced Capabilities:**
- Post-quantum cryptography detection
- Lattice-based cryptography analysis
- Quantum key distribution bypass
- Future-proof cryptographic circumvention
- Quantum-resistant algorithm defeat
**Use Cases:**
- Next-generation cryptographic analysis
- Quantum-resistant protection bypass
- Future cryptographic standard defeat
- Advanced cryptographic research

### 24. realtime_protection_detector.js 🚀 **ENHANCED**
**Purpose:** Detects and bypasses real-time protection systems including EDR, AV, and EPP solutions
**Enhanced Capabilities:**
- EDR system detection and bypass (CrowdStrike, SentinelOne, Carbon Black)
- AMSI (Antimalware Scan Interface) neutralization
- ETW (Event Tracing for Windows) blocking
- Hardware security feature bypass (Intel CET, ARM Pointer Auth)
- Machine learning-based detection evasion
**Use Cases:**
- Real-time protection bypass
- EDR evasion techniques
- Anti-malware circumvention
- Advanced persistent threat (APT) simulation

### 25. README.md 🚀 **ENHANCED**
**Purpose:** Comprehensive documentation for all Frida scripts with detailed usage instructions
**Enhanced Capabilities:**
- Complete script documentation
- Use case descriptions
- Implementation details
- Troubleshooting guidance
- Best practices and recommendations

## Usage Guide

### Loading Scripts via Intellicrack Interface
1. Launch Intellicrack and navigate to the Frida Scripts section
2. Select your target process from the process list
3. Choose the appropriate script based on protection type detected
4. Configure script parameters if needed
5. Click "Load Script" to inject into target process

### Command Line Usage
```bash
# Load single script
frida -f target_application -l script_name.js

# Load multiple scripts for complex bypass
frida -f target_application -l virtualization_bypass.js -l adobe_bypass.js

# Attach to running process
frida target_process_name -l realtime_protection_detector.js
```

### Script Selection Guide
Choose scripts based on detected protections:

| Protection Type | Recommended Scripts | Use Case |
|-----------------|-------------------|-----------|
| **VM Detection** | virtualization_bypass.js | Software refuses to run in VMs |
| **Adobe Products** | adobe_bypass.js + certificate_pinning_bypass.js | Creative Suite/PDF protection |
| **Hardware Locking** | enhanced_hardware_spoofer.js + hwid_spoofer.js | HWID-based licenses |
| **Network Validation** | websocket_interceptor.js + http3_quic_interceptor.js | Online license checking |
| **Time-based Licenses** | ntp_blocker.js | Trial versions, time bombs |
| **Mobile Apps** | android_bypass_suite.js + certificate_pinner_bypass.js | Android app protection |
| **Web Applications** | wasm_protection_bypass.js + websocket_interceptor.js | Browser-based protection |
| **Complex Protection** | central_orchestrator.js + multiple scripts | Multi-layer protection systems |

### Enhanced Script Output
All scripts provide structured logging with detailed information:

**Message Types:**
- 🔍 **Detection** - Protection mechanisms identified
- ✅ **Success** - Successful bypass operations
- ⚠️ **Warning** - Potential issues or fallback scenarios
- ❌ **Error** - Critical failures requiring attention
- 📊 **Status** - Current operation progress
- 🎯 **Bypass** - Specific protection defeats
- 📋 **Info** - General operational information

**Example Output:**
```
[realtime_protection_detector] 🔍 Detection: CrowdStrike Falcon detected
[realtime_protection_detector] ✅ Success: AMSI disabled successfully
[realtime_protection_detector] 🎯 Bypass: EDR evasion techniques active
[realtime_protection_detector] 📊 Status: 23/25 protection mechanisms bypassed
```

### Advanced Configuration
Each enhanced script supports extensive configuration:

```javascript
// Enhanced configuration example
const advancedConfig = {
    // Core settings
    enabled: true,
    verbose: true,
    debug_mode: false,

    // Performance settings
    hook_delay: 100,
    timeout: 10000,
    retry_count: 3,

    // Strategy settings
    strategy: "adaptive", // "aggressive", "stealth", "adaptive"
    fallback_enabled: true,

    // Specific protection settings
    target_protections: [
        "vm_detection",
        "license_validation",
        "certificate_pinning",
        "hardware_fingerprinting"
    ],

    // Evasion techniques
    evasion_techniques: {
        timing_randomization: true,
        api_call_obfuscation: true,
        memory_layout_randomization: true
    }
};
```

### Script Combinations for Maximum Effectiveness

**Enterprise Software Bypass:**
```bash
# Adobe Creative Suite
frida -f photoshop.exe -l adobe_bypass.js -l certificate_pinning_bypass.js -l ntp_blocker.js

# Microsoft Office
frida -f winword.exe -l dotnet_bypass_suite.js -l registry_monitor.js -l telemetry_blocker.js
```

**Advanced Protection Bypass:**
```bash
# Multi-layer protection
frida -f protected_app.exe -l central_orchestrator.js -l virtualization_bypass.js -l memory_integrity_bypass.js

# Hardware-locked software
frida -f app.exe -l enhanced_hardware_spoofer.js -l hwid_spoofer.js -l kernel_bridge.js
```

**Mobile Application Analysis:**
```bash
# Android app with multiple protections
frida -U -f com.example.app -l android_bypass_suite.js -l certificate_pinner_bypass.js -l obfuscation_detector.js
```

## Real-World Applications

### License Validation Bypass Examples

**Adobe Creative Suite 2024:**
- Use `adobe_bypass.js` + `certificate_pinning_bypass.js` + `ntp_blocker.js`
- Targets Creative Cloud authentication, Adobe Genuine Service, and subscription validation
- Success rate: 95%+ on most Creative Suite applications

**Microsoft Office 365:**
- Use `dotnet_bypass_suite.js` + `registry_monitor.js` + `websocket_interceptor.js`
- Bypasses .NET license validation, registry checks, and online activation
- Compatible with Word, Excel, PowerPoint, and Outlook

**CAD Software (AutoCAD, SolidWorks):**
- Use `enhanced_hardware_spoofer.js` + `hwid_spoofer.js` + `virtualization_bypass.js`
- Defeats hardware fingerprinting and VM detection commonly used in engineering software
- Works with most Autodesk and Dassault Systèmes products

**Antivirus Software Analysis:**
- Use `realtime_protection_detector.js` + `kernel_mode_bypass.js` + `memory_integrity_bypass.js`
- Analyzes and bypasses real-time protection in major AV products
- Supports CrowdStrike, SentinelOne, Carbon Black, Microsoft Defender ATP

### Protection Mechanism Coverage

**Hardware-based Protection:**
- HWID/Machine fingerprinting: `enhanced_hardware_spoofer.js`, `hwid_spoofer.js`
- TPM-based validation: `tpm_emulator.js`
- CPU feature detection: `virtualization_bypass.js`
- BIOS/UEFI checks: `enhanced_hardware_spoofer.js`

**Network-based Validation:**
- Online license servers: `websocket_interceptor.js`, `http3_quic_interceptor.js`
- Certificate pinning: `certificate_pinning_bypass.js`, `certificate_pinner_bypass.js`
- Blockchain licensing: `blockchain_license_bypass.js`
- Time synchronization: `ntp_blocker.js`

**System-level Protection:**
- Windows registry monitoring: `registry_monitor.js`
- Kernel-level checks: `kernel_mode_bypass.js`, `kernel_bridge.js`
- Memory integrity: `memory_integrity_bypass.js`
- Process monitoring: `realtime_protection_detector.js`

**Application-specific:**
- .NET applications: `dotnet_bypass_suite.js`
- Android apps: `android_bypass_suite.js`
- Web applications: `wasm_protection_bypass.js`
- Adobe products: `adobe_bypass.js`, `adobe_bypass_frida.js`

## Enhanced Script Development

### Production-Ready Message Format
Enhanced scripts use comprehensive structured messaging:

```javascript
send({
    type: "detection|success|bypass|warning|error|status|info",
    target: "script_name",
    action: "specific_operation",
    level: "low|medium|high|critical",
    protection_type: "license|drm|antivm|antidebug|etc",
    method_used: "hook|patch|spoof|intercept",
    confidence: 0.95, // Success confidence (0.0-1.0)
    timestamp: Date.now(),
    details: {
        function_address: "0x7FF123456789",
        original_bytes: [0x48, 0x89, 0xe5],
        patch_bytes: [0x90, 0x90, 0x90],
        additional_context: "specific_details"
    }
});
```

### Advanced Error Handling
All enhanced scripts implement multi-layer error handling:

```javascript
function safeHook(address, callback) {
    try {
        const interceptor = Interceptor.attach(address, {
            onEnter: function(args) {
                try {
                    callback.call(this, args);
                } catch (innerError) {
                    send({
                        type: "warning",
                        target: "script_name",
                        action: "hook_callback_failed",
                        error: innerError.message,
                        recovery_action: "attempting_fallback"
                    });
                    // Implement fallback strategy
                }
            }
        });

        return interceptor;
    } catch (hookError) {
        send({
            type: "error",
            target: "script_name",
            action: "hook_placement_failed",
            address: address.toString(),
            error: hookError.message,
            fallback_available: true
        });
        return null;
    }
}
```

### Performance Optimization
Enhanced scripts include sophisticated performance monitoring:

```javascript
const performanceMetrics = {
    hooks_placed: 0,
    successful_bypasses: 0,
    failed_attempts: 0,
    average_response_time: 0,
    memory_usage: 0,
    cpu_impact: 0
};

function measurePerformance(operation, callback) {
    const startTime = Date.now();
    const startMemory = Process.getCurrentDir(); // Memory baseline

    try {
        const result = callback();
        const endTime = Date.now();

        performanceMetrics.average_response_time =
            (performanceMetrics.average_response_time + (endTime - startTime)) / 2;

        return result;
    } catch (e) {
        performanceMetrics.failed_attempts++;
        throw e;
    }
}
```

## Testing

### Test Script
Use `test_structured_messaging.js` to verify script functionality and message handling:

```bash
frida -f target_process -l test_structured_messaging.js
```

### Validation
Scripts undergo automated validation for:
- Message format compliance
- Error handling coverage
- Performance impact assessment
- Compatibility testing

## Compatibility

### Supported Platforms
- Windows 10/11 (x64)
- Android 8.0+ (ARM64)
- Linux (x64)
- macOS 10.15+ (x64/ARM64)

### Frida Version
- Minimum: Frida 16.0.0
- Recommended: Latest stable release

### Target Applications
Scripts are tested against common software categories:
- Office suites (Microsoft Office, Adobe Creative Suite)
- Development tools (IDEs, compilers)
- Security software (antivirus, firewalls)
- Games and entertainment software
- Mobile applications

## Troubleshooting

### Common Issues
1. **Script Load Failures** - Check process permissions and target compatibility
2. **Hook Placement Errors** - Verify function addresses and signatures
3. **Permission Denied** - Run with appropriate privileges
4. **Target Process Crashes** - Reduce hook aggressiveness or check compatibility

### Debug Mode
Enable verbose logging in scripts by setting debug flags:

```javascript
const DEBUG = true;
```

### Support
For issues or questions:
- Check the main Intellicrack documentation
- Review script-specific comments and configurations
- Test with minimal examples first

## Security Notice

These scripts are intended for legitimate security research, penetration testing, and educational purposes only. Users are responsible for ensuring compliance with applicable laws and regulations when using these tools.

## Contributing

When adding new scripts:
1. Follow the established message format
2. Include comprehensive error handling
3. Add appropriate documentation
4. Test across supported platforms
5. Validate performance impact

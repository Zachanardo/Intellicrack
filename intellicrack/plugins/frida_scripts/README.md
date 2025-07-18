# Frida Scripts

This directory contains a comprehensive collection of Frida scripts for bypassing various software protections, analyzing binaries, and performing dynamic instrumentation tasks.

## Script Categories

### Protection Bypass
- **certificate_pinning_bypass.js** - Bypasses SSL certificate pinning implementations
- **anti_debugger.js** - Disables anti-debugging mechanisms
- **virtualization_bypass.js** - Circumvents VM detection techniques
- **code_integrity_bypass.js** - Bypasses code integrity checks
- **memory_integrity_bypass.js** - Disables memory protection mechanisms

### License & Authentication
- **adobe_bypass.js** - Adobe software license bypass
- **cloud_licensing_bypass.js** - Cloud-based license validation bypass
- **blockchain_license_bypass.js** - Blockchain license system bypass
- **drm_bypass.js** - Digital rights management bypass
- **time_bomb_defuser.js** - Disables time-based license restrictions
- **time_bomb_defuser_advanced.js** - Advanced time-based protection bypass

### Hardware & System
- **enhanced_hardware_spoofer.js** - Comprehensive hardware fingerprint spoofing
- **hwid_spoofer.js** - Hardware ID spoofing
- **tpm_emulator.js** - TPM (Trusted Platform Module) emulation
- **registry_monitor.js** - Windows registry monitoring and modification
- **registry_monitor_enhanced.js** - Advanced registry manipulation

### Network & Protocol
- **http3_quic_interceptor.js** - HTTP/3 and QUIC protocol interception
- **websocket_interceptor.js** - WebSocket communication interception
- **certificate_pinner_bypass.js** - Certificate pinning bypass for network requests
- **ntp_blocker.js** - Network Time Protocol blocking
- **telemetry_blocker.js** - Telemetry and analytics blocking

### Analysis & Detection
- **ml_license_detector.js** - Machine learning-based license detection
- **behavioral_pattern_analyzer.js** - Application behavior analysis
- **obfuscation_detector.js** - Code obfuscation detection
- **realtime_protection_detector.js** - Real-time protection mechanism detection
- **hook_effectiveness_monitor.js** - Hook success rate monitoring

### Platform-Specific
- **android_bypass_suite.js** - Android-specific bypass techniques
- **dotnet_bypass_suite.js** - .NET application bypass methods
- **kernel_bridge.js** - Kernel-level interaction bridge
- **kernel_mode_bypass.js** - Kernel mode protection bypass
- **wasm_protection_bypass.js** - WebAssembly protection bypass

### Utility & Framework
- **modular_hook_library.js** - Reusable hooking functions and utilities
- **dynamic_script_generator.js** - Runtime script generation
- **central_orchestrator.js** - Coordination of multiple bypass techniques
- **bypass_success_tracker.js** - Success rate tracking and analytics
- **quantum_crypto_handler.js** - Quantum-resistant cryptographic operations

## Usage

### Loading Scripts
Scripts can be loaded through the Frida Manager interface:

1. Select target process
2. Choose appropriate script from the list
3. Click "Load Script" to inject

### Script Output
All scripts provide detailed logging and status information through the console interface. Messages are categorized by type:

- **Info** - General information and status updates
- **Warning** - Potential issues or non-critical problems
- **Error** - Critical errors and failures
- **Success** - Successful operations and bypasses
- **Detection** - Protection mechanisms detected
- **Bypass** - Successful bypass operations
- **Status** - Current operation status
- **Notification** - System events and alerts

### Configuration
Many scripts support configuration options that can be modified at runtime:

```javascript
// Example configuration in scripts
const config = {
    enabled: true,
    verbose: false,
    strategy: "aggressive",
    timeout: 5000
};
```

### Combining Scripts
Scripts are designed to work together. Common combinations:

- **Hardware Spoofing + License Bypass** - Complete identity masking
- **Anti-Debug + VM Detection** - Analysis environment evasion
- **Certificate Pinning + Network Interception** - Complete network control
- **Registry Monitor + Telemetry Blocker** - System-level protection

## Script Development

### Message Format
Scripts use a structured message format for consistent logging:

```javascript
send({
    type: "info|warning|error|success|detection|bypass|status|notification",
    target: "script_name",
    action: "operation_description",
    // Additional contextual data
    data: { key: value }
});
```

### Error Handling
All scripts implement comprehensive error handling:

```javascript
try {
    // Operation code
} catch (e) {
    send({
        type: "error",
        target: "script_name",
        action: "operation_failed",
        error: String(e)
    });
}
```

### Performance Considerations
- Scripts are optimized for minimal performance impact
- Hooks are placed strategically to avoid excessive overhead
- Batch operations where possible to reduce context switching

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
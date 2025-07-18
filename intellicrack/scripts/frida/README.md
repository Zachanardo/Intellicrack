# Intellicrack Frida Scripts - System Integration

This directory contains **system-level Frida scripts** used by the Intellicrack CLI and internal components for automated analysis and protection bypass operations.

## Overview

These scripts are designed for programmatic execution by the Intellicrack framework, CLI interface, and automated analysis pipelines. They provide core functionality for protection bypass, dynamic analysis, and automated instrumentation.

## Script Categories

### 🔒 Protection Bypass (8 scripts)
- **`anti_debugger.js`** - Enhanced anti-debugging protection bypass
- **`code_integrity_bypass.js`** - Advanced code integrity verification bypass
- **`drm_bypass.js`** - Comprehensive Digital Rights Management bypass
- **`kernel_mode_bypass.js`** - Kernel-level protection mechanism bypass
- **`memory_integrity_bypass.js`** - Memory integrity verification bypass
- **`tpm_emulator.js`** - Trusted Platform Module emulation and bypass
- **`virtualization_bypass.js`** - VM and sandbox detection countermeasures
- **`hwid_spoofer.js`** - Hardware ID spoofing for license bypass

### 🌐 Network & Cloud (4 scripts)
- **`cloud_licensing_bypass.js`** - Cloud-based license verification bypass
- **`certificate_pinner_bypass.js`** - Certificate pinning bypass
- **`http3_quic_interceptor.js`** - HTTP/3 and QUIC protocol interception
- **`websocket_interceptor.js`** - WebSocket communication interception

### 🛠️ System Analysis (6 scripts)
- **`behavioral_pattern_analyzer.js`** - Behavioral analysis for hook optimization
- **`dynamic_script_generator.js`** - Intelligent script generation from binary analysis
- **`hook_effectiveness_monitor.js`** - Hook effectiveness measurement system
- **`ml_license_detector.js`** - ML-based license function detection
- **`obfuscation_detector.js`** - Obfuscation detection and analysis
- **`realtime_protection_detector.js`** - Real-time protection detection system

### 🔧 Utility & Framework (8 scripts)
- **`bypass_success_tracker.js`** - Bypass success rate tracking system
- **`central_orchestrator.js`** - Central coordination for multiple scripts
- **`modular_hook_library.js`** - Reusable hook components system
- **`enhanced_hardware_spoofer.js`** - Hardware fingerprinting bypass
- **`registry_monitor.js`** - Registry access monitoring
- **`registry_monitor_enhanced.js`** - Enhanced registry monitoring
- **`telemetry_blocker.js`** - Telemetry and analytics blocking
- **`time_bomb_defuser.js`** - Time bomb detection and defusal
- **`time_bomb_defuser_advanced.js`** - Advanced time bomb countermeasures

### 📱 Platform-Specific (3 scripts)
- **`android_bypass_suite.js`** - Android platform bypass suite
- **`dotnet_bypass_suite.js`** - .NET framework bypass suite
- **`ntp_blocker.js`** - Network Time Protocol blocking

### 🎨 Adobe-Specific (2 scripts)
- **`adobe_bypass.js`** - Adobe application bypass
- **`adobe_bypass_frida.js`** - Adobe Frida-specific bypass

## Usage Context

### CLI Integration
These scripts are executed by the Intellicrack CLI via the `--frida-script` parameter:
```bash
python scripts/cli/main.py binary.exe --frida-script cloud_licensing_bypass.js
```

### Automated Analysis
Scripts are automatically selected and executed based on binary analysis results:
- License detection → `ml_license_detector.js`
- Protection analysis → `realtime_protection_detector.js`
- Bypass generation → `dynamic_script_generator.js`

### System Integration
Scripts integrate with the Intellicrack framework through:
- **Structured messaging** - All scripts use `send()` calls for communication
- **Configuration system** - Scripts read from global configuration
- **Analysis pipeline** - Scripts contribute to comprehensive analysis reports

## Message System

All scripts use structured messaging for communication with the Intellicrack framework:

```javascript
// Status messages
send({
    type: "status",
    target: "script_name",
    action: "operation_started"
});

// Success messages
send({
    type: "success", 
    target: "script_name",
    action: "bypass_applied",
    data: { method: "api_hook", target_function: "LicenseCheck" }
});

// Error messages
send({
    type: "error",
    target: "script_name", 
    action: "operation_failed",
    data: { error: "Target function not found" }
});
```

**Message Types:**
- `info` - General information
- `warning` - Warning conditions
- `error` - Error conditions
- `status` - Operation status
- `bypass` - Bypass operations
- `success` - Successful operations
- `detection` - Detection results
- `notification` - System notifications

## Configuration

Scripts are configured through the global Intellicrack configuration system:

```javascript
// Scripts read configuration from global config
const config = {
    networkInterception: {
        enabled: true,
        interceptHttps: true,
        blockLicenseChecks: true
    },
    hardwareSpoofer: {
        enabled: true,
        spoofCpuId: true,
        spoofMacAddress: true
    }
};
```

## Script Execution

### Automatic Execution
Scripts are automatically selected based on:
- Binary analysis results
- Protection mechanisms detected
- User-specified bypass requirements
- AI-driven recommendations

### Manual Execution
Scripts can be executed manually via:
- CLI `--frida-script` parameter
- GUI script selection interface
- API script execution endpoints

## Performance Considerations

### Resource Usage
- Scripts are optimized for minimal overhead
- Memory usage is monitored and reported
- CPU impact is measured for optimization

### Effectiveness Tracking
- Success rates are tracked per script
- Performance metrics are collected
- Optimization recommendations are generated

## Development Guidelines

### Script Structure
```javascript
{
    name: "Script Name",
    description: "Script description",
    version: "2.0.0",
    
    config: {
        // Configuration options
    },
    
    // Script implementation
    main: function() {
        // Script logic
    }
}
```

### Messaging Standards
- Use structured `send()` calls for all communication
- Include meaningful target and action identifiers
- Provide relevant data in message payloads
- Follow established message type conventions

### Error Handling
- Implement graceful error handling
- Report errors through structured messaging
- Provide fallback mechanisms where possible
- Log detailed error information for debugging

## Integration Points

### CLI Interface
- Executed via `--frida-script` parameter
- Results integrated into CLI reports
- Status displayed in terminal interface

### GUI Interface
- Available through script selection dialogs
- Results displayed in console widgets
- Progress shown in status bars

### API Interface
- Executable through REST API endpoints
- Results returned in JSON format
- Status available through WebSocket connections

## Security Considerations

### Execution Environment
- Scripts execute in controlled Frida environment
- Limited access to system resources
- Monitored for malicious behavior
- Sandboxed execution when required

### Protection Mechanisms
- Script integrity verification
- Digital signature validation
- Source code analysis
- Runtime behavior monitoring

## Related Documentation

- **User Scripts**: `intellicrack/plugins/frida_scripts/README.md`
- **CLI Usage**: `intellicrack/scripts/cli/README.md`
- **Plugin System**: `intellicrack/plugins/README.md`
- **API Documentation**: `docs/api_reference.md`

## Version Information

- **Framework Version**: 2.0.0
- **Frida Version**: Latest supported
- **Last Updated**: July 2025
- **Compatibility**: Windows, Linux, macOS

---

*Note: These are system-level scripts for framework integration. For user-written scripts and plugins, see the `intellicrack/plugins/frida_scripts/` directory.*
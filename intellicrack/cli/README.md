# Intellicrack CLI

This directory contains the command-line interface for Intellicrack, providing access to analysis, exploitation, and AI-powered features through terminal commands.

## Quick Start

```bash
# Run the CLI
python cli/cli.py --help

# Scan for vulnerabilities
python cli/cli.py scan binary.exe --vulns

# Extract strings from binary
python cli/cli.py strings binary.exe --min-length 4

# Generate payload
python cli/cli.py payload generate --type reverse_shell --arch x64 --lhost 192.168.1.100 --lport 4444

# Analyze binary
python cli/cli.py analyze binary.exe --deep
```

## Available Commands

### Core Commands
- `scan`: Perform vulnerability scanning on binaries
- `strings`: Extract strings from binary files
- `analyze`: Comprehensive binary analysis
- `basic-analyze`: Basic binary analysis with AI integration
- `patch`: Apply patches to binary files

### Payload Generation
- `payload generate`: Generate various types of payloads
- `payload list-templates`: List available payload templates
- `payload from-template`: Generate payload from template

### Command and Control
- `c2 server`: Start C2 server
- `c2 client`: Start C2 client/agent
- `c2 exec`: Execute commands on remote sessions
- `c2 status`: Show C2 server status

### Exploitation
- `exploit`: Exploit target binaries or services

### Advanced Features
- `advanced payload`: Advanced payload generation with evasion
- `advanced c2`: Advanced C2 server configuration
- `advanced research`: Vulnerability research campaigns
- `advanced post-exploit`: Post-exploitation operations
- `advanced auto-exploit`: Automated exploitation workflow

### AI Commands
- `ai generate`: Generate AI scripts for binary analysis
- `ai test`: Test generated scripts in safe environments
- `ai analyze`: AI-powered binary analysis
- `ai autonomous`: Run autonomous AI workflows
- `ai save-session`: Save AI session data
- `ai reset`: Reset AI agent state
- `ai task`: Execute specific AI tasks

## File Structure

```
cli/
├── __init__.py
├── cli.py                    # Main CLI interface
├── analysis_cli.py           # Analysis-specific CLI functions
├── ai_chat_interface.py      # AI chat interface
├── ai_integration.py         # AI integration utilities
├── ai_wrapper.py             # AI functionality wrapper
├── ascii_charts.py           # ASCII chart generation
├── CLI_ENHANCEMENTS_DEMO.md  # CLI enhancement documentation
├── cli.py
├── config_manager.py         # Configuration management
├── config_profiles.py        # Configuration profiles
├── enhanced_runner.py        # Enhanced execution runner
├── examples.md               # Usage examples
├── hex_viewer_cli.py         # Hex viewer for CLI
├── interactive_mode.py       # Interactive CLI mode
├── pipeline.py               # Command pipeline support
├── progress_manager.py       # Progress tracking
├── project_manager.py        # Project management
├── README.md                 # This file
├── terminal_dashboard.py     # Terminal dashboard
└── tutorial_system.py        # Tutorial system
```

## Key Features

### Binary Analysis
- Static and dynamic analysis
- Vulnerability detection
- Protection mechanism identification
- String extraction and analysis

### Payload Generation
- Multiple payload types (reverse shell, bind shell, etc.)
- Cross-platform support (x86, x64, ARM, ARM64)
- Encoding options (XOR, polymorphic, etc.)
- Template-based generation

### Command & Control
- Multi-protocol C2 server (HTTPS, DNS, TCP)
- Session management
- Remote command execution
- Encrypted communications

### AI Integration
- Automated script generation (Frida, Ghidra)
- Intelligent binary analysis
- Autonomous workflows
- Session persistence

## Requirements

- Python 3.8+
- Click (command-line framework)
- Various analysis libraries depending on features used

## Note

The CLI provides access to core Intellicrack functionality. Some advanced features may require additional dependencies or external tools (Frida, Ghidra, QEMU, etc.). Check individual command help for specific requirements.

## Command Categories

### Analysis Commands
```bash
--comprehensive              # Full analysis suite
--cfg-analysis               # Control flow graph
--symbolic-execution         # Symbolic execution
--concolic-execution         # Concolic execution
--taint-analysis            # Taint analysis
--rop-gadgets               # ROP gadget finding
--similarity-search         # Binary similarity
--multi-format              # Multi-format analysis
--section-analysis          # Section analysis
--import-export             # Import/export analysis
```

### Vulnerability Detection
```bash
--vulnerability-scan        # Static vulnerability scan
--weak-crypto              # Weak cryptography detection
--ml-vulnerability         # ML-based vulnerability prediction
--vuln-scan-depth {quick,normal,deep}  # Scan depth
```

### Protection Analysis
```bash
--detect-packing           # Packing/obfuscation detection
--detect-protections       # All known protections
--commercial-protections   # Commercial protection systems
--anti-debug              # Anti-debugging techniques
--license-analysis        # License mechanism analysis
```

### Network Analysis
```bash
--network-capture          # Network traffic capture
--protocol-fingerprint     # Protocol fingerprinting
--ssl-intercept           # SSL/TLS interception
--network-interface IFACE  # Network interface
--capture-duration SECS    # Capture duration
--capture-filter FILTER    # BPF filter
--pcap-file FILE          # Analyze PCAP file
--ssl-port PORT           # SSL port
--ssl-cert FILE           # SSL certificate
```

### Patching and Exploitation
```bash
--suggest-patches          # Generate patch suggestions
--apply-patch             # Apply patches from file
--patch-file FILE         # Patch definition file
--memory-patch            # Memory-only patching
--generate-payload        # Generate exploit payload
--payload-type {license,bypass,hook}  # Payload type
--payload-options OPTS    # Payload options (JSON)
--payload-output FILE     # Save payload to file
```

### Protection Bypass
```bash
--bypass-tpm              # TPM bypass generation
--tpm-method {api,virtual,patch}  # TPM bypass method
--bypass-vm-detection     # VM detection bypass
--aggressive-bypass       # Aggressive bypass techniques
--emulate-dongle          # Hardware dongle emulation
--dongle-type {safenet,hasp,codemeter}  # Dongle type
--dongle-id ID            # Dongle ID
--hwid-spoof              # HWID spoofing
--target-hwid HWID        # Target HWID
--time-bomb-defuser       # Time bomb defusion
--telemetry-blocker       # Telemetry blocking
```

### Machine Learning
```bash
--ml-similarity           # ML-based similarity
--ml-database PATH        # ML feature database
--train-model             # Train custom model
--training-data PATH      # Training data directory
--model-type {rf,nn,svm}  # Model type
--training-epochs NUM     # Training epochs
--save-model PATH         # Save trained model
--ml-model PATH           # Custom ML model
```

### External Tools
```bash
--ghidra-analysis         # Ghidra analysis
--ghidra-script SCRIPT    # Ghidra script
--radare2-analysis        # Radare2 analysis
--r2-commands CMDS        # Radare2 commands
--qemu-emulate           # QEMU emulation
--qemu-arch ARCH         # QEMU architecture
--qemu-snapshot          # Create QEMU snapshot
--frida-script SCRIPT    # Frida script
--frida-spawn            # Spawn process for Frida
```

### Processing Options
```bash
--gpu-accelerate         # GPU acceleration
--distributed            # Distributed processing
--distributed-backend {ray,dask}  # Distributed backend
--threads NUM            # Number of threads
--incremental            # Incremental analysis cache
--memory-optimized       # Memory-optimized loading
```

### Plugin System
```bash
--plugin-list            # List available plugins
--plugin-run PLUGIN      # Run specific plugin
--plugin-params PARAMS   # Plugin parameters (JSON)
--plugin-install PATH    # Install plugin
--plugin-remote          # Execute on remote server
--plugin-server SERVER   # Remote server address
--plugin-port PORT       # Remote server port
--plugin-sandbox         # Sandboxed execution
```

### Utility Features
```bash
--extract-icon           # Extract executable icon
--icon-output FILE       # Icon output path
--generate-report        # Generate detailed report
--report-format {pdf,html}  # Report format
--generate-license-key   # Generate license key
--license-algorithm ALG  # License algorithm
--ai-assistant          # AI assistant Q&A mode
--ai-question QUESTION  # Question for AI
--ai-context CONTEXT    # Context for AI
```

### Batch Processing
```bash
--batch FILE             # Batch process file list
--batch-output-dir DIR   # Batch output directory
--batch-parallel         # Parallel batch processing
```

### Output Options
```bash
--output FILE            # Output file path
--format {text,json,pdf,html}  # Output format
--verbose               # Verbose output
--quiet                 # Quiet mode
--no-color              # Disable colored output
```

### Advanced Options
```bash
--config FILE           # Custom configuration file
--timeout SECS          # Analysis timeout
--ignore-errors         # Continue on errors
--debug                 # Debug mode
```

### Special Modes
```bash
--server                # REST API server mode
--server-port PORT      # API server port
--watch                 # Watch file for changes
--watch-interval SECS   # Watch interval
```

## Usage Examples

### Complete Security Assessment
```bash
python intellicrack/cli/main.py protected.exe \
  --comprehensive \
  --vulnerability-scan \
  --detect-protections \
  --ml-vulnerability \
  --suggest-patches \
  --gpu-accelerate \
  --format pdf \
  --output security_report.pdf
```

### License Analysis and Bypass
```bash
python intellicrack/cli/main.py software.exe \
  --license-analysis \
  --detect-protections \
  --suggest-patches \
  --generate-payload --payload-type license \
  --bypass-tpm \
  --hwid-spoof \
  --generate-license-key \
  --time-bomb-defuser \
  --telemetry-blocker \
  --format json \
  --output bypass_config.json
```

### Network Protocol Analysis
```bash
python intellicrack/cli/main.py client.exe \
  --network-capture --capture-duration 120 \
  --protocol-fingerprint \
  --ssl-intercept \
  --format html \
  --output network_analysis.html
```

### Advanced Binary Analysis
```bash
python intellicrack/cli/main.py binary.exe \
  --cfg-analysis --cfg-output cfg.dot \
  --symbolic-execution \
  --concolic-execution \
  --taint-analysis \
  --rop-gadgets \
  --similarity-search --similarity-db database.db \
  --ai-assistant --ai-question "What are the main vulnerabilities?" \
  --format json \
  --output advanced_analysis.json
```

### Batch Protected Binary Analysis
```bash
python intellicrack/cli/main.py \
  --batch protected_samples.txt \
  --comprehensive \
  --ml-vulnerability \
  --gpu-accelerate \
  --batch-parallel \
  --threads 16 \
  --batch-output-dir reports/ \
  --format json
```

### Plugin Development and Testing
```bash
# List available plugins
python intellicrack/cli/main.py --plugin-list

# Run plugin locally
python intellicrack/cli/main.py binary.exe \
  --plugin-run custom_analyzer \
  --plugin-params '{"depth": 5}'

# Run plugin remotely
python intellicrack/cli/main.py binary.exe \
  --plugin-run custom_analyzer \
  --plugin-remote \
  --plugin-server analysis.server.com \
  --plugin-port 9999

# Run plugin in sandbox
python intellicrack/cli/main.py binary.exe \
  --plugin-run untrusted_plugin \
  --plugin-sandbox
```

### Machine Learning Workflows
```bash
# Train custom model
python intellicrack/cli/main.py \
  --train-model \
  --training-data /path/to/samples \
  --model-type rf \
  --training-epochs 100 \
  --save-model custom_model.pkl

# Use custom model for prediction
python intellicrack/cli/main.py binary.exe \
  --ml-vulnerability \
  --ml-model custom_model.pkl \
  --ml-similarity \
  --ml-database features.db
```

### Server and Monitoring Modes
```bash
# Run as REST API server
python intellicrack/cli/main.py --server --server-port 8080

# Watch file for changes
python intellicrack/cli/main.py binary.exe \
  --watch \
  --watch-interval 5 \
  --comprehensive
```

## Integration with Other Tools

### CI/CD Pipeline Integration
```bash
# Security scan in CI/CD
python intellicrack/cli/main.py build/app.exe \
  --vulnerability-scan \
  --detect-protections \
  --format json \
  --output security_scan.json \
  --quiet

# Check exit code for decisions
if [ $? -eq 0 ]; then
    echo "Security scan passed"
else
    echo "Security issues found"
    exit 1
fi
```

### Shell Pipeline Integration
```bash
# Use with other tools
python intellicrack/cli/main.py binary.exe --format json | \
  jq '.vulnerabilities[] | select(.severity == "high")' | \
  alert-system

# Generate multiple formats
python intellicrack/cli/main.py binary.exe --comprehensive \
  --output report.json --format json
python intellicrack/cli/main.py binary.exe --comprehensive \
  --output report.pdf --format pdf
```

## Performance Tips

1. **Use GPU acceleration** for large binaries: `--gpu-accelerate`
2. **Enable distributed processing** for batch jobs: `--distributed --threads 16`
3. **Use incremental analysis** for repeated analysis: `--incremental`
4. **Memory optimization** for large files: `--memory-optimized`
5. **Parallel batch processing** for multiple files: `--batch-parallel`

## Configuration

### Custom Configuration Files
```json
{
  "gpu_acceleration": true,
  "max_threads": 16,
  "analysis_timeout": 3600,
  "distributed_backend": "ray",
  "output_format": "json",
  "enable_verbose_logging": false
}
```

Use with: `--config custom_config.json`

## Error Handling

### Graceful Degradation
The CLI handles missing dependencies gracefully:
- GPU features fall back to CPU
- Missing tools are skipped with warnings
- Partial analysis continues if some modules fail

### Debug Mode
```bash
python intellicrack/cli/main.py binary.exe --debug --verbose
```

### Ignore Errors
```bash
python intellicrack/cli/main.py binary.exe --ignore-errors --batch files.txt
```

## Next Steps

See the following files for more details:
- `commands.md` - Complete command reference with all parameters
- `examples.md` - Detailed usage examples and workflows
- `../cli_usage.md` - Complete usage documentation

The Intellicrack CLI provides 100% feature parity with the GUI application, making it perfect for automation, testing, and headless deployments while maintaining the full power and flexibility of the complete Intellicrack suite.

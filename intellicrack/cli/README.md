# Intellicrack CLI - Complete Command Line Interface

This directory contains the comprehensive command-line interface for Intellicrack, providing access to **ALL 78 features** through command-line arguments.

## Quick Start

```bash
# Basic analysis
python intellicrack/cli/main.py binary.exe

# Comprehensive analysis
python intellicrack/cli/main.py binary.exe --comprehensive

# Full help with all commands
python intellicrack/cli/main.py --help

# Category-specific help
python intellicrack/cli/main.py --help-category analysis
```

## File Structure

```
intellicrack/cli/
├── main.py              # Main CLI script with all 78 features
├── README.md            # This file
├── commands.md          # Complete command reference
├── examples.md          # Usage examples and workflows
├── interactive.py       # Interactive mode (coming soon)
├── completion.sh        # Bash completion script (coming soon)
└── templates/           # Analysis templates (coming soon)
    ├── bypass.json
    ├── license.json
    └── network.json
```

## Complete Feature Coverage

The CLI provides access to every single Intellicrack feature through command-line arguments:

#### **Core Analysis Capabilities (15 features)**
1. `--skip-basic` / default: Static Binary Analysis (PE, ELF, Mach-O)
2. `--comprehensive`: Dynamic Runtime Analysis (Subprocess & Frida)
3. `--multi-format`: Multi-Format Binary Parsing & Manipulation (LIEF)
4. `--license-analysis`: Deep License Logic Analysis & Pattern Recognition
5. `--frida-script`: Deep Runtime Monitoring & API Hooking
6. `--cfg-analysis`: Control Flow Graph Generation & Analysis
7. `--symbolic-execution`: Symbolic Execution for Path Exploration (Angr)
8. `--concolic-execution`: Concolic Execution for Precise Path Finding (Manticore)
9. `--rop-gadgets`: ROP Chain Generation & Analysis (ROPgadget)
10. `--taint-analysis`: Taint Analysis for Data Flow Tracking
11. `--distributed`: Distributed Analysis Processing for Large Binaries
12. `--gpu-accelerate`: GPU-Accelerated Analysis
13. `--incremental`: Incremental Analysis Caching System
14. `--memory-optimized`: Memory-Optimized Loading for Very Large Binaries
15. `--qemu-emulate`: Full System Emulation (QEMU Integration)

#### **Advanced Vulnerability & Protection Detection (12 features)**
16. `--import-export`: Import/Export Table Analysis
17. `--section-analysis`: Section Analysis (Entropy, Permissions, Unusual Names)
18. `--weak-crypto`: Weak Cryptography Detection
19. `--license-analysis`: License Weakness Detection
20. `--detect-packing`: Obfuscation Detection (Packing, High Entropy)
21. `--comprehensive`: Self-Healing Code Detection
22. `--comprehensive`: Integrity/Checksum Verification Detection
23. `--commercial-protections`: Commercial Protection System Recognition
24. `--comprehensive`: Hardware Dongle Detection
25. `--comprehensive`: TPM Protection Usage Detection
26. `--bypass-vm-detection`: Virtualization/Container/Sandbox Detection
27. `--anti-debug`: Anti-Debugger Technique Detection

#### **Patching and Exploitation (8 features)**
28. `--suggest-patches`: Automated Patch Planning and Application
29. `--comprehensive`: AI-Driven Patching
30. `--apply-patch`: Static File Patching with Backups
31. `--memory-patch`: Memory Patching for Protected Binaries
32. `--generate-payload`: Runtime Patching Fallback (Frida-based)
33. `--generate-payload`: Automated Exploit Strategy Generation
34. `--generate-payload`: Advanced Payload Generation
35. `--comprehensive`: Patch Simulation and Verification

#### **Network and Protocol Analysis (6 features)**
36. `--network-capture`: Network Traffic Analysis & Capture
37. `--protocol-fingerprint`: Protocol Fingerprinting with Learning Mode
38. `--comprehensive`: Network License Server Emulation
39. `--comprehensive`: Cloud License Verification Interception
40. `--ssl-intercept`: SSL/TLS Interception for Encrypted Traffic
41. `--comprehensive`: Comprehensive Network API Hooking

#### **Protection Bypass Capabilities (8 features)**
42. `--emulate-dongle`: Hardware Dongle Emulation
43. `--bypass-tpm`: TPM Protection Bypass Strategies
44. `--bypass-vm-detection`: Virtualization/Container Detection Bypass
45. `--hwid-spoof`: HWID Spoofing (Frida Plugin)
46. `--comprehensive`: Anti-Debugger Countermeasures
47. `--time-bomb-defuser`: Time Bomb Defuser (Frida Plugin & API Hooks)
48. `--telemetry-blocker`: Telemetry Blocking (Frida Plugin & Network Hooks)
49. `--comprehensive`: Embedded/Encrypted Script Detection & Extraction

#### **Machine Learning Integration (5 features)**
50. `--ml-vulnerability`: ML-Based Vulnerability Prediction
51. `--similarity-search`: Binary Similarity Search
52. `--comprehensive`: Automated Feature Extraction for ML Models
53. `--ai-assistant`: AI Assistant for Guidance & Analysis
54. `--train-model`: AI Model Fine-tuning Interface

#### **External Tool Integration (3 features)**
55. `--ghidra-analysis`: Advanced Ghidra Analysis Integration
56. `--qemu-emulate`: QEMU System Emulation Integration
57. `--frida-script`: Frida Dynamic Instrumentation Integration

#### **Plugin System (6 features)**
1. `--plugin-list`: Self-Initializing Plugin Framework
2. `--plugin-run`: Custom Python Module Support
3. `--frida-script`: Frida Script Plugin Support
4. `--ghidra-script`: Ghidra Script Plugin Support
5. `--plugin-remote`: Remote Plugin Execution Framework
6. `--plugin-sandbox`: Sandboxed Plugin Execution

#### **User Interface and Experience (9 features)**
1. CLI interface: Comprehensive GUI alternative
2. `--help`: Guided Workflow Wizard (command-line version)
3. `--apply-patch`: Visual Patch Editor (JSON-based)
4. `--format text`: Editable Hex Viewer Widget (text output)
5. `--format pdf/html`: PDF and HTML Report Generation
6. `--generate-license-key`: License Key Generator Utility
7. `--format text`: Visual Network Traffic Analyzer (text output)
8. `--cfg-output`: Visual CFG Explorer (export to DOT/JSON)
9. Text-based themes: Theme Support (Light/Dark via colored output)

#### **System Features (6 features)**
1. Built-in: Persistent Logging with Rotation
2. Built-in: Automatic Dependency Management & Installation Checks
3. `--threads`: Multi-Threading for Long-Running Operations
4. `--train-model`: Custom AI Model Import & Fine-tuning Support
5. `--extract-icon`: Executable Icon Extraction for UI
6. Built-in: Memory Usage Optimization

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

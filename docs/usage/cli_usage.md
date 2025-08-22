# Intellicrack CLI Usage Guide

Intellicrack provides comprehensive command-line interface access to all 65 feasible features. This guide covers all CLI capabilities for testing, automation, and server deployments.

## Installation

Ensure Intellicrack is properly installed:
```bash
cd dependencies
./INSTALL.bat
```

## Basic Usage

### Quick Start
```bash
# Basic analysis
python scripts/intellicrack_cli.py binary.exe

# Full comprehensive analysis
python intellicrack/cli/main.py binary.exe --comprehensive

# Help and all options
python intellicrack/cli/main.py --help
```

### Alternative Entry Points
```bash
# After pip install
intellicrack-cli binary.exe --comprehensive

# Direct script execution
python intellicrack/cli/main.py binary.exe

# Via wrapper
./intellicrack_cli binary.exe
```

## Core Analysis Features

### Basic Analysis
```bash
# Skip basic analysis (for advanced-only workflows)
intellicrack_cli.py binary.exe --skip-basic

# Basic with JSON output
intellicrack_cli.py binary.exe --format json
```

### Control Flow Graph Analysis
```bash
# Generate CFG and export to DOT format
intellicrack_cli.py binary.exe --cfg-analysis --cfg-output cfg.dot

# Export as JSON
intellicrack_cli.py binary.exe --cfg-analysis --cfg-output cfg.json --cfg-format json
```

### Symbolic and Concolic Execution
```bash
# Symbolic execution from entry point
intellicrack_cli.py binary.exe --symbolic-execution

# Start from specific address
intellicrack_cli.py binary.exe --symbolic-execution --symbolic-address 0x401000

# Concolic execution with coverage target
intellicrack_cli.py binary.exe --concolic-execution --concolic-coverage 0.9
```

### Taint Analysis
```bash
# Basic taint analysis
intellicrack_cli.py binary.exe --taint-analysis

# With specific taint sources
intellicrack_cli.py binary.exe --taint-analysis --taint-sources "argv,stdin,network"
```

### ROP Gadget Analysis
```bash
# Find ROP gadgets
intellicrack_cli.py binary.exe --rop-gadgets

# Limit gadget count and generate chain
intellicrack_cli.py binary.exe --rop-gadgets --rop-max-gadgets 500 --rop-chain "execve"
```

### Binary Similarity Search
```bash
# Search for similar binaries
intellicrack_cli.py binary.exe --similarity-search --similarity-db /path/to/db

# Custom threshold
intellicrack_cli.py binary.exe --similarity-search --similarity-db db --similarity-threshold 0.7
```

### Multi-Format and Section Analysis
```bash
# Multi-format binary analysis
intellicrack_cli.py binary.exe --multi-format

# Section analysis (entropy, permissions)
intellicrack_cli.py binary.exe --section-analysis

# Import/export table analysis
intellicrack_cli.py binary.exe --import-export
```

## Vulnerability Detection

### Static Vulnerability Scanning
```bash
# Basic vulnerability scan
intellicrack_cli.py binary.exe --vulnerability-scan

# Deep scan with custom depth
intellicrack_cli.py binary.exe --vulnerability-scan --vuln-scan-depth deep

# Detect weak cryptography
intellicrack_cli.py binary.exe --weak-crypto
```

### Machine Learning Vulnerability Prediction
```bash
# ML-based vulnerability prediction
intellicrack_cli.py binary.exe --ml-vulnerability

# With custom model
intellicrack_cli.py binary.exe --ml-vulnerability --ml-model custom_model.pkl
```

## Protection Detection and Analysis

### Protection Detection
```bash
# Detect packing and obfuscation
intellicrack_cli.py binary.exe --detect-packing

# Scan for all known protections
intellicrack_cli.py binary.exe --detect-protections

# Commercial protection systems
intellicrack_cli.py binary.exe --commercial-protections

# Anti-debugging techniques
intellicrack_cli.py binary.exe --anti-debug
```

### License Analysis
```bash
# Deep license mechanism analysis
intellicrack_cli.py binary.exe --license-analysis
```

## Network Analysis

### Traffic Capture and Analysis
```bash
# Capture network traffic
intellicrack_cli.py binary.exe --network-capture --network-interface eth0 --capture-duration 60

# With custom filter
intellicrack_cli.py binary.exe --network-capture --capture-filter "port 443"

# Protocol fingerprinting
intellicrack_cli.py binary.exe --protocol-fingerprint

# Analyze existing PCAP
intellicrack_cli.py binary.exe --protocol-fingerprint --pcap-file capture.pcap
```

### SSL/TLS Interception
```bash
# Setup SSL interception
intellicrack_cli.py binary.exe --ssl-intercept --ssl-port 8443 --ssl-cert cert.pem
```

## Patching and Modification

### Patch Analysis and Generation
```bash
# Generate patch suggestions
intellicrack_cli.py binary.exe --suggest-patches

# Apply patches from file
intellicrack_cli.py binary.exe --apply-patch --patch-file patches.json

# Memory-only patching
intellicrack_cli.py binary.exe --apply-patch --patch-file patches.json --memory-patch
```

### Payload Generation
```bash
# Generate license bypass payload
intellicrack_cli.py binary.exe --generate-payload --payload-type license --payload-output payload.bin

# Generate hook payload with options
intellicrack_cli.py binary.exe --generate-payload --payload-type hook --payload-options '{"target": "CheckLicense"}'
```

## Protection Bypass

### TPM and VM Detection Bypass
```bash
# TPM bypass generation
intellicrack_cli.py binary.exe --bypass-tpm --tmp-method api

# VM detection bypass
intellicrack_cli.py binary.exe --bypass-vm-detection --aggressive-bypass
```

### Hardware Dongle Emulation
```bash
# Emulate SafeNet dongle
intellicrack_cli.py binary.exe --emulate-dongle --dongle-type safenet --dongle-id "12345678"

# HASP dongle emulation
intellicrack_cli.py binary.exe --emulate-dongle --dongle-type hasp
```

### HWID Spoofing
```bash
# Generate HWID spoofing config
intellicrack_cli.py binary.exe --hwid-spoof --target-hwid "DESKTOP-ABC123"
```

## Machine Learning Features

### Similarity Analysis and Model Training
```bash
# ML-based similarity analysis
intellicrack_cli.py binary.exe --ml-similarity --ml-database features.db

# Train custom model
intellicrack_cli.py --train-model --training-data /path/to/data --model-type rf --save-model model.pkl
```

## External Tool Integration

### Ghidra Integration
```bash
# Basic Ghidra analysis
intellicrack_cli.py binary.exe --ghidra-analysis

# With custom script
intellicrack_cli.py binary.exe --ghidra-analysis --ghidra-script custom_script.java
```

### Radare2 Integration
```bash
# Radare2 analysis
intellicrack_cli.py binary.exe --radare2-analysis

# With custom commands
intellicrack_cli.py binary.exe --radare2-analysis --r2-commands "aaa;pdf@main"
```

### QEMU Emulation
```bash
# QEMU emulation
intellicrack_cli.py binary.exe --qemu-emulate --qemu-arch x86_64

# With snapshot creation
intellicrack_cli.py binary.exe --qemu-emulate --qemu-snapshot
```

### Frida Scripting
```bash
# Run Frida script
intellicrack_cli.py binary.exe --frida-script script.js

# Spawn process mode
intellicrack_cli.py binary.exe --frida-script script.js --frida-spawn
```

## Processing and Performance Options

### GPU Acceleration
```bash
# Enable GPU acceleration
intellicrack_cli.py binary.exe --comprehensive --gpu-accelerate
```

### Distributed Processing
```bash
# Distributed analysis with Ray
intellicrack_cli.py binary.exe --comprehensive --distributed --threads 16

# With Dask backend
intellicrack_cli.py binary.exe --comprehensive --distributed --distributed-backend dask
```

### Memory Optimization
```bash
# Memory-optimized loading for large binaries
intellicrack_cli.py binary.exe --memory-optimized

# Incremental analysis with caching
intellicrack_cli.py binary.exe --incremental
```

## Plugin System

### Plugin Management
```bash
# List available plugins
intellicrack_cli.py --plugin-list

# Run specific plugin
intellicrack_cli.py binary.exe --plugin-run custom_analyzer

# With parameters
intellicrack_cli.py binary.exe --plugin-run custom_analyzer --plugin-params '{"depth": 5}'

# Install new plugin
intellicrack_cli.py --plugin-install /path/to/plugin.py
```

## Utility Features

### Icon Extraction
```bash
# Extract executable icon
intellicrack_cli.py binary.exe --extract-icon --icon-output icon.png
```

### Report Generation
```bash
# Generate detailed PDF report
intellicrack_cli.py binary.exe --comprehensive --generate-report --report-format pdf

# HTML report
intellicrack_cli.py binary.exe --comprehensive --generate-report --report-format html
```

## Advanced Workflows

### Batch Processing
```bash
# Process multiple files
intellicrack_cli.py --batch file_list.txt --comprehensive --batch-output-dir results/

# Parallel batch processing
intellicrack_cli.py --batch file_list.txt --comprehensive --batch-parallel --threads 8
```

### Server Mode
```bash
# Run as REST API server
intellicrack_cli.py --server --server-port 8080

# Test the API
curl -X POST -F "binary=@test.exe" -F "comprehensive=true" http://localhost:8080/analyze
```

### Watch Mode
```bash
# Watch file for changes and re-analyze
intellicrack_cli.py binary.exe --watch --watch-interval 10
```

## Output Formats

### JSON Output
```bash
# JSON for automation
intellicrack_cli.py binary.exe --comprehensive --format json --output results.json
```

### Text Reports
```bash
# Human-readable text
intellicrack_cli.py binary.exe --comprehensive --format text --output report.txt
```

### PDF and HTML Reports
```bash
# Professional PDF report
intellicrack_cli.py binary.exe --comprehensive --format pdf --output report.pdf

# Interactive HTML report
intellicrack_cli.py binary.exe --comprehensive --format html --output report.html
```

## Configuration and Advanced Options

### Custom Configuration
```bash
# Use custom config file
intellicrack_cli.py binary.exe --config custom_config.json
```

### Timeout and Error Handling
```bash
# Custom timeout
intellicrack_cli.py binary.exe --comprehensive --timeout 600

# Continue on errors
intellicrack_cli.py binary.exe --comprehensive --ignore-errors

# Debug mode
intellicrack_cli.py binary.exe --comprehensive --debug
```

### Verbose and Quiet Modes
```bash
# Verbose output
intellicrack_cli.py binary.exe --comprehensive --verbose

# Quiet mode (errors only)
intellicrack_cli.py binary.exe --comprehensive --quiet
```

## Example Complete Workflows

### Full Security Assessment
```bash
# Comprehensive security analysis
intellicrack_cli.py protected_software.exe \
  --comprehensive \
  --vulnerability-scan \
  --detect-protections \
  --ml-vulnerability \
  --suggest-patches \
  --gpu-accelerate \
  --format pdf \
  --output security_report.pdf
```

### License Bypass Development
```bash
# License analysis and bypass generation
intellicrack_cli.py software.exe \
  --license-analysis \
  --detect-protections \
  --suggest-patches \
  --generate-payload --payload-type license \
  --bypass-tpm \
  --hwid-spoof \
  --format json \
  --output bypass_config.json
```

### Network Protocol Analysis
```bash
# Network behavior analysis
intellicrack_cli.py client.exe \
  --network-capture --capture-duration 120 \
  --protocol-fingerprint \
  --ssl-intercept \
  --format html \
  --output network_analysis.html
```

### Batch License Protection Analysis
```bash
# Analyze protected software samples in batch
intellicrack_cli.py \
  --batch protected_samples.txt \
  --comprehensive \
  --ml-vulnerability \
  --gpu-accelerate \
  --batch-parallel \
  --threads 16 \
  --batch-output-dir protection_reports/ \
  --format json
```

## Integration with CI/CD

### Automated Security Scanning
```bash
# In CI pipeline
intellicrack_cli.py build/myapp.exe \
  --vulnerability-scan \
  --detect-protections \
  --format json \
  --output security_scan.json \
  --quiet

# Check exit code for CI/CD decisions
if [ $? -eq 0 ]; then
    echo "Security scan passed"
else
    echo "Security issues found"
    exit 1
fi
```

## Performance Tips

1. **Use GPU acceleration** for large binaries: `--gpu-accelerate`
2. **Enable distributed processing** for batch jobs: `--distributed --threads 16`
3. **Use incremental analysis** for repeated analysis: `--incremental`
4. **Memory optimization** for large files: `--memory-optimized`
5. **Parallel batch processing** for multiple files: `--batch-parallel`

## Troubleshooting

### Import Errors
```bash
# Check installation
cd dependencies && ./INSTALL.bat

# Test minimal functionality
intellicrack_cli.py --help

# Debug mode for detailed errors
intellicrack_cli.py binary.exe --debug
```

### Performance Issues
```bash
# Reduce analysis depth
intellicrack_cli.py binary.exe --quick

# Skip expensive operations
intellicrack_cli.py binary.exe --skip-basic --cfg-analysis

# Increase timeout
intellicrack_cli.py binary.exe --timeout 1200
```

The CLI provides access to all 65 feasible Intellicrack features, making it perfect for automation, testing, and headless environments while maintaining the full power of the GUI version.

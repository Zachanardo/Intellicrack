# CLI Command Reference

## Overview

Intellicrack provides a powerful command-line interface for automation, scripting, and headless operation. The CLI supports all major features available in the GUI.

## Installation

```bash
# After installing Intellicrack
pip install intellicrack

# Or use directly
python -m intellicrack.cli
```

## Basic Usage

```bash
# Basic syntax
intellicrack [command] [options] [target]

# Help
intellicrack --help
intellicrack [command] --help

# Version
intellicrack --version
```

## Global Options

| Option | Short | Description |
|--------|-------|-------------|
| `--verbose` | `-v` | Increase verbosity (can use multiple times) |
| `--quiet` | `-q` | Suppress non-error output |
| `--config` | `-c` | Path to config file |
| `--output` | `-o` | Output directory |
| `--format` | `-f` | Output format (json, yaml, txt, pdf) |
| `--no-color` | | Disable colored output |
| `--gpu` | | Enable GPU acceleration |
| `--threads` | `-t` | Number of threads to use |

## Commands

### analyze

Perform comprehensive binary analysis.

```bash
intellicrack analyze [options] <binary>

Options:
  --deep              Enable deep analysis
  --skip-strings      Skip string extraction
  --skip-crypto       Skip cryptographic analysis
  --skip-network      Skip network analysis
  --timeout SECONDS   Analysis timeout
  --profile PROFILE   Analysis profile (quick, standard, deep)

Examples:
  intellicrack analyze app.exe
  intellicrack analyze --deep --gpu protected_software.bin
  intellicrack analyze --profile quick --output results/ target.elf
```

### protect

Analyze protection mechanisms.

```bash
intellicrack protect [options] <binary>

Options:
  --detect-only       Only detect, don't analyze
  --bypass            Generate bypass strategies
  --risk-level LEVEL  Risk tolerance (low, medium, high)

Examples:
  intellicrack protect --bypass game.exe
  intellicrack protect --detect-only protected.dll
```

### patch

Apply patches to binaries.

```bash
intellicrack patch [options] <binary>

Options:
  --patch-file FILE   Load patches from file
  --backup            Create backup before patching
  --verify            Verify patches after applying
  --dry-run           Show what would be patched

Examples:
  intellicrack patch --patch-file bypass.json target.exe
  intellicrack patch --backup --verify app.exe
```

### exploit

Vulnerability analysis and exploit generation.

```bash
intellicrack exploit [options] <binary>

Options:
  --scan              Scan for vulnerabilities only
  --generate          Generate exploits
  --test              Test exploits (safe mode)
  --target OS         Target OS (windows, linux, macos)

Examples:
  intellicrack exploit --scan vulnerable.exe
  intellicrack exploit --generate --target linux service
```

### network

Network protocol analysis.

```bash
intellicrack network [options] <target>

Options:
  --capture           Start packet capture
  --analyze FILE      Analyze capture file
  --protocol PROTO    Focus on specific protocol
  --emulate           Start server emulation

Examples:
  intellicrack network --capture --protocol flexlm
  intellicrack network --analyze capture.pcap
  intellicrack network --emulate license-server
```

### ai

AI-powered analysis and assistance.

```bash
intellicrack ai [options] <command>

Subcommands:
  ask                 Ask AI a question
  analyze             AI-guided analysis
  generate            Generate scripts/code
  explain             Explain analysis results

Options:
  --model MODEL       Specify AI model
  --provider PROVIDER AI provider
  --context FILE      Additional context file

Examples:
  intellicrack ai ask "How to bypass ASLR?"
  intellicrack ai analyze --model gpt-4o binary.exe
  intellicrack ai generate ghidra-script --context analysis.json
```

### script

Script generation and execution.

```bash
intellicrack script [options] <type>

Types:
  frida               Frida scripts
  ghidra              Ghidra scripts
  radare2             Radare2 scripts

Options:
  --template TEMPLATE Use specific template
  --execute           Execute after generation
  --language LANG     Script language

Examples:
  intellicrack script frida --template anti-debug
  intellicrack script ghidra --execute decompile.py
```

### plugin

Plugin management.

```bash
intellicrack plugin [command] [options]

Commands:
  list                List installed plugins
  install             Install a plugin
  remove              Remove a plugin
  enable              Enable a plugin
  disable             Disable a plugin

Examples:
  intellicrack plugin list
  intellicrack plugin install custom-analyzer
  intellicrack plugin enable exploit-pack
```

### convert

File format conversion.

```bash
intellicrack convert [options] <input> <output>

Options:
  --format FORMAT     Output format
  --compress          Compress output
  --encrypt           Encrypt output

Examples:
  intellicrack convert analysis.json report.pdf
  intellicrack convert --format gguf model.bin model.gguf
```

## Advanced Usage

### Pipeline Mode

Chain multiple commands:

```bash
# Analyze, then patch based on findings
intellicrack analyze target.exe | intellicrack patch --auto

# Full automated workflow
intellicrack analyze app.exe \
  | intellicrack protect --bypass \
  | intellicrack patch --apply \
  | intellicrack verify
```

### Batch Processing

Process multiple files:

```bash
# Analyze all executables in directory
intellicrack analyze --batch "*.exe" --output results/

# With parallel processing
intellicrack analyze --batch binaries.txt --parallel 4
```

### Configuration File

Create `.intellicrack.yml`:

```yaml
defaults:
  output: ./results
  format: json
  gpu: true

analyze:
  profile: deep
  timeout: 3600

ai:
  provider: openai
  model: gpt-4o
```

Use with:
```bash
intellicrack --config .intellicrack.yml analyze target.exe
```

### Scripting Integration

```bash
# Python integration
python -c "from intellicrack.cli import analyze; analyze('target.exe')"

# Shell scripting
#!/bin/bash
for file in *.exe; do
    intellicrack analyze --quiet "$file" || echo "Failed: $file"
done
```

## Output Formats

### JSON Output
```bash
intellicrack analyze --format json app.exe > analysis.json
```

```json
{
  "file": "app.exe",
  "analysis": {
    "protections": ["aslr", "dep"],
    "vulnerabilities": [],
    "strings": ["License check failed", ...]
  }
}
```

### YAML Output
```bash
intellicrack analyze --format yaml app.exe
```

### PDF Reports
```bash
intellicrack analyze --format pdf --output report.pdf app.exe
```

## Environment Variables

| Variable | Description |
|----------|-------------|
| `INTELLICRACK_HOME` | Intellicrack installation directory |
| `INTELLICRACK_CONFIG` | Default config file path |
| `INTELLICRACK_GPU_TYPE` | GPU type (nvidia, amd, intel) |
| `INTELLICRACK_API_KEYS` | Path to API keys file |
| `INTELLICRACK_LOG_LEVEL` | Logging level |

## Exit Codes

| Code | Meaning |
|------|---------|
| 0 | Success |
| 1 | General error |
| 2 | Invalid arguments |
| 3 | File not found |
| 4 | Analysis failed |
| 5 | Timeout |
| 127 | Command not found |

## Examples

### Complete Analysis Workflow
```bash
#!/bin/bash
# Full analysis and reporting

TARGET="application.exe"
OUTPUT_DIR="./analysis_results"

# Create output directory
mkdir -p "$OUTPUT_DIR"

# Basic analysis
intellicrack analyze \
  --deep \
  --gpu \
  --output "$OUTPUT_DIR/basic_analysis.json" \
  "$TARGET"

# Protection analysis
intellicrack protect \
  --bypass \
  --risk-level medium \
  --output "$OUTPUT_DIR/protections.json" \
  "$TARGET"

# Vulnerability scan
intellicrack exploit \
  --scan \
  --output "$OUTPUT_DIR/vulnerabilities.json" \
  "$TARGET"

# Generate comprehensive report
intellicrack report \
  --input "$OUTPUT_DIR" \
  --format pdf \
  --output "$OUTPUT_DIR/final_report.pdf"
```

### AI-Assisted Reverse Engineering
```bash
# Use AI to guide analysis
intellicrack ai analyze \
  --model claude-3.5-sonnet \
  --context previous_analysis.json \
  protected_sample.exe \
  --output ai_analysis.json

# Generate bypass based on AI analysis
intellicrack ai generate \
  --type frida-script \
  --input ai_analysis.json \
  --output bypass_script.js
```

### Network License Analysis
```bash
# Capture license traffic
intellicrack network \
  --capture \
  --duration 60 \
  --filter "port 27000 or port 1947" \
  --output license_traffic.pcap

# Analyze and emulate
intellicrack network \
  --analyze license_traffic.pcap \
  --identify-protocol \
  --generate-emulator
```

## Tips

1. Use `--verbose` for debugging
2. Always use `--backup` when patching
3. GPU acceleration significantly speeds up analysis
4. Use configuration files for repeated tasks
5. Check exit codes in scripts
6. Use `--dry-run` to preview changes
7. Combine with standard Unix tools via pipes

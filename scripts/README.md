# Intellicrack Production-Readiness Scanner

A sophisticated Rust-based code analysis tool that detects non-production code, stubs, mocks, placeholders, and naive implementations across the Intellicrack codebase.

## Features

### Multi-Language Support
- **Python** - Primary analysis with full AST parsing
- **JavaScript** - Frida script analysis
- **Java** - Ghidra script analysis
- **Rust** - Launcher code analysis

### Detection Capabilities

#### Pass 1: Syntactic Stub Detection
- Empty function bodies (`pass`, `{}`)
- TODO/FIXME/PLACEHOLDER/STUB comments
- Single-line hardcoded returns

#### Pass 2: Semantic Analysis
- Function name vs implementation mismatch
- Missing file I/O for binary operations
- Missing external tool calls for analysis functions
- Domain-specific violations (keygen without crypto, etc.)

#### Pass 3: Data Flow Analysis
- Return value origin tracking
- Hardcoded data detection
- Input parameter usage validation

#### Pass 4: Call Graph Analysis
- Cross-function dependency analysis
- Stub detection through caller context
- Test vs production code separation

#### Pass 5: Domain-Specific Analysis (Intellicrack)
- **Keygen functions**: Must use RSA/ECDSA/cryptographic operations
- **Binary patchers**: Must perform actual file modifications
- **Frida hooks**: Must use Interceptor.attach/replace
- **Ghidra scripts**: Must call Ghidra API
- **License analyzers**: Must parse and validate data

#### Pass 6: Import-Usage Correlation
- Detects imported but unused libraries
- Flags functions with relevant imports that aren't used

#### Pass 7: Complexity Metrics
- Cyclomatic complexity analysis
- Lines of code vs function purpose
- Halstead metrics

#### Pass 8: Naive Implementation Detection
Detects simple implementations that won't work against real-world protection:

- **Weak Encryption**: XOR instead of AES/RSA, character-by-character encryption
- **Insecure Key Generation**: `random` instead of `secrets`, time-based keys without crypto
- **Trivial Validation**: Simple equality checks, no cryptographic verification
- **Bypassable Anti-Debug**: Simple IsDebuggerPresent, naive VM detection
- **Ineffective Obfuscation**: Base64 encoding (not encryption)
- **Inadequate Binary Patching**: String replace on compiled code, NOP without alignment
- **Weak Brute Force**: Small iteration ranges
- **Missing Disassembly Framework**: Decompilation without Capstone/IDA/Ghidra
- **Insufficient Unpacking**: Relying only on UPX for commercial packers
- **Simple Regex Extraction**: Won't find obfuscated keys
- **Spoofable Hardware ID**: Simple MAC address checks
- **Clock-Based Trial**: Easily bypassed with system time manipulation

### Exclusion System (Minimizes False Positives)

**Automatically excludes**:
- Test files (in `tests/` directory)
- Example/template code
- Fallback classes (PyQt6 import fallbacks)
- Abstract base classes (with NotImplementedError)
- Configuration getters
- Property decorators
- Intentional error handlers

**Deduction scoring**:
- Has logging statements (-30 points)
- Has proper error handling (-20 points)
- Uses external tools/binary ops (-60 points)
- Has type hints (-10 points)
- Is pytest fixture (-100 points)

### Confidence Levels

- **CRITICAL** (100+ score): 99-100% confidence - Production blockers
- **HIGH** (70-99 score): 85-95% confidence - Require implementation
- **MEDIUM** (45-69 score): 65-80% confidence - Should review
- **LOW** (25-44 score): 40-60% confidence - Manual verification needed
- **INFO** (<25 score): Informational - May be intentional

## Installation

### Prerequisites
- Rust toolchain (1.70+): https://rustup.rs/
- Windows with MSYS/Git Bash

### Quick Start

```batch
cd D:\Intellicrack\scripts
scan.bat
```

This will:
1. Check for Rust toolchain
2. Compile the scanner with maximum optimization
3. Run full scan on Intellicrack codebase
4. Display results in colored console output
5. Optionally export to JSON

### Manual Build

```bash
cd scripts
cargo build --release --manifest-path=Cargo.toml
```

Binary location: `target/release/scanner.exe`

## Usage

### Basic Scan
```bash
scanner.exe D:\Intellicrack
```

### Console Output (default)
```bash
scanner.exe D:\Intellicrack --format console --confidence medium
```

### JSON Export
```bash
scanner.exe D:\Intellicrack --format json --confidence high > results.json
```

### Verbose Mode (includes LOW confidence)
```bash
scanner.exe D:\Intellicrack --format console --confidence low --verbose
```

## Output Format

### Console Output
```
╔══════════════════════════════════════════════════════════════╗
║    INTELLICRACK PRODUCTION-READINESS SCAN RESULTS            ║
╚══════════════════════════════════════════════════════════════╝

Total Issues Found: 47
  Critical: 12 | High: 18 | Medium: 15 | Low: 2

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

🔴 CRITICAL (12 issues)

intellicrack/core/keygen_generator.py:145
  ├─ [1] generate_license_key (Line 145, Col 4)
  ├─ Confidence: 100% (CRITICAL)
  ├─ Issue: Returns hardcoded string without cryptographic operations
  ├─ Evidence:
  │   • Single-line hardcoded literal return (+40 points)
  │   • Function name implies complex operation (+30 points)
  │   • Keygen function without cryptographic operations (+40 points)
  │   • Total Score: 110
  ├─ Expected: Should use RSA/ECDSA to generate unique keys
  └─ Fix: Implement cryptographic key generation using Crypto library
```

### JSON Output
```json
{
  "scan_info": {
    "timestamp": "2025-11-01T15:30:00Z",
    "files_scanned": {"python": 1143, "rust": 25, "javascript": 48},
    "total_issues": 47
  },
  "issues": [
    {
      "id": 1,
      "file": "intellicrack/core/keygen_generator.py",
      "line": 145,
      "function": "generate_license_key",
      "severity": "critical",
      "confidence": 100,
      "issue_type": "hardcoded_return",
      "description": "Returns hardcoded string...",
      "evidence": [...],
      "suggested_fix": "Implement real keygen..."
    }
  ]
}
```

## Performance

- **Files scanned**: 1,200+ source files
- **Scan time**: 60-120 seconds (full codebase)
- **Memory usage**: ~500MB-1GB
- **CPU**: Parallel processing (uses all cores)
- **First build**: 2-3 minutes (downloads dependencies)
- **Subsequent builds**: 30-60 seconds

## Configuration

Edit `production_scanner.rs` constants:

```rust
const DEFAULT_ROOT: &str = "D:\\Intellicrack";
const DEFAULT_CONFIDENCE: ConfidenceLevel = ConfidenceLevel::Medium;
const MAX_THREADS: usize = 16; // or num_cpus::get()
```

## Architecture

### Single-File Monolith
- **Total**: ~1,500 lines of production Rust
- **No external files**: Everything in `production_scanner.rs`
- **Self-contained**: Tree-sitter queries embedded

### Modules (within single file)
- `file_scanner`: Directory traversal, file classification
- `ast_parser`: Tree-sitter integration
- `extractors`: Function/import/call extraction
- `detectors`: 8 detection passes
- `exclusions`: False positive reduction
- `scorer`: Weighted scoring engine
- `reporters`: Console/JSON output

## Troubleshooting

### Build Errors

**"cargo not found"**
```bash
# Install Rust
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
# Or Windows: https://rustup.rs/
```

**"linking with `link.exe` failed"**
```bash
# Install Visual Studio Build Tools
# Or use MSYS2/MinGW toolchain
```

### Runtime Errors

**"tree-sitter parse failed"**
- Check file encoding (must be UTF-8)
- Some generated files may have syntax errors

**"Permission denied"**
- Run from directory with read access
- Don't scan locked/system directories

### False Positives

If legitimate code is flagged:
1. Check if it matches exclusion rules
2. Add deduction patterns in `calculate_deductions()`
3. Adjust scoring thresholds

### False Negatives

If stubs aren't detected:
1. Add pattern to relevant detection pass
2. Check function extraction is working
3. Verify imports are being tracked

## Development

### Adding New Detection Patterns

```rust
fn detect_new_pattern(func: &FunctionInfo) -> Vec<(String, i32)> {
    let mut issues = Vec::new();

    if func.name.contains("pattern") {
        if /* condition */ {
            issues.push(("Description".to_string(), score));
        }
    }

    issues
}
```

Then add to `analyze_file()`:
```rust
for (pattern, points) in detect_new_pattern(func) {
    evidence.push(Evidence { ... });
    score += points;
}
```

### Adjusting Scores

Edit detection functions:
```rust
("Pattern description".to_string(), 40) // Change score here
```

### Adding Language Support

1. Add to `LanguageType` enum
2. Add tree-sitter dependency in `Cargo.toml`
3. Add query in `file_query()` method
4. Add extractor function (`extract_X_functions`)

## CI/CD Integration

### GitHub Actions
```yaml
- name: Run Production Scanner
  run: |
    cd scripts
    cargo build --release
    ../target/release/scanner.exe . --format json > scan-results.json

- name: Check Critical Issues
  run: |
    CRITICAL=$(jq '.issues[] | select(.severity=="critical") | length' scan-results.json)
    if [ "$CRITICAL" -gt 0 ]; then exit 1; fi
```

### Pre-commit Hook
```bash
#!/bin/bash
scripts/target/release/scanner.exe . --format console --confidence critical
if [ $? -ne 0 ]; then
    echo "❌ Critical production issues found!"
    exit 1
fi
```

## License

Part of the Intellicrack project - for authorized security research and defensive security purposes only.

## Support

For issues or questions:
1. Check this README
2. Review hook validation log: `F:\Temp\hook-validation.log`
3. Check Rust compilation errors
4. Review scanner source code comments

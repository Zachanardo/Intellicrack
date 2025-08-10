# Scan Modes Reference Guide

The ICP Engine offers five distinct scan modes, each optimized for different analysis scenarios. Understanding when and how to use each mode is crucial for effective protection analysis.

## Overview

Scan modes control the depth and thoroughness of protection analysis, trading speed for detection accuracy:

```
Speed vs Accuracy Trade-off:

NORMAL     ██████████                    (Fastest)
DEEP       ███████████████               (Balanced)
HEURISTIC  ███████████████               (Behavioral)
AGGRESSIVE ████████████████████          (Thorough)
ALL        ████████████████████████████  (Complete)

           ↑                         ↑
        Speed                   Accuracy
```

## Scan Mode Details

### NORMAL Mode

**Purpose**: Fast analysis for initial triage and batch processing

**Technical Details:**
- **die-python Flag**: `0` (no special flags)
- **Analysis Type**: Signature-based detection only
- **Pattern Matching**: Basic known signatures
- **Heuristics**: Disabled

**Performance Characteristics:**
- **Average Speed**: 0.02-0.04 seconds per file
- **Memory Usage**: Low (< 10MB overhead)
- **CPU Utilization**: Minimal
- **Best For**: Large batches, quick screening

**Detection Coverage:**
- **Common Packers**: UPX, PECompact, ASPack
- **Popular Protectors**: Basic VMProtect, Themida signatures
- **Standard Formats**: PE, ELF header-based detection
- **Limitations**: May miss custom or modified protections

**Use Cases:**
```
✓ Initial file triage
✓ Batch processing large datasets
✓ Quick "is it packed?" checks
✓ Performance-critical environments
✓ Known sample analysis

✗ Unknown protection research
✗ Custom protection analysis
✗ Detailed investigation
✗ Comprehensive reports
```

**Example Output:**
```
File: sample.exe
Detections:
├─ [PACKER] UPX
└─ [PROTECTOR] VMProtect

Analysis Time: 0.03 seconds
Confidence: Medium
```

### DEEP Mode

**Purpose**: Thorough analysis with extended pattern matching

**Technical Details:**
- **die-python Flag**: `1` (DEEP_SCAN)
- **Analysis Type**: Extended signature database
- **Pattern Matching**: Deep binary scanning
- **Heuristics**: Basic behavioral analysis

**Performance Characteristics:**
- **Average Speed**: 0.05-0.15 seconds per file
- **Memory Usage**: Moderate (20-30MB overhead)
- **CPU Utilization**: Moderate
- **Best For**: Regular analysis workflow

**Detection Coverage:**
- **Comprehensive Packers**: All major packers and variants
- **Protector Versions**: Specific version identification
- **Custom Modifications**: Modified packer detection
- **Embedded Resources**: Protection in resources/overlays

**Use Cases:**
```
✓ Standard analysis workflow
✓ Research and investigation
✓ Version-specific detection
✓ Detailed protection mapping
✓ Production analysis pipelines

✗ Large batch processing
✗ Time-critical analysis
✗ Resource-constrained systems
```

**Example Output:**
```
File: sample.exe
Detections:
├─ [PACKER] UPX 3.96 (modified)
├─ [PROTECTOR] VMProtect 3.5.1
├─ [ANTI-DEBUG] IsDebuggerPresent check
└─ [OBFUSCATOR] Control flow flattening

Analysis Time: 0.08 seconds
Confidence: High
```

### HEURISTIC Mode

**Purpose**: Behavioral and pattern-based detection for unknown protections

**Technical Details:**
- **die-python Flag**: `2` (HEURISTIC_SCAN)
- **Analysis Type**: Behavioral pattern analysis
- **Pattern Matching**: Statistical and entropy analysis
- **Heuristics**: Advanced behavioral detection

**Performance Characteristics:**
- **Average Speed**: 0.1-0.3 seconds per file
- **Memory Usage**: Moderate (25-40MB overhead)
- **CPU Utilization**: Moderate to high
- **Best For**: Unknown protection research

**Detection Coverage:**
- **Unknown Protections**: Novel or custom protection schemes
- **Behavioral Patterns**: Anti-analysis behaviors
- **Statistical Analysis**: Entropy, compression ratios
- **Code Patterns**: Obfuscation and packing indicators

**Use Cases:**
```
✓ Research on unknown samples
✓ Custom protection analysis
✓ Zero-day protection detection
✓ Academic research
✓ License protection analysis

✗ Known protection analysis
✗ Speed-critical applications
✗ Batch processing workflows
```

**Example Output:**
```
File: sample.exe
Detections:
├─ [HEURISTIC] High entropy sections (98.7%)
├─ [HEURISTIC] Unusual import patterns
├─ [HEURISTIC] Anti-VM instructions detected
├─ [PROTECTOR] Unknown protector (signature: 0x4A3B2C1D)
└─ [BEHAVIOR] Dynamic API resolution

Analysis Time: 0.23 seconds
Confidence: Medium-High
```

### AGGRESSIVE Mode

**Purpose**: Maximum detection coverage combining deep and heuristic analysis

**Technical Details:**
- **die-python Flag**: `3` (DEEP_SCAN | HEURISTIC_SCAN)
- **Analysis Type**: Combined signature + behavioral
- **Pattern Matching**: Full signature database + heuristics
- **Heuristics**: All available detection methods

**Performance Characteristics:**
- **Average Speed**: 0.2-0.8 seconds per file
- **Memory Usage**: High (50-80MB overhead)
- **CPU Utilization**: High
- **Best For**: Comprehensive analysis

**Detection Coverage:**
- **Maximum Coverage**: All available detection methods
- **Multi-Layer Protection**: Complex protection stacks
- **Variant Detection**: Modified and custom versions
- **Complete Analysis**: No stone left unturned

**Use Cases:**
```
✓ Comprehensive investigation
✓ Important sample analysis
✓ Multi-layer protection research
✓ Final verification analysis
✓ Detailed reporting

✗ Routine analysis
✗ Batch processing
✗ Time-sensitive analysis
✗ Resource-limited systems
```

**Example Output:**
```
File: sample.exe
Detections:
├─ [PACKER] UPX 3.96 (modified, scrambled headers)
├─ [PROTECTOR] VMProtect 3.5.1 (virtualized sections)
├─ [CRYPTOR] Custom XOR encryption (key: 0xDEADBEEF)
├─ [ANTI-DEBUG] Multiple anti-debugging techniques
├─ [ANTI-VM] VMware detection routines
├─ [HEURISTIC] Code injection patterns
├─ [HEURISTIC] Suspicious API call sequences
└─ [BEHAVIOR] Self-modifying code detected

Analysis Time: 0.54 seconds
Confidence: Very High
```

### ALL Mode

**Purpose**: Complete analysis with all available scanning techniques

**Technical Details:**
- **die-python Flag**: `7` (all flags enabled)
- **Analysis Type**: Every available analysis method
- **Pattern Matching**: Complete signature database
- **Heuristics**: All heuristic engines enabled

**Performance Characteristics:**
- **Average Speed**: 0.5-2.0 seconds per file
- **Memory Usage**: Very High (100MB+ overhead)
- **CPU Utilization**: Maximum
- **Best For**: Critical sample analysis

**Detection Coverage:**
- **Absolute Maximum**: Every possible detection method
- **Experimental Features**: Cutting-edge detection algorithms
- **Deep Analysis**: Multiple analysis passes
- **Research Quality**: Academic-grade thoroughness

**Use Cases:**
```
✓ Critical sample investigation
✓ Research and development
✓ Forensic analysis
✓ Competition/CTF analysis
✓ Publication-quality results

✗ Regular workflow
✗ Production environments
✗ Automated processing
✗ Time-critical analysis
```

**Example Output:**
```
File: sample.exe
Detections:
├─ [PACKER] UPX 3.96 (modified, entropy: 7.89)
├─ [PROTECTOR] VMProtect 3.5.1 (95% virtualized)
├─ [CRYPTOR] Custom encryption (AES-256-CBC detected)
├─ [ANTI-DEBUG] 12 anti-debugging techniques
├─ [ANTI-VM] VMware, VirtualBox, Hyper-V detection
├─ [ANTI-ANALYSIS] Debugger timing checks
├─ [OBFUSCATOR] Control flow obfuscation (complexity: 8.2)
├─ [HEURISTIC] Polymorphic code patterns
├─ [HEURISTIC] Suspicious string encryption
├─ [BEHAVIOR] Runtime packer detection
├─ [BEHAVIOR] Dynamic import resolution
└─ [EXPERIMENTAL] ML-based protection classification

Analysis Time: 1.32 seconds
Confidence: Maximum
```

## Performance Comparison

### Speed Benchmarks

Based on Phase 5 testing with die-python v0.4.0:

| Mode | Avg Time | Range | Typical File Size |
|------|----------|-------|-------------------|
| NORMAL | 0.03s | 0.02-0.04s | 1-10MB |
| DEEP | 0.08s | 0.05-0.15s | 1-10MB |
| HEURISTIC | 0.18s | 0.10-0.30s | 1-10MB |
| AGGRESSIVE | 0.45s | 0.20-0.80s | 1-10MB |
| ALL | 1.10s | 0.50-2.00s | 1-10MB |

### Memory Usage

| Mode | Base Memory | Peak Memory | Concurrent Limit |
|------|-------------|-------------|------------------|
| NORMAL | 8MB | 15MB | 8+ files |
| DEEP | 20MB | 35MB | 6 files |
| HEURISTIC | 25MB | 45MB | 4 files |
| AGGRESSIVE | 50MB | 85MB | 2 files |
| ALL | 80MB | 150MB | 1 file |

## Selection Guidelines

### Decision Tree

```
Start Analysis
     │
     ▼
Is this initial triage? ────YES───► NORMAL mode
     │
     NO
     ▼
Is speed critical? ────YES───► NORMAL or DEEP mode
     │
     NO
     ▼
Is protection unknown? ────YES───► HEURISTIC mode
     │
     NO
     ▼
Need comprehensive analysis? ────YES───► AGGRESSIVE mode
     │
     NO
     ▼
Is this research/forensic? ────YES───► ALL mode
     │
     NO
     ▼
Use DEEP mode (default)
```

### Scenario-Based Recommendations

**Scenario 1: License Bypass Triage**
```
Files: 1000+ protected samples
Goal: Quick categorization
Recommendation: NORMAL mode
Rationale: Speed over accuracy for initial sorting
```

**Scenario 2: Software Research**
```
Files: 10-50 commercial applications
Goal: Protection identification
Recommendation: DEEP mode
Rationale: Balanced speed and accuracy
```

**Scenario 3: Unknown Sample Investigation**
```
Files: 1-5 suspicious samples
Goal: Complete understanding
Recommendation: HEURISTIC → AGGRESSIVE progression
Rationale: Start behavioral, escalate if needed
```

**Scenario 4: Forensic Analysis**
```
Files: 1-2 critical evidence files
Goal: Court-admissible results
Recommendation: ALL mode
Rationale: Maximum thoroughness and documentation
```

**Scenario 5: CTF Competition**
```
Files: 1 challenge binary
Goal: Find protection bypass route
Recommendation: ALL mode
Rationale: No time to miss any details
```

## Mode Switching Strategies

### Progressive Analysis

Start with lighter modes and escalate as needed:

```
Stage 1: NORMAL scan
    ├─ No detections found ─────► Stage 2: HEURISTIC scan
    ├─ Simple protections ─────► Analysis complete
    └─ Complex protections ────► Stage 2: DEEP scan

Stage 2: Detailed analysis
    ├─ DEEP scan results ──────► Stage 3: AGGRESSIVE (if incomplete)
    ├─ HEURISTIC results ──────► Stage 3: DEEP (for verification)
    └─ Conflicting results ────► Stage 3: ALL mode

Stage 3: Maximum analysis
    └─ ALL mode ───────────────► Final results
```

### Comparative Analysis

Use multiple modes for verification:

```
Workflow: Multi-Mode Verification
1. Run NORMAL scan for baseline
2. Run DEEP scan for comprehensive detection
3. Run HEURISTIC scan for behavioral analysis
4. Compare results for consistency
5. Investigate any discrepancies
```

## Troubleshooting Scan Modes

### Common Issues

**Issue: Mode Selection Grayed Out**
- **Cause**: Analysis in progress
- **Solution**: Wait for completion or cancel current analysis

**Issue: Unexpected Mode Performance**
- **Cause**: System resources or file complexity
- **Solution**: Check system load, try different file

**Issue: Mode Results Inconsistent**
- **Cause**: Different detection algorithms
- **Solution**: This is normal; use multiple modes for verification

### Performance Optimization

**For System Resource Management:**
```
High Memory Usage:
├─ Close other applications
├─ Reduce concurrent analysis limit
├─ Use lighter scan modes
└─ Restart application if needed

High CPU Usage:
├─ Lower scan mode complexity
├─ Reduce parallel analysis
├─ Close background processes
└─ Monitor system temperature
```

**For Analysis Speed:**
```
Slow Analysis:
├─ Check file size and complexity
├─ Verify die-python installation
├─ Update to latest ICP version
├─ Use SSD storage for temporary files
└─ Increase analysis timeout
```

## Advanced Configuration

### Custom Scan Profiles

Create custom combinations for specific needs:

```python
# Example: Custom license protection analysis profile
LICENSE_ANALYSIS_PROFILE = {
    "flags": DEEP_SCAN | HEURISTIC_SCAN,
    "timeout": 60,
    "memory_limit": "512MB",
    "focus": ["packers", "protectors", "anti-analysis"]
}
```

### Batch Processing Recommendations

For processing multiple files efficiently:

**Small Batches (< 10 files):**
- Use DEEP mode for good balance
- Process files sequentially
- Monitor individual results

**Medium Batches (10-100 files):**
- Use NORMAL mode for speed
- Enable parallel processing (4 concurrent)
- Review high-confidence results only

**Large Batches (100+ files):**
- Use NORMAL mode exclusively
- Maximum parallel processing
- Export results for offline analysis
- Focus on anomalies and outliers

## Integration with Analysis Workflow

### With Other Intellicrack Tools

**Hex Editor Integration:**
- Use DEEP mode results to guide hex analysis
- Jump to protection signatures in hex view
- Plan patches based on detection details

**Disassembly Integration:**
- Use AGGRESSIVE mode for entry point analysis
- HEURISTIC mode for behavioral pattern confirmation
- ALL mode for comprehensive disassembly planning

**AI Script Generation:**
- DEEP mode provides sufficient detail for script generation
- AGGRESSIVE mode gives comprehensive bypass information
- ALL mode enables advanced script optimization

---

*For more information on interpreting scan results, see the [Result Interpretation Guide](result_interpretation.md).*

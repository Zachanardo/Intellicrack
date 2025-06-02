# Intellicrack CLI - Advanced Features Examples

This document demonstrates the 7 new advanced features added to the Intellicrack CLI.

## GUI Integration Features

### 1. Launch GUI with Results
```bash
# Analyze a binary and launch GUI with results
python scripts/cli/main.py malware.exe --comprehensive --launch-gui

# Combine with other analysis options
python scripts/cli/main.py target.exe \
  --vulnerability-scan \
  --detect-protections \
  --launch-gui
```

### 2. Export to GUI Format
```bash
# Export analysis results for later GUI viewing
python scripts/cli/main.py binary.exe \
  --comprehensive \
  --gui-export analysis_results.gui.json

# Load in GUI later:
# python -m intellicrack.ui.main_app --load-results analysis_results.gui.json
```

### 3. Visual CFG Generation
```bash
# Generate visual control flow graph
python scripts/cli/main.py binary.exe \
  --cfg-analysis \
  --visual-cfg \
  --visual-cfg-output my_cfg.png

# Generate high-res CFG for presentation
python scripts/cli/main.py binary.exe \
  --cfg-analysis \
  --visual-cfg \
  --visual-cfg-output presentation_cfg.svg
```

### 4. Interactive Hex Editor
```bash
# Launch hex editor after analysis
python scripts/cli/main.py binary.exe \
  --section-analysis \
  --interactive-hex

# Quick hex view of suspicious file
python scripts/cli/main.py suspicious.bin \
  --skip-basic \
  --interactive-hex
```

## Performance and Debugging Features

### 5. Developer Debug Mode
```bash
# Enable detailed debug tracing
python scripts/cli/main.py binary.exe \
  --debug-mode \
  --symbolic-execution

# Debug with verbose output
python scripts/cli/main.py binary.exe \
  --debug-mode \
  --verbose \
  --timeout 600
```

### 6. Performance Profiling
```bash
# Profile performance of analysis
python scripts/cli/main.py large_binary.exe \
  --comprehensive \
  --profile-performance

# Profile specific expensive operations
python scripts/cli/main.py binary.exe \
  --symbolic-execution \
  --concolic-execution \
  --profile-performance \
  --output perf_report.json
```

### 7. Memory Usage Tracking
```bash
# Track memory usage during analysis
python scripts/cli/main.py huge_binary.exe \
  --comprehensive \
  --memory-trace

# Memory optimization with tracking
python scripts/cli/main.py binary.exe \
  --memory-optimized \
  --memory-trace \
  --gpu-accelerate
```

## Complete Workflow Examples

### Security Assessment with Visual Output
```bash
python scripts/cli/main.py malware.exe \
  --comprehensive \
  --vulnerability-scan \
  --detect-protections \
  --cfg-analysis \
  --visual-cfg \
  --visual-cfg-output malware_flow.png \
  --gui-export malware_analysis.gui.json \
  --format pdf \
  --output malware_report.pdf
```

### Performance-Optimized Batch Analysis
```bash
python scripts/cli/main.py \
  --batch samples.txt \
  --comprehensive \
  --gpu-accelerate \
  --distributed \
  --profile-performance \
  --memory-trace \
  --batch-output-dir optimized_results/
```

### Debug Mode for Development
```bash
python scripts/cli/main.py test_binary.exe \
  --debug-mode \
  --profile-performance \
  --memory-trace \
  --symbolic-execution \
  --timeout 1200 \
  --output debug_analysis.json
```

### Interactive Analysis Session
```bash
# Start with basic analysis
python scripts/cli/main.py unknown.exe --quick

# If suspicious, do deeper analysis with visual output
python scripts/cli/main.py unknown.exe \
  --license-analysis \
  --detect-protections \
  --cfg-analysis \
  --visual-cfg

# Launch hex editor to inspect specific sections
python scripts/cli/main.py unknown.exe \
  --interactive-hex

# Finally, launch full GUI for detailed exploration
python scripts/cli/main.py unknown.exe \
  --comprehensive \
  --launch-gui
```

## Integration with Development Workflow

### CI/CD Pipeline with Performance Monitoring
```bash
#!/bin/bash
# ci-security-check.sh

# Run analysis with performance tracking
python scripts/cli/main.py build/app.exe \
  --vulnerability-scan \
  --detect-protections \
  --profile-performance \
  --memory-trace \
  --gui-export ci_results.gui.json \
  --format json \
  --output ci_analysis.json

# Check if performance is acceptable
ANALYSIS_TIME=$(jq '.analysis_time' ci_analysis.json)
if (( $(echo "$ANALYSIS_TIME > 300" | bc -l) )); then
    echo "Analysis took too long: ${ANALYSIS_TIME}s"
    exit 1
fi

# Check memory usage
MEM_INCREASE=$(jq '.memory_trace.increase_mb' ci_analysis.json)
if (( $(echo "$MEM_INCREASE > 1024" | bc -l) )); then
    echo "Excessive memory usage: ${MEM_INCREASE}MB"
    exit 1
fi
```

### Development Debug Workflow
```bash
# Enable all debugging features
export INTELLICRACK_DEBUG=1

python scripts/cli/main.py dev_binary.exe \
  --debug-mode \
  --profile-performance \
  --memory-trace \
  --verbose \
  --ai-assistant \
  --ai-question "What are the performance bottlenecks?" \
  --gui-export debug_session.gui.json

# View results in GUI for detailed analysis
python -m intellicrack.ui.main_app --load-results debug_session.gui.json
```

## Tips and Best Practices

1. **Visual CFG Generation**:
   - Requires `matplotlib` and `networkx` packages
   - Use SVG format for scalable diagrams
   - PNG format is better for embedding in reports

2. **Performance Profiling**:
   - Adds ~5-10% overhead to analysis time
   - Top 30 functions are shown by default
   - Results included in JSON output for automation

3. **Memory Tracing**:
   - Requires `psutil` package for accurate tracking
   - Shows top 10 memory allocation points
   - Useful for optimizing large binary analysis

4. **GUI Export Format**:
   - Includes all analysis results
   - Preserves command-line used
   - Can be loaded in GUI for full interactivity

5. **Debug Mode**:
   - Generates extensive logs
   - Traces all function calls
   - Best used with `--timeout` to prevent hanging

6. **Interactive Hex Editor**:
   - Tries integrated hex viewer first
   - Falls back to system hex editors
   - Supports HxD, Notepad++, hexedit, ghex

7. **Combining Features**:
   - All 7 features can be used together
   - Performance features help optimize workflows
   - GUI features bridge CLI and visual analysis

These advanced features make the Intellicrack CLI even more powerful for both automated analysis and interactive debugging sessions.
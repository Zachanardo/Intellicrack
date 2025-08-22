# Intellicrack CLI Enhancements Demo

This document showcases the new CLI enhancements implemented for Intellicrack, demonstrating practical usage examples of each major improvement.

## 🚀 New CLI Features Overview

### 1. **Interactive REPL Mode** (`interactive_mode.py`)
- Tab completion for commands and file paths
- Command history with arrow keys
- Rich terminal UI with colors and formatting
- Context-aware help system
- Session state persistence

### 2. **Progress Visualization** (`progress_manager.py`)
- Real-time progress bars for long operations
- Multi-stage operation tracking
- Performance metrics (operations/second)
- Time estimation and elapsed time
- Beautiful summary reports

### 3. **Configuration Profiles** (`config_profiles.py`)
- Save and reuse analysis configurations
- Default profiles for common workflows
- Profile management (create, edit, delete)
- Advanced settings customization
- Last-used tracking

### 4. **Pipeline Support** (`pipeline.py`)
- Unix-style command chaining
- Data transformation between formats
- Filtering and processing stages
- Multiple output formats
- Stream processing support

### 5. **Enhanced Runner** (`enhanced_runner.py`)
- Integrates all enhancements
- Parallel operation execution
- Beautiful result display
- Interactive prompts
- File output options

## 📋 Quick Start Examples

### Example 1: Interactive Analysis Session

```bash
$ python intellicrack/cli/interactive_mode.py

╔══════════════════════════════════════════════════════════════════╗
║              🚀 Intellicrack Interactive Mode v2.0               ║
╚══════════════════════════════════════════════════════════════════╝

intellicrack> load protected_sample.exe
✓ Loaded: protected_sample.exe

intellicrack> analyze
[Progress bar animation]
Analysis complete! Found 5 vulnerabilities, 3 protections.

intellicrack> show protections
1. VMProtect 3.5.1 detected
2. Anti-debugging techniques found
3. Code obfuscation present

intellicrack> filter vulnerabilities severity:high
Filtered to 2 high-severity vulnerabilities

intellicrack> export results.json
✓ Results exported to results.json
```

### Example 2: Using Configuration Profiles

```bash
# Create a custom profile
$ python intellicrack/cli/config_profiles.py
> 2  # Create new profile
Profile name: quick_protection_scan
# ... configure options ...

# Use the profile in analysis
$ python intellicrack/cli/main.py basic-analyze suspicious.exe
```

### Example 3: Pipeline Processing

```bash
# Analyze multiple files and extract high-risk functions
$ ls *.exe | python intellicrack/cli/pipeline.py \
    "analyze | filter imports CreateRemoteThread,VirtualAllocEx | transform csv | output risky_functions.csv"

# Generate a security audit report
$ python intellicrack/cli/pipeline.py -i application.exe \
    "analyze | filter vulnerability | transform html | output security_report.html"
```

### Example 4: Progress-Enabled Analysis

```bash
$ python intellicrack/cli/enhanced_runner.py

Enter binary path: /samples/packed_software.bin

Select operations to perform:
  Run Static Analysis? (Y/n): y
  Run Vulnerability Scan? (Y/n): y
  Run Protection Detection? (Y/n): y

[Beautiful progress display with live updates]

Analysis Summary
┌─────────────────┬─────────────┬──────────┬─────────────────┐
│ Analysis Type   │ Status      │ Duration │ Details         │
├─────────────────┼─────────────┼──────────┼─────────────────┤
│ Static Analysis │ ✓ Completed │ 0:00:12  │ PE32, UPX 3.96  │
│ Vulnerability.. │ ✓ Completed │ 0:00:08  │ 3 issues found  │
│ Protection Det..│ ✓ Completed │ 0:00:05  │ 2 protections   │
└─────────────────┴─────────────┴──────────┴─────────────────┘
```

## 🔧 Implementation Details

### Interactive Mode Features
- **Command Parser**: Robust argument parsing with shlex
- **Tab Completion**: Context-aware completions for commands and paths
- **State Management**: Maintains analysis context between commands
- **Rich Output**: Tables, progress bars, and formatted text

### Progress System Architecture
- **Async Updates**: Non-blocking progress updates
- **Multi-threading**: Parallel task execution with progress tracking
- **Memory Efficient**: Minimal overhead for progress tracking
- **Customizable**: Easy to add new progress indicators

### Profile System Design
- **JSON Storage**: Human-readable profile files
- **Extensible**: Easy to add new configuration options
- **Validation**: Input validation for all settings
- **Import/Export**: Share profiles between systems

### Pipeline Processing
- **Modular Stages**: Each stage is independent and reusable
- **Error Handling**: Graceful failure with error propagation
- **Format Conversion**: Automatic data format detection
- **Streaming**: Memory-efficient processing of large datasets

## 🎯 Use Cases

### Security Auditing
```bash
# Comprehensive security audit with report
python intellicrack/cli/enhanced_runner.py --profile security_audit target.exe
```

### Batch Processing
```bash
# Process all executables in a directory
for file in /protected_samples/*.exe; do
    python intellicrack/cli/pipeline.py -i "$file" \
        "analyze | filter protection | output ${file}.protections.json"
done
```

### License Analysis
```bash
# Find all license-related functions
python intellicrack/cli/pipeline.py -i commercial_app.exe \
    "analyze | filter imports license,activation,serial | transform table"
```

### Vulnerability Research
```bash
# Interactive vulnerability exploration
python intellicrack/cli/interactive_mode.py
> load vulnerable_app.exe
> find_rop_gadgets
> show gadgets type:jmp_esp
> generate_exploit buffer_overflow_0x401234
```

## 📚 Advanced Features

### Custom Pipeline Stages
Create your own pipeline stages by extending `PipelineStage`:

```python
class CustomFilterStage(PipelineStage):
    def process(self, input_data):
        # Your custom filtering logic
        return filtered_data
```

### Progress Callbacks
Add custom progress handlers:

```python
def my_progress_callback(current, total, message):
    # Custom progress handling
    pass

progress_manager.add_callback(my_progress_callback)
```

### Profile Inheritance
Create profiles that extend others:

```python
child_profile = ProfileManager.create_from_parent("parent_profile")
child_profile.add_options(["additional_analysis"])
```

## 🚦 Getting Started

1. **Install Requirements**:
   ```bash
   pip install rich click prompt_toolkit
   ```

2. **Try Interactive Mode**:
   ```bash
   python intellicrack/cli/interactive_mode.py
   ```

3. **Run with Progress**:
   ```bash
   python intellicrack/cli/enhanced_runner.py
   ```

4. **Create Profiles**:
   ```bash
   python intellicrack/cli/config_profiles.py
   ```

5. **Build Pipelines**:
   ```bash
   python intellicrack/cli/pipeline.py -h  # See examples
   ```

## 🔮 Future Enhancements

- **Web UI Integration**: Connect CLI to web interface
- **Remote Analysis**: Distributed processing support
- **Plugin Marketplace**: Download community plugins
- **AI Assistant**: Natural language commands
- **Visual Debugger**: Step through analysis visually

The enhanced CLI transforms Intellicrack from a powerful tool into a professional, user-friendly platform suitable for both beginners and advanced users!

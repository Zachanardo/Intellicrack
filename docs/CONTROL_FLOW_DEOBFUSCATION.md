# Control Flow Deobfuscation Guide

## Overview

The Control Flow Deobfuscation Engine is a sophisticated component of Intellicrack designed to reverse engineer and defeat control flow obfuscation techniques commonly used to protect software licensing validation code. This engine can detect and unflatten control flow flattening, identify and remove opaque predicates, and recover the original control flow graph from heavily obfuscated binaries.

## Supported Obfuscation Schemes

The deobfuscator has been designed to handle the following commercial and open-source obfuscation schemes:

### 1. OLLVM (Obfuscator-LLVM)
- Control flow flattening with state variable dispatchers
- Bogus control flow insertion
- Instruction substitution patterns
- Opaque predicate insertion

### 2. Tigress
- Virtualization-based obfuscation
- Control flow flattening
- Dispatcher-based control flow
- Junk code insertion

### 3. VMProtect
- Control flow graph flattening
- Virtual machine-based protection
- Code mutation and polymorphism
- Anti-debugging obfuscation

### 4. Code Virtualizer
- Dispatcher-based obfuscation
- VM bytecode transformation
- Control flow hiding

### 5. Custom Obfuscators
- Generic control flow flattening patterns
- State machine-based obfuscation
- Switch-based dispatchers

## Key Features

### Dispatcher Detection
- **Automated Pattern Recognition**: Identifies dispatcher blocks based on structural characteristics (high out-degree, comparison operations, jump tables)
- **State Variable Tracking**: Locates and tracks state variables used for control flow management
- **Multi-Architecture Support**: Works with x86, x86_64, ARM, and ARM64 binaries
- **Obfuscator Classification**: Identifies the specific obfuscation scheme (OLLVM, Tigress, VMProtect, etc.)

### Control Flow Recovery
- **Edge Recovery**: Reconstructs original control flow edges from flattened structure
- **Dataflow Analysis**: Analyzes state variable assignments to determine original flow
- **Graph Simplification**: Removes dispatcher blocks and reconnects legitimate control flow
- **Confidence Scoring**: Provides confidence metrics for deobfuscation quality

### Opaque Predicate Removal
- **Self-Comparison Detection**: Identifies comparisons where operands are always equal
- **Invariant Condition Detection**: Detects conditions with constant outcomes
- **Dead Code Elimination**: Removes unreachable branches from opaque predicates

### Bogus Block Detection
- **Unreachable Code Detection**: Identifies blocks that can never be reached
- **NOP Sled Detection**: Finds blocks containing only no-operation instructions
- **Junk Code Identification**: Detects semantically meaningless code blocks

### Binary Patching
- **Automated Patch Generation**: Creates patches to permanently deobfuscate binaries
- **NOP Dispatcher**: Replaces dispatcher blocks with NOP instructions
- **Edge Redirection**: Rewrites jumps to restore original control flow
- **Minimal Modification**: Preserves binary functionality while removing obfuscation

## Installation & Dependencies

### Required Dependencies
```bash
pip install networkx lief capstone-windows keystone-engine
```

### Optional Dependencies
```bash
# For visualization (recommended)
pip install graphviz pydot

# For enhanced analysis
pip install r2pipe
```

### Radare2 Installation
The deobfuscator uses radare2 for binary analysis:

**Windows:**
```bash
# Download from https://github.com/radareorg/radare2/releases
# Or use chocolatey:
choco install radare2
```

**Linux:**
```bash
git clone https://github.com/radareorg/radare2
cd radare2
sys/install.sh
```

## Usage

### Command-Line Interface

#### Basic Usage
```bash
# Deobfuscate a single function
python intellicrack/tools/deobfuscate_cfg.py -b target.exe -f 0x401000

# With verbose output
python intellicrack/tools/deobfuscate_cfg.py -b target.exe -f 0x401000 -v

# Specify output directory
python intellicrack/tools/deobfuscate_cfg.py -b target.exe -f 0x401000 -o results/
```

#### Advanced Usage
```bash
# Export all analysis artifacts
python intellicrack/tools/deobfuscate_cfg.py \
    -b protected.exe \
    -f 0x401000 \
    --export-cfg \
    --export-json \
    -o analysis_results/

# Apply patches to create deobfuscated binary
python intellicrack/tools/deobfuscate_cfg.py \
    -b protected.exe \
    -f 0x401000 \
    --apply-patches \
    -o patched/

# Batch deobfuscate multiple functions
python intellicrack/tools/deobfuscate_cfg.py \
    -b protected.exe \
    --batch functions.txt \
    -o batch_results/

# Use custom radare2 installation
python intellicrack/tools/deobfuscate_cfg.py \
    -b protected.exe \
    -f 0x401000 \
    --radare2 /opt/radare2/bin/radare2
```

### Python API

#### Basic Deobfuscation
```python
from intellicrack.core.analysis import ControlFlowDeobfuscator

# Initialize deobfuscator
deobf = ControlFlowDeobfuscator("protected.exe")

# Deobfuscate a function
result = deobf.deobfuscate_function(0x401000, "LicenseValidation")

# Check confidence
print(f"Deobfuscation confidence: {result.confidence:.2%}")

# Examine dispatchers
for dispatcher in result.dispatcher_info:
    print(f"Dispatcher at 0x{dispatcher.dispatcher_address:x}")
    print(f"  Type: {dispatcher.switch_type}")
    print(f"  Controlled blocks: {len(dispatcher.controlled_blocks)}")

# Export results
deobf.export_deobfuscated_cfg(result, "deobfuscated_cfg.dot")
```

#### Advanced Analysis
```python
from intellicrack.core.analysis import ControlFlowDeobfuscator
from pathlib import Path

deobf = ControlFlowDeobfuscator(
    binary_path="protected.exe",
    radare2_path="/custom/path/to/radare2"
)

# Deobfuscate function
result = deobf.deobfuscate_function(0x401000)

# Analyze results
print(f"Original CFG: {result.original_cfg.number_of_nodes()} blocks")
print(f"Deobfuscated CFG: {result.deobfuscated_cfg.number_of_nodes()} blocks")
print(f"Removed blocks: {len(result.removed_blocks)}")
print(f"Recovered edges: {len(result.recovered_edges)}")

# Check opaque predicates
if result.opaque_predicates:
    print(f"\nFound {len(result.opaque_predicates)} opaque predicates:")
    for pred in result.opaque_predicates:
        print(f"  - {pred['type']} at 0x{pred['address']:x}")

# Export multiple formats
deobf.export_deobfuscated_cfg(result, "output/cfg.dot")

# Apply patches to binary
if result.confidence > 0.7:
    deobf.apply_patches(result, "output/deobfuscated.exe")
    print("Created patched binary with deobfuscated control flow")
```

#### Integration with CFG Explorer
```python
from intellicrack.core.analysis import CFGExplorer, ControlFlowDeobfuscator

# Load binary with CFG explorer
explorer = CFGExplorer("protected.exe")
explorer.load_binary()

# Get functions with license checks
functions = explorer.get_function_list()
for func_name in functions:
    if "license" in func_name.lower() or "validate" in func_name.lower():
        func_data = explorer.functions[func_name]
        func_addr = func_data['addr']

        # Deobfuscate the license check function
        deobf = ControlFlowDeobfuscator("protected.exe")
        result = deobf.deobfuscate_function(func_addr, func_name)

        print(f"Deobfuscated {func_name} (confidence: {result.confidence:.2%})")

        # Export deobfuscated CFG
        deobf.export_deobfuscated_cfg(
            result,
            f"output/{func_name}_deobf.dot"
        )
```

## Output Formats

### DOT Graph Export
Deobfuscated control flow graphs are exported in DOT format for visualization with Graphviz:

```bash
# Generate SVG visualization
dot -Tsvg deobfuscated_cfg.dot -o cfg.svg

# Generate PNG visualization
dot -Tpng deobfuscated_cfg.dot -o cfg.png

# Interactive PDF
dot -Tpdf deobfuscated_cfg.dot -o cfg.pdf
```

### JSON Analysis Report
```json
{
  "function_address": "0x401000",
  "confidence": 0.87,
  "metrics": {
    "original_blocks": 45,
    "deobfuscated_blocks": 12,
    "blocks_removed": 33,
    "original_edges": 67,
    "deobfuscated_edges": 15,
    "complexity_reduction": 73.33
  },
  "dispatchers": [
    {
      "address": "0x401000",
      "type": "OLLVM",
      "state_variable": "stack",
      "controlled_blocks": ["0x401100", "0x401200", "..."],
      "case_count": 8
    }
  ],
  "opaque_predicates": [
    {
      "address": "0x401150",
      "instruction": "xor eax, eax; jz 0x401160",
      "type": "invariant_test",
      "always_value": true
    }
  ],
  "removed_blocks": ["0x401300", "0x401400"],
  "recovered_edges": [
    {"source": "0x401100", "target": "0x401200"}
  ]
}
```

### Patched Binary
When using `--apply-patches`, the deobfuscator creates a modified binary with:
- Dispatcher blocks NOPed out
- Direct jumps replacing state-based control flow
- Opaque predicates simplified to direct branches
- Bogus blocks removed

## Analysis Workflow

### 1. Function Identification
First, identify functions containing obfuscated license validation code:

```python
from intellicrack.core.analysis import CFGExplorer

explorer = CFGExplorer("protected.exe")
explorer.load_binary()

# Find license-related functions
license_functions = []
for func_name, func_data in explorer.functions.items():
    # Check for license-related patterns
    patterns = explorer.find_license_check_patterns()
    if patterns:
        license_functions.append({
            'name': func_name,
            'address': func_data['addr'],
            'patterns': len(patterns)
        })

print(f"Found {len(license_functions)} license validation functions")
```

### 2. Deobfuscation Analysis
Deobfuscate identified functions:

```python
from intellicrack.core.analysis import ControlFlowDeobfuscator

deobf = ControlFlowDeobfuscator("protected.exe")

for func in license_functions:
    print(f"\nDeobfuscating {func['name']} at 0x{func['address']:x}")

    result = deobf.deobfuscate_function(func['address'], func['name'])

    if result.confidence > 0.5:
        print(f"  ✓ Successful deobfuscation (confidence: {result.confidence:.2%})")

        # Export for manual review
        deobf.export_deobfuscated_cfg(
            result,
            f"output/{func['name']}_deobf.dot"
        )
    else:
        print(f"  ⚠ Low confidence deobfuscation: {result.confidence:.2%}")
```

### 3. Patch Generation and Application
Generate and apply patches to create a deobfuscated binary:

```python
# Collect high-confidence results
high_confidence_results = []

for func in license_functions:
    result = deobf.deobfuscate_function(func['address'])
    if result.confidence > 0.7:
        high_confidence_results.append(result)

# Apply patches if we have reliable results
if len(high_confidence_results) > 0:
    print(f"\nApplying {len(high_confidence_results)} high-confidence patches")

    # For single-function patching
    deobf.apply_patches(high_confidence_results[0], "deobfuscated.exe")

    print("Deobfuscated binary created: deobfuscated.exe")
```

### 4. Verification
Verify the deobfuscated binary maintains correct functionality:

```python
# Load and analyze deobfuscated binary
explorer_deobf = CFGExplorer("deobfuscated.exe")
explorer_deobf.load_binary()

# Compare complexity metrics
for func_name in license_functions:
    if func_name['name'] in explorer_deobf.functions:
        original_complexity = explorer.functions[func_name['name']]['complexity']
        deobf_complexity = explorer_deobf.functions[func_name['name']]['complexity']

        reduction = ((original_complexity - deobf_complexity) / original_complexity) * 100
        print(f"{func_name['name']}: {reduction:.1f}% complexity reduction")
```

## Advanced Topics

### Custom Dispatcher Detection
Extend dispatcher detection for custom obfuscators:

```python
from intellicrack.core.analysis import ControlFlowDeobfuscator, BasicBlock

class CustomDeobfuscator(ControlFlowDeobfuscator):
    def _is_dispatcher_block(self, basic_block: BasicBlock, cfg) -> bool:
        # Call parent implementation
        if super()._is_dispatcher_block(basic_block, cfg):
            return True

        # Add custom dispatcher detection logic
        # Example: detect custom switch pattern
        disasm_text = " ".join(
            inst.get("disasm", "") for inst in basic_block.instructions
        )

        if "custom_switch_pattern" in disasm_text:
            return True

        return False

# Use custom deobfuscator
deobf = CustomDeobfuscator("protected.exe")
result = deobf.deobfuscate_function(0x401000)
```

### State Variable Analysis
Analyze state variable access patterns:

```python
result = deobf.deobfuscate_function(0x401000)

for dispatcher in result.dispatcher_info:
    print(f"Dispatcher at 0x{dispatcher.dispatcher_address:x}")
    print(f"State variable type: {dispatcher.state_variable_type}")
    print(f"State variable location: 0x{dispatcher.state_variable_location:x}")

    # Analyze case mappings
    print(f"Case mappings ({len(dispatcher.case_mappings)}):")
    for case_value, target_block in dispatcher.case_mappings.items():
        print(f"  Case {case_value} -> 0x{target_block:x}")
```

### Performance Optimization
For large binaries, optimize deobfuscation performance:

```python
import concurrent.futures
from intellicrack.core.analysis import ControlFlowDeobfuscator

def deobfuscate_func(args):
    binary_path, func_addr = args
    deobf = ControlFlowDeobfuscator(binary_path)
    return deobf.deobfuscate_function(func_addr)

# Parallel deobfuscation
function_addresses = [0x401000, 0x402000, 0x403000, 0x404000]

with concurrent.futures.ProcessPoolExecutor() as executor:
    results = executor.map(
        deobfuscate_func,
        [(binary_path, addr) for addr in function_addresses]
    )

    for addr, result in zip(function_addresses, results):
        print(f"0x{addr:x}: confidence {result.confidence:.2%}")
```

## Troubleshooting

### Low Confidence Scores
If deobfuscation confidence is low (<0.5):

1. **Check Architecture Detection**: Verify the correct architecture is detected
2. **Verify Function Boundaries**: Ensure the function address is correct
3. **Examine Dispatcher Detection**: Review dispatcher detection results manually
4. **Try Manual Analysis**: Use the CFG explorer to manually examine the function

```python
# Enable verbose logging
import logging
logging.basicConfig(level=logging.DEBUG)

deobf = ControlFlowDeobfuscator("protected.exe")
result = deobf.deobfuscate_function(0x401000)

# Examine intermediate results
print(f"Dispatchers found: {len(result.dispatcher_info)}")
print(f"Opaque predicates: {len(result.opaque_predicates)}")
print(f"Bogus blocks: {len(result.removed_blocks)}")
```

### Failed Patch Application
If binary patching fails:

1. **Check Write Permissions**: Ensure output directory is writable
2. **Verify LIEF/Keystone**: Confirm dependencies are properly installed
3. **Check Binary Format**: Ensure binary format is supported (PE/ELF/Mach-O)
4. **Review Patch Info**: Examine patch operations for conflicts

```python
result = deobf.deobfuscate_function(0x401000)

# Review patch information
for patch in result.patch_info:
    print(f"Patch type: {patch['type']}")
    print(f"Address: 0x{patch['address']:x}")
    print(f"Description: {patch['description']}")
```

### Radare2 Integration Issues
If radare2 integration fails:

```python
# Specify custom radare2 path
deobf = ControlFlowDeobfuscator(
    "protected.exe",
    radare2_path="/custom/path/to/radare2"
)

# Test radare2 connection
from intellicrack.utils.tools.radare2_utils import r2_session

try:
    with r2_session("protected.exe") as r2:
        version = r2._execute_command("?V")
        print(f"Radare2 version: {version}")
except Exception as e:
    print(f"Radare2 error: {e}")
```

## Best Practices

### 1. Start with High-Level Analysis
Before deobfuscation, use Intellicrack's other analysis tools to understand the binary:

```python
from intellicrack.core.analysis import CFGExplorer, ControlFlowDeobfuscator

# Initial CFG analysis
explorer = CFGExplorer("protected.exe")
explorer.load_binary()

# Identify obfuscated functions
for func_name in explorer.get_function_list():
    func_data = explorer.functions[func_name]

    # High complexity often indicates obfuscation
    if func_data.get('complexity', 0) > 50:
        print(f"Potentially obfuscated: {func_name}")
```

### 2. Validate Results
Always validate deobfuscation results:

```python
result = deobf.deobfuscate_function(0x401000)

# Check confidence threshold
if result.confidence < 0.7:
    print("Warning: Low confidence result")
    print("Manual review recommended")

# Verify metrics
reduction = result.metrics.get('complexity_reduction', 0)
if reduction < 20:
    print("Warning: Minimal complexity reduction")
    print("May not be obfuscated or deobfuscation incomplete")
```

### 3. Use Batch Processing for Multiple Functions
For binaries with many obfuscated functions:

```bash
# Create function list
cat > functions.txt << EOF
0x401000
0x402000
0x403000
0x404000
EOF

# Batch deobfuscate
python intellicrack/tools/deobfuscate_cfg.py \
    -b protected.exe \
    --batch functions.txt \
    -o batch_results/ \
    --export-cfg \
    --export-json
```

### 4. Incremental Patching
For complex binaries, apply patches incrementally:

```python
# Deobfuscate functions one at a time
functions = [0x401000, 0x402000, 0x403000]
binary_path = "protected.exe"

for i, func_addr in enumerate(functions):
    deobf = ControlFlowDeobfuscator(binary_path)
    result = deobf.deobfuscate_function(func_addr)

    if result.confidence > 0.7:
        output_path = f"stage_{i+1}_deobf.exe"
        deobf.apply_patches(result, output_path)
        binary_path = output_path  # Use patched binary for next iteration
        print(f"Stage {i+1} complete: {output_path}")
```

## Performance Considerations

### Memory Usage
For large binaries, control memory usage:

```python
# Process functions in batches
def process_batch(binary_path, addresses):
    deobf = ControlFlowDeobfuscator(binary_path)
    results = []

    for addr in addresses:
        result = deobf.deobfuscate_function(addr)
        results.append(result)

        # Clear caches if needed
        if len(results) > 100:
            results = results[-50:]  # Keep only recent results

    return results

# Process in batches of 10
batch_size = 10
all_addresses = list(range(0x401000, 0x410000, 0x1000))

for i in range(0, len(all_addresses), batch_size):
    batch = all_addresses[i:i+batch_size]
    results = process_batch("protected.exe", batch)
    print(f"Processed batch {i//batch_size + 1}")
```

### Processing Time
Expected deobfuscation times:

- Simple function (10-20 blocks): 1-5 seconds
- Medium function (20-50 blocks): 5-15 seconds
- Complex function (50-100 blocks): 15-30 seconds
- Very complex function (100+ blocks): 30-60+ seconds

Optimize for speed:

```python
# Disable detailed analysis for batch processing
result = deobf.deobfuscate_function(
    function_address=0x401000,
    function_name=None  # Skip name resolution
)

# Skip exports for intermediate results
# Only export final results
```

## License & Legal Notice

This tool is provided for **defensive security research** purposes only. It should only be used:

- By software developers to test their own licensing protection mechanisms
- In controlled, isolated research environments
- For authorized security assessment of proprietary software by developers and security teams

**Unauthorized use to circumvent software protections may violate applicable laws.**

Copyright (C) 2025 Zachary Flint - Licensed under GPL v3.0

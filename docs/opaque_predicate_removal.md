# Advanced Opaque Predicate Removal

## Overview

The enhanced opaque predicate removal system in Intellicrack provides sophisticated analysis and removal of opaque predicates - conditional branches that always evaluate to the same result regardless of input. This is a critical capability for defeating modern software licensing protections that use control flow obfuscation.

## Features

### 1. Constant Propagation Analysis

The system performs interprocedural constant propagation to track constant values through the control flow graph:

- **Dataflow Analysis**: Tracks register values across basic blocks
- **Lattice-based Merging**: Merges register states at control flow join points
- **Arithmetic Tracking**: Handles ADD, SUB, INC, DEC, MUL operations on constants
- **Bitwise Operations**: Tracks XOR, OR, AND, shifts with constant values
- **Call Handling**: Properly invalidates volatile registers across function calls

#### Example Detection

```assembly
mov eax, 5          ; eax = 5 (constant)
add eax, 10         ; eax = 15 (propagated)
cmp eax, 15         ; always equal
je always_taken     ; always taken
```

### 2. Symbolic Execution with Z3

When Z3 is available, the system uses symbolic execution to mathematically prove whether predicates are opaque:

- **Z3 Solver Integration**: Creates symbolic variables for registers
- **SMT Solving**: Proves predicates using satisfiability modulo theories
- **Proof Generation**: Provides mathematical proof of predicate evaluation
- **High Confidence**: Symbolic proofs have 95% confidence rating

#### Example Analysis

```assembly
cmp eax, eax        ; symbolic: eax == eax
je target           ; Z3 proves: ALWAYS TRUE
```

**Z3 Proof**: `(eax == eax) is valid for all values of eax`

### 3. Pattern Recognition

Recognizes common opaque predicate patterns used by obfuscators:

#### Supported Patterns

| Pattern | Description | Always Value |
|---------|-------------|--------------|
| **Self XOR** | `xor reg, reg` | TRUE (result = 0) |
| **Self Comparison** | `cmp reg, reg` | TRUE (always equal) |
| **Algebraic Identity** | `(x * x) >= 0` | TRUE (squares non-negative) |
| **Modulo Invariant** | `(x % 2) in {0, 1}` | Conditional |
| **Bit Masking** | `(x & 0) == 0` | TRUE (always zero) |
| **Impossible Overflow** | Small constants overflow | FALSE |

#### Pattern Examples

**Self XOR Pattern:**
```assembly
xor eax, eax        ; eax = 0 for any initial value
test eax, eax       ; zero flag always set
jz next             ; always taken
```

**Square Non-Negative:**
```assembly
imul eax, eax       ; eax = eax * eax
test eax, eax       ; check sign
jge positive        ; always taken (squares >= 0)
```

### 4. Dead Code Elimination

Comprehensive dead code elimination after opaque predicate removal:

- **Dead Branch Removal**: Removes branches that can never be taken
- **Unreachable Block Detection**: Identifies blocks unreachable from entry
- **Iterative Elimination**: Removes blocks that become dead after previous removals
- **Linear Chain Collapse**: Merges straight-line sequences of blocks

#### Elimination Process

1. Remove edges to dead branches identified by predicate analysis
2. Compute reachable blocks from function entry using graph traversal
3. Remove all unreachable blocks
4. Iteratively remove blocks with no incoming edges
5. Collapse linear chains of blocks with single predecessor/successor

## Architecture Support

The system works across multiple architectures:

- **x86**: 32-bit Intel/AMD processors
- **x86_64**: 64-bit Intel/AMD processors (AMD64)
- **ARM**: 32-bit ARM processors
- **ARM64**: 64-bit ARM processors (AArch64)

## Integration with Control Flow Deobfuscation

The opaque predicate analyzer integrates seamlessly with the existing control flow deobfuscation module:

```python
from intellicrack.core.analysis.control_flow_deobfuscation import ControlFlowDeobfuscator

deobfuscator = ControlFlowDeobfuscator("protected.exe")
result = deobfuscator.deobfuscate_function(0x401000)

# Opaque predicates are automatically detected and removed
for pred in result.opaque_predicates:
    print(f"Address: 0x{pred['address']:x}")
    print(f"Type: {pred['type']}")
    print(f"Always: {pred['always_value']}")
    print(f"Method: {pred['analysis_method']}")
    print(f"Confidence: {pred['confidence']:.2f}")
```

## Analysis Output

### Predicate Analysis Structure

Each detected opaque predicate includes:

```python
{
    'address': 0x401234,              # Block address
    'instruction': 'xor eax, eax',    # Assembly instruction
    'type': 'self_xor',               # Pattern type
    'always_value': True,             # Evaluation result
    'confidence': 0.95,               # Confidence score (0.0-1.0)
    'analysis_method': 'pattern_...',  # Detection method
    'dead_branch': 0x401250,          # Address of dead branch
    'symbolic_proof': 'Z3 proof...'   # Mathematical proof (if available)
}
```

### Confidence Scoring

| Method | Confidence | Description |
|--------|------------|-------------|
| **Symbolic Execution** | 0.95 | Z3-proven mathematical certainty |
| **Constant Propagation** | 0.90 | Concrete value tracking |
| **Pattern Recognition** | 0.85 | Known pattern matching |
| **Heuristic** | 0.75-0.80 | Simple syntactic analysis |

## Usage Examples

### Basic Usage

```python
from intellicrack.core.analysis.opaque_predicate_analyzer import OpaquePredicateAnalyzer

analyzer = OpaquePredicateAnalyzer()
results = analyzer.analyze_cfg(cfg, entry_block=0x401000)

for predicate in results:
    if predicate.always_value:
        print(f"Always TRUE at 0x{predicate.address:x}")
    else:
        print(f"Always FALSE at 0x{predicate.address:x}")
```

### Standalone Constant Propagation

```python
from intellicrack.core.analysis.opaque_predicate_analyzer import ConstantPropagationEngine

engine = ConstantPropagationEngine()
block_states = engine.analyze_cfg(cfg, entry_block=0x401000)

for block_addr, register_state in block_states.items():
    print(f"Block 0x{block_addr:x}:")
    for reg, const_val in register_state.items():
        if const_val.is_constant:
            print(f"  {reg} = {const_val.value}")
```

### Pattern Recognition Only

```python
from intellicrack.core.analysis.opaque_predicate_analyzer import PatternRecognizer

recognizer = PatternRecognizer()
pattern_name, always_value = recognizer.recognize_pattern(basic_block)

if pattern_name:
    print(f"Detected pattern: {pattern_name}")
    print(f"Always evaluates to: {always_value}")
```

## Binary Patching

After opaque predicate detection, the system can generate and apply binary patches:

```python
deobfuscator = ControlFlowDeobfuscator("protected.exe")
result = deobfuscator.deobfuscate_function(0x401000)

# Generate patched binary with dead code removed
deobfuscator.apply_patches(result, output_path="protected_deobf.exe")

# Export deobfuscated CFG for visualization
deobfuscator.export_deobfuscated_cfg(result, output_path="cfg_deobf.dot")
```

### Patch Types Generated

1. **NOP Dispatcher**: Replace dispatcher blocks with NOPs
2. **Redirect Edge**: Change conditional jumps to direct jumps
3. **Remove Dead Code**: Remove unreachable basic blocks

## Performance Considerations

### Analysis Complexity

- **Constant Propagation**: O(N × E) where N = blocks, E = edges
- **Symbolic Execution**: O(N) with SMT solver overhead
- **Pattern Recognition**: O(N × I) where I = instructions per block
- **Dead Code Elimination**: O(N) iterative graph traversal

### Optimization Tips

1. **Cache Results**: Block states are cached during analysis
2. **Early Termination**: Advanced analysis runs first, skips fallback if successful
3. **Parallel Analysis**: Multiple predicates analyzed independently
4. **Incremental Updates**: Only reanalyze affected blocks after modifications

## Limitations and Edge Cases

### Current Limitations

1. **Memory Operations**: Limited tracking of memory-based state variables
2. **Complex Arithmetic**: Very complex expressions may not be fully resolved
3. **Data-Dependent Predicates**: Cannot prove predicates that depend on runtime data
4. **Polymorphic Code**: Self-modifying code not supported

### Fallback Behavior

When advanced analysis fails:
- Falls back to heuristic-based detection
- Lower confidence scores assigned
- Manual verification may be required
- Conservative dead code elimination

## Dependencies

### Required

- **NetworkX**: Graph analysis and manipulation
- **Python 3.10+**: Modern Python features (type hints, pattern matching)

### Optional (Enhanced Capabilities)

- **Z3-Solver**: Symbolic execution and SMT solving
- **Capstone**: Disassembly for instruction analysis
- **LIEF**: Binary parsing and patching

### Installation

```bash
# Core dependencies
pixi add networkx

# Enhanced capabilities
pixi add z3-solver
pixi add capstone
pixi add lief
```

## Common Use Cases

### 1. License Validation Deobfuscation

Licensing code often uses opaque predicates to hide serial number validation:

```assembly
; Obfuscated serial check
xor eax, eax        ; Opaque: always 0
test eax, eax
jz real_check       ; Always taken
; Dead code follows (fake checks)
call fake_validation
jmp exit_fail
real_check:
call actual_serial_validation
```

### 2. Trial Period Protection

Trial limitations hidden behind opaque branches:

```assembly
; Trial check with opaque predicate
mov ecx, 1
imul ecx, ecx      ; ecx = 1 (1*1 = 1)
test ecx, ecx      ; Always non-zero
jnz unlimited      ; Always taken
; Dead trial enforcement code
call enforce_trial_limit
unlimited:
; Full functionality
```

### 3. Activation Bypass

Online activation protected by control flow obfuscation:

```assembly
; Activation with dispatcher
mov [state_var], 0x42
jmp dispatcher
dispatcher:
mov eax, [state_var]
cmp eax, 0x42      ; Opaque: always equal
je activation_bypass
; Dead online check
call contact_server
activation_bypass:
mov byte [activated], 1
```

## Verification and Validation

### Testing Deobfuscation Results

```python
# Compare original and deobfuscated metrics
print(f"Blocks removed: {result.metrics['blocks_removed']}")
print(f"Complexity reduction: {result.metrics['complexity_reduction']:.2f}%")
print(f"Confidence: {result.confidence:.2f}")

# Verify dead code elimination
if result.metrics['blocks_removed'] > 0:
    print(f"Successfully eliminated {result.metrics['blocks_removed']} dead blocks")

# Check opaque predicate detection
detection_rate = len(result.opaque_predicates) / result.metrics['original_blocks']
print(f"Opaque predicate density: {detection_rate:.2%}")
```

### Manual Verification

1. **Disassemble Results**: Compare before/after assembly
2. **Test Execution**: Run patched binary to verify functionality
3. **CFG Visualization**: Inspect DOT graphs for correctness
4. **Symbolic Proofs**: Review Z3 proofs for mathematical validity

## Advanced Topics

### Custom Pattern Addition

Extend the pattern recognizer with custom patterns:

```python
class CustomPatternRecognizer(PatternRecognizer):
    def _initialize_patterns(self):
        patterns = super()._initialize_patterns()
        patterns.append({
            'name': 'custom_invariant',
            'description': 'Custom opaque pattern',
            'match_func': self._match_custom,
            'always_value': True
        })
        return patterns

    def _match_custom(self, basic_block):
        # Custom pattern matching logic
        pass
```

### Integration with Other Tools

Combine with other Intellicrack modules:

```python
# Use with binary patching
from intellicrack.core.binary_patching import BinaryPatcher

patcher = BinaryPatcher("protected.exe")
for pred in result.opaque_predicates:
    if pred['dead_branch']:
        patcher.nop_region(pred['dead_branch'], size=16)
```

## Troubleshooting

### Common Issues

**Issue**: Low confidence scores
- **Solution**: Ensure Z3 is installed for symbolic execution
- **Check**: `pip list | grep z3-solver`

**Issue**: No opaque predicates detected
- **Cause**: Function may not be obfuscated
- **Action**: Verify with manual disassembly

**Issue**: Dead code not removed
- **Cause**: Complex control flow or data dependencies
- **Action**: Review CFG and check for indirect jumps

**Issue**: Patching fails
- **Cause**: Code section may be read-only or packed
- **Action**: Check binary protections with `pefile`

## Performance Benchmarks

### Typical Analysis Times

| Binary Size | Function Blocks | Analysis Time | Memory Usage |
|-------------|-----------------|---------------|--------------|
| Small (100KB) | 10-50 | <1 second | ~50 MB |
| Medium (1MB) | 50-200 | 1-5 seconds | ~200 MB |
| Large (10MB) | 200-1000 | 5-30 seconds | ~500 MB |
| Very Large (50MB+) | 1000+ | 30-120 seconds | ~1-2 GB |

### Optimization Results

Average complexity reduction across obfuscated samples:

- **OLLVM Obfuscation**: 40-60% block reduction
- **Tigress Protection**: 30-50% block reduction
- **VMProtect**: 20-40% block reduction
- **Custom Obfuscators**: 10-30% block reduction

## References

### Academic Background

- **Opaque Predicates**: C. Collberg et al., "A Taxonomy of Obfuscating Transformations"
- **Constant Propagation**: G. Wegman & F. Zadeck, "Constant Propagation with Conditional Branches"
- **Symbolic Execution**: C. Cadar et al., "Symbolic Execution for Software Testing"

### Related Modules

- `control_flow_deobfuscation.py`: Main deobfuscation orchestration
- `binary_patching.py`: Binary modification and patching
- `cfg_analysis.py`: Control flow graph utilities

## License

Copyright (C) 2025 Zachary Flint

This documentation is part of Intellicrack, licensed under GNU GPL v3.

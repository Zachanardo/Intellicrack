# Polymorphic and Metamorphic Code Analysis

## Overview

The **PolymorphicAnalyzer** is a production-ready engine for detecting, analyzing, and normalizing polymorphic and metamorphic code used in software licensing protections. It employs semantic analysis, behavior extraction, and invariant detection to identify core functionality regardless of syntactic variations.

## Key Features

### 1. Mutation Detection
Identifies 10 types of code mutations:
- **Instruction Substitution**: Equivalent instruction replacement (e.g., `xor eax, eax` → `sub eax, eax`)
- **Register Renaming**: Systematic register substitution across code
- **Code Reordering**: Independent instruction sequence permutation
- **Junk Insertion**: NOPs and semantically meaningless operations
- **Dead Code**: Code with no effect on program state
- **Opaque Predicates**: Conditions with constant outcomes
- **Semantic NOPs**: Operation pairs with no net effect
- **Instruction Expansion**: Single operations split into multiple steps
- **Control Flow Flattening**: Linear control flow converted to dispatcher-based
- **Virtualization**: Code converted to bytecode for custom VM

### 2. Polymorphic Engine Identification
Recognizes known engines:
- **MetaPHOR**: XOR-based decryption loops with high instruction diversity
- **NGVCK**: Timing-based with extensive control flow mutations
- **Zmist**: Stack-heavy with balanced push/pop operations
- **PRIZM, RDA, CreatePoly**: Additional commercial engines
- **Custom/Unknown**: Generic polymorphic patterns

### 3. Semantic Analysis
- **Code Normalization**: Converts syntactic variants to canonical form
- **Semantic Signature**: Extracts behavior-based fingerprint
- **Invariant Extraction**: Identifies features constant across mutations
- **Behavior Patterns**: Captures data flow, control flow, and side effects

### 4. Advanced Capabilities
- **Decryption Routine Identification**: Locates XOR loops and decoding stubs
- **Evasion Detection**: Timing checks, VM detection, anti-debugging
- **Mutation Complexity**: Quantitative assessment of obfuscation depth
- **Code Variant Comparison**: Semantic similarity scoring

## Architecture

### Core Components

```
PolymorphicAnalyzer
├── analyze_polymorphic_code()     # Main analysis entry point
├── normalize_code_variant()       # Canonical form conversion
├── extract_semantic_signature()   # Behavior-based fingerprint
├── compare_code_variants()        # Similarity analysis
└── Internal Analysis Methods
    ├── _identify_polymorphic_engine()
    ├── _detect_mutations()
    ├── _normalize_instructions()
    ├── _extract_behavior_patterns()
    ├── _extract_invariants()
    ├── _identify_decryption_routine()
    └── _detect_evasion_techniques()
```

### Data Structures

**InstructionNode**: Normalized instruction representation
```python
@dataclass
class InstructionNode:
    semantic_class: str              # "arithmetic", "data_transfer", etc.
    operand_types: Tuple[str, ...]   # ("reg", "imm", "mem")
    data_dependencies: Set[str]       # Data flow relationships
    control_dependencies: Set[str]    # Control flow relationships
    side_effects: Set[str]            # Memory, flags, stack effects
    semantic_hash: str                # Unique semantic identifier
```

**BehaviorPattern**: Invariant behavior extraction
```python
@dataclass
class BehaviorPattern:
    pattern_id: str
    semantic_signature: str
    data_flow_graph: Dict[str, Set[str]]
    control_flow_graph: Dict[int, Set[int]]
    register_usage: Dict[str, str]
    memory_accesses: List[Tuple[str, int, int]]
    api_calls: List[str]
    constants: Set[int]
    behavioral_hash: str
    confidence: float
```

**PolymorphicAnalysis**: Complete analysis result
```python
@dataclass
class PolymorphicAnalysis:
    engine_type: PolymorphicEngine
    mutation_types: List[MutationType]
    behavior_patterns: List[BehaviorPattern]
    invariant_features: Dict[str, Any]
    decryption_routine: Optional[CodeBlock]
    mutation_complexity: float
    evasion_techniques: List[str]
```

## Usage Examples

### Basic Analysis
```python
from intellicrack.core.analysis.polymorphic_analyzer import PolymorphicAnalyzer

analyzer = PolymorphicAnalyzer(arch="x86", bits=32)

# Analyze polymorphic code
code = bytes([0x55, 0x89, 0xE5, 0x31, 0xC0, 0x5D, 0xC3])
analysis = analyzer.analyze_polymorphic_code(code, base_address=0x1000)

print(f"Engine: {analysis.engine_type.value}")
print(f"Mutations: {[m.value for m in analysis.mutation_types]}")
print(f"Complexity: {analysis.mutation_complexity:.2f}")
```

### Code Normalization
```python
# Normalize two variants to canonical form
variant1 = bytes([0x31, 0xC0])  # xor eax, eax
variant2 = bytes([0x29, 0xC0])  # sub eax, eax

sig1 = analyzer.normalize_code_variant(variant1)
sig2 = analyzer.normalize_code_variant(variant2)

# Signatures will be similar for semantically equivalent code
```

### Semantic Signature Extraction
```python
# Extract behavior-based signature
code = bytes([0x8B, 0x45, 0x08, 0x01, 0xC0, 0x89, 0x45, 0xFC, 0xC3])
signature = analyzer.extract_semantic_signature(code)

# Signature remains stable across syntactic variations
print(f"Semantic signature: {signature[:16]}...")
```

### Code Variant Comparison
```python
# Compare two code variants
similarity, details = analyzer.compare_code_variants(variant1, variant2)

print(f"Similarity: {similarity:.2f}")
print(f"Details: {details}")
```

### Decryption Routine Detection
```python
# Analyze code with decryption loop
code = bytes([
    0xBE, 0x00, 0x40, 0x00, 0x00,  # mov esi, 0x4000
    0xB9, 0x20, 0x00, 0x00, 0x00,  # mov ecx, 0x20
    0xB0, 0x42,                     # mov al, 0x42
    0x30, 0x06,                     # xor [esi], al
    0x46,                           # inc esi
    0xE2, 0xFB,                     # loop -5
])

analysis = analyzer.analyze_polymorphic_code(code)

if analysis.decryption_routine:
    routine = analysis.decryption_routine
    print(f"Decryption routine at: 0x{routine.start_address:x}")
    print(f"Instructions: {len(routine.instructions)}")
```

## Integration with Protection Scanner

The PolymorphicAnalyzer integrates seamlessly with `protection_scanner.py`:

```python
from intellicrack.core.analysis.protection_scanner import ProtectionScanner

scanner = ProtectionScanner(binary_path="target.exe")
results = scanner.scan()

# Polymorphic patterns automatically detected
for detection in results.detected_protections:
    if "polymorphic" in detection.name.lower():
        print(f"Found: {detection.name}")
        print(f"Confidence: {detection.confidence}")
```

## Detection Algorithms

### Instruction Substitution Detection
1. Identify equivalent instruction pairs (xor/sub, add/inc, etc.)
2. Count frequency of substitution patterns
3. Flag blocks with 2+ equivalent sequences

### Register Renaming Detection
1. Track register usage frequency across code block
2. Calculate usage variance (max/min ratio)
3. Flag blocks with balanced register distribution (ratio < 3.0)

### Junk Insertion Detection
1. Identify explicit NOPs
2. Detect push/pop pairs on same register
3. Find mov instructions with identical source/destination
4. Flag blocks with 3+ junk patterns

### Dead Code Detection
1. Identify operations immediately overwritten
2. Track zero-register patterns followed by overwrites
3. Flag blocks with 2+ dead code sequences

### Opaque Predicate Detection
1. Find test/cmp followed by conditional branch
2. Identify conditions with constant outcomes (test reg, reg)
3. Flag any opaque predicate patterns

### Semantic NOP Detection
1. Identify operation pairs with inverse effects
2. Track add/sub, xor/xor, push/pop sequences
3. Flag blocks with 1+ semantic NOP

### Code Reordering Detection
1. Build data dependency graph
2. Identify independent instruction sequences
3. Flag blocks with 3+ reorderable sequences

## Performance Characteristics

- **Analysis Speed**: ~100-500 instructions/second (with Capstone)
- **Memory Usage**: O(n) where n = instruction count
- **Signature Generation**: O(n log n) for normalization
- **Comparison**: O(1) for semantic signatures

## Dependencies

**Required**:
- Python 3.10+
- hashlib (stdlib)
- dataclasses (stdlib)

**Optional** (for full functionality):
- **Capstone**: Disassembly and instruction analysis
- **r2pipe**: Advanced emulation support

Without Capstone, analyzer operates in limited mode with basic pattern matching.

## Technical Implementation Details

### Semantic Classification
Instructions mapped to semantic classes:
- `data_transfer`: mov, movzx, movsx, lea
- `arithmetic`: add, sub, inc, dec, imul, mul, div
- `bitwise`: xor, or, and, not, shl, shr, rol, ror
- `comparison`: cmp, test
- `control_flow`: jmp, je, jne, jl, jg, call, ret, loop
- `stack_operation`: push, pop
- `function_call`: call
- `function_return`: ret
- `no_operation`: nop

### Invariant Features
Extracted features constant across mutations:
- **Semantic Sequence**: Ordered list of semantic classes
- **Data Flow Depth**: Maximum depth of data dependencies
- **Control Flow Branches**: Count of branching instructions
- **Unique Constants**: Set of immediate values
- **API Call Count**: Number of function calls

### Behavioral Hash
Combined hash of:
- Data flow graph structure
- Control flow graph topology
- Register usage patterns
- Memory access patterns
- API call sequences
- Constant value sets

## Testing

Comprehensive test suite in `tests/unit/core/analysis/test_polymorphic_analyzer.py`:
- 50+ test cases covering all mutation types
- Real-world polymorphic stub patterns
- Engine identification validation
- Semantic signature stability tests
- Edge case handling

Run tests:
```bash
pytest tests/unit/core/analysis/test_polymorphic_analyzer.py -v
```

## Limitations

1. **Requires Capstone** for full disassembly and analysis
2. **x86/x64 Only** currently (ARM support planned)
3. **Heuristic-Based** engine identification (not 100% accurate)
4. **Static Analysis** only (no runtime behavior tracking)
5. **Performance** scales linearly with code size

## Future Enhancements

- ARM/ARM64 architecture support
- Integration with radare2 ESIL emulator for runtime behavior
- Machine learning-based engine classification
- Cross-platform bytecode analysis
- Automatic keygen generation from normalized signatures

## References

- **MetaPHOR**: Morgenstern & Liskin, "Principles of the Polymorphic Engine"
- **NGVCK**: Next Generation Virus Creation Kit documentation
- **Zmist**: Analysis by Kaspersky Lab
- **Semantic Analysis**: Christodorescu & Jha, "Static Analysis of Executables to Detect Malicious Patterns"

## License

Copyright (C) 2025 Zachary Flint
Licensed under GNU General Public License v3.0

---

**Status**: ✅ Production Ready
**Version**: 1.0.0
**Last Updated**: 2025-10-24

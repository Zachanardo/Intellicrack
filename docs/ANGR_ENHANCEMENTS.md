# Angr Enhancements for License Cracking

## Overview

The Angr enhancements module provides production-ready symbolic execution capabilities specifically designed for analyzing and defeating software licensing protections. This document describes the advanced features and how to use them effectively.

## Features

### 1. Path Prioritization (`LicensePathPrioritizer`)

Intelligent path exploration that prioritizes execution paths likely to contain license validation logic.

**Key Capabilities:**
- **License Function Detection**: Automatically identifies functions with licensing-related names
- **Loop Detection**: Detects and limits excessive loop iterations to prevent path explosion
- **State Deduplication**: Prevents redundant exploration of equivalent states
- **Coverage-Guided Exploration**: Prioritizes unexplored code regions
- **Smart Scoring**: Multi-factor scoring based on:
  - Proximity to license-related functions
  - Path length optimization
  - Constraint complexity
  - Coverage novelty

**Usage:**
```python
from intellicrack.core.analysis.angr_enhancements import LicensePathPrioritizer

prioritizer = LicensePathPrioritizer(
    prioritize_license_paths=True,
    max_loop_iterations=3
)
simgr.use_technique(prioritizer)
```

### 2. Constraint Optimization (`ConstraintOptimizer`)

Advanced constraint solving optimization to improve performance and reduce SMT solver overhead.

**Key Capabilities:**
- **Incremental Simplification**: Periodically simplifies constraint sets
- **Constraint Caching**: Caches previously solved constraint sets
- **Solver Timeout Management**: Configurable Z3 solver timeouts
- **Memory-Efficient**: Bounded cache with LRU eviction

**Usage:**
```python
from intellicrack.core.analysis.angr_enhancements import ConstraintOptimizer

optimizer = ConstraintOptimizer(
    simplify_interval=10,      # Simplify every 10 steps
    cache_size=1000,           # Cache up to 1000 constraint sets
    solver_timeout=5000        # 5 second solver timeout
)
simgr.use_technique(optimizer)
```

### 3. State Merging (`StateMerger`)

Reduces path explosion by merging similar states at convergence points.

**Key Capabilities:**
- **Automatic Merge Point Detection**: Identifies states at same addresses
- **Configurable Thresholds**: Control when merging occurs
- **Safe Merging**: Only merges compatible states

**Usage:**
```python
from intellicrack.core.analysis.angr_enhancements import StateMerger

merger = StateMerger(
    merge_threshold=10,    # Merge when 10+ states at same address
    max_merge_count=5      # Merge up to 5 states at once
)
simgr.use_technique(merger)
```

### 4. Windows API Simprocedures

Custom simprocedures for Windows APIs commonly used in licensing protection.

**Implemented Simprocedures:**

#### Signature Verification
- **CryptVerifySignatureW/A**: Always returns success (bypasses code signing checks)
- **WinVerifyTrust**: Returns ERROR_SUCCESS (bypasses Authenticode verification)

#### Registry Operations
- **RegQueryValueExW/A**: Returns symbolic license data from registry
- **RegOpenKeyExW/A**: Always succeeds for registry key opens

#### Hardware Fingerprinting
- **GetVolumeInformationW/A**: Returns symbolic volume serial number
- **GetComputerNameW/A**: Returns symbolic computer name

#### File Operations
- **CreateFileW/A**: Intercepts license file access, returns valid handles
- **ReadFile**: Returns symbolic license file content
- **WriteFile**: Tracks license file writes

#### Time Manipulation
- **GetSystemTime**: Returns symbolic/controllable time for trial bypass
- **GetTickCount**: Returns symbolic tick count for timing-based checks

#### Memory Operations
- **VirtualAlloc**: Allocates symbolic memory
- **VirtualFree**: Tracks memory deallocations

#### Anti-Debugging
- **NtQueryInformationProcess**: Returns safe values (DebugPort = 0)

#### Network Operations
- **socket**: Creates symbolic socket handles
- **connect**: Always succeeds for license server connections
- **send**: Tracks outgoing license validation data
- **recv**: Returns symbolic license server responses

#### User Interface
- **MessageBoxA/W**: Logs and detects license-related messages

**Installation:**
```python
from intellicrack.core.analysis.angr_enhancements import install_license_simprocedures

project = angr.Project("protected.exe", auto_load_libs=False)
installed_count = install_license_simprocedures(project)
print(f"Installed {installed_count} custom simprocedures")
```

### 5. License Validation Detection (`LicenseValidationDetector`)

Analyzes symbolic execution states to detect license validation routines.

**Detection Categories:**
- **Serial Check**: Product key, license key, serial number validation
- **Trial Check**: Expiration, evaluation period, demo mode checks
- **Hardware Check**: Hardware ID, machine fingerprint validation
- **Activation Check**: Online activation, registration verification
- **Online Check**: Server validation, authentication checks

**Usage:**
```python
from intellicrack.core.analysis.angr_enhancements import LicenseValidationDetector

detector = LicenseValidationDetector()

for state in simgr.active:
    validation_info = detector.analyze_state(state)

    if validation_info["validation_type"]:
        print(f"Found {validation_info['validation_type']} validation")
        print(f"Confidence: {validation_info['confidence']:.2%}")
        print(f"Evidence: {validation_info['evidence']}")
```

### 6. Enhanced Execution Manager

Convenience function to create a fully-configured symbolic execution manager.

**Usage:**
```python
from intellicrack.core.analysis.angr_enhancements import create_enhanced_simgr

project = angr.Project("protected.exe", auto_load_libs=False)
initial_state = project.factory.entry_state()

simgr = create_enhanced_simgr(
    project,
    initial_state,
    enable_state_merging=True
)

# Automatically includes:
# - LicensePathPrioritizer
# - ConstraintOptimizer
# - StateMerger (if enabled)
# - DFS exploration
# - Spiller for memory management
# - Veritesting for path merging
# - LoopSeer for loop detection
```

## Integration with Concolic Execution

The Angr enhancements integrate seamlessly with the existing concolic obfuscation handler:

```python
from intellicrack.core.analysis.angr_enhancements import create_enhanced_simgr
from intellicrack.core.analysis.concolic_obfuscation_handler import ObfuscationAwareConcolicEngine

project = angr.Project("obfuscated.exe", auto_load_libs=False)
initial_state = project.factory.entry_state()

simgr = create_enhanced_simgr(project, initial_state)

# Wrap with obfuscation handling
obf_engine = ObfuscationAwareConcolicEngine(simgr)

# Analyze for obfuscation patterns
for state in simgr.active:
    if state.history.bbl_addrs:
        addr = state.addr
        obf_analysis = obf_engine.analyze_basic_block_obfuscation(addr, [])

        if obf_analysis["obfuscation_detected"]:
            print(f"Obfuscation at {hex(addr)}: {obf_analysis['techniques']}")

# Get comprehensive report
report = obf_engine.get_obfuscation_report()
print(f"Opaque predicates eliminated: {report['summary']['opaque_predicates']}")
print(f"Control flow flattening: {report['summary']['control_flow_flattening']}")
```

## Complete Example

```python
import angr
import claripy
from intellicrack.core.analysis.angr_enhancements import (
    create_enhanced_simgr,
    install_license_simprocedures,
    LicenseValidationDetector,
)

# Load protected binary
project = angr.Project("protected.exe", auto_load_libs=False)

# Install custom simprocedures
hooks_installed = install_license_simprocedures(project)
print(f"Installed {hooks_installed} simprocedures")

# Create symbolic inputs
serial_key = claripy.BVS("serial_key", 128)
license_data = claripy.BVS("license_data", 256)

# Set up initial state
initial_state = project.factory.entry_state(
    add_options={
        angr.options.ZERO_FILL_UNCONSTRAINED_MEMORY,
        angr.options.SYMBOL_FILL_UNCONSTRAINED_MEMORY,
    }
)

# Store symbolic license data in state
initial_state.globals['license_info'] = {
    'serial': serial_key,
    'data': license_data,
}

# Create enhanced execution manager
simgr = create_enhanced_simgr(project, initial_state, enable_state_merging=True)

# Initialize detector
detector = LicenseValidationDetector()

# Explore binary
max_steps = 100
for step in range(max_steps):
    if not simgr.active:
        break

    simgr.step()

    # Analyze states for license validation
    for state in simgr.active[:5]:
        validation = detector.analyze_state(state)

        if validation["validation_type"] and validation["confidence"] > 0.7:
            print(f"\n=== License Validation Detected ===")
            print(f"Type: {validation['validation_type']}")
            print(f"Address: {hex(state.addr)}")
            print(f"Confidence: {validation['confidence']:.2%}")

            # Check for license file access
            if hasattr(state, 'license_files'):
                print(f"License files: {list(state.license_files.keys())}")

            # Check constraints
            if state.solver.constraints:
                print(f"Constraints: {len(state.solver.constraints)}")

                # Try to solve for valid inputs
                if state.solver.satisfiable():
                    valid_serial = state.solver.eval(serial_key, cast_to=bytes)
                    print(f"Valid serial found: {valid_serial.hex()}")

print(f"\nExploration complete: {len(simgr.deadended)} paths finished")
```

## Performance Considerations

### Path Explosion Mitigation

1. **Enable State Merging**: Reduces total states by merging at convergence points
2. **Limit Loop Iterations**: Prevents infinite loops from exploding state count
3. **Use Veritesting**: Angr's built-in path merging technique
4. **Set Max Path Limits**: Cap total active states

### Solver Optimization

1. **Configure Timeouts**: Prevent individual queries from hanging
2. **Enable Caching**: Reuse solutions for equivalent constraint sets
3. **Simplify Regularly**: Keep constraint sets manageable
4. **Use Incremental Solving**: Leverage Z3's incremental mode

### Memory Management

1. **Enable Spiller**: Swap inactive states to disk
2. **Limit Active States**: Keep working set small
3. **Clear Dead States**: Remove finished paths regularly

## Troubleshooting

### "No active states remaining"
- Check if entry point is correct
- Verify binary architecture matches
- Enable debug logging to see where exploration stops

### "Solver timeout"
- Increase solver_timeout parameter
- Simplify constraints more frequently
- Check for constraint explosion

### "Path explosion"
- Reduce max_loop_iterations
- Enable state merging
- Use more aggressive path pruning

### "Simprocedures not working"
- Verify binary imports the API
- Check if symbol resolution succeeded
- Use project.hook() manually if needed

## Advanced Topics

### Custom Simprocedures

Create your own simprocedures for proprietary licensing APIs:

```python
from intellicrack.core.analysis.angr_enhancements import WindowsLicensingSimProcedure
import claripy

class MyCustomLicenseCheck(WindowsLicensingSimProcedure):
    def run(self, license_ptr, key_ptr):
        self.logger.info(f"Custom license check at {hex(self.state.addr)}")

        # Create symbolic license data
        symbolic_license = claripy.BVS("custom_license", 256)
        self.state.memory.store(license_ptr, symbolic_license)

        # Return success
        return 1

# Install custom simprocedure
project.hook_symbol("CheckLicense", MyCustomLicenseCheck())
```

### Path-Specific Analysis

Target specific code regions:

```python
# Define target addresses
license_check_addr = 0x401000
success_addr = 0x401500
fail_addr = 0x401600

# Explore to target
simgr.explore(
    find=success_addr,
    avoid=[fail_addr],
)

# Analyze successful paths
for state in simgr.found:
    # Extract constraints needed to reach success
    for constraint in state.solver.constraints:
        print(f"Required constraint: {constraint}")
```

## Best Practices

1. **Start Small**: Begin with limited exploration steps, increase gradually
2. **Use Timeouts**: Always set solver and exploration timeouts
3. **Monitor Resources**: Watch memory and CPU usage during exploration
4. **Validate Results**: Verify discovered inputs on actual binary
5. **Combine Techniques**: Use with static analysis and dynamic instrumentation
6. **Save Progress**: Serialize states for long-running analyses

## References

- [Angr Documentation](https://docs.angr.io/)
- [Symbolic Execution Overview](https://github.com/enzet/symbolic-execution)
- [SMT Solving with Z3](https://github.com/Z3Prover/z3)

## License

This module is part of Intellicrack and licensed under GPL v3.
